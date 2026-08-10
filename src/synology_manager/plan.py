from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Literal

from synology_manager.config import Host, Share
from synology_manager.dsm import DsmError
from synology_manager.models import (
    INHERITANCE,
    PERMISSIONS,
    ObservedAclRule,
    ObservedNfsRule,
    ObservedShare,
    desired_acl,
    desired_nfs,
)

Kind = Literal["create", "update", "delete", "noop", "unsupported"]
_DISPLAY_LIMIT = 512


@dataclass(frozen=True)
class Action:
    kind: Kind
    resource: str
    detail: str
    gated: bool = False
    display: tuple[str, ...] = field(default=(), repr=False, compare=False)
    dependent: bool = field(default=False, repr=False, compare=False)

    def as_dict(self) -> dict[str, str | bool]:
        return {
            "kind": self.kind,
            "resource": _safe(self.resource),
            "detail": _safe(_display(self.detail)),
            "gated": self.gated,
        }


@dataclass(frozen=True)
class ActionPlan:
    actions: tuple[Action, ...]

    def _hash_payload(self) -> list[dict[str, object]]:
        """Internal canonical payload; public JSON action compatibility stays unchanged."""
        return [
            {
                **action.as_dict(),
                "display": [_safe(line) for line in action.display],
                "dependent": action.dependent,
            }
            for action in self.actions
        ]

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            json.dumps(
                self._hash_payload(), ensure_ascii=True, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()

    def as_dict(self) -> dict[str, object]:
        return {"hash": self.digest, "actions": [action.as_dict() for action in self.actions]}

    def as_text(self) -> str:
        lines = [f"plan hash: {self.digest}"]
        index = 0
        while index < len(self.actions):
            action = self.actions[index]
            if action.resource.startswith("share:"):
                lines.extend(("", *_action_lines(action, 0)))
                index += 1
                while index < len(self.actions) and self.actions[index].dependent:
                    lines.extend(("", *_action_lines(self.actions[index], 2)))
                    index += 1
                continue
            lines.extend(("", *_action_lines(action, 0)))
            index += 1
        return "\n".join(lines)


def _action_lines(action: Action, indent: int) -> tuple[str, ...]:
    resource, separator, name = action.resource.partition(":")
    label = f"{resource}:{_safe(name)}" if separator else _safe(action.resource)
    qualifiers: list[str] = [action.kind]
    if action.dependent:
        qualifiers.append("after share verification")
    if action.gated:
        qualifiers.append("deletion operation")
    prefix = " " * indent
    detail = tuple(_display(line) for line in action.display) or (_safe(_display(action.detail)),)
    return (f"{prefix}{label} [{'; '.join(qualifiers)}]", *(f"{prefix}  {line}" for line in detail))


def _display(value: str) -> str:
    if len(value) <= _DISPLAY_LIMIT:
        return value
    return f"{value[: _DISPLAY_LIMIT - 3]}..."


def _safe(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)[1:-1]


def _quoted(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _quota(value: int) -> str:
    return "unlimited" if value == 0 else f"{value} MiB"


def _nfs_rule(rule: ObservedNfsRule) -> str:
    return (
        f"{_safe(rule.client)} access={rule.privilege} root_squash={rule.root_squash} "
        f"security={','.join(rule.flavors)} async={str(rule.asynchronous).lower()} "
        f"insecure={str(rule.insecure).lower()} crossmnt={str(rule.crossmnt).lower()}"
    )


def _acl_rule(rule: ObservedAclRule) -> str:
    identity = f"{rule.owner_type}:{_safe(rule.owner_name)} effect={rule.permission_type}"
    permissions = _acl_preset(rule.permissions)
    inheritance = _acl_inheritance(rule.inheritance)
    return f"{identity} permissions={permissions} inheritance={inheritance}"


def _acl_preset(values: tuple[bool, ...]) -> str:
    presets = {
        "read_only": {"read_data", "exe_file", "read_attr", "read_ext_attr", "read_perm"},
        "read_write": {
            "read_data",
            "write_data",
            "exe_file",
            "append_data",
            "delete",
            "delete_sub",
            "read_attr",
            "write_attr",
            "read_ext_attr",
            "write_ext_attr",
            "read_perm",
        },
        "full_control": set(PERMISSIONS),
    }
    enabled = {key for key, value in zip(PERMISSIONS, values, strict=True) if value}
    return next((name for name, preset in presets.items() if enabled == preset), "custom")


def _acl_inheritance(values: tuple[bool, ...]) -> str:
    presets = {
        "none": set(),
        "this_folder": {"this_folder"},
        "children": {"child_files", "child_folders"},
        "all": set(INHERITANCE),
    }
    enabled = {key for key, value in zip(INHERITANCE, values, strict=True) if value}
    return next((name for name, preset in presets.items() if enabled == preset), "custom")


def _nfs_display(
    baseline: tuple[ObservedNfsRule, ...], desired: tuple[ObservedNfsRule, ...]
) -> tuple[str, ...]:
    before = {rule.client: rule for rule in baseline}
    after = {rule.client: rule for rule in desired}
    lines: list[str] = []
    for client in sorted(before.keys() - after.keys()):
        lines.append(f"- {_nfs_rule(before[client])}")
    for client in sorted(after.keys() - before.keys()):
        lines.append(f"+ {_nfs_rule(after[client])}")
    for client in sorted(before.keys() & after.keys()):
        if before[client] != after[client]:
            lines.append(f"~ {_nfs_rule(before[client])} -> {_nfs_rule(after[client])}")
    return tuple(lines)


def _acl_display(
    baseline: tuple[ObservedAclRule, ...],
    desired: tuple[ObservedAclRule, ...],
    recursive: bool,
    inherit: bool,
) -> tuple[str, ...]:
    before = {(rule.owner_type, rule.owner_name, rule.permission_type): rule for rule in baseline}
    after = {(rule.owner_type, rule.owner_name, rule.permission_type): rule for rule in desired}
    before_principals = _acl_principals(baseline)
    after_principals = _acl_principals(desired)
    replacements: list[tuple[ObservedAclRule, ObservedAclRule]] = []
    for principal in sorted(before_principals.keys() & after_principals.keys()):
        old_rules, new_rules = before_principals[principal], after_principals[principal]
        if len(old_rules) == len(new_rules) == 1:
            old_rule, new_rule = old_rules[0], new_rules[0]
            before.pop((old_rule.owner_type, old_rule.owner_name, old_rule.permission_type))
            after.pop((new_rule.owner_type, new_rule.owner_name, new_rule.permission_type))
            if old_rule != new_rule:
                replacements.append((old_rule, new_rule))
    lines = [
        "authoritative ACL replacement",
        f"inherit_parent={str(inherit).lower()} recursive={str(recursive).lower()}",
    ]
    for identity in sorted(before):
        lines.append(f"- {_acl_rule(before[identity])}")
    for identity in sorted(after):
        lines.append(f"+ {_acl_rule(after[identity])}")
    for old_rule, new_rule in sorted(
        replacements,
        key=lambda pair: (
            pair[0].owner_type,
            pair[0].owner_name,
            pair[0].permission_type,
            pair[1].permission_type,
        ),
    ):
        lines.append(f"~ {_acl_rule(old_rule)} -> {_acl_rule(new_rule)}")
    return tuple(lines)


def _acl_principals(
    rules: tuple[ObservedAclRule, ...],
) -> dict[tuple[str, str], tuple[ObservedAclRule, ...]]:
    result: dict[tuple[str, str], list[ObservedAclRule]] = {}
    for rule in rules:
        result.setdefault((rule.owner_type, rule.owner_name), []).append(rule)
    return {identity: tuple(items) for identity, items in result.items()}


def build_plan(
    host: Host,
    observed: dict[str, ObservedShare],
    nfs: dict[str, tuple[ObservedNfsRule, ...]],
    acl: dict[str, tuple[ObservedAclRule, ...]],
    acl_inherited: dict[str, bool] | None = None,
) -> ActionPlan:
    if acl_inherited is None:
        inherited = getattr(acl, "inherited", {})
        acl_inherited = inherited if isinstance(inherited, dict) else {}
    actions: list[Action] = []
    shares = sorted(host.shares, key=lambda item: (item.volume, item.name))
    for share in sorted(shares, key=lambda item: item.state == "absent"):
        current = observed.get(share.name)
        if share.name == "homes":
            detail = (
                "homes cannot be deleted" if share.state == "absent" else "homes cannot be managed"
            )
            actions.append(Action("unsupported", f"share:{share.name}", detail))
            continue
        if share.state == "absent":
            _plan_absent(actions, share, current)
            continue
        if current is None:
            actions.append(
                Action(
                    "create",
                    f"share:{share.name}",
                    "create shared folder",
                    display=(
                        f"description: absent -> {_quoted(share.description)}",
                        f"quota: unlimited -> {_quota(share.quota_mib)}",
                    ),
                )
            )
            _plan_children(actions, share, (), (), new=True)
            continue
        try:
            quota = current.quota
        except DsmError:
            actions.append(
                Action("unsupported", f"share:{share.name}", "quota observation is unsafe")
            )
            continue
        if current.protected:
            actions.append(
                Action("unsupported", f"share:{share.name}", "protected share cannot be managed")
            )
            continue
        if current.volume != share.volume:
            actions.append(
                Action("unsupported", f"share:{share.name}", "volume moves are not supported")
            )
            continue
        share_lines = tuple(
            line
            for line in (
                f"description: {_quoted(current.description)} -> {_quoted(share.description)}"
                if current.description != share.description
                else None,
                f"quota: {_quota(quota.mib)} -> {_quota(share.quota_mib)}"
                if quota.mib != share.quota_mib
                else None,
            )
            if line is not None
        )
        actions.append(
            Action(
                "update" if share_lines else "noop",
                f"share:{share.name}",
                "reconcile description or capacity quota"
                if share_lines
                else "shared folder matches",
                display=share_lines or ("shared folder matches",),
            )
        )
        _plan_children(
            actions,
            share,
            nfs.get(share.name, ()),
            acl.get(share.name, ()),
            acl_inherited.get(share.name) if acl_inherited is not None else None,
            new=False,
        )
    return ActionPlan(tuple(actions))


def _plan_absent(
    actions: list[Action],
    share: Share,
    current: ObservedShare | None,
) -> None:
    if share.name == "homes":
        actions.append(Action("unsupported", f"share:{share.name}", "homes cannot be deleted"))
        return
    if current is None:
        actions.append(
            Action("noop", f"share:{share.name}", "already absent", display=("already absent",))
        )
        return
    safe = share.name != "homes" and not current.protected and current.volume == share.volume
    if not safe:
        actions.append(
            Action("unsupported", f"share:{share.name}", "unsafe share deletion request")
        )
        return
    actions.append(
        Action(
            "delete",
            f"share:{share.name}",
            "delete configured absent share",
            False,
            display=("delete configured absent share",),
        )
    )


def _plan_children(
    actions: list[Action],
    share: Share,
    nfs_baseline: tuple[ObservedNfsRule, ...],
    acl_baseline: tuple[ObservedAclRule, ...],
    inherited: bool | None = None,
    *,
    new: bool,
) -> None:
    # NFS is authoritative for every configured present share; omission is EMPTY_NFS.
    desired = tuple(sorted(desired_nfs(rule) for rule in share.nfs.rules))
    if new and not nfs_baseline and not desired:
        pass
    elif nfs_baseline == desired:
        actions.append(
            Action(
                "noop",
                f"nfs:{share.name}",
                "NFS exports match authoritative configuration",
                dependent=new,
                display=("NFS exports match authoritative configuration",),
            )
        )
    elif not desired:
        actions.append(
            Action(
                "delete",
                f"nfs:{share.name}",
                "clear authoritative NFS exports",
                display=("clear authoritative NFS exports", *_nfs_display(nfs_baseline, desired)),
                dependent=new,
            )
        )
    else:
        actions.append(
            Action(
                "create" if new else "update",
                f"nfs:{share.name}",
                "replace authoritative NFS exports",
                display=_nfs_display(nfs_baseline, desired),
                dependent=new,
            )
        )
    # Every configured present share has an authoritative ACL target; omission means empty.
    # Missing observation is unsafe and is never equivalent to an empty observed ACL.
    if inherited is None and not new:
        actions.append(
            Action(
                "unsupported",
                f"acl:{share.name}",
                "ACL observation or inheritance metadata is unavailable",
            )
        )
        return
    desired_acl_rules = desired_acl(share.acl)
    inheritance_matches = inherited == share.acl.inherit_parent
    if acl_baseline == desired_acl_rules and inheritance_matches:
        actions.append(
            Action(
                "noop",
                f"acl:{share.name}",
                "ACL matches",
                dependent=new,
                display=("ACL matches",),
            )
        )
    else:
        actions.append(
            Action(
                "create" if new else "update",
                f"acl:{share.name}",
                f"replace ACL recursively={share.acl.recursive}",
                display=_acl_display(
                    acl_baseline,
                    desired_acl_rules,
                    share.acl.recursive,
                    share.acl.inherit_parent,
                ),
                dependent=new,
            )
        )
