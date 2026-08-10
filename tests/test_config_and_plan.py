from pathlib import Path

import pytest

from synology_manager.config import EMPTY_ACL, EMPTY_NFS, AclRule, ConfigError, load_config
from synology_manager.models import ObservedShare
from synology_manager.plan import build_plan


def config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text)
    return path


def base(extra: str = "") -> str:
    return f"""version: 1
host: test
volumes:
  - name: volume1
    shares:
      - name: data
        description: ''
        state: present
{extra}"""


def test_sample_config_loads_offline() -> None:
    sample = Path(__file__).parents[1] / "sample_config.yaml"
    loaded = load_config(sample)
    assert loaded.host.alias == "sample-host"


def test_nested_schema_quota_and_omitted_acl(tmp_path: Path) -> None:
    loaded = load_config(config(tmp_path, base("        quota: 2\n")))
    share = loaded.host.shares[0]
    assert (loaded.host.alias, share.volume, share.quota_mib, share.acl) == (
        "test",
        "/volume1",
        2048,
        EMPTY_ACL,
    )


@pytest.mark.parametrize(
    "field", ["hosts: []", "version: 2", "host: https://nas.invalid", "extra: x"]
)
def test_legacy_and_invalid_roots_rejected(tmp_path: Path, field: str) -> None:
    text = "version: 1\nhost: test\nvolumes: []\n"
    if field.startswith("host:"):
        text = text.replace("host: test", field)
    elif field.startswith("version:"):
        text = text.replace("version: 1", field)
    else:
        text += field + "\n"
    with pytest.raises(ConfigError):
        load_config(config(tmp_path, text))


def test_cidr_list_expands_and_duplicate_rejected(tmp_path: Path) -> None:
    rule = """        nfs:
          enabled: true
          rules:
            - client_cidr: [192.0.2.7/24, 198.51.100.1]
              access: read_write
              root_squash: root
              security_flavors: [sys]
              async: true
              insecure: false
              crossmnt: false
"""
    nfs = load_config(config(tmp_path, base(rule))).host.shares[0].nfs
    assert nfs is not None and [item.client for item in nfs.rules] == [
        "192.0.2.0/24",
        "198.51.100.1/32",
    ]
    with pytest.raises(ConfigError, match="duplicate"):
        load_config(config(tmp_path, base(rule.replace("198.51.100.1", "192.0.2.0/24"))))


@pytest.mark.parametrize("field", ["owned_by_tool: true", "volume: /volume1"])
def test_legacy_share_fields_rejected(tmp_path: Path, field: str) -> None:
    with pytest.raises(ConfigError):
        load_config(config(tmp_path, base(f"        {field}\n")))


def test_acl_group_principal_requires_canonical_dsm_name(tmp_path: Path) -> None:
    acl = """        acl:
          authoritative: true
          inherit_parent: false
          recursive: false
          rules:
            - principal: "@administrators"
              principal_type: group
              permissions: full_control
              inheritance: all
              effect: allow
"""
    with pytest.raises(ConfigError) as raised:
        load_config(config(tmp_path, base(acl)))
    assert (
        str(raised.value)
        == "ACL group principals must use the canonical DSM group name without '@'"
    )
    with pytest.raises(ValueError, match="canonical DSM group name"):
        AclRule("group", "@administrators", "allow", "full_control", "all")


def test_acl_canonical_group_and_email_user_principals_are_accepted(tmp_path: Path) -> None:
    acl = """        acl:
          authoritative: true
          inherit_parent: false
          recursive: false
          rules:
            - principal: administrators
              principal_type: group
              permissions: full_control
              inheritance: all
              effect: allow
            - principal: user@example.test
              principal_type: user
              permissions: read_write
              inheritance: all
              effect: allow
"""
    rules = load_config(config(tmp_path, base(acl))).host.shares[0].acl.rules
    assert [(rule.owner_type, rule.owner_name) for rule in rules] == [
        ("group", "administrators"),
        ("user", "user@example.test"),
    ]


def test_present_acl_is_strict_and_clear_is_visible(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(config(tmp_path, base("        acl: null\n")))
    with pytest.raises(ConfigError):
        load_config(config(tmp_path, base("        acl: {authoritative: true}\n")))
    host = load_config(config(tmp_path, base())).host
    current = ObservedShare("data", "/volume1", "", 0, "v1", False)
    plan = build_plan(host, {"data": current}, {}, {"data": ()}, {"data": False})
    assert any(action.resource == "acl:data" and action.kind == "noop" for action in plan.actions)


@pytest.mark.parametrize(
    "acl",
    [
        "",
        "        acl: {authoritative: true, inherit_parent: false, recursive: false, rules: []}\n",
        "        acl: null\n",
        "        acl: {}\n",
        "        acl: {authoritative: true}\n",
        "        acl: []\n",
        "        acl: malformed\n",
        "        acl: {authoritative: false}\n",
    ],
    ids=["omitted", "valid", "null", "empty", "incomplete", "list", "malformed", "false"],
)
def test_absent_share_ignores_every_acl_value(tmp_path: Path, acl: str) -> None:
    text = base(acl).replace("state: present", "state: absent")
    share = load_config(config(tmp_path, text)).host.shares[0]
    assert (share.state, share.acl) == ("absent", EMPTY_ACL)


@pytest.mark.parametrize(
    "nfs",
    [
        "",
        "        nfs: null\n",
        "        nfs: malformed\n",
        "        nfs: {}\n",
        "        nfs: {enabled: invalid, rules: []}\n",
        "        nfs: {enabled: false, rules: [{unknown: value}]}\n",
        "        nfs: {enabled: false, rules: [{state: present}]}\n",
        "        nfs: {unknown: value}\n",
    ],
    ids=[
        "omitted",
        "null",
        "malformed",
        "incomplete",
        "invalid",
        "disabled-rules",
        "obsolete-rule",
        "unknown",
    ],
)
def test_absent_share_ignores_every_nfs_value(tmp_path: Path, nfs: str) -> None:
    text = base(nfs).replace("state: present", "state: absent")
    share = load_config(config(tmp_path, text)).host.shares[0]
    assert (share.state, share.nfs) == ("absent", EMPTY_NFS)


def test_absent_share_rejects_unknown_share_fields(tmp_path: Path) -> None:
    text = base("        unknown: value\n").replace("state: present", "state: absent")
    with pytest.raises(ConfigError, match="unknown fields"):
        load_config(config(tmp_path, text))


def test_absent_share_plan_has_no_acl_action(tmp_path: Path) -> None:
    host = load_config(config(tmp_path, base().replace("state: present", "state: absent"))).host
    current = ObservedShare("data", "/volume1", "", 0, "v1", False)
    plan = build_plan(host, {"data": current}, {"data": ()}, {"data": ()})
    assert all(action.resource != "acl:data" for action in plan.actions)
