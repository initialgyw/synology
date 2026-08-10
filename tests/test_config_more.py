from __future__ import annotations

from pathlib import Path

import pytest

from synology_manager.config import ConfigError, load_config

VALID = """version: 1
host: fictional
volumes:
- name: volume1
  shares:
  - name: data
    description: data
    quota: {value: 3, unit: MiB}
    state: present
    nfs:
      enabled: true
      rules:
      - client: client.example
        access: read_only
        root_squash: guest
        security_flavors: [sys, krb5]
        async: false
        insecure: false
        crossmnt: false
    acl:
      authoritative: true
      inherit_parent: true
      recursive: true
      rules:
      - principal: staff
        principal_type: group
        permissions: read_write
        inheritance: children
        effect: deny
"""


def load(tmp_path: Path, text: str) -> object:
    path = tmp_path / "config.yaml"
    path.write_text(text)
    return load_config(path)


def test_complete_schema_and_nfs_hostname(tmp_path: Path) -> None:
    result = load(tmp_path, VALID)
    share = result.host.shares[0]  # type: ignore[attr-defined]
    assert share.quota_mib == 3 and share.nfs.rules[0].client == "client.example"
    assert share.acl.rules[0].owner_type == "group"


@pytest.mark.parametrize(
    "old,new",
    [
        ("client: client.example", "client: bad..host"),
        ("security_flavors: [sys, krb5]", "security_flavors: []"),
        ("state: present", "owned_by_tool: true"),
        ("authoritative: true", "authoritative: maybe"),
        ("quota: {value: 3, unit: MiB}", "quota: {value: -1, unit: MiB}"),
    ],
)
def test_schema_rejects_unsafe_variants(tmp_path: Path, old: str, new: str) -> None:
    with pytest.raises(ConfigError):
        load(tmp_path, VALID.replace(old, new, 1))


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("version: 1\nversion: 1\n", "YAML contains duplicate mapping keys"),
        ("? [one, two]\n: value\n", "YAML mapping keys must be hashable"),
        ("? {one: two}\n: value\n", "YAML mapping keys must be hashable"),
    ],
)
def test_yaml_mapping_keys_are_safely_validated(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        load(tmp_path, text)


def test_trimmed_text_is_required(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load(tmp_path, VALID.replace("host: fictional", 'host: " fictional "'))


def test_nfs_rule_state_is_obsolete_for_present_shares(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="NFS rule state is obsolete"):
        load(tmp_path, VALID.replace("crossmnt: false", "crossmnt: false\n        state: present"))
