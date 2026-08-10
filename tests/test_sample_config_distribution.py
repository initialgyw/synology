from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tarfile
import textwrap
import zipfile
from copy import deepcopy
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
import yaml

from synology_manager import cli
from synology_manager.config import (
    EMPTY_ACL,
    EMPTY_NFS,
    Config,
    ConfigError,
    NfsConfig,
    NfsRule,
    load_config,
)

ROOT = Path(__file__).parents[1]
SAMPLE = ROOT / "sample_config.yaml"

PARSER_MATRIX = {
    "root": frozenset({"version", "host", "volumes"}),
    "volume": frozenset({"name", "shares"}),
    "share": frozenset({"name", "description", "quota", "state", "acl", "nfs"}),
    "acl": frozenset({"authoritative", "inherit_parent", "recursive", "rules"}),
    "acl rule": frozenset({"principal", "principal_type", "permissions", "inheritance", "effect"}),
    "nfs": frozenset({"enabled", "rules"}),
    "nfs rule": frozenset(
        {
            "client_cidr",
            "client",
            "access",
            "root_squash",
            "security_flavors",
            "async",
            "insecure",
            "crossmnt",
        }
    ),
    "share states": frozenset({"present", "absent"}),
    "acl principal types": frozenset({"user", "group", "special"}),
    "acl permissions": frozenset({"read_only", "read_write", "full_control"}),
    "acl inheritance": frozenset({"none", "this_folder", "children", "all"}),
    "acl effects": frozenset({"allow", "deny"}),
    "nfs access": frozenset({"read_only", "read_write"}),
    "nfs root squash": frozenset({"root", "admin", "guest", "all_admin", "all_guest"}),
    "nfs flavors": frozenset({"sys", "krb5", "krb5i", "krb5p"}),
}

DOCUMENTED_NFS_RULE_REQUIREMENTS = (
    "enabled false with non-empty rules is rejected",
    "At most 200 canonical expanded rules",
    "exactly one of\n          # client_cidr/client plus access, root_squash, security_flavors, async,\n          # insecure, and crossmnt.",
)

DOCUMENTED_DEFAULTS = (
    "Parser defaults:",
    "`volumes[].shares` defaults to []",
    'description defaults\n# to ""',
    "omitted quota, `quota: null`, or `quota: 0` is unlimited",
    "state\n# defaults to present",
    "`nfs.rules` defaults to []",
    "For\n# present shares only, omitted acl is authoritative empty ACL",
    "and omitted nfs is authoritative zero exports.",
    "For absent shares, any acl or nfs value is ignored;",
)


def _assert_safe_member_names(names: list[str]) -> None:
    assert len(names) == len(set(names))
    assert all(
        not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts
        for name in names
    )


def _active_values(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [str(key) for key in value] + [
            item for child in value.values() for item in _active_values(child)
        ]
    if isinstance(value, list):
        return [item for child in value for item in _active_values(child)]
    return [value] if isinstance(value, str) else []


def _load(tmp_path: Path, share: dict[str, Any] | None = None, *, shares: bool = True) -> Config:
    volume: dict[str, Any] = {"name": "volume1"}
    if shares:
        volume["shares"] = [share if share is not None else {"name": "fixture-share"}]
    path = tmp_path / "fixture.yaml"
    path.write_text(
        yaml.safe_dump(
            {"version": 1, "host": "fixture-host", "volumes": [volume]}, sort_keys=False
        ),
        encoding="utf-8",
    )
    return load_config(path)


def _nfs_rule(client_key: str, client: str | list[str]) -> dict[str, Any]:
    return {
        client_key: client,
        "access": "read_write",
        "root_squash": "root",
        "security_flavors": ["sys"],
        "async": False,
        "insecure": False,
        "crossmnt": False,
    }


def test_sample_parses_and_canonicalizes_representative_values() -> None:
    config = load_config(SAMPLE)
    share = config.host.shares[0]
    assert config.host.alias == "sample-host"
    assert config.host.volumes == ("/volume1",)
    assert (share.name, share.volume, share.quota_mib, share.state) == (
        "example-share",
        "/volume1",
        2048,
        "present",
    )
    assert [(rule.owner_type, rule.owner_name) for rule in share.acl.rules] == [
        ("group", "example-group")
    ]
    assert [rule.client for rule in share.nfs.rules] == ["192.0.2.0/24", "198.51.100.9/32"]


def test_sample_documents_parser_aligned_schema_and_defaults() -> None:
    raw = yaml.safe_load(SAMPLE.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    share = raw["volumes"][0]["shares"][0]
    assert frozenset(raw) == PARSER_MATRIX["root"]
    assert frozenset(raw["volumes"][0]) == PARSER_MATRIX["volume"]
    assert frozenset(share) == PARSER_MATRIX["share"]
    assert frozenset(share["acl"]) == PARSER_MATRIX["acl"]
    assert frozenset(share["acl"]["rules"][0]) == PARSER_MATRIX["acl rule"]
    assert frozenset(share["nfs"]) == PARSER_MATRIX["nfs"]
    assert frozenset(share["nfs"]["rules"][0]) == PARSER_MATRIX["nfs rule"] - {"client"}
    text = SAMPLE.read_text(encoding="utf-8")
    assert all(default in text for default in DOCUMENTED_DEFAULTS)
    assert all(requirement in text for requirement in DOCUMENTED_NFS_RULE_REQUIREMENTS)


def test_sample_nfs_clearing_alternatives_are_inline_and_copy_safe() -> None:
    text = SAMPLE.read_text(encoding="utf-8")
    alternatives = (
        "nfs: {enabled: true, rules: []}",
        "nfs: {enabled: false, rules: []}",
    )
    assert "do not add a second nfs key" in text
    assert all(alternative in text for alternative in alternatives)
    assert all(yaml.safe_load(alternative)["nfs"]["rules"] == [] for alternative in alternatives)


def test_parser_defaults_for_empty_volume_and_present_share(tmp_path: Path) -> None:
    empty_volume = _load(tmp_path, shares=False)
    assert empty_volume.host.shares == ()
    config = _load(tmp_path)
    share = config.host.shares[0]
    assert (share.description, share.quota_mib, share.state, share.acl, share.nfs) == (
        "",
        0,
        "present",
        EMPTY_ACL,
        EMPTY_NFS,
    )


@pytest.mark.parametrize(
    ("quota", "expected_mib"),
    [
        (None, 0),
        (0, 0),
        (3, 3072),
        ({"value": 7, "unit": "MiB"}, 7),
        ({"value": 4, "unit": "GiB"}, 4096),
    ],
)
def test_documented_quota_alternatives_parse(
    tmp_path: Path, quota: object, expected_mib: int
) -> None:
    share = {"name": "fixture-share", "quota": quota}
    assert _load(tmp_path, share).host.shares[0].quota_mib == expected_mib


@pytest.mark.parametrize(
    ("nfs", "expected_enabled", "expected_clients"),
    [
        ({"enabled": True}, True, []),
        ({"enabled": True, "rules": []}, True, []),
        ({"enabled": False, "rules": []}, False, []),
        (
            {"enabled": True, "rules": [_nfs_rule("client_cidr", "192.0.2.7/24")]},
            True,
            ["192.0.2.0/24"],
        ),
        (
            {
                "enabled": True,
                "rules": [_nfs_rule("client_cidr", ["192.0.2.7/24", "198.51.100.9"])],
            },
            True,
            ["192.0.2.0/24", "198.51.100.9/32"],
        ),
        (
            {"enabled": True, "rules": [_nfs_rule("client", "nfs-client.example.test")]},
            True,
            ["nfs-client.example.test"],
        ),
    ],
)
def test_documented_nfs_alternatives_parse(
    tmp_path: Path, nfs: dict[str, Any], expected_enabled: bool, expected_clients: list[str]
) -> None:
    share = {"name": "fixture-share", "nfs": nfs}
    result = _load(tmp_path, share).host.shares[0].nfs
    assert result.enabled is expected_enabled
    assert [rule.client for rule in result.rules] == expected_clients


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        (
            "client_cidr",
            {"client": "192.0.2.1"},
            "NFS client_cidr must be a string or non-empty list of strings",
        ),
        ("client_cidr", None, "NFS client_cidr must be a string or non-empty list of strings"),
        ("client_cidr", 1, "NFS client_cidr must be a string or non-empty list of strings"),
        ("client_cidr", True, "NFS client_cidr must be a string or non-empty list of strings"),
        ("client_cidr", [], "NFS client_cidr must be a string or non-empty list of strings"),
        (
            "client_cidr",
            ["192.0.2.1", 1],
            "NFS client_cidr must be a string or non-empty list of strings",
        ),
        ("client", {"client": "nfs-client.example.test"}, "NFS client must be a string"),
        ("client", ["nfs-client.example.test"], "NFS client must be a string"),
        ("client", None, "NFS client must be a string"),
        ("client", 1, "NFS client must be a string"),
        ("client", True, "NFS client must be a string"),
    ],
)
def test_nfs_client_forms_are_strictly_typed(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    rule = _nfs_rule(field, "192.0.2.1" if field == "client_cidr" else "nfs-client.example.test")
    rule[field] = value
    with pytest.raises(ConfigError, match=message):
        _load(tmp_path, {"name": "fixture-share", "nfs": {"enabled": True, "rules": [rule]}})


def test_nfs_rule_bounds_apply_before_and_after_cidr_expansion(tmp_path: Path) -> None:
    clients = [f"198.51.100.{index}" for index in range(1, 202)]
    valid = {
        "name": "fixture-share",
        "nfs": {
            "enabled": True,
            "rules": [_nfs_rule("client_cidr", client) for client in clients[:200]],
        },
    }
    assert len(_load(tmp_path, valid).host.shares[0].nfs.rules) == 200
    with pytest.raises(ConfigError, match="nfs.rules must contain 0 to 200 rules"):
        _load(
            tmp_path,
            {
                "name": "fixture-share",
                "nfs": {
                    "enabled": True,
                    "rules": [_nfs_rule("client_cidr", client) for client in clients],
                },
            },
        )
    with pytest.raises(ConfigError, match="nfs.rules must contain 0 to 200 rules"):
        _load(
            tmp_path,
            {
                "name": "fixture-share",
                "nfs": {"enabled": True, "rules": [_nfs_rule("client_cidr", clients)]},
            },
        )


def test_disabled_nfs_rules_are_rejected_by_parser_and_model(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="disabled NFS requires an empty rule list"):
        _load(
            tmp_path,
            {
                "name": "fixture-share",
                "nfs": {"enabled": False, "rules": [_nfs_rule("client_cidr", "192.0.2.1")]},
            },
        )
    rule = NfsRule("192.0.2.1", "rw", "root", False, False, False, ("sys",))
    with pytest.raises(ValueError, match="disabled NFS requires an empty rule list"):
        NfsConfig(False, (rule,))


def test_duplicate_canonical_nfs_clients_are_rejected_by_parser(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="NFS client identities are duplicated"):
        _load(
            tmp_path,
            {
                "name": "fixture-share",
                "nfs": {
                    "enabled": True,
                    "rules": [_nfs_rule("client_cidr", ["192.0.2.7/24", "192.0.2.0/24"])],
                },
            },
        )


def test_documented_acl_alternatives_and_enums_parse(tmp_path: Path) -> None:
    rules = [
        {
            "principal": "fictional.user@example.test",
            "principal_type": "user",
            "permissions": "read_only",
            "inheritance": "none",
            "effect": "allow",
        },
        {
            "principal": "fixture-group",
            "principal_type": "group",
            "permissions": "read_write",
            "inheritance": "this_folder",
            "effect": "deny",
        },
        {
            "principal": "fictional-special-principal",
            "principal_type": "special",
            "permissions": "full_control",
            "inheritance": "children",
            "effect": "allow",
        },
        {
            "principal": "fixture-group-all",
            "principal_type": "group",
            "permissions": "read_only",
            "inheritance": "all",
            "effect": "deny",
        },
    ]
    share = {
        "name": "fixture-share",
        "acl": {
            "authoritative": True,
            "inherit_parent": True,
            "recursive": True,
            "rules": rules,
        },
    }
    result = _load(tmp_path, share).host.shares[0].acl.rules
    assert {rule.owner_type for rule in result} == PARSER_MATRIX["acl principal types"]
    assert {rule.preset for rule in result} == PARSER_MATRIX["acl permissions"]
    assert {rule.inheritance for rule in result} == PARSER_MATRIX["acl inheritance"]
    assert {rule.permission_type for rule in result} == PARSER_MATRIX["acl effects"]


def test_documented_nfs_enums_parse(tmp_path: Path) -> None:
    rules = []
    for index, root_squash in enumerate(sorted(PARSER_MATRIX["nfs root squash"])):
        rule = _nfs_rule("client_cidr", f"198.51.100.{index + 1}")
        rule["root_squash"] = root_squash
        rule["access"] = "read_only" if index == 0 else "read_write"
        rule["security_flavors"] = sorted(PARSER_MATRIX["nfs flavors"])
        rules.append(rule)
    result = _load(tmp_path, {"name": "fixture-share", "nfs": {"enabled": True, "rules": rules}})
    parsed = result.host.shares[0].nfs.rules
    assert {rule.privilege for rule in parsed} == {"ro", "rw"}
    assert {rule.root_squash for rule in parsed} == PARSER_MATRIX["nfs root squash"]
    assert {flavor for rule in parsed for flavor in rule.flavors} == PARSER_MATRIX["nfs flavors"]


@pytest.mark.parametrize(
    "share",
    [
        {
            "name": "fixture-share",
            "nfs": {"enabled": False, "rules": [_nfs_rule("client_cidr", "192.0.2.1")]},
        },
        {"name": "fixture-share", "acl": None},
        {"name": "fixture-share", "acl": {"authoritative": True}},
        {
            "name": "fixture-share",
            "acl": {
                "authoritative": False,
                "inherit_parent": False,
                "recursive": False,
                "rules": [],
            },
        },
        {
            "name": "fixture-share",
            "nfs": {
                "enabled": True,
                "rules": [
                    {**_nfs_rule("client_cidr", "192.0.2.1"), "client": "nfs-client.example.test"}
                ],
            },
        },
        {
            "name": "fixture-share",
            "nfs": {
                "enabled": True,
                "rules": [{**_nfs_rule("client_cidr", "192.0.2.1"), "state": "present"}],
            },
        },
    ],
)
def test_documented_invalid_combinations_are_rejected(
    tmp_path: Path, share: dict[str, Any]
) -> None:
    with pytest.raises(ConfigError):
        _load(tmp_path, deepcopy(share))


@pytest.mark.parametrize(
    "nfs",
    [
        None,
        "malformed",
        {},
        {"enabled": False, "rules": [_nfs_rule("client_cidr", "192.0.2.1")]},
        {"enabled": True, "rules": [{"unknown": "value"}]},
    ],
    ids=["null", "malformed", "incomplete", "disabled-rules", "unknown-nested"],
)
def test_absent_share_ignores_nfs_values(tmp_path: Path, nfs: Any) -> None:
    share = _load(
        tmp_path, {"name": "fixture-share", "state": "absent", "nfs": deepcopy(nfs)}
    ).host.shares[0]
    assert (share.state, share.acl, share.nfs) == ("absent", EMPTY_ACL, EMPTY_NFS)


def test_absent_share_with_acl_and_nfs_omitted_parses(tmp_path: Path) -> None:
    share = _load(tmp_path, {"name": "fixture-share", "state": "absent"}).host.shares[0]
    assert (share.state, share.acl, share.nfs) == ("absent", EMPTY_ACL, EMPTY_NFS)


def test_commented_alternatives_are_inactive_and_active_config_has_no_obsolete_keys() -> None:
    raw = yaml.safe_load(SAMPLE.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    share = raw["volumes"][0]["shares"][0]
    assert len(raw["volumes"][0]["shares"]) == 1
    assert share["quota"] == 2
    assert share["state"] == "present"
    assert "client" not in share["nfs"]["rules"][0]
    assert "hosts" not in raw
    assert "volume" not in share
    assert "owned_by_tool" not in share
    assert "state" not in share["nfs"]["rules"][0]


def test_active_sample_contains_only_safe_placeholder_values() -> None:
    raw = yaml.safe_load(SAMPLE.read_text(encoding="utf-8"))
    active = _active_values(raw)
    joined = "\n".join(active)
    assert not re.search(r"https?://|://|@", joined, flags=re.IGNORECASE)
    assert not re.search(r"\b(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", joined)
    assert not re.search(r"\b192\.168\.\d{1,3}\.\d{1,3}\b", joined)
    assert not re.search(r"\b172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b", joined)
    assert not re.search(r"password|credential|token|secret", joined, flags=re.IGNORECASE)
    assert {"sample-host", "example-share", "example-group"} <= set(active)


def test_full_sample_text_contains_only_safe_reserved_examples() -> None:
    text = SAMPLE.read_text(encoding="utf-8")
    assert not re.search(r"https?://|://", text, flags=re.IGNORECASE)
    assert not re.search(r"\b(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
    assert not re.search(r"\b192\.168\.\d{1,3}\.\d{1,3}\b", text)
    assert not re.search(r"\b172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b", text)
    assert not re.search(r"(?im)^\s*(?:password|token|secret|api[_-]?key)\s*:\s*\S+", text)
    emails = re.findall(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+)\b", text)
    assert all(domain.endswith((".test", ".invalid")) for domain in emails)


def test_distributions_package_the_canonical_sample_without_local_artifacts(tmp_path: Path) -> None:
    output = tmp_path / "dist"
    result = subprocess.run(
        [sys.executable, "-m", "build", "--outdir", str(output)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    sdist = next(output.glob("*.tar.gz"))
    wheel = next(output.glob("*.whl"))
    forbidden = re.compile(
        r"(^|/)(?:\.opencode|tests|build|dist|__pycache__|\.pytest_cache|\.mypy_cache|"
        r"\.ruff_cache|\.env(?:\.|$)|credentials(?:\.json)?)(?:/|$)"
    )
    with tarfile.open(sdist) as archive:
        sdist_names = archive.getnames()
        _assert_safe_member_names(sdist_names)
        sdist_samples = [name for name in sdist_names if name.endswith("/sample_config.yaml")]
        assert len(sdist_samples) == 1
        sample_name = sdist_samples[0]
        sample = archive.extractfile(sample_name)
        assert sample is not None
        sdist_text = sample.read().decode("utf-8")
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = archive.namelist()
        _assert_safe_member_names(wheel_names)
        wheel_samples = [name for name in wheel_names if name.endswith("/sample_config.yaml")]
        assert wheel_samples == ["synology_manager/sample_config.yaml"]
        wheel_text = archive.read("synology_manager/sample_config.yaml").decode("utf-8")
    assert sdist_text == wheel_text == SAMPLE.read_text(encoding="utf-8")
    assert not [name for name in sdist_names if forbidden.search(name)]
    assert not [name for name in wheel_names if forbidden.search(name)]
    packaged = tmp_path / "packaged-sample.yaml"
    packaged.write_text(wheel_text, encoding="utf-8")
    assert load_config(packaged).host.alias == "sample-host"
    # The package retains this reference resource, but the public CLI never selects it implicitly.


def test_public_cli_never_selects_ambient_or_packaged_sample(tmp_path: Path) -> None:
    (tmp_path / "sample_config.yaml").write_text(
        "version: 1\nhost: ambient-host\nvolumes:\n  - name: volume1\n", encoding="utf-8"
    )
    with pytest.raises(SystemExit) as exited:
        cli._parser().parse_args(["apply-config"])
    assert exited.value.code == 2


def test_sample_resource_is_not_a_runtime_cli_default() -> None:
    parser = cli._parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["apply-config", "--output", "json"])


def _assert_installed_wheel_uses_bundled_sample(tmp_path: Path, wheel: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    explicit = runtime / "explicit.yaml"
    explicit.write_text(
        "version: 1\nhost: explicit-host\nvolumes:\n  - name: volume1\n",
        encoding="utf-8",
    )
    (runtime / "sample_config.yaml").write_text(
        "version: 1\nhost: ambient-host\nvolumes:\n  - name: volume1\n",
        encoding="utf-8",
    )
    dependencies = tmp_path / "runtime-dependencies"
    dependencies.mkdir()
    dependency_root = Path(yaml.__file__).parents[1]
    for name in ("yaml", "requests", "urllib3", "charset_normalizer", "idna", "certifi"):
        shutil.copytree(dependency_root / name, dependencies / name)
    venv = tmp_path / "installed-wheel"
    create = subprocess.run(
        [
            "uv",
            "venv",
            "--offline",
            "--no-project",
            "--system-site-packages",
            "--python",
            sys.executable,
            str(venv),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert create.returncode == 0, create.stdout + create.stderr
    interpreter = venv / "bin" / "python"
    install = subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--offline",
            "--no-deps",
            "--python",
            str(interpreter),
            str(wheel),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert install.returncode == 0, install.stdout + install.stderr
    script = textwrap.dedent(
        """
        import sys
        from pathlib import Path
        from unittest.mock import patch
        from synology_manager import cli

        assert Path(cli.__file__).is_relative_to(Path(sys.prefix))
        seen = []
        active_paths = []
        original = cli._host
        def capture(path, alias):
            host = original(path, alias)
            active_paths.append(Path(path))
            seen.append(host.alias)
            return host

        class Client:
            def __init__(self, *args, **kwargs):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def inspect(self):
                assert active_paths[-1].is_file()
                return {"offline": True}

        options = ["inspect", "--host", "nas.example.invalid", "--username", "fixture", "--password", "fixture"]
        with patch.object(cli, "_host", capture), patch.object(cli, "credentials", lambda *args: object()), patch.object(cli, "validate_ca_bundle", lambda path: None), patch.object(cli, "DsmClient", Client):
            assert cli.main(options) == 0
            assert cli.main(options + ["--config", "explicit.yaml"]) == 0
        assert seen == ["sample-host", "explicit-host"]
        """
    )
    result = subprocess.run(
        [str(interpreter), "-c", script],
        cwd=runtime,
        env={"PYTHONNOUSERSITE": "1", "PYTHONPATH": str(dependencies)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
