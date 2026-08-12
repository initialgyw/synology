import json
import stat
from io import StringIO
from pathlib import Path

import pytest
import yaml

import synology.cli as cli
import synology.config_import as config_import
from synology.apply_config import ApplyConfig, ApplyShare
from synology.cli import run
from synology.config import MAX_QUOTA_GIB, QUOTA_MIB_PER_GIB
from synology.config_import import (
    ConfigImportDocument,
    ConfigImportResult,
    atomic_write,
    import_share_config,
    load_config_import_document,
)
from synology.exceptions import ApiError, ConfigurationError, LocalPersistenceError
from synology.models import (
    AclPermissionRecord,
    ConnectionConfig,
    EnrichmentStatus,
    NfsAccessMode,
    NfsClientPermission,
    NfsRootSquash,
    NfsSecurityFlavor,
    OutputFormat,
    ShareDetails,
    ShareRecord,
)
from synology.output import render_config_import


class ReadOnlyClient:
    def __init__(
        self, details: ShareDetails, shares: tuple[ShareRecord, ...] | None = None
    ):
        self.details = details
        self.shares = shares or (details.share,)
        self.calls: list[str] = []
        self.mutations: list[str] = []

    def list_shares(self) -> tuple[ShareRecord, ...]:
        self.calls.append("list")
        return self.shares

    def read_apply_details(self, name: str) -> ShareDetails:
        self.calls.append(f"read:{name}")
        return self.details

    def create_share(self) -> None:
        self.mutations.append("create")

    def delete_share(self) -> None:
        self.mutations.append("delete")

    def modify_share(self) -> None:
        self.mutations.append("modify")


def _details(
    *,
    name: str = "projects",
    volume: str = "/volume1",
    description: str = "Project files",
    quota: int = 2048,
    acl: tuple[AclPermissionRecord, ...] = (),
    nfs: tuple[NfsClientPermission, ...] = (),
) -> ShareDetails:
    return ShareDetails(
        ShareRecord(name, volume, description, quota_api_value=quota),
        acl_permissions=acl,
        nfs_permissions=nfs,
        acl_status=EnrichmentStatus.AVAILABLE if acl else EnrichmentStatus.EMPTY,
        nfs_status=EnrichmentStatus.AVAILABLE if nfs else EnrichmentStatus.EMPTY,
    )


def _document(
    tmp_path: Path,
    *,
    source: str = "version: 1\nvolumes: {}\n",
    tree: object | None = None,
    config: ApplyConfig | None = None,
) -> ConfigImportDocument:
    path = tmp_path / "config.yaml"
    path.write_text(source)
    return ConfigImportDocument(
        path,
        source,
        ApplyConfig(None, None, ()) if config is None else config,
        {} if tree is None else tree,
    )


def _dump(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        config_import,
        "_dump",
        lambda document: yaml.safe_dump(document, sort_keys=False),
    )
    monkeypatch.setattr(config_import, "_commented_map", dict)
    monkeypatch.setattr(config_import, "_commented_seq", list)


def test_default_import_reads_only_and_reports_exact_diff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _dump(monkeypatch)
    source = "version: 1\nvolumes: {}\n"
    document = _document(tmp_path, source=source, tree={"version": 1, "volumes": {}})
    before = document.path.read_bytes()
    before_stat = document.path.stat()
    client = ReadOnlyClient(_details())

    result = import_share_config(
        document, share_name="projects", host="nas.test", client=client, write=False
    )

    assert result.action == "imported"
    assert result.written is False
    assert result.diff.startswith("--- current-config.yaml\n+++ proposed-config.yaml\n")
    assert document.path.read_bytes() == before
    assert document.path.stat().st_mtime_ns == before_stat.st_mtime_ns
    assert client.calls == ["list", "read:projects"]
    assert client.mutations == []


def test_yes_writes_atomically_and_preserves_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _dump(monkeypatch)
    document = _document(
        tmp_path,
        tree={"version": 1, "volumes": {}},
    )
    document.path.chmod(0o640)

    result = import_share_config(
        document,
        share_name="projects",
        host="nas.test",
        client=ReadOnlyClient(_details()),
        write=True,
    )

    assert result.written is True
    assert stat.S_IMODE(document.path.stat().st_mode) == 0o640
    rendered = yaml.safe_load(document.path.read_text())
    assert rendered["host"] == "nas.test"
    assert rendered["volumes"]["/volume1"]["shares"][0]["name"] == "projects"


def test_exact_serialized_noop_never_calls_atomic_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = "version: 1\nvolumes: {}\n"
    document = _document(tmp_path, source=source, tree={"version": 1, "volumes": {}})
    monkeypatch.setattr(config_import, "_commented_map", dict)
    monkeypatch.setattr(config_import, "_commented_seq", list)
    monkeypatch.setattr(config_import, "_dump", lambda proposed: source)
    monkeypatch.setattr(
        config_import,
        "atomic_write",
        lambda path, content: pytest.fail("exact serialized no-op must not write"),
    )

    result = import_share_config(
        document,
        share_name="projects",
        host="nas.test",
        client=ReadOnlyClient(_details()),
        write=True,
    )

    assert result.action == "no-change"
    assert result.diff == ""
    assert result.written is False


def test_semantic_noop_with_reformatted_text_reports_diff_and_writes_with_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = "# retained comment\nversion: 1\nvolumes: {}\n"
    document = _document(tmp_path, source=source, tree={"version": 1, "volumes": {}})
    rendered = "version: 1\nvolumes: {}\n"
    writes: list[bytes] = []
    monkeypatch.setattr(config_import, "_commented_map", dict)
    monkeypatch.setattr(config_import, "_commented_seq", list)
    monkeypatch.setattr(config_import, "_dump", lambda proposed: rendered)
    monkeypatch.setattr(
        config_import, "atomic_write", lambda path, content: writes.append(content)
    )

    result = import_share_config(
        document,
        share_name="projects",
        host="nas.test",
        client=ReadOnlyClient(_details()),
        write=False,
    )

    assert result.action == "imported"
    assert result.written is False
    assert result.diff.startswith("--- current-config.yaml\n+++ proposed-config.yaml\n")
    assert writes == []

    document = _document(tmp_path, source=source, tree={"version": 1, "volumes": {}})
    result = import_share_config(
        document,
        share_name="projects",
        host="nas.test",
        client=ReadOnlyClient(_details()),
        write=True,
    )

    assert result.written is True
    assert writes == [rendered.encode()]


def test_merge_moves_target_and_preserves_unrelated_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _dump(monkeypatch)
    old = ApplyShare("projects", "/volume2", "absent", object(), 0, (), ())
    tree = {
        "version": 1,
        "host": "configured.test",
        "volumes": {
            "/volume1": {"shares": [{"name": "other"}]},
            "/volume2": {"shares": [{"name": "projects", "state": "absent"}]},
        },
    }
    document = _document(
        tmp_path, tree=tree, config=ApplyConfig("configured.test", None, (old,))
    )

    import_share_config(
        document,
        share_name="projects",
        host="ignored.test",
        client=ReadOnlyClient(_details()),
        write=False,
    )

    assert tree["host"] == "configured.test"
    assert tree["volumes"]["/volume2"]["shares"] == []
    assert tree["volumes"]["/volume1"]["shares"][0]["name"] == "other"
    assert tree["volumes"]["/volume1"]["shares"][1]["state"] == "present"


def test_missing_volumes_creates_live_volume_and_inserts_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _dump(monkeypatch)
    tree = {"version": 1}
    document = _document(tmp_path, tree=tree)

    import_share_config(
        document,
        share_name="projects",
        host="environment.test",
        client=ReadOnlyClient(_details(volume="/volume9")),
        write=False,
    )

    assert tree["host"] == "environment.test"
    assert tree["volumes"]["/volume9"]["shares"][0]["quota"] == 2


def test_import_filters_protected_acl_and_serializes_nfs_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _dump(monkeypatch)
    acl = (
        AclPermissionRecord(
            "administrators", "local_group", False, False, True, False, True
        ),
        AclPermissionRecord("alice", "local_user", False, True, False, False, False),
    )
    nfs = tuple(
        NfsClientPermission(
            f"10.0.0.{index}/32",
            NfsAccessMode.READ_WRITE,
            True,
            True,
            True,
            squash,
            NfsSecurityFlavor(),
        )
        for index, squash in enumerate(NfsRootSquash, start=1)
    )
    tree = {"version": 1, "volumes": {}}
    document = _document(tmp_path, tree=tree)

    import_share_config(
        document,
        share_name="projects",
        host="nas.test",
        client=ReadOnlyClient(_details(acl=acl, nfs=nfs)),
        write=False,
    )

    share = tree["volumes"]["/volume1"]["shares"][0]
    assert share["acl"]["entries"] == [
        {
            "principal": "alice",
            "principal_type": "local-user",
            "permissions": "read-only",
        }
    ]
    assert {rule["root_squash"] for rule in share["nfs"]["rules"]} == {
        "root",
        "admin",
        "guest",
        "all_admin",
        "all_guest",
    }
    assert all(rule["security_flavors"] == ["sys"] for rule in share["nfs"]["rules"])
    assert all(
        rule["async"] and rule["insecure"] and rule["crossmnt"]
        for rule in share["nfs"]["rules"]
    )


@pytest.mark.parametrize(
    "details",
    [
        _details(quota=1),
        _details(nfs=(NfsClientPermission("not-a-cidr", NfsAccessMode.READ_ONLY),)),
        _details(
            nfs=(
                NfsClientPermission(
                    "10.0.0.0/24",
                    NfsAccessMode.READ_ONLY,
                    security_flavor=NfsSecurityFlavor(kerberos=True),
                ),
            )
        ),
        _details(
            acl=(
                AclPermissionRecord(
                    "alice", "unknown", False, True, False, False, False
                ),
            )
        ),
    ],
)
def test_unrepresentable_live_state_fails_before_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, details: ShareDetails
) -> None:
    _dump(monkeypatch)
    document = _document(tmp_path, tree={"version": 1, "volumes": {}})
    monkeypatch.setattr(
        config_import,
        "atomic_write",
        lambda path, content: pytest.fail("invalid live state must not write"),
    )

    with pytest.raises(ApiError):
        import_share_config(
            document,
            share_name="projects",
            host="nas.test",
            client=ReadOnlyClient(details),
            write=True,
        )


def test_oversized_aligned_live_quota_is_an_api_error_with_exit_40(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = _document(tmp_path, tree={"version": 1, "volumes": {}})
    client = ReadOnlyClient(
        _details(quota=(MAX_QUOTA_GIB + 1) * QUOTA_MIB_PER_GIB)
    )
    monkeypatch.setattr(cli, "load_config_import_document", lambda path: document)

    result = run(
        ["config-import", "-c", "ignored.yaml", "projects"],
        stdout=StringIO(),
        stderr=StringIO(),
        environ={
            "SYN_HOST": "nas.test",
            "SYN_USERNAME": "user",
            "SYN_PASSWORD": "secret",
        },
        client_factory=lambda config, logger: client,
    )

    assert result == 40
    assert client.calls == ["list", "read:projects"]
    assert client.mutations == []


def test_atomic_write_rejects_symlink_nonregular_and_maps_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "config.yaml"
    target.write_text("version: 1\n")
    link = tmp_path / "link.yaml"
    link.symlink_to(target)
    directory = tmp_path / "directory"
    directory.mkdir()

    with pytest.raises(LocalPersistenceError):
        atomic_write(link, b"changed")
    with pytest.raises(LocalPersistenceError):
        atomic_write(directory, b"changed")
    monkeypatch.setattr(
        config_import.os,
        "replace",
        lambda source, destination: (_ for _ in ()).throw(OSError("no")),
    )
    with pytest.raises(LocalPersistenceError):
        atomic_write(target, b"changed")


def test_output_formats_are_equivalent_and_secret_safe() -> None:
    result = ConfigImportResult(
        "projects", "nas.test", "imported", "--- current-config.yaml\n", False
    )
    table = render_config_import(result, OutputFormat.TABLE)
    json_record = json.loads(render_config_import(result, OutputFormat.JSON))
    yaml_record = yaml.safe_load(render_config_import(result, OutputFormat.YAML))

    assert "--- current-config.yaml" in table
    assert json_record == yaml_record
    assert "password" not in table.lower()
    assert "password" not in json_record["diff"].lower()


class _YamlAdapter:
    def load(self, source: str) -> object:
        return yaml.safe_load(source)


def test_loader_accepts_missing_volumes_but_validates_its_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("version: 1\nhost: nas.test\n")
    monkeypatch.setattr(config_import, "_round_trip_yaml", _YamlAdapter)

    document = load_config_import_document(str(path))

    assert document.config == ApplyConfig("nas.test", None, ())
    path.write_text("version: 1\nunknown: true\n")
    with pytest.raises(ConfigurationError, match="unknown configuration root fields"):
        load_config_import_document(str(path))


def test_loader_rejects_duplicate_configured_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        "version: 1\nvolumes:\n  /volume1:\n    shares:\n"
        "      - name: projects\n      - name: projects\n"
    )
    monkeypatch.setattr(config_import, "_round_trip_yaml", _YamlAdapter)

    with pytest.raises(ConfigurationError, match="duplicate share"):
        load_config_import_document(str(path))


def test_parser_requires_config_and_rejects_dry_run() -> None:
    stdout = StringIO()
    stderr = StringIO()

    assert run(["config-import", "projects"], stdout=stdout, stderr=stderr) == 2
    assert (
        run(
            ["config-import", "-c", "x.yaml", "projects", "--dry-run"],
            stdout=stdout,
            stderr=stderr,
        )
        == 2
    )


def test_cli_host_precedence_and_global_flag_placement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    document = _document(tmp_path, config=ApplyConfig("config.test", None, ()))
    captured: list[ConnectionConfig] = []
    monkeypatch.setattr(cli, "load_config_import_document", lambda path: document)
    monkeypatch.setattr(
        cli,
        "import_share_config",
        lambda document, **kwargs: ConfigImportResult(
            "projects", kwargs["host"], "no-change", "", False
        ),
    )

    def factory(config: ConnectionConfig, logger: object) -> ReadOnlyClient:
        captured.append(config)
        return ReadOnlyClient(_details())

    assert (
        run(
            [
                "--host",
                "cli.test",
                "config-import",
                "-c",
                "ignored.yaml",
                "projects",
                "--username",
                "user",
                "--password",
                "secret",
            ],
            stdout=StringIO(),
            stderr=StringIO(),
            environ={"SYN_HOST": "environment.test"},
            client_factory=factory,
        )
        == 0
    )
    assert captured[0].host == "config.test"
    assert captured[0].username == "user"
    assert captured[0].password == "secret"


def test_cli_maps_local_persistence_error_to_exit_12(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    document = _document(tmp_path)
    monkeypatch.setattr(cli, "load_config_import_document", lambda path: document)

    def fail_import(
        document: ConfigImportDocument, **kwargs: object
    ) -> ConfigImportResult:
        raise LocalPersistenceError("write failed")

    monkeypatch.setattr(cli, "import_share_config", fail_import)
    stderr = StringIO()

    result = run(
        ["config-import", "-c", "ignored.yaml", "projects"],
        stdout=StringIO(),
        stderr=stderr,
        environ={
            "SYN_HOST": "nas.test",
            "SYN_USERNAME": "user",
            "SYN_PASSWORD": "secret",
        },
        client_factory=lambda config, logger: ReadOnlyClient(_details()),
    )

    assert result == 12
    assert "write failed" in stderr.getvalue()
