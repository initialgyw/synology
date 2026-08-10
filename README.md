# Synology Manager

A safety-first declarative manager for DSM shared folders, capacity quotas, NFS exports, and ACLs. DSM web APIs used by the adapter are private UI interfaces; capability checks and postconditions fail closed when their observed contracts differ.

## Connection and TLS

CPython **3.14+** is required. Supply the DSM endpoint and credentials with root/global CLI options or `SYN_HOST`, `SYN_USERNAME`, and `SYN_PASSWORD`. An explicit CLI value takes precedence over its environment value. `--password` is supported when requested, but may be visible in process listings and shell history; prefer `SYN_PASSWORD`. Credentials never belong in YAML; the manager never prompts, reads standard input, or emits passwords, session identifiers, raw API payloads, physical paths, or FileStation identifiers.

The configuration `host` is an informational logical identifier only. It never selects a DSM endpoint, credentials, or TLS behavior. Endpoints must pass the existing HTTPS endpoint validation. TLS verification is enabled by default; use `--ca-bundle` for a private CA. `--insecure` disables verification and prints a warning, so it is only appropriate for diagnostics.

## Public CLI

The sole public command is:

```text
synology-manager [GLOBAL OPTIONS] apply-config -c PATH [--do-it] [--verbose] [--timeout SECONDS] [--output text|json]
```

Global options **must precede** `apply-config`:

```text
--host DSM_ENDPOINT --username USERNAME --password PASSWORD --ca-bundle PATH --insecure
```

Command options must follow `apply-config`. `-c`/`--config` is always required; the packaged `sample_config.yaml` is reference material only and is never selected implicitly.

```sh
# Dry run (the default): connect, observe, and build a plan, but make no mutations.
SYN_HOST=nas.example.invalid SYN_USERNAME=admin SYN_PASSWORD='...' \
  synology-manager apply-config -c config.yaml

# Use explicit values and a private CA. Root options come before the command.
synology-manager --host nas.example.invalid --username admin --password '...' \
  --ca-bundle company-ca.pem apply-config -c config.yaml --timeout 30

# Render the exact pre-apply plan, then permit mutation.
synology-manager --host nas.example.invalid --username admin --password '...' \
  apply-config -c config.yaml --do-it --verbose

# JSON is one deterministic document on stdout.
synology-manager apply-config -c config.yaml --output json
```

Without `--do-it`, `apply-config` is a successful dry run. Concise text reports status, the plan hash, action counts, and an authoritative-empty warning; `--verbose` additionally renders the complete hierarchical `ActionPlan`. JSON includes `mode: "dry_run"`, `status`, `plan`, `plan_hash`, `applied: false`, and `cleanup`. The hash binds the complete displayed canonical plan—including hierarchical display and dependency metadata—to the later apply check.

With `--do-it`, text always prints **Plan to apply** and the exact plan before mutation. It then prints **Apply result**, status, expected/current plan hashes, and the final/current plan. `--verbose` shows ordered, safe `starting` events immediately before state-changing DSM calls only (share create/set/delete, NFS save, ACL set), never validation or read checks. JSON remains one document (never progressive JSON): it contains `pre_apply_plan`, `expected_plan_hash`, `events`, `applied`, `status`, `exit_code`, and `cleanup`, plus current/final plans when available. `cleanup.status` is `ok` or `failed`; a failed cleanup has only the fixed safe message, text emits the same warning after the result, and otherwise-successful commands exit with code 1. Error documents include a safe structured error. Partial failures include `recovery_observation: available|unavailable`; current state is never inferred from the pre-apply plan. JSON output emits no human stderr warning, including for `--insecure` or session cleanup.

Before a mutation, the engine re-observes DSM and compares the fresh plan hash to the displayed plan. A stale result has zero mutations. A partial apply is not rolled back automatically: resolve the blocker and rerun with the same declared configuration. Existing NFS, share deletion, ACL preflight, postcondition, and stale-binding safety semantics remain in force.

### Migration from the removed interface

| Removed public interface | Replacement |
|---|---|
| `inspect` | No public replacement; use `apply-config` dry-run to observe managed state. |
| `plan` | `apply-config -c PATH` (dry run). |
| `apply --apply` | `apply-config -c PATH --do-it`. |
| `--config` before the command | `apply-config -c PATH`. |
| `--host-alias` | Removed; the config has exactly one informational `host`. |
| `--allow-delete-nfs`, `--allow-delete-shares`, `--yes` | Removed; `--do-it` plus existing engine safety gates authorize mutations. |
| Global options after a subcommand | Move them before `apply-config`. |

## Configuration

Use the parser-valid [repository-root `sample_config.yaml`](sample_config.yaml) as the complete configuration reference. The file is packaged for reference in source distributions and wheels, but no public command defaults to it. The former root `hosts` schema and explicit share `volume` are rejected; configuration has one root `host` and nested volumes/shares. `homes` is unsupported.

**Destructive default warning:** for every configured `state: present` share, an omitted `acl` is an authoritative empty ACL target and an omitted `nfs` is an authoritative zero-export target. Applying such a configuration can clear existing ACLs or NFS exports. Omitted shares remain unmanaged. A `state: absent` share ignores and normalizes any `acl` or `nfs` value to empty state; deletion reads and clears all live exports before deleting the share, and does not reconcile ACL. Global DSM services are unmanaged. Protected, external, system/package, read-only, or volume-moved shares are refused for mutation.

NFS blocks for present shares are strict: each non-empty rule requires exactly one of `client_cidr` or `client`, and all access semantics. Global NFS is queried only when a present share has non-empty desired exports. DSM has no NFS compare-and-swap token or transactional conditional share delete. The final NFS read detects drift only up to that read: an export can be added after it and before the unconditional delete, so successful deletion cannot prove an export-free state at the instant of deletion. `applied: true` confirms the delete API result and share-absence postcondition, not the absence of an export added during that unobservable interval. Run authoritative NFS reconciliation and share deletion only during exclusive DSM maintenance; if drift is detected, resolve the concurrent writer, replan, and rerun. ACL replacement is guarded by the self-denial check and exact response validation; unknown responses fail closed.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Dry run completed, or apply converged. |
| 2 | CLI/configuration/credential validation failure. |
| 3 | Authentication, TLS, or DSM transport failure. |
| 4 | Safety gate failure. |
| 5 | Unsupported DSM capability. |
| 6 | Stale plan, partial apply, or non-converged/drift state. |

## Development validation

All tests use mocked/offline DSM clients; do not use this suite to contact a NAS.

```sh
uv run ruff format --check .
uv run ruff check .
uv run mypy src tests
uv run pytest
uv run python -m build
```

Source and distribution configuration exclude credentials, `.env` files, `.opencode`, virtual environments, and local build artifacts.
