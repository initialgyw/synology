# synology

Manage Synology NAS shared folders through the Synology Web API.

## Installation

```bash
python -m venv .venv
. .venv/bin/activate
pip install .
```

For development:

```bash
pip install -e '.[test,dev]'
pytest
ruff check .
mypy
```

The packaged command is `syn-cli`. It uses the pinned
[N4S4/synology-api](https://github.com/N4S4/synology-api) v0.9.2 upstream.

## Credentials and global options

Required connection values can be supplied as options or environment variables:

```bash
export SYN_HOST=nas.example.test
export SYN_USERNAME=admin
export SYN_PASSWORD='password-from-secret-injection'

syn-cli list-shares
```

Supported global options:

| Option | Default | Description |
| --- | --- | --- |
| `--username` | `SYN_USERNAME` | NAS username |
| `--password` | `SYN_PASSWORD` | NAS password |
| `--host` | `SYN_HOST` | NAS hostname or address |
| `--port` | `5001` | NAS API port |
| `--insecure` | disabled | Disable TLS certificate verification |
| `--verbose` | disabled | Sanitized DEBUG diagnostics on stderr |

CLI options override their corresponding environment variables. Global options may be
placed before or after the subcommand:

```bash
syn-cli --host nas.example.test --username admin list-shares
syn-cli list-shares --host nas.example.test --username admin
```

Avoid passing passwords directly on the command line when possible. Shell history and
process inspection may expose them. Use environment-based secret injection instead.
`--insecure` disables TLS certificate verification and should be used only for controlled
troubleshooting. Verbose diagnostics are written to stderr and redact credentials,
tokens, cookies, and session values.

## List shares

The default output is a human-readable table:

```bash
syn-cli list-shares
```

JSON output:

```bash
syn-cli list-shares --output json
```

YAML output:

```bash
syn-cli list-shares --output yaml
```

The table includes `NAME`, `VOLUME`, `DESCRIPTION`, `USB`, and `QUOTA_GIB`. UUID remains available in JSON and YAML.

Use `--permissions` to enrich each share with explicitly configured custom ACL entries from all four categories and one per-share NFS privilege read. Inherited/default ACL entries are excluded; records without `is_custom: true` are conservatively excluded. This performs additional sequential read calls and never fetches or changes global NFS settings:

```bash
syn-cli list-shares --permissions
syn-cli list-shares --permissions --output json
```

Permission tables add `PERMISSION` and `NFS-PERMISSIONS`; long values may occupy continuation lines with blank metadata cells. Empty details are distinct from unavailable details. Unavailable details render as `?`, diagnostics are written to stderr, and the command returns exit code `60` while preserving available rows. Structured output retains UUIDs and full permission/NFS details.
Quota data is requested from DSM using the `share_quota` selector and returned by DSM
as `quota_value`. JSON and YAML include `quota_gib`, `quota_api_value`, and
`quota_api_unit`. Missing quotas display as `-`.

Verbose listing:

```bash
syn-cli --verbose list-shares
syn-cli --verbose --insecure list-shares --output json
```

## Create-share plan mode

Without `--yes`, `create-share` validates arguments and prints a local plan:

```bash
syn-cli create-share projects \
  --path /volume1 \
  --description 'Project files'
```

Plan mode:

- Does not resolve `SYN_USERNAME`, `SYN_PASSWORD`, or `SYN_HOST`.
- Does not construct a NAS client.
- Does not contact the NAS.
- Returns exit code `11`.

Use structured plan output when reviewing automation:

```bash
syn-cli create-share projects \
  --path /volume1 \
  --description 'Project files' \
  --quota 100 \
  --output json
```

## Confirmed share creation

`--yes` is required for NAS mutation:

```bash
syn-cli create-share projects \
  --path /volume1 \
  --description 'Project files' \
  --yes
```

The `--path` value is a NAS volume path, not a local filesystem path and not the final
`/volume1/projects` path. Creation is not idempotent; do not blindly retry after a
transport timeout without checking whether the share was created.

## Create-share options

### Quota

`--quota` is a positive integer in GiB. The CLI converts it to the DSM API unit in MiB:

```text
1 GiB = 1024 MiB
5 GiB = 5120 MiB
```

Example:

```bash
syn-cli create-share media \
  --path /volume1 \
  --quota 100 \
  --yes
```

### Recycle bin

Recycle bin defaults to enabled and administrator-only:

```bash
syn-cli create-share shared \
  --path /volume1 \
  --yes
```

Disable it:

```bash
syn-cli create-share temporary \
  --path /volume1 \
  --disable-recycle-bin \
  --yes
```

Allow non-administrators to access it:

```bash
syn-cli create-share shared \
  --path /volume1 \
  --recycle-bin-user-access \
  --yes
```

`--disable-recycle-bin` and `--recycle-bin-user-access` cannot be combined.

### Compression

Request compression when supported by the DSM version, NAS model, volume, and
filesystem:

```bash
syn-cli create-share compressed \
  --path /volume1 \
  --compress \
  --yes
```

## Share permissions

ACL permissions use repeatable colon-separated values:

```text
TYPE:NAME:ACCESS
```

Supported types:

```text
local-user
local-group
ldap-user
ldap-group
```

Supported access modes:

```text
read-only
read-write
deny
```

Local user:

```bash
syn-cli create-share projects \
  --path /volume1 \
  --permission 'local-user:alice:read-write' \
  --yes
```

Local group:

```bash
syn-cli create-share projects \
  --path /volume1 \
  --permission 'local-group:developers:read-only' \
  --yes
```

LDAP user:

```bash
syn-cli create-share research \
  --path /volume1 \
  --permission 'ldap-user:konri@jumpcloud.com:read-only' \
  --yes
```

LDAP names containing colons are supported because parsing uses the first and final
colon:

```bash
syn-cli create-share research \
  --path /volume1 \
  --permission 'ldap-user:uid=alice:ou=People:read-only' \
  --yes
```

Multiple entries may be supplied:

```bash
syn-cli create-share projects \
  --path /volume1 \
  --permission 'local-user:alice:read-write' \
  --permission 'local-group:developers:read-only' \
  --permission 'ldap-user:konri@jumpcloud.com:read-only' \
  --yes
```

Supplied ACL entries represent the complete desired ACL across the supported principal
categories. Permission application occurs after share creation. If it fails, the share
is preserved and the command returns exit code `60`; no automatic rollback or retry is
performed.

## NFS client permissions

NFS rules use repeatable comma-separated key/value specifications:

```text
client=CLIENT,access=read-only|read-write
```

A literal IPv4 client:

```bash
syn-cli create-share nfs-data \
  --path /volume1 \
  --nfs-permission 'client=10.192.10.20,access=read-write' \
  --yes
```

An IPv4 subnet:

```bash
syn-cli create-share nfs-data \
  --path /volume1 \
  --nfs-permission 'client=10.192.10.0/24,access=read-write' \
  --yes
```

IPv6 and wildcard clients:

```bash
syn-cli create-share nfs-data \
  --path /volume1 \
  --nfs-permission 'client=2001:db8::/64,access=read-only' \
  --yes

syn-cli create-share nfs-data \
  --path /volume1 \
  --nfs-permission 'client=*,access=read-only' \
  --yes
```

Optional operational flags:

```bash
syn-cli create-share nfs-data \
  --path /volume1 \
  --nfs-permission \
  'client=10.192.10.0/24,access=read-write,async=true,insecure=true,crossmnt=true' \
  --yes
```

Defaults are synchronous writes, privileged source ports, no cross-mounts, root
squashing, and AUTH_SYS security. `insecure=true` permits non-privileged source ports;
`crossmnt=true` broadens filesystem visibility; and `async=true` may reduce durability
under failure. Wildcards and broad subnets can expose the share widely.

Global NFS must already be enabled. `create-share` never enables or changes the global
NFS service. Supplied NFS entries replace the complete NFS rule set. The command saves
and reads the rules back for verification. A post-create NFS failure or verification
mismatch returns exit code `60`, preserves the share, and performs no automatic rollback
or retry.

## Exit codes and remediation

| Code | Meaning |
| ---: | --- |
| `0` | Success |
| `2` | Command-line syntax or usage error |
| `10` | Configuration or validation failure |
| `11` | Validated local create plan; no mutation performed |
| `20` | Authentication or authorization failure |
| `30` | Transport, TLS, or network failure |
| `40` | Synology API or malformed-response failure |
| `50` | Output or serialization failure |
| `60` | Partial or uncertain post-create operation outcome |
| `70` | Unexpected internal failure |

Capture an exit code in shell scripts:

```bash
syn-cli create-share projects --path /volume1
rc=$?
printf 'syn-cli exit code: %s\n' "$rc"
```

For exit `60`, inspect the structured output and DSM. The share may exist while ACL or
NFS configuration is incomplete or uncertain. Correct the resulting state manually or
run a targeted remediation command after confirming the current NAS state. No automatic
share deletion or retry is performed.
