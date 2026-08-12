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

## Continuous integration and releases

Pull requests run Ruff and the pytest suite on Python 3.12 through GitHub Actions.
When a pull request is merged into `main`, another workflow reads the project version
from `pyproject.toml` and creates the corresponding `v<version>` tag. Existing tags are
never force-updated; a conflicting tag causes the workflow to fail.

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

Use `--permissions` to enrich each share with active ACL entries from all four categories and one per-share NFS privilege read. Entries with no active access bits are excluded; active entries are shown regardless of `is_custom`. This performs additional sequential read calls and never fetches or changes global NFS settings:

```bash
syn-cli list-shares --permissions
syn-cli list-shares --permissions --output json
```

Permission tables add `PERMISSION` and `NFS-PERMISSIONS`; long values may occupy continuation lines with blank metadata cells. The active protected `local_group:administrators:read-write` ACL is hidden only from this display (including JSON and YAML); it remains in live state, reconciliation, apply payloads, and verification. Other ACLs remain visible, and a protected-only ACL displays as `-` or `[]` in structured output. NFS detail rows use `client:access,squash=<root|admin|guest|all_admin|all_guest>,security_flavors=[<enabled flavors>],async=<true|false>,insecure=<true|false>,crossmnt=<true|false>`, listing enabled live flavors in the deterministic order `sys`, `kerberos`, `kerberos_integrity`, and `kerberos_privacy` (or `[]` when none are enabled). This read-only display preserves the actual four DSM security-flavor booleans, including GUI-created Kerberos modes. A malformed live client is shown using its raw client value with the same fields, but it remains unsafe for apply-config reconciliation. This malformed-live-rule display behavior applies only to `list-shares --permissions` detail output; `create-share` and `modify-share` results represent their requested or mutation state and do not include unrelated live rules. Empty details are distinct from unavailable details: structured `nfs_permissions` is `[]` for a known empty NFS read and `null` when NFS is unavailable; tables render unavailable NFS as `?`. Diagnostics are written to stderr, and the command returns exit code `60` while preserving available rows. Structured output retains UUIDs and full permission/NFS details without internal observations fields.
Quota data is requested from DSM using the `share_quota` selector and returned by DSM
as `quota_value`. JSON and YAML include `quota_gib`, `quota_api_value`, and
`quota_api_unit`. Missing quotas display as `-`.

Verbose listing:

```bash
syn-cli --verbose list-shares
syn-cli --verbose --insecure list-shares --output json
```

## Delete-share plan mode

Without `--yes`, `delete-share` validates the exact shared-folder name and prints a local plan:

```bash
syn-cli delete-share projects --output json
```

Plan mode does not resolve credentials, construct a NAS client, or contact the NAS. It
returns exit code `11`.

## Confirmed share deletion

`--yes` is required for NAS mutation:

```bash
syn-cli delete-share projects --yes
```

The command passes the exact share name to the Synology `SYNO.Core.Share` delete API.
It does not preflight or postflight list shares. Do not retry blindly after a transport
timeout because the deletion outcome may be unknown. DSM-specific behavior for the
share's contents, special shares, and active dependencies is determined by the NAS API
and is not inferred by this command.

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
client=CLIENT,access=read-only|read-write[,root_squash=root|admin|guest|all_admin|all_guest]
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
  'client=10.192.10.0/24,access=read-write,root_squash=root,async=true,insecure=true,crossmnt=true' \
  --yes
```

`root_squash` is optional and defaults to `root`. Every NFS CLI entry point, including
`create-share` and `modify-share`, accepts only these exact raw DSM v1 tokens:
`root`, `admin`, `guest`, `all_admin`, and `all_guest`. Linux NFS aliases such as
`no_root_squash`, `none`, `all_squash`, and `map_root`, case variants, empty values, and
unknown values are rejected rather than translated. Desired CLI rules use only the DSM
`security_flavor` of `[sys]`; Kerberos flavors cannot be selected or reconciled. In
contrast, `list-shares --permissions` is read-only and displays actual live Kerberos
flavor booleans when DSM reports them. Desired clients must be canonical IP addresses, CIDRs, or `*`; malformed or noncanonical CIDRs such as
`10.192.10.0/2` are rejected before a client is constructed or any NAS write is attempted.

Defaults are synchronous writes, privileged source ports, no cross-mounts, root
squashing, and AUTH_SYS (`[sys]`) security. `insecure=true` permits non-privileged source
ports; `crossmnt=true` broadens filesystem visibility; and `async=true` may reduce
durability under failure. Wildcards and broad subnets can expose the share widely.
`admin` and `all_admin` map access to the administrator identity, while `all_admin` and
`all_guest` map every user; review non-default identity mappings before applying them.

Global NFS must already be enabled. `create-share` never enables or changes the global
NFS service. Supplied NFS entries replace the complete NFS rule set. The command saves
and reads the rules back for verification. A post-create NFS failure or verification
mismatch returns exit code `60`, preserves the share, and performs no automatic rollback
or retry.

## Modify-share

`modify-share` replaces exactly one setting family per invocation: quota, ACL, or NFS.
It does not support append, remove, selectors, or merge modes.

```bash
syn-cli modify-share projects --permission 'local-user:alice:read-write'
syn-cli modify-share projects --permission '' --yes
syn-cli modify-share projects --nfs-permission 'client=10.192.10.0/24,access=read-write,root_squash=guest' --yes
syn-cli modify-share projects --nfs-permission '' --yes
syn-cli modify-share projects --quota 0
```

ACL replacement applies the supplied collection across all four mutable categories:
local users, local groups, LDAP users, and LDAP groups. DSM treats permission updates
as patches, so omitted active non-administrator principals are explicitly sent with
no access bits to revoke them; empty lists are never used as a clearing signal. Protected
administrator entries may remain when they are not requested. Before a confirmed ACL
replacement writes anything, each requested principal must appear with the exact category and
name in the complete DSM permission inventory; inactive inventory/default rows prove a
principal exists but are ignored during reconciliation. This validation applies only to
`modify-share`, not `create-share`.
An explicit empty ACL value, `--permission ''`, revokes every currently active mutable
permission, including local administrator users such as `synadmin`. Every local
administrator group is preserved; in particular, `local_group:administrators` is never
cleared. Omit `--permission` to leave ACL unselected. For each repeatable ACL option,
exactly one empty value is valid; repeated empty values or an empty value mixed with a
nonempty value are rejected.

NFS replacement saves the complete supplied NFS rule list; `--nfs-permission ''` saves
an empty list. The rule syntax is
`client=CLIENT,access=read-only|read-write[,root_squash=root|admin|guest|all_admin|all_guest]`.
`root_squash` defaults to `root`; only the five exact raw DSM tokens listed above are
accepted. Linux aliases (`no_root_squash`, `none`, `all_squash`, and `map_root`), case
variants, missing or empty values, and other values are rejected. Rules are limited to
DSM `security_flavor: [sys]`; Kerberos flavors are not supported. Non-default mappings
change the NAS identity used for access; `admin` and `all_admin` are privileged, and
`all_admin` and `all_guest` affect all users. Review these settings before `--yes`.
Omit `--nfs-permission` to leave NFS unselected. For each repeatable NFS option, exactly
one empty value is valid; repeated empty values or an empty value mixed with a nonempty
value are rejected. Global NFS is not enabled, disabled, or otherwise changed by this
command.

`--quota` accepts a nonnegative integer in GiB. Positive values are converted to DSM's
MiB API unit (`5 GiB` is sent as `5120 MiB`); `--quota 0` clears the limit and reports
`unlimited`. A confirmed quota update reads the mutable share state, skips an exact
quota no-op, sends a single complete share update that preserves known mutable fields,
and reads it back to verify both the quota and preserved state. JSON and YAML include the
observed API value and unit after a remote read; table output shows the observed value as
GiB or `unlimited`.

Without `--yes`, every modification is a local validated plan, requires no credentials,
contacts no NAS, and exits `11`. ACL plans identify requested principal existence as
unverified because they do not read DSM inventory. Confirmed ACL, NFS, and quota replacements skip writes
for an exact no-op and verify changed state. A failed or uncertain write or post-write
verification returns `60` with its completed and failed steps in the output. In particular,
do not retry a quota request after a transport failure or malformed post-write response:
the NAS may have accepted it, and the output marks the outcome as unknown.

## Config import

`config-import` reads exactly one existing live share using read-only NAS methods and merges
it into an existing strict V1 configuration. It never creates, changes, or deletes a NAS
share.

```bash
syn-cli config-import -c config.yaml projects
syn-cli config-import -c config.yaml projects --yes --output json
```

`-c`/`--config` is required and the file must already exist. The default is a preview: it
prints the final unified diff (`current-config.yaml` to `proposed-config.yaml`) and does not
write the file. `--yes` prints that same diff and atomically replaces only the local config,
without a prompt or NAS mutation. Table output contains the readable diff; JSON and YAML
contain metadata plus a `diff` string. The command always merges and round-trip serializes a
proposed document in memory. It reports no change and never rewrites the file, including with
`--yes`, only when that serialized text exactly matches the original file; retained comments or
formatting that produce a real serialized diff require `--yes` to write.

The command validates duplicate keys and all present V1 root and managed structures before
resolving credentials or constructing a NAS client. As the sole config-import exception, a root
with valid `version: 1` but no `volumes` is accepted so the import can create `volumes`; every
serialized proposal is then strict V1-valid. It replaces the target share node with
live description, quota, mutable ACLs, and complete supported NFS rules; it creates missing
`volumes`, creates the live
volume when needed, moves a target configured under another volume, and preserves supported
root fields, volumes, shares, comments, and formatting where possible. The protected exact
`local_group:administrators:read-write` ACL is omitted. Live quota must be unlimited or a
nonnegative, exactly GiB-aligned value within both the DSM API MiB maximum and the supported
GiB maximum. A malformed or oversized live quota is a remote-response representability failure
and returns exit `40`; NFS clients must be valid and NFS security must be exactly `[sys]`.
Unsupported or malformed live state aborts before any local write.

For this command, config `host` takes precedence over `--host`, then `SYN_HOST`; if absent,
the selected CLI/environment host is inserted into the proposed config. Username and password
remain `--username` then their environment variables. `--yes` rejects symlink and non-regular
targets and uses a same-directory atomic write preserving the target mode, fsyncing data and
the directory when supported. Local persistence failures return exit `12`.

## Exit codes and remediation

| Code | Meaning |
| ---: | --- |
| `0` | Success |
| `2` | Command-line syntax or usage error |
| `10` | Configuration or validation failure |
| `11` | Validated local create, delete, or modify plan; no mutation performed |
| `12` | Local config-import persistence failure |
| `20` | Authentication or authorization failure |
| `30` | Transport, TLS, or network failure |
| `40` | Synology API or malformed-response failure |
| `41` | Requested ACL principal was not found in a complete DSM inventory |
| `50` | Output or serialization failure |
| `60` | Partial or uncertain mutation outcome |
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

## Apply configuration

`apply-config` reconciles only shares explicitly named in a strict, single-target V1
YAML document; omitted live shares remain untouched. See
[`examples/apply-config-v1.yaml`](examples/apply-config-v1.yaml).

```bash
syn-cli apply-config examples/apply-config-v1.yaml
syn-cli apply-config examples/apply-config-v1.yaml --yes --output json
```

The root must be a mapping with `version: 1` and `volumes`. `host` and
`principal_lookup_share` are optional. `principal_lookup_share`, when supplied, is the
exact name of an existing live share used only for read-only DSM ACL principal inventory;
it cannot be configured as `state: absent`. Each absolute volume path maps to `shares`;
share fields are `name`, `state`, `description`, `quota`, `acl`, and `nfs`. Unknown
fields, duplicate YAML keys, malformed values, duplicate share names, duplicate ACL
identities, and duplicate normalized NFS clients are rejected. `state` defaults to
`present`; `state: absent` permits only `name` and `state`.

`quota` is an integer GiB value in the supported API range. Omitted quota means DSM
unlimited (`0 MiB`) and changes finite quotas to unlimited. Omitted descriptions preserve
an existing description and use an empty description for new shares; an explicit empty
string clears it. Omitted ACLs and `entries: []` clear mutable ACL entries while preserving
`local_group:administrators:read-write`. Omitted NFS and `rules: []` clear all NFS rules.
NFS V1 accepts only these exact DSM `root_squash` tokens and
`security_flavors: [sys]`:

| Token | Verified DSM UI meaning |
| --- | --- |
| `root` | No mapping |
| `admin` | Map root to admin |
| `guest` | Map root to guest |
| `all_admin` | Map all users to admin |
| `all_guest` | Map all users to guest |

These values were verified through read-only DSM `SharePrivilege.load` responses on
named mapping test shares. They are raw DSM v1 values, not Linux NFS aliases:
`no_root_squash`, `none`, `all_squash`, `map_root`, case variants, missing values, and
wrong types are rejected with exit `10` rather than mapped. This DSM target rejected
`no_root_squash` and `none` in prior disposable save tests. Desired Kerberos or
omitted/malformed flavors are also rejected. Read-only `list-shares --permissions`
continues to display valid live Kerberos booleans for inspection, but apply-config fails
closed before writing a managed share whose live NFS state is not exactly `[sys]`.

The non-default mappings alter the identity DSM uses for NFS access. In particular,
`admin` and `all_admin` map access to the administrator identity and are privileged
mappings; `all_admin` and `all_guest` apply to all users, not only root. Dry-run and
apply output warn for every non-default mapping, with additional privileged-mapping
warnings for `admin` and `all_admin`; review the exact plan before supplying the sole
apply confirmation, `--yes`. For Kubernetes NFS clients, prefer a narrowly scoped
client CIDR and `root` unless the workload's UID/GID and required access have been
reviewed; do not select an administrator mapping merely to resolve a container
permission error.

NFS is full-rule replacement: omitted `nfs`, `rules: []`, or an empty desired rule set
removes every NFS client rule for that managed share. Apply-config compares rules without
regard to order, saves the complete replacement, and reads it back. An unknown live DSM
token or malformed live NFS response fails before mutation with exit `40`; a post-save
read-back mismatch is a partial outcome with exit `60`. `list-shares --permissions`
preserves a GUI-created malformed client CIDR as its raw `client:access` value for
inspection, but apply-config refuses to reconcile any managed present share with that
state, including when NFS is omitted or empty, until it is corrected manually.
For nonempty desired ACLs, apply-config validates every requested principal with exact
category-and-name matching before any write. DSM's verified read-only inventory route is
share-scoped, so `principal_lookup_share` should name an approved existing share from
which the inventory can be read. If it is omitted, apply-config uses the lexicographically first configured,
live, non-absent managed share deterministically; it never selects an unconfigured live
share. A new share with ACL entries and no such source fails preflight with code `40`.
The lookup performs no mutation and does not query LDAP directly from the CLI. Incomplete,
unsupported, duplicate, or malformed DSM inventory responses fail with code `40`; a
complete lookup missing an exact requested identity fails with code `41`. Only the implicit
`local_group:administrators:read-write` grant is protected during ACL reconciliation.

Config `host` takes precedence over `--host`, then `SYN_HOST`. Username is `--username`
then `SYN_USERNAME`; password is `--password` then `SYN_PASSWORD`; port remains CLI/default
`5001` and `--insecure` is CLI-only. Credentials, session data, and raw secret values are
not rendered or logged.

Without `--yes`, apply-config authenticates, reads the NAS, performs remote preflight,
and renders a real NAS-backed `mode: dry-run` diff. It performs no writes and exits `0`,
including no-op plans. `--yes` completes the same preflight before any write, applies
serially without a prompt, and verifies changed families by read-back. A failed or uncertain
mutation stops the plan without rollback and exits `60`; inspect the rendered operations,
remediate the NAS, and re-run. Apply-config uses `10`, `20`, `30`, `40`, `41`, `50`, `60`,
and `70` as described above; it never uses local-plan code `11`.
