# synology

Manage Synology NAS shared folders through the Synology Web API.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
  - [Credentials and global options](#credentials-and-global-options)
  - [List shares](#list-shares)
  - [List directories](#list-directories)
  - [Remove a directory](#remove-a-directory)
  - [Delete a share](#delete-a-share)
  - [Create a share](#create-a-share)
    - [Create-share options](#create-share-options)
      - [Quota](#quota)
      - [Recycle bin](#recycle-bin)
          - [Compression](#compression)
  - [Add a directory](#add-a-directory)
  - [Modify a share](#modify-a-share)
  - [Config import](#config-import)
  - [Apply configuration](#apply-configuration)
- [Exit codes and remediation](#exit-codes-and-remediation)
- [Continuous integration and releases](#continuous-integration-and-releases)
  - [Container usage](#container-usage)
- [Note](#note)
  - [ACL and share permissions](#acl-and-share-permissions)
  - [NFS client permissions](#nfs-client-permissions)
    - [NFS squash mappings](#nfs-squash-mappings)

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

The packaged command is `syn-cli`. It uses pinned
[N4S4/synology-api](https://github.com/N4S4/synology-api) v0.9.2.

## Usage

### Credentials and global options

Supply required connection values as options or environment variables:

```bash
export SYN_HOST=nas.example.test
export SYN_USERNAME=admin
export SYN_PASSWORD='password-from-secret-injection'

syn-cli list-shares
```

| Option | Default | Description |
| --- | --- | --- |
| `--username` | `SYN_USERNAME` | NAS username |
| `--password` | `SYN_PASSWORD` | NAS password |
| `--host` | `SYN_HOST` | NAS hostname or address |
| `--port` | `5001` | NAS API port |
| `--insecure` | disabled | Disables TLS certificate verification |
| `--verbose` | disabled | Sanitized DEBUG diagnostics on stderr |

CLI options override corresponding environment variables. Global options may appear
before or after the subcommand:

```bash
syn-cli --host nas.example.test --username admin list-shares
syn-cli list-shares --host nas.example.test --username admin
```

Avoid command-line passwords: shell history and process inspection can expose them.
Use environment-based secret injection. Use `--insecure` only for controlled TLS
troubleshooting. Verbose stderr diagnostics redact credentials, tokens, cookies, and
session values.

### List shares

The default output is a table:

```bash
syn-cli list-shares
syn-cli list-shares --output json
syn-cli list-shares --output yaml
```

Tables include `NAME`, `VOLUME`, `DESCRIPTION`, `USB`, and `QUOTA_GIB`. JSON and
YAML also retain UUIDs. DSM quota reads use `share_quota` and return `quota_value`.
JSON and YAML include `quota_gib`, `quota_api_value`, and `quota_api_unit`; a missing
quota displays as `-`.

Use `--permissions` to include active ACL entries from all four categories and one
per-share NFS privilege read. It makes additional sequential reads and never changes
or fetches global NFS settings:

```bash
syn-cli list-shares --permissions
syn-cli list-shares --permissions --output json
syn-cli --verbose --insecure list-shares --output json
```

Permission tables add `PERMISSION` and `NFS-PERMISSIONS`; long values use continuation
lines with blank metadata cells. Entries without active access bits are excluded, while
active entries appear regardless of `is_custom`.

The active protected `local_group:administrators:read-write` ACL is filtered only from
this display, including JSON and YAML. It remains live, reconciled, applied, and
verified. Other ACLs remain visible; protected-only ACLs render as `-` or `[]`.

NFS rows use this format:

```text
client:access,squash=<token>,security_flavors=[<enabled flavors>],async=<bool>,
insecure=<bool>,crossmnt=<bool>
```

Enabled live flavors appear as `sys`, `kerberos`, `kerberos_integrity`, and
`kerberos_privacy` in that order, or `[]`. This read-only display preserves actual
DSM booleans, including GUI-created Kerberos modes. A malformed live client displays
its raw client value and the same fields, but is unsafe for `apply-config`.
That behavior is only for `list-shares --permissions`; create and modify results do
not include unrelated live rules.

Known-empty NFS details serialize as `[]`; unavailable details serialize as `null` and
render as `?` in tables. Diagnostics go to stderr and the command exits `60` while
preserving available rows. Structured output retains UUIDs and full permission/NFS
information without internal observation fields.

### List directories

`list-dirs` performs a read-only NAS lookup and lists every immediate child directory
inside an existing share. It does not recurse and excludes files. Pagination is handled
internally; no pagination options are required.

```bash
syn-cli list-dirs -s projects
syn-cli list-dirs -s projects --output json
syn-cli list-dirs -s projects --output yaml
```

The command returns exit code `0` for an empty or non-empty listing. Authentication,
transport, malformed-response, and missing-share failures use the existing error codes.

### Remove a directory

`rm-dir` removes exactly one empty immediate child directory. It never recurses and
never deletes files. Without `--yes`, it authenticates and performs a read-only
preflight, returning a planned result without deleting anything.

```bash
syn-cli rm-dir -s projects projectA
syn-cli rm-dir -s projects projectA --yes
syn-cli rm-dir -s projects projectA --yes --output json
```

Missing targets, file targets, and non-empty directories fail before mutation with
exit code `10`. If deletion or post-delete verification is uncertain, the command
returns exit code `60`; inspect the NAS before retrying.

### Delete a share

Without `--yes`, deletion validates the exact share name, prints a local plan, avoids
credential resolution/client construction/NAS contact, and exits `11`:

```bash
syn-cli delete-share projects --output json
```

`--yes` is required to mutate the NAS:

```bash
syn-cli delete-share projects --yes
```

The command sends the exact name to `SYNO.Core.Share` delete. It does not preflight or
postflight list shares. Do not blindly retry after a transport timeout: deletion may
have succeeded. DSM determines behavior for contents, special shares, and dependencies.

### Create a share

Without `--yes`, creation validates arguments, prints a local plan, avoids credential
resolution/client construction/NAS contact, and exits `11`:

```bash
syn-cli create-share projects \
  --path /volume1 \
  --description 'Project files'
```

Use structured local-plan output for automation:

```bash
syn-cli create-share projects \
  --path /volume1 \
  --description 'Project files' \
  --quota 100 \
  --output json
```

`--yes` is required to mutate the NAS:

```bash
syn-cli create-share projects \
  --path /volume1 \
  --description 'Project files' \
  --yes
```

`--path` is a NAS volume path, not a local path or final `/volume1/projects` path.
Creation is not idempotent. After a transport timeout, check whether the share exists
before retrying.

#### Create-share options

##### Quota

`--quota` is a positive GiB integer and is converted to DSM MiB (`1 GiB = 1024 MiB`; `5
GiB = 5120 MiB`):

```bash
syn-cli create-share media --path /volume1 --quota 100 --yes
```

##### Recycle bin

Recycle bin defaults to enabled and administrator-only:

```bash
syn-cli create-share shared --path /volume1 --yes
syn-cli create-share temporary --path /volume1 --disable-recycle-bin --yes
syn-cli create-share shared --path /volume1 --recycle-bin-user-access --yes
```

`--disable-recycle-bin` and `--recycle-bin-user-access` cannot be combined.

##### Compression

Request compression when DSM, NAS model, volume, and filesystem support it:

```bash
syn-cli create-share compressed --path /volume1 --compress --yes
```

### Add a directory

`add-dir` creates exactly one child directory in an existing DSM share. It
has no ACL or NFS options: permissions remain those managed by DSM and the parent
share.

```bash
syn-cli add-dir -s projects archives
syn-cli add-dir -s projects archives --yes --output json
```

Without `--yes`, the command authenticates and performs a read-only NAS preflight,
then reports the resolved target path and exits `0`; it never creates, overwrites,
recursively creates, or deletes. If the target already exists, it prints an error and
exits `10`. With `--yes`, it performs the same preflight, creates the directory, and
reads it back before reporting success. Creation is non-idempotent.

DSM Share and FileStation APIs use different path forms internally. The command
checks DSM's FileStation mapping and reports the verified physical NAS path such as
`/volume1/projects/archives`; this mapping is implementation detail, not an
additional path option.

### Modify a share

`modify-share` replaces exactly one family per invocation: quota, ACL, or NFS. It has
no append, removal, selector, or merge mode.

```bash
syn-cli modify-share projects --permission 'local-user:alice:read-write'
syn-cli modify-share projects --permission '' --yes
syn-cli modify-share projects --nfs-permission \
  'client=10.192.10.0/24,access=read-write,root_squash=guest' --yes
syn-cli modify-share projects --nfs-permission '' --yes
syn-cli modify-share projects --quota 0
```

ACL replacement covers local users/groups and LDAP users/groups. DSM updates are
patches, so omitted active non-administrator principals are sent with no access bits to
revoke them; empty lists never signal clearing. Requested principals must exactly match
category and name in the complete DSM inventory before a confirmed ACL write. Inactive
inventory/default rows establish existence but are ignored in reconciliation. This
lookup validation applies to `modify-share`, not `create-share`.

`--permission ''` revokes every active mutable permission, including local administrator
users such as `synadmin`. All local administrator groups are preserved; in particular,
`local_group:administrators` is never cleared. Omit `--permission` to leave ACLs
unselected. Each repeatable ACL option accepts exactly one empty value, not repeated or
mixed with nonempty values.

NFS replacement saves the complete supplied list; `--nfs-permission ''` saves an empty
list. See [NFS squash mappings](#nfs-squash-mappings) for valid tokens; `root_squash`
defaults to `root`. Local validation rejects aliases, case variants, and missing or
empty values. Rules are limited to `security_flavor: [sys]`; Kerberos is unsupported.
Omit `--nfs-permission` to leave NFS unselected. Each repeatable NFS option accepts
exactly one empty value, not repeated or mixed with nonempty values. This command never
changes global NFS service state.

`--quota` accepts a nonnegative GiB integer. Positive values become DSM MiB (`5 GiB` is
`5120 MiB`); `--quota 0` clears the limit and reports `unlimited`. A confirmed update
reads mutable state, skips an exact quota no-op, submits one complete update preserving
known mutable fields, and reads it back to verify quota and preserved state. JSON/YAML
include observed API value and unit; tables show observed GiB or `unlimited`.

Without `--yes`, every modification is a validated local plan: no credentials,
NAS contact, or mutation; exit `11`. ACL plans mark principal existence unverified.
Confirmed ACL, NFS, and quota replacements skip exact no-op writes and verify changed
state. Failed/uncertain writes or verification exit `60` with completed and failed
steps. Do not retry a quota request after transport failure or malformed post-write
response; the NAS may have accepted it and output marks the outcome unknown.

### Config import

`config-import` reads one existing live share with read-only NAS methods and merges it
into an existing strict V1 configuration. It never creates, changes, or deletes a NAS
share.

```bash
syn-cli config-import -c config.yaml projects
syn-cli config-import -c config.yaml projects --yes --output json
```

`-c`/`--config` is required and must name an existing file. By default the command
prints a unified `current-config.yaml` to `proposed-config.yaml` diff and does not
write. `--yes` prints the same diff, then atomically replaces only the local config:
it neither prompts nor mutates the NAS. Table output has the readable diff; JSON/YAML
have metadata and `diff`. The document is always merged and round-trip serialized in
memory. No change means exact serialized equality and never rewrites, even with `--yes`;
retained comments or formatting that create a serialized diff require `--yes`.

Duplicate keys and all present V1 root/managed structures are validated before
credentials or client construction. A valid `version: 1` root without `volumes` is the
sole import exception, allowing import to create `volumes`; every proposal is strict
V1-valid. Import replaces the target node with live description, available quota,
mutable ACLs, and complete supported NFS rules; it omits `quota` when the live share does
not expose quota capability. It creates missing `volumes` or the live volume,
moves a target from another volume, and preserves supported root fields, volumes,
shares, comments, and formatting where possible. The protected exact
`local_group:administrators:read-write` ACL is omitted.

Live quota must be unlimited or a nonnegative, GiB-aligned value within DSM MiB and
supported GiB limits. A malformed/oversized live quota exits `40`. NFS clients must be
valid and NFS security exactly `[sys]`; unsupported or malformed live state aborts
before local write. Config `host` precedes `--host`, then `SYN_HOST`; username/password
remain CLI option then environment. With `--yes`, symlink and non-regular targets are
rejected; the same-directory atomic write preserves target mode and fsyncs
data/directory when supported. Local persistence failures exit `12`.

### Apply configuration

`apply-config` reconciles only named shares in a strict, single-target V1 YAML document;
omitted live shares are untouched. See
[`examples/apply-config-v1.yaml`](examples/apply-config-v1.yaml).

```bash
syn-cli apply-config examples/apply-config-v1.yaml
syn-cli apply-config examples/apply-config-v1.yaml --yes --output json
```

The root is a mapping with `version: 1` and `volumes`; `host` and
`principal_lookup_share` are optional. The latter is the exact existing share used only
for read-only DSM ACL inventory and cannot be `state: absent`. Each absolute volume maps
to `shares`; fields are `name`, `state`, `description`, `quota`, `acl`, `nfs`, and
`directories`. `directories` is an optional managed list of immediate child directory
components. Each item has exactly `name` and optional `state` (`present` by default or
`absent`). Omitted directories and `directories: []` leave all children untouched. A
present item creates a missing directory and leaves an existing directory unchanged; a
file target is rejected. An absent item leaves a missing directory unchanged, deletes
only an empty directory, and rejects files and nonempty directories during preflight.
Directories are not allowed on absent shares. New-share directory targets are
preflighted from the configured volume/share placement before the apply plan mutates
anything; their live File Station mapping is resolved after the share is created.
Unknown fields, duplicate YAML keys,
malformed values, duplicate share names/ACL
identities/normalized NFS clients are rejected. `state` defaults to `present`;
`state: absent` permits only `name` and `state`.

`quota` is an in-range GiB integer. On canonical internal `/volumeN` shares, omitted
quota means unlimited (`0 MiB`) and clears a finite quota. Some noncanonical/external
volumes do not expose quota, compression, or COW capabilities: omitted quota preserves
that unavailable quota, while an explicit quota is rejected before any write. Their
description, ACL, and NFS rules remain managed. Omitted descriptions preserve an existing
description or use empty for a new share; explicit empty clears it. Omitted ACLs and
`entries: []` clear mutable ACLs while preserving
`local_group:administrators:read-write`. Omitted NFS and `rules: []`
clear all NFS rules.

NFS V1 accepts only tokens in [NFS squash mappings](#nfs-squash-mappings) and
`security_flavors: [sys]`. Validation rejects Linux aliases, case variants, missing or
wrong-type values, desired Kerberos, omitted flavors, malformed flavors, malformed
clients, and noncanonical CIDRs with exit `10`. Read-only listing can show live
Kerberos, but apply-config fails closed before writing a managed share whose NFS is not
exactly `[sys]`. Dry-run and apply warn for each non-default mapping, with extra
warnings for privileged `admin` and `all_admin`. For Kubernetes, use a narrow CIDR and
`root`
unless workload access requirements are reviewed; never use an administrator mapping
merely to fix a container permission error.

NFS is full-rule replacement: omitted `nfs`, `rules: []`, or an empty desired set
removes all client rules for that managed share. Rules compare unordered, save as a
complete replacement, and read back. Unknown DSM tokens or malformed live NFS fail
before mutation with `40`; a read-back mismatch exits `60`. Listing preserves a
GUI-created malformed client CIDR as raw `client:access` for inspection, but
apply-config refuses to reconcile a managed present share with it, including an
omitted/empty NFS
configuration, until manual correction.

For nonempty desired ACLs, every principal must exactly match category/name before
writes. DSM's verified inventory is share-scoped, so `principal_lookup_share` should
identify an approved existing source. Otherwise apply-config deterministically uses the
lexicographically first configured, live, non-absent managed share, never an
unconfigured live share. A new share with ACL entries and no source fails preflight with
`40`. Lookup is read-only and never queries LDAP directly. Incomplete, unsupported,
duplicate, or malformed inventory exits `40`; a complete inventory missing an exact
identity exits `41`. Only implicit `local_group:administrators:read-write` is protected
in reconciliation.

Config `host` precedes `--host`, then `SYN_HOST`; username/password are CLI option then
environment. Port is CLI/default `5001`; `--insecure` is CLI-only. Credentials,
sessions, and raw secrets are not rendered or logged.

Without `--yes`, apply-config authenticates, reads the NAS, preflights remotely, and
renders a NAS-backed `mode: dry-run` diff. It performs no writes and exits `0`,
including no-op plans. `--yes` completes that preflight, applies serially without
prompting, and verifies changed families by read-back. Failed or uncertain mutation
stops the plan without rollback and exits `60`; inspect operations, remediate, and
rerun. Apply-config uses `10`, `20`, `30`, `40`, `41`, `50`, `60`, and `70`, never
local-plan code `11`.

## Exit codes and remediation

| Code | Meaning |
| ---: | --- |
| `0` | Success |
| `2` | Command-line syntax or usage error |
| `10` | Configuration or validation failure |
| `11` | Validated local create/delete/modify plan; no NAS contact or mutation |
| `12` | Local config-import persistence failure |
| `20` | Authentication or authorization failure |
| `30` | Transport, TLS, or network failure |
| `40` | Synology API or malformed-response failure |
| `41` | Requested ACL principal absent from complete DSM inventory |
| `50` | Output or serialization failure |
| `60` | Partial or uncertain mutation outcome |
| `70` | Unexpected internal failure |

Capture the code in scripts:

```bash
syn-cli create-share projects --path /volume1
rc=$?
printf 'syn-cli exit code: %s\n' "$rc"
```

For `60`, inspect structured output and DSM. The share may exist while ACL/NFS state is
incomplete or uncertain. Confirm live state, correct it manually or with a targeted
command, and do not automatically delete or retry the share.

## Continuous integration and releases

Pull requests run Ruff and pytest on Python 3.12 in GitHub Actions. Merges to `main`
read `pyproject.toml` version and create its `v<version>` tag. Tags are never
force-updated; conflicting tags fail the workflow.

Tags matching `v*` publish a multi-architecture container image to GitHub Container
Registry. A release such as `v0.1.0` publishes `0.1.0` and `latest`.

### Container usage

```bash
docker pull ghcr.io/initialgyw/synology:latest
docker run --rm ghcr.io/initialgyw/synology:latest --help
```

The image contains only the `syn-cli` entry point. Supply connection values through
environment variables or options. Local `credentials.json` and `config.yaml` are
excluded from the image build context.

## Note

### ACL and share permissions

ACL values are repeatable colon-separated `TYPE:NAME:ACCESS` specifications. Types are
`local-user`, `local-group`, `ldap-user`, and `ldap-group`; access is `read-only`,
`read-write`, or `deny`.

```text
local-user:alice:read-write
local-group:developers:read-only
ldap-user:konri@jumpcloud.com:read-only
```

Names may contain colons: parsing uses the first and final colon, so
`ldap-user:uid=alice:ou=People:read-only` is valid.

Repeat `--permission` for multiple entries. Supplied entries are the complete desired
ACL across supported categories. Permission application follows creation; failure keeps
the share, exits `60`, and does not roll back or retry.

### NFS client permissions

NFS rules are repeatable comma-separated specifications:

```text
client=CLIENT,access=read-only|read-write[,root_squash=CONFIG_STRING]
```

```text
client=10.192.10.20,access=read-write
client=10.192.10.0/24,access=read-write
client=2001:db8::/64,access=read-only
client=*,access=read-only
client=10.192.10.0/24,access=read-write,root_squash=root,async=true,
insecure=true,crossmnt=true
```

`root_squash` is optional and defaults to `root`. Each NFS CLI entry point accepts only
the exact raw DSM v1 tokens in [NFS squash mappings](#nfs-squash-mappings). Local
validation rejects Linux aliases (`no_root_squash`, `none`, `all_squash`, `map_root`),
case variants, empty values, and unknown values rather than translating them. Desired
rules use only `security_flavor: [sys]`; Kerberos cannot be selected or reconciled.
Clients must be canonical IP addresses, CIDRs, or `*`; malformed/noncanonical CIDRs,
including `10.192.10.0/2`, are rejected before client construction or NAS writes.

Defaults are synchronous writes, privileged source ports, no cross-mounts, root
squashing, and AUTH_SYS (`[sys]`). `insecure=true` permits non-privileged ports;
`crossmnt=true` broadens filesystem visibility; `async=true` can reduce durability.
Wildcards and broad CIDRs expose shares widely. Review every non-default mapping,
especially `admin` and `all_admin`.

Global NFS must already be enabled; create-share never changes it. Supplied NFS entries
replace the complete rule set, then save/read back for verification. Post-create failure
or verification mismatch exits `60`, preserves the share, and never rolls back or
retries.

#### NFS squash mappings

| Config String | DSM UI mapping | What it does |
| --- | --- | --- |
| `root` | `No mapping` | Clients keep presented identities. |
| `admin` | `Map root to admin` | Client root acts as NAS admin. |
| `guest` | `Map root to guest` | Client root acts as NAS guest. |
| `all_admin` | `Map all users to admin` | All clients act as NAS admin. |
| `all_guest` | `Map all users to guest` | All clients act as NAS guest. |

- `root` leaves root and non-root client identities presented to DSM; it has no mapping.
- `admin` and `guest` map client root only; non-root clients retain presented
  identities.
- `all_admin` and `all_guest` map root and every non-root client, collapsing identities.
- `admin` and especially `all_admin` are privileged mappings. Broad mappings and client
  ranges increase access risk; choose the least-privileged reviewed option.
- These are client-perspective DSM mappings. They make no claim about undocumented
  UID/GID internals or equivalence to Linux `/etc/exports` aliases.
