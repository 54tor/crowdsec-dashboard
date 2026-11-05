# Export and import bundles

The Export / Import page (administrators only) saves the state of an engine into one JSON file, a
bundle, and applies a bundle to an engine, for example to migrate to a new CrowdSec. The engine is
the local one by default; an engine with a usable sidecar can be chosen instead (see
[Remote engines](#remote-engines)). Four sections can be chosen independently: the installed hub
collections, the active bans, the alerts and the configuration files.

## Format

```json
{
  "format": "crowdsec-dashboard-bundle",
  "version": 1,
  "created_at": "2026-11-03T10:00:00Z",
  "engine_version": "v1.x",
  "contains_secrets": false,
  "sections": {
    "hub": {"collections": [{"name": "crowdsecurity/linux", "version": "0.4"}]},
    "decisions": {"decisions": [{"origin": "crowdsec", "type": "ban", "scope": "Ip",
      "value": "203.0.113.7", "scenario": "crowdsecurity/ssh-bf", "until": "2026-11-04T10:00:00Z"}]},
    "alerts": {"alerts": [ ... LAPI alert objects ... ]},
    "config": {"redacted": true, "files": [{"name": "acquis.d/nginx.yaml", "content": "..."}]}
  }
}
```

Each section is optional. A bundle is read strictly: the `format` must match, then the `version`
(only `1`; another one answers `bundle_version`), unknown fields and unknown sections are refused,
nesting deeper than 32 levels is refused, nothing may follow the JSON object, and the bundle is at
most 8 MiB (`bundle_invalid`, `bundle_too_large`). Before the content is decoded, its structure is
counted: any array of more than 5000 elements, or more than 1 500 000 JSON values in all (object
keys not counted), is refused with `bundle_too_large`. Any bundle produced by the export stays
within these bounds: at most 8 MiB holds fewer than 1 500 000 values, and an alert with more than
5000 decisions, events or meta entries in one event is skipped at export (counted in
`X-Bundle-Skipped-Alerts`); the export also checks its own output against both bounds. A future
version of the format gets a new `version` number.

## Export

`POST /api/export` with `{"sections": [...], "include_secrets": false, "strip_events": false}`
([api.md](api.md#sync-export-and-import)) answers the bundle as an attachment named
`crowdsec-bundle-<UTC date>.json`, with `Cache-Control: no-store`. Admin role (a session, or a
`write` token of an administrator).

- **hub**: the installed collections that are not local, with name and version. Other hub item
  types are pulled by the collections.
- **decisions**: the active bans of origin `crowdsec` and `cscli`, with their absolute end
  (`until`, computed from the remaining duration at export time). Left out: community and list
  decisions, other types, bans imported earlier (scenario `import/...`) and the sync copies of this
  dashboard (scenario `sync/...` pushed by its machine `LAPI_MACHINE_ID`). A `sync/` ban pushed by
  another machine is native and exported. At most 5000 bans: if the local engine holds more, or
  its read is incomplete, the export is refused with `bundle_too_large` rather than truncated, so a
  bundle always holds every exportable ban.
- **alerts**: the newest 1000 native alerts found within the newest 3000 alerts read from the local
  engine (CAPI excluded, 16 MiB response bound). The alerts of this dashboard's sync copies
  (scenario `sync/<engine>` pushed by its own machine) are left out, like their decisions; a `sync/`
  alert pushed by another machine is exported. When fewer than 1000 native alerts exist in that
  window, the export holds the ones found; older alerts are not exported. The export is refused
  with `bundle_too_large` only when the alert read exceeds 16 MiB or the encoded bundle exceeds
  8 MiB. Events are included unless `strip_events` is true. Alerts the dashboard cannot decode, and
  alerts the import could not read back (more than 5000 decisions, events, or meta entries in one
  event, counted after `strip_events`), are skipped and counted in the `X-Bundle-Skipped-Alerts`
  response header (always present, `0` when none).
- **config**: the files of the Config page allowlist (`acquis.yaml`, `acquis.d/*.yaml|yml`,
  `profiles.yaml`, `parsers/*/*whitelist*.yaml|yml`, `postoverflows/*/*whitelist*.yaml|yml`), never `config.yaml` nor a file whose name
  contains `credential`, `secret`, `password`, `token`, `apikey`, `api_key`, `.key` or `.pem`. The
  content is **redacted** like the Config page (`"redacted": true`). A file that disappears or turns
  into a symlink during the export is skipped; a file over 256 KiB fails the export with
  `bundle_too_large`.
- **Secrets.** `include_secrets: true` exports the configuration unredacted and marks the bundle
  `contains_secrets: true`. It needs a browser session (a token gets 403 `session_required`) and
  `"confirm_secrets": "SECRETS"` retyped (400 `confirmation_required`). Treat such a file as a
  secret. Without the config section the flag has no effect. On a remote engine it is refused with
  409 `remote_secrets_unsupported` before anything is read: a sidecar only serves masked content.
- The export takes the operation lock shared with the sync and the import (409
  `operation_running`). An unreadable engine version (`cscli version`) fails the whole export with
  an upstream code; there is never a partial bundle.
- Audited `bundle_exported`, target `secrets=<bool> [skipped=<n>] [skipped_files=<n>]
  sections=<list>`, on success only; on a remote engine the target starts with `engine=<name> `.

## Import

Import is a preview, then an apply of exactly what was previewed. `POST /api/import` takes
`{"mode": "preview"|"apply", "bundle": {...}, "sections": [...], "confirm": "IMPORT", "digest": "..."}`
and is **admin and session only**: an API token gets 403 `session_required`, a `read_only` account
403 `forbidden`. The body is at most 8 MiB plus 64 KiB of envelope. The requested sections must
be present in the bundle. Previews and applies take the shared operation lock **before** the body is
read: while another operation runs, the answer is 409 `operation_running` and the bundle is not
read at all.

1. **Preview** returns the plan per section: collections to install, decisions to add, alerts to
   push, configuration files to create or update with a redacted diff, the skipped items with their
   reason and per-section counts, warnings, the unavailable sections with their code, and a
   `digest`. Nothing is written and the preview is not audited. It has 45 seconds (504
   `import_timeout`).
2. **Apply** needs `"confirm": "IMPORT"` (typed by the operator) and the `digest` of the preview.
   It reads the local state again, recomputes the plan and refuses with 409 `import_conflict` when
   the digest differs: re-run the preview. It refuses the whole bundle with 409
   `section_unavailable` when a requested section is unavailable (deselect it), and has at most 10
   minutes.

The **digest** is a SHA-256 over the canonical plan: the sections, the planned collections,
decisions (target, scenario, `until` rounded **down** to the minute), alerts and files (name, new
and current SHA-256), the skipped items, warnings and unavailable sections, and the name of the
target engine when it is not the local one (the local digest is unchanged). Anything that changes
the plan between preview and apply changes it: a ban added or expired meanwhile, a new allowlist
entry, a configuration file edited on disk. The decisions scenario is `import/<UTC date>`, so an
apply after midnight UTC needs a new preview.

Sections are applied in the order hub, config, decisions, alerts. The first section that fails
stops the import: later sections report `not_run`, earlier ones are not rolled back. Each section
reports `applied`, `failed` (with an `error_code`), `not_run` or `section_unavailable`, with
applied, skipped and failed counts. The answer is 200 even when a section failed. Replaying a
bundle is idempotent: what is already there is skipped. Each apply is audited `bundle_imported`,
target `failed=<n> hub=<n> decisions=<n> alerts=<n> config=<n> skipped=<n>` (counts only, never
content; `failed` comes first so that it survives the truncation of long targets). On a remote
engine the target starts with `engine=<name> ` (the engine is kept before the counters by the
64-character truncation).

Limits per apply, beyond which the **whole** bundle is refused with 422 `too_many_changes` (no
truncation; split the bundle): 20 collections, `min(500, SYNC_MAX_CHANGES)` decisions, 500 alerts.
A bundle with more than 5000 decisions or 1000 alerts is refused with `bundle_too_large`.

### Hub

Names are validated at preview (`invalid_name`). A collection already installed (local ones
included) is skipped `already_installed`; a different version gives the warning
`version_mismatch:<name>` and is not forced; a repeated name is `duplicate`. Missing collections are
installed with the allowlisted `cscli collections install <name>`, which downloads them from the
**public CrowdSec hub** (the CrowdSec container needs outbound access). Nothing is ever removed.
CrowdSec is not reloaded: use "Reload CrowdSec" on the Hub page afterwards.

### Decisions

Each ban goes through, in order: a valid target, canonicalised (`invalid_target`), type `ban`
(`unsupported_type`), not expired (`expired`), at most 9999 hours left (`too_long`), the sync sharing
rules (`origin`, `too_short` under 5 minutes, `prefix_too_wide`, `private`, `engine_address` for any
engine of the table, `excluded` for `SHARE_EXCLUDE_CIDRS`; see [sync.md](sync.md#exclusions)), the
own-address guard (`own_address`: the target is, or contains, the address of the browser doing the
import, as resolved for the login rate limiter), duplicates (`duplicate`: an active local ban, native
or copy, or an earlier entry of the bundle, already covers the target with at least the same time
left, give or take one minute), and the local allowlists (`allowlisted`). The bans are planned in
the order of their canonical target, and for the same target the one with the most time left
first: a bundle that holds the same target twice plans the longer ban, and the other one is
`duplicate`. Two spellings of one target are grouped (`203.0.113.5` and `203.0.113.5/32`,
`2001:DB8::1` and `2001:db8::1`).

The local state is read once per plan: the allowlists (fail closed: any error, any 404, more than
10 000 entries makes the section unavailable, `allowlist_unavailable`), the local bans (an
incomplete read or an error makes it unavailable, `local_bans_incomplete`) and the addresses of
every engine (a failed resolution makes it unavailable, `engine_addresses_unknown`). Each
written ban is checked against the allowlists again just before the write. A ban is written like a
manual ban: origin `cscli`, scenario and reason `import/<UTC date>`, duration = `until` minus the
time of the apply. It is then a native ban of the local engine, shared by the sync.

### Alerts

The alerts section ships **enabled**, best effort, with these guards:

- **No effect.** Each alert is pushed with `simulated: true`, `remediation: false`, no labels, and
  exactly one **already expired** marker decision (ban, 1 second, origin `cscli`, scope `Ip` or
  `Range`). An alert that carries a decision is not processed by the profiles, so no new ban is
  created. `too_recent` refuses alerts whose `stop_at` is less than 1 minute old **or in the
  future**, so the marker is always expired.
- **Sources.** Only `Ip` and `Range` sources: Country, AS and other scopes are refused
  (`unsupported_scope`); an unparsable address or range, an empty scenario or unreadable dates are
  `invalid`. Sources overlapping an active local allowlist entry are skipped (`allowlisted`), with
  the same single allowlist read as the decisions section.
- **Duplicates.** The LAPI regenerates the uuid, so an alert is a duplicate when (scenario,
  `start_at`, `stop_at`, source value) matches an alert already stored or earlier in the bundle.
- **Flush guard.** CrowdSec deletes the oldest alerts without an active decision above
  `db_config.flush.max_items`. The limit is read from `config.yaml`, then `config.yaml.local` (its
  value wins; missing file ignored; default 5000 when absent). The section is refused
  (`flush_limit`) when the alerts stored plus those imported would exceed 90 % of it, and
  `flush_config_unreadable` when a file exists but cannot be read or parsed, or the value is not a
  positive integer. The local alerts are read for the count (`local_alerts_unreadable` on failure).
- **Verification.** After the first push of **each distinct scenario** (pushes are reordered so
  these come first), at most 10 verifications per apply, the dashboard reads back the pushed alert
  by the id the LAPI returned. If it carries an active decision other than the expired marker, the
  section stops at once (`alert_import_side_effect`) and those decisions are deleted: only the
  decisions attached to that alert id **and** created by the dashboard's machine account, never
  another ban on the same address. When the alert cannot be attributed (unreadable id, foreign
  machine, unparsable duration) nothing is deleted and the section stops
  (`alert_import_side_effect_unverifiable`). A failed delete counts as failed, gives
  `alert_import_cleanup_failed` and the warning `simulated_decision_may_remain`.
- **Not detected:** profile **notifications** (a notifier plugin reacting to the pushed alert).
  Only decisions are checked.
- **Sanitising.** Control and format characters are removed, invalid UTF-8 dropped, strings capped
  at 256 bytes (message 1024), at most 20 events of 20 meta each (`events_count` keeps the original
  count), times converted to RFC 3339.

### Configuration

Disabled by default (`import_disabled`). It is the only feature that gives the dashboard a write
permission on CrowdSec's configuration, and it is limited to acquisition files:

- Only bundle entries named `acquis.d/<name>.yaml` are imported, into `CONFIG_IMPORT_DIR` only
  (the bundle name `acquis.d/nginx.yaml` becomes `<CONFIG_IMPORT_DIR>/nginx.yaml`). `acquis.yaml`,
  `profiles.yaml`, whitelists, `config.yaml`, `simulation.yaml`, `console.yaml` and any name
  containing `whitelist`, `credential` or `secret` are exported but never imported
  (`forbidden_name`). Names must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.yaml$` (`invalid_name`).
- **Content.** At most 256 KiB (`too_large`); no `[REDACTED]` marker, so a redacted export cannot
  be imported (`redacted_content`); valid YAML without anchors or aliases (`invalid_yaml`).
- **Datasource policy** (operator decision): every YAML document of the file must be a mapping with
  exactly one `source` whose value is `file`, `journalctl` or `docker`; a `transform` key, any
  other source (http, syslog, kafka, s3, loki, appsec, ...), a duplicated or case-variant `source`,
  an explicit YAML tag (`!!binary`, `!custom`, ...), a non-string key and a merge key (`<<`) are
  refused (`forbidden_source`). Write plain YAML. Other acquisition types must be set up by hand.
  Residual reach of the allowed types: a `file` source may name any path readable by CrowdSec in its
  `filenames`, a `docker` source may set `docker_host` to a remote daemon, and `journalctl_filter`
  passes arbitrary `journalctl` arguments (no shell).
- **Preview.** Each file is `created`, `updated` or `unchanged` (identical content: nothing written,
  reported as skipped `unchanged` after the apply), with a diff of the first 200 lines of both
  sides after redaction, capped at 200 lines.
- **Apply.** All files are validated first. Each file is written to a temporary file in the same
  directory, then renamed (atomic per file). Every replaced file is first copied to
  `.dashboard-backup/<UTC timestamp>/` in the import directory (CrowdSec only reads the `*.yaml`
  files directly in `acquis.d`, so neither the backups nor the `.dashboard-tmp-*` files are read). Then `crowdsec -t` (the allowlisted command `config_test`, run in the CrowdSec
  container) validates the whole configuration, which also catches duplicate keys and
  multi-document semantics the dashboard leaves to CrowdSec. On any failure (test failed, missing
  binary, timeout) every replaced file is restored and every created file deleted:
  `config_test_failed`, nothing kept. The test output is never returned or logged by the import.
  CrowdSec is not reloaded: reload it yourself once the import succeeded.
- **Concurrency.** A file changed on disk after the preview gives `import_conflict`; one changed
  between the checks and the rename aborts and rolls back (`config_changed_concurrently`). Imports
  are serialised.
- **Crash recovery.** Before the first rename, a journal `.dashboard-backup/<ts>/.pending` lists the
  created and replaced files. At the next start (only with `CONFIG_IMPORT_ENABLED=true`) a pending
  journal is replayed: replaced files restored from the backup, created files deleted
  (`config_recovered` in the log). A crash after `crowdsec -t` passed but before the journal was
  removed also reverts that import (fail closed). While a journal is pending the section is
  unavailable (`config_recovery_pending`). If a restore fails, the files listed are in
  `config_inconsistent` (see [operations.md](operations.md#config-import-recovery)).
- **Backups** are kept 30 days and purged at start; stale temporary files are removed at start.
- **Ownership.** Created files are mode 0640 owned by the dashboard user (uid 10000 by default); a
  replaced file keeps its mode but takes the dashboard owner. CrowdSec must be able to read them
  (it runs as root in the official image). See [security.md](security.md#configuration-import) for
  the mount and the threat model.

## Remote engines

`POST /api/export?engine=<name>` and `POST /api/import?engine=<name>` run on that engine only; absent
or `engine=local` keeps the local behaviour. The engine is resolved once per request, before the
body is read (for the import, right after the operation lock), with the codes of the
[engine target](api.md#engine-target): 400 `invalid_request`, 404 `engine_not_found`, 409
`engine_has_no_sidecar` (also when the engine has no sidecar or no LAPI client), 409
`engine_target_mismatch`. Every read and write of the request then uses that engine and never
falls back to the local one:

- **Export.** Hub and version through the sidecar (`hub_list`, `version`), bans and alerts from the
  engine's LAPI, configuration through the sidecar's masked file reads (`/v1/files`). The
  configuration is always redacted; `include_secrets` gives 409 `remote_secrets_unsupported`.
- **Import.** Same preview, digest, `IMPORT` confirmation, operation lock, codes and statuses as
  locally. Collections are installed through the sidecar; bans and alerts are written to the
  engine's LAPI after a real read of **that engine's** allowlists (unreadable: the section is
  unavailable with `allowlist_unavailable` and nothing is written). The caller-address and sharing
  rules are the same as locally; the alerts flush limit is read through the sidecar.
- **Configuration import** is always enabled on a sidecar engine (the sidecar decides): files are
  written only by the sidecar's apply (`/v1/config/apply`) into its dedicated `acquis.d`, which runs
  `crowdsec -t` and rolls back itself. The current file is read masked with an opaque digest
  computed by that sidecar: `previous_sha256` in a remote plan is that digest, comparable only with
  another answer of the same sidecar, so an identical file plans as `updated` with an empty diff
  and is reported `unchanged` by the apply. A read-only sidecar (`SIDECAR_READ_ONLY`) refuses the
  apply: the config section fails with `sidecar_command_refused` and the later sections do not run.
- **Digest.** It includes the engine name, so a plan previewed on one engine is refused with 409
  `import_conflict` when applied to another (or to the local engine).

## Codes

HTTP errors of `POST /api/export` and `POST /api/import`:

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_request` | 400 | Malformed body, unknown field, unknown mode, empty, unknown or duplicate section, section absent from the bundle. |
| `bundle_invalid` | 400 | The bundle cannot be decoded: wrong format, unknown field or section, too deep, trailing data. |
| `bundle_version` | 400 | Unsupported bundle version. |
| `bundle_too_large` | 413 | Import: body over 8 MiB, an array of more than 5000 elements, more than 1 500 000 JSON values, more than 5000 decisions or 1000 alerts. Export: more than 5000 bans or an incomplete ban read, alert read over 16 MiB, a config file over 256 KiB, or a bundle over 8 MiB. |
| `confirmation_required` | 400 | Apply without `confirm: "IMPORT"`, or a secrets export without `confirm_secrets: "SECRETS"`. |
| `session_required` | 403 | Import with an API token, or a secrets export with a token. |
| `forbidden` | 403 | `read_only` account or `read` token. |
| `import_conflict` | 409 | The plan changed since the preview (or no digest): run the preview again. |
| `section_unavailable` | 409 | Apply with a requested section unavailable: nothing written. |
| `operation_running` | 409 | A sync run, an export or an import is in progress (an import is refused before its body is read). |
| `too_many_changes` | 422 | More than 20 collections, `min(500, SYNC_MAX_CHANGES)` decisions or 500 alerts to apply. |
| `operation_lock_unavailable` | 503 | No operation lock wired (fail closed). |
| `import_timeout` | 504 | Preview over 45 s, or apply plan over 10 minutes. |
| `lapi_unavailable`, `lapi_error`, `cscli_failed`, `cscli_timeout`, `not_found` | 4xx/5xx | Upstream errors, as elsewhere ([operations.md](operations.md#troubleshooting)). |

Unavailable sections (`unavailable`, with `unavailable_codes` when known):

| Code | Section | Meaning |
|---|---|---|
| `section_unavailable` | any | A dependency is missing or its read failed (hub list; import directory missing, not a directory, not writable, or no config test for config). |
| `allowlist_unavailable` | decisions | The local allowlists are unreadable (fail closed). |
| `engine_addresses_unknown` | decisions | The address of an engine of the table could not be resolved. |
| `local_bans_incomplete` | decisions | The local bans could not be read, or not completely. |
| `dependency_missing` | decisions | A component the decisions import needs is not wired in this server (a build problem: report it). |
| `allowlist_unavailable` | alerts | The local allowlists are unreadable (fail closed). |
| `flush_limit` | alerts | Stored plus imported alerts would exceed 90 % of `flush.max_items`. |
| `flush_config_unreadable` | alerts | `config.yaml` or `config.yaml.local` unreadable, or `max_items` not a positive integer. |
| `local_alerts_unreadable` | alerts | The local alerts could not be counted. |
| `import_disabled` | config | `CONFIG_IMPORT_ENABLED` is false. |
| `config_recovery_pending` | config | A crash-recovery journal is pending. |

Section `error_code` after an apply:

| Code | Meaning |
|---|---|
| `apply_failed` | Generic failure: an I/O or other error that no more specific code describes. |
| `import_timeout`, `canceled` | The apply deadline expired, or the request was cancelled. |
| `lapi_unavailable`, `lapi_error`, `not_found`, `invalid_request`, `cscli_timeout`, `cscli_failed` | Upstream failure while writing. |
| `alert_import_side_effect` | A pushed alert produced a decision: it was deleted and the section stopped. |
| `alert_import_side_effect_unverifiable` | The pushed alert could not be attributed: nothing deleted, section stopped. |
| `alert_import_cleanup_failed` | Deleting such a decision failed (warning `simulated_decision_may_remain`). |
| `config_test_failed` | `crowdsec -t` failed: everything was rolled back. |
| `config_inconsistent` | A rollback could not restore every file: `affected_files` lists them. |
| `config_changed_concurrently` | A file changed on disk during the apply: rolled back. |
| `config_recovery_pending` | A recovery journal appeared: nothing written. |

Skip reasons:

| Reason | Section | Meaning |
|---|---|---|
| `already_installed` | hub | The collection is installed. |
| `invalid_name` | hub, config | The name is refused. |
| `duplicate` | all | Already present locally or repeated in the bundle. |
| `expired`, `too_short`, `too_long` | decisions | Ended, under 5 minutes, over 9999 hours. |
| `unsupported_type`, `origin` | decisions | Not a ban, or not of origin `crowdsec`/`cscli`. |
| `invalid_target`, `prefix_too_wide`, `private`, `engine_address`, `excluded` | decisions | Target refused by the sharing rules. |
| `own_address` | decisions | The target is, or contains, your own address. |
| `allowlisted` | decisions, alerts | Overlaps an active local allowlist entry. |
| `allowlist_unavailable` | decisions | The allowlists were unreadable at the pre-write recheck. |
| `invalid`, `too_recent`, `unsupported_scope` | alerts | See [Alerts](#alerts). |
| `forbidden_name`, `forbidden_source`, `redacted_content`, `invalid_yaml`, `too_large`, `not_regular_file` | config | See [Configuration](#configuration); `not_regular_file`: the current file is a symlink or not a regular file. |
| `unchanged` | config | Identical content, nothing written (apply report). |

Warnings: `version_mismatch:<collection>`, `simulated_decision_may_remain`.

## Known limits

- **The apply runs inside the HTTP request.** A reverse proxy timeout or a closed browser cancels
  it mid-way: the sections already applied stay, the current one stops (`canceled`) and later ones
  do not run. Preview and apply again: a replay is idempotent, and configuration writes are
  journalled and rolled back ([Crash recovery](#configuration)). Give the proxy a read timeout
  above 10 minutes for large imports.
- **The digest does not cover the message and events of the alerts.** Two bundles whose alerts
  differ only there have the same plan.
- **Hub versions are informative.** The preview shows the version of the bundle (and
  `version_mismatch` for an installed one), but `cscli collections install` installs the current
  version of the hub.
- **Bans of origin `dashboard-sync` are never exported**, including the copies pushed by another
  dashboard, although the sync of this dashboard reads them.
