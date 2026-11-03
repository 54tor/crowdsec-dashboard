# Operations

## Known limits

| Area | Behaviour |
|---|---|
| Alerts | The 100 most recent alerts of the local LAPI are fetched live, followed by the archive (older local alerts and the alerts of remote engines). Filters (`scenario`, IP/CIDR, `since` such as `24h`, `7d`) are applied by the LAPI inside that cap and by the database on the archive, with different IP scopes (see `docs/api.md`). When the local LAPI is unreachable the archive is still served, flagged `live_status:"unavailable"` (a banner says so and the archive stays paged). Each row shows its engine and a "Live" or "Archived" badge; an engine selector (any role) narrows the list. Pages are counted from `total`; when capped, the total (live window plus up to 10 000 archived rows) is shown with a "+", and paging stops at that reachable range. Archived alerts open a details dialog with their events as plain text; events purged by retention leave an explicit empty state. Only live rows of the `local` engine offer Delete, which also deletes the archived copy. |
| Decisions | Built from the alerts that still have an active decision (same 100-alert window), expired ones dropped, followed by archived decisions still active at collection time, badged "Archived, not active" (the "Show expired decisions" checkbox sends `include_expired=true` for the history). Decisions of the community blocklist (CAPI) are not listed: they are not attached to local alerts. A manual ban shows up as origin `cscli`, scenario `manual/dashboard`. |
| Unban | Deletes one decision by id; the request must carry the `scope` and `value` query parameters. Before deleting, the dashboard looks the id up (among the active decisions of that value, then among the newest 100 alerts): an unknown id answers 404 `not_found`, an id whose scope or value differs answers 409 `target_mismatch`, and nothing is deleted. The archived copy remains, shown "Archived, not active". |
| Hub whitelists | Whitelist files that the hub installs as symlinks are not listed in the Config page; symlinks are never followed. |
| Hub list | At most 1000 items are returned. |
| Hub operations | `update`, `upgrade`, `install` and `remove` can take up to 120 s (others 30 s); the HTTP write deadline is extended to match. Other requests have a 60 s write deadline. |
| Reload | "Reload CrowdSec" sends `SIGHUP` to process 1 of the CrowdSec container, so CrowdSec must be PID 1 (true for the official image). Hub changes need it to take effect; the banner "CrowdSec must be reloaded" appears on the Hub page after a change and is kept in the browser tab only, it disappears on a page reload. Counters of the Metrics page restart at zero after a reload. |
| Metrics | Needs Prometheus enabled in CrowdSec, otherwise "Metrics are unavailable" ([configuration.md](configuration.md#prometheus-for-the-metrics-page)). Only the acquisition and parser tables are shown. |
| Contact status | A bouncer or machine is "stale" after more than 5 minutes without contact. The dashboard's own machine account never sends a heartbeat: it is flagged "This dashboard" and shows no contact status. |
| Health page | One failing source does not blank the page: the response lists it in `degraded` (`version`, `bouncers`, `machines`) and shows the others. It also reports the database, the schema version and the collector of each engine ([Health and metrics](#health-and-metrics)). |
| Sessions | Stored in PostgreSQL, 12 h by default, kept across restarts. The login rate limiter is per process: one replica only. |
| Pending logins | The state between the password step and the second factor (5 minutes, 5 attempts, bound to the client address) is in memory: a restart makes everybody in mid-login start again. The first-account enrolment state is also in memory, with no expiry, and is lost at restart. |
| Second factor | TOTP always; WebAuthn only with `WEBAUTHN_RP_ID` and `WEBAUTHN_RP_ORIGINS`. An administrator resets the factors of an account from the Accounts page ([Account administration](#account-administration)); a user cannot change their own. |
| Access allowlist | No rule means no restriction; any rule means deny by default. Country rules need the GeoLite2 database, otherwise they never match. New IP rules are no broader than IPv4 /8 or IPv6 /16 (400 `prefix_too_broad`); rules stored before that floor keep working. Checked at sign-in, and for every call made with an API token; existing sessions are not cut off. |
| Audit log | Written to `audit_event`; no page to read it. Client addresses are scrubbed after 30 days and rows deleted after 365 days by default ([Retention and purge](#retention-and-purge)); some events are not recorded ([security.md](security.md#audit-log)). |
| Engines | Managed on the Engines page by `admin` accounts only ([Engines and the archive](#engines-and-the-archive)). The collection counters restart with the process, and so does the "History incomplete" notice of the Engines page, which only covers gaps seen by the current process. The persisted flag is in `/api/health` (`collector[].history_incomplete`) and the `csdash_collector_history_incomplete` gauge: it survives restarts and only goes away when the engine is deleted. |
| Roles | Every route that writes to CrowdSec or the archive, creates a LAPI credential, manages engines or accounts, or reads configuration files needs the `admin` role, for a session as for an API token; `read_only` accounts and `read` tokens get 403 `forbidden`, and the interface hides the write buttons for them ([security.md](security.md#roles-and-access)). Your own API tokens (`POST`/`DELETE /api/tokens`), your own allowlist rules and `logout-all` are open to `read_only` accounts too, from a browser session only. |
| Sync | Off by default, dry run by default. Peers are engines of the table marked as sync peers; results stay in memory (lost at restart); runs are sequential per engine and share one lock with exports and imports ([Sync and bundles](#sync-and-bundles), [sync.md](sync.md)). |
| Export / Import | Local engine only. Exports at most 5000 bans and the newest 1000 native alerts; imports at most 20 collections, `min(500, SYNC_MAX_CHANGES)` decisions and 500 alerts per apply; config import of `acquis.d` files only, off by default ([bundles.md](bundles.md)). |
| Prometheus | `GET /api/prometheus/metrics` accepts a session or an API token of any scope; give Prometheus a `read` token. There is no anonymous scrape ([Health and metrics](#health-and-metrics)). |

## Troubleshooting

Errors reach the UI as a stable code (`{"error": "<code>"}`), translated in the interface.

| Code | HTTP | Meaning and what to check |
|---|---|---|
| `unauthenticated` | 401 | No or expired session. Sign in again. |
| `invalid_credentials` | 401 | Wrong account name or password (the two are not distinguished). |
| `database_unavailable` | 503 | PostgreSQL unreachable or failing. Check the `postgres` service and `DATABASE_URL`; the interface keeps the session and recovers when the database is back. |
| `invalid_enrollment_token` | 403 | Wrong enrolment token. Use the one of the latest start ([First start and enrolment](#first-start-and-enrolment)). |
| `invalid_account_name`, `invalid_password_length` | 400 | Enrolment: name not matching `^[a-z0-9][a-z0-9._-]{0,63}$`, or password outside 12 to 128 characters. |
| `pending_login_expired` | 401 | The pending login (cookie `pending_login`) is missing, older than 5 minutes, used up (5 attempts, success or lock), already consumed, from another client address, or lost in a restart. Sign in again from the password. |
| `invalid_code` | 401 | Wrong TOTP code or recovery code at login (also 400 at setup for a wrong confirmation code). Check the phone clock; a code can be used once. Counts toward the lockout. |
| `webauthn_failed` | 401 | Passkey assertion refused: wrong origin or relying party, expired or reused challenge, unknown credential, or a counter that did not increase. Counts toward the lockout at login. |
| `webauthn_disabled` | 404 | `WEBAUTHN_RP_ID` and `WEBAUTHN_RP_ORIGINS` are not set. |
| `account_locked` | 423 | Five second-factor failures. The response carries `Retry-After` in seconds; the lock lasts 15 minutes. To unlock now: [Unlocking an account](#unlocking-an-account). |
| `access_denied` | 403 | The password and factor were right but the account's allowlist does not admit this address or country. With a country rule, check that the GeoLite2 database is present ([Dashboard image](#dashboard-image)). Fix it by SQL: [Removing an allowlist](#removing-an-allowlist). |
| `second_factor_setup_not_allowed` | 403 | The account has no second factor and its setup window is closed. An administrator reopens it with "Reset second factor" ([Account administration](#account-administration)), or by SQL: [Reopening the setup window](#reopening-the-setup-window). |
| `second_factor_required` | 409 | Enrolment or setup was completed before a factor was confirmed and the recovery codes were generated. |
| `enrollment_not_started` | 409 | An enrolment step came before `POST /api/auth/enroll`, or the dashboard restarted since. Start again with the token from the new log. |
| `second_factor_unavailable` | 503 | A TOTP key or recovery codes could not be generated; the dashboard log has the cause. |
| `too_many_pending_logins` | 503 | 10 000 logins are waiting for their second factor; retry shortly. |
| `invalid_access_rule`, `access_rule_exists` | 400, 409 | Allowlist rule malformed (kind `ip` or `country`, `/0` refused) or already present. |
| `prefix_too_broad` | 400 | A new IP rule is broader than IPv4 /8 or IPv6 /16. Use a narrower prefix; rules stored earlier are not affected. |
| `would_lock_out_current_client` | 409 | The change would stop your current address from signing in. Add an IP rule for it first, or use the SQL procedure from the host. |
| `geolocation_unavailable` | 409 | A country rule was added while no readable GeoLite2 database is loaded. |
| `too_many_attempts` | 429 | Login rate limit or concurrency cap. Wait a minute (the response carries `Retry-After: 60`). If everybody is limited, the proxy address is probably not in `TRUSTED_PROXY_CIDRS` and all users share one client address. |
| `cross_origin` | 403 | A state-changing request came from another origin. Check that the reverse proxy forwards `Host` and does not rewrite `Origin`. |
| `invalid_request` | 400 | Malformed body, id or filter. |
| `invalid_target`, `invalid_duration`, `invalid_reason` | 400 | Ban form: not an IP/CIDR (or range wider than /8 IPv4, /32 IPv6), duration not like `24h`, reason over 200 characters or with control characters. |
| `confirmation_required` | 400 | A delete request did not repeat the target in `confirm`. |
| `self_account` | 409 | You tried to delete the dashboard's own LAPI machine. |
| `self_ban` | 409 | The ban target is, or its range contains, the address you are connected from (as seen by the dashboard; behind a proxy, set `TRUSTED_PROXY_CIDRS`). Ask another admin or use `cscli decisions add` on the host. |
| `not_found` | 404 | Unknown API route, configuration file not on the allowlist, or enrolment already closed (an account exists). |
| `file_too_large` | 413 | A configuration file is over 256 KiB. |
| `config_unavailable` | 500 | `CROWDSEC_CONF_DIR` is missing or unreadable. Check the read-only mount. |
| `lapi_unavailable` | 502 | LAPI unreachable, answered 5xx, or refused the machine login. Check `LAPI_URL`, the machine name and password, and that the machine is validated. |
| `lapi_error` | 502 | The LAPI answered with an unexpected 4xx (including 403). Check the machine account. |
| `cscli_failed` | 502 | The exec failed: Docker unreachable, CrowdSec container not running or misnamed, socket proxy denying the call, `cscli` exited non-zero (for example an unknown collection or machine), or output could not be parsed. Look at the socket proxy log first. |
| `forbidden` | 403 | The action needs the `admin` role: every write, bouncer and machine creation, hub change, engine and account management, and configuration files. A `read` API token is always refused on those routes. |
| `session_required` | 403 | The route accepts a browser session only (token management, account administration, engine writes, allowlist rules, `logout-all`); an `Authorization: Bearer` call is refused even with a `write` token. |
| `invalid_token` | 401 | The `Authorization: Bearer` value is not a valid API token: unknown, revoked, expired, or not starting with `csd_`. A Bearer header never falls back to the session cookie. |
| `token_denied` | 403 | The token is valid but its account is locked or the calling address is refused by the account's allowlist. Behind a proxy without `TRUSTED_PROXY_CIDRS`, the proxy address is the one evaluated. A new allowlist rule can take up to a minute to apply to tokens. |
| `scope_not_allowed` | 403 | A `write` token was requested by a `read_only` account. |
| `token_name_taken` | 409 | A token of the account that is not revoked already has this name. An expired token that was not revoked still holds its name: revoke it to reuse the name. |
| `invalid_token_name`, `invalid_expiry` | 400 | Token name empty, over 64 characters or with control characters; `expires_in_days` outside 1 to 365. |
| `account_exists` | 409 | An account with this name already exists. |
| `invalid_role` | 400 | `account_role` is neither `admin` nor `read_only`. |
| `last_admin` | 409 | The change would remove the last `admin` (demotion or deletion). Create or promote another administrator first. |
| `cannot_delete_own_account` | 409 | An administrator tried to delete the account they are signed in with. Another administrator must delete it. |
| `engine_deleting` | 409 | A create used the name or URL of an engine whose archive is still being deleted. Retry once the deletion has finished (see [Engines and the archive](#engines-and-the-archive)). |
| `target_mismatch` | 409 | The alert or decision id now designates another target (different uuid, scope or value): the list was stale or the LAPI was reset. Reload the page. |
| `engine_exists`, `engine_not_found`, `invalid_engine` | 409, 404, 400 | Engine name or URL already used, unknown engine (an engine being deleted counts as unknown), or a field refused (name, URL scheme without `allow_insecure_http`, credentials or forbidden address in a URL, proxy kind). |
| `engine_local_readonly` | 409 | The `local` engine comes from `LAPI_URL` and cannot be changed or deleted from the API. |
| `engine_secret_required` | 400 | The destination changed: re-enter the machine password (and the proxy credentials) in the same request. |
| `engine_unreachable` | 502 | No answer from the engine or its proxy, a timeout, an answer that is not a LAPI login, or an answer over the size limit. Check the URL, the port, the proxy and the network between the dashboard and the engine. |
| `engine_auth_failed` | 502 | The engine refused the machine login: check the machine id and password with `cscli machines list` on that engine, and that the machine is validated. |
| `engine_blocked_address` | 502 | The address (or the proxy address) resolved to a forbidden range ([security.md](security.md#engines-and-outbound-connections)). |
| `engine_secret_unreadable` | engine status | The stored secret cannot be decrypted with the current secrets key (key changed or row restored from another installation): edit the engine and re-enter the secrets. The engine is left out of collection meanwhile. |
| `archive_write_failed` | engine status | The archive write failed (database). The engine is retried with backoff. |
| `cscli_timeout` | 504 | The command exceeded 30 s (120 s for hub operations). Retry; check the network of the CrowdSec container for hub calls. |
| `operation_running` | 409 | A sync run, an export or an import is already in progress (one lock for the three; an import is refused before its body is read). Wait for it; the Sync page shows a running run. |
| `operation_lock_unavailable` | 503 | Export or import refused because no operation lock is wired (fail closed). A build or startup problem: report it. |
| `sync_disabled` | 409 | "Sync now" while `SYNC_ENABLED` is false. |
| `sync_guard_tripped` | engine status | An `expected_changes` override was refused: the recomputed plan exceeds the expected count by more than 10 %. |
| `engine_addresses_unknown` | engine status | The host of an enabled engine could not be resolved (or the engine table could not be listed): the whole run was skipped, nothing written. Fix or disable that engine ([Sync and bundles](#sync-and-bundles)). |
| `engine_backoff` | engine status | The engine failed recently; scheduled runs skip it for a doubling delay (at most 1 h). "Sync now" still tries it. |
| `run_deadline`, `canceled`, `run_panicked` | run, engine status | The run hit its 10 minute deadline, was stopped by a shutdown, or an internal error stopped it; the next run starts afresh. Shown in a notice at the top of the Sync page (`error_code` of `GET /api/sync`), copied onto every engine row without a code of its own, and first in the `sync_run` audit target (`err=<code>`). |
| `engine_unavailable` | engine status | A participating engine is missing from the engine registry (secret unreadable, or a registry reload in progress): nothing is written to it and its copies on the other engines are kept. Fix the engine on the Engines page (see `engine_secret_unreadable`). |
| `bundle_invalid`, `bundle_version` | 400 | The file is not a dashboard bundle of version 1, or holds unknown fields or sections, or is too deeply nested. |
| `bundle_too_large` | 413 | Import over 8 MiB, with an array of more than 5000 elements, more than 1 500 000 JSON values, over 5000 decisions or 1000 alerts; export over 5000 bans, an incomplete ban read, an alert read over 16 MiB or a bundle over 8 MiB. Export fewer sections. |
| `import_conflict` | 409 | The local state changed since the preview (a ban, an allowlist entry, a file), or the preview was made before midnight UTC: run the preview again. |
| `section_unavailable` | 409 | A selected section cannot be applied (see its code in the preview): deselect it or fix the cause. |
| `too_many_changes` | 422 | More than 20 collections, `min(500, SYNC_MAX_CHANGES)` decisions or 500 alerts to apply: split the bundle. |
| `import_timeout` | 504 | The preview took over 45 s, or the apply plan over 10 minutes. Retry; check the LAPI. |
| `import_disabled` | section | `CONFIG_IMPORT_ENABLED` is false ([configuration.md](configuration.md#config-import-mount)). |
| `config_test_failed` | section | `crowdsec -t` refused the imported acquisition files: everything was rolled back. Fix the file and import again. |
| `config_inconsistent` | section, log | A rollback or a startup recovery could not restore every file ([Config import recovery](#config-import-recovery)). |
| `config_recovery_pending` | section | An interrupted import awaits recovery ([Config import recovery](#config-import-recovery)). |
| `config_changed_concurrently` | section | A file of the import directory changed during the apply: rolled back. Preview again. |
| `flush_limit`, `flush_config_unreadable`, `local_alerts_unreadable` | section | Alerts import refused: the import would push CrowdSec over 90 % of `flush.max_items`, that setting cannot be read, or the local alerts cannot be counted ([bundles.md](bundles.md#alerts)). |
| `alert_import_side_effect`, `alert_import_side_effect_unverifiable`, `alert_import_cleanup_failed` | section | An imported alert produced a decision (deleted), could not be verified, or its cleanup failed: check `cscli decisions list` for that address. |
| `allowlist_unavailable` | engine status, section | The allowlists of the engine could not be read (error, any 404, more than 10 000 entries): nothing is written to it. |
| `local_bans_incomplete`, `dependency_missing` | section | Decisions import unavailable: the local bans could not be read completely, or a component of the decisions import is not wired (report it). `engine_addresses_unknown` and `allowlist_unavailable` can also make that section unavailable ([bundles.md](bundles.md#codes)). |

Quick checks:

- Reverse proxy timeouts: hub operations (update, upgrade, install, remove) may take up to 135 s,
  so the proxy's read and send timeouts must exceed that. nginx: `proxy_read_timeout 150s;
  proxy_send_timeout 150s;` (the default 60 s cuts them). Traefik: `respondingTimeouts.readTimeout`
  and `writeTimeout` on the entry point, or `forwardingTimeouts.responseHeaderTimeout`, above 150 s.
- Server-side failures are logged by the dashboard (`docker logs`): a line `upstream error: class=...`
  with the error class and, for known failures, the exit code or status. Command output is never logged.

- Socket proxy denies: its log prints `blocked request` with the path. A pair of `HEAD /_ping` 405 and
  `GET /_ping` 403 lines at each exec is normal: the Docker client probes the API version and falls
  back. Anything else means the allow rules or `-allowfrom` do not match the real container names.
- The proxy resolves `-allowfrom` by container name, so start order does not matter and recreating
  the dashboard container needs no proxy restart.
- `GET /api/healthz` answers 200 without a session when PostgreSQL answers a ping, 503 otherwise, for container health checks. The detailed state is `GET /api/health` ([Health and metrics](#health-and-metrics)).
- Metrics page empty after a reload: counters restart at zero until new log lines are read.

## PostgreSQL

The dashboard needs a PostgreSQL server (the `postgres` service of `deploy/compose.example.yaml`,
configured by `postgres.env`, data in the `postgres-data` volume). The dashboard container starts
after the database is healthy.

- At every start it opens the database, applies the pending schema migrations automatically and only
  then serves requests. It refuses to start if `DATABASE_URL` is missing or unreachable, or if a
  migration fails: read the container log.
- Back up the database before upgrading the dashboard to a new version, since an upgrade may migrate
  the schema ([Backup and restore](#backup-and-restore)). The upgrade that introduces the second factor applies migration 00002 at the next
  start: it adds the factor, recovery code, allowlist and lockout columns and tables, and opens the
  second-factor setup window of every existing account (see
  [security.md](security.md#accounts-from-the-first-release)). The dashboard also needs the secrets
  key before that start ([Secrets key](#secrets-key)). Sign in right after upgrading to enrol
  your factor.
- The hardening release adds migrations 00004 (API token constraints and indexes), 00005 (archive
  ordering indexes and the persisted `engine_history_incomplete` flag) and 00006 (`engine_deleting_at`).
  None of them was applied anywhere before this release: they run together at the next start, so back
  up first and let that start apply all three. 00005 builds two indexes on `alert` without
  `CONCURRENTLY`, inside the fixed 60 s start-up timeout (not configurable): on a very large archive
  that first start can time out and the dashboard then exits. The same start reseals the engine secrets that still use
  the former associated data ([Rotating the secrets key](#rotating-the-secrets-key)).
- If PostgreSQL goes down while the dashboard runs, `/api/healthz` answers 503 and login and
  authenticated routes answer 503 `database_unavailable`. Nobody is signed out: sessions are valid
  again once the database is back.
- Major upgrade trap: since PostgreSQL 18 the image keeps data in `/var/lib/postgresql/<major>/docker`,
  so a `docker compose pull` that crosses a major version initialises a new empty cluster beside the
  old one. A major upgrade is a dump, a pull and a restore: note the running major
  (`SELECT version()`), take a dump with `deploy/backup.sh` **before** pulling, pull and start the
  new PostgreSQL, then restore the dump with `deploy/restore.sh` ([Backup and restore](#backup-and-restore)).
  If the dashboard log shows an enrolment token after an upgrade, the cluster is empty: stop the
  dashboard, do not enrol, and restore the dump.

## First start and enrolment

1. Create the secrets key (once) and, optionally, the MaxMind files ([Secrets key](#secrets-key),
   [Dashboard image](#dashboard-image)). Fill `dashboard.env` and `postgres.env` from the examples
   and start the stack.
2. While the `account` table is empty, the dashboard logs a line such as
   `no account yet: open /enroll and enroll the first account with token <token>`
   (`docker logs <dashboard container>`). The token lives in memory only and is replaced at each
   restart while no account exists.
3. Open `https://<your host>/enroll`, enter the token, an account name and a password of 12 to 128
   characters.
4. Add a second factor: scan the QR code (or type the secret) in an authenticator app and enter a
   code, or register a passkey when WebAuthn is enabled. Then save the 10 recovery codes: they are
   shown once. Only when you confirm are the account, its factor and its recovery codes written.
   The first account is an administrator and is signed in at once.
5. From then on enrolment is closed (`POST /api/auth/enroll` answers 404) and no token is logged.

If the dashboard restarts between steps 3 and 4, the work in progress is lost and nothing was
created: use the new token from the log.

Whoever can read the logs while no account exists can create the first account: enrol promptly and
keep the logs private ([security.md](security.md#accounts-and-enrolment)). The development stack
(`deploy/dev/up.sh`) prints the token for you.

Signing in afterwards: password, then a TOTP code (or a passkey, or a recovery code), then the
allowlist if you defined one. Accounts that existed before the second factor are asked to enrol one
at their next login; see [security.md](security.md#accounts-from-the-first-release).

## Secrets key

The key that encrypts the TOTP secrets is a 32-byte random value, base64 encoded, in a file given to
the container as the compose secret `dashboard-secrets-key`:

```
install -d -m 0700 secrets && (umask 077; openssl rand -base64 32 > secrets/dashboard-secrets.key)
```

At start, `25-secrets-key` copies it to `/run/dashboard-secrets/key` on a tmpfs (0400, owned by
`docker-user`), which `SECRETS_KEY_FILE` names. The container stops at start when the secret is
missing, unreadable or empty, and the dashboard refuses to start when the copy is not a valid key.

- **Back the key up separately from the database dump.** A database backup alone is useless for
  TOTP without the key, and a backup that sits next to the key defeats the encryption.
- **If the key is lost, the TOTP secrets are unreadable** and TOTP logins fail for everybody.
  Passwords, passkeys and recovery codes keep working, so recovery codes or a passkey are the way
  back in; then reset the TOTP factors by SQL (see
  [Resetting a lost factor](#resetting-a-lost-factor)) and enrol again.
- Do not replace the key by editing the file in place: the rows are identified by the `key_id` of
  the key that sealed them, and the dashboard refuses to start when one of them uses a key it does not
  hold. To change the key, follow [Rotating the secrets key](#rotating-the-secrets-key).
- The engine secrets (machine password, proxy credentials) are sealed with the same key.

## Rotating the secrets key

The TOTP secrets and the engine secrets (machine passwords, proxy credentials) are sealed with the key
of [Secrets key](#secrets-key). Rotate it when it may have leaked, or on your own schedule. Two
restarts are needed, and nothing is lost if you stop between them.

1. Generate the new key file next to the old one (same command as for the first key, another file name).
2. In the compose file, make the new file the `dashboard-secrets-key` secret and add the old file as a
   second secret, `dashboard-secrets-key-retired`, by uncommenting the four places of
   `deploy/compose.example.yaml`: the two environment lines
   `SECRETS_RETIRED_KEY_SOURCES: /run/secrets/dashboard-secrets-key-retired` (comma-separated, no
   spaces, when there are several) and `SECRETS_RETIRED_KEY_FILES: /run/dashboard-secrets/retired-1`,
   the `dashboard-secrets-key-retired` entry in the dashboard service's `secrets` list, and the
   `dashboard-secrets-key-retired` block under the top-level `secrets`. The `25-secrets-key` script reads the sources and copies them in
   order to `/run/dashboard-secrets/retired-1`, `retired-2`, and so on; the dashboard reads those
   copies through `SECRETS_RETIRED_KEY_FILES`, in the same order.
3. Recreate the dashboard (**first restart**). At start it applies pending migrations, then refuses to
   start when a stored secret uses a key id that is neither the current key nor a retired one, and the
   log lists the missing key ids. New secrets are sealed with the new key; old ones stay readable.
4. Count what has to move: `docker compose exec -u docker-user dashboard dashboard rotate-secrets -dry-run`.
   It prints, per column, the number of rows per key id and writes nothing. The command needs the
   restart of step 3 (migrations must have run). The server keeps serving meanwhile.
5. Rewrite the rows: the same command without `-dry-run`. Rows are rewritten in batches of 500, each
   one only if it did not change meanwhile; run the command again when it reports `skipped_concurrent`
   other than 0. A row that cannot be opened (corrupt, or copied from another account or engine) is
   skipped and its id is printed as `unreadable row ids`; the other rows are still rewritten, and the
   command exits non-zero at the end, dry run included. Look at those rows before going on. A real
   run records the audit event `secrets_rotated` (target: the number of rows rewritten).
6. Run `-dry-run` once more: only the current key id must remain.
7. Remove the retired secret, `SECRETS_RETIRED_KEY_SOURCES` and `SECRETS_RETIRED_KEY_FILES` from the
   compose file and recreate the dashboard (**second restart**).

Keep the old key file for as long as you keep database backups taken before the rotation: restoring
such a backup brings back rows sealed with it, and the dashboard refuses to start until the old key
is given again as a retired key. Engines being deleted are ignored by the key check and by the rotation.

Engine secrets are also bound to the engine they belong to: the engine id and its destination (scheme,
host and port of the LAPI URL; for the proxy credentials also the proxy kind and URL). At start the
dashboard reseals the rows that still use the older, id-only form (a restored pre-hardening backup
included), and logs `engine secrets reseal: ...` with counts and the ids of engines it could not open
(`engine_secret_unreadable`: edit the engine and re-enter its secrets). The id-only form is still
read, so that window only closes for good when you rotate to a new key and drop the old one (see
[security.md](security.md#encryption-of-secrets)).

## Dashboard image

The dashboard image is Alpine with s6-overlay (init and supervisor), not distroless. s6 supervises
two services in one container: the dashboard, which runs as the unprivileged `docker-user`
(UID/GID 10000), and a cron service (supercronic) that runs `geoipupdate`. The container is
started as root so the init scripts can run; the hardening and its reasons are in
[security.md](security.md#container-image). Points to know when operating it:

- **Compose settings are not optional**: `read_only: true` with the three tmpfs of the example
  (`/run` with `exec` and mode `0755`, `/etc/cron.d` with mode `0755`, `/tmp`), `S6_READ_ONLY_ROOT: "1"`,
  `cap_drop: [ALL]` and `cap_add: [CHOWN, DAC_READ_SEARCH, KILL, SETGID, SETUID]`. A `/run` mounted
  with Docker's default tmpfs options (`noexec`, mode 1777) makes s6 fail. The startup scripts stop
  the container on failure (`S6_BEHAVIOUR_IF_STAGE2_FAILS=2`), except `30-geoipupdate`, which never
  fails the start.
- **UID remap**: `DOCKER_USER_UID` / `DOCKER_USER_GID` work only with a writable root filesystem.
  They edit `/etc/passwd` and `/etc/group`; with `read_only: true` the container stops with
  `groupmod` failing. Set `read_only: false` if you must remap, or keep the default 10000 and
  `chown` your volumes.
- **WAIT_FOR_NETWORK**: the image waits for `1.1.1.1:443` for up to 15 s by default and then
  continues; the example compose sets `WAIT_FOR_NETWORK: "false"` because the database is already
  awaited by `depends_on` (see [configuration.md](configuration.md#environment-variables)).
- **Hooks**: executable files in `/custom-scripts.d` and `/docker-entrypoint.d` run as root at
  start. Both directories are root-owned; add scripts by mounting them read-only.
- **GeoLite2 updates**: `geoipupdate` is compiled from source in the image (no Alpine package) and
  scheduled by cron inside the dashboard container, as `docker-user`. You need a free MaxMind
  account. Put the account id and the licence key in the compose secrets `maxmind-account-id` and
  `maxmind-license-key` ([configuration.md](configuration.md#maxmind-credentials)). Without both
  files, or with malformed values, no cron entry is created and the log says
  `GeoLite2 updates are disabled`; the dashboard then runs without country rules. The database is
  stored in the `geoip-data` volume as `GeoLite2-Country.mmdb`, with the frequency of
  `GEOIPUPDATE_FREQUENCY_HOURS`.
- **First download**: at start, when the cron entry exists and the database file is missing or
  empty, the cron service launches one update immediately, in the background. If the database file
  is not empty but corrupt, no immediate update runs: the first fetch waits for the next
  scheduled run (minute 17 of the scheduled hour). Delete the bad file and restart to fetch at
  once. The dashboard keeps ignoring an unreadable file and logs `geolocation database ... is not
  readable yet`; country rules are refused meanwhile. It also logs a warning when the database is
  older than 45 days.
- **Check it**: `docker logs <dashboard container>` shows `[geoipupdate] GeoLite2 updates scheduled at
  '<cron expression>'` and, after a failed run, `update failed with status N`. Updates need outbound
  access to `updates.maxmind.com` over HTTPS from the dashboard container, so it needs at least one
  network that is not `internal` (in the example, `crowdsec` or `web`).

This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com.

## Engines and the archive

The `local` engine row is created or updated at start from `LAPI_URL` and `LAPI_MACHINE_ID` (no
password stored: it uses `LAPI_MACHINE_PASSWORD`). Remote engines are added on the Engines page;
each needs a machine account on that engine (`cscli machines add <name> --password <password>`,
validated). "Test connection" logs in once and reports the outcome only.

**Collector.** Every `COLLECTOR_INTERVAL` (default 1 min), each enabled engine is read
independently: a slow or failing engine never delays the others and is retried with exponential
backoff (at most 1 h). The cursor is the highest upstream alert id archived for the engine, stored
in the database and read again at each collection. The first collection reads the whole history
(at most 16 MiB and 120 s); later ones read the newest `COLLECTOR_POLL_LIMIT` alerts and only
archive the ones above the cursor. Alerts from the community blocklist (CAPI) are not archived.
The first import is written in chunks of 64 alerts, oldest first, one transaction and one cursor update per chunk, so an interrupted import resumes after its last chunk; at most two full reads run at the same time, so many engines do not all read their history at start. Duplicates are impossible: an alert is keyed by engine, upstream id and upstream uuid. Each
collection updates `last_collected_at` (last success) and `last_error_code` in the `engine` row;
the counters (`inserted`, `duplicates`, `skipped`, `gaps`, `resets`) live in memory. An alert that
cannot be stored (for example a meta value that is not a string, or a value the database refuses)
is skipped and counted, and the next valid alert is still archived. Events are bounded per alert
(see [security.md](security.md#engines-and-outbound-connections)); an alert whose events or meta
were cut has `events_truncated:true` in its detail; this includes a meta key cut to a length that
collides with an earlier key.

**History incomplete.** When the newest alerts read do not reach back to the cursor (more new
alerts than the poll limit since the last collection), the collector reads the whole history
again; if that read is truncated or too slow it archives what the poll returned, counts a gap
and the Engines page shows "History incomplete". That notice comes from the in-memory `gaps` counter,
so it only covers the current process and disappears at restart. Some alerts of that window may never
be archived if the engine purged them meanwhile. The lasting record is the flag stored in the `engine`
row (`engine_history_incomplete`): it survives restarts, is visible in `GET /api/health`
(`collector[].history_incomplete`) and is exported as the `csdash_collector_history_incomplete` gauge.
It describes the stored archive, so nothing clears it except deleting the engine; if it fires for good,
treat it as known. Lower the interval or raise `COLLECTOR_POLL_LIMIT` for busy engines.

**Engine flush.** CrowdSec purges its own alerts (`db_config.flush.max_items`, `max_age`, checked
every minute). It keeps the newest `max_items + 1` alerts and never purges an alert that still has
an active decision; the dashboard archive keeps them all, within the archive retention. Measured on
the demo engine (`max_items: 20`): 43 alerts pushed, 21 left on the engine after the flush, 43 in
the archive.

**Engine reset.** If an engine's database is recreated, its alert ids restart at 1. The collector
detects it (an id it already holds with another uuid, or a newest id below the cursor while none of
the received alerts is already archived), sets the cursor back to 0 and counts a `reset`; nothing
is duplicated and the old alerts stay in the archive. Residual case: when every alert the engine
still serves has already left the archive by retention and its newest alert was deleted, a reset
is assumed wrongly and that window is archived once more (purged again by retention). Re-archiving after a reset gives the old alerts a new collection time, hence a fresh retention period. If an engine's database is reset while the dashboard is not running and its new ids exceed the old cursor, the reset goes undetected and the alerts in between are never archived: the gap is silent and not counted. Changing the
host, port or scheme of an engine's URL also resets its cursor, and the reset is counted in `resets`.

**Dates.** An archived alert whose engine date (`created_at`) is missing, unparseable or in the future is dated by its collection time, so a skewed engine clock cannot pin its alerts at the top of the lists.

**Retention.** Archived alerts, decisions and events are purged hourly by collection age
([configuration.md](configuration.md#environment-variables)). Decisions still active on the engine
are never purged, and the alert that owns one is kept until that decision expires. Alerts purged from the archive are
not collected again while the engine still serves them (they are below the cursor).

**Deleting an engine deletes its archive** (alerts, events and decisions), after the name is
retyped. The request answers 202 `{"status":"deleting"}` without waiting for the archive deletion;
it can first wait, up to the collector's store timeout (120 s), while a running collection of that
engine holds its row lock. Then the engine row is marked
(`engine_deleting_at`), disappears from the Engines page, the engine filters, the collector and the
archive lists, and a background job deletes its alerts in batches, then the row. The job is resumed at
every start and every hour if a restart or an error interrupted it. While it runs, creating an engine
with the same name or URL answers 409 `engine_deleting`. To stop collecting and keep the archive,
disable the engine instead.

**Deleting alerts.** Delete on a live local alert removes it from the LAPI (`cscli alerts delete`)
and its archived copy in the same request, so it does not come back from the archive.
Unbanning a live local decision leaves its archived copy, shown "Archived, not active". Archived
alerts of any engine can be deleted from the archive through the API only
(`DELETE /api/alerts/archive/{archive_id}`); remote engines are never written to.

**Schema notes.** The archive tables (`engine`, `alert`, `event`, `decision`, migration 00003)
deliberately keep two denormalisations: alert fields that CrowdSec repeats per alert (scenario,
source scope and value, country, AS, decision type and origin) are stored as text instead of
lookup tables, and `event_meta` and `engine_public_address_list` are JSONB documents. Upgrading to
the release that adds the archive applies migration 00003 at the next start: back up the database
first (see [PostgreSQL](#postgresql)).

## Sync and bundles

Set-up and semantics: [sync.md](sync.md) and [bundles.md](bundles.md); variables:
[configuration.md](configuration.md).

**An engine is blocked or failed on the Sync page.** Nothing is written to it and its copies
elsewhere are kept, so a blocked engine is safe; but it is not synchronised until fixed.

- `allowlist_unavailable` with no error code: its allowlists cannot be read. Check that its
  CrowdSec has allowlists (`cscli allowlists list`: an engine without the route is never synced),
  that it has at most 10 000 entries, and that the URL points to the LAPI, not a proxy answering 404.
- An error code (`engine_unreachable`, `engine_auth_failed`, `engine_blocked_address`): fix it like
  for the collector, then "Test connection" on the Engines page.
- `target_guard` or `source_guard`: too many changes at once. Read the last plan: a mass unban, a
  new engine with many bans (bootstrap: raise `SYNC_MAX_CHANGES` for one run, in dry run first), or
  a misbehaving engine (disable its sync on the Engines page). There is no override button.
- `engine_unavailable`: the engine is missing from the dashboard's registry (its secret cannot be
  decrypted, or a reload is in progress); its copies elsewhere are kept. Re-enter its secrets on the
  Engines page if the Engines page shows `engine_secret_unreadable`.
- `engine_addresses_unknown` on every engine: one engine host does not resolve (for example a
  stopped container). Bring it back, fix its URL, or disable it: a disabled engine does not block.
- Copies left on an engine that left the sync expire by themselves; delete them earlier with
  `cscli decisions delete --scenario sync/<engine>` on that engine if needed.

**Import step by step.** Export from the old engine, import on the new one: choose the sections,
preview, read the skipped items and warnings, type `IMPORT`, apply, then reload CrowdSec for the
hub and configuration sections (Hub page). An `import_conflict` only means "preview again". The
apply runs inside the request: keep the page open and give the reverse proxy a read timeout above
10 minutes, or a proxy timeout cancels it mid-way (a replay is idempotent; see
[bundles.md](bundles.md#known-limits)). Each apply is audited `bundle_imported`, target
`failed=<n> hub=<n> decisions=<n> alerts=<n> config=<n> skipped=<n>`.

### Config import recovery

An import that was interrupted (crash, kill) leaves a journal
`<CONFIG_IMPORT_DIR>/.dashboard-backup/<timestamp>/.pending`. At the next start with
`CONFIG_IMPORT_ENABLED=true` the dashboard restores the replaced files from that backup and deletes
the created ones, then logs `config import: config_recovered files=...`. A crash after
`crowdsec -t` passed also reverts that import: import it again.

When a file cannot be restored, the log says
`config import: config_inconsistent reason=<unrestored_files|unreadable_journal|sync_failed|journal_not_removed> files=<names> backup=.dashboard-backup/<ts>: restore the listed files from .dashboard-backup/<ts>/ then delete .dashboard-backup/<ts>/.pending`,
the journal is kept, and every config import is refused with `config_recovery_pending` (an apply
that hit the same state reports `config_inconsistent` with `affected_files`). To recover:

1. copy the listed files back from `.dashboard-backup/<ts>/` into the import directory (keep their
   mode, readable by CrowdSec); a listed file absent from the backup was created by the import:
   delete it;
2. run `docker exec crowdsec crowdsec -t` to check the configuration, then reload CrowdSec;
3. delete `.dashboard-backup/<ts>/.pending` (or restart the dashboard to let it retry the recovery).

Backups are kept 30 days and purged at start; a backup directory holding a journal is never purged.

## Retention and purge

One job does all the housekeeping: it runs once at start and then every hour, each run stopping after
30 minutes and resuming at the next. In this order it:

1. scrubs the personal data of old audit rows: the client address (`audit_event_client_ip`) of rows older than
   `AUDIT_IP_RETENTION_DAYS`, and the target of `login_failure` rows (the name as typed, which can be an
   e-mail address) after the same delay;
2. deletes the audit rows older than `AUDIT_RETENTION_DAYS`, in batches of 5 000;
3. deletes expired sessions;
4. deletes the API tokens revoked or expired for more than `API_TOKEN_RETENTION_DAYS`;
5. purges the archive: events, decisions and alerts by collection age
   ([configuration.md](configuration.md#environment-variables)). The event purge keeps the date it
   has already swept in the `setting` table (`archive_event_purge_horizon`) and only looks at newer
   rows; the date never moves back, and a stored date in the future (clock set back) is ignored.

It first resumes the engine deletions left unfinished ([Engines and the archive](#engines-and-the-archive)).
When a run removed or scrubbed something, it records one audit event `retention_purged` whose target
is the counts (`ips=… audit=… sessions=… tokens=… archive=…`); a run that did nothing records nothing.
A failing step is logged and the others still run.

| Variable | Default | Allowed |
|---|---|---|
| `AUDIT_RETENTION_DAYS` | 365 | 90 to 3650 |
| `AUDIT_IP_RETENTION_DAYS` | 30 | 1 to `AUDIT_RETENTION_DAYS` |
| `API_TOKEN_RETENTION_DAYS` | 30 | 1 to 3650 |

The `audit_event_target` of `access_rule_added` and `access_rule_removed` (an address or CIDR you put in
your own allowlist) is not scrubbed: it stays until the audit row is deleted. The complete list of personal data and their
retention is in [security.md](security.md#personal-data). A database dump keeps all of it for as long as
the dump exists.

## Account administration

Administrators manage accounts on the Accounts page (API: [api.md](api.md#accounts)); the page is
for a session only. An administrator can create an account (name, initial password of 12 to 128
characters, role), change a role, reset a second factor, unlock, revoke the sessions and tokens, and
delete.

- **Second-factor setup window: 72 hours.** A new account has no second factor. The first correct
  password within 72 hours starts its enrolment; after that, the account answers 403
  `second_factor_setup_not_allowed` until an administrator resets its factor, which opens a new 72
  hours window. **Whoever presents the password first within the window enrols the factor.** The
  administrator knows the initial password they chose, so they could enrol their own factor and sign
  in as that user: hand the password over by a channel you trust, and have the user enrol at once.
- **Reset second factor** deletes the TOTP and passkeys and the recovery codes of the account, opens the
  72 hours window and revokes its sessions and API tokens.
- **Revoke sessions** (also the account's "log out everywhere") destroys every session **and revokes every
  API token** of the account.
- **Last administrator.** Demoting or deleting the only `admin` is refused with 409 `last_admin`.
  Several administrators can still demote each other down to one.
- **Delete** removes the account with its sessions, tokens, factors and rules (the audit events stay).
  The request must repeat the name in `confirm`. An administrator cannot delete the account they are
  signed in with (409 `cannot_delete_own_account`); another administrator must do it.
- The page disables the role selector and the delete action on your own row, so an administrator
  cannot demote or delete themselves from the interface; another administrator does it. The server
  also refuses self-deletion (409 `cannot_delete_own_account`) but not self-demotion, which only the
  last-administrator guard limits.
- Every action is audited (`account_created`, `account_role_changed`, `account_second_factor_reset`,
  `account_sessions_revoked`, `account_unlocked`, `account_deleted`; target `account:<name>`).
- There is still no password reset: to change a password, delete the account and create it again.

## Health and metrics

`GET /api/healthz` (no session) only tells whether PostgreSQL answers. `GET /api/health` (any role, or a
`read` token) reports more:

- `database`: `ok` or `unavailable` (2 s ping);
- `schema_version`: the applied goose migration number, `null` when it cannot be read;
- `collector`: one entry per engine configured, `{engine_name, last_success_at, lag_seconds,
  errors_total, stale, history_incomplete}`. An engine is `stale` when its last success is older than
  three times `COLLECTOR_INTERVAL`, or when it never succeeded since the start (`last_success_at` and
  `lag_seconds` are then `null`): an engine that is never reachable shows up as stale rather than
  missing. `errors_total` counts failed collections since the process started;
- the existing fields (`version`, `bouncers`, `machines`, `degraded`).

`GET /api/prometheus/metrics` serves the same collector state in the Prometheus text format, behind
authentication (a session or an API token of any scope, never anonymously; a `read` token is enough):

| Metric | Type | Meaning |
|---|---|---|
| `csdash_collector_last_success_timestamp_seconds{engine}` | gauge | Unix time of the last successful collection; absent until the first success |
| `csdash_collector_errors_total{engine}` | counter | Failed collections since the start (resets at restart) |
| `csdash_collector_stale{engine}` | gauge | 1 when stale as defined above |
| `csdash_collector_history_incomplete{engine}` | gauge | 1 when the archive is known to miss part of the engine's history (sticky) |

Create a `read` token on the Tokens page (at most 365 days) and give it to Prometheus
([configuration.md](configuration.md#prometheus-scraping-the-dashboard)). Alert on the age of the
last success with `time() - csdash_collector_last_success_timestamp_seconds > 300`; an engine that
never polled has no such series, so also alert on `csdash_collector_stale == 1`. When the token
expires the scrape fails with 401 `invalid_token`: renew it every year before its date.

## Account recovery by SQL

An administrator resets factors, unlocks and revokes sessions from the Accounts page
([Account administration](#account-administration)). When no administrator can sign in, or to reset
an allowlist (still not in the interface), run SQL on the dashboard database from the host, for example
`docker exec -i <postgres container> psql -U <user> -d <database>`. Check the account first
(`SELECT account_id, account_name FROM account;`) and use its id below. Everything here is a write
to the production database: take a backup before the first one.

### Unlocking an account

A locked account (423 `account_locked`) unlocks itself after 15 minutes. To unlock now:

```sql
UPDATE account SET account_locked_until = NULL, account_failed_second_factor_count = 0
 WHERE account_name = '<account name>';
```

### Removing an allowlist

If the rules refuse every address you have (403 `access_denied`), delete the rules; with no rule the
account is unrestricted again:

```sql
DELETE FROM access_rule WHERE access_rule_account_id =
  (SELECT account_id FROM account WHERE account_name = '<account name>');
```

The lock-out guard of the interface does not apply to SQL.

### Revoking every session

Access rules are checked at sign-in only: an existing session, including a stolen one, keeps working
from any address until it expires (`SESSION_TTL`, 12 h by default). After adding a rule because of a
suspected compromise, revoke the account's sessions and tokens: with a session of the account, call
`POST /api/auth/logout-all`, or use "Revoke sessions" on the Accounts page. By SQL (sessions only; the
tokens also need `UPDATE api_token SET api_token_revoked_at = now() WHERE api_token_account_id = ... AND
api_token_revoked_at IS NULL`):

```sql
DELETE FROM session WHERE session_account_id =
  (SELECT account_id FROM account WHERE account_name = '<account name>');
```

### Reopening the setup window

An account with no second factor and a closed window is refused with 403
`second_factor_setup_not_allowed`. Reopen the window for 72 hours; the next correct password lets the
holder enrol a factor (whoever presents the password first enrols it, so do it when you are ready to
sign in), and the window closes at completion:

```sql
UPDATE account SET account_second_factor_setup_until = now() + interval '72 hours'
 WHERE account_name = '<account name>';
```

### Resetting a lost factor

If an operator lost both their authenticator and their recovery codes, delete the factors and the
codes, then reopen the setup window. The next login asks to enrol a new factor and generates new
codes. These statements follow from how the login code decides between a factor step and a setup
step (the account has no `totp` or `webauthn` credential): they are not part of the automated test
suite, so try them on a copy first.

```sql
DELETE FROM credential WHERE credential_kind IN ('totp', 'webauthn')
   AND credential_account_id = (SELECT account_id FROM account WHERE account_name = '<account name>');
DELETE FROM recovery_code WHERE recovery_code_account_id =
  (SELECT account_id FROM account WHERE account_name = '<account name>');
UPDATE account SET account_webauthn_user_handle = NULL WHERE account_name = '<account name>';
UPDATE account SET account_second_factor_setup_until = now() + interval '72 hours'
 WHERE account_name = '<account name>';
```

The `account_webauthn_user_handle` line matters for an account that had a passkey: the handle is
unique and a new enrolment generates a new one, which is stored only over an empty handle; without
the reset, enrolling a passkey again fails and rolls back (503). The procedure does not clear the
lock: an account whose attempts are exhausted answers 423 `account_locked` at the password step until
the lock expires, so run [Unlocking an account](#unlocking-an-account) too if needed.

## Backup and restore

The dashboard keeps its state in PostgreSQL (accounts, factors, recovery codes, allowlist rules,
sessions, API token hashes, audit events, engines with their sealed secrets, and the alert archive). The
archive is the only copy of the alerts that the engines have already purged. Keep the compose file,
`dashboard.env`, `postgres.env` in your usual configuration backup. The GeoLite2 volume needs no
backup: it is downloaded again. CrowdSec's own volumes (configuration, `crowdsec.db`) are backed up
with CrowdSec, not with the dashboard.

**Back up the secrets key apart from the database** (and every retired key still needed by an older
dump, see [Rotating the secrets key](#rotating-the-secrets-key)). A restored database cannot verify
TOTP codes nor open the engine secrets without it ([Secrets key](#secrets-key)), and a backup that
sits next to the key defeats the encryption. The dump holds password hashes, sealed secrets, client
addresses and attacker addresses: store it like a secret, and note that it keeps data beyond the
[retention](#retention-and-purge) until you delete it.

Both scripts run `docker compose` against the PostgreSQL service, so run them from the directory of
the compose file or set `COMPOSE_FILE`. They need Docker access, which is a host-side operation: they
are not part of the dashboard image.

### Backup

```
deploy/backup.sh -p <compose-project> -s <postgres-service> -d <database> -o <output-directory>
```

`pg_dump -Fc` runs inside the PostgreSQL container (as `POSTGRES_USER`, `postgres` by default) and the
dump is written to `<output-directory>/<database>-<UTC timestamp>.dump`, mode 0600. The script prints
the absolute path of the file. A failed or empty dump is deleted and the exit status is non-zero. The
database name is limited to letters, digits and `_`. Take a dump before every upgrade and on a
schedule of your own (cron on the host); the dashboard can keep running.

### Restore

```
deploy/restore.sh -p <compose-project> -s <postgres-service> -d <database> [-w <dashboard-service>] \
    [--confirm <database>] [--allow-database-mismatch] <backup-file>
```

The script prints the compose project, the PostgreSQL service, its container and image, and the
database that will be replaced, then asks you to retype the database name (or takes `--confirm`).
It refuses, without changing anything, when the service is not defined or not running, when the file is
missing, empty or not a valid `pg_dump` archive, when the database recorded in the dump is not the one
you name (unless `--allow-database-mismatch`), when the confirmation differs, when the name is longer than 51
characters (the temporary name `<database>_restore_tmp` would be truncated by PostgreSQL and could
collide with the real one) or when a database called `<database>_restore_tmp` already exists
(inspect it and drop it yourself).

Then it stops the dashboard service (`-w`, default `dashboard`), restores the dump into
`<database>_restore_tmp`, and only when that succeeded drops `<database>` and renames the temporary
database to its name. A failure before the swap leaves the original database untouched, drops the
temporary one and restarts the dashboard if it was running. The dashboard is restarted after a
success too; the next start applies any migration newer than the dump. A failure during the swap
itself leaves the dashboard stopped and prints the state of both databases: do not restart anything
before reading it. Objects of the restored database belong to `POSTGRES_USER`.

After a restore, the dashboard needs the key that sealed the data: a database from another
installation or from before a rotation needs the matching key (as current or retired key).
Sessions in the dump are live again, which is a reason to restore from your own dumps only.
`deploy/dev/backup-check.sh` exercises both scripts on a disposable PostgreSQL
([development.md](development.md#backup-and-restore-check)).

Accounts have no password-reset feature (for a lost second factor, see [Account
administration](#account-administration) and [Account recovery by SQL](#account-recovery-by-sql)): with the
database restored you keep your accounts; if the `account` table is emptied, the next start opens
enrolment again. To rotate the machine password, run `cscli machines delete` and `add` again with the
new value, then recreate the dashboard.
