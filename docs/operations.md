# Operations

## Known limits

| Area | Behaviour |
|---|---|
| Alerts | The 100 most recent alerts of the local LAPI are fetched live, followed by the archive (older local alerts and the alerts of remote engines). Filters (`scenario`, IP/CIDR, `since` such as `24h`, `7d`) are applied by the LAPI inside that cap and by the database on the archive, with different IP scopes (see `docs/api.md`). When the local LAPI is unreachable the archive is still served, flagged `live_status:"unavailable"` (a banner says so and the archive stays paged). Each row shows its engine and a "Live" or "Archived" badge; an engine selector (any role) narrows the list. Pages are counted from `total`; when capped, the total (live window plus up to 10 000 archived rows) is shown with a "+", and paging stops at that reachable range. Archived alerts open a details dialog with their events as plain text; events purged by retention leave an explicit empty state. Only live rows of the `local` engine offer Delete, which also deletes the archived copy. |
| Decisions | Built from the alerts that still have an active decision (same 100-alert window), expired ones dropped, followed by archived decisions still active at collection time, badged "Archived, not active" (the "Show expired decisions" checkbox sends `include_expired=true` for the history). Decisions of the community blocklist (CAPI) are not listed: they are not attached to local alerts. A manual ban shows up as origin `cscli`, scenario `manual/dashboard`. |
| Unban | Deletes one decision by id. An id that does not exist makes the LAPI answer 500, which the dashboard reports as 502 `lapi_unavailable`, not as a 404. |
| Hub whitelists | Whitelist files that the hub installs as symlinks are not listed in the Config page; symlinks are never followed. |
| Hub list | At most 1000 items are returned. |
| Hub operations | `update`, `upgrade`, `install` and `remove` can take up to 120 s (others 30 s); the HTTP write deadline is extended to match. Other requests have a 60 s write deadline. |
| Reload | "Reload CrowdSec" sends `SIGHUP` to process 1 of the CrowdSec container, so CrowdSec must be PID 1 (true for the official image). Hub changes need it to take effect; the banner "CrowdSec must be reloaded" appears on the Hub page after a change and is kept in the browser tab only, it disappears on a page reload. Counters of the Metrics page restart at zero after a reload. |
| Metrics | Needs Prometheus enabled in CrowdSec, otherwise "Metrics are unavailable" ([configuration.md](configuration.md#prometheus-for-the-metrics-page)). Only the acquisition and parser tables are shown. |
| Contact status | A bouncer or machine is "stale" after more than 5 minutes without contact. The dashboard's own machine account never sends a heartbeat: it is flagged "This dashboard" and shows no contact status. |
| Health page | One failing source does not blank the page: the response lists it in `degraded` (`version`, `bouncers`, `machines`) and shows the others. |
| Sessions | Stored in PostgreSQL, 12 h by default, kept across restarts. The login rate limiter is per process: one replica only. |
| Pending logins | The state between the password step and the second factor (5 minutes, 5 attempts, bound to the client address) is in memory: a restart makes everybody in mid-login start again. The first-account enrolment state is also in memory, with no expiry, and is lost at restart. |
| Second factor | TOTP always; WebAuthn only with `WEBAUTHN_RP_ID` and `WEBAUTHN_RP_ORIGINS`. Factors cannot be changed or reset from the interface yet. |
| Access allowlist | No rule means no restriction; any rule means deny by default. Country rules need the GeoLite2 database, otherwise they never match. No minimum prefix length except zero. Checked at sign-in only: existing sessions are not cut off. |
| Audit log | Written to `audit_event`; no page, no retention, and some events are not recorded yet ([security.md](security.md#audit-log)). |
| Engines | Managed on the Engines page by `admin` accounts only ([Engines and the archive](#engines-and-the-archive)). Collection counters and the "History incomplete" warning restart with the process. |
| Roles | `read_only` hides the Engines page and is refused on the engine and alert-deletion routes; the other write routes and buttons are not restricted yet (a `read_only` account still sees Delete on live local alerts and gets 403 `forbidden`). |

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
| `second_factor_setup_not_allowed` | 403 | The account has no second factor and its setup window is closed. See [Reopening the setup window](#reopening-the-setup-window). |
| `second_factor_required` | 409 | Enrolment or setup was completed before a factor was confirmed and the recovery codes were generated. |
| `enrollment_not_started` | 409 | An enrolment step came before `POST /api/auth/enroll`, or the dashboard restarted since. Start again with the token from the new log. |
| `second_factor_unavailable` | 503 | A TOTP key or recovery codes could not be generated; the dashboard log has the cause. |
| `too_many_pending_logins` | 503 | 10 000 logins are waiting for their second factor; retry shortly. |
| `invalid_access_rule`, `access_rule_exists` | 400, 409 | Allowlist rule malformed (kind `ip` or `country`, `/0` refused) or already present. |
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
| `forbidden` | 403 | The action needs the `admin` role (engines, alert deletion). |
| `target_mismatch` | 409 | The alert or decision id now designates another target (different uuid, scope or value): the list was stale or the LAPI was reset. Reload the page. |
| `engine_exists`, `engine_not_found`, `invalid_engine` | 409, 404, 400 | Engine name already used, unknown engine, or a field refused (name, URL scheme without `allow_insecure_http`, credentials or forbidden address in a URL, proxy kind). |
| `engine_local_readonly` | 409 | The `local` engine comes from `LAPI_URL` and cannot be changed or deleted from the API. |
| `engine_secret_required` | 400 | The destination changed: re-enter the machine password (and the proxy credentials) in the same request. |
| `engine_unreachable` | 502 | No answer from the engine or its proxy, a timeout, an answer that is not a LAPI login, or an answer over the size limit. Check the URL, the port, the proxy and the network between the dashboard and the engine. |
| `engine_auth_failed` | 502 | The engine refused the machine login: check the machine id and password with `cscli machines list` on that engine, and that the machine is validated. |
| `engine_blocked_address` | 502 | The address (or the proxy address) resolved to a forbidden range ([security.md](security.md#engines-and-outbound-connections)). |
| `engine_secret_unreadable` | engine status | The stored secret cannot be decrypted with the current secrets key (key changed or row restored from another installation): edit the engine and re-enter the secrets. The engine is left out of collection meanwhile. |
| `archive_write_failed` | engine status | The archive write failed (database). The engine is retried with backoff. |
| `cscli_timeout` | 504 | The command exceeded 30 s (120 s for hub operations). Retry; check the network of the CrowdSec container for hub calls. |

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
- `GET /api/healthz` answers 200 without a session when PostgreSQL answers a ping, 503 otherwise, for container health checks.
- Metrics page empty after a reload: counters restart at zero until new log lines are read.

## PostgreSQL

The dashboard needs a PostgreSQL server (the `postgres` service of `deploy/compose.example.yaml`,
configured by `postgres.env`, data in the `postgres-data` volume). The dashboard container starts
after the database is healthy.

- At every start it opens the database, applies the pending schema migrations automatically and only
  then serves requests. It refuses to start if `DATABASE_URL` is missing or unreachable, or if a
  migration fails: read the container log.
- Back up the database before upgrading the dashboard to a new version, since an upgrade may migrate
  the schema. The upgrade that introduces the second factor applies migration 00002 at the next
  start: it adds the factor, recovery code, allowlist and lockout columns and tables, and opens the
  second-factor setup window of every existing account (see
  [security.md](security.md#accounts-from-the-first-release)). The dashboard also needs the secrets
  key before that start ([Secrets key](#secrets-key)). Sign in right after upgrading to enrol
  your factor.
- If PostgreSQL goes down while the dashboard runs, `/api/healthz` answers 503 and login and
  authenticated routes answer 503 `database_unavailable`. Nobody is signed out: sessions are valid
  again once the database is back.
- Major upgrade trap: since PostgreSQL 18 the image keeps data in `/var/lib/postgresql/<major>/docker`,
  so a `docker compose pull` that crosses a major version initialises a new empty cluster beside the
  old one. A major upgrade needs a dump and restore (or `pg_upgrade`): note the running major
  (`SELECT version()`) before pulling. If the dashboard log shows an enrolment token after an upgrade,
  the cluster is empty: stop the stack, do not enrol, and restore the previous data.
- Automated backup and restore of the database are not provided yet (planned for a later lot):
  until then, back up the `postgres-data` volume or dump the database with your usual tooling.

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
- Do not replace the key with another one while TOTP secrets exist: they were sealed with the old
  one and are identified by its `key_id`, and the dashboard holds a single key.

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
Duplicates are impossible: an alert is keyed by engine, upstream id and upstream uuid. Each
collection updates `last_collected_at` (last success) and `last_error_code` in the `engine` row;
the counters (`inserted`, `duplicates`, `skipped`, `gaps`, `resets`) live in memory. An alert that
cannot be stored (for example a meta value that is not a string, or a value the database refuses)
is skipped and counted, and the next valid alert is still archived. Events are bounded per alert
(see [security.md](security.md#engines-and-outbound-connections)); an alert whose events or meta
were cut has `events_truncated:true` in its detail.

**History incomplete.** When the newest alerts read do not reach back to the cursor (more new
alerts than the poll limit since the last collection), the collector reads the whole history
again; if that read is truncated or too slow it archives what the poll returned, counts a gap
and the Engines page shows "History incomplete since the dashboard started". Some alerts of that
window may never be archived if the engine purged them meanwhile. The warning is held in memory and
disappears at the next restart even though the archive keeps the hole. Lower the interval or raise
`COLLECTOR_POLL_LIMIT` for busy engines.

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
is assumed wrongly and that window is archived once more (purged again by retention). Changing the
host, port or scheme of an engine's URL also resets its cursor.

**Retention.** Archived alerts, decisions and events are purged hourly by collection age
([configuration.md](configuration.md#environment-variables)). Alerts purged from the archive are
not collected again while the engine still serves them (they are below the cursor).

**Deleting an engine deletes its archive** (alerts, events and decisions, in one cascade), after
the name is retyped. To stop collecting and keep the archive, disable the engine instead.

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

## Account recovery by SQL

There is no password reset, no factor reset and no allowlist reset in the interface yet. When an
operator is locked out, run SQL on the dashboard database from the host, for example
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
suspected compromise, revoke the account's sessions: with a session of the account, call
`POST /api/auth/logout-all` (the interface has no button for it yet); otherwise:

```sql
DELETE FROM session WHERE session_account_id =
  (SELECT account_id FROM account WHERE account_name = '<account name>');
```

### Reopening the setup window

An account with no second factor and a closed window is refused with 403
`second_factor_setup_not_allowed`. Reopen the window for one day; the next correct password lets the
holder enrol a factor (whoever presents the password first enrols it, so do it when you are ready to
sign in), and the window closes at completion:

```sql
UPDATE account SET account_second_factor_setup_until = now() + interval '1 day'
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
UPDATE account SET account_second_factor_setup_until = now() + interval '1 day'
 WHERE account_name = '<account name>';
```

The `account_webauthn_user_handle` line matters for an account that had a passkey: the handle is
unique and a new enrolment generates a new one, which is stored only over an empty handle; without
the reset, enrolling a passkey again fails and rolls back (503). The procedure does not clear the
lock: an account whose attempts are exhausted answers 423 `account_locked` at the password step until
the lock expires, so run [Unlocking an account](#unlocking-an-account) too if needed.

## Backup and restore

The dashboard keeps its state in PostgreSQL (accounts, factors, recovery codes, allowlist rules,
sessions, audit events, engines with their sealed secrets, and the alert archive). The archive is
the only copy of the alerts that the engines have already purged. Keep the compose file, `dashboard.env`, `postgres.env` and the secrets
key file in your usual configuration backup, and back up the database (see
[PostgreSQL](#postgresql)). **Back up the secrets key apart from the database**, otherwise a restored
database cannot verify TOTP codes nor open the engine secrets ([Secrets key](#secrets-key)). The GeoLite2 volume needs no backup:
it is downloaded again. To restore, redeploy the files and the database, and recreate the
LAPI machine account if the CrowdSec data was lost. CrowdSec's own volumes (configuration,
`crowdsec.db`) are backed up with CrowdSec, not with the dashboard.

Accounts have no password-reset feature yet (for a lost second factor, see [Account recovery by SQL](#account-recovery-by-sql)): with the database restored you keep your accounts; if
the `account` table is emptied, the next start opens enrolment again. To rotate the machine password,
run `cscli machines delete` and `add` again with the new value, then recreate the dashboard.
