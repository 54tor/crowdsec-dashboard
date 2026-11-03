# HTTP API

JSON over HTTP, served by the same process as the UI. Every route except `healthz`, `auth/status`, `auth/logout` and the
`auth/enroll...` and `auth/login...` routes below needs the `session` cookie (set at the end of login
or enrolment), or an API token in `Authorization: Bearer csd_...` ([Access levels](#access-levels)),
and answers 401 `unauthenticated` without credentials (401 `invalid_token` for a bad token). When PostgreSQL is unreachable, authentication-related
routes answer 503 `database_unavailable`. Errors are
`{"error": "<code>"}`; codes are explained in [operations.md](operations.md#troubleshooting).
Unsafe methods from another origin are refused with 403 `cross_origin`. All responses carry the
security headers described in [security.md](security.md#headers-and-content-security-policy).

Delete requests carry a body `{"confirm": "<value>"}` where the value equals the identifier in the
path. Bodies of the bouncer, machine and hub creation routes reject unknown fields.

## Access levels

The "Access" of each route below is one of:

- **public**: no credential;
- **authenticated**: a session, or any API token (`read` or `write`);
- **admin**: an `admin` session, or a `write` token of an `admin` account; otherwise 403 `forbidden`;
- **session only**: a browser session of any role; a token gets 403 `session_required`;
- **admin, session only**: an `admin` session.

A token is sent as `Authorization: Bearer csd_<token>` (nothing else is accepted). An unknown, revoked
or expired token answers 401 `invalid_token`; a valid one whose account is locked or whose address
the account's allowlist refuses answers 403 `token_denied`. A `read` token has the effective role
`read_only`. The unsafe-method cross-origin check does not get in the way of `curl`. Example:

```
curl -H "Authorization: Bearer $DASHBOARD_TOKEN" https://dashboard.example.com/api/alerts
```

## Authentication and service

| Method | Path | Access | Body | Success response | Errors |
|---|---|---|---|---|---|
| GET | `/api/healthz` | public | none | `200 {"status":"ok","database":"ok"}` | 503 `{"status":"degraded","database":"unavailable"}` when the database does not answer a 2 s ping |
| GET | `/api/auth/status` | public | none | `200 {"enrollment_required": <bool>}`, true while an enrolment token is open (answered from memory, no database access) | none |
| POST | `/api/auth/enroll` | public | `{"token","account_name","password"}` (max 1 KiB) | `200 {"status":"second_factor_required","methods":["totp"]}` (`"webauthn"` too when enabled). Nothing is created yet: the name and password hash are kept in memory under the token | 400 `invalid_request`, 400 `invalid_account_name` (not `^[a-z0-9][a-z0-9._-]{0,63}$`), 400 `invalid_password_length` (not 12 to 128 characters), 403 `invalid_enrollment_token`, 404 `not_found` (enrolment closed: an account exists), 429 `too_many_attempts`, 503 `database_unavailable` |
| POST | `/api/auth/login` | public | `{"account_name","password"}` (max 1 KiB) | `200 {"status":"second_factor_required","methods":[...]}` for an account with a factor (the enrolled methods), or `200 {"status":"second_factor_setup_required","methods":[...]}` for a legacy account without one (methods that can be enrolled). Both set the `pending_login` cookie; no session yet | 400 `invalid_request`, 401 `invalid_credentials` (unknown account and wrong password are indistinguishable), 403 `second_factor_setup_not_allowed`, 423 `account_locked` (with `Retry-After`), 429 `too_many_attempts`, 503 `too_many_pending_logins`, 503 `database_unavailable` |
| POST | `/api/auth/logout` | public | none | `200 {"status":"ok"}`, session destroyed, cookie cleared | 503 `database_unavailable` |
| POST | `/api/auth/logout-all` | session only | none | `200 {"status":"ok"}`, every session of the account destroyed **and every API token revoked**, cookie cleared | 401, 403 `session_required`, 503 `database_unavailable` |
| GET | `/api/auth/me` | authenticated | none | `200 {"status":"authenticated","account_name","account_role"}` | 401, 503 `database_unavailable` |

The enrolment token is the one logged at start while no account exists ([operations.md](operations.md#first-start-and-enrolment)).
`login` and `enroll` share the per-client and global rate limits described in [security.md](security.md#rate-limits).

### Enrolment steps

After `POST /api/auth/enroll`, the first account is finished with these routes. Every body carries
the token: `{"token": "<token>", ...}`. All are unauthenticated and rate limited at 30 per minute
per client. Common errors: 400 `invalid_request` (no valid token field), 403
`invalid_enrollment_token`, 404 `not_found` (enrolment closed), 409 `enrollment_not_started` (no
`enroll` call yet, or the dashboard restarted), 429 `too_many_attempts`.

| Method | Path | Body (plus `token`) | Success response | Specific errors |
|---|---|---|---|---|
| POST | `/api/auth/enroll/totp` | none | `200 {"secret","otpauth_url"}`: the base32 secret and the `otpauth://` URL for the QR code. Idempotent: the same secret until completion | 503 `second_factor_unavailable` |
| POST | `/api/auth/enroll/totp/confirm` | `{"code"}` | `200 {"status":"ok"}` | 400 `invalid_code` |
| POST | `/api/auth/enroll/webauthn/options` | none | `200` the WebAuthn credential creation options (`{"publicKey": {...}}`) | 404 `webauthn_disabled`, 503 `second_factor_unavailable` |
| POST | `/api/auth/enroll/webauthn/confirm` | `{"credential": <PublicKeyCredential.toJSON()>}` (max 64 KiB) | `200 {"status":"ok"}` | 400 `webauthn_failed` (also when no options were requested first, or the challenge was already used), 404 `webauthn_disabled` |
| POST | `/api/auth/enroll/recovery-codes` | none | `200 {"recovery_codes":[10 codes]}`; the same codes on a repeated call. Only after a factor is confirmed | 409 `second_factor_required` |
| POST | `/api/auth/enroll/complete` | none | `200 {"status":"ok"}` and `Set-Cookie: session`; creates the account, its factor(s) and the recovery codes in one transaction | 409 `second_factor_required` (no confirmed factor or no recovery codes yet), 503 `database_unavailable` |

### Login steps

After `POST /api/auth/login`, the browser holds the `pending_login` cookie (`HttpOnly`, `Secure`,
`SameSite=Strict`, path `/api/auth`, 5 minutes) and calls one of these routes. All are
unauthenticated, rate limited at 30 per minute per client with no global limit, and **require a JSON
body** (use `{}` when there is nothing to send, including for `webauthn/options`, `setup/...` and
`setup/complete`), otherwise 400 `invalid_request`. A missing, expired, used or foreign (other
client address) pending login answers 401 `pending_login_expired` and clears the cookie; so does
calling a route of the other stage (a setup route for an account that has a factor, or the reverse).

| Method | Path | Body | Success response | Specific errors |
|---|---|---|---|---|
| POST | `/api/auth/login/totp` | `{"code"}` | `200 {"status":"ok"}`, `Set-Cookie: session`, `pending_login` cleared | 401 `invalid_code` (a wrong code is counted; the pending login survives until the fifth try or a lock) |
| POST | `/api/auth/login/recovery-code` | `{"code"}` | as above; the code is consumed | 401 `invalid_code` |
| POST | `/api/auth/login/webauthn/options` | `{}` | `200` the WebAuthn assertion options (`{"publicKey": {...}}`) for the account's passkeys | 404 `webauthn_disabled` |
| POST | `/api/auth/login/webauthn` | `{"credential": <PublicKeyCredential.toJSON()>}` (max 64 KiB) | as above | 401 `webauthn_failed` (including an assertion without a prior `options` call), 404 `webauthn_disabled` |
| POST | `/api/auth/login/setup/totp` | `{}` | `200 {"secret","otpauth_url"}` | 503 `second_factor_unavailable` |
| POST | `/api/auth/login/setup/totp/confirm` | `{"code"}` | `200 {"status":"ok"}` | 400 `invalid_code` |
| POST | `/api/auth/login/setup/webauthn/options` | `{}` | `200` creation options | 404 `webauthn_disabled` |
| POST | `/api/auth/login/setup/webauthn/confirm` | `{"credential": ...}` | `200 {"status":"ok"}` | 400 `webauthn_failed`, 404 `webauthn_disabled` |
| POST | `/api/auth/login/setup/recovery-codes` | `{}` | `200 {"recovery_codes":[...]}` | 409 `second_factor_required` |
| POST | `/api/auth/login/setup/complete` | `{}` | `200 {"status":"ok"}`, `Set-Cookie: session`; saves the factor(s) and codes, closes the setup window and revokes the account's other sessions | 403 `second_factor_setup_not_allowed` (window closed meanwhile), 409 `second_factor_required` |

Errors that can end any of the final steps (`login/totp`, `login/recovery-code`, `login/webauthn`,
`login/setup/complete`) and also clear the pending login:

- 423 `account_locked`, with `Retry-After` set to the seconds left, when the account is locked at
  the time of the attempt (for instance by the failures of another pending login). The fifth wrong
  factor itself still answers 401 and locks the account for 15 minutes; it also consumes the
  pending login, so the next call answers 401 `pending_login_expired` and the next password step
  answers 423;
- 403 `access_denied` when the second factor was valid but the account's
  [allowlist](security.md#access-allowlist) refuses the client; the factor is consumed;
- 401 `pending_login_expired` once the pending login is used up (fifth attempt, lock, success);
- 503 `database_unavailable` otherwise.

`GET /api/auth/status` answers `{"enrollment_required": <bool>}` as before.

## Account access allowlist

Per-account rules deciding from where the account may sign in
([security.md](security.md#access-allowlist)). All three routes are session only and act on the
caller's own account. A rule is `{"id","kind","value"}` with `kind` `ip` (an address or a CIDR,
stored as a CIDR) or `country` (two letters, stored upper case).

| Method | Path | Body | Success response | Errors |
|---|---|---|---|---|
| GET | `/api/account/access-rules` | none | `200 {"rules":[...],"client_ip","client_country"}`; `client_ip` is the address the dashboard sees for this request, `client_country` its country or `null` when unknown or when no GeoLite2 database is loaded | 401, 403 `session_required` (API token), 503 `database_unavailable` |
| POST | `/api/account/access-rules` | `{"kind","value"}` (max 1 KiB, unknown fields refused) | `201 {"id","kind","value"}` with the canonical value | 400 `invalid_access_rule` (bad kind or value, or a `/0` prefix), 400 `prefix_too_broad` (broader than IPv4 /8 or IPv6 /16), 409 `access_rule_exists`, 409 `would_lock_out_current_client`, 409 `geolocation_unavailable` (country rule with no readable GeoLite2 database), 401, 403 `session_required`, 503 |
| DELETE | `/api/account/access-rules/{id}` | none | `204` with no body | 404 `not_found` (unknown id, or a rule of another account), 409 `would_lock_out_current_client`, 401, 403 `session_required`, 503 |

Deleting the last rule turns the allowlist off. The two 409 lock-out answers mean that, with the
change applied, the caller's current address would not be admitted.
Rules are checked at sign-in only: a change never ends an existing session, from any address; use
`POST /api/auth/logout-all` to revoke them.

## API tokens

Session only. A token belongs to the account that creates it ([security.md](security.md#api-tokens)).

| Method | Path | Body | Success response | Errors |
|---|---|---|---|---|
| GET | `/api/tokens` | none | `200 [{"token_id","name","scope","created_at","expires_at","revoked_at"}]`, the account's own tokens, never the secret | 401, 403 `session_required`, 503 |
| POST | `/api/tokens` | `{"name","scope","expires_in_days"}` (max 1 KiB): `scope` is `read` or `write`, `expires_in_days` 1 to 365 | `201 {"token_id","name","scope","expires_at","token"}`, `Cache-Control: no-store`; **`token` is shown only here** | 400 `invalid_request` (unknown scope or body), 400 `invalid_token_name`, 400 `invalid_expiry`, 403 `scope_not_allowed` (`write` for a `read_only` account), 409 `token_name_taken`, 403 `session_required`, 503 |
| DELETE | `/api/tokens/{id}` | `{"confirm":"<id>"}` | `200 {"status":"ok"}` | 400 `confirmation_required`, 404 `not_found` (unknown or another account's), 403 `session_required`, 503 |

## Accounts

Admin, session only. Names match `^[a-z0-9][a-z0-9._-]{0,63}$`; see
[operations.md](operations.md#account-administration). Bodies are capped at 2 KiB.

| Method | Path | Body | Success response | Errors |
|---|---|---|---|---|
| GET | `/api/accounts` | none | `200` list of `{"account_name","account_role","created_at","second_factor_enrolled","locked"}` | 403, 503 |
| POST | `/api/accounts` | `{"account_name","password","account_role"}` (password 12 to 128 characters) | `201 {"account_name"}`; the account has a 72 hours second-factor setup window | 400 `invalid_account_name`, `invalid_password_length`, `invalid_role`; 409 `account_exists` |
| POST | `/api/accounts/{name}/role` | `{"account_role"}` | `200 {"status":"ok"}` | 400 `invalid_role`; 404 `not_found`; 409 `last_admin` (demoting the last administrator) |
| POST | `/api/accounts/{name}/second-factor/reset` | none | `200 {"status":"ok"}`: factors and recovery codes deleted, 72 hours window opened, sessions and tokens revoked | 404 |
| POST | `/api/accounts/{name}/sessions/revoke` | none | `200 {"status":"ok"}`: sessions and tokens revoked | 404 |
| POST | `/api/accounts/{name}/unlock` | none | `200 {"status":"ok"}` | 404 |
| DELETE | `/api/accounts/{name}` | `{"confirm":"<name>"}` | `200 {"status":"ok"}` | 400 `confirmation_required`; 404; 409 `last_admin`; 409 `cannot_delete_own_account` (the signed-in account) |

Each is audited, target `account:<name>` (`account:<name>:<role>` at creation, `account:<name>:<previous>-><new>` for a role change) ([security.md](security.md#audit-log)). Every route
answers 403 `forbidden` to a `read_only` session and 403 `session_required` to a token.

## Read

List routes take `page` (1 to 10000, default 1), `per_page` (default 50, capped at 100) and the
filters `scenario` (`^[A-Za-z0-9][A-Za-z0-9._/:-]{0,127}$`), `ip` (IP or CIDR) and `since` (`<1-4
digits>` then `s`, `m`, `h` or `d`). `/api/alerts` and `/api/decisions` also take `engine` (an
engine name, `^[a-z0-9][a-z0-9-]{0,31}$`), `/api/alerts` takes `source_kind` (`log` or `appsec`,
see [Alert origin](#alert-origin-log-or-appsec)) and `/api/decisions` takes `include_expired` (`true` or
`false`). Invalid values answer 400 `invalid_request`. The page object is `{"items": [...], "page",
"per_page", "window_size", "may_be_truncated", "total", "total_capped", "live_status"}`;
`window_size` is the number of entries fetched from the local LAPI (at most 100),
`may_be_truncated` is true when that window is full.

### Live and archived alerts and decisions

`/api/alerts` and `/api/decisions` merge two parts: the live window of the **local** engine
(newest 100 alerts of its LAPI, as before) first, then the archive (every engine, remote engines
included, see [Engines](#engines)). Each item carries the LAPI fields plus `engine` (engine name,
`local` for the live part), `live` and, for alerts, `archive_id` (null when the alert is not
archived yet). A live alert already archived is listed once, from the live part, with `live:true`
and its `archive_id`; an alert served by the archive alone has `live:false`. Archived decisions
are listed with `live:false` and their `until` as known at collection time (`duration` is empty):
they are never presented as currently enforced. By default only archived decisions whose `until`
is in the future are listed; `include_expired=true` adds the expired history (the live part only
ever holds active decisions). Lists never carry alert `events`.

- `total` is the live window size plus the matching archive rows, counted up to 10 000;
  `total_capped:true` means there are more (the client shows the total with a "+"). A page whose archive offset would pass
  10 000 answers 400 `invalid_request`.
- `live_status` is `ok`, or `unavailable` when the local LAPI could not be read: the page is then
  served from the archive alone with status 200 (an empty `items` with `live_status:"ok"` means
  there is nothing to show). The archive unreachable answers 503 `database_unavailable`.
- `engine=local` lists the live window and the local archive; any other name lists that engine's
  archive only (the live LAPI is not read, `live_status` stays `ok`); an unknown name lists nothing.
- `ip` is normalised before use: canonical form, IPv4-mapped IPv6 unmapped, CIDR masked, zone
  (`fe80::1%eth0`) refused. Scopes differ between the parts: on the live part the LAPI matches the
  alerts whose decisions cover the IP (an IP inside a range-scoped ban matches it, an alert without
  a decision does not); on the archive `ip` is an exact match on the alert source value
  (`alert_source_value`), so a range alert is found with the range itself, not with an IP inside it.
  For archived decisions `ip` matches the decision value or the source value of the alert that
  produced it, exactly: an archived range ban is found by its range string or by the source IP of its
  alert, not by an address the range contains.
- `since` is forwarded to the LAPI, which compares it with the alert `start_at`
  (`started_at >= now - since`, CrowdSec `pkg/database/alertfilter.go`); on the archive it bounds the
  alert `created_at`. An archived alert whose engine date is missing, unparseable or in the future is dated by its collection time, so it neither sorts first nor escapes this bound.
- Order: live items in LAPI order, then archived alerts by `created_at` descending, alerts without a
  date last (archive id as tie-break) and archived decisions by archive decision id descending (insertion order).
- Paging is by offset over "live window, then archive": if the live window changes between two
  requests (new alert, or the collector archives in between), an item can repeat or be skipped at a
  page boundary.

### Alert origin (log or AppSec)

Every alert item carries `source_kind`: `appsec` when the alert comes from the AppSec component
(WAF), `log` otherwise (log parsing, but also manual bans, sync copies and imported alerts).
`source_kind=appsec` or `source_kind=log` keeps only the alerts of that origin, on the live window
and on the archive alike. An alert is `appsec` when at least one of its events has the meta
`service` equal to `appsec`, a `log_type` starting with `appsec-`, or both the keys `matched_zones`
and `target_fqdn` (the per-rule alerts of CrowdSec 1.8 carry neither `service` nor `log_type`). The
archive stores the kind when the alert is first archived (column `alert_source_kind`) and never
recomputes it ([operations.md](operations.md#appsec-origin-of-archived-alerts)). Without an archive
reader (not the case in production) the route serves the live window alone: the filter still
applies but the items carry no `source_kind` field.

| Method | Path | Access | Response | Errors |
|---|---|---|---|---|
| GET | `/api/alerts` | authenticated | page of alerts: `id, uuid, scenario_version, created_at, machine_id, scenario, message, events_count, start_at, stop_at, simulated, source{scope,value,ip,range,cn,as_name,as_number}, decisions[]` (always an array), `engine, archive_id, live, source_kind` | 400, 503 `database_unavailable` |
| GET | `/api/alerts/archive/{archive_id}` | authenticated | one archived alert: the list fields plus `events_truncated` and `events: [{timestamp, meta:{key: value}}]` exactly as stored (`[]` once events were purged by retention); attacker-controlled values are plain JSON strings, never HTML | 400 `invalid_request`, 404 `not_found`, 503 |
| GET | `/api/decisions` | authenticated | page of decisions: `id, alert_id, origin, type, scope, value, duration, until, scenario, simulated, engine, live, archive_decision_id` (the archive row id of the decision, `null` for a live one not archived yet) | 400, 503 |
| GET | `/api/health` | authenticated | `{"version", "database":"ok"\|"unavailable", "schema_version":<number or null>, "collector":[{engine_name,last_success_at,lag_seconds,errors_total,stale,history_incomplete}], "bouncers":[{name,type,version,ip_address,last_pull,revoked,auth_type}], "machines":[{machine_id,ip_address,last_heartbeat,version,is_validated,auth_type,self}], "degraded":[...]}`; `self` is true only for the machine whose id equals `LAPI_MACHINE_ID` (always present, false otherwise); `degraded` lists sources that failed (`version`, `bouncers`, `machines`); `collector` has one entry per configured engine, `stale` being true after three `COLLECTOR_INTERVAL` without success or when none happened yet (`last_success_at` and `lag_seconds` null) ([operations.md](operations.md#health-and-metrics)) | none: failures are reported in `degraded` |
| GET | `/api/prometheus/metrics` | authenticated | Prometheus text format: `csdash_collector_last_success_timestamp_seconds`, `csdash_collector_errors_total`, `csdash_collector_stale`, `csdash_collector_history_incomplete`, labelled by `engine` | 401 `unauthenticated` or `invalid_token`; 403 `token_denied` (token of a locked account or from an address refused by its allowlist) |
| GET | `/api/metrics` | authenticated | `{"available":true, "acquisition":[{source,lines_read,parsed,unparsed}], "parsers":[{name,hits,parsed,unparsed}]}` or `{"available":false,"reason":"unavailable"}` | none |
| GET | `/api/config/files` | admin | `{"files":["acquis.yaml", ...]}` | 500 `config_unavailable` |
| GET | `/api/config/files/{name...}` | admin | `{"name","content"}` with secrets redacted | 403 `forbidden`, 404 `not_found`, 413 `file_too_large`, 500 |
| GET | `/api/hub` | authenticated | array of `{type,name,status,local_version,description}` (max 1000) | 502 `cscli_failed`, 504 `cscli_timeout` |

## Write

Every route of this table is **admin** (an `admin` session or a `write` token of an `admin` account):
a `read_only` account or a `read` token gets 403 `forbidden`.

| Method | Path | Access | Body | Success response | Errors |
|---|---|---|---|---|---|
| POST | `/api/decisions` | admin | `{"ip","duration","reason"}`; `ip` is an IP or CIDR no wider than /8 (IPv4) or /32 (IPv6), `duration` like `24h`, `reason` up to 200 characters, optional | `201 {"status":"created"}` (not audited) | 400 `invalid_target`, `invalid_duration`, `invalid_reason`, `invalid_request`; 409 `self_ban` (the target is, or a range contains, the caller's client address; checked before any LAPI call); 409 `target_allowlisted` (the target overlaps an active allowlist entry of the local engine); 503 `allowlist_unavailable` (the local allowlists could not be read: the ban is refused); 502 |
| DELETE | `/api/decisions/{id}?scope=<scope>&value=<value>` | admin | `{"confirm":"<id>"}` | `200 {"status":"deleted"}`, audited `decision_removed` | 400 `confirmation_required`, `invalid_request`; 404 `not_found`; 409 `target_mismatch`; 502 |
| DELETE | `/api/alerts/{id}?uuid=<uuid>` | admin | `{"confirm":"<id>"}` | `200 {"status":"deleted","archive_deleted":true}` | 400; 403 `forbidden`; 404 `not_found`; 409 `target_mismatch`; 502 `cscli_failed` |
| DELETE | `/api/alerts/archive/{archive_id}` | admin | `{"confirm":"<archive_id>"}` | `200 {"status":"deleted"}` | 400 `invalid_request`, `confirmation_required`; 403; 404 `not_found`; 503 |
| POST | `/api/bouncers` | admin | `{"name"}` | `200 {"name","key"}`, `Cache-Control: no-store` | 400 `invalid_request`; 502; 504 |
| DELETE | `/api/bouncers/{name}` | admin | `{"confirm":"<name>"}` | `200 {"status":"deleted"}` | 400; 502; 504 |
| POST | `/api/machines` | admin | `{"name"}` | `200 {"name","password"}`, `Cache-Control: no-store` | 400; 502; 504 |
| POST | `/api/machines/{name}/validate` | admin | none | `200 {"status":"validated"}` | 400; 502 |
| DELETE | `/api/machines/{name}` | admin | `{"confirm":"<name>"}` | `200 {"status":"deleted"}` | 400; 409 `self_account`; 502 |
| POST | `/api/hub/update` | admin | none | `200 {"status":"updated"}` | 502; 504 |
| POST | `/api/hub/upgrade` | admin | none | `200 {"status":"upgraded"}` | 502; 504 |
| POST | `/api/hub/{kind}` | admin | `{"name"}` such as `crowdsecurity/linux` | `200 {"status":"installed"}` | 400 `invalid_request`; 404 `not_found` (unknown kind); 502 `cscli_failed`; 504 `cscli_timeout` |
| DELETE | `/api/hub/{kind}/{name...}` | admin | `{"confirm":"<name>"}` | `200 {"status":"removed"}` | 400 `confirmation_required`, `invalid_request`; 404 `not_found` (unknown kind); 409 `hub_item_still_installed`; 502 `cscli_failed`; 504 `cscli_timeout` |
| POST | `/api/crowdsec/reload` | admin | none | `200 {"status":"reload_requested"}` | 502; 504 |

Both live deletions name the target they mean, because an `id` alone may belong to another engine
or to an older generation of the local LAPI (ids are reused after a reset):

- `DELETE /api/alerts/{id}` needs `uuid` (lowercase, as listed). The dashboard reads the alert from
  the local LAPI (`GET /v1/alerts/{id}`) first: 404 `not_found` when the LAPI has no such alert,
  409 `target_mismatch` when its uuid differs, and in both cases nothing is deleted or audited. It
  then deletes the alert with `cscli alerts delete` and its archived copy (same engine, id and uuid)
  in the same request, so it does not come back from the archive. `archive_deleted:true` means no
  archived copy is left (including when none existed); `false` means the LAPI copy is gone but the
  archive copy could not be removed (logged).
- `DELETE /api/decisions/{id}` needs `scope` and `value`. The machine API has no route to read one
  decision, so the dashboard looks for the id among the active decisions on that value (the alerts
  route filtered on the target), then among the newest 100 alerts with an active decision: 404
  `not_found` when it is in neither, 409 `target_mismatch` when its scope (case-insensitive) or
  value differs.

Only `live:true` rows of the `local` engine can be deleted this way. `DELETE /api/alerts/archive/{archive_id}` removes an archived alert of any engine
from the archive only (a remote engine is never contacted). Both alert routes (`DELETE /api/alerts/{id}` and `DELETE /api/alerts/archive/{archive_id}`) are audited `alert_deleted` with
target `<engine>/<upstream id>`.

The manual ban checks the allowlists of the local engine just before the write, with the same
filter as the sync and the bundle import ([security.md](security.md#allowlist-check-before-writes)):
there is no override, remove the entry first. The order is: body, target, duration, reason,
`self_ban`, allowlists, then the LAPI write.

Hub `{kind}` is `collections`, `appsec-rules` or `appsec-configs` (the commands `cscli collections`,
`cscli appsec-rules`, `cscli appsec-configs` on the local engine); any other kind answers 404
`not_found` before the body is read. `crowdsecurity/appsec-virtual-patching` and
`crowdsecurity/appsec-generic-rules` are collections: installing them as `appsec-rules` or
`appsec-configs` fails with 502 `cscli_failed`. A removal answers 409 `hub_item_still_installed`
when the hub still lists the item as installed afterwards: `cscli` exits 0 without removing a rule
or configuration that belongs to an installed collection; remove the collection instead (when the
hub cannot be listed again, the removal is reported as done without that check). Hub
installs and removals are not audited ([security.md](security.md#audit-log)).

Machine names match `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`; bouncer names also allow `@` after the first character (bouncers registered over TLS are named `name@<address>`); hub names allow one `/`.
The machine self-check runs before the confirmation check, so `self_account` wins over
`confirmation_required`.

## Engines

CrowdSec engines whose alerts the dashboard archives. The `local` engine comes from `LAPI_URL` /
`LAPI_MACHINE_ID` at start-up and is read-only here. `GET /api/engines/names` is authenticated; `GET /api/engines` and the connection test are admin;
the create, change and delete routes are admin and session only (403 `session_required` for a
token). Everything but the names answers 403 `forbidden` to a `read_only` account, before any read or
write. Bodies are capped at 8 KiB and unknown fields are refused (400 `invalid_request`).
No response, error or audit entry ever contains a machine password or proxy credential: the only
trace of them is `has_proxy_credentials`. Error bodies never repeat a submitted URL.

| Method | Path | Body | Success response | Errors |
|---|---|---|---|---|
| GET | `/api/engines/names` | none | `200 {"items":[{name,is_local,enabled}]}`, any role | 401, 503 `database_unavailable` |
| GET | `/api/engines` | none | `200 {"items":[engine]}` | 403, 503 |
| POST | `/api/engines` | `{name, lapi_url, machine_id, machine_password, proxy?{kind,url,username?,password?}, allow_insecure_http, public_addresses, enabled, sync_enabled}` | `201 engine` | 400 `invalid_engine`, `invalid_request`; 409 `engine_exists`, `engine_deleting` (same name or URL as an engine whose archive is still being deleted); 403; 503 |
| PATCH | `/api/engines/{name}` | same fields, all optional; absent = unchanged; `"proxy": null` removes the proxy; `proxy.clear_credentials: true` drops the proxy credentials | `200 engine` | 400 `invalid_engine`, `engine_secret_required`, `invalid_request`; 404 `engine_not_found`; 409 `engine_exists`, `engine_local_readonly`; 403; 503 |
| DELETE | `/api/engines/{name}` | `{"confirm":"<name>"}` | `202 {"status":"deleting"}`: the archive is deleted in the background | 400 `confirmation_required`; 404; 409 `engine_local_readonly`; 403; 503 |
| POST | `/api/engines/{name}/test` | none | `200 {"status":"ok"}` | 502 `engine_unreachable`, `engine_auth_failed`, `engine_blocked_address`; 404; 403; 503 |

`engine` is `{name, is_local, lapi_url, machine_id, proxy:{kind,url}|null, has_proxy_credentials,
allow_insecure_http, public_addresses, enabled, sync_enabled, collection:{cursor,
last_collected_at, last_error_code, consecutive_failures, next_attempt_at, inserted, duplicates,
skipped, gaps, resets}}`. `cursor`, `last_collected_at` (last successful collection) and
`last_error_code` come from the database; `consecutive_failures`, `next_attempt_at` and the counters
come from the running collector and restart at zero with the process (`0` or `null` before the
first collection). `last_error_code` is one of `engine_unreachable`, `engine_auth_failed`,
`engine_blocked_address`, `archive_write_failed` (the archive write failed) or
`engine_secret_unreadable` (the stored secret of the engine cannot be decrypted: the engine is left
out of the collection until it is fixed); never a raw error text.

- `lapi_url` must be `https` unless `allow_insecure_http` is true, and carries no credentials,
  query or fragment. A literal loopback, link-local, unspecified, multicast, reserved or cloud
  metadata address (`127.0.0.1`, `[::1]`, `169.254.169.254`, `100.100.100.200`, `[fd00:ec2::254]`, `168.63.129.16`…)
  in `lapi_url` or `proxy.url` is refused at write time with `invalid_engine`; private ranges
  (RFC 1918, `100.64.0.0/10`, `fc00::/7`) are accepted. Host names are checked when the connection
  is made, after DNS resolution.
- `engine_secret_required`: a `lapi_url` change of scheme, host or port without `machine_password`
  in the same request (a change of the path alone keeps the stored password; such a change of
  scheme, host or port also resets the collection cursor to 0, so the next collection reads the new
  engine from its start); a `proxy.url` or `proxy.kind` change on an engine that has proxy credentials
  without new credentials or `clear_credentials`; a proxy change on an `http` engine without
  `machine_password`. Nothing is written and no connection is made.
- Deleting an engine deletes its whole archive; disable it (`"enabled": false`) to keep the archive.
  The delete answers 202 at once: `engine_deleting_at` is set, the engine disappears from every
  route (404 `engine_not_found`), the lists and the collector, and a background job removes its
  alerts in batches and then the engine, resuming after a restart ([operations.md](operations.md#engines-and-the-archive)).
- `test` logs in as the machine (`POST /v1/watchers/login`) through the engine's own guarded
  client and proxy, also for a disabled engine and for `local` (which uses the dashboard's own LAPI
  client). The engine's answer is never returned, only the outcome: `ok`, `engine_unreachable`,
  `engine_auth_failed` or `engine_blocked_address` (see the oracle note in
  [security.md](security.md#engines-and-outbound-connections)).
- `name` can be changed by `PATCH` (rename); the audit target is `old>new` (names cannot contain `>`).
- Every successful create, update and delete, and every test of an existing engine, is audited
  (`engine_created`, `engine_updated`, `engine_deleted`, `engine_tested`) with the engine name as
  target. After each successful write the engine registry is reloaded; when that reload fails the
  write is kept, the failure is logged and the response carries `"warning":"registry_reload_failed"`
  (the previous engine set stays active until the next successful reload).

## Allowlists

CrowdSec allowlists (centralised allowlists, `cscli allowlists`) of each engine
([security.md](security.md#allowlists-of-the-engines)). Reading is open to every role; the four
writes are admin (an `admin` session or a `write` token of an `admin` account) and act on the
**local** engine only: the LAPI has no route to write an allowlist, so the dashboard writes with
`cscli` in the local CrowdSec container, and every remote engine is read-only (409
`allowlist_engine_readonly`, nothing read or written). Bodies are capped at 2 KiB and unknown
fields are refused (400 `invalid_request`).

| Method | Path | Access | Body | Success response |
|---|---|---|---|---|
| GET | `/api/engines/{name}/allowlists` | authenticated | none | `200` listing |
| POST | `/api/engines/{name}/allowlists` | admin | `{"name","description"}` | `201` mutation result |
| DELETE | `/api/engines/{name}/allowlists/{allowlist}` | admin | `{"confirm":"<allowlist>"}` | `200` mutation result |
| POST | `/api/engines/{name}/allowlists/{allowlist}/entries` | admin | `{"value","expiration","description","confirm"}` | `201` mutation result |
| DELETE | `/api/engines/{name}/allowlists/{allowlist}/entries` | admin | `{"value","confirm":"<value>"}` | `200` mutation result |

The listing is:

```json
{"engine": "local", "writable": true, "truncated": false,
 "allowlists": [{"name": "trusted", "description": "Trusted partners", "console_managed": false,
   "created_at": "2026-11-03T15:47:00Z", "updated_at": "2026-11-03T15:47:44Z",
   "entries": [{"value": "203.0.113.7", "description": "partner gateway",
     "created_at": "2026-11-03T15:47:44Z", "expires_at": null, "expired": false}]}]}
```

- `writable` is true for the local engine only. `truncated` is true when the LAPI answer was over
  4 MiB (the listing is then empty) or held more than 10 000 entries in total (the entries beyond
  are not shown); the page shows a banner, and the manual ban and the sync refuse every target on
  that engine.
- `expires_at` is null for an entry without expiry (CrowdSec stores it as
  `0001-01-01T00:00:00.000Z`); `expired` is computed against the dashboard clock at the time of the
  read. An expired entry is still listed (`expired:true`) and no longer protects its value.
- A mutation result is the listing re-read after the write plus `refreshed`. `refreshed:false`
  means the write was made (and audited) but the allowlists could not be read again, or the re-read
  was truncated (the change is then not verified): the listing may be empty, read it again with
  `GET`.

Fields:

- `name`: `^[a-z0-9][a-z0-9._-]{0,31}$`. `description` (required at creation, optional for an
  entry): 1 to 256 bytes of UTF-8, not starting with `-`, without control, format (zero-width,
  bidirectional) or line and paragraph separator characters. It is passed to `cscli` as a single
  `--description=` or `--comment=` value.
- `value`: an IP address or a CIDR range, IPv4 or IPv6, written in canonical form to the engine.
  A range wider than IPv4 /8 or IPv6 /32 is refused (400 `allowlist_prefix_too_wide`, `0.0.0.0/0`
  and `::/0` included, no confirmation can lift it). A range wider than IPv4 /24 or IPv6 /48 needs
  `confirm` equal to the canonical range (400 `confirmation_required` otherwise). These floors are
  constants, no setting changes them.
- `expiration`: empty (no expiry) or 1 to 4 digits not starting with 0, then `h` or `d` (`12h`,
  `7d`), passed as `cscli allowlists add --expiration=`.
- Delete routes need `confirm` equal to the allowlist name, or to the `value` as sent.

`cscli allowlists` exits 0 on a duplicate value, an invalid value or the removal of a missing value
(only an unknown or duplicate allowlist name exits non-zero), so the dashboard checks the change
itself: it reads the allowlists before the write (to refuse duplicates, unknown or
console-managed allowlists) and again after it, and answers 502 `allowlist_write_failed` when the
expected change is not visible. **Adding an entry makes CrowdSec delete at once every decision of
that engine covered by any of its allowlists**, not only by the new value.

| Code | HTTP | When |
|---|---|---|
| `invalid_request` | 400 | Body malformed, over 2 KiB, or with unknown fields |
| `confirmation_required` | 400 | Delete without the retyped name or value, or a range wider than /24 (IPv4) or /48 (IPv6) without the retyped canonical range |
| `invalid_allowlist` | 400 | Name, value, expiration or description refused |
| `allowlist_prefix_too_wide` | 400 | Range wider than /8 (IPv4) or /32 (IPv6) |
| `forbidden` | 403 | A write by a `read_only` account or a `read` token |
| `engine_not_found` | 404 | Unknown or disabled engine |
| `allowlist_not_found`, `allowlist_entry_not_found` | 404 | No such allowlist or value on the engine (also any write to an existing allowlist when the LAPI answer was over 4 MiB) |
| `allowlist_exists`, `allowlist_entry_exists` | 409 | Name or value already present |
| `allowlist_console_managed` | 409 | The allowlist is managed by the CrowdSec console: change it there |
| `allowlist_engine_readonly` | 409 | Write on a remote engine |
| `engine_unreachable`, `engine_auth_failed`, `engine_blocked_address` | 502 | The allowlists could not be read: no answer, login refused, forbidden address. Any 404 on `/v1/allowlists` (a CrowdSec without allowlists, a wrong URL or a proxy) and an undecodable answer count as `engine_unreachable` |
| `allowlist_write_failed` | 502 | `cscli` failed or timed out, or the re-read does not show the change; the output of `cscli` is never returned |
| `database_unavailable` | 503 | The engine table could not be read |

Each successful write is audited after the fact: `allowlist_created` and `allowlist_deleted` with
target `<engine>/<allowlist>`, `allowlist_entry_added` and `allowlist_entry_removed` with target
`<value>@<engine>/<allowlist>` (the value is never cut). A refused or failed write is not audited.

## Sync, export and import

Engine synchronisation ([sync.md](sync.md)) and bundles ([bundles.md](bundles.md)). A sync run, an
export and an import share one operation lock: a second one answers 409 `operation_running`.

| Method | Path | Access | Body | Success response | Errors |
|---|---|---|---|---|---|
| GET | `/api/sync` | authenticated | none | `200 {"enabled","dry_run","interval_seconds","running","error_code","peers":[{name,url_host,last_run_at,status,added,removed,skipped,skipped_allowlisted,blocked_reason,error_code}],"last_plan":[{engine,kind,target,source,reason}]}` | 401, 503 `database_unavailable` |
| POST | `/api/sync/run` | admin | none, `{}`, or `{"expected_changes":{"<engine>":<n>}}` (max 1 KiB, unknown fields refused) | `202 {"status":"started"}`: the run continues in the background; poll `GET /api/sync` | 400 `invalid_request`, 403 `forbidden`, 409 `sync_disabled`, 409 `operation_running` |
| POST | `/api/export` | admin; with `include_secrets`, session only | `{"sections":[...],"include_secrets":false,"confirm_secrets":"SECRETS","strip_events":false}` (max 1 KiB, unknown fields refused); sections among `hub`, `decisions`, `alerts`, `config` | `200` the bundle, `Content-Disposition: attachment; filename="crowdsec-bundle-<UTC date>.json"`, `Cache-Control: no-store`, `X-Bundle-Skipped-Alerts: <n>` | 400 `invalid_request`, `confirmation_required`; 403 `forbidden`, `session_required`; 409 `operation_running`; 413 `bundle_too_large`; 502/504 upstream codes |
| POST | `/api/import` | admin, session only | `{"mode":"preview"\|"apply","bundle":{...},"sections":[...],"confirm":"IMPORT","digest":"<from the preview>"}` (at most 8 MiB plus 64 KiB) | preview: `200` the plan `{sections,hub,decisions,alerts,config,skipped,skipped_counts,warnings,unavailable,unavailable_codes,digest}`, `Cache-Control: no-store`; apply: `200 {"digest","report":{"sections":[{section,status,applied,skipped,failed,skipped_reasons,error_code?,warnings?,affected_files?}]}}`, also when a section failed | 400 `invalid_request`, `bundle_invalid`, `bundle_version`, `confirmation_required`; 403 `forbidden`, `session_required`; 409 `import_conflict`, `section_unavailable`, `operation_running`; 413 `bundle_too_large`; 422 `too_many_changes`; 503 `operation_lock_unavailable`; 504 `import_timeout`; upstream codes |

- `GET /api/sync` lists, before the first run, the participating engines with status `never_run`
  and `last_run_at: null`; afterwards the engines of the last report. `url_host` is the host and
  port of the LAPI URL, never a path, credentials or the proxy. `last_plan` holds at most 100 rows:
  changes (`kind` `add`, `remove`, `replace`) then skips (`reason`). The top-level `error_code` is the
  run-level code of the last run (`""` when none). Codes: [sync.md](sync.md#codes).
- `expected_changes` asks to apply the pending changes of a guarded engine once; it is honoured
  only when the recomputed count is at most 110 % of the given one, otherwise that engine reports
  `sync_guard_tripped`. The page does not use it.
- A manual run is audited `sync_run` when it finishes. The run uses the server lifetime, not the
  request: closing the browser or a proxy timeout does not stop it.
- Export and import act on the local engine only. Item codes and section statuses:
  [bundles.md](bundles.md#codes). Previews are not audited; an export and an apply are
  (`bundle_exported`, `bundle_imported`).

## Everything else

Any other `/api/...` path answers 404 `not_found` (401 without a session). Any other path serves the
single-page application: unknown paths return `index.html`.
