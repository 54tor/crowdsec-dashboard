# HTTP API

JSON over HTTP, served by the same process as the UI. Every route except `healthz`, `auth/status`, `auth/logout` and the
`auth/enroll...` and `auth/login...` routes below needs the `session` cookie (set at the end of login
or enrolment) and answers 401 `unauthenticated` without it. When PostgreSQL is unreachable, authentication-related
routes answer 503 `database_unavailable`. Errors are
`{"error": "<code>"}`; codes are explained in [operations.md](operations.md#troubleshooting).
Unsafe methods from another origin are refused with 403 `cross_origin`. All responses carry the
security headers described in [security.md](security.md#headers-and-content-security-policy).

Delete requests carry a body `{"confirm": "<value>"}` where the value equals the identifier in the
path. Bodies of the bouncer, machine and hub creation routes reject unknown fields.

## Authentication and service

| Method | Path | Auth | Body | Success response | Errors |
|---|---|---|---|---|---|
| GET | `/api/healthz` | no | none | `200 {"status":"ok","database":"ok"}` | 503 `{"status":"degraded","database":"unavailable"}` when the database does not answer a 2 s ping |
| GET | `/api/auth/status` | no | none | `200 {"enrollment_required": <bool>}`, true while an enrolment token is open (answered from memory, no database access) | none |
| POST | `/api/auth/enroll` | no | `{"token","account_name","password"}` (max 1 KiB) | `200 {"status":"second_factor_required","methods":["totp"]}` (`"webauthn"` too when enabled). Nothing is created yet: the name and password hash are kept in memory under the token | 400 `invalid_request`, 400 `invalid_account_name` (not `^[a-z0-9][a-z0-9._-]{0,63}$`), 400 `invalid_password_length` (not 12 to 128 characters), 403 `invalid_enrollment_token`, 404 `not_found` (enrolment closed: an account exists), 429 `too_many_attempts`, 503 `database_unavailable` |
| POST | `/api/auth/login` | no | `{"account_name","password"}` (max 1 KiB) | `200 {"status":"second_factor_required","methods":[...]}` for an account with a factor (the enrolled methods), or `200 {"status":"second_factor_setup_required","methods":[...]}` for a legacy account without one (methods that can be enrolled). Both set the `pending_login` cookie; no session yet | 400 `invalid_request`, 401 `invalid_credentials` (unknown account and wrong password are indistinguishable), 403 `second_factor_setup_not_allowed`, 423 `account_locked` (with `Retry-After`), 429 `too_many_attempts`, 503 `too_many_pending_logins`, 503 `database_unavailable` |
| POST | `/api/auth/logout` | no | none | `200 {"status":"ok"}`, session destroyed, cookie cleared | 503 `database_unavailable` |
| POST | `/api/auth/logout-all` | yes | none | `200 {"status":"ok"}`, every session of the account destroyed, cookie cleared | 401, 503 `database_unavailable` |
| GET | `/api/auth/me` | yes | none | `200 {"status":"authenticated","account_name","account_role"}` | 401, 503 `database_unavailable` |

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
([security.md](security.md#access-allowlist)). All three routes need a session and act on the
caller's own account. A rule is `{"id","kind","value"}` with `kind` `ip` (an address or a CIDR,
stored as a CIDR) or `country` (two letters, stored upper case).

| Method | Path | Body | Success response | Errors |
|---|---|---|---|---|
| GET | `/api/account/access-rules` | none | `200 {"rules":[...],"client_ip","client_country"}`; `client_ip` is the address the dashboard sees for this request, `client_country` its country or `null` when unknown or when no GeoLite2 database is loaded | 401, 503 `database_unavailable` |
| POST | `/api/account/access-rules` | `{"kind","value"}` (max 1 KiB, unknown fields refused) | `201 {"id","kind","value"}` with the canonical value | 400 `invalid_access_rule` (bad kind or value, or a `/0` prefix), 409 `access_rule_exists`, 409 `would_lock_out_current_client`, 409 `geolocation_unavailable` (country rule with no readable GeoLite2 database), 401, 503 |
| DELETE | `/api/account/access-rules/{id}` | none | `204` with no body | 404 `not_found` (unknown id, or a rule of another account), 409 `would_lock_out_current_client`, 401, 503 |

Deleting the last rule turns the allowlist off. The two 409 lock-out answers mean that, with the
change applied, the caller's current address would not be admitted.
Rules are checked at sign-in only: a change never ends an existing session, from any address; use
`POST /api/auth/logout-all` to revoke them.

## Read

List routes take `page` (1 to 10000, default 1), `per_page` (default 50, capped at 100) and the
filters `scenario` (`^[A-Za-z0-9][A-Za-z0-9._/:-]{0,127}$`), `ip` (IP or CIDR) and `since` (`<1-4
digits>` then `s`, `m`, `h` or `d`). `/api/alerts` and `/api/decisions` also take `engine` (an
engine name, `^[a-z0-9][a-z0-9-]{0,31}$`) and `/api/decisions` takes `include_expired` (`true` or
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
- `since` is forwarded to the LAPI, which compares it with the alert `start_at`
  (`started_at >= now - since`, CrowdSec `pkg/database/alertfilter.go`); on the archive it bounds the
  alert `created_at`. An archived alert whose engine date is missing, unparseable or in the future is dated by its collection time, so it neither sorts first nor escapes this bound.
- Order: live items in LAPI order, then archived alerts by `created_at` descending (archive id as
  tie-break) and archived decisions by archive decision id descending (insertion order).
- Paging is by offset over "live window, then archive": if the live window changes between two
  requests (new alert, or the collector archives in between), an item can repeat or be skipped at a
  page boundary.

| Method | Path | Auth | Response | Errors |
|---|---|---|---|---|
| GET | `/api/alerts` | yes | page of alerts: `id, uuid, scenario_version, created_at, machine_id, scenario, message, events_count, start_at, stop_at, simulated, source{scope,value,ip,range,cn,as_name,as_number}, decisions[]` (always an array), `engine, archive_id, live` | 400, 503 `database_unavailable` |
| GET | `/api/alerts/archive/{archive_id}` | yes | one archived alert: the list fields plus `events_truncated` and `events: [{timestamp, meta:{key: value}}]` exactly as stored (`[]` once events were purged by retention); attacker-controlled values are plain JSON strings, never HTML | 400 `invalid_request`, 404 `not_found`, 503 |
| GET | `/api/decisions` | yes | page of decisions: `id, alert_id, origin, type, scope, value, duration, until, scenario, simulated, engine, live` | 400, 503 |
| GET | `/api/health` | yes | `{"version", "bouncers":[{name,type,version,ip_address,last_pull,revoked,auth_type}], "machines":[{machine_id,ip_address,last_heartbeat,version,is_validated,auth_type,self}], "degraded":[...]}`; `self` is true only for the machine whose id equals `LAPI_MACHINE_ID` (always present, false otherwise); `degraded` lists sources that failed (`version`, `bouncers`, `machines`) | none: failures are reported in `degraded` |
| GET | `/api/metrics` | yes | `{"available":true, "acquisition":[{source,lines_read,parsed,unparsed}], "parsers":[{name,hits,parsed,unparsed}]}` or `{"available":false,"reason":"unavailable"}` | none |
| GET | `/api/config/files` | yes | `{"files":["acquis.yaml", ...]}` | 500 `config_unavailable` |
| GET | `/api/config/files/{name...}` | yes | `{"name","content"}` with secrets redacted | 404 `not_found`, 413 `file_too_large`, 500 |
| GET | `/api/hub` | yes | array of `{type,name,status,local_version,description}` (max 1000) | 502 `cscli_failed`, 504 `cscli_timeout` |

## Write

| Method | Path | Auth | Body | Success response | Errors |
|---|---|---|---|---|---|
| POST | `/api/decisions` | yes | `{"ip","duration","reason"}`; `ip` is an IP or CIDR no wider than /8 (IPv4) or /32 (IPv6), `duration` like `24h`, `reason` up to 200 characters, optional | `201 {"status":"created"}` | 400 `invalid_target`, `invalid_duration`, `invalid_reason`, `invalid_request`; 409 `self_ban` (the target is, or a range contains, the caller's client address; checked before any LAPI call); 502 |
| DELETE | `/api/decisions/{id}?scope=<scope>&value=<value>` | yes | `{"confirm":"<id>"}` | `200 {"status":"deleted"}` | 400 `confirmation_required`, `invalid_request`; 404 `not_found`; 409 `target_mismatch`; 502 |
| DELETE | `/api/alerts/{id}?uuid=<uuid>` | admin | `{"confirm":"<id>"}` | `200 {"status":"deleted","archive_deleted":true}` | 400; 403 `forbidden`; 404 `not_found`; 409 `target_mismatch`; 502 `cscli_failed` |
| DELETE | `/api/alerts/archive/{archive_id}` | admin | `{"confirm":"<archive_id>"}` | `200 {"status":"deleted"}` | 400 `invalid_request`, `confirmation_required`; 403; 404 `not_found`; 503 |
| POST | `/api/bouncers` | yes | `{"name"}` | `200 {"name","key"}`, `Cache-Control: no-store` | 400 `invalid_request`; 502; 504 |
| DELETE | `/api/bouncers/{name}` | yes | `{"confirm":"<name>"}` | `200 {"status":"deleted"}` | 400; 502; 504 |
| POST | `/api/machines` | yes | `{"name"}` | `200 {"name","password"}`, `Cache-Control: no-store` | 400; 502; 504 |
| POST | `/api/machines/{name}/validate` | yes | none | `200 {"status":"validated"}` | 400; 502 |
| DELETE | `/api/machines/{name}` | yes | `{"confirm":"<name>"}` | `200 {"status":"deleted"}` | 400; 409 `self_account`; 502 |
| POST | `/api/hub/update` | yes | none | `200 {"status":"updated"}` | 502; 504 |
| POST | `/api/hub/upgrade` | yes | none | `200 {"status":"upgraded"}` | 502; 504 |
| POST | `/api/hub/collections` | yes | `{"name"}` such as `crowdsecurity/linux` | `200 {"status":"installed"}` | 400; 502; 504 |
| DELETE | `/api/hub/collections/{name...}` | yes | `{"confirm":"<name>"}` | `200 {"status":"removed"}` | 400; 502; 504 |
| POST | `/api/crowdsec/reload` | yes | none | `200 {"status":"reload_requested"}` | 502; 504 |

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
target `<engine>/<upstream id>` and refuse a `read_only` account (403 `forbidden`).

In this release the routes marked "yes" above (decisions, bouncers, machines, hub, reload) still
accept a `read_only` account: only the alert deletions and the engine routes check the role. Role
enforcement on the other write routes comes with the account management of a later release.

Machine names match `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`; bouncer names also allow `@` after the first character (bouncers registered over TLS are named `name@<address>`); hub names allow one `/`.
The machine self-check runs before the confirmation check, so `self_account` wins over
`confirmation_required`.

## Engines

CrowdSec engines whose alerts the dashboard archives. The `local` engine comes from `LAPI_URL` /
`LAPI_MACHINE_ID` at start-up and is read-only here. Every route needs a session; all but
`/api/engines/names` also need the `admin` role (403 `forbidden` otherwise, before any read or
write). Bodies are capped at 8 KiB and unknown fields are refused (400 `invalid_request`).
No response, error or audit entry ever contains a machine password or proxy credential: the only
trace of them is `has_proxy_credentials`. Error bodies never repeat a submitted URL.

| Method | Path | Body | Success response | Errors |
|---|---|---|---|---|
| GET | `/api/engines/names` | none | `200 {"items":[{name,is_local,enabled}]}`, any role | 401, 503 `database_unavailable` |
| GET | `/api/engines` | none | `200 {"items":[engine]}` | 403, 503 |
| POST | `/api/engines` | `{name, lapi_url, machine_id, machine_password, proxy?{kind,url,username?,password?}, allow_insecure_http, public_addresses, enabled, sync_enabled}` | `201 engine` | 400 `invalid_engine`, `invalid_request`; 409 `engine_exists`; 403; 503 |
| PATCH | `/api/engines/{name}` | same fields, all optional; absent = unchanged; `"proxy": null` removes the proxy; `proxy.clear_credentials: true` drops the proxy credentials | `200 engine` | 400 `invalid_engine`, `engine_secret_required`, `invalid_request`; 404 `engine_not_found`; 409 `engine_exists`, `engine_local_readonly`; 403; 503 |
| DELETE | `/api/engines/{name}` | `{"confirm":"<name>"}` | `200 {"status":"deleted"}` | 400 `confirmation_required`; 404; 409 `engine_local_readonly`; 403; 503 |
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
  metadata address (`127.0.0.1`, `[::1]`, `169.254.169.254`, `100.100.100.200`, `[fd00:ec2::254]`…)
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

## Everything else

Any other `/api/...` path answers 404 `not_found` (401 without a session). Any other path serves the
single-page application: unknown paths return `index.html`.
