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
| POST | `/api/auth/login/webauthn` | `{"credential": <PublicKeyCredential.toJSON()>}` (max 64 KiB) | as above | 401 `webauthn_failed` (including an assertion without a prior `options` call) |
| POST | `/api/auth/login/setup/totp` | `{}` | `200 {"secret","otpauth_url"}` | 503 `second_factor_unavailable` |
| POST | `/api/auth/login/setup/totp/confirm` | `{"code"}` | `200 {"status":"ok"}` | 400 `invalid_code` |
| POST | `/api/auth/login/setup/webauthn/options` | `{}` | `200` creation options | 404 `webauthn_disabled` |
| POST | `/api/auth/login/setup/webauthn/confirm` | `{"credential": ...}` | `200 {"status":"ok"}` | 400 `webauthn_failed` |
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

## Read

List routes take `page` (1 to 10000, default 1), `per_page` (default 50, capped at 100) and the
filters `scenario` (`^[A-Za-z0-9][A-Za-z0-9._/:-]{0,127}$`), `ip` (IP or CIDR) and `since` (`<1-4
digits>` then `s`, `m`, `h` or `d`). Invalid values answer 400 `invalid_request`. The page object is
`{"items": [...], "page", "per_page", "window_size", "may_be_truncated"}`; `window_size` is the
number of entries fetched (at most 100), `may_be_truncated` is true when the window is full.

| Method | Path | Auth | Response | Errors |
|---|---|---|---|---|
| GET | `/api/alerts` | yes | page of alerts: `id, created_at, machine_id, scenario, message, events_count, start_at, stop_at, simulated, source{scope,value,ip,range,cn,as_name,as_number}, decisions[]` (always an array) | 400, 502 `lapi_unavailable`, `lapi_error` |
| GET | `/api/decisions` | yes | page of active decisions: `id, alert_id, origin, type, scope, value, duration, until, scenario, simulated` | 400, 502 |
| GET | `/api/health` | yes | `{"version", "bouncers":[{name,type,version,ip_address,last_pull,revoked,auth_type}], "machines":[{machine_id,ip_address,last_heartbeat,version,is_validated,auth_type,self}], "degraded":[...]}`; `self` is true only for the machine whose id equals `LAPI_MACHINE_ID` (always present, false otherwise); `degraded` lists sources that failed (`version`, `bouncers`, `machines`) | none: failures are reported in `degraded` |
| GET | `/api/metrics` | yes | `{"available":true, "acquisition":[{source,lines_read,parsed,unparsed}], "parsers":[{name,hits,parsed,unparsed}]}` or `{"available":false,"reason":"unavailable"}` | none |
| GET | `/api/config/files` | yes | `{"files":["acquis.yaml", ...]}` | 500 `config_unavailable` |
| GET | `/api/config/files/{name...}` | yes | `{"name","content"}` with secrets redacted | 404 `not_found`, 413 `file_too_large`, 500 |
| GET | `/api/hub` | yes | array of `{type,name,status,local_version,description}` (max 1000) | 502 `cscli_failed`, 504 `cscli_timeout` |

## Write

| Method | Path | Auth | Body | Success response | Errors |
|---|---|---|---|---|---|
| POST | `/api/decisions` | yes | `{"ip","duration","reason"}`; `ip` is an IP or CIDR no wider than /8 (IPv4) or /32 (IPv6), `duration` like `24h`, `reason` up to 200 characters, optional | `201 {"status":"created"}` | 400 `invalid_target`, `invalid_duration`, `invalid_reason`, `invalid_request`; 409 `self_ban` (the target is, or a range contains, the caller's client address; checked before any LAPI call); 502 |
| DELETE | `/api/decisions/{id}` | yes | `{"confirm":"<id>"}` | `200 {"status":"deleted"}` | 400 `confirmation_required`, `invalid_request`; 502 |
| DELETE | `/api/alerts/{id}` | yes | `{"confirm":"<id>"}` | `200 {"status":"deleted"}` | 400; 502 `cscli_failed` |
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

Machine names match `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`; bouncer names also allow `@` after the first character (bouncers registered over TLS are named `name@<address>`); hub names allow one `/`.
The machine self-check runs before the confirmation check, so `self_account` wins over
`confirmation_required`.

## Everything else

Any other `/api/...` path answers 404 `not_found` (401 without a session). Any other path serves the
single-page application: unknown paths return `index.html`.
