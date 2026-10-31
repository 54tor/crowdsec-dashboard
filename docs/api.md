# HTTP API

JSON over HTTP, served by the same process as the UI. Every route except `healthz` and `login`
needs the `session` cookie (set by login) and answers 401 `unauthenticated` without it. Errors are
`{"error": "<code>"}`; codes are explained in [operations.md](operations.md#troubleshooting).
Unsafe methods from another origin are refused with 403 `cross_origin`. All responses carry the
security headers described in [security.md](security.md#headers-and-content-security-policy).

Delete requests carry a body `{"confirm": "<value>"}` where the value equals the identifier in the
path. Bodies of the bouncer, machine and hub creation routes reject unknown fields.

## Authentication and service

| Method | Path | Auth | Body | Success response | Errors |
|---|---|---|---|---|---|
| GET | `/api/healthz` | no | none | `200 {"status":"ok"}` | none |
| POST | `/api/auth/login` | no | `{"password"}` (max 1 KiB) | `200 {"status":"ok"}` and `Set-Cookie: session` | 400 `invalid_request`, 401 `invalid_credentials`, 429 `too_many_attempts` |
| POST | `/api/auth/logout` | no | none | `200 {"status":"ok"}`, cookie cleared | none |
| GET | `/api/auth/me` | yes | none | `200 {"status":"authenticated"}` | 401 |

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
| GET | `/api/health` | yes | `{"version", "bouncers":[{name,type,version,ip_address,last_pull,revoked,auth_type}], "machines":[{machine_id,ip_address,last_heartbeat,version,is_validated,auth_type}], "degraded":[...]}`; `degraded` lists sources that failed (`version`, `bouncers`, `machines`) | none: failures are reported in `degraded` |
| GET | `/api/metrics` | yes | `{"available":true, "acquisition":[{source,lines_read,parsed,unparsed}], "parsers":[{name,hits,parsed,unparsed}]}` or `{"available":false,"reason":"unavailable"}` | none |
| GET | `/api/config/files` | yes | `{"files":["acquis.yaml", ...]}` | 500 `config_unavailable` |
| GET | `/api/config/files/{name...}` | yes | `{"name","content"}` with secrets redacted | 404 `not_found`, 413 `file_too_large`, 500 |
| GET | `/api/hub` | yes | array of `{type,name,status,local_version,description}` (max 1000) | 502 `cscli_failed`, 504 `cscli_timeout` |

## Write

| Method | Path | Auth | Body | Success response | Errors |
|---|---|---|---|---|---|
| POST | `/api/decisions` | yes | `{"ip","duration","reason"}`; `ip` is an IP or CIDR no wider than /8 (IPv4) or /32 (IPv6), `duration` like `24h`, `reason` up to 200 characters, optional | `201 {"status":"created"}` | 400 `invalid_target`, `invalid_duration`, `invalid_reason`, `invalid_request`; 502 |
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
