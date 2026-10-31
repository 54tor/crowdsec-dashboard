# Operations

## Known limits

| Area | Behaviour |
|---|---|
| Alerts | Only the 100 most recent alerts of the LAPI are fetched, then paged in the dashboard. When the window is full the UI warns that older entries are not displayed. Filters (`scenario`, IP/CIDR, `since` such as `24h`, `7d`) are applied by the LAPI inside that cap. |
| Decisions | Built from the alerts that still have an active decision (same 100-alert window), expired ones dropped. Decisions of the community blocklist (CAPI) are not listed: they are not attached to local alerts. A manual ban shows up as origin `cscli`, scenario `manual/dashboard`. |
| Unban | Deletes one decision by id. An id that does not exist makes the LAPI answer 500, which the dashboard reports as 502 `lapi_unavailable`, not as a 404. |
| Hub whitelists | Whitelist files that the hub installs as symlinks are not listed in the Config page; symlinks are never followed. |
| Hub list | At most 1000 items are returned. |
| Hub operations | `update`, `upgrade`, `install` and `remove` can take up to 120 s (others 30 s); the HTTP write deadline is extended to match. Other requests have a 60 s write deadline. |
| Reload | "Reload CrowdSec" sends `SIGHUP` to process 1 of the CrowdSec container, so CrowdSec must be PID 1 (true for the official image). Hub changes need it to take effect; the banner "CrowdSec must be reloaded" appears on the Hub page after a change and is kept in the browser tab only, it disappears on a page reload. Counters of the Metrics page restart at zero after a reload. |
| Metrics | Needs Prometheus enabled in CrowdSec, otherwise "Metrics are unavailable" ([configuration.md](configuration.md#prometheus-for-the-metrics-page)). Only the acquisition and parser tables are shown. |
| Contact status | A bouncer or machine is "stale" after more than 5 minutes without contact. The dashboard's own machine account never sends a heartbeat: it is flagged "This dashboard" and never shown as stale. |
| Health page | One failing source does not blank the page: the response lists it in `degraded` (`version`, `bouncers`, `machines`) and shows the others. |
| Sessions | In memory, 12 h by default, lost at restart. One replica only. |

## Troubleshooting

Errors reach the UI as a stable code (`{"error": "<code>"}`), translated in the interface.

| Code | HTTP | Meaning and what to check |
|---|---|---|
| `unauthenticated` | 401 | No or expired session. Sign in again; also happens after a dashboard restart. |
| `invalid_credentials` | 401 | Wrong password. Check `ADMIN_PASSWORD_HASH` was single-quoted in the env file. |
| `too_many_attempts` | 429 | Login rate limit or concurrency cap. Wait a minute (the response carries `Retry-After: 60`). If everybody is limited, the proxy address is probably not in `TRUSTED_PROXY_CIDRS` and all users share one client address. |
| `cross_origin` | 403 | A state-changing request came from another origin. Check that the reverse proxy forwards `Host` and does not rewrite `Origin`. |
| `invalid_request` | 400 | Malformed body, id or filter. |
| `invalid_target`, `invalid_duration`, `invalid_reason` | 400 | Ban form: not an IP/CIDR (or range wider than /8 IPv4, /32 IPv6), duration not like `24h`, reason over 200 characters or with control characters. |
| `confirmation_required` | 400 | A delete request did not repeat the target in `confirm`. |
| `self_account` | 409 | You tried to delete the dashboard's own LAPI machine. |
| `self_ban` | 409 | The ban target is, or its range contains, the address you are connected from (as seen by the dashboard; behind a proxy, set `TRUSTED_PROXY_CIDRS`). Ask another admin or use `cscli decisions add` on the host. |
| `not_found` | 404 | Unknown API route or configuration file not on the allowlist. |
| `file_too_large` | 413 | A configuration file is over 256 KiB. |
| `config_unavailable` | 500 | `CROWDSEC_CONF_DIR` is missing or unreadable. Check the read-only mount. |
| `lapi_unavailable` | 502 | LAPI unreachable, answered 5xx, or refused the machine login. Check `LAPI_URL`, the machine name and password, and that the machine is validated. |
| `lapi_error` | 502 | The LAPI answered with an unexpected 4xx (including 403). Check the machine account. |
| `cscli_failed` | 502 | The exec failed: Docker unreachable, CrowdSec container not running or misnamed, socket proxy denying the call, `cscli` exited non-zero (for example an unknown collection or machine), or output could not be parsed. Look at the socket proxy log first. |
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
- `GET /api/healthz` answers 200 without a session, for container health checks.
- Metrics page empty after a reload: counters restart at zero until new log lines are read.

## Backup and restore

The dashboard holds no state: nothing to back up. Keep the compose file and `dashboard.env` (the
hash and the machine password) in your usual configuration backup. To restore, redeploy them and
recreate the LAPI machine account if the CrowdSec data was lost. CrowdSec's own volumes
(configuration, `crowdsec.db`) are backed up with CrowdSec, not with the dashboard.

To rotate the admin password, generate a new hash, update `dashboard.env` and recreate the container
(this also ends all sessions). To rotate the machine password, run `cscli machines delete` and `add`
again with the new value, then recreate the dashboard.
