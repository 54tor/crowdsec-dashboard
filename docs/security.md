# Security

## Model in one paragraph

Named accounts, stored in PostgreSQL, protect a web UI that can ban addresses, create credentials and run
`cscli` in the CrowdSec container. The dashboard is a single trusted process: its Go code decides
which commands may run. Treat the dashboard as having the same power as whoever can reach the Docker
socket (see [Limits](#honest-limits)).

## Accounts and enrolment

- An account has a name (`^[a-z0-9][a-z0-9._-]{0,63}$`) and a password of 12 to 128 characters,
  stored as an argon2id hash (library default parameters) in PostgreSQL. The plain password is never
  kept.
- The first account is created by enrolment. While no account exists, the dashboard generates a
  random token at start, writes it once to its log and keeps it in memory only; it is never in an
  API response or in the database. `POST /api/auth/enroll` needs this token, the new account name and
  password. **Whoever can read the logs while no account exists can create the first (admin) account**:
  protect the logs and enrol promptly after the first start.
- A restart while no account exists generates a new token and invalidates the previous one. Once the
  first account exists, enrolment is closed for good: the route answers 404 and the old token is
  useless. Two simultaneous enrolments with the right token create one account (a PostgreSQL advisory
  lock); the other gets 404, as enrolment is then closed.
- A wrong token answers 403 `invalid_enrollment_token` (a missing or empty one, 400 `invalid_request`);
  it is compared in constant time and enrolment is limited per client like login.

## Login

- Login takes an account name and a password. An unknown account and a wrong password cost the same
  time and answer the same 401 `invalid_credentials`, so accounts cannot be enumerated.
- If PostgreSQL is unreachable, login and authenticated requests answer 503 `database_unavailable`,
  never 401 (which would sign the user out of the interface).
- Rate limits, applied to every login attempt, successful ones included:
  - per client, 5 attempts per minute (burst of 5, one more every 12 s); the client key is the IPv4
    address or the IPv6 `/64` prefix, so rotating addresses inside a /64 does not help;
  - globally, 30 attempts per minute, so a distributed guess cannot run faster whatever the sources;
  - at most 10 000 tracked clients: beyond that new clients are refused until old entries expire;
  - a single password verification at a time (each one allocates 64 MiB for argon2id, the container is capped at 256 MiB); a concurrent attempt answers 429;
  - a failed attempt always takes at least 500 ms.
  Blocked requests answer 429 `too_many_attempts` with `Retry-After: 60`. The global limit means an attacker can briefly lock the
  legitimate admin out; that is accepted over letting guesses through.
- The login body is capped at 1 KiB.

## Sessions

- A session token is 32 random bytes. The server keeps only its SHA-256 digest, with an expiry, in
  the `session` table of PostgreSQL. Lifetime is fixed (`SESSION_TTL`, default 12 h), not extended
  by activity; expired rows are pruned every hour.
- Sessions survive a dashboard restart. Logout destroys the server-side session, "log out
  everywhere" (`POST /api/auth/logout-all`) destroys all sessions of the account, and deleting an
  account removes its sessions (cascade).
- Cookie `session`: `HttpOnly`, `Secure`, `SameSite=Strict`, path `/`. Because of `Secure`, serve the
  dashboard over HTTPS (browsers also accept `http://127.0.0.1` and `localhost`).

## CSRF and cross-origin requests

- `SameSite=Strict` keeps the cookie off cross-site requests.
- Every request also goes through Go's `http.CrossOriginProtection`, which rejects cross-origin
  state-changing requests (based on `Sec-Fetch-Site` / `Origin`) with 403 `cross_origin`. Requests
  without those headers, such as `curl`, are allowed and still need a valid session.

## Headers and content security policy

Every response carries `Content-Security-Policy: default-src 'self'`, `X-Content-Type-Options:
nosniff`, `Referrer-Policy: no-referrer` and `X-Frame-Options: DENY`. Every response under `/api/`
(configuration file contents and new secrets included) carries `Cache-Control: no-store`; static assets do not.

`default-src 'self'` allows only same-origin scripts, styles, fonts, images and connections: no
inline script, no CDN, no external font. The front end bundles its fonts and charts for this reason.
Known consequence: the dialog library injects an inline `<style>` to lock page scrolling, which the
policy blocks. A console message "Applying inline style violates ... Content Security Policy" appears
when a dialog opens, and the page behind a modal dialog can still scroll. Dialogs themselves work.

HSTS is not sent: terminate TLS at the reverse proxy and set it there.

## Command allowlist: the security boundary

The dashboard never builds a shell command. The API maps to 16 named commands, each a fixed argv:

| Area | Commands |
|---|---|
| Alerts | `cscli alerts delete --id <id>` |
| Bouncers | `bouncers list -o json`, `bouncers add <name>`, `bouncers delete <name>` |
| Machines | `machines list -o json`, `machines add <name> --auto -f /dev/stdout`, `machines validate <name>`, `machines delete <name>` |
| Hub | `hub list -o json`, `hub update`, `hub upgrade`, `collections install <name>`, `collections remove <name>` |
| Other | `metrics -o json`, `version`, and `kill -HUP 1` (reload) |

Each variable field is validated before the exec: names `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`, hub names
the same with one optional `vendor/item` slash, ids 1 to 10 digits, durations 1 to 4 digits plus
`s|m|h|d`, targets a plain IP or CIDR of at most 43 characters (no zone, no IPv4-mapped form).
Unknown commands and unexpected fields are refused. Output is capped (8 MiB of stdout) and every
command has a timeout (30 s, 120 s for hub update, upgrade, install and remove). Error responses carry
a stable code only, never command output.

Manual bans go to the LAPI, not through cscli, and refuse ranges wider than /8 (IPv4) or /32 (IPv6),
so `0.0.0.0/0` and `::/0` cannot be banned from the UI.

## Destructive actions and one-time secrets

- Deleting an alert, decision, bouncer, machine or hub collection requires a JSON body
  `{"confirm": "<same value as the path>"}`; otherwise 400 `confirmation_required`. The UI asks the
  user to retype the value (for an unban, the IP or range of the decision; the request still carries the decision id). Deleting the dashboard's own machine account answers 409 `self_account`.
- `POST /api/decisions` refuses with 409 `self_ban` a ban whose target is, or whose range contains, the
  client address of the request, before calling the LAPI. It is a safety net, not a security control:
  the address is the one resolved with the same rule as the login rate limiter, and an address that
  cannot be parsed is not blocked. Behind a reverse proxy it only works if `TRUSTED_PROXY_CIDRS` is
  set; otherwise the proxy's own address is what is compared.
- A new bouncer key and a new machine password are returned once, in the creation response, and are
  not stored or logged. The UI clears them when the dialog closes and cannot be closed while the
  request is pending.

## Configuration files

Only an allowlist is readable: `config.yaml`, `acquis.yaml`, `profiles.yaml`, `acquis.d/*.yaml|yml`
and `parsers/*/*whitelist*.yaml|yml`, each at most 256 KiB. Any file whose name contains
`credentials` is refused, as is any path through a symlink. The mount is read-only.

Redaction is line based. A value is replaced by `[REDACTED]` when its key contains `password`,
`passwd`, `token`, `secret`, `api_key`, `apikey`, `key`, `authorization`, `bearer`, `credential` or
`dsn`, together with the indented block below it; URL userinfo (`://user:pw@`) and `Bearer <value>`
are masked anywhere. Known gaps: a secret stored under a key with another name, or written in a
comment or free text, is not detected. Do not rely on redaction for files you
would not show an admin.

## Honest limits

- The socket proxy filters by method and path, not by body. It allows `POST /containers/<crowdsec>/exec`
  with whatever body the dashboard sends. A compromised dashboard process could therefore ask for an
  exec with any command, as root, and `Privileged`, in the CrowdSec container, and read credential
  files visible there; it could also read credential files in the read-only configuration mount.
  The Go allowlist is the boundary only while the process is intact.
- Consequently, protect the dashboard like the Docker daemon: keep it patched and do not co-host
  it with untrusted workloads.
- The proxy blocks everything else (other containers, images, networks, container creation), so the
  blast radius is the CrowdSec container and the dashboard's own LAPI account, not the whole host.
- No audit log yet, no two-factor authentication, no IP or country allowlist: these come in later
  lots. All accounts created so far are administrators.
- The login rate limiter is per process (one replica).

## Exposure advice

- Put it behind a TLS reverse proxy; do not publish the container port.
- Restrict who can reach it: IP allowlist at the proxy, or a VPN, in addition to the password.
- Use a long random password (12 characters minimum). Protect `dashboard.env` and `postgres.env`
  (mode 0600): they hold the database password and `LAPI_MACHINE_PASSWORD`.
- Set `TRUSTED_PROXY_CIDRS` to the proxy's single address (see [configuration.md](configuration.md)).
