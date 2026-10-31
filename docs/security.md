# Security

## Model in one paragraph

One shared admin password protects a web UI that can ban addresses, create credentials and run
`cscli` in the CrowdSec container. The dashboard is a single trusted process: its Go code decides
which commands may run. Treat the dashboard as having the same power as whoever can reach the Docker
socket (see [Limits](#honest-limits)).

## Login

- The password is verified against an argon2id hash (library default parameters). The hash is the
  only secret stored; the plain password is never kept.
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
  memory. Lifetime is fixed (`SESSION_TTL`, default 12 h), not extended by activity.
- Restarting the process logs everyone out. Logout destroys the server-side session.
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
  user to retype the value. Deleting the dashboard's own machine account answers 409 `self_account`.
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
- No audit log, no per-user identity, no two-factor authentication.
- Sessions are lost on restart, and the session store and rate limiter are per process (one replica).

## Exposure advice

- Put it behind a TLS reverse proxy; do not publish the container port.
- Restrict who can reach it: IP allowlist at the proxy, or a VPN, in addition to the password.
- Use a long random admin password; the hash is the only thing to protect in `dashboard.env`
  (mode 0600), together with `LAPI_MACHINE_PASSWORD`.
- Set `TRUSTED_PROXY_CIDRS` to the proxy's single address (see [configuration.md](configuration.md)).
