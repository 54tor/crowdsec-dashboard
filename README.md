# CrowdSec dashboard

A small web dashboard for a self-hosted [CrowdSec](https://www.crowdsec.net/) Security Engine
running in Docker. It reads alerts and decisions from the local API (LAPI) and manages bouncers,
machines, hub collections, AppSec items and allowlists by running a fixed set of `cscli` commands
in the CrowdSec container.
It can also archive the alerts of remote engines, share bans between engines, and export or import
the state of the local engine.

## What it is, and what it is not

It is a web UI (French and English, light and dark) shipped as one Go binary that embeds the React
front end, with its state in PostgreSQL: named accounts with an `admin` or `read_only` role, API
tokens, the engines, an archive of their alerts and an audit log.

It is not:

- a replacement for the CrowdSec Console: history is limited to the dashboard's own archive and its
  retention, no community blocklist (CAPI) decisions, no charts of past metrics;
- a configuration editor: configuration files are shown read-only, with secrets redacted; the only
  write is the optional import of `acquis.d` files from a bundle, off by default;
- a hardened boundary on its own: it holds the power to run `cscli` in your CrowdSec container, so
  protect it like the Docker daemon (see [docs/security.md](docs/security.md)).

## Features

| Page | What you can do |
|---|---|
| Alerts | List the 100 most recent live alerts, then the archive of every engine, hourly timeline, filter by scenario, IP/CIDR, age and origin (logs or AppSec), AppSec summary as plain text, delete an alert |
| Decisions | List active local decisions, filter, ban an IP or range (manual ban, refused when the target is in a local allowlist), unban |
| Allowlists | Read the CrowdSec allowlists of every engine; create and delete allowlists and entries, with expiry and comment, on the local engine (administrators, [docs/operations.md](docs/operations.md#allowlists)) |
| Health | CrowdSec version, bouncers and machines with last contact, stale and revoked status |
| Metrics | Acquisition and parser counters from `cscli metrics` (needs Prometheus enabled in CrowdSec) |
| Config | Read-only viewer of an allowlist of configuration files (parser and postoverflow whitelists included), secrets redacted |
| Bouncers | Create (API key shown once), delete |
| Machines | Create (password shown once), validate, delete |
| Hub | List installed items, install or remove a collection, an AppSec rule or an AppSec configuration ([docs/operations.md](docs/operations.md#appsec)), update and upgrade the hub, reload CrowdSec |
| Engines | Register remote CrowdSec engines (administrators), archive their alerts, mark them as sync peers |
| Sync | Share native bans between engines through their LAPI, with dry run, circuit breaker and allowlist filter ([docs/sync.md](docs/sync.md)) |
| Export / Import | Download the hub collections, bans, alerts and configuration of the local engine as a bundle; preview and apply a bundle (administrators, [docs/bundles.md](docs/bundles.md)) |
| Accounts, API tokens | Manage accounts and roles (administrators); create `read` or `write` API tokens |

Every destructive action asks you to retype the target, and the server checks it again.

## Architecture

```
                    TLS, optional IP allowlist / VPN
  Browser  ------------------------------------------>  Reverse proxy
                                                              |  HTTP (X-Forwarded-For)
                                                              v
                                                    +-------------------+
                                                    |     dashboard     |  read-only
                                                    |  (Go + embedded   |<--- mount of the
                                                    |   React front)    |     CrowdSec /etc/crowdsec
                                                    +---------+---------+
                         HTTP, machine login (JWT)            |
              +-----------------------------------+           | Docker API over TCP
              v                                   |           v
      CrowdSec LAPI                               |   +----------------+
      (alerts, decisions)                         |   |  socket-proxy  |  only: exec create on the
                                                  |   +--------+-------+  CrowdSec container, exec
                                                  |            |          start, exec inspect
                                                  |            v
                                                  |   /var/run/docker.sock (read-only mount)
                                                  v
                                         CrowdSec container  <-- `cscli ...` via docker exec
```

- Reads of alerts, decisions and allowlists go to the LAPI over HTTP with a dedicated machine account.
- Bouncers, machines, hub, allowlist writes, metrics, version and reload go through `docker exec` of an allowlisted
  `cscli` command (see [docs/security.md](docs/security.md)). The dashboard never mounts the Docker
  socket: it talks to a filtering proxy.
- Configuration files are read from a read-only mount of the CrowdSec configuration volume.
- Remote engines (archive, sync) are reached over their LAPI with a machine account each, sealed in
  the database; the optional config import writes only to a dedicated `acquis.d` mount
  ([docs/bundles.md](docs/bundles.md#configuration)).
- Accounts and sessions are stored in PostgreSQL (passwords and session tokens are hashed); schema migrations run at every start. The first release, 0.1.0, creates the whole schema from one initial migration; a database from an earlier development build must be recreated ([docs/operations.md](docs/operations.md#postgresql)).
- Sign-in is password, then a second factor (TOTP, or a passkey / security key when WebAuthn is configured, with recovery codes), then an optional per-account IP and country allowlist (country rules use GeoLite2 data, refreshed inside the image when you provide a MaxMind account).

## Quick start

1. Copy `deploy/compose.example.yaml` next to your CrowdSec stack and adapt container names and
   networks (the dashboard needs to reach the LAPI and the socket proxy).
2. Create the secrets key that encrypts the TOTP secrets, outside git:
   `install -d -m 0700 secrets && (umask 077; openssl rand -base64 32 > secrets/dashboard-secrets.key)`
   and back it up apart from the database ([docs/operations.md](docs/operations.md#secrets-key)).
   Then create the LAPI machine account of the dashboard, then fill `deploy/dashboard.env.example` (copy to
   `dashboard.env`, mode 0600) and `deploy/postgres.env.example` (copy to `postgres.env`): see
   [docs/configuration.md](docs/configuration.md).
3. Set `DOCKER_GID` to the group of the Docker socket, then start:

   ```
   export DOCKER_GID="$(stat -c '%g' /var/run/docker.sock)"
   docker compose -f compose.example.yaml up -d --build
   ```

4. Read the enrolment token in the dashboard log (`docker logs`), open `/enroll`, create the first
   account and confirm its second factor (the account is created only then): see [docs/operations.md](docs/operations.md#first-start-and-enrolment).
5. Put a TLS reverse proxy in front of `dashboard:8080` and set `TRUSTED_PROXY_CIDRS` to its single
   address. The session cookie is `Secure`: sign-in only works over HTTPS, or over
   `http://127.0.0.1` / `http://localhost` in browsers that treat these as secure contexts.

## Documentation

- [docs/configuration.md](docs/configuration.md): environment variables, secrets key, WebAuthn, MaxMind, database, machine account, Prometheus
- [docs/security.md](docs/security.md): threat model, protections and their limits
- [docs/operations.md](docs/operations.md): known limits, troubleshooting by error code, secrets key, dashboard image, account recovery, backup
- [docs/api.md](docs/api.md): HTTP API reference
- [docs/sync.md](docs/sync.md): engine synchronisation
- [docs/bundles.md](docs/bundles.md): export and import bundles
- [docs/development.md](docs/development.md): layout, tests, dev stack, conventions
