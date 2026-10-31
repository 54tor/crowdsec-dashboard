# CrowdSec dashboard

A small web dashboard for a self-hosted [CrowdSec](https://www.crowdsec.net/) Security Engine
running in Docker. It reads alerts and decisions from the local API (LAPI) and manages bouncers,
machines and hub collections by running a fixed set of `cscli` commands in the CrowdSec container.

## What it is, and what it is not

It is a single-admin, stateless web UI (French and English, light and dark) shipped as one Go
binary that embeds the React front end.

It is not:

- a multi-user or role-based tool: there is one shared admin password;
- a replacement for the CrowdSec Console: no history beyond what the LAPI keeps, no community
  blocklist (CAPI) decisions, no charts of past metrics;
- a configuration editor: configuration files are shown read-only, with secrets redacted;
- a hardened boundary on its own: it holds the power to run `cscli` in your CrowdSec container, so
  protect it like the Docker daemon (see [docs/security.md](docs/security.md)).

## Features

| Page | What you can do |
|---|---|
| Alerts | List the 100 most recent alerts, hourly timeline, filter by scenario, IP/CIDR and age, delete an alert |
| Decisions | List active local decisions, filter, ban an IP or range (manual ban), unban |
| Health | CrowdSec version, bouncers and machines with last contact, stale and revoked status |
| Metrics | Acquisition and parser counters from `cscli metrics` (needs Prometheus enabled in CrowdSec) |
| Config | Read-only viewer of an allowlist of configuration files, secrets redacted |
| Bouncers | Create (API key shown once), delete |
| Machines | Create (password shown once), validate, delete |
| Hub | List installed items, install or remove a collection, update and upgrade the hub, reload CrowdSec |

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

- Reads of alerts and decisions go to the LAPI over HTTP with a dedicated machine account.
- Bouncers, machines, hub, metrics, version and reload go through `docker exec` of an allowlisted
  `cscli` command (see [docs/security.md](docs/security.md)). The dashboard never mounts the Docker
  socket: it talks to a filtering proxy.
- Configuration files are read from a read-only mount of the CrowdSec configuration volume.
- Nothing is stored by the dashboard. Sessions live in memory.

## Quick start

1. Copy `deploy/compose.example.yaml` next to your CrowdSec stack and adapt container names and
   networks (the dashboard needs to reach the LAPI and the socket proxy).
2. Create the LAPI machine account of the dashboard and the admin password hash, then fill
   `deploy/dashboard.env.example` (copy to `dashboard.env`, mode 0600): see
   [docs/configuration.md](docs/configuration.md).
3. Set `DOCKER_GID` to the group of the Docker socket, then start:

   ```
   export DOCKER_GID="$(stat -c '%g' /var/run/docker.sock)"
   docker compose -f compose.example.yaml up -d --build
   ```

4. Put a TLS reverse proxy in front of `dashboard:8080` and set `TRUSTED_PROXY_CIDRS` to its single
   address. The session cookie is `Secure`: sign-in only works over HTTPS, or over
   `http://127.0.0.1` / `http://localhost` in browsers that treat these as secure contexts.

## Documentation

- [docs/configuration.md](docs/configuration.md): environment variables, password hash, machine account, Prometheus
- [docs/security.md](docs/security.md): threat model, protections and their limits
- [docs/operations.md](docs/operations.md): known limits, troubleshooting by error code, backup
- [docs/api.md](docs/api.md): HTTP API reference
- [docs/development.md](docs/development.md): layout, tests, dev stack, conventions
