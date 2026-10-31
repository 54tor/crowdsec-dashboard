# Configuration

The dashboard is configured only through environment variables, read once at start. Secrets belong
in a file with mode 0600 passed as `env_file` (see `deploy/dashboard.env.example`). Single-quote the
argon2id hash in that file: it contains `$`, which compose would otherwise expand.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `ADMIN_PASSWORD_HASH` | none, required | argon2id encoded hash of the admin password. The process refuses to start when it is empty or not a valid argon2id hash. |
| `SESSION_TTL` | `12h` | Lifetime of a session, a Go duration (`30m`, `12h`). Must be positive. Fixed lifetime from login, not extended by activity. |
| `LISTEN_ADDR` | `:8080` | Address the HTTP server listens on. |
| `LAPI_URL` | none | Base URL of the CrowdSec local API, for example `http://crowdsec:8080`. |
| `LAPI_MACHINE_ID` | none | Name of the LAPI machine account used for alerts and decisions. Also the account the dashboard refuses to delete. |
| `LAPI_MACHINE_PASSWORD` | none | Password of that machine account. |
| `CROWDSEC_CONTAINER` | none | Name of the CrowdSec container in which `cscli` commands are executed. Must match the name allowed in the socket-proxy rule. |
| `DOCKER_HOST` | none | Docker API endpoint, normally the socket proxy: `tcp://socket-proxy:2375`. |
| `CROWDSEC_CONF_DIR` | none | Directory holding a read-only copy of the CrowdSec configuration, for example `/etc/crowdsec`. |
| `TRUSTED_PROXY_CIDRS` | empty | Comma-separated CIDRs of reverse proxies whose `X-Forwarded-For` is believed. Empty means the TCP peer address is always used. |
| `SYNC_ENABLED` | `false` | Turns on the engine synchronisation. When `true`, `SYNC_PEERS_FILE` is required. |
| `SYNC_INTERVAL` | `5m` | Delay between two synchronisation runs, a Go duration. Any configured value below `1m` is refused. |
| `SYNC_DRY_RUN` | `true` | Compute and show the plan without writing anything. Set `false` once the plan looks right. |
| `SYNC_MAX_CHANGES` | `500` | Circuit breaker: maximum additions plus removals per engine and run, from 1 to 100000. |
| `SYNC_READ_LIMIT` | `5000` | Maximum number of alerts read per request from each engine, from 100 to 50000. A read that hits the limit is treated as incomplete. |
| `SYNC_PEERS_FILE` | none | Path of the peers file (see below). Required when `SYNC_ENABLED` is `true`. |
| `SHARE_EXCLUDE_CIDRS` | empty | Comma-separated CIDRs that are never shared with other engines, for example `203.0.113.0/24`. An invalid entry stops the start. |
| `CONFIG_IMPORT_ENABLED` | `false` | Allows importing configuration files from a bundle. |
| `CONFIG_IMPORT_DIR` | none | Absolute, clean path of the directory the import may write to, at least two components deep (`/` and top-level directories such as `/etc` are refused). Required when `CONFIG_IMPORT_ENABLED` is `true`. |

`ADMIN_PASSWORD_HASH`, `SESSION_TTL`, `TRUSTED_PROXY_CIDRS` and the `SYNC_*`, `SHARE_EXCLUDE_CIDRS` and
`CONFIG_IMPORT_*` variables are validated at start; a wrong value stops the process. The LAPI,
Docker and configuration variables have no default and no start-time check: a
wrong value shows up as an error code on the pages that need it (see
[operations.md](operations.md#troubleshooting)).

## Peers file

`SYNC_PEERS_FILE` points to a YAML file listing the other engines to synchronise with. It holds the
peers' machine passwords: treat it as a secret, keep it out of version control and mount it
read-only into the container. The API never serves it.

```yaml
peers:
  - name: edge-1
    url: https://engine-one.example.com:8080
    machine_id: dashboard
    password: change-me-please
    public_ips: [203.0.113.10]
  - name: lab
    url: http://198.51.100.20:8080
    allow_insecure_http: true
    machine_id: dashboard
    password: change-me-too
exclude:
  - 203.0.113.0/24
```

- `name`: unique, matches `^[a-z0-9][a-z0-9-]{0,31}$`; `local` is reserved for the local engine.
- `url`: absolute, `https` unless `allow_insecure_http: true` is set for that peer; no credentials,
  query or fragment in it.
- `machine_id` and `password` (at least 8 characters): the LAPI machine account of the peer.
- `public_ips`: optional addresses other engines see this peer under, added to the exclusions (IPv4-mapped IPv6 forms are converted to IPv4, zones are refused).
- `exclude`: optional CIDRs that are never shared.
- At least one and at most 16 peers, one YAML document, no two peers with the same URL, file at most 64 KiB, regular file only. Unknown fields are refused, and the
  start fails on any error. Error messages name the peer and the field, never the password or the URL.

## Admin password hash

Read the password silently so it stays out of the shell history and the process list, then hash it
with the helper shipped in the image (no Go toolchain needed):

```
read -rs -p 'Admin password: ' admin_password; echo
docker run --rm -i --entrypoint /hashpassword crowdsec-dashboard:latest <<< "$admin_password"
unset admin_password
```

From a source checkout: `(cd backend && go run ./cmd/hashpassword) <<< "$admin_password"`. The helper
reads the first line of stdin and prints the hash (argon2id library default parameters). Put the
printed value, single-quoted, in `ADMIN_PASSWORD_HASH`.

## LAPI machine account

The dashboard logs in to the LAPI as a machine to read alerts, push manual bans and delete
decisions. Create it in the CrowdSec container:

```
docker exec crowdsec cscli machines add dashboard --auto -f /dev/stdout
docker exec crowdsec cscli machines validate dashboard
```

`--auto` makes cscli generate the password, and `-f /dev/stdout` prints the credentials YAML to the
terminal instead of overwriting the credentials file of the engine. Copy the `password:` value into
`LAPI_MACHINE_PASSWORD` in `dashboard.env`. This keeps the password out of the shell history and out
of the process list, which `--password '<password>'` would not. In current CrowdSec releases
`machines add` validates the account at once and `validate` is a no-op; keep it for setups that
require manual validation. Use the machine name for `LAPI_MACHINE_ID`.

## Prometheus for the Metrics page

The Metrics page runs `cscli metrics`, which reads the engine's Prometheus endpoint. Without it the
page shows "Metrics are unavailable". Enable it in the CrowdSec `config.yaml` (or a
`config.yaml.local` override), then reload CrowdSec:

```yaml
prometheus:
  enabled: true
  level: full
  listen_addr: 127.0.0.1
  listen_port: 6060
```

The listener only needs to be reachable from inside the CrowdSec container, so keep it on
`127.0.0.1` unless something else scrapes it. Counters restart at zero on every reload.

## Trusted proxy

The client address drives the per-IP login rate limit. `X-Forwarded-For` is believed only when the
TCP peer is inside `TRUSTED_PROXY_CIDRS`, and the right-most entry that is not itself trusted is
taken as the client.

- List only your reverse proxy, as a single address (`172.30.0.10/32`, or `/128` for IPv6). Give
  the proxy a fixed address on the network it shares with the dashboard.
- Never list a shared subnet: any other container on it could forge the header and dodge the
  limiter.
- Leave it empty when the dashboard is reached directly, and when the proxy address is not known.
  The limiter then sees the proxy address as one client for everybody, which is safe but coarse.
- Do not publish the dashboard port on a public interface. The example compose publishes nothing
  and uses `expose`; the dev stack binds `127.0.0.1` only.

## Socket proxy

The example uses `wollomatic/socket-proxy` with three allow rules (exec inspect, exec create on one
container, exec start) and `-allowfrom=<dashboard container name>`. Replace the container name in
the POST rule if yours differs, and set `DOCKER_GID` to the group that owns the Docker socket
(`stat -c '%g' /var/run/docker.sock`). The proxy runs as an unprivileged user in that group, with a
read-only root filesystem and no capabilities.
