# Configuration

The dashboard is configured only through environment variables, read once at start. Secrets belong
in a file with mode 0600 passed as `env_file` (see `deploy/dashboard.env.example`). The PostgreSQL
service reads its own file (`deploy/postgres.env.example`). Single-quote values that contain `$` in
these files, which compose would otherwise expand.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | none, required | PostgreSQL connection URL, `postgres://` or `postgresql://`, for example `postgres://dashboard:<password>@postgres:5432/dashboard`. Percent-encode special characters of the password. The process refuses to start when it is empty, has another scheme, or the database is unreachable. The value is never logged. |
| `SESSION_TTL` | `12h` | Lifetime of a session, a Go duration (`30m`, `12h`). Must be positive. Fixed lifetime from login, not extended by activity. |
| `LISTEN_ADDR` | `:8080` | Address the HTTP server listens on. |
| `LAPI_URL` | none | Base URL of the CrowdSec local API, for example `http://crowdsec:8080`. |
| `LAPI_MACHINE_ID` | none | Name of the LAPI machine account used for alerts and decisions. Also the account the dashboard refuses to delete. |
| `LAPI_MACHINE_PASSWORD` | none | Password of that machine account. |
| `CROWDSEC_CONTAINER` | none | Name of the CrowdSec container in which `cscli` commands are executed. Must match the name allowed in the socket-proxy rule. |
| `DOCKER_HOST` | none | Docker API endpoint, normally the socket proxy: `tcp://socket-proxy:2375`. |
| `CROWDSEC_CONF_DIR` | none | Directory holding a read-only copy of the CrowdSec configuration, for example `/etc/crowdsec`. |
| `TRUSTED_PROXY_CIDRS` | empty | Comma-separated CIDRs of reverse proxies whose `X-Forwarded-For` is believed. Empty means the TCP peer address is always used. |
| `SECRETS_KEY_FILE` | none, required | Path of the file holding the key that encrypts the TOTP secrets: 32 random bytes, base64 encoded on one line. The process refuses to start when it is unset, unreadable, not base64 or not 32 bytes. The example compose sets `/run/dashboard-secrets/key` (see [Secrets key](#secrets-key)). |
| `WEBAUTHN_RP_ID` | empty | WebAuthn relying party ID: the public domain name of the dashboard, lowercase, without scheme, port or path, never an IP address. Set it together with `WEBAUTHN_RP_ORIGINS` or leave both empty (TOTP only). |
| `WEBAUTHN_RP_ORIGINS` | empty | Comma-separated bare origins from which the browser reaches the dashboard, for example `https://dashboard.example.com`. Each must be `https://` (`http://` only for `localhost`), without path, and equal to `WEBAUTHN_RP_ID` or one of its subdomains. |
| `GEOIP_DATABASE_FILE` | empty | Path of a GeoLite2 Country database (`.mmdb`), for example `/var/lib/geoip/GeoLite2-Country.mmdb`. Empty means no geolocation: country rules are refused ([security.md](security.md#access-allowlist)). The file is re-read when it changes (checked every minute). |
| `GEOIPUPDATE_FREQUENCY_HOURS` | `24` | Hours between two GeoLite2 updates: `1`, `2`, `3`, `4`, `6`, `8` or `12`, or a multiple of 24 up to `168` (`24`, `48`, ... `168`). Any other value is reported in the log and replaced by `24`. Used by the image only, not by the Go process. |
| `DOCKER_USER_UID`, `DOCKER_USER_GID` | `10000` | Image only. UID and GID of the unprivileged `docker-user` that runs the dashboard. Changing them rewrites `/etc/passwd` and `/etc/group` and therefore needs a writable root filesystem (`read_only: false`); with `read_only: true` the container stops. |
| `WAIT_FOR_NETWORK` | `true` in the image, `"false"` in the example compose | Image only. When true, the container waits at start until `WAIT_FOR_NETWORK_HOST:WAIT_FOR_NETWORK_PORT` (default `1.1.1.1:443`) accepts a connection, for at most `WAIT_FOR_NETWORK_TIMEOUT` seconds (default 15, polled every `WAIT_FOR_NETWORK_INTERVAL`, default 1), then continues anyway unless `WAIT_FOR_NETWORK_STRICT` is true. The example disables it: the database is already guaranteed by `depends_on: service_healthy`, and the default probe would add an external dependency. |
| `SYNC_ENABLED` | `false` | Turns on the engine synchronisation. When `true`, `SYNC_PEERS_FILE` is required. |
| `SYNC_INTERVAL` | `5m` | Delay between two synchronisation runs, a Go duration. Any configured value below `1m` is refused. |
| `SYNC_DRY_RUN` | `true` | Compute and show the plan without writing anything. Set `false` once the plan looks right. |
| `SYNC_MAX_CHANGES` | `500` | Circuit breaker: maximum additions plus removals per engine and run, from 1 to 100000. |
| `SYNC_READ_LIMIT` | `5000` | Maximum number of alerts read per request from each engine, from 100 to 50000. A read that hits the limit is treated as incomplete. |
| `SYNC_PEERS_FILE` | none | Path of the peers file (see below). Required when `SYNC_ENABLED` is `true`. |
| `SHARE_EXCLUDE_CIDRS` | empty | Comma-separated CIDRs that are never shared with other engines, for example `203.0.113.0/24`. An invalid entry stops the start. |
| `CONFIG_IMPORT_ENABLED` | `false` | Allows importing configuration files from a bundle. |
| `CONFIG_IMPORT_DIR` | none | Absolute, clean path of the directory the import may write to, at least two components deep (`/` and top-level directories such as `/etc` are refused). Required when `CONFIG_IMPORT_ENABLED` is `true`. |

`DATABASE_URL`, `SECRETS_KEY_FILE`, `WEBAUTHN_RP_*`, `SESSION_TTL`, `TRUSTED_PROXY_CIDRS` and the `SYNC_*`, `SHARE_EXCLUDE_CIDRS` and
`CONFIG_IMPORT_*` variables are validated at start; a wrong value stops the process. The LAPI,
Docker and configuration variables have no default and no start-time check: a
wrong value shows up as an error code on the pages that need it (see
[operations.md](operations.md#troubleshooting)).

## Accounts and the database

Accounts and sessions live in PostgreSQL. There is no admin password in the configuration any more:
`ADMIN_PASSWORD_HASH` and the `hashpassword` command were removed, and a leftover `ADMIN_PASSWORD_HASH`
is ignored. The first account is created from the web interface with a one-time token written to the
dashboard log, and only once its second factor is confirmed (see
[operations.md](operations.md#first-start-and-enrolment)).

At every start the dashboard applies the pending schema migrations before it serves requests; a
failed migration stops the start. Back up the database before upgrading to a new version (see
[operations.md](operations.md#postgresql)).

## Secrets key

TOTP secrets are stored encrypted (AES-256-GCM) with a key that lives outside the database. Generate
it once, outside git, and keep it in a file readable only by you:

```
install -d -m 0700 secrets && (umask 077; openssl rand -base64 32 > secrets/dashboard-secrets.key)
```

The example compose passes it as the compose secret `dashboard-secrets-key`, mounted at
`/run/secrets/dashboard-secrets-key`. At every start the `25-secrets-key` init script copies it to
`/run/dashboard-secrets/key` (a tmpfs directory, mode 0700, file 0400, owned by `docker-user`), which
is the path `SECRETS_KEY_FILE` points to. The dashboard cannot read the compose secret itself, which
is root-owned. The init script fails, and the container stops, when the secret is missing or empty.
The key is identified by its `key_id`, the first 16 hex characters of its SHA-256, stored with each
encrypted secret.

**Losing the key makes every TOTP secret unreadable**: with the wrong or a missing key, TOTP codes
are never accepted. Back the key up separately from the database (see
[operations.md](operations.md#secrets-key)). Only one key is active; there is no rotation yet.

## WebAuthn

WebAuthn (passkeys, hardware security keys) is optional and enabled only when `WEBAUTHN_RP_ID` and
`WEBAUTHN_RP_ORIGINS` are both set. Setting only one stops the start, as does an invalid value. The
values are never derived from request headers. Without them only TOTP is offered.

- Production: the public name and origin of the dashboard behind your reverse proxy, for example
  `WEBAUTHN_RP_ID=dashboard.example.com` and `WEBAUTHN_RP_ORIGINS=https://dashboard.example.com`.
  A passkey is bound to the relying party ID: changing it later makes existing passkeys unusable.
- Development: `WEBAUTHN_RP_ID=localhost` and `WEBAUTHN_RP_ORIGINS=http://localhost:18080`, and open
  `http://localhost:18080`, not `http://127.0.0.1:18080` (an IP address cannot be a relying party
  ID). The `deploy/dev` compose does not set them, so the dev stack offers TOTP only until you add
  both variables to its `dashboard` service.
- The browser needs the JSON WebAuthn API (`PublicKeyCredential.parseCreationOptionsFromJSON` and
  `toJSON()`). A browser without it shows an error for passkeys and keeps TOTP available.

## MaxMind credentials

Country rules need the GeoLite2 Country database. The image can fetch and refresh it with
`geoipupdate` when you give it a MaxMind account (free GeoLite2 account) as two compose secret
files, never as variables or arguments:

```
(umask 077; printf '%s' '<account id>' > secrets/maxmind-account-id; printf '%s' '<licence key>' > secrets/maxmind-license-key)
```

Uncomment the `maxmind-account-id` and `maxmind-license-key` entries of `compose.example.yaml` (service
and top-level `secrets`). The `30-geoipupdate` init script requires a numeric account id and a licence
key made of letters, digits and `_`; with a missing, empty or malformed file it logs why and
schedules nothing (the container still starts, country rules stay refused). Otherwise it writes
`GeoIP.conf` (`/run/geoipupdate`, 0600, owned by `docker-user`, so the dashboard process can read the
licence key; see [security.md](security.md#container-image)) and a cron entry at minute 17 for `GEOIPUPDATE_FREQUENCY_HOURS`. The database goes to the
`geoip-data` volume, mounted at `/var/lib/geoip`.

This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com.
Use of the GeoLite2 data is governed by MaxMind's GeoLite2 licence terms, which you accept with your
account.

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
