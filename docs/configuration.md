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
| `LAPI_URL` | required | Base URL of the CrowdSec local API, for example `http://crowdsec:8080`. Startup refuses with `LAPI_URL is required` when it is empty; the value is never echoed in errors. |
| `LAPI_MACHINE_ID` | none | Name of the LAPI machine account used for alerts and decisions. Also the account the dashboard refuses to delete. |
| `LAPI_MACHINE_PASSWORD` | none | Password of that machine account. |
| `CROWDSEC_CONTAINER` | none | Name of the CrowdSec container in which `cscli` commands are executed. Must match the name allowed in the socket-proxy rule. |
| `DOCKER_HOST` | none | Docker API endpoint, normally the socket proxy: `tcp://socket-proxy:2375`. |
| `CROWDSEC_CONF_DIR` | none | Directory holding the CrowdSec configuration, for example `/etc/crowdsec`. Mounted read-write it enables the config editor; mounted read-only the Config page stays a viewer and saves answer `config_unavailable` ([Config editor mount](#config-editor-mount)). |
| `LOGS_ALLOWED_ROOTS` | empty | Colon-separated absolute folders the dashboard may read log files from, for the `local` engine's received logs view ([Received logs](operations.md#received-logs)). Empty disables the view (`logs_disabled`). Mount the log folders read-only at the same paths as in the CrowdSec acquisition. |
| `TRUSTED_PROXY_CIDRS` | empty | Comma-separated CIDRs of reverse proxies whose `X-Forwarded-For` is believed. Empty means the TCP peer address is always used. An entry with a zero-length prefix (`0.0.0.0/0`, `::/0`) stops the start. |
| `SECRETS_KEY_FILE` | none, required | Path of the file holding the key that encrypts the TOTP secrets: 32 random bytes, base64 encoded on one line. The process refuses to start when it is unset, unreadable, not base64 or not 32 bytes. The example compose sets `/run/dashboard-secrets/key` (see [Secrets key](#secrets-key)). |
| `SECRETS_RETIRED_KEY_FILES` | empty | Comma-separated paths of the retired keys the dashboard still reads during a rotation (same format as the current key), for example `/run/dashboard-secrets/retired-1`. They are the copies made at start by the `25-secrets-key` script from `SECRETS_RETIRED_KEY_SOURCES` (compose secrets under `/run/secrets`, read by the script only). A stored secret whose key is neither the current key nor listed here stops the start and the log names the key ids ([Secrets key](#secrets-key)). |
| `WEBAUTHN_RP_ID` | empty | WebAuthn relying party ID: the public domain name of the dashboard, lowercase, without scheme, port or path, never an IP address. Set it together with `WEBAUTHN_RP_ORIGINS` or leave both empty (TOTP only). |
| `WEBAUTHN_RP_ORIGINS` | empty | Comma-separated bare origins from which the browser reaches the dashboard, for example `https://dashboard.example.com`. Each must be `https://` (`http://` only for `localhost`), without path, and equal to `WEBAUTHN_RP_ID` or one of its subdomains. |
| `GEOIP_DATABASE_FILE` | empty | Path of a GeoLite2 Country database (`.mmdb`), for example `/var/lib/geoip/GeoLite2-Country.mmdb`. Empty means no geolocation: country rules are refused ([security.md](security.md#access-allowlist)). The file is re-read when it changes (checked every minute). |
| `GEOIPUPDATE_FREQUENCY_HOURS` | `24` | Hours between two GeoLite2 updates: `1`, `2`, `3`, `4`, `6`, `8` or `12`, or a multiple of 24 up to `168` (`24`, `48`, ... `168`). Any other value is reported in the log and replaced by `24`. Hourly values run at minute 17 (`17 */N * * *`); `24` and above run at 03:17, multi-day values (`48` to `168`) with a day-of-month step (`17 3 */D * *`, `D` = N/24), so the step restarts on the 1st and the last gap of a month is shorter. Used by the image only, not by the Go process. |
| `DOCKER_USER_UID`, `DOCKER_USER_GID` | `10000` | Image only. UID and GID of the unprivileged `docker-user` that runs the dashboard. Changing them rewrites `/etc/passwd` and `/etc/group` and therefore needs a writable root filesystem (`read_only: false`); with `read_only: true` the container stops. |
| `WAIT_FOR_NETWORK` | `true` in the image, `"false"` in the example compose | Image only. When true, the container waits at start until `WAIT_FOR_NETWORK_HOST:WAIT_FOR_NETWORK_PORT` (default `1.1.1.1:443`) accepts a connection, for at most `WAIT_FOR_NETWORK_TIMEOUT` seconds (default 15, polled every `WAIT_FOR_NETWORK_INTERVAL`, default 1), then continues anyway unless `WAIT_FOR_NETWORK_STRICT` is true. The example disables it: the database is already guaranteed by `depends_on: service_healthy`, and the default probe would add an external dependency. |
| `SYNC_ENABLED` | `false` | Turns on the scheduled engine synchronisation ([sync.md](sync.md)). Peers are the engines of the Engines page with "Use as a synchronisation peer" checked. |
| `SYNC_INTERVAL` | `5m` | Delay between two scheduled synchronisation runs, a Go duration, at least `1m`. It is also the extension threshold: a copy is renewed when its source has more than this much time left beyond the copy (floored at 1 minute). |
| `SYNC_DRY_RUN` | `true` | Compute and show the plan without writing anything. Set `false` once the plan looks right. |
| `SYNC_MAX_CHANGES` | `500` | Circuit breaker: maximum additions plus removals per target engine, and per source engine, in one run, from 1 to 100000. The decisions of one bundle import are capped at `min(500, SYNC_MAX_CHANGES)`. |
| `SYNC_READ_LIMIT` | `5000` | Maximum number of alerts read per request from each engine, from 100 to 50000. A read that hits the limit is treated as incomplete. |
| `SYNC_PEERS_FILE` | removed | Refused: when set, the dashboard does not start (`SYNC_PEERS_FILE is no longer supported: add sync peers on the Engines page`). Re-enter the peers on the Engines page ([sync.md](sync.md#peers-come-from-the-engine-table)). |
| `SHARE_EXCLUDE_CIDRS` | empty | Comma-separated CIDRs that are never shared by the sync nor imported from a bundle, for example `203.0.113.0/24`. An invalid entry stops the start. |
| `CONFIG_IMPORT_ENABLED` | `false` | Allows importing `acquis.d` files from a bundle into `CONFIG_IMPORT_DIR` ([bundles.md](bundles.md#configuration)). |
| `CONFIG_IMPORT_DIR` | none | Absolute, clean path of the dedicated writable directory the import writes to, at least two components deep (`/` and top-level directories such as `/etc` are refused). Required when `CONFIG_IMPORT_ENABLED` is `true`. It must be the directory CrowdSec reads as its `acquis.d`, mounted at another path in the dashboard ([Config import mount](#config-import-mount)). |
| `COLLECTOR_INTERVAL` | `1m` | Delay between two archive collections of each enabled engine, a Go duration. Any value below `15s` is refused. A failing engine is retried with an exponential backoff (doubling from this interval, ±20 %, at most 1 h) without delaying the others. |
| `COLLECTOR_POLL_LIMIT` | `1000` | Number of newest alerts read from an engine on each collection, from 100 to 5000. The first collection, and any collection that finds a gap since the last one, reads the whole history instead (at most 16 MiB and 120 s); when that full read is truncated or too slow the collection falls back to this limit and the engine is marked `history_incomplete`. |
| `ARCHIVE_ALERT_RETENTION_DAYS` | `365` | Days an archived alert is kept, counted from its collection time, from 1 to 3650. |
| `ARCHIVE_DECISION_RETENTION_DAYS` | `365` | Days an archived decision is kept, from 1 to 3650, never more than `ARCHIVE_ALERT_RETENTION_DAYS`. |
| `AUDIT_RETENTION_DAYS` | `365` | Days an audit event is kept, from 90 to 3650. |
| `AUDIT_IP_RETENTION_DAYS` | `30` | Days the client address of an audit event, and the target of a `login_failure` event (the name as typed, possibly an e-mail address), are kept; then they are erased and the event stays. From 1 to `AUDIT_RETENTION_DAYS`. |
| `API_TOKEN_RETENTION_DAYS` | `30` | Days a revoked or expired API token row is kept before deletion, from 1 to 3650. A revoked or expired token never authenticates, whatever this value. |
| `ARCHIVE_EVENT_RETENTION_DAYS` | `90` | Days the archived events (attacker-controlled data, the largest part) are kept, from 1 to 3650, never more than `ARCHIVE_ALERT_RETENTION_DAYS`. |

The archive retention runs once at start and then every hour (each run stops after 30 minutes and
resumes at the next one). All three horizons count from the time the dashboard collected the alert
(its own clock, so a skewed engine clock cannot shorten or extend them). Each run deletes, in this
order and in batches of 5 000 rows, the events, then the decisions, then the alerts older than their
horizon; deleting an alert also deletes whatever events and decisions it still has. A decision or
event retention longer than the alert retention would be cut short silently by that cascade, so it
is refused at start. A decision still active on the engine (its expiry, computed at collection from
the engine's remaining duration, is not past) is never purged, and the alert that owns it is kept
until the decision expires, whatever the horizons; the events of that alert still follow their own
horizon. A decision without a usable expiry is treated as inactive and follows its horizon.

The audit, token and archive retentions run in one hourly job ([operations.md](operations.md#retention-and-purge)).

`DATABASE_URL`, `SECRETS_KEY_FILE`, `SECRETS_RETIRED_KEY_FILES`, `WEBAUTHN_RP_*`, `SESSION_TTL`, `TRUSTED_PROXY_CIDRS` and the `SYNC_*`, `SHARE_EXCLUDE_CIDRS`,
`COLLECTOR_*`, `ARCHIVE_*`, `AUDIT_*`, `API_TOKEN_RETENTION_DAYS` and `CONFIG_IMPORT_*` variables are validated at start; a wrong value stops the process. The LAPI,
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

TOTP secrets and the secrets of the engines (machine passwords, proxy credentials) are stored encrypted (AES-256-GCM) with a key that lives outside the database. Generate
it once, outside git, and keep it in a file readable only by you:

```
install -d -m 0700 secrets && (umask 077; openssl rand -base64 32 > secrets/dashboard-secrets.key)
```

The example compose passes it as the compose secret `dashboard-secrets-key`, mounted at
`/run/secrets/dashboard-secrets-key`. At every start the `25-secrets-key` init script copies it to
`/run/dashboard-secrets/key` (a tmpfs directory, mode 0700, file 0400, owned by `docker-user`), which
is the path `SECRETS_KEY_FILE` points to. The dashboard cannot read the compose secret itself: it keeps
the host owner and mode (owned by the host user, mode 0600), so it is not readable by `docker-user`. The init script fails, and the container stops, when the secret is missing or empty.
The key is identified by its `key_id`, the first 16 hex characters of its SHA-256, stored with each
encrypted secret.

**Losing the key makes every TOTP secret and engine secret unreadable**: with the wrong or a missing key, TOTP codes
are never accepted. Back the key up separately from the database (see
[operations.md](operations.md#secrets-key)). Only one key seals new secrets; during a rotation the
previous keys are listed in `SECRETS_RETIRED_KEY_FILES` (and `SECRETS_RETIRED_KEY_SOURCES`, read by the
init script) and `dashboard rotate-secrets` rewrites the rows
([operations.md](operations.md#rotating-the-secrets-key)).

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

## Engine synchronisation

The sync is configured by the `SYNC_*` and `SHARE_EXCLUDE_CIDRS` variables above; the peers
themselves, with their machine credentials and public addresses, are rows of the engine table,
managed on the Engines page ([sync.md](sync.md)). There is no peers file any more: `SYNC_PEERS_FILE`
stops the start. The safe first deployment is `SYNC_ENABLED=true` with `SYNC_DRY_RUN=true`, then
`SYNC_DRY_RUN=false` once the plan on the Sync page looks right.

## Config editor mount

The editor of the Config page (advanced mode, [api.md](api.md#configuration-editor)) writes straight
into `CROWDSEC_CONF_DIR`, so the example compose mounts the CrowdSec configuration volume
**read-write** in the dashboard. This widens the attack surface ([security.md](security.md#configuration-editor-and-the-writable-mount)).
To keep the viewer only, append `:ro` to that mount: editing then answers `config_unavailable` and
nothing else changes.

- **Ownership**: the dashboard runs as uid and gid 10000 by default (`DOCKER_USER_UID`,
  `DOCKER_USER_GID`), while the `crowdsec-config` volume of the example is created by the CrowdSec
  container as root, with directories in mode 0755. As is, the dashboard cannot create its
  temporary files nor `.dashboard-backup/` there, and the editor reports `writable: false`. Give
  that user write access to `CROWDSEC_CONF_DIR` and to each directory holding a file you edit
  (`acquis.d`, `parsers/<stage>`, `postoverflows/<stage>`), by ownership, group or ACL, and keep the
  files you edit readable by it. For a host directory this is the same step as for the import:
  `install -d -o 10000 -g 10000 -m 0750 <directory>`. Only the top directory is probed: a
  subdirectory left root-owned makes the save of its files fail.
- **New files** are created owned by the dashboard user, mode 0640; a replaced file keeps its mode
  and becomes owned by the dashboard user. CrowdSec (root) still reads them.
- **Not verified in a container**: this ownership setup was not tested against the real CrowdSec
  image. Verify with the Config page: `writable` must be true (`GET /api/config/edit/<name>`), and
  one save of a harmless file must succeed.
- **Crash recovery**: a save interrupted by a crash or a kill is replayed or rolled back at the next
  start ([operations.md](operations.md#config-editor-recovery)).
- **Editable files**: the allow list of the viewer, at most 256 KiB each: `acquis.yaml`,
  `profiles.yaml`, `acquis.d/*.yaml|yml`, `parsers/*/*whitelist*.yaml|yml`,
  `postoverflows/*/*whitelist*.yaml|yml`, and `config.yaml.local`. `credentials` files are never
  readable or writable.
- **`config.yaml` is read-only.** Changes to the main configuration go into `config.yaml.local`,
  CrowdSec's native override file; `config.yaml` itself is left intact.
- **Backups**: every save, restore or delete keeps the previous content, masked, in the database
  (table `config_file_backup`): the 10 newest per engine and file. The digests that guard against
  overwriting are valid for the life of the dashboard process; a restart makes the editor re-read
  the files.
- **Symlinks**: a symlinked directory in the path of a file (for example `acquis.d` itself) is now
  refused for writes, as it already was for reads. Behaviour change: an `acquis.d` symlink that
  the viewer used to follow no longer accepts saves; mount a real directory instead.
- **With the config import** (`CONFIG_IMPORT_*`, below): the import directory is CrowdSec's
  `acquis.d`. If you mount it read-only at `<CROWDSEC_CONF_DIR>/acquis.d`, the editor cannot write
  acquisition files there (they change through the import); mounted read-write, both the import and
  the editor write the same files, each with its own backup.

## Config import mount

Importing configuration files from a bundle is off unless `CONFIG_IMPORT_ENABLED=true`. When you
turn it on, give the dashboard **one dedicated writable directory**, and nothing else of the
CrowdSec configuration:

- a host directory (for example `./acquis.d`) owned by the dashboard user, uid and gid 10000 by
  default (`DOCKER_USER_UID`, `DOCKER_USER_GID`): `install -d -o 10000 -g 10000 -m 0750 acquis.d`.
  Existing files in it must be readable by that user, or they cannot be backed up and replaced;
- mounted read-write in the dashboard at `CONFIG_IMPORT_DIR` (for example
  `/var/lib/dashboard-acquis.d`);
- mounted **read-only** in the CrowdSec container at its acquisition directory
  (`/etc/crowdsec/acquis.d`), so that CrowdSec, and `crowdsec -t`, read the same files. Move the
  files you already have in `acquis.d` into it first;
- mounted **read-only** in the dashboard as well, at `<CROWDSEC_CONF_DIR>/acquis.d`
  (`/etc/crowdsec/acquis.d` in the example). The Config page and the config export read the
  acquisition files from `CROWDSEC_CONF_DIR`, that is from the CrowdSec configuration volume: once
  the files are moved out of it into the dedicated directory, they disappear from both without this
  mount.

Unless you use the [config editor](#config-editor-mount), do not mount `/etc/crowdsec` (or the
CrowdSec configuration volume) writable in the dashboard. The commented lines of `deploy/compose.example.yaml` show the setup; the threat model is in
[security.md](security.md#configuration-import). Turn the feature off again once the migration is
done.

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

## Prometheus scraping the dashboard

The dashboard exports the collector state of each engine at `GET /api/prometheus/metrics`
([operations.md](operations.md#health-and-metrics)). It accepts an API token of any scope; give it a
`read` token (Tokens page, at most 365 days: renew it every year). Put the token in a file readable by Prometheus only and reference it:

```yaml
scrape_configs:
  - job_name: crowdsec-dashboard
    scheme: https
    metrics_path: /api/prometheus/metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/dashboard.token
    static_configs:
      - targets: ['dashboard.example.com']
```

Not to be confused with the CrowdSec Prometheus endpoint of the section above, which feeds the
Metrics page.

## Trusted proxy

The client address drives the per-IP login rate limit, and the address checked against the
account's allowlist when an API token is used. `X-Forwarded-For` is believed only when the
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
