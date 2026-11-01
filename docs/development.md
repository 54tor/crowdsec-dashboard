# Development

## Layout

```
backend/                 Go module "crowdsec-dashboard" (Go 1.26)
  cmd/dashboard/         HTTP server entry point
  internal/api/          router, handlers, services (one file per resource)
  internal/accounts/     account repository, first-account enrolment, second-factor lockout and setup window
  internal/accessrule/   per-account IP/country allowlist: rules, evaluation, lock-out guard
  internal/audit/        authentication audit events (`audit_event`)
  internal/auth/         password authentication, session middleware, rate limiters, client IP resolution
  internal/login/        three-step login (password, second factor, allowlist), in-memory pending logins
  internal/secondfactor/ TOTP, recovery codes, WebAuthn, in-memory enrolment accumulator, persistence
  internal/secrets/      AES-256-GCM keyring read from the secrets key file
  internal/geo/          country lookup: rereading GeoLite2 reader, provider chain
  internal/config/       environment variable loading and validation
  internal/confread/     allowlisted, redacted reading of configuration files
  internal/cscli/        command allowlist, field validation, Docker exec runner
  internal/sessions/     session store in PostgreSQL (hashed tokens, pruning)
  internal/store/        database connection, goose migrations (`migrations/*.sql`)
  internal/lapi/         LAPI client (machine login, alerts, decisions)
  internal/webui/        embeds the built front end (dist/) and serves the SPA
web/                     Vite + React + TypeScript front end, Tailwind, TanStack Query, i18next
  src/pages/ components/ hooks/ api/ i18n/ lib/ test/
deploy/                  Dockerfile (Alpine + s6-overlay), production compose example, env examples
  s6/                    init scripts, services and shell tests of the image (rootfs/, overlays/, test/)
  dev/                   disposable development stack (see below)
docs/                    this documentation
```

The front end builds into `backend/internal/webui/dist`, which the Go binary embeds. A backend build
therefore needs a built front end to serve the UI (the folder only has to exist for compilation).

## Tests

```
deploy/dev/test-db.sh up        # throwaway PostgreSQL, prints TEST_DATABASE_URL=...
cd backend && TEST_DATABASE_URL=... go vet ./... && TEST_DATABASE_URL=... go test -count=1 -p 4 ./...
deploy/dev/test-db.sh down      # stops it and removes its volume
cd web && npm test           # vitest, jsdom
cd web && npm run typecheck && npm run lint
for suite in deploy/s6/test/*.test.sh; do bash "$suite"; done   # image init scripts, no Docker needed
```

The shell suites exercise the init scripts of the image (`05-wait-network`, `25-secrets-key`,
`30-geoipupdate` and the cron service) with fakes, and `scrub.test.sh` checks the identity scrub of `deploy/`
(`scrub.sh` itself needs `SCRUB_PATTERNS`, patterns kept outside the repository, and reads tracked
files: `git add` new files first). The WebAuthn flows are tested with a virtual authenticator, the
GeoLite2 reader with databases written by a test-only library, so no hardware and no MaxMind
account are needed.

Tests that need PostgreSQL (store, sessions, accounts, API) read `TEST_DATABASE_URL`; each test gets
its own schema. Without that variable they are skipped, so a plain `go test` still passes but does
not cover the database code. `test-db.sh` uses its own compose project `csdash-test-db`.

Keep `-p 4` on shared machines. Backend tests use fake services and the frozen CrowdSec outputs under
`deploy/dev/fixtures`; web tests stub `fetch` (`web/src/test/fetchStub.ts`) and render whole pages.

## Running locally

Front end with hot reload, proxying `/api` to a locally running backend on `:8080`:

```
cd web && npm install && npm run dev
```

Back end: export the variables of [configuration.md](configuration.md) (at least `DATABASE_URL`,
for example the URL printed by `test-db.sh up` or a PostgreSQL of your own) and
`cd backend && go run ./cmd/dashboard`. The first start logs the enrolment token; open `/enroll`. The session cookie is `Secure`,
so use `http://localhost` or `http://127.0.0.1`.

## Dev stack

`deploy/dev` starts a throwaway CrowdSec, the socket proxy and the dashboard under the compose
project `csdash-dev`, with documentation addresses only (203.0.113.0/24, 198.51.100.0/24,
2001:db8::/32).

```
cd deploy/dev
./up.sh              # CrowdSec with Prometheus off, like a typical instance
./up.sh metrics      # Prometheus on, for the Metrics page
./up.sh peer         # also start the demo engine peer-a
./seed.sh            # fake alerts and decisions (run once per fresh stack)
SEED_ENGINE=peer-a ./seed.sh   # the same on peer-a (about 10 alerts per run)
./check-proxy.sh     # proves the socket proxy denies everything except the three exec calls
docker compose -p csdash-dev --env-file .env.local \
  -f compose.yaml -f peer/compose.override.yaml down -v --remove-orphans
```

The teardown with `down -v` deletes the volumes (database, secrets): it is for a throwaway project only, and
never for a stack whose data you want to keep. The `peer/compose.override.yaml` file is part of it so the
`peer-a` volumes are removed too.

The first `up.sh` generates the git-ignored `.env.local` (random machine and database passwords) and
`secrets/dashboard-secrets.key` (the secrets key, `openssl rand -base64 32`; do not delete it while
the stack holds accounts). It
prints the enrolment token of the first account (read from the dashboard log) and the address to
enrol at, `http://127.0.0.1:18080/enroll`; once an account exists it says so instead. The dashboard is on `http://127.0.0.1:18080` only.
Enrolment asks for a second factor: use any TOTP app, or a virtual authenticator in the browser
developer tools. The dev stack runs the same hardened image as production and has no MaxMind
account, so country rules are refused there; to try WebAuthn, add `WEBAUTHN_RP_ID: localhost` and
`WEBAUTHN_RP_ORIGINS: http://localhost:18080` to the `dashboard` service and browse
`http://localhost:18080` (an IP cannot be a relying party ID).
Writing log lines to `/var/log/dev/*.log` in the CrowdSec container feeds the Metrics page.
Only touch your own `csdash-dev` project when other stacks run on the same Docker host.

`CSDASH_PROJECT` (default `csdash-dev`) and `CSDASH_DASHBOARD_PORT` (default `18080`) start a
second, isolated copy beside the default one, with its own containers, volumes, networks, image tag
and socket-proxy rules; its generated env file and secrets key go to `secrets/<project>/`
(git-ignored), so the default `.env.local` and key are never touched. `seed.sh` honours
`CSDASH_PROJECT` too. Tear such a copy down with its own project name:

```
CSDASH_PROJECT=csdash-e2e CSDASH_DASHBOARD_PORT=18180 ./up.sh peer
CSDASH_PROJECT=csdash-e2e SEED_ENGINE=peer-a ./seed.sh
docker compose -p csdash-e2e --env-file secrets/csdash-e2e/env.local \
  -f compose.yaml -f peer/compose.override.yaml down -v --remove-orphans
```

### Demo engine peer-a

`./up.sh peer` starts `peer-a`, a second CrowdSec on the internal network only (no published
port), with `db_config.flush.max_items: 20` so its own purge is visible quickly, and a profile that
bans on any alert. To archive it:

1. create a machine on it: `docker exec csdash-dev-peer-a cscli machines add <name> --password
   <password> -f /dev/null`;
2. on the Engines page, add `peer-a` with URL `http://peer-a:8080`, that machine and password, and
   "Allow plain HTTP to this engine" checked; "Test connection" must succeed;
3. seed it (`SEED_ENGINE=peer-a ./seed.sh`, several runs for more than 20 alerts).

CrowdSec keeps an alert with an active decision whatever `max_items` says; to see the flush, expire
them on the demo engine (`docker exec csdash-dev-peer-a cscli decisions delete --all`), then wait a
minute.

### Allowlist probe

`deploy/dev/allowlist-probe.sh` starts its own throwaway engine (project `csdash-allowlist-probe`,
no published port), records how the LAPI serves allowlists (shape of
`GET /v1/allowlists?with_content=true`, permanent entries as `0001-01-01T00:00:00.000Z`, expired
entries never returned, empty-body 404 for unknown routes, 500 for an unknown allowlist name) and
what it stores for an alert on an allowlisted address, then tears itself down. The
`allowlists.json` and `allowlist-not-found.json` fixtures were recorded with it; run it again when
upgrading CrowdSec.

### End-to-end check of the archive

On an isolated copy (above), with `peer-a`:

1. enrol, add `peer-a` on the Engines page and test it;
2. push more than 20 alerts on `peer-a`, expire its decisions, wait for its flush: `docker exec
   <project>-peer-a cscli alerts list -o json --limit 0 | jq length` drops to 21 while the Alerts
   page filtered on `peer-a` still lists every alert, badged "Archived", without Delete;
3. seed the local engine, wait a collection, delete a live local alert: it disappears from the LAPI
   and from the archive (`GET /api/alerts/archive/<archive_id>` answers 404);
4. `docker stop <project>-crowdsec`: the Alerts page stays served from the archive with the "Local API
   unreachable, showing the archive." banner (`live_status:"unavailable"`);
5. downgrade the account in that copy's database only (`docker exec <project>-postgres psql -U
   dashboard -d dashboard -c "UPDATE account SET account_role='read_only' WHERE
   account_name='<account>'"`): the Engines link and page are gone, `/api/engines` answers 403
   `forbidden`, and the engine filter of the Alerts page still lists every engine.

The "10 000+" total needs more than 10 000 archived alerts and is covered by the API tests, not
by this check.

## Refreshing the fixtures

`deploy/dev/fixtures` holds real outputs of the CrowdSec version the parsers were written against.
When upgrading CrowdSec, regenerate them from a seeded dev stack and rerun the backend tests:

| File | Source |
|---|---|
| `version.txt` | `docker exec csdash-dev-crowdsec cscli version` |
| `hub-list.json` | `cscli hub list -o json` |
| `collections-list.json` | `cscli collections list -o json` |
| `bouncers-list.json`, `machines-list.json`, `alerts-list.json` | `cscli bouncers list -o json`, `machines list -o json`, `alerts list -o json` |
| `metrics.json` | `cscli metrics -o json` (stack started with `./up.sh metrics`) |
| `bouncers-add.txt`, `bouncers-add-raw.txt` | `cscli bouncers add <name>`, with `-o raw` |
| `machines-add.txt` | `cscli machines add <name> --auto -f /dev/stdout` (stdout only) |
| `lapi-alerts.json` | `GET /v1/alerts` on the LAPI with a machine token |

Keep only documentation addresses, no real host names and no real credentials in them. A parser test
that starts failing after a refresh means CrowdSec changed an output shape.

## Conventions

- No comments in production code; the code states what it does through names. Non-production code
  (tests, scripts) explains non-obvious behaviour.
- Explicit, descriptive names everywhere, loop variables and test variables included
  (`expectedValue`, `observedValue`, not `a`, `b`).
- Small files and functions with one responsibility; one handler file per resource.
- Prefer maintained libraries over home-grown code (argon2id, rate limiting, Docker client,
  Radix/shadcn components); custom code is integration and business logic.
- Container images use floating tags (`latest`, or the major tag when the publisher has no `latest`,
  e.g. `wollomatic/socket-proxy:1`); no digest or version pinning in compose files.
- New API behaviour comes with a test first, and a change of behaviour updates these docs in the
  same change.
- No names, local paths or e-mail addresses of people in code, docs, fixtures or file names.
