# Development

## Layout

```
backend/                 Go module "crowdsec-dashboard" (Go 1.26)
  cmd/dashboard/         HTTP server entry point
  cmd/hashpassword/      reads a password on stdin, prints its argon2id hash
  internal/api/          router, handlers, services (one file per resource)
  internal/auth/         sessions, login rate limiter, client IP resolution
  internal/config/       environment variable loading and validation
  internal/confread/     allowlisted, redacted reading of configuration files
  internal/cscli/        command allowlist, field validation, Docker exec runner
  internal/lapi/         LAPI client (machine login, alerts, decisions)
  internal/webui/        embeds the built front end (dist/) and serves the SPA
web/                     Vite + React + TypeScript front end, Tailwind, TanStack Query, i18next
  src/pages/ components/ hooks/ api/ i18n/ lib/ test/
deploy/                  Dockerfile, production compose example, env example
  dev/                   disposable development stack (see below)
docs/                    this documentation
```

The front end builds into `backend/internal/webui/dist`, which the Go binary embeds. A backend build
therefore needs a built front end to serve the UI (the folder only has to exist for compilation).

## Tests

```
cd backend && go test -count=1 -p 4 ./...
cd web && npm test           # vitest, jsdom
cd web && npm run typecheck && npm run lint
```

Keep `-p 4` on shared machines. Backend tests use fake services and the frozen CrowdSec outputs under
`deploy/dev/fixtures`; web tests stub `fetch` (`web/src/test/fetchStub.ts`) and render whole pages.

## Running locally

Front end with hot reload, proxying `/api` to a locally running backend on `:8080`:

```
cd web && npm install && npm run dev
```

Back end: export the variables of [configuration.md](configuration.md) (at least
`ADMIN_PASSWORD_HASH`) and `cd backend && go run ./cmd/dashboard`. The session cookie is `Secure`,
so use `http://localhost` or `http://127.0.0.1`.

## Dev stack

`deploy/dev` starts a throwaway CrowdSec, the socket proxy and the dashboard under the compose
project `csdash-dev`, with documentation addresses only (203.0.113.0/24, 198.51.100.0/24,
2001:db8::/32).

```
cd deploy/dev
./up.sh              # CrowdSec with Prometheus off, like a typical instance
./up.sh metrics      # Prometheus on, for the Metrics page
./seed.sh            # fake alerts and decisions (run once per fresh stack)
./check-proxy.sh     # proves the socket proxy denies everything except the three exec calls
docker compose -p csdash-dev down -v --remove-orphans
```

The first `up.sh` generates the git-ignored `.env.local` (random machine password, admin password hash)
and prints the admin password once. The dashboard is on `http://127.0.0.1:18080` only.
Writing log lines to `/var/log/dev/*.log` in the CrowdSec container feeds the Metrics page.
Only touch your own `csdash-dev` project when other stacks run on the same Docker host.

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
