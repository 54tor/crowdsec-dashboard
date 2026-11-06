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
  internal/store/        database connection, goose migrations (`migrations/*.sql`, 0.1.0 schema in `00001_initial.sql`)
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

The search subselects of the archive and audit readers (`= ANY(ARRAY(SELECT ...))` in
`internal/archive/reader_search.go` and `internal/audit/reader_search.go`) must never carry a
`LIMIT`: it would drop matches silently and make `total` wrong. Their cost is bounded by the 5 s
search deadline and the limit of 4 concurrent searches instead.

### Backup and restore check

`deploy/dev/backup-check.sh` runs the real `deploy/backup.sh` and `deploy/restore.sh` against the
disposable PostgreSQL of `test-db.sh` (it starts it if needed). It creates its own two databases,
`backup_source` and `backup_restored`, and never touches `csdash_test`: it seeds data, takes a dump,
restores it into the other database and compares row counts, then checks that every refusal (empty,
truncated, header-only or corrupt dump, wrong database name, wrong confirmation, a name over 51
characters, a leftover temporary database) and a restore that fails midway leave both databases intact,
and that the restored data opens with the key that sealed it and not with another one. It also
checks that `pg_trgm` is restored in `public`, that the 12 trigram indexes exist and that an archive
search answers the seeded count.
It prints `backup-check: OK` and exits 0 on success.

```
deploy/dev/backup-check.sh
```

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

### Smoke test of the sync and bundles

Always on an isolated project, never on `csdash-dev` (its database holds demo data):

```
cd deploy/dev
CSDASH_PROJECT=csdash-sync-smoke CSDASH_DASHBOARD_PORT=18280 ./up.sh peer
```

1. Append `SYNC_ENABLED=true`, `SYNC_DRY_RUN=true` and `SYNC_INTERVAL=1m` to
   `secrets/csdash-sync-smoke/env.local` (the dashboard's `env_file`) and run the same `up.sh`
   command again to recreate the dashboard. Enrol on `http://127.0.0.1:18280/enroll`.
2. Create the dashboard's machine on the peer: `docker exec csdash-sync-smoke-peer-a cscli machines
   add dashboard-sync --auto -f /dev/stdout`; add `peer-a` on the Engines page
   (`http://peer-a:8080`, that machine and password, a public address, plain HTTP allowed,
   "Use as a synchronisation peer"), test it.
3. Ban an address natively on each engine (`cscli decisions add --ip 203.0.113.77`), press "Sync
   now": the dry-run plan adds each ban on the other engine and nothing is written. Switch
   `SYNC_DRY_RUN=false`, recreate, run again: copies appear with scenario `sync/<engine>`; an unban
   on the source removes the copy at the next run; turning `sync_enabled` off removes the copies of
   that engine from the others.
4. Allowlists: `cscli allowlists create smoke` and `cscli allowlists add smoke 203.0.113.7` on the
   local engine, ban `203.0.113.7` on `peer-a`: the run skips it `allowlisted`.
5. Export / Import page: export every section, import a decision and an alert (preview, then apply
   with `IMPORT`), replay (nothing written), and check `import_conflict` by adding a ban between
   preview and apply. A `read_only` account sees the Sync page without "Sync now" and gets 403 on
   `POST /api/sync/run`, `/api/export` and `/api/import`.
6. The config import needs a dedicated volume mounted at `/etc/crowdsec/acquis.d` in `crowdsec` and
   at `CONFIG_IMPORT_DIR` in `dashboard`, owned by uid 10000: add it with an extra compose override
   file kept outside the repository, plus `CONFIG_IMPORT_ENABLED=true` and `CONFIG_IMPORT_DIR` in
   the env file. An invalid acquisition file must end `config_test_failed` and leave no file.
   Hub installs are not exercised: they download from the public hub.

Tear it down with its own project name (add the extra override file if you used one, so its
volume goes too), then remove its generated state:

```
docker compose -p csdash-sync-smoke --env-file secrets/csdash-sync-smoke/env.local \
  -f compose.yaml -f peer/compose.override.yaml down -v --remove-orphans
docker image rm csdash-sync-smoke-dashboard:local
rm -r secrets/csdash-sync-smoke
```

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

## CI and releases

Two GitHub Actions workflows live in `.github/workflows`; third-party actions are pinned by commit
SHA (with the version in a trailing comment) and Dependabot (`.github/dependabot.yml`) proposes
grouped weekly updates for the actions, the Go modules, the npm packages and the base images of
`deploy/`.

`ci.yml` runs on every pull request and every push to `main` (a newer run of the same ref cancels
the older one), and is reused by the release workflow. Its jobs:

| Job | What it checks |
|---|---|
| `backend` | `go vet ./...`, `go build ./cmd/dashboard ./cmd/sidecar`, `go test -p 2` against a `postgres:latest` service (`TEST_DATABASE_URL` set, `pg_trgm` comes with the image), `-race` on `./internal/api` only; the backup check tests skip without their variables |
| `web` | Node LTS, `npm ci`, `npm run lint`, `npm run typecheck`, `npm test`, `npm run build` |
| `docker` | hadolint on `deploy/Dockerfile` and `deploy/Dockerfile.sidecar` (`.hadolint.yaml` ignores the floating-tag and unpinned-package rules on purpose), then a buildx build of both images without push, each cached in the GitHub Actions cache; `linux/amd64` on pull requests, `linux/amd64` and `linux/arm64` otherwise |
| `docs-hygiene` | fails when a tracked file other than a changelog holds a local home path, or when `docs/superpowers` or `.superpowers` is tracked |

`release.yml` runs on a tag `vX.Y.Z` (or `vX.Y.Z-rc.N`). It refuses a tag that differs from `v`
plus the `version` of `web/package.json` and runs the whole `ci.yml`. It then publishes in two
phases, so a release is complete or absent:

1. `publish` builds every image of its `images` matrix from the tag commit for `linux/amd64` and
   `linux/arm64` and pushes it under the commit tag `sha-<full commit sha>` only: the dashboard to
   `ghcr.io/<owner>/<repository>` (the repository name, lowercased), the sidecar to
   `ghcr.io/<owner>/<repository>/sidecar`. Each image carries a max-mode provenance and an SBOM, and
   a signed build provenance attestation is stored with it. A failed build moves no public tag.
2. `promote` runs only when every build succeeded and copies each `sha-<commit>` manifest, without
   rebuilding (`docker buildx imagetools create`, same digest and attestations), under `X.Y.Z`,
   `X.Y` and `latest`; a pre-release tag (with a `-`) only gets `X.Y.Z-rc.N`. A failure here is
   retried by re-running the job.

Finally a GitHub Release is created with generated notes, marked as a pre-release for a pre-release
tag. Verify an image with `gh attestation verify oci://ghcr.io/<owner>/<repository>:X.Y.Z --repo
<owner>/<repository>`. Only `publish` and `promote` may write packages (`publish` alone writes
attestations), and only the release job may write the repository contents. A further image needs
an entry (`name`, `dockerfile`, `context`) in the `images` matrix of `publish` and a matching
metadata step and `promote_image` call in `promote`; it is pushed as
`ghcr.io/<owner>/<repository>/<name>`.

To cut a release:

1. in `web/`, `npm version X.Y.Z --no-git-tag-version` (updates `package.json` and
   `package-lock.json`), then commit both on `main`;
2. `git tag vX.Y.Z` on that commit and push the tag (`git push origin vX.Y.Z`);
3. follow the Release workflow in the Actions tab; the tag must point at the commit that holds the
   version, otherwise the first job fails and nothing is published.

The same checks run locally with the commands of [Tests](#tests), plus `hadolint deploy/Dockerfile deploy/Dockerfile.sidecar`
(it reads `.hadolint.yaml`), `docker build -f deploy/Dockerfile .` and
`docker build -f deploy/Dockerfile.sidecar .` from the repository root.
`actionlint` checks the workflow files.

Repository settings and first publication:

- Settings, Actions, General: allow GitHub Actions and the actions used by the workflows; under
  Workflow permissions the default `read` is enough, the workflows ask for more per job.
- Branch protection (or a ruleset) on `main` requiring the `backend`, `web`, `docker` and
  `docs-hygiene` checks, and, if wanted, a tag ruleset restricting who can push `v*` tags.
- After the first release, the package is private: in the package settings on GitHub
  (Packages, the image, Package settings), change its visibility to public once and check that it
  is linked to the repository. Later releases keep that visibility.

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

## Interface

- **Theme tokens** live in `web/src/index.css`: light values on `:root`, dark values on `.dark`
  (surfaces, text, amber accent, state colours `critical`, `warning`, `info`, `nominal` and their
  tints). Components use the tokens through Tailwind classes.
- **Theme choice** (light, dark or system) is stored in `localStorage` under `theme-preference`.
  `web/public/theme-init.js` applies it before React mounts, so the page never flashes the wrong
  theme; it is an external file because the CSP (`default-src 'self'`) forbids inline scripts.
- **Table density** (comfortable: 40 px minimum rows and roomier cells, compact: 32 px and tight
  cells) is stored under `table-density` and shared by every list. The toggle sits in the page
  header, only when the list has rows, and is hidden on phones above lists shown as cards, which
  ignore it. Columns with short values set `noWrap` on their `DataTableColumn`: they stay on one
  line in tables (the scroll region scrolls instead) and still wrap inside cards.
- **Fonts** are IBM Plex Sans, Sans Condensed and Mono from the `@fontsource/*` packages, latin
  subsets only, bundled with the front end: no CDN, no external request.
- **Icons** are Material Symbols (outlined, weight 400) from `@material-symbols/svg-400`, inlined as
  SVG. To add one, add its name to `IconName` and its `?raw` import to `ICON_SOURCES` in
  `web/src/components/iconSources.ts`, then use `<Icon name="…" />`.
- **Contrast** of text, field borders and focus ring in both themes is pinned by
  `web/src/theme.contrast.test.ts` (WCAG AA: 4.5:1 for text, 3:1 for borders and focus ring).
- **Small-list filter**: engines, bouncers, machines, API tokens, accounts, allowlist entries and
  the hub are filtered in the browser, without any request. `useClientFilter(rows,
  searchableTextsOf)` keeps the filter text in local component state (never in the URL) and returns
  the rows whose displayed text contains it: `searchableTextsOf` returns the same text the table
  shows (translated labels and formatted dates included), never raw objects. `normaliseSearchText`
  in `web/src/lib/searchText.ts` applies `NFD`, removes diacritics and lowercases, so `equipe`
  finds `Équipe`; the term is a literal substring, not a pattern. `ClientFilterField` is the
  labelled `type="search"` field with a clear button; it is hidden on an empty list and announces
  the `clientFilter.count` text (« 2 sur 5 ») in a polite live region 300 ms after the last change.
  `ClientFilterResults` shows `clientFilter.noMatch` instead of the list when the filter hides
  every row, so the list keeps its own empty message for a truly empty list.
- **Command palette** (`web/src/components/CommandPalette.tsx`, built on `cmdk` inside the shared
  Radix `Dialog`): Ctrl+K or Cmd+K opens it from anywhere, text fields included, and the shortcut's
  default action is prevented; it does nothing while another dialog or alert dialog is open. The
  « Rechercher partout » button in the header opens it too, on phones as well (44 px target).
  Pages come from `visibleNavItems(accountRole)` and engines from `GET /api/engines/names`, both
  filtered in the browser on every keystroke with `matchesSearchText`. Alerts and decisions come
  from the existing list routes with `q` and `per_page=5`, 250 ms after the last keystroke
  (`PALETTE_DEBOUNCE_MILLISECONDS`) and only for a trimmed term of 3 to 64 characters; a shorter
  term shows a hint and sends nothing. Each category shows at most 5 results
  (`PALETTE_RESULTS_PER_CATEGORY`). Choosing a page opens it, an engine opens
  `/alerts?engine=<name>`, an alert opens `/alerts?q=<typed term>` and a decision
  `/decisions?q=<typed term>` (paths built by `web/src/lib/paletteTargets.ts`); the list pages
  re-apply `q` and `engine` when the URL changes. Results are rendered as text in `<bdi>`. They
  are kept only in the in-memory TanStack Query cache (default 5 minutes after the last use),
  never persisted and never logged, nor is the search term. Results of a previous term are hidden
  while the next one loads, a chosen alert or decision opens with the term its results came from,
  a request abandoned for a newer term is cancelled, and a failed search shows
  `palette.searchError`. Ctrl+Shift+K and Ctrl+Alt+K (AltGr) are left to the browser. Closing
  returns the focus to the element focused before opening, or to `#main-content` when that
  element left with the previous page.
- **Mobile**: below 768 px the rail becomes a bottom tab bar and lists rendered with
  `cardsOnMobile` turn into one card per row. Tests drive the viewport with `setViewportWidth`
  from the `matchMedia` stub in `web/src/test/matchMedia.ts`.
