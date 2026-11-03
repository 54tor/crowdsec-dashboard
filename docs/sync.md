# Engine synchronisation

The dashboard can share the local and manual bans of every CrowdSec engine it knows with all the
others, through their LAPI only: no configuration mount, no remote `cscli`, no remote bouncer. It
reads each engine, computes a plan and writes the missing bans as **copies** on the other engines,
so their bouncers enforce them. It is off by default and starts in dry run.

## Semantics

- **Participants.** The `local` engine (from `LAPI_URL`) always takes part when the sync runs.
  Remote engines take part when their row of the engine table is `enabled` **and** `sync_enabled`
  (Engines page, "Use as a synchronisation peer"). The list is read again at every run: a change on the Engines
  page applies to the next run without a restart.
- **What is shared.** A native ban only: decision `type` `ban`, scope `Ip` or `Range`, origin
  `crowdsec` or `cscli`, not simulated, at least 5 minutes left, a target no wider than IPv4 /8 or
  IPv6 /32, and not excluded (see [Exclusions](#exclusions)). Community blocklists (CAPI), lists,
  other decision types and other origins are never shared. A ban imported from a bundle
  ([bundles.md](bundles.md)) is a native `cscli` ban of the local engine and is shared.
- **Union.** A ban native on at least one engine is present on every participating engine. To lift
  a ban everywhere, lift it on every engine where it is native. Unbanning a copy does not propagate:
  the copy comes back at the next run while its source still holds the ban.
- **No state.** Nothing is stored between runs: each run reads every engine and reconciles. Results
  live in memory (the last report, shown on the Sync page) and are lost at restart.
- **Copies.** A copy is an alert carrying one ban decision, written with scenario `sync/<source
  engine>`, origin `dashboard-sync`, and the remaining duration of the source (shortened by the time
  elapsed since the source was read). A decision is a copy of the dashboard **only if** its scenario
  starts with `sync/` **and** its alert was pushed by the dashboard's machine account on that
  engine (the `machine_id` of the engine row). A ban whose scenario starts with `sync/` but that was
  pushed by another machine is native and shared like any other. The dashboard only ever deletes
  its own copies, by decision id; a native ban is never touched.
- **No loop.** A copy is never shared again, and never exported in a bundle.
- **Duplicates and coverage.** A target already covered on an engine by an active ban (native or
  copy, exact or a wider range) is not copied there (`covered`). Targets are compared in canonical
  form (a single address is a /32 or /128); ranges are neither merged nor split. When several
  engines hold the same native ban, the copy takes the source with the longest remaining duration.
- **Removals.** A copy is removed when its source no longer holds a shareable active ban for that
  target, when it is an exact duplicate, when the target became excluded or allowlisted on the
  engine that holds the copy, or when it is a copy of the engine itself.
- **Extension.** When the source has more time left than the copy by more than `SYNC_INTERVAL`
  (floored at 1 minute), the copy is replaced (added again with the longer duration, then the old
  one deleted).
- **Orphans.** Copies whose `sync/<name>` does not name a participating engine are removed. An
  engine leaving the sync (disabled, `sync_enabled` off, deleted) therefore loses its copies **on
  the other engines** at the next run. The copies previously written **on** that engine stay there
  until they expire: the dashboard no longer contacts it.
- **Read states.** Each engine read is `complete`, `incomplete` or `failed`. Bans are read with one
  `GET /v1/alerts` per origin (`crowdsec`, `cscli`, `dashboard-sync`), `has_active_decision=true`,
  `include_capi=false`, at most `SYNC_READ_LIMIT` alerts per request and 16 MiB per response. A read
  that reaches the limit or the size bound is `incomplete`. An engine whose read is not `complete`
  receives no change and is not the source of any removal: its copies elsewhere are kept. The other
  engines continue.
- **Engines are read one after the other**, each call with its own timeout (15 s), through the
  engine's own guarded client and proxy ([security.md](security.md#engines-and-outbound-connections)).
  A run stops writing after 10 minutes (`run_deadline`).

## Dry run first

`SYNC_DRY_RUN=true` (the default) reads every engine and computes the plan, but writes nothing.
The Sync page shows a "dry run" banner, the per-engine counters are the planned ones and the last
plan lists the planned rows. A dry run still logs in to each engine as its machine
(`POST /v1/watchers/login`) and performs the same reads (bans, allowlists): only writes are skipped.

To deploy:

1. Create a machine account on each remote engine (`cscli machines add <name> --auto -f
   /dev/stdout` on that engine); the dashboard needs read, add and delete rights on decisions,
   which a machine account has.
2. Add each engine on the Engines page with its LAPI URL, that machine and password, its public
   addresses, with "Collect from this engine" and "Use as a synchronisation peer" checked; "Test connection" must succeed.
3. Set `SYNC_ENABLED=true` (and keep `SYNC_DRY_RUN=true`), recreate the dashboard container, open
   the Sync page and press "Sync now". Read the plan: added and removed targets, skipped reasons,
   blocked engines.
4. For a first synchronisation of engines that already hold many bans, the breaker will likely
   block (see [Circuit breaker](#circuit-breaker)): raise `SYNC_MAX_CHANGES` for the bootstrap.
5. Set `SYNC_DRY_RUN=false`, recreate the container, run once by hand and check the copies on each
   engine (`cscli decisions list` shows them with scenario `sync/<engine>`). Lower
   `SYNC_MAX_CHANGES` again afterwards.

The variables are described in [configuration.md](configuration.md#engine-synchronisation).

## Peers come from the engine table

Peers are the rows of the engine table, managed on the Engines page by administrators
([api.md](api.md#engines)). Their machine passwords and proxy credentials are sealed in the
database with the secrets key; they never appear in a response, a log or the Sync page, which
shows only `url_host` (host and port).

`SYNC_PEERS_FILE` no longer exists: when it is set, the dashboard refuses to start with
`SYNC_PEERS_FILE is no longer supported: add sync peers on the Engines page`. There is no import
command. Re-enter each peer of a former peers file on the Engines page:

| Peers file field | Engines page field |
|---|---|
| `name` | Name |
| `url` | LAPI URL |
| `machine_id` | Machine ID |
| `password` | Machine password |
| `allow_insecure_http` | Allow plain HTTP to this engine |
| `public_ips` | Public addresses |
| `exclude` (top level) | `SHARE_EXCLUDE_CIDRS` (environment) |

and check "Collect from this engine" and "Use as a synchronisation peer" on each of them. Then remove `SYNC_PEERS_FILE` from the environment
and the peers file mount from the compose file.

## Exclusions

A target that overlaps any of these, even partly, is never shared (it is skipped whole, never cut):

- `private`: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10` (carrier-grade NAT), `127.0.0.0/8`,
  `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `224.0.0.0/4`, `::`, `::1`,
  `::ffff:0:0/96` and `64:ff9b::/96`, `64:ff9b:1::/48` (IPv4 reached through IPv6), `fc00::/7`,
  `fe80::/10`, `ff00::/8`;
- `engine_address`: the addresses of **every** engine of the table, participating or not: the
  resolved host of its LAPI URL and its public addresses (at most 16 per engine);
- `excluded`: `SHARE_EXCLUDE_CIDRS`, for example your own office or home networks.

Engine host names are resolved at every run (5 s per lookup, 30 s for all of them). If the
addresses of any enabled engine cannot all be known (a failed lookup, more than 16 addresses, or the
engine table cannot be listed), the whole run fails closed with `engine_addresses_unknown` on every
engine: nothing is read, written or removed. One unresolvable host therefore stops the sync between
all the others (for example a stopped container that left the Docker DNS). A **disabled** engine
whose host does not resolve does not block the run. There is no "own address" check in the sync:
put the addresses you connect from in `SHARE_EXCLUDE_CIDRS`.

## Circuit breaker

Two thresholds, both on additions plus removals (plus extensions) in one run, both
`SYNC_MAX_CHANGES` (default 500):

- **per target engine** (`target_guard`): the changes planned on one engine;
- **per source engine** (`source_guard`): the changes one source would cause across all targets.
  A guarded source produces no addition and no removal of its copies in that run; its copies stay
  in place.

Crossing either threshold blocks that engine for the run (status `blocked`, `blocked_reason`), not
the others. Removals of copies that became allowlisted on their target count toward the target
breaker like any other change.

**Override.** The UI has no override any more: the earlier "retype the peer name" dialog was
removed because the page cannot show the exact pending count. A guarded peer is listed in a notice
and stays blocked; each run re-evaluates it. To clear it, fix the cause (a misbehaving engine, a
mass unban) or raise `SYNC_MAX_CHANGES` for one run. The API still accepts
`{"expected_changes": {"<engine>": <count>}}` on `POST /api/sync/run`; the run applies a guarded
engine's changes only if the recomputed count is at most 110 % of the given count, otherwise the
engine reports `sync_guard_tripped` ([api.md](api.md#sync-export-and-import)). What a guarded peer
means: something changed a lot at once on it (or on its source); treat it as suspect until you know
why.

## Allowlists

Every write of a copy goes through the single allowlist filter of the dashboard (`allowguard`),
on the allowlists of the **target** engine, read at the start of each run
(`GET /v1/allowlists?with_content=true`, with the engine's machine account):

- no copy is added on a target that overlaps an active allowlist entry, in either direction, IPv4
  and IPv6 (skip `allowlisted`, counted in "Skipped (allowlisted)");
- a copy already present that overlaps an active entry is removed; these removals count toward the
  breaker;
- native bans are never touched; the source engine's allowlists are not consulted;
- each add is checked again just before the write.

It fails closed. An engine whose allowlists cannot be read receives nothing and loses nothing in
that run (status `blocked`, `blocked_reason` `allowlist_unavailable`). Unreadable means: an error,
an answer over 4 MiB or 10 000 entries, an entry that cannot be read, and **every 404** on
`/v1/allowlists`. A CrowdSec too old to have allowlists is therefore never synced; an engine with
more than 10 000 entries stays blocked (the Sync page says so in a banner, so it is not mistaken
for an outage). An engine whose read failed for another reason (unreachable, login refused) also
carries `allowlist_unavailable`, but the page shows its error code as the cause and keeps it out of
the allowlist banner.

**Race window.** An allowlist entry added during a run is honoured at the next one: a copy can
exist on an allowlisted address for at most one run plus one interval. CrowdSec itself also deletes
the decisions that match an entry when you add it with `cscli allowlists add`.

The allowlists of each engine are visible on the Allowlists page, and those of the local engine are
managed there ([operations.md](operations.md#allowlists)); remote ones are changed with `cscli` on
their host. An allowlist is respected on the engine that holds it only: to keep an address from
being banned by the sync on every engine, allowlist it on each of them. The manual ban of the
Decisions page uses the same filter on the local engine.

## Runs, backoff and the lock

- **Scheduled runs** happen every `SYNC_INTERVAL` while `SYNC_ENABLED=true`, the first one after
  one interval (never at start). The scheduler stops cleanly when the server stops (a run in
  progress ends with `canceled`).
- **Backoff.** A peer whose read or write failed in a scheduled run is skipped by the next
  scheduled runs for a delay doubling from `SYNC_INTERVAL` up to 1 hour; it reports
  `engine_backoff` meanwhile, and its copies elsewhere are kept. A successful run resets it. A
  manual run ignores the backoff (and does not update it). Run-level failures
  (`engine_addresses_unknown`, `run_deadline`, `canceled`, `run_panicked`) do not feed it.
- **Manual run.** "Sync now" (administrators) calls `POST /api/sync/run`, which answers 202
  `{"status":"started"}` at once; the run continues on the server even if the browser or a proxy
  gives up, and the page polls `GET /api/sync` until `running` is false. With `SYNC_ENABLED=false`
  it answers 409 `sync_disabled`.
- **One operation at a time.** Sync runs, bundle exports and bundle imports share one lock: a
  second one gets 409 `operation_running` (a scheduled tick refused this way is logged
  `sync_tick_skipped` and skipped).
- **Audit.** Manual runs are always audited (`sync_run`, target
  `[err=<code> ]dry_run=<bool> engines=<n> added=<n> removed=<n> skipped=<n>`, `err=` first and
  only when the run ended with a run-level code). Scheduled runs are audited only
  when they planned or applied a change or ended with an error code (a backed-off peer alone does
  not count), so a quiet scheduler leaves no audit row; `last_run_at` on the Sync page shows it is
  alive.
- **Logs.** Only `sync_engine_read_failed` and `sync_write_failed` lines, with the engine name and
  an error code; never a password, a token or an LAPI answer.

## Sync page

Readable by every role; "Sync now" and the link to the Engines page are shown to administrators
only. It shows the dry-run and disabled banners, one row per participating engine (`url_host`, last
run, status `never_run`/`ok`/`blocked`/`failed`, added, removed, skipped, skipped because
allowlisted, blocked reason, error code) and the last plan (at most 100 rows: changes, then skips
with their reason). When the last run ended with a run-level code, a notice at the top shows it.
Codes are listed in [Codes](#codes).

## Codes

Engine status: `never_run`, `ok`, `blocked`, `failed`.

Blocked reasons (`blocked_reason`, comma-separated when several apply):

| Reason | Meaning |
|---|---|
| `target_guard` | More than `SYNC_MAX_CHANGES` changes planned on this engine: nothing applied to it this run. |
| `source_guard` | This engine as a source would cause more than `SYNC_MAX_CHANGES` changes: none of its bans are copied and its copies are kept. |
| `allowlist_unavailable` | The engine's allowlists could not be read (or the engine could not be read at all): nothing written to it. |

Error codes (`error_code` of an engine). A run-level code is also the top-level `error_code` of
`GET /api/sync` (`""` when none) and is copied onto every engine row that has no code of its own:

| Code | Meaning |
|---|---|
| `engine_unreachable`, `engine_auth_failed`, `engine_blocked_address` | Read or write failed: no answer, machine login refused, forbidden address ([operations.md](operations.md#troubleshooting)). |
| `engine_backoff` | Skipped by a scheduled run because of its failure backoff. |
| `engine_unavailable` | A participating engine is missing from the dashboard's engine registry (for example its secret cannot be decrypted, or the registry is reloading): nothing is read from or written to it, and its copies on the other engines are **kept**. |
| `sync_guard_tripped` | An override (`expected_changes`) was refused: the recomputed plan exceeds the expected count by more than 10 %. |
| `engine_addresses_unknown` | Run level: an engine address could not be resolved; nothing was done. |
| `run_deadline` | Run level: the 10 minute deadline expired; remaining writes were skipped. |
| `canceled` | Run level: the server stopped during the run. |
| `run_panicked` | Run level: an internal error stopped the run; the lock was released. |

Skip reasons (last plan and counters):

| Reason | Meaning |
|---|---|
| `covered` | The target is already covered on that engine by an active ban. |
| `allowlisted` | The target overlaps an active allowlist entry of that engine. |
| `allowlist_unavailable` | The allowlists read at the start of the run were unavailable when the write was rechecked (the recheck uses that snapshot, it does not read the allowlists again). |
| `origin`, `simulated`, `too_short`, `prefix_too_wide`, `private`, `engine_address`, `excluded` | The source ban is not shareable (see [Semantics](#semantics) and [Exclusions](#exclusions)). |
| `invalid_target` | The target could not be judged by the allowlist filter. |
| `not_a_copy` | A planned removal no longer designates a dashboard copy: nothing deleted. |
| `engine_failed` | An earlier write to this engine failed in this run: its remaining changes were skipped. |
| `write_failed` | A delete was refused by the engine; retried next run. |
| `too_short` | Also at write time: less than one second would remain once the elapsed time is removed. |
| `run_deadline` | The run deadline expired before this change. |

POST errors: 409 `sync_disabled`, 409 `operation_running`, 400 `invalid_request`, 403 `forbidden`.
