# Security

## Model in one paragraph

Named accounts, stored in PostgreSQL, protect a web UI that can ban addresses, create credentials and run
`cscli` in the CrowdSec container. The dashboard is a single trusted process: its Go code decides
which commands may run. Treat the dashboard as having the same power as whoever can reach the Docker
socket (see [Limits](#honest-limits)).

## Accounts and enrolment

- An account has a name (`^[a-z0-9][a-z0-9._-]{0,63}$`) and a password of 12 to 128 characters,
  stored as an argon2id hash (library default parameters) in PostgreSQL. The plain password is never
  kept.
- The first account is created by enrolment. While no account exists, the dashboard generates a
  random token at start, writes it once to its log and keeps it in memory only; it is never in an
  API response or in the database. `POST /api/auth/enroll` needs this token, the new account name and
  password. **Whoever can read the logs while no account exists can create the first (admin) account**:
  protect the logs and enrol promptly after the first start.
- The enrolment window reopens whenever the database holds no account (for instance an empty cluster after a PostgreSQL major upgrade): see docs/operations.md.
- A restart while no account exists generates a new token and invalidates the previous one. Once the
  first account exists, enrolment is closed for good: the route answers 404 and the old token is
  useless. Two simultaneous enrolments with the right token create one account (a PostgreSQL advisory
  lock); the other gets 404, as enrolment is then closed.
- A wrong token answers 403 `invalid_enrollment_token` (a missing or empty one, 400 `invalid_request`);
  it is compared in constant time and enrolment is limited per client like login.
- The first account needs a second factor. `POST /api/auth/enroll` with the token, a name and a
  password creates nothing in the database: the validated name and password hash are held in memory
  under the token, and the account is written only at `POST /api/auth/enroll/complete`, once a TOTP
  or a passkey is confirmed and the recovery codes have been shown. This state has no expiry of its
  own: it disappears at completion or when the process restarts, and a new `enroll` call with the
  token replaces it. Until completion nothing is stored, so an abandoned enrolment leaves no
  account (and a restart gives a new token).

## Roles and access

Accounts have a role, `admin` or `read_only`. The first account is `admin`; an administrator creates
the others on the Accounts page. Each route of the API declares one access level, and a test walks
the route table so that no write route can be added without one:

| Access | Who | Routes |
|---|---|---|
| Public | nobody authenticated | `healthz`, `auth/status`, `auth/enroll...`, `auth/login...`, `auth/logout` |
| Authenticated | any session, any token | `auth/me`, the list and detail reads (alerts, decisions, `alerts/archive/{id}`, hub, `metrics`, engine allowlists), `health`, `prometheus/metrics`, `engines/names`, `GET /api/sync` |
| Admin | `admin` session, or a `write` token of an `admin` account | `GET /api/engines`, `POST /api/engines/{name}/test`, configuration files, ban and unban, alert deletion (live and archive), bouncers, machines, hub changes, engine allowlist writes, reload, `POST /api/sync/run`, `POST /api/export` (a secrets export needs a session) |
| Session only | a browser session, any role | `auth/logout-all`, the account's own allowlist rules, API token management |
| Admin and session only | an `admin` session | account administration, engine create, change and delete, `POST /api/import` |

A `read_only` account, or a `read` token, gets 403 `forbidden` on every admin route; a token on a
session-only route gets 403 `session_required`, whatever its scope. The interface hides the actions
the role cannot perform, but the server is the control. Configuration files are readable by
administrators only, since redaction is best effort ([Configuration files](#configuration-files)).

The command palette (Ctrl+K) offers only the pages of the current role (the same
`visibleNavItems` as the navigation, so an admin-only page is absent for `read_only`), and reaches
records only through the existing list routes (`GET /api/alerts` and `GET /api/decisions` with `q`
and `per_page=5`) and `GET /api/engines/names`: it adds no route. An engine result opens the alert
list filtered on that engine, never the admin Engines page. Result text is rendered as text, and
navigation targets are built from encoded URL parameters, never from a link in the data.

**A `write` token of an administrator can mint LAPI credentials.** Bouncer and machine creation,
hub changes, reload, configuration files and engine reads are admin routes, not session-only: a
stolen `write` token can create a bouncer key or a machine password. The routes that change who can
sign in or where secrets go (accounts, tokens, access allowlist rules, engine writes) need a
session. Engine allowlist writes are admin routes too: a stolen `write` token of an administrator
can add an allowlist entry on the local engine, which disarms its protection for that range
([Allowlists of the engines](#allowlists-of-the-engines)). Keep `write` tokens rare and short, and
prefer `read` tokens.

### API tokens

- Created on the Tokens page (or `POST /api/tokens`) by a session, per account. Fields: a name (1 to 64
  printable characters, unique among the account's tokens that are not revoked), a scope and a
  lifetime of 1 to 365 days. No token lives longer than a year.
- The token is `csd_` followed by 43 characters, from 32 random bytes. The server keeps only its SHA-256.
  It is shown **once**, in the creation response (`Cache-Control: no-store`) and the dialog; if lost, create another.
- Sent as `Authorization: Bearer <token>` and nothing else (no query parameter, no cookie). The scheme
  name is case-insensitive. A Bearer header that holds a bad token answers 401 `invalid_token` and
  never falls back to a session cookie.
- **Scopes.** `read` gives the effective role `read_only`; `write` gives the role the account has now
  (an account demoted to `read_only` loses the write power of its existing tokens at once). A
  `read_only` account cannot create a `write` token (403 `scope_not_allowed`).
- **The account's protections apply to its tokens.** On every call the token's account must not be
  locked, and the client address must pass the account's [allowlist](#access-allowlist) (country
  rules included), else 403 `token_denied`. The decision is cached for a minute per account and
  address, so a new or removed rule can take up to a minute to reach tokens. A lockout and a token
  revocation are not cached: they apply to the next call. The address is resolved like the
  login limiter: **set `TRUSTED_PROXY_CIDRS`**, otherwise behind a proxy every token call appears to
  come from the proxy.
- **Revocation.** Revoke one token on the Tokens page (audited `api_token_revoked`). Every token of an
  account is revoked when an administrator resets its second factor or revokes its sessions, and when
  the account uses "log out everywhere"; deleting the account deletes them. A revoked or expired
  token never authenticates; its row is removed after `API_TOKEN_RETENTION_DAYS`.
- Creation and revocation are audited (`api_token_created`, `api_token_revoked`, target
  `api_token:<id>:<name>`). Calls made with a token are not logged one by one, but the audited write actions
  a `write` token can reach (`alert_deleted`, `decision_removed`, `engine_tested`, `allowlist_created`,
  `allowlist_deleted`, `allowlist_entry_added`, `allowlist_entry_removed`, `sync_run`, and `bundle_exported`
  for an export without secrets) record the account.
  The other engine changes and account administration need an `admin` browser session and are
  never made with a token.

### Account administration

- Only an `admin` session can create, change, reset, unlock, revoke or delete accounts, and the last
  administrator cannot be demoted or deleted (409 `last_admin`, checked under an advisory lock so two
  simultaneous requests cannot remove both).
- A created account gets a password chosen by the administrator and a 72 hours second-factor
  setup window ([Second-factor setup window](#second-factor-setup-window)). **The
  administrator knows the initial password, so they could enrol a second factor of their own before
  the user does and then sign in as that user.** Give the password over a channel you trust, let the
  user enrol at once, and treat an unused window as a risk. There is no password reset: a new password
  means a new account.
- Resetting a second factor revokes the account's sessions and tokens, and opens the window again.

## Login

Login has three steps. Each one must succeed before the next is reached, and a session cookie is
issued only at the end.

1. **Password** (`POST /api/auth/login`). An unknown account and a wrong password cost the same time
   and answer the same 401 `invalid_credentials`, so accounts cannot be enumerated. On success the
   dashboard creates a *pending login* and answers `second_factor_required` with the enrolled
   methods (`totp`, `webauthn` when enabled; a recovery code is always accepted as well), or
   `second_factor_setup_required` for an account that has no factor yet (see
   [Second-factor setup window](#second-factor-setup-window)).
2. **Second factor**: a TOTP code, a recovery code or a WebAuthn assertion.
3. **Access allowlist**: the client address and country are checked against the account's rules
   ([Access allowlist](#access-allowlist)). The session is created only if they pass.

If PostgreSQL is unreachable, login and authenticated requests answer 503 `database_unavailable`,
never 401 (which would sign the user out of the interface).

### Pending login

- It is a 256-bit random identifier kept only in memory, in the cookie `pending_login`:
  `HttpOnly`, `Secure`, `SameSite=Strict`, path `/api/auth`, lifetime 5 minutes. It never reaches the
  database and does not survive a restart (the user signs in again).
- It is bound to the client address that presented the password: used from another address it is
  refused as expired. It is usable once: success, lockout and the fifth wrong factor all consume it.
  At most 5 factor attempts per pending login; at most 10 000 pending logins at a time (beyond that,
  503 `too_many_pending_logins`).
- Two requests for the same pending login are processed one after the other, never in parallel.

### Rate limits

Applied to every attempt, successful ones included:

- `POST /api/auth/login` and `POST /api/auth/enroll`, the two entries that check a secret with no
  earlier state:
  - per client, 5 attempts per minute (burst of 5, one more every 12 s); the client key is the IPv4
    address or the IPv6 `/64` prefix, so rotating addresses inside a /64 does not help;
  - globally, 30 attempts per minute, so a distributed guess cannot run faster whatever the sources;
  - at most 10 000 tracked clients: beyond that new clients are refused until old entries expire;
  - a single password verification at a time (each one allocates 64 MiB for argon2id, the container is capped at 256 MiB); a concurrent attempt answers 429;
  - a failed login (`POST /api/auth/login`) always takes at least 500 ms; a failed enrolment
    (`POST /api/auth/enroll`) answers at once, bounded by the limits above and the single
    verification slot.
- Every later step (`/api/auth/login/*` and `/api/auth/enroll/*`): 30 requests per minute per client
  (same client key), with **no global bucket**. These steps are already bounded by the pending
  login (5 attempts, one address, 5 minutes), by the account lockout and by the 256-bit enrolment
  token. Without a global bucket, a flood of password attempts from many addresses cannot stop the
  operator from completing the second factor, and a typo or a complete TOTP plus passkey enrolment
  (7 calls) is never rate limited. The setup stage of an old account has no attempt cap of its own
  beyond this per-client limit and the 5 minute pending lifetime.

Blocked requests answer 429 `too_many_attempts` with `Retry-After: 60`. The global limit on
`login` and `enroll` means an attacker can briefly lock the legitimate admin out of the password
step; that is accepted over letting guesses through. Login bodies are capped at 1 KiB (64 KiB for a
WebAuthn response).

### Lockout

- Only second-factor failures count. A wrong password never changes the counter, so an attacker who
  only knows the account name cannot lock the owner out: this is deliberate, to avoid a
  denial-of-service on the account. Only someone who already knows the password can trigger a
  lockout.
- Each factor check first *reserves* an attempt in the database (an atomic `UPDATE` on the account
  row), and only then verifies the code. Concurrent guesses therefore cannot exceed the limit.
  The fifth failure within a series locks the account for 15 minutes. A success resets the counter.
  When a lock has expired, the next attempt starts a new series at one.
- A locked account answers 423 `account_locked` with `Retry-After` (seconds left), at the password
  step (after a correct password) and at a factor step started before the lock, and the pending
  login is dropped. The failure that triggers the lock answers 401 like the others and consumes
  its pending login. Recovery codes count as second-factor attempts like any other method.
- A factor that was accepted stays used even when the allowlist then refuses the login: a TOTP step
  or recovery code cannot be replayed afterwards.
- A locked account also refuses its API tokens (`token_denied`). An administrator unlocks it on the
  Accounts page; by SQL: [operations.md](operations.md#unlocking-an-account).

## Second factor

- Every login requires a second factor; there is no way to skip it. Two kinds, plus recovery codes:
  - **TOTP**: SHA-1, 6 digits, 30 seconds (the combination every authenticator app supports). A
    code from the previous, current or next 30 s step is accepted, and a step already used is
    refused (`credential_totp_last_step`), so a code cannot be replayed within its window. One TOTP
    per account.
  - **WebAuthn** (optional, see `WEBAUTHN_RP_ID` in [configuration.md](configuration.md#webauthn)):
    passkeys and security keys, attestation `none`. User verification is `preferred`, not required:
    a security key that only proves presence (touch, no PIN or biometric) is accepted, so it is
    then a possession factor only. Challenges expire (the library's timeouts are enforced) and are
    single use: the server drops the pending challenge before it verifies the response, so an
    assertion cannot be replayed. A passkey whose signature counter stays at 0 (many synced
    passkeys) gets no clone detection; for others, a counter that does not increase is refused
    and audited as `webauthn_clone_suspected`. No `excludeCredentials` list is sent when enrolling:
    setup is only offered to an account that has no factor, and a reset deletes the factors first.
  - **Recovery codes**: 10 codes of 16 characters (80 bits), shown once at enrolment, stored only as
    SHA-256 hashes, each usable once. They are typed like a TOTP code (case, dashes and the
    lookalikes `O`, `I`, `L` are normalised). Using one is audited.
- Enrolment cannot finish without a confirmed factor and the generated recovery codes.
- Browsers without the JSON WebAuthn API cannot enrol or use a passkey; they use TOTP.
- A user cannot change their own factors; an administrator resets them from the Accounts page
  ([Account administration](#account-administration)), and the SQL procedures of
  [operations.md](operations.md#account-recovery-by-sql) cover the case where no administrator can sign in.

### Encryption of secrets

A TOTP secret, and the machine password and proxy credentials of an engine, must be readable to be
used, so they are encrypted rather than hashed: AES-256-GCM with a random nonce, authenticated data
that ties the ciphertext to its owner (the account id for TOTP; the engine id and its destination for
engine secrets, [below](#engines-and-outbound-connections)), and a key held outside the database
(`SECRETS_KEY_FILE`). Each row stores the `key_id` (first 16 hex characters of the key's SHA-256) of
the key that sealed it. New secrets use the current key; the retired keys listed in
`SECRETS_RETIRED_KEY_FILES` stay readable during a rotation, and the dashboard refuses to start when a
row uses a key it does not hold. `dashboard rotate-secrets` rewrites the rows with the current key
([operations.md](operations.md#rotating-the-secrets-key)). A database dump alone does not reveal the
secrets; a dump plus the key does. **Losing the key makes the secrets unreadable**: see
[operations.md](operations.md#secrets-key).

Engine secrets written before the destination binding used the engine id alone as authenticated
data. They are still read, and resealed in the new form at start and by `rotate-secrets`, so restored
older backups keep working. That fallback is the weak point: someone who can write to the database and
replays an old sealed value under the same key can use the id-only form. There is no format flag to
check, since a database writer could set it too. The window closes for good when you rotate to a new
key and remove the old one, because the old blobs then no longer open at all. Passkey public data
and recovery-code hashes are not secret and are not encrypted. The key is read from a tmpfs file
that only `docker-user` can read, and is never logged.

### Second-factor setup window

An account created by an administrator, or whose factor an administrator reset, has no factor and
gets a *setup window* of 72 hours (`account_second_factor_setup_until`). At the next login, after
the correct password, the dashboard asks to enrol a factor instead of asking for one: **whoever
presents the password first enrols their own factor**. Hand over the password and sign in at once. On completion
the window closes, the recovery codes are shown, and every session of the account is revoked. An
account with no factor and a closed window is refused with 403
`second_factor_setup_not_allowed`. An administrator reopens the window by resetting the factor, or an
operator by SQL ([operations.md](operations.md#reopening-the-setup-window)). Refusals are audited
(`second_factor_setup_refused`).

## Access allowlist

Each account can restrict where it signs in from, with IP/CIDR rules and country rules.

- **No rule means unrestricted. Any rule means deny by default**: the login is accepted only if the
  client address matches an IP rule, or its country matches a country rule. Deleting the last rule
  turns the allowlist off (the UI says so).
- Order of checks: password, then second factor, then allowlist. A refused login answers 403
  `access_denied` (audited as `login_denied_access_rule`) after the factor was consumed.
- Rules are normalised before they are stored: addresses to `/32` or `/128`, IPv4-mapped IPv6 to
  IPv4, host bits cleared. A prefix of length zero (`0.0.0.0/0`, `::/0`) is refused, and so is any
  new IP rule broader than IPv4 /8 or IPv6 /16 (400 `prefix_too_broad`), because a wide rule makes
  the allowlist meaningless. Rules stored before this floor keep working and can still be deleted.
- **Lock-out guard**: adding or deleting a rule is refused with 409 `would_lock_out_current_client`
  when the resulting rule set would not admit the address you are connected from, evaluated inside a
  transaction with the account row locked. The address is the one resolved like the login rate
  limiter (`TRUSTED_PROXY_CIDRS`): behind a proxy without it, the proxy's own address is what is
  protected. The guard covers the current session's address only: a later sign-in from another
  address can be refused.
- **Rules apply at sign-in only.** They are evaluated once, when the login completes; a session that
  already exists is never checked against them. Adding or tightening a rule therefore does not cut
  off any existing session (API tokens, by contrast, are checked on every call), including a stolen one: it keeps working from any address until it
  expires (`SESSION_TTL`, 12 h by default) or is revoked. After a suspected compromise, add the rule
  and then revoke the sessions and tokens ("Revoke sessions" on the Accounts page,
  `POST /api/auth/logout-all` with a session of the account, or by SQL:
  [Revoking every session](operations.md#revoking-every-session)).
- Country rules need a GeoLite2 Country database (`GEOIP_DATABASE_FILE`). With no database, an
  unreadable one, or an address the database does not know, a country rule never matches: the login
  is refused unless an IP rule matches (fail closed). Adding a country rule while no database is
  available is refused (409 `geolocation_unavailable`). The database file is re-read when it
  changes; if the replacement cannot be read the previous one stays in use (logged). The log warns
  at start when the database is older than 45 days.
- The country of an address comes from MaxMind's data, which is approximate: VPNs and mobile
  carriers appear in the country of the exit point.
- A fallback to an external geolocation service exists in the code as an extension point, but no
  provider ships and none is configured. Enabling one would send the addresses of your operators
  (every address presented at login, and the address shown in the access rules page) to a third
  party. Do not enable one without accepting that.
- GeoLite2 attribution and licence: this product includes GeoLite2 data created by MaxMind,
  available from https://www.maxmind.com. Use of the data is governed by MaxMind's GeoLite2 licence
  terms. The MaxMind licence key is a secret file, never a variable or a command-line argument, and
  is readable by `docker-user` (see [Container image](#container-image)).

## Audit log

Authentication events, account and token management, and the engine, alert-deletion and decision-removal actions are written to the `audit_event` table with the account (empty for an
unknown account), an action, a short target, the client address and the time. Targets are stripped
of control characters and cut at 64 characters. Recorded actions:

| Action | When | Target |
|---|---|---|
| `login_success` | a login completed (session issued) | account name |
| `login_failure` | wrong password or unknown account | the account name as typed |
| `second_factor_failure` | a wrong code or assertion | `totp`, `recovery_code`, `webauthn`, or `webauthn_clone_suspected` |
| `account_locked` | the failure that triggered a lockout | account name |
| `login_denied_access_rule` | second factor accepted, allowlist refused | account name |
| `recovery_code_used` | a recovery code was accepted | account name |
| `login_locked_password_ok` | the password was right but the account is locked | account name |
| `second_factor_setup_refused` | the password was right, the account has no factor and its setup window is closed | account name |
| `second_factor_attempt_refused` | a factor attempt on an account that is already locked | account name |
| `enrollment_completed` | the first account was created | account name |
| `second_factor_enrolled` | a factor was confirmed at enrolment or at setup | `totp` or `webauthn` |
| `access_rule_added`, `access_rule_removed` | a rule changed | `ip:<cidr>` or `country:<code>` |
| `engine_created`, `engine_updated`, `engine_deleted` | an engine was written | engine name, `old>new` after a rename |
| `engine_tested` | a connection test of an existing engine, successful or not | engine name |
| `engine_sidecar_configured`, `engine_sidecar_removed` | the sidecar of an engine was enrolled or removed | engine name |
| `engine_sidecar_key_staged`, `engine_sidecar_key_promoted` | a next sidecar signing key was staged or promoted | engine name |
| `alert_deleted` | a live local alert (with its archived copy) or an archived alert was deleted | `<engine>/<upstream alert id>`; `archive/<engine>/<upstream alert id>` for an archive-only delete |
| `decision_removed` | a live decision was deleted (unban) | `decision:<id>` |
| `allowlist_created`, `allowlist_deleted` | an allowlist of an engine was created or deleted | `<engine>/<allowlist>` |
| `allowlist_entry_added`, `allowlist_entry_removed` | an allowlist entry was added or removed | `<value>@<engine>/<allowlist>`; the value comes first and is never cut |
| `api_token_created`, `api_token_revoked` | a token was created or revoked | `api_token:<id>:<name>` |
| `account_created`, `account_role_changed`, `account_second_factor_reset`, `account_sessions_revoked`, `account_unlocked`, `account_deleted` | an administrator acted on an account; `account_sessions_revoked` is also recorded when an account uses "log out everywhere" on itself | `account:<name>`; at creation `account:<name>:<role>`; role change `account:<name>:<previous role>-><new role>` |
| `secrets_rotated` | `dashboard rotate-secrets` finished a real run (no account) | number of rows rewritten |
| `retention_purged` | the hourly job removed or scrubbed something (no account) | counts: `ips=… audit=… sessions=… tokens=… archive=…` |
| `sync_run` | a manual sync run finished, or a scheduled one planned or applied a change or ended with an error (no account) | `[err=<code> ]dry_run=<bool> engines=<n> added=<n> removed=<n> skipped=<n>` (`err=` only when the run ended with a run-level code) |
| `bundle_exported` | a bundle was exported | `secrets=<bool> [skipped=<n>] [skipped_files=<n>] sections=<list>` |
| `bundle_imported` | a bundle import was applied (previews are not audited) | `failed=<n> hub=<n> decisions=<n> alerts=<n> config=<n> skipped=<n>` |

The client address is stored as plain text with an IPv4-mapped IPv6 address shown as IPv4 (empty when
it cannot be parsed). Not audited: rate-limited requests, session creation and logout, bouncer,
machine and hub changes (installs and removals of collections, AppSec rules and AppSec
configurations included; whether to audit them is an open question), manual bans
(`POST /api/decisions` writes no audit record, unlike the unban), the use of an API token. The `login_failure`
target is whatever was typed in the account name field, so a password typed there by mistake is
recorded: restrict who can read the table; the target is erased with the client address after
`AUDIT_IP_RETENTION_DAYS`, and the row after `AUDIT_RETENTION_DAYS`
([Personal data](#personal-data)). Administrators read the log with a session from the « Journal
d'audit » page, through `GET /api/audit` ([api.md](api.md#audit-log)); it is never readable with an
API token, and a `read_only` account cannot read it. The page and the route are read-only, return
the stored columns except the target of `login_failure` events, which is neither returned nor
searched, and change nothing in the retention above. A failed write is logged by the
dashboard and never blocks the login.

## Personal data

What the database holds about people, and for how long. Retention runs in one hourly job
([operations.md](operations.md#retention-and-purge)); nothing here leaves the database.

| Data | Where | Kept | Then |
|---|---|---|---|
| Client address of the operator | `audit_event_client_ip` | `AUDIT_IP_RETENTION_DAYS` (30) | erased, the event stays |
| Account name as typed at a failed login (may be an e-mail address, or a mistyped password) | `audit_event_target` of `login_failure` | `AUDIT_IP_RETENTION_DAYS` (30) | target erased, the event stays |
| Other audit targets (account names, engine names, `decision:<id>`) and the action | `audit_event` | `AUDIT_RETENTION_DAYS` (365, at least 90) | row deleted |
| Address or CIDR of an allowlist change | `audit_event_target` of `access_rule_added` and `access_rule_removed` | `AUDIT_RETENTION_DAYS` (365) | row deleted; **not** erased by the 30 days scrub, since it is the account's own configuration |
| Address or CIDR of an engine allowlist entry | `audit_event_target` of `allowlist_entry_added` and `allowlist_entry_removed` | `AUDIT_RETENTION_DAYS` (365) | row deleted; not erased by the 30 days scrub. The entry itself lives in CrowdSec, not in the dashboard database |
| Account name, role, creation date | `account` | while the account exists | deleted with the account; names remain in audit targets until their retention |
| Allowlist rules (addresses, networks, countries of the operator) | `access_rule` | until removed or the account is deleted | deleted with the account |
| Sessions (token hash, account, expiry; no address) | `session` | until expiry or revocation | pruned every hour |
| Lockout state (failed-attempt count, lock end) | `account` | until a success, an unlock or the lock end passes | overwritten, no history |
| API tokens (name, scope, hash, dates; no address) | `api_token` | until revoked or expired, then `API_TOKEN_RETENTION_DAYS` (30) | row deleted |
| Source addresses of attackers (alert source and decision values, event meta) | archive tables | `ARCHIVE_ALERT_RETENTION_DAYS` and `ARCHIVE_DECISION_RETENTION_DAYS` (365), events `ARCHIVE_EVENT_RETENTION_DAYS` (90) | deleted; a decision still active on the engine is kept until it expires |

Password hashes, recovery-code hashes and passkey public data are credentials, not logs: they live
and die with the account. Backups ([operations.md](operations.md#backup-and-restore)) keep all of the
above until the dump is deleted, so give dumps their own retention.

## Sessions

- A session token is 32 random bytes. The server keeps only its SHA-256 digest, with an expiry, in
  the `session` table of PostgreSQL. Lifetime is fixed (`SESSION_TTL`, default 12 h), not extended
  by activity; expired rows are pruned every hour.
- Sessions are created only after the third step of login. Completing a second-factor setup at
  login revokes every existing session of that account.
- Sessions survive a dashboard restart. Logout destroys the server-side session, "log out
  everywhere" (`POST /api/auth/logout-all`, or "Revoke sessions" by an administrator) destroys all
  sessions of the account **and revokes all its API tokens**, and deleting an account removes its
  sessions and tokens (cascade).
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

Engine data (alert scenario, source, message, machine id, decision value, event meta keys and
values) is attacker-controlled. The front end renders it as plain React text only: no HTML
injection, no link built from it, no link detection. Each free-text value sits in a `<bdi>` bidi
isolate, so a right-to-left override (U+202E) cannot reorder neighbouring cells, and long unbroken
strings wrap (`break-all`).

HSTS is not sent: terminate TLS at the reverse proxy and set it there.

## Command allowlist: the security boundary

The dashboard never builds a shell command. The API maps to 25 named commands, each a fixed argv:

| Area | Commands |
|---|---|
| Alerts | `cscli alerts delete --id <id>` |
| Bouncers | `bouncers list -o json`, `bouncers add <name>`, `bouncers delete <name>` |
| Machines | `machines list -o json`, `machines add <name> --auto -f /dev/stdout`, `machines validate <name>`, `machines delete <name>` |
| Hub | `hub list -o json`, `hub update`, `hub upgrade`, `collections install <name>`, `collections remove <name>`, `appsec-rules install <name>`, `appsec-rules remove <name>`, `appsec-configs install <name>`, `appsec-configs remove <name>` |
| Allowlists | `allowlists create <name> --description=<text>`, `allowlists delete <name>`, `allowlists add <name> <value> [--expiration=<duration>] [--comment=<text>]`, `allowlists remove <name> <value>` |
| Other | `metrics -o json`, `version`, `kill -HUP 1` (reload), and `crowdsec -t` (configuration test of the [config import](#configuration-import), no argument) |

Each variable field is validated before the exec: names `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`, hub names
the same with one optional `vendor/item` slash, ids 1 to 10 digits, durations 1 to 4 digits plus
`s|m|h|d`, targets a plain IP or CIDR of at most 43 characters (no zone, no IPv4-mapped form),
allowlist names `^[a-z0-9][a-z0-9._-]{0,31}$`, allowlist values an IP or CIDR in canonical form,
allowlist expirations `^[1-9][0-9]{0,3}[hd]$`, and free text (descriptions, comments) 1 to 256
bytes of UTF-8, not starting with `-`, without control, format or separator characters, always
passed as one `--flag=value` argument so it can never be read as a flag.
Unknown commands and unexpected fields are refused. Output is capped (8 MiB of stdout) and every
command has a timeout (30 s, 120 s for hub update, upgrade, install and remove). Error responses carry
a stable code only, never command output.

Manual bans go to the LAPI, not through cscli, and refuse ranges wider than /8 (IPv4) or /32 (IPv6),
so `0.0.0.0/0` and `::/0` cannot be banned from the UI.

## Search concurrency

Searches (`q`) take a slot from a server-wide limiter: 4 shared by `/api/alerts` and
`/api/decisions`, open to every authenticated reader, and 2 reserved to `/api/audit`, which only
administrators reach, so a `read_only` account or a `read` token cannot starve the audit search. A
full limiter answers 429 `search_busy`. The limits are per route class, not per account: one reader
can still fill the 4 list slots for everybody (known limit, no per-account fairness).

## SQL parameters

Queries go through bun, which inlines the parameters into the SQL text on the client side instead of
sending them separately. String literals are quoted with doubled single quotes and backslashes are
left as they are, which is safe only while `standard_conforming_strings` is `on` (the PostgreSQL
default since 9.1). Never turn it off, neither in the server configuration nor through
`DATABASE_URL` (for example `options=-c standard_conforming_strings=off`).

## Destructive actions and one-time secrets

- Deleting an alert, decision, bouncer, machine, hub item, allowlist or allowlist entry requires a JSON body
  `{"confirm": "<same value as the path>"}`; otherwise 400 `confirmation_required`. The UI asks the
  user to retype the value (for an unban, the IP or range of the decision; the request still carries the decision id). Deleting the dashboard's own machine account answers 409 `self_account`.
- `POST /api/decisions` refuses with 409 `self_ban` a ban whose target is, or whose range contains, the
  client address of the request, before calling the LAPI. It is a safety net, not a security control:
  the address is the one resolved with the same rule as the login rate limiter, and an address that
  cannot be parsed is not blocked. Behind a reverse proxy it only works if `TRUSTED_PROXY_CIDRS` is
  set; otherwise the proxy's own address is what is compared.
- A new bouncer key and a new machine password are returned once, in the creation response, and are
  not stored or logged. The UI clears them when the dialog closes and cannot be closed while the
  request is pending.

## Configuration files

Only administrators can read configuration files, and only an allowlist is readable: `config.yaml`, `acquis.yaml`, `profiles.yaml`, `acquis.d/*.yaml|yml`,
`parsers/*/*whitelist*.yaml|yml` and `postoverflows/*/*whitelist*.yaml|yml`, each at most 256 KiB. Any file whose name contains
`credentials` is refused, as is any path through a symlink. The mount is read-only; the only
writable CrowdSec path is the optional, dedicated import directory ([Configuration import](#configuration-import)).

Redaction is line based. A value is replaced by `[REDACTED]` when its key contains `password`,
`passwd`, `token`, `secret`, `api_key`, `apikey`, `key`, `authorization`, `bearer`, `credential` or
`dsn`, together with the indented block below it; URL userinfo (`://user:pw@`) and `Bearer <value>`
are masked anywhere. Known gaps: a secret stored under a key with another name, or written in a
comment or free text, is not detected. Do not rely on redaction for files you
would not show an admin. Engine credentials and the LAPI client also print as redacted when
formatted or logged.

## Container image

The dashboard image is built on Alpine with s6-overlay as init and supervisor, not on a distroless
base. That is a larger attack surface than before (a shell, `apk`, busybox, cron, `bash`) that was
accepted to supervise the dashboard and `geoipupdate` in one container. Mitigations:

- The dashboard process runs as `docker-user` (UID/GID 10000, remappable with `DOCKER_USER_UID` and
  `DOCKER_USER_GID`). The container itself starts as root because s6 and the init scripts need it;
  they drop privileges with `s6-setuidgid`.
- Root filesystem read-only (`read_only: true`), with three tmpfs:
  - `/run:exec,nosuid,nodev,mode=0755`: s6-overlay runs code from `/run` and refuses a
    world-writable one, so Docker's tmpfs defaults (`noexec`, mode 1777) would break it. It holds
    the s6 state, the copied secrets key and the `geoipupdate` configuration;
  - `/etc/cron.d:noexec,nosuid,nodev,mode=0755`: the cron entry written at start; root-only, so
    `docker-user` cannot schedule anything;
  - `/tmp:noexec,nosuid,nodev,mode=1777`.
  The only writable volume is `/var/lib/geoip`, owned by `docker-user`.
- `cap_drop: [ALL]`, `no-new-privileges`, and only these capabilities added back, each shown to be
  necessary by removing it in turn:

  | Capability | Why |
  |---|---|
  | `SETUID`, `SETGID` | `s6-setuidgid` drops to `docker-user`; without them the dashboard does not start (`s6-applyuidgid: fatal: unable to setuid`) |
  | `KILL` | root (`s6-supervise`) signals the dashboard on stop; without it `docker stop` ends with exit 137 and no clean shutdown |
  | `CHOWN`, `DAC_READ_SEARCH` | the compose secret keeps the host owner and mode (owned by the host user, mode 0600), so it is not readable by `docker-user`: root needs `DAC_READ_SEARCH` to read it and `CHOWN` to hand the copy and the GeoLite2 volume to `docker-user`; either one alone fails |

  `DAC_OVERRIDE` and `FOWNER` are not needed.
- The hook directories `/custom-scripts.d` and `/docker-entrypoint.d` are root-owned in the image and
  run as root at start; with a read-only root filesystem `docker-user` cannot add to them. Mounting
  scripts there is a root-level decision: only mount scripts you trust.
- Secrets: the secrets key is copied by `25-secrets-key` to a tmpfs file (mode 0400, owner
  `docker-user`, directory 0700). The MaxMind licence key is read from a secret file, never from an
  environment variable or a command-line argument (so it is not in `docker inspect`, `/proc/*/environ`
  or process listings), and `GeoIP.conf` is written mode 0600 to the tmpfs. `docker-user` must be
  able to read that file, because `geoipupdate` runs as `docker-user`: a compromised dashboard
  process can therefore read the licence key (a free GeoLite2 key, revocable from the MaxMind
  account).
- `chown` over the GeoLite2 volume never follows symbolic links (`find -xdev -exec chown -h`), so a
  link planted in the volume cannot change the owner of files elsewhere.
- Supply chain: s6-overlay is downloaded from its release archives and verified against a pinned
  SHA-256 before extraction; `geoipupdate` has no Alpine package and is compiled from source in a
  separate Go build stage (checked by the Go checksum database); the final image carries no
  compiler. The image is built for `x86_64` and `aarch64` only.
- A UID remap rewrites `/etc/passwd` and `/etc/group` and so requires a writable root filesystem;
  with `read_only: true` the container stops at start (the log shows `groupmod` failing on the
  read-only `/etc`) rather than running with the wrong user.

## Engines and outbound connections

An administrator can register remote CrowdSec engines (`/api/engines`, [api.md](api.md#engines));
the dashboard then logs in to their LAPI as a machine and archives their alerts. Only the `admin`
role can read, add, change, test or delete engines (and writes need a session, not a token); a `read_only` account only sees the engine
names (`GET /api/engines/names`, for filters and selectors), never their URL, machine, proxy or
collection state.

Every connection to a remote engine (collection, connection test, allowlist read) goes through one
client per engine, never through `HTTP_PROXY` / `HTTPS_PROXY` of the environment:

- **Address policy.** The address is checked when the connection is made, after DNS resolution,
  so a name that resolves (or re-resolves) to a forbidden address is refused. Allowed: private ranges, because engines legitimately live there (RFC 1918
  `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, carrier-grade NAT `100.64.0.0/10`, IPv6 ULA
  `fc00::/7`) and public unicast addresses, on any port. Refused: loopback, link-local (including
  `169.254.169.254`), unspecified, multicast and the reserved and documentation ranges
  (the built-in list of `code.dny.dev/ssrf`), plus three metadata endpoints that sit inside allowed
  ranges: `100.100.100.200` (Alibaba Cloud), `fd00:ec2::254` (AWS IPv6) and `168.63.129.16` (Azure wire server). A refusal is reported
  as `engine_blocked_address`. A forbidden address written as a canonical literal in `lapi_url` or `proxy.url` (for example
  `127.0.0.1`) is also refused when the engine is saved. Other spellings of the same address (`127.1`,
  `0x7f.0.0.1`) are not literals for the save-time check and are saved; the check made when connecting
  still refuses them. IPv4-mapped IPv6 forms are unmapped before the check.
- **Proxy as a trust boundary.** With a proxy (`socks5` or `http`), the check applies to the proxy
  address; the engine host name is resolved by the proxy (`socks5` behaves as `socks5h`), so the
  dashboard cannot check where the proxy connects. Choosing a proxy is choosing to trust it: only
  configure proxies you control.
- **No redirects, bounded exchanges.** Redirects are never followed. Connecting and the TLS
  handshake have 5 s each, response headers are capped at 64 KiB, a request or a login has 15 s
  (a connection test 10 s, the collector's full history read 120 s), and bodies are capped (16 MiB
  for collector reads, 4 MiB for allowlists, 8 MiB otherwise). An oversized answer is an error or
  an incomplete read; it is never used partially.
- **Secrets at rest.** The machine password and the proxy credentials of an engine are sealed with
  the secrets key (AES-GCM, see [Encryption of secrets](#encryption-of-secrets)). The authenticated
  data is the engine id and its destination (scheme, host and port of `lapi_url`; for the proxy
  credentials also the proxy kind and URL): a sealed value copied to another engine row, or left in
  place under a changed destination, does not open (`engine_secret_unreadable`). No API
  response, error, log or audit entry carries them; the API only says `has_proxy_credentials`.
- **Secrets bound to their destination.** Changing the scheme, host or port of `lapi_url` requires
  the machine password in the same request; changing `proxy.url` or `proxy.kind` of an engine
  that has proxy credentials requires new credentials (or `clear_credentials`); changing the proxy
  of an `http` engine requires the machine password (the password crosses the new proxy in clear
  text). Otherwise the request fails with `engine_secret_required` before any write or connection,
  so a stored secret is never sent to a destination an administrator just typed. A change of the
  URL **path** alone keeps the stored password: a gateway that routes engines by path could then
  receive it, so treat path-routed gateways as one destination.
- **Collection racing a destination change.** A collection already running when the destination
  of an engine changes, or when the engine is disabled, is discarded without writing anything and
  is not counted as a failure: the next attempt uses the new destination.
- **Connection test oracle.** `POST /api/engines/{name}/test` returns only the outcome (`ok`,
  `engine_unreachable`, `engine_auth_failed`, `engine_blocked_address`), never the body of the
  answer, and errors never repeat the submitted URL. An administrator can still use it, and the
  collector status, as a reachability probe: "something answers on that address and port", "it
  refused the machine login", or "this address is blocked". Addresses that the policy allows but
  that may be sensitive on your host stay reachable this way, for example the Docker bridge
  gateway (`172.17.0.1`, RFC 1918) or the Tailscale resolver (`100.100.100.100`, carrier-grade
  NAT). If the dashboard sits next to services it must not reach, isolate it at the network
  level (a dedicated Docker network, an egress firewall), the policy above is not a substitute.
- **What an administrator can reach.** Any allowed address and port, as an HTTP client that sends
  `POST /v1/watchers/login` and the LAPI read routes with the stored machine credentials.
  Nothing else: no free-form request, no response content shown.
- **The local engine** comes from `LAPI_URL` (configuration, not the UI). Its client is not subject
  to the address policy, since it is usually on a Docker network or loopback; it cannot be edited
  through the API (`engine_local_readonly`).
- **Engine data is attacker data.** Archived events (user agents, URLs, payloads, meta) are stored
  as received after removal of NUL bytes and replacement of invalid UTF-8, bounded per alert (200 events, 200
  decisions, 64 meta keys of 128 bytes, values of 4 KiB, 60 KiB of meta per event), and rendered as
  plain text in `<bdi>` isolates (see [Headers and content security
  policy](#headers-and-content-security-policy)). Bidirectional control characters are kept and
  isolated, not stripped.

### Allowlist check before writes

`allowguard` reads the allowlists of an engine (`GET /v1/allowlists?with_content=true`) and
decides whether a ban target overlaps an active allowlist entry, in both directions (an entry
inside the target range or the target inside an entry), for IPv4 and IPv6. An entry is active when
it has no expiration (CrowdSec serialises a permanent entry as `0001-01-01T00:00:00.000Z`) or its
expiration is not past. It fails closed: a read error, a truncated answer (over 4 MiB or 10 000
entries), an unreadable entry value or a 404 (a real LAPI answers an unknown route with an empty
404, which cannot be told apart from a wrong port or a proxy) makes the engine's allowlists
unavailable and every target is refused (`allowlist_unavailable`). This holds for EVERY 404 on
`/v1/allowlists`, including one whose body is a JSON object with a `message` (an API gateway can send
that too): it is never read as "allowlists unsupported". Consequence: an engine whose CrowdSec is too
old to have allowlists refuses the writes guarded this way.

The engine sync ([sync.md](sync.md#allowlists)) and the bundle import of decisions and alerts
([bundles.md](bundles.md#decisions)) use this filter on the allowlists of the engine they write to,
read at the start of the run or plan, and check again before each write; an unavailable allowlist
means nothing is written to that engine. An entry added during a sync run is honoured at the next
run (window: one run plus one interval).

The manual ban `POST /api/decisions` goes through the same filter, on the allowlists of the local
engine, read just before the write: a target that overlaps an active entry is refused with 409
`target_allowlisted` (no override: remove the entry first), and unreadable allowlists refuse every
ban with 503 `allowlist_unavailable`. The check is needed because the ban is written through
`POST /v1/alerts` as an alert carrying its decision, and the LAPI skips its own allowlist check
for such an alert: without the filter it would store a ban on an allowlisted IP and serve it to
bouncers. Race window: an entry added by an external `cscli` between the allowlist read and the
LAPI write is not seen by that ban (the same window as the sync); CrowdSec itself deletes the
covered decisions when an entry is added with `cscli allowlists add`, so only an entry added by
another path leaves the ban in place.

### Allowlists of the engines

The Allowlists page and its routes ([api.md](api.md#allowlists)) show the CrowdSec allowlists of
every engine and change those of the local engine.

- **An allowlist disarms protection.** An address or range in an active entry is never banned by
  that engine's scenarios or AppSec, nor by the dashboard's manual ban, sync or import. Every
  write is admin and audited. A value wider than IPv4 /8 or IPv6 /32 is refused outright
  (`0.0.0.0/0` and `::/0` never pass), and one wider than IPv4 /24 or IPv6 /48 needs the canonical
  range retyped; these floors are constants that no setting can relax.
- **Adding an entry deletes decisions.** `cscli allowlists add` makes CrowdSec delete at once every
  decision of that engine covered by **any** of its allowlists, not only by the new value. The
  confirmation dialog of a wide range says so.
- **AppSec is bypassed for allowlisted addresses**: requests from them are not inspected by the
  AppSec rules of that engine.
- **Local writes only.** The LAPI can read allowlists but has no route to write them, and
  `cscli allowlists` must run on the host of the LAPI. The dashboard therefore writes with `cscli`
  in the local CrowdSec container, through the [command allowlist](#command-allowlist-the-security-boundary)
  (fixed argv, validated fields, free text as a single `--flag=value`). A remote engine is
  written through its [sidecar](operations.md#engine-sidecar) only, and is read-only
  (`allowlist_engine_readonly`) without one. Console-managed allowlists are read-only too (`allowlist_console_managed`).
- **Verification.** `cscli allowlists` exits 0 on a duplicate, invalid or missing value, so the
  dashboard reads the allowlists from the LAPI before and after each write and reports
  `allowlist_write_failed` when the change is not visible. The output of `cscli` and the LAPI
  answer are never returned or logged, only a stable code.
- Descriptions and comments are attacker-reachable text for any reader of the page: they are
  rendered as plain text, like engine data.

### AppSec data

AppSec alerts and their events (rule names, messages, URIs, target hosts, matched zones) come from
HTTP requests sent by attackers. They are stored and shown exactly like other engine data (see
**Engine data is attacker data** above): plain text in `<bdi>` isolates, never HTML, a link or an
attribute, under the unchanged content security policy. The AppSec summary of an alert only picks
known meta keys out of the events; it adds no rendering path.

### Engine synchronisation

The sync ([sync.md](sync.md)) uses the remote engines of the engine table marked as sync peers.
Their machine passwords and proxy credentials are the sealed engine secrets above: never in a
response, a log, the Sync page (which shows the host and port only) or an environment variable.
The peers file of earlier designs is refused at start.

- **A peer can ban addresses everywhere.** A ban native on any participating engine is copied to
  all the others. A compromised or misconfigured peer (or anyone holding its machine password or
  `cscli` on it) can therefore have addresses banned on every engine, within the guards: only bans
  of origin `crowdsec`/`cscli`, no range wider than IPv4 /8 or IPv6 /32, never a private,
  loopback, link-local or carrier-grade NAT address, never an address of an engine of the table or
  of `SHARE_EXCLUDE_CIDRS`, never an address allowlisted on the target engine, at most
  `SYNC_MAX_CHANGES` changes per source and per target in one run, and the dry run as the default.
  Put the addresses you administer from in `SHARE_EXCLUDE_CIDRS` (the sync has no "own address"
  check) and in the CrowdSec allowlists of each engine.
- The dashboard only writes copies tagged `sync/<engine>` with its own machine account and only
  deletes decisions it can identify as its copies (that scenario prefix **and** its machine id);
  a native ban is never deleted.
- Unbanning a copy does not propagate: lift the ban on the engine where it is native.

### Bundles

- Export and import touch the local engine only. The import route is **admin and session only**:
  a stolen `write` token cannot import a bundle. An export is admin (session or `write` token), but
  an export with secrets (`include_secrets`) needs a session and the retyped word `SECRETS`; the
  file then holds the unredacted configuration (`contains_secrets: true`): treat it as a secret.
  `config.yaml` and credential-like file names are never exported.
- A bundle is untrusted input: decoded strictly (8 MiB, 32 levels, no unknown field), every
  decision passes the sync sharing rules, the own-address guard and the allowlist filter, alerts
  are sanitised and pushed without effect ([bundles.md](bundles.md#alerts)), and an apply must
  match the previewed digest.

### Configuration import

Off by default. Enabling it (`CONFIG_IMPORT_ENABLED=true`) **gives the dashboard a write permission
on part of the CrowdSec configuration**: the dedicated directory `CONFIG_IMPORT_DIR`, mounted
read-write in the dashboard and read-only in CrowdSec as its `acquis.d`. Nothing else of
`/etc/crowdsec` may be writable ([configuration.md](configuration.md#config-import-mount)).

- **Threat model.** A compromised dashboard, or an administrator session, with the import enabled
  can add or change acquisition files, that is decide what CrowdSec reads: it can blind detection
  (replace a source) or make CrowdSec read other files. It cannot write profiles, whitelists,
  parsers, scenarios or `config.yaml` through this feature. A compromised dashboard process with
  write access to the directory can of course write anything there directly, bypassing every check
  below; the checks bind the import feature, not a compromised process.
- **Datasource policy** (operator decision): only `file`, `journalctl` and `docker` sources, no
  `transform`, plain YAML only (no tags, anchors, aliases, merge keys, non-string keys). So an
  imported file cannot open a network listener (http, syslog, kafka, ...) or send lines elsewhere.
  Residual reach: `file` `filenames` can name any path readable by CrowdSec, `docker_host` can point
  to a remote Docker daemon, and journalctl filters pass arbitrary `journalctl` arguments (no
  shell).
- **Writing.** Names `acquis.d/<name>.yaml` only (no `profiles.yaml`, `acquis.yaml`, whitelists,
  credentials), 256 KiB, no `[REDACTED]` marker. Paths go through `os.Root` (no escape from the
  directory), no symlink is followed or accepted (file, import directory, backup directory), each
  file is checked to be the one classified before it is backed up or replaced, writes are a
  temporary file then a rename, and the whole set is validated by `crowdsec -t` and rolled back on
  failure, with a crash-recovery journal ([bundles.md](bundles.md#configuration)).
- **Ownership.** Created files are 0640 owned by the dashboard user; a replaced file keeps its
  mode but takes the dashboard owner.
- **Logs.** The import never returns or logs the output of `crowdsec -t`. The Docker runner logs the
  stderr of a failed command at debug level, `crowdsec -t` included, which may show paths; the
  dashboard uses the default Go logger, which does not emit debug lines, and has no setting to
  raise the level.
- Turn it off again once the migration is done.

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
- Roles and tokens are described in [Roles and access](#roles-and-access). A `write` token of an
  administrator reaches the credential-creating admin routes; there is no page to read the audit
  log.
- Known limits of the second factor and the allowlist, collected here:
  - the allowlist prefix floor (IPv4 /8, IPv6 /16) applies to new rules only;
  - the pending state of a first-account enrolment and of a setup has no expiry of its own (memory
    only, gone at restart or completion);
  - WebAuthn `excludeCredentials` is not used because setup is offered only to accounts without a
    factor (a reset deletes them);
  - a security key used without PIN or biometric is accepted (user verification `preferred`), and a
    passkey with a counter stuck at 0 has no clone detection;
  - without a GeoLite2 database, country rules refuse everyone not matched by an IP rule;
  - the audit log is not complete (see [Audit log](#audit-log));
  - an allowlist entry in IPv4-mapped form is read as IPv4 only from `::ffff:0:0/96` and narrower
    (`::ffff:192.0.2.0/120` becomes `192.0.2.0/24`). A wider one (`::ffff:0:0/95`, `::/0`) stays an
    IPv6 range and does not protect IPv4 addresses, which are always unmapped before matching. The
    reverse holds for a target (a ban, a sync or import entry) such as `::/0` or `::ffff:0:0/80`: it
    does not cover IPv4 addresses, so an IPv4 allowlist entry never matches it. The IPv6 ban floor
    (/32) keeps such wide values out of manual bans.
- The login rate limiter, the pending logins and the enrolment state are per process (one replica).
- The manual ban checks the local allowlists just before writing, but an entry added by an
  external `cscli` between that read and the LAPI write is not seen
  ([Allowlist check before writes](#allowlist-check-before-writes)); manual bans are not audited.
- Allowlists are written on the local engine only; remote engines are read-only
  ([Allowlists of the engines](#allowlists-of-the-engines)). Hub installs and removals, AppSec
  included, are not audited.
- Engine sync widens the blast radius of one compromised engine to every engine within the guards
  ([Engine synchronisation](#engine-synchronisation)); the config import, when enabled, gives the
  dashboard write access to CrowdSec's acquisition files ([Configuration import](#configuration-import)).

## Exposure advice

- Put it behind a TLS reverse proxy; do not publish the container port.
- Restrict who can reach it: IP allowlist at the proxy, or a VPN, in addition to the password.
- Use a long random password (12 characters minimum). Protect `dashboard.env` and `postgres.env`
  (mode 0600): they hold the database password and `LAPI_MACHINE_PASSWORD`. Protect the secrets key
  file the same way and keep a copy apart from the database backups.
- Prefer a passkey or security key with a PIN or biometric over presence-only keys, keep the
  recovery codes offline, and add an allowlist rule for your usual networks once you rely on it.
- Set `TRUSTED_PROXY_CIDRS` to the proxy's single address (see [configuration.md](configuration.md)).
