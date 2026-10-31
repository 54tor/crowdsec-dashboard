## PostgreSQL

The dashboard needs a PostgreSQL server (the `postgres` service of `deploy/compose.example.yaml`,
configured by `postgres.env`, data in the `postgres-data` volume). The dashboard container starts
after the database is healthy.

- At every start it opens the database, applies the pending schema migrations automatically and only
  then serves requests. It refuses to start if `DATABASE_URL` is missing or unreachable, or if a
  migration fails: read the container log.
- Back up the database before upgrading the dashboard to a new version, since an upgrade may migrate
  the schema.
- If PostgreSQL goes down while the dashboard runs, `/api/healthz` answers 503 and login and
  authenticated routes answer 503 `database_unavailable`. Nobody is signed out: sessions are valid
  again once the database is back.
- Automated backup and restore of the database are not provided yet (planned for a later lot):
  until then, back up the `postgres-data` volume or dump the database with your usual tooling.

## First start and enrolment

1. Fill `dashboard.env` and `postgres.env` from the examples and start the stack.
2. While the `account` table is empty, the dashboard logs a line such as
   `no account yet: open /enroll and enroll the first account with token <token>`
   (`docker logs <dashboard container>`). The token lives in memory only and is replaced at each
   restart while no account exists.
3. Open `https://<your host>/enroll`, enter the token, an account name and a password of 12 to 128
   characters. The first account is an administrator and is signed in at once.
4. From then on enrolment is closed (`POST /api/auth/enroll` answers 404) and no token is logged.

Whoever can read the logs while no account exists can create the first account: enrol promptly and
keep the logs private ([security.md](security.md#accounts-and-enrolment)). The development stack
(`deploy/dev/up.sh`) prints the token for you.

## Backup and restore

The dashboard keeps its state in PostgreSQL (accounts, sessions). Keep the compose file,
`dashboard.env` and `postgres.env` in your usual configuration backup, and back up the database
(see [PostgreSQL](#postgresql)). To restore, redeploy the files and the database, and recreate the
LAPI machine account if the CrowdSec data was lost. CrowdSec's own volumes (configuration,
`crowdsec.db`) are backed up with CrowdSec, not with the dashboard.

Accounts have no password-reset feature yet: with the database restored you keep your accounts; if
the `account` table is emptied, the next start opens enrolment again. To rotate the machine password,
run `cscli machines delete` and `add` again with the new value, then recreate the dashboard.
