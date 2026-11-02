#!/usr/bin/env bash
# End-to-end check of deploy/backup.sh and deploy/restore.sh on the disposable PostgreSQL
# (compose project csdash-test-db, see test-db.sh). Everything happens in two databases
# created here, backup_source and backup_restored; the shared csdash_test database
# is never dropped or altered.
set -euo pipefail

cd "$(dirname "$0")"
here="$PWD"
deploy_directory="$(dirname "$here")"
backend_directory="$(dirname "$deploy_directory")/backend"

project=csdash-test-db
service=postgres
source_database=backup_source
restored_database=backup_restored

work_directory="$(mktemp -d)"
# Removes the temporary files by literal relative names from inside the temporary directory.
remove_work_directory() {
  cd "$work_directory" || return 0
  rm -rf ./keys ./state ./backups ./compose.yaml ./empty.dump ./header-only.dump ./truncated.dump ./corrupt-data.dump ./test.log
  cd / && rmdir "$work_directory" || true
}
trap remove_work_directory EXIT

# Same project, service name and image as test-db.sh; restore.sh reads this file through
# "docker compose config". The dashboard service only exists to prove restore.sh
# copes with a stack where it is not running.
cat > "$work_directory/compose.yaml" <<COMPOSE
services:
  postgres:
    image: postgres:latest
  dashboard:
    image: postgres:latest
COMPOSE
export COMPOSE_FILE="$work_directory/compose.yaml"

database_url="$(./test-db.sh up | sed -n 's/^TEST_DATABASE_URL=//p')"
if [ -z "$database_url" ]; then
  echo "backup-check: test database did not start" >&2
  exit 1
fi
url_for() {
  echo "${database_url%/csdash_test?sslmode=disable}/$1?sslmode=disable"
}

# Only the two literal database names below are ever dropped or created.
psql_admin() {
  docker compose -p "$project" exec -T "$service" psql -v ON_ERROR_STOP=1 -U postgres -d postgres -c "$1"
}
psql_admin 'DROP DATABASE IF EXISTS backup_source WITH (FORCE)'
psql_admin 'DROP DATABASE IF EXISTS backup_restored WITH (FORCE)'
psql_admin 'CREATE DATABASE backup_source'
cleanup_databases() {
  psql_admin 'DROP DATABASE IF EXISTS backup_source WITH (FORCE)' >/dev/null || true
  psql_admin 'DROP DATABASE IF EXISTS backup_restored WITH (FORCE)' >/dev/null || true
  psql_admin 'DROP DATABASE IF EXISTS backup_restored_restore_tmp WITH (FORCE)' >/dev/null || true
  remove_work_directory
}
trap cleanup_databases EXIT

# Two distinct 32-byte base64 keys: the right one seals the data, the other one must be refused.
umask 077
mkdir "$work_directory/keys" "$work_directory/state" "$work_directory/backups"
head -c 32 /dev/urandom | base64 > "$work_directory/keys/right.key"
head -c 32 /dev/urandom | base64 > "$work_directory/keys/wrong.key"

run_check() {
  (cd "$backend_directory" && env \
    BACKUP_CHECK_KEY_FILE="$work_directory/keys/right.key" \
    BACKUP_CHECK_STATE_DIR="$work_directory/state" \
    "$@" go test -count=1 -p 4 -v ./internal/store/backupcheck/ -run "$RUN_PATTERN") | tee "$work_directory/test.log"
  if grep -q -- '--- SKIP' "$work_directory/test.log"; then
    echo "backup-check: a test was skipped" >&2
    exit 1
  fi
}

RUN_PATTERN=TestSeedBackupCheckDatabase
run_check BACKUP_CHECK_SOURCE_URL="$(url_for backup_source)"

backup_file="$("$deploy_directory/backup.sh" -p "$project" -s "$service" -d "$source_database" -o "$work_directory/backups")"
echo "backup-check: backup written, mode $(stat -c %a "$backup_file")"

# The dump records backup_source as its origin, so restoring it into backup_restored needs the explicit flag.
restore() {
  "$deploy_directory/restore.sh" -p "$project" -s "$service" -d "$restored_database" "$@"
}

psql_query() {
  docker compose -p "$project" exec -T "$service" psql -U postgres -d "$1" -tAc "$2"
}

# Row counts of the account, engine, alert, event and decision tables: a cheap fingerprint of a database's content.
fingerprint() {
  psql_query "$1" "SELECT (SELECT count(*) FROM account) || '/' || (SELECT count(*) FROM engine) || '/' || (SELECT count(*) FROM alert) || '/' || (SELECT count(*) FROM event) || '/' || (SELECT count(*) FROM decision)"
}

restore --allow-database-mismatch --confirm "$restored_database" "$backup_file"
restored_marker="$(fingerprint backup_restored)"
source_marker="$(fingerprint backup_source)"
echo "backup-check: fingerprints restored=$restored_marker source=$source_marker"
if [ "$restored_marker" != "$source_marker" ] || [ "$restored_marker" = "" ]; then
  echo "backup-check: restored database differs from its source" >&2
  exit 1
fi

# Every refusal below must leave both databases (and the temporary restore database) exactly as they are.
: > "$work_directory/empty.dump"
backup_size="$(stat -c %s "$backup_file")"
head -c 200 "$backup_file" > "$work_directory/header-only.dump"
head -c "$((backup_size * 3 / 4))" "$backup_file" > "$work_directory/truncated.dump"
# Random bytes in the middle of the data: the table of contents still lists fine, so only the restore itself fails.
cp "$backup_file" "$work_directory/corrupt-data.dump"
head -c 16 /dev/urandom | dd of="$work_directory/corrupt-data.dump" bs=1 seek="$((backup_size / 2))" conv=notrunc 2>/dev/null

expect_refusal() {
  description="$1"
  shift
  if restore "$@" </dev/null; then
    echo "backup-check: restore.sh accepted $description" >&2
    exit 1
  fi
}
expect_refusal "a missing confirmation" --allow-database-mismatch "$backup_file"
expect_refusal "a wrong confirmation" --allow-database-mismatch --confirm wrong_name "$backup_file"
expect_refusal "a database mismatch without the flag" --confirm "$restored_database" "$backup_file"
expect_refusal "an empty backup" --allow-database-mismatch --confirm "$restored_database" "$work_directory/empty.dump"
expect_refusal "a missing backup" --allow-database-mismatch --confirm "$restored_database" "$work_directory/missing.dump"
expect_refusal "an invalid archive" --allow-database-mismatch --confirm "$restored_database" "$work_directory/header-only.dump"
expect_refusal "a truncated archive" --allow-database-mismatch --confirm "$restored_database" "$work_directory/truncated.dump"
# Passes validation, fails midway in pg_restore: the original database must survive and the dashboard restart path runs.
expect_refusal "an archive with corrupt data" --allow-database-mismatch --confirm "$restored_database" "$work_directory/corrupt-data.dump"
# A name over 51 characters would make "<name>_restore_tmp" collide with the real name after postgres truncates it to 63.
expect_refusal "a database name over 51 characters" -d "$(printf 'a%.0s' $(seq 1 52))" --confirm "$(printf 'a%.0s' $(seq 1 52))" "$backup_file"
# A leftover temporary database is never dropped automatically.
psql_admin 'CREATE DATABASE backup_restored_restore_tmp'
expect_refusal "a restore while a temporary database exists" --allow-database-mismatch --confirm "$restored_database" "$backup_file"
if [ "$(psql_query postgres "SELECT count(*) FROM pg_database WHERE datname = 'backup_restored_restore_tmp'")" != 1 ]; then
  echo "backup-check: the leftover temporary database was dropped" >&2
  exit 1
fi
psql_admin 'DROP DATABASE backup_restored_restore_tmp'

if [ "$(fingerprint backup_restored)" != "$restored_marker" ] || [ "$(fingerprint backup_source)" != "$source_marker" ]; then
  echo "backup-check: a refused restore changed a database" >&2
  exit 1
fi
if [ "$(psql_query postgres "SELECT count(*) FROM pg_database WHERE datname = 'backup_restored_restore_tmp'")" != 0 ]; then
  echo "backup-check: a failed restore left its temporary database behind" >&2
  exit 1
fi
echo "backup-check: refusals and failed restores leave the databases intact"

RUN_PATTERN=TestRestoredDatabaseServesLoginAndArchive
run_check BACKUP_CHECK_RESTORED_URL="$(url_for backup_restored)"
run_check BACKUP_CHECK_RESTORED_URL="$(url_for backup_restored)" BACKUP_CHECK_WRONG_KEY_FILE="$work_directory/keys/wrong.key"

echo "backup-check: OK"
