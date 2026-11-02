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
  rm -rf ./keys ./state ./backups ./compose.yaml ./empty.dump ./test.log
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

restore() {
  "$deploy_directory/restore.sh" -p "$project" -s "$service" -d "$restored_database" "$@"
}

# restore.sh must refuse before touching anything: first a wrong confirmation, then an empty file.
# backup_restored does not exist yet, so any change would make it appear.
database_exists() {
  docker compose -p "$project" exec -T "$service" psql -U postgres -d postgres -tAc \
    "SELECT count(*) FROM pg_database WHERE datname = 'backup_restored'"
}
if restore "$backup_file" </dev/null; then
  echo "backup-check: restore.sh accepted a missing confirmation" >&2
  exit 1
fi
if restore --confirm wrong_name "$backup_file"; then
  echo "backup-check: restore.sh accepted a wrong confirmation" >&2
  exit 1
fi
: > "$work_directory/empty.dump"
if restore --confirm "$restored_database" "$work_directory/empty.dump"; then
  echo "backup-check: restore.sh accepted an empty backup" >&2
  exit 1
fi
if restore --confirm "$restored_database" "$work_directory/missing.dump"; then
  echo "backup-check: restore.sh accepted a missing backup" >&2
  exit 1
fi
if [ "$(database_exists)" != 0 ]; then
  echo "backup-check: a refused restore touched the database" >&2
  exit 1
fi
echo "backup-check: refusals leave the database untouched"

restore --confirm "$restored_database" "$backup_file"

RUN_PATTERN=TestRestoredDatabaseServesLoginAndArchive
run_check BACKUP_CHECK_RESTORED_URL="$(url_for backup_restored)"
run_check BACKUP_CHECK_RESTORED_URL="$(url_for backup_restored)" BACKUP_CHECK_WRONG_KEY_FILE="$work_directory/keys/wrong.key"

echo "backup-check: OK"
