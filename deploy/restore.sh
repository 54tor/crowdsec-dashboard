#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 -p <compose-project> -s <postgres-service> -d <database> [-w <dashboard-service>] [--confirm <database>] [--allow-database-mismatch] <backup-file>" >&2
  exit 2
}

project=""
service=""
database=""
dashboard_service="dashboard"
confirmation=""
allow_mismatch=""
while [ $# -gt 0 ]; do
  case "$1" in
    -p | -s | -d | -w | --confirm)
      [ $# -ge 2 ] || usage
      case "$1" in
        -p) project="$2" ;;
        -s) service="$2" ;;
        -d) database="$2" ;;
        -w) dashboard_service="$2" ;;
        --confirm) confirmation="$2" ;;
      esac
      shift 2
      ;;
    --allow-database-mismatch) allow_mismatch=1; shift ;;
    -*) usage ;;
    *) break ;;
  esac
done
if [ -z "$project" ] || [ -z "$service" ] || [ -z "$database" ] || [ $# -ne 1 ]; then
  usage
fi
backup_file="$1"
if ! [[ "$database" =~ ^[A-Za-z0-9_]+$ ]]; then
  echo "invalid database name" >&2
  exit 2
fi
if [ "${#database}" -gt 51 ]; then
  echo "database name is longer than 51 characters: the temporary restore name would be truncated by postgres" >&2
  exit 2
fi
temporary_database="${database}_restore_tmp"

compose() {
  docker compose -p "$project" "$@"
}

if ! compose config --services | grep -qx "$service"; then
  echo "service $service is not defined in compose project $project" >&2
  exit 1
fi
container_id="$(compose ps -q --status running "$service")"
if [ -z "$container_id" ]; then
  echo "service $service of compose project $project is not running: nothing was changed" >&2
  exit 1
fi

existing_temporary="$(compose exec -T "$service" sh -c 'psql -U "${POSTGRES_USER:-postgres}" -d postgres -tAc "SELECT count(*) FROM pg_database WHERE datname = '"'"'$1'"'"'"' sh "$temporary_database")"
if [ "$existing_temporary" != 0 ]; then
  echo "database $temporary_database already exists: inspect it and drop it manually, nothing was changed" >&2
  exit 1
fi

echo "docker compose project: $project"
echo "postgres service:       $service"
echo "postgres container:     $container_id ($(docker inspect -f '{{.Config.Image}}' "$container_id"))"
echo "database to be replaced: $database"

if [ ! -f "$backup_file" ]; then
  echo "backup file is missing: nothing was changed" >&2
  exit 1
fi
exec 3< "$backup_file"
backup_source="/proc/self/fd/3"
if [ ! -s "$backup_source" ]; then
  echo "backup file is empty: nothing was changed" >&2
  exit 1
fi

if ! archive_listing="$(compose exec -T "$service" pg_restore -l < "$backup_source")"; then
  echo "backup file is not a valid pg_dump archive: nothing was changed" >&2
  exit 1
fi
recorded_database="$(sed -n 's/^; *dbname: //p' <<<"$archive_listing" | head -n 1)"
echo "database recorded in the backup: ${recorded_database:-unknown}"
if [ "$recorded_database" != "$database" ] && [ -z "$allow_mismatch" ]; then
  echo "the backup was taken from another database: pass --allow-database-mismatch to restore it anyway; nothing was changed" >&2
  exit 1
fi

if [ -z "$confirmation" ]; then
  read -r -p "retype the database name to confirm: " confirmation || confirmation=""
fi
if [ "$confirmation" != "$database" ]; then
  echo "confirmation does not match the database name: nothing was changed" >&2
  exit 1
fi

dashboard_was_running=""
dashboard_stopped=""
temporary_created=""
database_state="original kept"

finish() {
  exit_status=$?
  trap - EXIT
  if [ -n "$temporary_created" ] && [ "$database_state" = "original kept" ]; then
    admin_sql "DROP DATABASE IF EXISTS \"$temporary_database\" WITH (FORCE)" >/dev/null 2>&1 || true
  fi
  if [ "$exit_status" -ne 0 ]; then
    echo "restore failed, database state: $database_state" >&2
    if [ -n "$temporary_created" ] && [ "$database_state" != "original kept" ]; then
      echo "database $temporary_database holds the restored data and was kept" >&2
    fi
  fi
  if [ -n "$dashboard_stopped" ] && [ -n "$dashboard_was_running" ]; then
    if [ "$exit_status" -eq 0 ] || [ "$database_state" = "original kept" ]; then
      compose start "$dashboard_service" || echo "dashboard could not be restarted" >&2
    else
      echo "dashboard left stopped, database state: $database_state" >&2
    fi
  fi
  exit "$exit_status"
}

admin_sql() {
  compose exec -T "$service" sh -c 'psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d postgres -c "$1"' sh "$1"
}

trap finish EXIT

if compose ps --status running --services | grep -qx "$dashboard_service"; then
  dashboard_was_running=1
fi
dashboard_stopped=1
compose stop "$dashboard_service"

temporary_created=1
admin_sql "CREATE DATABASE \"$temporary_database\""
compose exec -T "$service" sh -c 'pg_restore --no-owner --exit-on-error -U "${POSTGRES_USER:-postgres}" -d "$1"' sh "$temporary_database" < "$backup_source"

database_state="unknown"
compose exec -T "$service" sh -c 'psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d postgres' <<SQL
DROP DATABASE IF EXISTS "$database" WITH (FORCE);
ALTER DATABASE "$temporary_database" RENAME TO "$database";
SQL
temporary_created=""
database_state="replaced"
echo "restored $database from $backup_file"
