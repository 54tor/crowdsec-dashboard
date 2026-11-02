#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 -p <compose-project> -s <postgres-service> -d <database> [-w <dashboard-service>] [--confirm <database>] <backup-file>" >&2
  exit 2
}

project=""
service=""
database=""
dashboard_service="dashboard"
confirmation=""
while [ $# -gt 0 ]; do
  case "$1" in
    -p) project="${2:-}"; shift 2 ;;
    -s) service="${2:-}"; shift 2 ;;
    -d) database="${2:-}"; shift 2 ;;
    -w) dashboard_service="${2:-}"; shift 2 ;;
    --confirm) confirmation="${2:-}"; shift 2 ;;
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

compose() {
  docker compose -p "$project" "$@"
}

configuration="$(compose config --format json)"
effective_project="$(jq -r '.name' <<<"$configuration")"
if ! jq -e --arg service "$service" '.services[$service]' <<<"$configuration" >/dev/null; then
  echo "service $service is not defined in compose project $project" >&2
  exit 1
fi
if [ "$effective_project" != "$project" ]; then
  echo "compose project mismatch: $effective_project" >&2
  exit 1
fi

echo "docker compose project: $effective_project"
echo "postgres service:       $service"
echo "database to be replaced: $database"

if [ ! -f "$backup_file" ] || [ ! -s "$backup_file" ]; then
  echo "backup file is missing or empty: nothing was changed" >&2
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
if compose ps --status running --services | grep -qx "$dashboard_service"; then
  dashboard_was_running=1
  compose stop "$dashboard_service"
fi

admin_sql() {
  compose exec -T "$service" sh -c 'psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d postgres -c "$1"' sh "$1"
}

admin_sql "DROP DATABASE IF EXISTS \"$database\" WITH (FORCE)"
admin_sql "CREATE DATABASE \"$database\""
compose exec -T "$service" sh -c 'pg_restore --no-owner --exit-on-error -U "${POSTGRES_USER:-postgres}" -d "$1"' sh "$database" < "$backup_file"

if [ -n "$dashboard_was_running" ]; then
  compose start "$dashboard_service"
fi
echo "restored $database from $backup_file"
