#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 -p <compose-project> -s <postgres-service> -d <database> -o <output-directory>" >&2
  exit 2
}

project=""
service=""
database=""
output_directory=""
while getopts "p:s:d:o:" option; do
  case "$option" in
    p) project="$OPTARG" ;;
    s) service="$OPTARG" ;;
    d) database="$OPTARG" ;;
    o) output_directory="$OPTARG" ;;
    *) usage ;;
  esac
done
if [ -z "$project" ] || [ -z "$service" ] || [ -z "$database" ] || [ -z "$output_directory" ]; then
  usage
fi
if ! [[ "$database" =~ ^[A-Za-z0-9_]+$ ]]; then
  echo "invalid database name" >&2
  exit 2
fi

umask 077
mkdir -p "$output_directory"
cd "$output_directory"
backup_name="$database-$(date -u +%Y%m%dT%H%M%SZ).dump"

if ! docker compose -p "$project" exec -T "$service" sh -c 'pg_dump -Fc -U "${POSTGRES_USER:-postgres}" -d "$1"' sh "$database" > "./$backup_name"; then
  rm -f -- "./$backup_name"
  echo "backup failed" >&2
  exit 1
fi
if [ ! -s "./$backup_name" ]; then
  rm -f -- "./$backup_name"
  echo "backup is empty" >&2
  exit 1
fi
chmod 0600 "./$backup_name"
echo "$PWD/$backup_name"
