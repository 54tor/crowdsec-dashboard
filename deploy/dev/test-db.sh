#!/usr/bin/env bash
# Disposable PostgreSQL for the Go store tests (compose project csdash-test-db).
#   ./test-db.sh up     starts it on 127.0.0.1 (random free port) and prints TEST_DATABASE_URL
#   ./test-db.sh down   stops it and removes its volumes
set -euo pipefail

project=csdash-test-db
password=test

compose() {
  docker compose -p "$project" -f - "$@" <<COMPOSE
services:
  postgres:
    image: postgres:latest
    environment:
      POSTGRES_PASSWORD: $password
      POSTGRES_DB: csdash_test
    ports:
      - "127.0.0.1::5432"
    tmpfs:
      - /var/lib/postgresql
    mem_limit: 256m
COMPOSE
}

case "${1:-}" in
  up)
    compose up -d --wait
    mapping="$(compose port postgres 5432)"
    echo "TEST_DATABASE_URL=postgres://postgres:${password}@127.0.0.1:${mapping##*:}/csdash_test?sslmode=disable"
    ;;
  down)
    compose down -v
    ;;
  *)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
