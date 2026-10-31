#!/usr/bin/env bash
# Proves what the socket proxy allows for the dashboard: only the three exec calls on the
# CrowdSec container. Everything else must answer 403. Needs ./up.sh to have run.
set -euo pipefail

cd "$(dirname "$0")"
compose() {
  docker compose -p csdash-dev --env-file .env.local "$@"
}

compose --profile probe up -d probe >/dev/null
trap 'compose --profile probe rm -sf probe >/dev/null' EXIT

proxy=http://socket-proxy:2375
failures=0

status_of() {
  docker exec csdash-dev-probe curl -s -o /dev/null -w '%{http_code}' "$@"
}

expect() {
  local expected="$1" label="$2"
  shift 2
  local actual
  actual="$(status_of "$@")"
  if [ "$actual" = "$expected" ]; then
    echo "ok    $actual  $label"
  else
    echo "FAIL  $actual (wanted $expected)  $label"
    failures=$((failures + 1))
  fi
}

expect 403 "GET /containers/json" "$proxy/containers/json"
expect 403 "GET /v1.50/containers/json" "$proxy/v1.50/containers/json"
expect 403 "GET /version" "$proxy/version"
expect 403 "GET /images/json" "$proxy/images/json"
expect 403 "GET /containers/csdash-dev-crowdsec/json" "$proxy/containers/csdash-dev-crowdsec/json"
expect 403 "POST /containers/create" -X POST -H 'Content-Type: application/json' -d '{}' "$proxy/containers/create"
expect 403 "POST exec on another container" -X POST -H 'Content-Type: application/json' -d '{}' "$proxy/containers/csdash-dev-socket-proxy/exec"
expect 405 "DELETE /containers/csdash-dev-crowdsec (method not enabled at all)" -X DELETE "$proxy/containers/csdash-dev-crowdsec"
expect 403 "POST /containers/csdash-dev-crowdsec/stop" -X POST "$proxy/containers/csdash-dev-crowdsec/stop"
expect 403 "POST /containers/csdash-dev-crowdsec/exec/extra" -X POST "$proxy/containers/csdash-dev-crowdsec/exec/extra"
expect 403 "GET exec inspect with short id" "$proxy/exec/abc/json"
expect 404 "GET exec inspect, well-formed unknown id (allowed, reaches Docker)" "$proxy/exec/0000000000000000000000000000000000000000000000000000000000000000/json"
expect 201 "POST exec create on the CrowdSec container (allowed)" -X POST -H 'Content-Type: application/json' -d '{"Cmd":["cscli","version"],"AttachStdout":true}' "$proxy/containers/csdash-dev-crowdsec/exec"

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed"
  exit 1
fi
