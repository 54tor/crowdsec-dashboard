#!/usr/bin/env bash
# DISPOSABLE probe of the CrowdSec LAPI allowlist behaviour. Development only, never run in production.
#
# It starts its OWN throwaway engine (compose project "csdash-lot5-probe": private network, no
# published port, anonymous volumes), then asks the LAPI from inside the container and prints one
# JSON line per observation on stdout (progress on stderr):
#   (a) GET /v1/allowlists?with_content=true with no allowlist, an empty one, then permanent / expired
#       / valid entries; how an expired and a permanent entry are serialised.
#   (b) the 404 bodies of the LAPI itself (unknown allowlist, unknown route) and what a machine
#       token gets on the allowlist routes.
#   (c) POST /v1/alerts by a machine account for an allowlisted IP: alert WITH a ban decision and the
#       same alert WITHOUT a decision; what is stored and what bouncers can see.
#
#   (d) lot 5: cscli allowlists writes (create / add / remove / delete): accepted flag forms, exit
#       codes and messages (unknown name, duplicate, invalid value), expiry of covered decisions.
#   (e) lot 5: hub items (appsec-rules / appsec-configs / collections, `hub list -o json` keys) and a
#       REAL AppSec alert: an appsec acquisition (written inside the container, nothing on the host),
#       two requests hitting two distinct vpatch rules with a bouncer's AppSec headers, then the
#       alerts as the LAPI returns them (scenario, exact meta keys, decision created).
#
# Usage: ./allowlist-probe.sh            run, then tear the probe project down
#        PROBE_KEEP=1 ./allowlist-probe.sh   leave the engine up (tear down by hand with the same project name)
# Only documentation addresses are used (RFC 5737). The machine password is random per run and never
# written to disk. Re-running is safe: a leftover probe project is removed first.
set -euo pipefail

project="csdash-lot5-probe"
container_name="csdash-lot5-probe-crowdsec"
lapi="http://crowdsec:8080"
client_container="csdash-lot5-probe-client"
allowlist_name="probe_allowlist"
unknown_allowlist="probe_unknown_list"
machine_name="dashboard-probe"
machine_password="$(head -c 24 /dev/urandom | base64 | tr -d '/+=\n')"

# The compose file is piped on stdin so nothing is written to disk. Floating tag on purpose.
compose_file() {
  cat <<'YAML'
name: csdash-lot5-probe
services:
  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: csdash-lot5-probe-crowdsec
    restart: "no"
    mem_limit: 768m
    pids_limit: 256
    cpus: 1.0
    environment:
      DISABLE_ONLINE_API: "true"
      # Throwaway engine: the image refuses to start without a mounted data volume otherwise.
      CROWDSEC_BYPASS_DB_VOLUME_CHECK: "true"
  # The crowdsec image ships no curl: a sidecar on the same private network issues the HTTP calls.
  client:
    image: curlimages/curl:latest
    container_name: csdash-lot5-probe-client
    restart: "no"
    entrypoint: ["sleep", "infinity"]
    depends_on:
      - crowdsec
YAML
}

compose() {
  compose_file | docker compose -p "$project" -f - "$@"
}

progress() {
  printf '%s\n' "$*" >&2
}

# Last HTTP result, set by call().
http_status=""
http_content_type=""
http_body=""

# call METHOD PATH [BEARER_TOKEN] [JSON_BODY]: curl run inside the container against the LAPI.
call() {
  local method="$1" path="$2" token="${3:-}" payload="${4:-}"
  local -a curl_args=(-sS -X "$method" -w "$trailer_format" "$lapi$path")
  if [ -n "$token" ]; then
    curl_args+=(-H "Authorization: Bearer $token")
  fi
  if [ -n "$payload" ]; then
    curl_args+=(-H 'Content-Type: application/json' --data-binary "$payload")
  fi
  parse_response "$(docker exec "$client_container" curl "${curl_args[@]}")"
}

# curl appends "<marker>status<marker>content-type<marker>" after the body, so an empty body or an
# absent Content-Type header cannot shift the fields.
trailer_format='\n@@%{http_code}@@%{content_type}@@'

parse_response() {
  local raw="$1" trailer
  trailer="${raw##*$'\n'@@}"
  http_body="${raw%$'\n'@@"$trailer"}"
  http_status="${trailer%%@@*}"
  trailer="${trailer#*@@}"
  http_content_type="${trailer%%@@*}"
}

# emit LABEL REQUEST: one JSON line with the last call; body kept as JSON when it parses, else as text.
emit() {
  jq -cn --arg label "$1" --arg request "$2" --arg status "$http_status" \
    --arg content_type "$http_content_type" --arg body "$http_body" \
    '{label: $label, request: $request, status: ($status | tonumber), content_type: $content_type,
      body: ($body | try fromjson catch $body)}'
}

emit_note() {
  jq -cn --arg label "$1" --arg name "$2" --arg value "$3" \
    '{label: $label, name: $name, value: ($value | try fromjson catch $value)}'
}

cscli() {
  docker exec "$container_name" cscli "$@"
}

login_machine() {
  local login_payload
  login_payload="$(jq -cn --arg machine_id "$machine_name" --arg password "$machine_password" \
    '{machine_id: $machine_id, password: $password, scenarios: []}')"
  call POST /v1/watchers/login "" "$login_payload"
  machine_token="$(printf '%s' "$http_body" | jq -r '.token')"
  http_body="$(printf '%s' "$http_body" | jq -c '.token = "<jwt>"')"
  emit auth login_machine "POST /v1/watchers/login"
}

# alert_json DECISIONS_JSON: one alert for the allowlisted IP, DECISIONS_JSON is an array.
alert_json() {
  local decisions="$1" scenario="$2" now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  jq -cn --argjson decisions "$decisions" --arg scenario "$scenario" --arg now "$now" '[{
    scenario: $scenario, scenario_hash: "", scenario_version: "", message: "allowlist probe",
    events_count: 1, start_at: $now, stop_at: $now, capacity: 0, leakspeed: "0", simulated: false,
    source: {scope: "Ip", value: "203.0.113.50", ip: "203.0.113.50"},
    events: [{timestamp: $now, meta: [{key: "source_ip", value: "203.0.113.50"}]}],
    decisions: $decisions
  }]'
}

ban_decision() {
  jq -cn '[{type: "ban", scope: "Ip", value: "203.0.113.50", duration: "1h", origin: "crowdsec",
            scenario: "probe/allowlisted", simulated: false}]'
}

probe_a_allowlists() {
  call GET '/v1/allowlists?with_content=true' "$machine_token"
  emit a no_allowlist_machine_token "GET /v1/allowlists?with_content=true (no allowlist exists, machine token)"
  cscli allowlists create "$allowlist_name" -d 'allowlist probe' >&2
  call GET '/v1/allowlists?with_content=true' "$machine_token"
  emit a empty_allowlist_machine_token "GET /v1/allowlists?with_content=true (one empty allowlist)"
  cscli allowlists add "$allowlist_name" 203.0.113.50 -d permanent >&2
  cscli allowlists add "$allowlist_name" 203.0.113.51 -d expired -e 2s >&2
  cscli allowlists add "$allowlist_name" 203.0.113.52 -d valid_one_hour -e 1h >&2
  sleep 4
  call GET '/v1/allowlists?with_content=true' "$machine_token"
  emit a three_entries_machine_token "GET /v1/allowlists?with_content=true (permanent, expired, valid 1h)"
  call GET '/v1/allowlists' "$machine_token"
  emit a without_content_machine_token "GET /v1/allowlists (no with_content)"
  call GET "/v1/allowlists/$allowlist_name?with_content=true" "$machine_token"
  emit a single_allowlist_machine_token "GET /v1/allowlists/$allowlist_name?with_content=true"
  emit_note a cscli_view "$(cscli allowlists inspect "$allowlist_name" -o json 2>&1 || true)"
}

probe_b_not_found() {
  call GET "/v1/allowlists/$unknown_allowlist" "$machine_token"
  emit b unknown_allowlist_machine_token "GET /v1/allowlists/$unknown_allowlist"
  call GET "/v1/allowlists/$unknown_allowlist?with_content=true" "$machine_token"
  emit b unknown_allowlist_with_content "GET /v1/allowlists/$unknown_allowlist?with_content=true"
  call GET /v1/nexistepas "$machine_token"
  emit b unknown_route_machine_token "GET /v1/nexistepas"
  call GET /v1/nexistepas ""
  emit b unknown_route_no_token "GET /v1/nexistepas (no token)"
  call GET '/v1/allowlists?with_content=true' ""
  emit b allowlists_no_token "GET /v1/allowlists?with_content=true (no token)"
  call GET '/v1/allowlists?with_content=true' "not.a.token"
  emit b allowlists_bad_token "GET /v1/allowlists?with_content=true (invalid token)"
  call GET /nexistepas ""
  emit b unknown_route_outside_v1 "GET /nexistepas"
}

probe_c_alerts() {
  call POST /v1/alerts "$machine_token" "$(alert_json "$(ban_decision)" probe/allowlisted)"
  emit c post_alert_with_ban_decision "POST /v1/alerts (ban decision on allowlisted 203.0.113.50)"
  call POST /v1/alerts "$machine_token" "$(alert_json '[]' probe/allowlisted-nodecision)"
  emit c post_alert_without_decision "POST /v1/alerts (same IP, no decision)"
  call GET '/v1/alerts?limit=50' "$machine_token"
  emit c list_alerts_machine "GET /v1/alerts?limit=50 (machine token)"
  call GET '/v1/alerts?scenario=probe/allowlisted-nodecision' "$machine_token"
  emit c list_alert_without_decision "GET /v1/alerts?scenario=probe/allowlisted-nodecision"
  emit_note c cscli_decisions "$(cscli decisions list -o json 2>&1 || true)"
  emit_note c cscli_alerts "$(cscli alerts list -o json 2>&1 || true)"
  emit_note c cscli_decisions_ip "$(cscli decisions list --ip 203.0.113.50 -o json 2>&1 || true)"
  local bouncer_key
  bouncer_key="$(cscli bouncers add allowlist-probe-bouncer -o raw)"
  call_bouncer GET '/v1/decisions?ip=203.0.113.50' "$bouncer_key"
  emit c bouncer_decisions_ip "GET /v1/decisions?ip=203.0.113.50 (bouncer API key)"
  call_bouncer GET '/v1/decisions/stream?startup=true' "$bouncer_key"
  emit c bouncer_decisions_stream "GET /v1/decisions/stream?startup=true (bouncer API key)"
  call_bouncer GET '/v1/allowlists?with_content=true' "$bouncer_key"
  emit b allowlists_bouncer_key "GET /v1/allowlists?with_content=true (bouncer API key)"
}

call_bouncer() {
  local method="$1" path="$2" key="$3"
  parse_response "$(docker exec "$client_container" curl -sS -X "$method" -H "X-Api-Key: $key" \
    -w "$trailer_format" "$lapi$path")"
}

wait_for_lapi() {
  local attempt
  for attempt in $(seq 1 60); do
    local ready_status
    ready_status="$(docker exec "$client_container" curl -s -o /dev/null -w '%{http_code}' "$lapi/v1/heartbeat" 2>/dev/null || true)"
    if [ "$ready_status" != "000" ] && [ -n "$ready_status" ]; then
      return 0
    fi
    sleep 2
  done
  progress "LAPI did not become ready"
  return 1
}

teardown_probe() {
  compose down -v --remove-orphans >&2 || true
}

# emit_cscli NAME CSCLI_ARGS...: run a cscli command, print one JSON line with its exit code and merged output.
emit_cscli() {
  local label="$1" exit_code=0 output
  shift
  output="$(cscli "$@" 2>&1)" || exit_code=$?
  jq -cn --arg label "d" --arg name "$label" --arg command "cscli $*" --argjson exit_code "$exit_code" \
    --arg output "$output" \
    '{label: $label, name: $name, command: $command, exit_code: $exit_code,
      output: ($output | try fromjson catch $output)}'
}

probe_d_cscli_writes() {
  local list="probe_write_list"
  emit_cscli create_equals_form allowlists create "$list" --description=probe_description
  emit_cscli create_duplicate allowlists create "$list" -d again
  emit_cscli add_equals_forms allowlists add "$list" 203.0.113.60 --comment=probe_comment --expiration=12h
  emit_cscli add_days_expiration allowlists add "$list" 203.0.113.61 -e 7d -d seven_days
  emit_cscli add_duplicate_value allowlists add "$list" 203.0.113.60
  emit_cscli add_invalid_value allowlists add "$list" not-an-address
  emit_cscli add_cidr_value allowlists add "$list" 198.51.100.0/24 -d range
  emit_cscli add_unknown_allowlist allowlists add probe_unknown_list 203.0.113.62
  emit_cscli remove_missing_value allowlists remove "$list" 203.0.113.99
  emit_cscli remove_unknown_allowlist allowlists remove probe_unknown_list 203.0.113.60
  emit_cscli delete_unknown_allowlist allowlists delete probe_unknown_list
  cscli decisions add -i 203.0.113.70 -d 2h >&2
  emit_cscli add_covering_active_decision allowlists add "$list" 203.0.113.70 -d covers_decision
  emit_cscli decisions_after_add decisions list -o json
  emit_cscli inspect_json allowlists inspect "$list" -o json
  emit_cscli remove_existing_value allowlists remove "$list" 203.0.113.70
  emit_cscli delete_existing allowlists delete "$list"
  emit_cscli delete_twice allowlists delete "$list"
}

install_appsec_hub_items() {
  emit_cscli appsec_rules_install_collection_item appsec-rules install crowdsecurity/appsec-virtual-patching
  emit_cscli appsec_configs_install_collection_item appsec-configs install crowdsecurity/appsec-virtual-patching
  emit_cscli waf_rules_alias_help waf-rules --help
  emit_cscli collection_install_virtual_patching collections install crowdsecurity/appsec-virtual-patching
  emit_cscli collection_install_generic_rules collections install crowdsecurity/appsec-generic-rules
  emit_cscli appsec_rules_remove_owned_by_collection appsec-rules remove crowdsecurity/vpatch-env-access
  emit_cscli appsec_rules_remove_unknown appsec-rules remove probe/unknown
  emit_cscli appsec_configs_remove_unknown appsec-configs remove probe/unknown
  emit_note d hub_list_keys "$(cscli hub list -o json 2>/dev/null | jq -c 'keys')"
  emit_note d hub_list_appsec_configs "$(cscli hub list -o json 2>/dev/null | jq -c '."appsec-configs"')"
  emit_note d hub_list_appsec_rules_sample "$(cscli hub list -o json 2>/dev/null | jq -c '."appsec-rules"[0:2]')"
  emit_note d hub_list_collections "$(cscli hub list -o json 2>/dev/null | jq -c '.collections')"
  emit_note d appsec_rules_list "$(cscli appsec-rules list -o json 2>/dev/null | jq -c '."appsec-rules"[0:2]')"
}

# The appsec acquisition is written inside the container (stdin, nothing on the host). The hub items
# the config references must be installed BEFORE it exists: a missing rule pattern is fatal at boot.
enable_appsec_acquisition() {
  docker exec -i "$container_name" sh -c 'cat > /etc/crowdsec/acquis.d/appsec.yaml' <<'ACQUIS'
source: appsec
listen_addr: 0.0.0.0:7422
path: /
appsec_configs:
  - crowdsecurity/appsec-default
labels:
  type: appsec
ACQUIS
  docker restart "$container_name" >&2
  wait_for_lapi
  wait_for_appsec
}

wait_for_appsec() {
  local attempt appsec_status
  for attempt in $(seq 1 60); do
    appsec_status="$(docker exec "$client_container" curl -s -o /dev/null -w '%{http_code}' http://crowdsec:7422/ 2>/dev/null || true)"
    if [ "$appsec_status" != "000" ] && [ -n "$appsec_status" ]; then
      return 0
    fi
    sleep 2
  done
  progress "AppSec listener did not become ready"
  return 1
}

# send_appsec_request KEY URI: mimics a bouncer forwarding one request (AppSec headers).
send_appsec_request() {
  local key="$1" request_uri="$2"
  http_body="$(docker exec "$client_container" curl -sS -w ' http_status=%{http_code}' http://crowdsec:7422/ \
    -H "X-Crowdsec-Appsec-Api-Key: $key" -H "X-Crowdsec-Appsec-Ip: 198.51.100.10" \
    -H "X-Crowdsec-Appsec-Uri: $request_uri" -H "X-Crowdsec-Appsec-Host: www.example.com" \
    -H "X-Crowdsec-Appsec-Verb: GET" -H "X-Crowdsec-Appsec-User-Agent: probe-agent/1.0")"
  jq -cn --arg label "e" --arg request "$request_uri" --arg body "$http_body" \
    '{label: $label, name: "appsec_response", request: $request, body: $body}'
}

probe_e_appsec() {
  install_appsec_hub_items
  enable_appsec_acquisition
  login_machine
  local bouncer_key
  bouncer_key="$(cscli bouncers add appsec-probe-bouncer -o raw)"
  send_appsec_request "$bouncer_key" /app/.env
  send_appsec_request "$bouncer_key" /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
  sleep 5
  call GET '/v1/alerts?limit=50' "$machine_token"
  emit e appsec_alerts "GET /v1/alerts?limit=50 (machine token, after two vpatch requests)"
  emit_cscli appsec_metrics metrics show appsec
}

main() {
  if [ "${PROBE_KEEP:-0}" != "1" ]; then
    trap teardown_probe EXIT
  fi
  # Idempotent: drop a leftover probe project (literal name, never a variable-built target elsewhere).
  compose down -v --remove-orphans >&2 || true
  progress "starting $project"
  compose up -d >&2
  wait_for_lapi
  emit_note env version "$(cscli version 2>&1 | tr '\n' ' ')"
  emit_note env image "$(docker inspect --format '{{.Config.Image}} {{.Image}}' "$container_name")"
  cscli machines add "$machine_name" --password "$machine_password" -f /dev/null --force >&2
  login_machine
  probe_a_allowlists
  probe_b_not_found
  probe_c_alerts
  probe_d_cscli_writes
  probe_e_appsec
}

main "$@"
