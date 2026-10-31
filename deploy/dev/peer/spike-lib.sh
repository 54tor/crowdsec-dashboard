#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154  # variables are shared with spike.sh and the probe files
# Helpers shared by spike.sh and the probe-*.sh files. Sourced, never run directly.
# DISPOSABLE development tooling: talks only to the csdash-dev compose project.

project=csdash-dev
local_container=csdash-dev-crowdsec
peer_container=csdash-dev-peer-a
curl_container=csdash-dev-spike-curl
machine_id=dashboard-spike
user_agent=dashboard-spike/0.1

# Hosts as seen from the internal network (compose service names).
declare -A engine_host=([local]=crowdsec [peer]=peer-a)
declare -A engine_container=([local]="$local_container" [peer]="$peer_container")
declare -A engine_token=()

# Last response of call(): status code and raw body.
http_status=""
http_body=""

# RFC 3339 UTC timestamp, optionally shifted: now_utc "2 hours ago".
now_utc() {
  date -u -d "${1:-now}" +%Y-%m-%dT%H:%M:%SZ
}

# call ENGINE METHOD PATH [BODY]: authenticated LAPI request from the throwaway curl
# container. The body travels on stdin (the container filesystem is read-only).
call() {
  local engine="$1" method="$2" path="$3" body="${4:-}"
  local url="http://${engine_host[$engine]}:8080${path}"
  local output
  output="$(printf '%s' "$body" | docker exec -i "$curl_container" curl -sS -m 60 \
    -A "$user_agent" -X "$method" -w '\n%{http_code}' \
    -H "Authorization: Bearer ${engine_token[$engine]:-}" -H 'Content-Type: application/json' \
    --data-binary @- "$url")"
  http_status="${output##*$'\n'}"
  http_body="${output%$'\n'*}"
}

# login ENGINE: same flow as backend/internal/lapi/client.go (machine_id + password -> JWT).
login() {
  local engine="$1"
  local payload
  payload="$(jq -nc --arg id "$machine_id" --arg pw "$machine_password" \
    '{machine_id:$id,password:$pw,scenarios:[]}')"
  local output
  output="$(printf '%s' "$payload" | docker exec -i "$curl_container" curl -sS -m 20 \
    -A "$user_agent" -w '\n%{http_code}' -H 'Content-Type: application/json' \
    --data-binary @- "http://${engine_host[$engine]}:8080/v1/watchers/login")"
  [ "${output##*$'\n'}" = 200 ] || { echo "login failed on $engine: ${output##*$'\n'}" >&2; return 1; }
  engine_token[$engine]="$(printf '%s' "${output%$'\n'*}" | jq -r .token)"
}

# emit PROBE STEP REQUEST [JQ_FILTER]: one JSON line with the last call() response.
# The filter (default: whole body) shapes the "result" field.
emit() {
  local probe="$1" step="$2" request="$3" filter="${4:-.}"
  local result
  result="$(printf '%s' "$http_body" | jq -c "$filter" 2>/dev/null || true)"
  [ -n "$result" ] || result="$(jq -nc --arg raw "$http_body" '$raw')"
  jq -nc --arg probe "$probe" --arg step "$step" --arg request "$request" \
    --arg status "$http_status" --argjson result "$result" \
    '{probe:$probe,step:$step,request:$request,status:($status|tonumber),result:$result}'
}

# emit_note PROBE STEP JSON_VALUE: a line that is not an HTTP response.
emit_note() {
  jq -nc --arg probe "$1" --arg step "$2" --argjson result "$3" \
    '{probe:$probe,step:$step,result:$result}'
}

# alert_payload SCENARIO SCOPE VALUE START STOP SIMULATED DECISIONS_JSON [UUID] [EXTRA_JSON]
# One-element alert array in the shape the dashboard pushes (see AddDecision).
alert_payload() {
  local extra_json="${9:-}"
  [ -n "$extra_json" ] || extra_json='{}'
  jq -nc --arg scenario "$1" --arg scope "$2" --arg value "$3" --arg start "$4" \
    --arg stop "$5" --argjson simulated "$6" --argjson decisions "$7" --arg uuid "${8:-}" --argjson extra "$extra_json" '
    [{scenario:$scenario, scenario_hash:"", scenario_version:"", message:"spike",
      capacity:0, events_count:1, leakspeed:"0", simulated:$simulated,
      start_at:$start, stop_at:$stop,
      events:[{timestamp:$start, meta:[{key:"source_ip", value:$value}]}],
      source:({scope:$scope, value:$value}
        + (if $scope == "Ip" then {ip:$value, cn:"ZZ", as_name:"Example Net", as_number:"64496"} else {} end)),
      decisions:$decisions}
     + (if $uuid == "" then {} else {uuid:$uuid} end) + $extra]'
}

# decision_json TYPE DURATION ORIGIN SCENARIO SCOPE VALUE
decision_json() {
  jq -nc --arg type "$1" --arg duration "$2" --arg origin "$3" --arg scenario "$4" \
    --arg scope "$5" --arg value "$6" \
    '{type:$type,duration:$duration,origin:$origin,scenario:$scenario,scope:$scope,value:$value}'
}

# push ENGINE PAYLOAD: POST /v1/alerts and keep the response in http_status/http_body.
push() {
  call "$1" POST /v1/alerts "$2"
}

# wait_lapi ENGINE: block until the LAPI answers /health (the container healthcheck can
# turn green slightly before the API listens).
wait_lapi() {
  local engine="$1" attempt
  for attempt in $(seq 1 60); do
    if docker exec "$curl_container" curl -sf -m 3 -o /dev/null "http://${engine_host[$engine]}:8080/health"; then
      return 0
    fi
    sleep 2
  done
  echo "LAPI of $engine did not come up" >&2
  return 1
}
