#!/usr/bin/env bash
# shellcheck disable=SC2154  # variables and helpers come from spike.sh / spike-lib.sh
# Probes (g) and (e): the dashboard login flow against another engine, and `crowdsec -t`.
# Sourced by spike.sh after spike-lib.sh.

# login_status ENGINE USER_AGENT PASSWORD: HTTP status of POST /v1/watchers/login.
login_status() {
  local payload
  payload="$(jq -nc --arg id "$machine_id" --arg pw "$3" '{machine_id:$id,password:$pw,scenarios:[]}')"
  printf '%s' "$payload" | docker exec -i "$curl_container" curl -sS -m 20 -A "$2" \
    -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' --data-binary @- \
    "http://${engine_host[$1]}:8080/v1/watchers/login"
}

# (g) same flow as backend/internal/lapi/client.go, from the other engine's network.
probe_g_cross_engine_login() {
  local engine user_agent_value
  for engine in local peer; do
    emit_note g "login_${engine}_default_ua" "$(jq -nc --arg status "$(login_status "$engine" "$user_agent" "$machine_password")" '{user_agent:"dashboard-spike/0.1",status:($status|tonumber)}')"
  done
  for user_agent_value in 'Go-http-client/1.1' 'Wget' 'curl' ''; do
    emit_note g login_peer_user_agent "$(jq -nc --arg ua "$user_agent_value" --arg status "$(login_status peer "$user_agent_value" "$machine_password")" '{user_agent:$ua,status:($status|tonumber)}')"
  done
  emit_note g login_peer_wrong_password "$(jq -nc --arg status "$(login_status peer "$user_agent" wrong-password)" '{status:($status|tonumber)}')"

  # Real cross-engine call: the LOCAL engine container (busybox wget, the only HTTP
  # client in the image) logs into peer-a and lists its alerts with the peer JWT.
  local output
  output="$(docker exec -e MACHINE_ID="$machine_id" -e MACHINE_PASSWORD="$machine_password" "$local_container" sh -c '
    body="{\"machine_id\":\"$MACHINE_ID\",\"password\":\"$MACHINE_PASSWORD\",\"scenarios\":[]}"
    token=$(wget -U crowdsec/spike -qO- --header "Content-Type: application/json" --post-data "$body" \
      http://peer-a:8080/v1/watchers/login | sed -n "s/.*\"token\":\"\([^\"]*\)\".*/\1/p")
    echo "login_token_length=${#token}"
    wget -U crowdsec/spike -qO- --header "Authorization: Bearer $token" \
      "http://peer-a:8080/v1/alerts?has_active_decision=true&limit=5" | head -c 400' 2>&1 || true)"
  emit_note g from_local_engine_container "$(jq -nc --arg out "$output" '{via:"busybox wget in the local engine container",output:$out}')"

  call peer GET '/v1/alerts?has_active_decision=true&decision_type=ban&origin=crowdsec&limit=5000'
  emit g peer_read_with_sync_query 'GET http://peer-a:8080/v1/alerts?has_active_decision=true&decision_type=ban&origin=crowdsec&limit=5000' '[.[]|{id,scenario,machine_id}]'
}

# config_test LABEL SHELL_SNIPPET: runs the snippet in the local engine container, with
# exit code and duration. The snippet must restore anything it changes.
config_test() {
  local label="$1" snippet="$2" started_ns finished_ns exit_code=0 output
  started_ns="$(date +%s%N)"
  output="$(docker exec "$local_container" sh -c "$snippet" 2>&1)" || exit_code=$?
  finished_ns="$(date +%s%N)"
  emit_note e "$label" "$(jq -nc --arg cmd "$snippet" --argjson code "$exit_code" \
    --argjson ms "$(((finished_ns - started_ns) / 1000000))" --arg out "$output" \
    '{command:$cmd,exit_code:$code,duration_ms:$ms,output_tail:($out|split("\n")|.[-6:]|join("\n"))}')"
}

# (e) `crowdsec -t` on the real image: what it validates and which exit codes it gives.
probe_e_config_test() {
  local acquis=/etc/crowdsec/acquis.d/x.yaml profiles=/etc/crowdsec/profiles.yaml
  config_test valid_no_flag 'crowdsec -t'
  config_test valid_with_config 'crowdsec -t -c /etc/crowdsec/config.yaml'
  config_test acquis_malformed_yaml "mkdir -p /etc/crowdsec/acquis.d; printf 'source: file\nfilenames: [unterminated\n' > $acquis; crowdsec -t; rc=\$?; rm -f $acquis; exit \$rc"
  config_test acquis_unknown_datasource "mkdir -p /etc/crowdsec/acquis.d; printf 'source: nonexistent\nlabels:\n  type: syslog\n' > $acquis; crowdsec -t; rc=\$?; rm -f $acquis; exit \$rc"
  config_test acquis_file_without_filenames "mkdir -p /etc/crowdsec/acquis.d; printf 'source: file\nlabels:\n  type: syslog\n' > $acquis; crowdsec -t; rc=\$?; rm -f $acquis; exit \$rc"
  config_test profiles_malformed_yaml "cp $profiles /tmp/profiles.bak; printf 'name: [oops\n' > $profiles; crowdsec -t; rc=\$?; cp /tmp/profiles.bak $profiles; exit \$rc"
  config_test profiles_invalid_filter_expression "cp $profiles /tmp/profiles.bak; printf 'name: broken\nfilters:\n - \"Alert.Nope(\"\ndecisions:\n - type: ban\n   duration: 4h\non_success: break\n' > $profiles; crowdsec -t; rc=\$?; cp /tmp/profiles.bak $profiles; exit \$rc"
  config_test profiles_unknown_notification "cp $profiles /tmp/profiles.bak; printf 'name: broken\nfilters:\n - \"true\"\ndecisions:\n - type: ban\n   duration: 4h\nnotifications:\n - does_not_exist\non_success: break\n' > $profiles; crowdsec -t; rc=\$?; cp /tmp/profiles.bak $profiles; exit \$rc"
  config_test valid_after_restore 'crowdsec -t'
}
