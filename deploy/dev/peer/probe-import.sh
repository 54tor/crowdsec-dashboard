#!/usr/bin/env bash
# shellcheck disable=SC2154  # variables and helpers come from spike.sh / spike-lib.sh
# Probe (d): re-importing alerts as simulated, with a profile that bans on any alert and a
# low flush.max_items (peer-a), plus the effect of the DEFAULT profile on the local engine.
# Sourced by spike.sh after spike-lib.sh.

# decision_count ENGINE: active decisions as counted by cscli inside the engine container.
decision_count() {
  docker exec "${engine_container[$1]}" cscli decisions list -o json 2>/dev/null | jq '[.[]?.decisions[]?] | length'
}

# alert_count ENGINE: alerts as listed by the LAPI with a huge limit.
alert_count() {
  call "$1" GET '/v1/alerts?limit=100000'
  printf '%s' "$http_body" | jq 'if type == "array" then length else -1 end' 2>/dev/null || echo -1
}

# import_variant LABEL IP SIMULATED DECISIONS_JSON EXTRA_JSON UUID: push one alert with fixed
# uuid / start_at / stop_at on peer-a, then show what came back and the decision count delta.
import_variant() {
  local label="$1" ip="$2" simulated="$3" decisions="$4" extra="$5" uuid="$6"
  local before after
  before="$(decision_count peer)"
  push peer "$(alert_payload spike/imported Ip "$ip" 2026-10-30T10:00:00Z 2026-10-30T10:05:00Z "$simulated" "$decisions" "$uuid" "$extra")"
  emit d "${label}_push" "POST /v1/alerts (simulated=${simulated}, extra=${extra}, decisions=${decisions}, uuid=${uuid}, start_at=2026-10-30T10:00:00Z, stop_at=2026-10-30T10:05:00Z)"
  after="$(decision_count peer)"
  call peer GET "/v1/alerts?ip=${ip}"
  emit d "${label}_stored" "GET /v1/alerts?ip=${ip} (decisions before=${before}, after=${after})" \
    '[.[]|{id,uuid,simulated,start_at,stop_at,created_at,events_count,events,labels,machine_id,decisions:[.decisions[]?|{id,origin,type,value,duration,scenario,simulated}]}]'
  emit_note d "${label}_decision_delta" "$(jq -nc --argjson before "$before" --argjson after "$after" '{before:$before,after:$after,created:($after-$before)}')"
}

# (d) alert import without remediation effect, flush behaviour with a low max_items.
probe_d_alert_import() {
  emit_note d profile_in_effect "$(jq -nc --arg profile "$(docker exec "$peer_container" cat /etc/crowdsec/profiles.yaml)" '{peer_a_profiles_yaml:$profile}')"
  emit_note d flush_config_in_effect "$(jq -nc --arg flush "$(docker exec "$peer_container" cscli config show --key Config.DbConfig.Flush 2>&1)" '{peer_a_flush:$flush}')"

  import_variant control_not_simulated_no_decision 203.0.113.20 false '[]' '{}' 00000000-0000-4000-8000-000000000020
  import_variant simulated_no_decision 203.0.113.21 true '[]' '{}' 00000000-0000-4000-8000-000000000021
  import_variant simulated_remediation_false 203.0.113.22 true '[]' '{"remediation":false}' 00000000-0000-4000-8000-000000000022
  import_variant not_simulated_remediation_false 203.0.113.23 false '[]' '{"remediation":false}' 00000000-0000-4000-8000-000000000023
  import_variant simulated_remediation_true 203.0.113.24 true '[]' '{"remediation":true}' 00000000-0000-4000-8000-000000000024
  import_variant not_simulated_with_decision 203.0.113.25 false "[$(decision_json ban 1h cscli manual/dashboard Ip 203.0.113.25)]" '{}' 00000000-0000-4000-8000-000000000025
  import_variant simulated_with_decision 203.0.113.26 true "[$(decision_json ban 1h cscli manual/dashboard Ip 203.0.113.26)]" '{}' 00000000-0000-4000-8000-000000000026

  call peer POST /v1/alerts "$(alert_payload spike/imported Ip 203.0.113.21 2026-10-30T10:00:00Z 2026-10-30T10:05:00Z true '[]' 00000000-0000-4000-8000-000000000021)"
  emit d duplicate_uuid_push 'POST /v1/alerts (same uuid as simulated_no_decision again)'
  call peer GET '/v1/alerts?ip=203.0.113.21'
  emit d duplicate_uuid_stored 'GET /v1/alerts?ip=203.0.113.21 (how many alerts with that uuid?)' '[.[]|{id,uuid}]'

  probe_d_neutralised_import
  probe_d_event_and_label_roundtrip
  probe_d_default_profile
  probe_d_bouncer_visibility
  probe_d_flush_low_max_items
}

# Alert dated in the past carrying one already-expired decision: the profile is skipped
# (it only runs on alerts without decisions) and no active decision appears.
probe_d_neutralised_import() {
  local before after
  before="$(decision_count peer)"
  push peer "$(alert_payload spike/neutral Ip 203.0.113.40 "$(now_utc '1 day ago')" "$(now_utc '23 hours ago')" true "[$(decision_json ban 1s cscli spike/neutral Ip 203.0.113.40)]" '' '{"remediation":false}')"
  emit d neutral_expired_decision_push 'POST /v1/alerts (past dates, simulated, remediation=false, one ban of 1s: expired at once)'
  after="$(decision_count peer)"
  call peer GET '/v1/alerts?ip=203.0.113.40'
  emit d neutral_expired_decision_stored "GET /v1/alerts?ip=203.0.113.40 (active decisions before=${before}, after=${after})" \
    '[.[]|{id,simulated,start_at,stop_at,decisions:[.decisions[]?|{origin,type,simulated,duration}]}]'
}

# Are the event timestamp (GET returns a Go time string), labels and an uuid kept?
probe_d_event_and_label_roundtrip() {
  local events_go_format='{"events":[{"timestamp":"2026-10-29 13:17:13 +0000 UTC","meta":[{"key":"source_ip","value":"203.0.113.41"}]}],"remediation":false}'
  push peer "$(alert_payload spike/roundtrip Ip 203.0.113.41 "$(now_utc '1 day ago')" "$(now_utc '23 hours ago')" true '[]' '' "$events_go_format")"
  emit d roundtrip_go_time_string_push 'POST /v1/alerts (event timestamp as GET prints it: "2026-10-29 13:17:13 +0000 UTC")'
  call peer GET '/v1/alerts?ip=203.0.113.41'
  emit d roundtrip_go_time_string_stored 'GET /v1/alerts?ip=203.0.113.41' '[.[]|{id,events,start_at}]'
  push peer "$(alert_payload spike/roundtrip Ip 203.0.113.42 2026-10-29T10:00:00Z 2026-10-29T10:05:00Z true '[]' '' '{"labels":{"imported_uuid":"x"},"remediation":false}')"
  emit d labels_as_object_push 'POST /v1/alerts (labels as a JSON object)'
  push peer "$(alert_payload spike/roundtrip Ip 203.0.113.42 2026-10-29T10:00:00Z 2026-10-29T10:05:00Z true '[]' '' '{"labels":["imported_uuid=x"],"remediation":false}')"
  emit d labels_as_array_push 'POST /v1/alerts (labels as a string array)'
  call peer GET '/v1/alerts?ip=203.0.113.42'
  emit d labels_as_array_stored 'GET /v1/alerts?ip=203.0.113.42' '[.[]|{id,labels,events,start_at,stop_at}]'
}

# The DEFAULT profile (local engine): does a pushed alert without decisions ban?
probe_d_default_profile() {
  local now variant ip simulated remediation
  now="$(now_utc)"
  emit_note d default_profile "$(jq -nc --arg profile "$(docker exec "$local_container" cat /etc/crowdsec/profiles.yaml | grep -v '^#' | grep -v '^ *#')" '{local_profiles_yaml:$profile}')"
  for variant in "203.0.113.31 true true" "203.0.113.32 true false" "203.0.113.33 false true" "203.0.113.34 false false"; do
    read -r ip simulated remediation <<< "$variant"
    push local "$(alert_payload spike/default-profile Ip "$ip" "$now" "$now" "$simulated" '[]' '' "{\"remediation\":${remediation}}")"
  done
  push local "$(alert_payload spike/default-profile Ip 203.0.113.35 "$now" "$now" true '[]')"
  push local "$(alert_payload spike/default-profile Range 198.51.100.128/25 "$now" "$now" true '[]' '' '{"remediation":true}')"
  call local GET '/v1/alerts?scenario=spike/default-profile&limit=20'
  printf '%s' "$http_body" | jq '.' > "$fixture_dir/spike-default-profile-import.json"
  emit d default_profile_result 'GET /v1/alerts?scenario=spike/default-profile (alerts pushed WITHOUT decisions: IPs .31 sim+rem, .32 sim, .33 rem, .34 neither, .35 sim without field, range sim+rem)' \
    '[.[]|{id,simulated,remediation,source:.source.value,decisions:[.decisions[]?|{origin,type,simulated,duration}]}]'
}

# Are the decisions the profile created for simulated alerts served to bouncers?
probe_d_bouncer_visibility() {
  local key
  key="$(docker exec "$peer_container" cscli bouncers add spike-bouncer -o raw)"
  bouncer_call() {
    docker exec "$curl_container" curl -sS -m 20 -A spike-bouncer/0.1 -H "X-Api-Key: $key" "$1"
  }
  emit_note d bouncer_decisions_ip_simulated "$(bouncer_call 'http://peer-a:8080/v1/decisions?ip=2001:db8:6::3' | jq -c '{response:.}')"
  emit_note d bouncer_decisions_ip_real "$(bouncer_call 'http://peer-a:8080/v1/decisions?ip=198.51.100.7' | jq -c '{response:.}')"
  emit_note d bouncer_stream_startup "$(bouncer_call 'http://peer-a:8080/v1/decisions/stream?startup=true' | jq -c '{new:(.new // [] | map({value,origin,scenario})),deleted:(.deleted // [] | length)}')"
  emit_note d simulated_decisions_active_on_peer "$(decision_count peer)"
}

# 30 simulated alerts dated now on a peer-a that keeps at most 20: do the older real
# alerts (with active bans) disappear, decisions included?
probe_d_flush_low_max_items() {
  local now batch ban_values
  now="$(now_utc)"
  emit_note d flush_before "$(jq -nc --argjson alerts "$(alert_count peer)" --argjson decisions "$(decision_count peer)" '{alerts:$alerts,active_decisions:$decisions}')"
  batch="$(jq -nc --arg now "$now" '[range(0;30) as $n | {scenario:"spike/import-bulk", scenario_hash:"", scenario_version:"", message:"spike", capacity:0, events_count:0, leakspeed:"0", simulated:true, start_at:$now, stop_at:$now, events:[], source:{scope:"Ip", value:"2001:db8:6::\($n)"}, decisions:[]}]')"
  push peer "$batch"
  emit d flush_import_30 'POST /v1/alerts (30 simulated alerts dated now, no decisions)' 'length'
  emit_note d flush_after_import_before_flush "$(jq -nc --argjson alerts "$(alert_count peer)" --argjson decisions "$(decision_count peer)" '{alerts:$alerts,active_decisions:$decisions}')"
  local waited=0
  while [ "$waited" -lt 150 ]; do
    sleep 15
    waited=$((waited + 15))
    [ "$(alert_count peer)" -le 20 ] && break
  done
  emit_note d flush_after_wait "$(jq -nc --argjson waited "$waited" --argjson alerts "$(alert_count peer)" --argjson decisions "$(decision_count peer)" '{waited_s:$waited,alerts:$alerts,active_decisions:$decisions}')"
  emit_note d flush_log "$(docker logs "$peer_container" 2>&1 | grep -i 'flushed' | tail -3 | jq -Rsc '.')"
  call peer GET '/v1/alerts?limit=100000'
  emit d flush_survivors 'GET /v1/alerts?limit=100000 (which alerts survived)' '[.[]|{id,scenario}]|{count:length,ids:map(.id),oldest_id:(map(.id)|min),scenarios:(group_by(.scenario)|map({(.[0].scenario):length})|add)}'
  call peer GET '/v1/alerts?has_active_decision=true&limit=100000'
  ban_values="$(printf '%s' "$http_body" | jq -c '[.[]|{id,scenario,values:[.decisions[]?.value]}]')"
  emit_note d flush_active_decisions_left "$ban_values"
}
