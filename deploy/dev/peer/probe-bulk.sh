#!/usr/bin/env bash
# shellcheck disable=SC2154  # variables and helpers come from spike.sh / spike-lib.sh
# Bulk part of (a) and (d): server cap of the limit parameter and the DEFAULT flush.max_items
# on the local engine. Sourced by spike.sh after spike-lib.sh and probe-import.sh.

# Number of alerts in the last response body, -1 when it is not a JSON array.
count_alerts_in_body() {
  local count
  count="$(printf '%s' "$http_body" | jq 'if type == "array" then length else -1 end' 2>/dev/null || true)"
  echo "${count:--1}"
}

# Pushes COUNT simulated alerts dated now on ENGINE in batches of 400.
push_bulk_alerts() {
  local engine="$1" count="$2" now offset=0 batch
  now="$(now_utc)"
  while [ "$offset" -lt "$count" ]; do
    batch="$(jq -nc --arg now "$now" --argjson offset "$offset" '[range($offset; $offset+400) as $n | {scenario:"spike/bulk", scenario_hash:"", scenario_version:"", message:"spike", capacity:0, events_count:0, leakspeed:"0", simulated:true, start_at:$now, stop_at:$now, events:[], source:{scope:"Ip", value:"2001:db8:7::\($n)"}, decisions:[]}]')"
    push "$engine" "$batch"
    [ "$http_status" = 201 ] || { emit d bulk_push_failed "POST /v1/alerts (offset ${offset})" '.'; return 1; }
    offset=$((offset + 400))
  done
}

# Server cap of the limit parameter, response size / time at 5000 alerts, and the DEFAULT
# flush.max_items (5000) on the local engine, whose seeded real alerts are the oldest.
probe_bulk_limit_and_flush() {
  emit_note bulk default_flush_config "$(jq -nc --arg flush "$(docker exec "$local_container" cscli config show --key Config.DbConfig.Flush 2>&1)" '{local_flush:$flush}')"
  emit_note bulk before_import "$(jq -nc --argjson alerts "$(alert_count local)" --argjson decisions "$(decision_count local)" '{alerts:$alerts,active_decisions:$decisions}')"
  local started_ns finished_ns
  started_ns="$(date +%s%N)"
  push_bulk_alerts local 5200
  finished_ns="$(date +%s%N)"
  emit_note bulk import_5200 "$(jq -nc --argjson ms "$(((finished_ns - started_ns) / 1000000))" '{alerts_pushed:5200,batch_size:400,duration_ms:$ms}')"
  local limit bytes
  for limit in 5000 5001 6000 100000; do
    started_ns="$(date +%s%N)"
    call local GET "/v1/alerts?limit=${limit}"
    finished_ns="$(date +%s%N)"
    bytes=${#http_body}
    emit_note bulk "limit_${limit}" "$(jq -nc --argjson limit "$limit" --arg status "$http_status" --argjson bytes "$bytes" \
      --argjson ms "$(((finished_ns - started_ns) / 1000000))" --argjson returned "$(count_alerts_in_body)" \
      '{limit:$limit,status:($status|tonumber),alerts_returned:$returned,body_bytes:$bytes,duration_ms:$ms}')"
  done
  local limit_param
  for limit_param in '' 'limit=0' 'limit=-1' 'limit=abc'; do
    call local GET "/v1/alerts?${limit_param}"
    emit_note bulk "limit_param_${limit_param:-omitted}" "$(jq -nc --arg param "$limit_param" --arg status "$http_status" --argjson returned "$(count_alerts_in_body)" --arg body "${http_body:0:120}" '{param:$param,status:($status|tonumber),alerts_returned:$returned,body_start_if_error:(if $returned == -1 then $body else null end)}')"
  done
  call local GET '/v1/alerts?limit=3&has_active_decision=false'
  emit bulk has_active_decision_false_under_load 'GET /v1/alerts?limit=3&has_active_decision=false' '[.[]|{id,scenario}]'
  call local GET '/v1/alerts?limit=5000&has_active_decision=true&decision_type=ban&origin=cscli'
  emit bulk sync_query_under_load 'GET /v1/alerts?limit=5000&has_active_decision=true&decision_type=ban&origin=cscli' '[.[]|{id,scenario}]|length'

  local waited=0
  while [ "$waited" -lt 150 ]; do
    sleep 15
    waited=$((waited + 15))
    [ "$(alert_count local)" -le 5000 ] && break
  done
  emit_note bulk after_flush "$(jq -nc --argjson waited "$waited" --argjson alerts "$(alert_count local)" --argjson decisions "$(decision_count local)" '{waited_s:$waited,alerts:$alerts,active_decisions:$decisions}')"
  call local GET '/v1/alerts?has_active_decision=true&limit=5000'
  emit bulk active_alerts_after_flush 'GET /v1/alerts?has_active_decision=true&limit=5000 (do the seeded real bans survive?)' '[.[]|{id,scenario}]'
}
