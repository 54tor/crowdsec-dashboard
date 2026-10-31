#!/usr/bin/env bash
# shellcheck disable=SC2154  # variables and helpers come from spike.sh / spike-lib.sh
# Probes (a), (b), (c), (f): LAPI alert listing, custom origin, own-decision deletion and
# decision duration format. Sourced by spike.sh after spike-lib.sh and the seeding.

summary='[.[]|{id,scenario,machine_id,decisions:[.decisions[]?|{id,origin,type,value,duration}]}]'

probe_a_listing() {
  local engine=local
  call "$engine" GET '/v1/alerts?limit=50'
  emit a default_listing 'GET /v1/alerts?limit=50' "$summary"
  printf '%s' "$http_body" | jq '.' > "$fixture_dir/spike-alerts-list.json"
  call "$engine" GET '/v1/alerts?scenario=crowdsecurity/ssh-bf'
  printf '%s' "$http_body" | jq '.[0]' > "$fixture_dir/spike-alert-shape.json"
  emit a alert_shape 'GET /v1/alerts?scenario=crowdsecurity/ssh-bf (first alert, full)' '.[0]'
  call "$engine" GET '/v1/alerts?limit=50&include_capi=false'
  emit a include_capi_false 'GET /v1/alerts?limit=50&include_capi=false' "$summary"
  emit a ordering_ids 'GET /v1/alerts?limit=50 (ids in response order)' '[.[].id]'
  emit a ordering_start_at 'GET /v1/alerts?limit=50 (start_at in response order)' '[.[].start_at]'

  local query
  for query in 'origin=cscli' 'origin=crowdsec' 'origin=CAPI' 'origin=dashboard-sync' \
    'decision_type=ban' 'decision_type=captcha' 'decision_type=nonsense' \
    'has_active_decision=true' 'has_active_decision=false' \
    'has_active_decision=true&decision_type=ban&origin=crowdsec' \
    'has_active_decision=true&decision_type=ban&origin=cscli' \
    'include_capi=true' 'origin=CAPI&include_capi=true' 'limit=5' 'limit=0'; do
    call "$engine" GET "/v1/alerts?${query}"
    emit a "filter" "GET /v1/alerts?${query}" "$summary"
  done
}

# (a) mixed alert: one ban (crowdsec) and one captcha (cscli) in the same alert; shows
# whether an origin / decision_type filter trims the decisions of the returned alert.
probe_a_mixed_alert() {
  local now decisions
  now="$(now_utc)"
  decisions="[$(decision_json ban 2h crowdsec spike/mixed Ip 203.0.113.60),$(decision_json captcha 2h cscli spike/mixed Ip 203.0.113.61)]"
  push local "$(alert_payload spike/mixed Ip 203.0.113.60 "$now" "$now" false "$decisions")"
  emit a mixed_alert_push 'POST /v1/alerts (ban crowdsec + captcha cscli in one alert)'
  call local GET '/v1/alerts?scenario=spike/mixed&origin=crowdsec&decision_type=ban'
  emit a mixed_alert_origin_crowdsec_ban 'GET /v1/alerts?scenario=spike/mixed&origin=crowdsec&decision_type=ban' "$summary"
  call local GET '/v1/alerts?scenario=spike/mixed&origin=cscli'
  emit a mixed_alert_origin_cscli 'GET /v1/alerts?scenario=spike/mixed&origin=cscli' "$summary"
  call local GET '/v1/alerts?scenario=spike/mixed&decision_type=captcha'
  emit a mixed_alert_type_captcha 'GET /v1/alerts?scenario=spike/mixed&decision_type=captcha' "$summary"
}

# (b) custom origin pushed through POST /v1/alerts, and the machine_id stored.
probe_b_custom_origin() {
  local now decisions
  now="$(now_utc)"
  decisions="[$(decision_json ban 3h dashboard-sync sync/peer-a Ip 203.0.113.50)]"
  push local "$(alert_payload sync/peer-a Ip 203.0.113.50 "$now" "$now" false "$decisions")"
  emit b push_custom_origin 'POST /v1/alerts (decision origin dashboard-sync, scenario sync/peer-a)'
  call local GET '/v1/alerts?scenario=sync/peer-a'
  emit b stored_origin_and_machine 'GET /v1/alerts?scenario=sync/peer-a' "$summary"
  call local GET '/v1/alerts?origin=dashboard-sync&has_active_decision=true'
  emit b filter_by_custom_origin 'GET /v1/alerts?origin=dashboard-sync&has_active_decision=true' "$summary"
  emit_note b cscli_view "$(docker exec "$local_container" cscli decisions list -o json --origin dashboard-sync 2>&1 | jq -c '[.[]?|.decisions[]?|{id,origin,scenario,value,type}]' 2>/dev/null || echo '"cscli decisions list failed"')"
}

# (c) the machine that pushed an alert deletes the decision it created.
probe_c_delete_own_decision() {
  local now decisions decision_id alert_id
  now="$(now_utc)"
  decisions="[$(decision_json ban 1h dashboard-sync sync/peer-a Ip 203.0.113.51)]"
  push local "$(alert_payload sync/peer-a Ip 203.0.113.51 "$now" "$now" false "$decisions")"
  call local GET '/v1/alerts?scenario=sync/peer-a&ip=203.0.113.51'
  decision_id="$(printf '%s' "$http_body" | jq -r '.[0].decisions[0].id')"
  alert_id="$(printf '%s' "$http_body" | jq -r '.[0].id')"
  call local DELETE "/v1/decisions/${decision_id}"
  emit c delete_own_decision "DELETE /v1/decisions/{id} (decision id ${decision_id})"
  call local GET "/v1/alerts/${alert_id}"
  emit c alert_after_delete "GET /v1/alerts/${alert_id} (alert kept, decisions?)" '{id,scenario,decisions}'
  call local GET '/v1/alerts?scenario=sync/peer-a&has_active_decision=true&ip=203.0.113.51'
  emit c active_listing_after_delete 'GET /v1/alerts?...&has_active_decision=true&ip=203.0.113.51' "$summary"
  call local DELETE "/v1/decisions/${decision_id}"
  emit c delete_again "DELETE /v1/decisions/${decision_id} (already deleted)"
  call local DELETE /v1/decisions/999999
  emit c delete_unknown 'DELETE /v1/decisions/999999'

  # A decision created by ANOTHER source (cscli, id of the seeded manual ban): can the
  # dashboard machine delete it? Shows how far the LAPI itself restricts deletions.
  call local GET '/v1/alerts?origin=cscli&has_active_decision=true&ip=203.0.113.5'
  decision_id="$(printf '%s' "$http_body" | jq -r '.[0].decisions[0].id')"
  call local DELETE "/v1/decisions/${decision_id}"
  emit c delete_foreign_decision "DELETE /v1/decisions/${decision_id} (cscli-origin ban created by cscli, not by this machine)"
}

# (f) duration is the remaining time? is "until" present? negative / expired values.
probe_f_duration() {
  local now decisions
  now="$(now_utc)"
  decisions="[$(decision_json ban 3h crowdsec spike/duration Ip 203.0.113.70)]"
  push local "$(alert_payload spike/duration Ip 203.0.113.70 "$(now_utc '1 hour ago')" "$(now_utc '1 hour ago')" false "$decisions")"
  emit f push_3h_started_1h_ago 'POST /v1/alerts (duration 3h, start_at 1 hour ago)'
  call local GET '/v1/alerts?scenario=spike/duration&has_active_decision=true'
  emit f remaining_time 'GET /v1/alerts?scenario=spike/duration&has_active_decision=true' '[.[].decisions[]|{id,duration,has_until:has("until")}]'
  sleep 3
  call local GET '/v1/alerts?scenario=spike/duration'
  emit f remaining_time_3s_later 'same, 3 s later (does it tick down?)' '[.[].decisions[]|{id,duration,has_until:has("until")}]'

  decisions="[$(decision_json ban 1h crowdsec spike/expired Ip 203.0.113.71)]"
  push local "$(alert_payload spike/expired Ip 203.0.113.71 "$(now_utc '3 hours ago')" "$(now_utc '3 hours ago')" false "$decisions")"
  emit f push_expired 'POST /v1/alerts (duration 1h, start_at 3 hours ago: already expired)'
  call local GET '/v1/alerts?scenario=spike/expired'
  emit f expired_without_filter 'GET /v1/alerts?scenario=spike/expired' '[.[].decisions[]|{id,duration,has_until:has("until")}]'
  call local GET '/v1/alerts?scenario=spike/expired&has_active_decision=true'
  emit f expired_with_has_active_decision 'GET /v1/alerts?scenario=spike/expired&has_active_decision=true' "$summary"
  call local GET '/v1/alerts?scenario=spike/expired&has_active_decision=false'
  emit f expired_with_has_active_decision_false 'GET /v1/alerts?scenario=spike/expired&has_active_decision=false' "$summary"
}
