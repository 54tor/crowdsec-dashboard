#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154  # variables come from peer/spike-lib.sh
# DISPOSABLE spike against two real CrowdSec engines (local + peer-a) to check the
# assumptions of the engine-sync design. Development only; prints one JSON line per
# observation on stdout (progress on stderr).
#   ./spike.sh                 run everything, then tear the csdash-dev project down
#   SPIKE_KEEP=1 ./spike.sh    leave the containers up afterwards
#   ./spike.sh a c f           run only the named probe groups (a b c f d e g bulk)
# Refuses to run when the csdash-dev project already has containers (the final teardown
# also drops its volumes). Only documentation addresses are used (RFC 5737, RFC 3849).
set -euo pipefail

cd "$(dirname "$0")"
here="$(pwd)"
fixture_dir="$here/fixtures"
# shellcheck disable=SC1091
. ./peer/spike-lib.sh
# shellcheck disable=SC1091
. ./peer/probe-alerts.sh
# shellcheck disable=SC1091
. ./peer/probe-login-config.sh
# shellcheck disable=SC1091
. ./peer/probe-import.sh
# shellcheck disable=SC1091
. ./peer/probe-bulk.sh

# The compose file interpolates DOCKER_GID for the socket proxy, which is never started here.
export DOCKER_GID="${DOCKER_GID:-0}"
machine_password="$(head -c 24 /dev/urandom | base64 | tr -d '/+=\n')"
groups=("$@")
[ "${#groups[@]}" -gt 0 ] || groups=(a b c f d e g bulk)

compose() {
  docker compose -p "$project" -f compose.yaml -f peer/compose.override.yaml --profile spike "$@"
}

wants() {
  local wanted
  for wanted in "${groups[@]}"; do
    [ "$wanted" = "$1" ] && return 0
  done
  return 1
}

# shellcheck disable=SC2329  # called through the EXIT trap
teardown() {
  if [ "${SPIKE_KEEP:-0}" = 1 ]; then
    echo "SPIKE_KEEP=1: containers left up (project $project)" >&2
    return
  fi
  compose down -v --remove-orphans >&2
}

register_machine() {
  docker exec "$1" cscli machines add "$machine_id" --password "$machine_password" -f /dev/null >&2
}

# Fake bans on both engines. cscli-added decisions get origin cscli; pushed alerts carry
# origin crowdsec like the engine's own scenarios do.
seed_engines() {
  local now
  now="$(now_utc)"
  docker exec "$local_container" cscli decisions add --ip 203.0.113.5 --duration 4h --reason "seed manual ban" >&2
  docker exec "$local_container" cscli decisions add --range 198.51.100.0/24 --duration 24h --reason "seed range ban" >&2
  docker exec "$local_container" cscli decisions add --ip 2001:db8::1 --duration 2h --type captcha --reason "seed captcha" >&2
  push local "$(alert_payload crowdsecurity/ssh-bf Ip 203.0.113.10 "$(now_utc '20 hours ago')" "$(now_utc '20 hours ago')" false "[$(decision_json ban 48h crowdsec crowdsecurity/ssh-bf Ip 203.0.113.10)]")"
  push local "$(alert_payload "update : +1/-0 IPs" Ip 203.0.113.99 "$now" "$now" false "[$(decision_json ban 24h CAPI "update : +1/-0 IPs" Ip 203.0.113.99)]")"
  docker exec "$peer_container" cscli decisions add --ip 203.0.113.77 --duration 4h --reason "seed manual ban" >&2
  push peer "$(alert_payload crowdsecurity/ssh-bf Ip 198.51.100.7 "$now" "$now" false "[$(decision_json ban 24h crowdsec crowdsecurity/ssh-bf Ip 198.51.100.7)]")"
}

if [ -n "$(compose ps -q)" ]; then
  echo "project $project already has containers; refusing to run (stop it first)" >&2
  exit 1
fi
trap teardown EXIT

echo "starting local engine, peer-a and the curl client" >&2
compose up -d --wait --wait-timeout 240 crowdsec peer-a spike-curl >&2
wait_lapi local
wait_lapi peer
register_machine "$local_container"
register_machine "$peer_container"
login local
login peer
seed_engines

wants a && { probe_a_listing; probe_a_mixed_alert; }
wants b && probe_b_custom_origin
wants c && probe_c_delete_own_decision
wants f && probe_f_duration
wants g && probe_g_cross_engine_login
wants e && probe_e_config_test
wants d && probe_d_alert_import
wants bulk && probe_bulk_limit_and_flush
exit 0
