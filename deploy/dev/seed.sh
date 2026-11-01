#!/usr/bin/env bash
# Fills the dev CrowdSec with fake alerts and decisions. Only documentation
# addresses are used: 203.0.113.0/24, 198.51.100.0/24 (RFC 5737), 2001:db8::/32 (RFC 3849).
# Run it once per fresh stack (a second run adds the same fake data again).
# CSDASH_PROJECT (default csdash-dev) selects the stack, SEED_ENGINE=peer-a seeds the demo engine
# instead of the local one (each run adds about 10 alerts: 3 manual ones and 7 pushed ones).
set -euo pipefail

project="${CSDASH_PROJECT:-csdash-dev}"
if ! [[ "$project" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
  echo "invalid CSDASH_PROJECT: use lowercase letters, digits, - and _" >&2
  exit 1
fi
container="$project-${SEED_ENGINE:-crowdsec}"
seed_machine=dev-agent

crowdsec() {
  docker exec "$container" "$@"
}

# Decisions added through cscli also create their own "manual" alert.
crowdsec cscli decisions add --ip 203.0.113.5 --duration 4h --reason "seed manual ban"
crowdsec cscli decisions add --range 198.51.100.0/24 --duration 24h --reason "seed range ban"
crowdsec cscli decisions add --ip 2001:db8::1 --duration 2h --type captcha --reason "seed captcha"

# The LAPI rejects a login whose User-Agent is not "name/version" (busybox wget sends "Wget"), hence -U.
# cscli has no "alerts add": push alerts to the LAPI as a fake agent machine, which also
# sends a heartbeat so that the machines list shows last_heartbeat.
seed_password="$(head -c 24 /dev/urandom | base64 | tr -d '/+=\n')"
crowdsec cscli machines delete "$seed_machine" >/dev/null 2>&1 || true
crowdsec cscli machines add "$seed_machine" --password "$seed_password" -f /dev/null >/dev/null

timestamp_hours_ago() {
  date -u -d "$1 hours ago" +%Y-%m-%dT%H:%M:%SZ
}

alert_json() {
  local scenario="$1" source_ip="$2" hours_ago="$3" decision_duration="$4"
  local started
  started="$(timestamp_hours_ago "$hours_ago")"
  local decisions='[]'
  if [ -n "$decision_duration" ]; then
    decisions="[{\"type\":\"ban\",\"duration\":\"$decision_duration\",\"origin\":\"crowdsec\",\"scenario\":\"$scenario\",\"scope\":\"Ip\",\"value\":\"$source_ip\"}]"
  fi
  cat <<JSON
{"scenario":"$scenario","scenario_hash":"","scenario_version":"0.1","message":"seed alert from $source_ip","capacity":5,"leakspeed":"10s","events_count":6,"simulated":false,"start_at":"$started","stop_at":"$started","events":[],"source":{"scope":"Ip","value":"$source_ip","ip":"$source_ip","cn":"ZZ","as_name":"Example Net","as_number":"64496"},"decisions":$decisions}
JSON
}

alerts_payload="[
$(alert_json crowdsecurity/ssh-bf 203.0.113.10 20 48h),
$(alert_json crowdsecurity/ssh-bf 203.0.113.11 14 48h),
$(alert_json crowdsecurity/ssh-slow-bf 198.51.100.7 9 24h),
$(alert_json crowdsecurity/http-probing 198.51.100.8 5 12h),
$(alert_json crowdsecurity/ssh-bf 2001:db8::42 3 4h),
$(alert_json crowdsecurity/http-crawl-non_statics 203.0.113.12 1 ''),
$(alert_json crowdsecurity/ssh-bf 203.0.113.13 30 1s)
]"

printf '%s' "$alerts_payload" | docker exec -i "$container" sh -c 'cat > /tmp/seed-alerts.json'
crowdsec sh -c "
  token=\$(wget -U crowdsec/seed -qO- --header 'Content-Type: application/json' \
    --post-data '{\"machine_id\":\"$seed_machine\",\"password\":\"$seed_password\",\"scenarios\":[]}' \
    http://127.0.0.1:8080/v1/watchers/login | sed -n 's/.*\"token\":\"\\([^\"]*\\)\".*/\\1/p')
  wget -U crowdsec/seed -qO- --header 'Content-Type: application/json' --header \"Authorization: Bearer \$token\" \
    --post-file /tmp/seed-alerts.json http://127.0.0.1:8080/v1/alerts
  echo
  wget -U crowdsec/seed -qO- --header \"Authorization: Bearer \$token\" http://127.0.0.1:8080/v1/heartbeat
  echo
  rm -f /tmp/seed-alerts.json
"

# A bouncer that has pulled once, so that last_pull, ip_address, type and version are filled.
bouncer_name=dev-firewall-bouncer
crowdsec cscli bouncers delete "$bouncer_name" >/dev/null 2>&1 || true
bouncer_key="$(crowdsec cscli bouncers add "$bouncer_name" -o raw)"
crowdsec wget -qO- -U 'crowdsec-firewall-bouncer/v0.0.31' --header "X-Api-Key: $bouncer_key" \
  'http://127.0.0.1:8080/v1/decisions/stream?startup=true' >/dev/null

# Log lines for the file datasource of acquis.yaml: gives `cscli metrics` something to count
# when Prometheus is on. CrowdSec only notices the file at (re)load, hence the SIGHUP.
# shellcheck disable=SC2016
crowdsec sh -c 'for attempt in 1 2 3 4 5 6 7 8; do
  echo "$(date "+%b %e %H:%M:%S") dev sshd[1234]: Failed password for invalid user admin from 203.0.113.200 port 4422$attempt ssh2" >> /var/log/dev/auth.log
done
echo "unparsable line" >> /var/log/dev/auth.log'
crowdsec kill -HUP 1

crowdsec cscli alerts list
