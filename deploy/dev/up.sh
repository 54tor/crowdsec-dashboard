#!/usr/bin/env bash
# Starts the disposable development stack (compose project csdash-dev).
#   ./up.sh            CrowdSec without Prometheus, like the real instance
#   ./up.sh metrics    CrowdSec with the Prometheus listener enabled
#   ./up.sh peer       also start the disposable second engine peer-a (peer/compose.override.yaml),
#                      reachable inside the stack as http://peer-a:8080 (see spike.sh)
# On first run it generates .env.local (git-ignored) with random secrets and prints
# the database password. The enrolment token of the first account is read from the dashboard
# logs and printed once the dashboard is up. Re-running keeps the existing secrets.
set -euo pipefail

cd "$(dirname "$0")"
project=csdash-dev
variant="${1:-default}"
machine_id=dashboard-dev
lapi_container=csdash-dev-crowdsec
dashboard_container=csdash-dev-dashboard

random_secret() {
  head -c 24 /dev/urandom | base64 | tr -d '/+=\n'
}

compose() {
  docker compose -p "$project" --env-file .env.local -f compose.yaml -f peer/compose.override.yaml "$@"
}

if [ ! -f .env.local ]; then
  machine_password="$(random_secret)"
  docker_gid="$(stat -c '%g' /var/run/docker.sock)"
  umask 077
  {
    printf "LAPI_MACHINE_PASSWORD='%s'\n" "$machine_password"
    printf "DOCKER_GID='%s'\n" "$docker_gid"
  } > .env.local
fi

if ! grep -q '^DATABASE_URL=' .env.local; then
  postgres_password="$(random_secret)"
  {
    printf "POSTGRES_PASSWORD='%s'\n" "$postgres_password"
    printf "DATABASE_URL='postgres://dashboard:%s@csdash-dev-postgres:5432/dashboard?sslmode=disable'\n" "$postgres_password"
  } >> .env.local
fi

set -a
# shellcheck disable=SC1091
. ./.env.local
set +a

if [ "$variant" = metrics ]; then
  export CROWDSEC_LOCAL_CONFIG=./config.prometheus-on.yaml
fi

compose up -d --wait --wait-timeout 180 crowdsec
if [ "$variant" = peer ]; then
  compose up -d --wait --wait-timeout 180 peer-a
fi

# (Re)register the dashboard machine so its password always matches .env.local.
# Machines created with cscli are validated at once.
if docker exec "$lapi_container" cscli machines list -o raw | cut -d, -f1 | grep -qx "$machine_id"; then
  docker exec "$lapi_container" cscli machines delete "$machine_id"
fi
docker exec "$lapi_container" cscli machines add "$machine_id" --password "$LAPI_MACHINE_PASSWORD" -f /dev/null

compose up -d --build --wait --wait-timeout 180 postgres socket-proxy dashboard

enrollment_line=""
for _ in $(seq 1 20); do
  enrollment_line="$(docker logs "$dashboard_container" 2>&1 | grep 'enroll the first account' | tail -n 1 || true)"
  [ -n "$enrollment_line" ] && break
  sleep 1
done
echo "Dashboard: http://127.0.0.1:18080"
if [ -n "$enrollment_line" ]; then
  echo "Enrolment token: ${enrollment_line##* }"
  echo "Enrol the first account at http://127.0.0.1:18080/enroll"
else
  echo "No enrolment token: an account already exists."
fi
