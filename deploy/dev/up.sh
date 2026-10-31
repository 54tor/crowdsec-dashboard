#!/usr/bin/env bash
# Starts the disposable development stack (compose project csdash-dev).
#   ./up.sh            CrowdSec without Prometheus, like the real instance
#   ./up.sh metrics    CrowdSec with the Prometheus listener enabled
# On first run it generates .env.local (git-ignored) with random secrets and prints
# the admin password once. Re-running keeps the existing secrets.
set -euo pipefail

cd "$(dirname "$0")"
project=csdash-dev
variant="${1:-default}"
repo_backend="$(cd ../../backend && pwd)"
machine_id=dashboard-dev
lapi_container=csdash-dev-crowdsec

random_secret() {
  head -c 24 /dev/urandom | base64 | tr -d '/+=\n'
}

compose() {
  docker compose -p "$project" --env-file .env.local "$@"
}

if [ ! -f .env.local ]; then
  admin_password="$(random_secret)"
  machine_password="$(random_secret)"
  admin_hash="$(printf '%s' "$admin_password" | (cd "$repo_backend" && go run ./cmd/hashpassword))"
  docker_gid="$(stat -c '%g' /var/run/docker.sock)"
  umask 077
  # Single quotes keep compose from interpolating the "$" signs of the argon2id hash.
  {
    printf "ADMIN_PASSWORD_HASH='%s'\n" "$admin_hash"
    printf "LAPI_MACHINE_PASSWORD='%s'\n" "$machine_password"
    printf "DOCKER_GID='%s'\n" "$docker_gid"
  } > .env.local
  echo "Dev admin password (shown once, kept only as a hash): $admin_password"
fi

set -a
# shellcheck disable=SC1091
. ./.env.local
set +a

if [ "$variant" = metrics ]; then
  export CROWDSEC_LOCAL_CONFIG=./config.prometheus-on.yaml
fi

compose up -d --wait --wait-timeout 180 crowdsec

# (Re)register the dashboard machine so its password always matches .env.local.
# Machines created with cscli are validated at once.
if docker exec "$lapi_container" cscli machines list -o raw | cut -d, -f1 | grep -qx "$machine_id"; then
  docker exec "$lapi_container" cscli machines delete "$machine_id"
fi
docker exec "$lapi_container" cscli machines add "$machine_id" --password "$LAPI_MACHINE_PASSWORD" -f /dev/null

compose up -d --build socket-proxy dashboard
echo "Dashboard: http://127.0.0.1:18080"
