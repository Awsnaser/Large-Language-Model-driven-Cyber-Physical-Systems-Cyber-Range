#!/usr/bin/env bash
# Prepare and validate the Version 2 safe-by-default local lab configuration.
# This script deliberately does not modify host firewall rules or start capture.
set -euo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

printf '%s\n' "Preparing CPS Cyber Range Version 2..."
mkdir -p configs/suricata/logs monitoring/grafana/dashboards

required_files=(
  docker-compose.yml
  monitoring/docker-compose-closed.yml
  monitoring/docker-compose-enhanced.yml
  monitoring/laptop-optimization.yml
  configs/suricata/suricata.yaml
  configs/suricata/custom-cps.rules
)

for path in "${required_files[@]}"; do
  if [[ ! -f "$path" ]]; then
    printf 'Missing required file: %s\n' "$path" >&2
    exit 1
  fi
done

python3 cyberrange.py --version
python3 quick-docker-test.py
python3 test-suricata.py

if docker compose version >/dev/null 2>&1; then
  for compose_file in \
    docker-compose.yml \
    monitoring/docker-compose-closed.yml \
    monitoring/docker-compose-enhanced.yml \
    monitoring/laptop-optimization.yml \
    monitoring/docker-compose.yml; do
    docker compose -f "$compose_file" config --quiet
  done
  printf '%s\n' "Compose profiles validated."
else
  printf '%s\n' "Docker Compose is unavailable; skipped runtime Compose validation."
fi

cat <<'EOF'

Setup validation complete.

Safe enhanced run:
  export GRAFANA_ADMIN_PASSWORD='replace-with-a-strong-password'
  python3 cyberrange.py --enhanced-docker --scripted-agents --rounds 20

Closed four-service run:
  python3 cyberrange.py --compose monitoring/docker-compose-closed.yml --scripted-agents --rounds 20

This simulator is not a complete isolation boundary. Do not connect it to
production systems. Live packet capture requires a separate explicit profile;
review monitoring/security-controls.md before enabling it.
EOF
