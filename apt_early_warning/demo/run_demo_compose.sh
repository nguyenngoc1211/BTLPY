#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

docker compose -f apt_early_warning/demo/compose.demo.yml up -d --build

cat <<'TXT'

Demo is up.

- n8n UI:   http://localhost:5678
- API:      http://localhost:8000/health

In n8n, import:
  apt_early_warning/demo/workflow_apt_demo_compose.json

Then test:
  python3 -m apt_early_warning.demo.send_sample --url http://localhost:5678/webhook/apt-ingest
  python3 -m apt_early_warning.demo.send_sample --url http://localhost:5678/webhook/apt-ingest --force-alert

TXT

