#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_PATH="${1:-$ROOT_DIR/security-demo-lab/logs/web/alerts.db}"
LIMIT="${2:-20}"

if [[ ! -f "$DB_PATH" ]]; then
  echo "Missing DB: $DB_PATH"
  exit 1
fi

sqlite3 -header -column "$DB_PATH" \
  "SELECT id, ts_utc, stage, round(confidence,4) AS conf, severity, src_ip, dest_ip, dest_port, method, path, source FROM alerts ORDER BY id DESC LIMIT ${LIMIT};"
