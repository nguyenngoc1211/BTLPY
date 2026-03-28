#!/usr/bin/env bash
set -euo pipefail

DB_PATH="${1:-/home/sealorl/BTLPY/security-demo-lab/logs/apt/alerts.db}"
LIMIT="${2:-20}"

if [[ ! -f "$DB_PATH" ]]; then
  echo "Missing DB: $DB_PATH"
  exit 1
fi

sqlite3 -header -column "$DB_PATH" \
  "SELECT id, ts_utc, stage, round(confidence,4) AS conf, severity, src_ip, dest_ip, dest_port, method, path, source FROM alerts ORDER BY id DESC LIMIT ${LIMIT};"
