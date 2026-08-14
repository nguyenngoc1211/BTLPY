#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LAB_DIR="$ROOT_DIR/security-demo-lab"
SERVICE_USER="${SERVICE_USER:-${SUDO_USER:-$(id -un)}}"
SERVICE_GROUP="${SERVICE_GROUP:-$(id -gn "$SERVICE_USER")}"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash $0"
  exit 1
fi

cat >/etc/web_early_warning_web_log_parser.env <<EOF
WEB_ACCESS_LOG_PATH=$LAB_DIR/logs/nginx/access.log
WEB_EVENTS_PATH=$LAB_DIR/logs/web/events.jsonl
WEB_FLOW_WINDOW_SEC=20
WEB_FLOW_MIN_REQUESTS=3
WEB_FLOW_FLUSH_SEC=3
VERBOSE=1
EOF

cat >/etc/web_early_warning_web_collector.env <<EOF
WEB_EVENTS_PATH=$LAB_DIR/logs/web/events.jsonl
SCORE_URL=http://127.0.0.1:8000/score
N8N_WEBHOOK=http://127.0.0.1:5678/webhook/web-ingest
ALERTS_DB_PATH=$LAB_DIR/logs/web/alerts.db
VERBOSE=1
EOF

cat >/etc/web_early_warning_scoring.env <<EOF
HOST=0.0.0.0
PORT=8000
BUNDLE_PATH=$ROOT_DIR/web_early_warning/model_out_flowfeatures/lgbm_combined_flow_web_60_webattack.joblib
ALERT_LABELS=WebAttack
ALERT_MIN_CONF_HIGH_IMPACT=0.50
ALERT_MIN_CONF_NON_BENIGN=0.50
EOF

# Ensure output paths exist and are writable by service user.
install -d -m 0755 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$LAB_DIR/logs/nginx" "$LAB_DIR/logs/web"
touch "$LAB_DIR/logs/web/events.jsonl"
touch "$LAB_DIR/logs/web/alerts.db"
chown "$SERVICE_USER:$SERVICE_GROUP" "$LAB_DIR/logs/web/events.jsonl" "$LAB_DIR/logs/web/alerts.db"

systemctl daemon-reload
systemctl enable --now web_early_warning_scoring.service
systemctl enable --now web_early_warning_web_log_parser.service
systemctl enable --now web_early_warning_web_collector.service

echo "ML web bridge configured."
echo "Check:"
echo "  systemctl status web_early_warning_scoring.service --no-pager"
echo "  systemctl status web_early_warning_web_log_parser.service --no-pager"
echo "  systemctl status web_early_warning_web_collector.service --no-pager"
