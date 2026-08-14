#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash $0"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

old_services=(
  apt_early_warning_scoring.service
  apt_early_warning_web_log_parser.service
  apt_early_warning_web_collector.service
)

new_services=(
  web_early_warning_scoring.service
  web_early_warning_web_log_parser.service
  web_early_warning_web_collector.service
)

for svc in "${old_services[@]}"; do
  systemctl disable --now "$svc" 2>/dev/null || true
done

if [[ -f /etc/apt_early_warning_scoring.env && ! -f /etc/web_early_warning_scoring.env ]]; then
  cp /etc/apt_early_warning_scoring.env /etc/web_early_warning_scoring.env
fi
if [[ -f /etc/apt_early_warning_web_log_parser.env && ! -f /etc/web_early_warning_web_log_parser.env ]]; then
  cp /etc/apt_early_warning_web_log_parser.env /etc/web_early_warning_web_log_parser.env
fi
if [[ -f /etc/apt_early_warning_web_collector.env && ! -f /etc/web_early_warning_web_collector.env ]]; then
  cp /etc/apt_early_warning_web_collector.env /etc/web_early_warning_web_collector.env
fi

sed -i 's#apt_early_warning#web_early_warning#g; s#apt-ingest#web-ingest#g; s#/logs/apt/#/logs/web/#g; s#ALERT_LABELS=APT#ALERT_LABELS=WebAttack#g' /etc/web_early_warning_scoring.env 2>/dev/null || true
sed -i 's#apt_early_warning#web_early_warning#g; s#/logs/apt/#/logs/web/#g' /etc/web_early_warning_web_log_parser.env 2>/dev/null || true
sed -i 's#apt_early_warning#web_early_warning#g; s#apt-ingest#web-ingest#g; s#/logs/apt/#/logs/web/#g' /etc/web_early_warning_web_collector.env 2>/dev/null || true

bash "$ROOT_DIR/web_early_warning/deploy/install_scoring_systemd.sh"
bash "$ROOT_DIR/web_early_warning/deploy/install_web_log_parser_systemd.sh"
bash "$ROOT_DIR/web_early_warning/deploy/install_web_collector_systemd.sh"

systemctl daemon-reload
for svc in "${new_services[@]}"; do
  systemctl enable --now "$svc"
  systemctl status --no-pager "$svc" | sed -n '1,8p'
done

echo "Migration completed."
