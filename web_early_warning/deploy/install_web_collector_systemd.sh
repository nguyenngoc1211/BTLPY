#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash $0"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
VENV_PY="$ROOT_DIR/.venv/bin/python3"
SERVICE_USER="${SERVICE_USER:-${SUDO_USER:-$(id -un)}}"
SERVICE_GROUP="${SERVICE_GROUP:-$(id -gn "$SERVICE_USER")}"

if [[ ! -x "$VENV_PY" ]]; then
  echo "Missing venv python at: $VENV_PY"
  echo "Create/install deps first:"
  echo "  cd $ROOT_DIR && python3 -m venv .venv && source .venv/bin/activate && pip install -r web_early_warning/requirements.txt"
  exit 1
fi

sed \
  -e "s#__ROOT_DIR__#$ROOT_DIR#g" \
  -e "s#__SERVICE_USER__#$SERVICE_USER#g" \
  -e "s#__SERVICE_GROUP__#$SERVICE_GROUP#g" \
  "$ROOT_DIR/web_early_warning/deploy/web_early_warning_web_collector.service" \
  > /etc/systemd/system/web_early_warning_web_collector.service
chmod 0644 /etc/systemd/system/web_early_warning_web_collector.service

if [[ ! -f /etc/web_early_warning_web_collector.env ]]; then
  install -m 0644 "$ROOT_DIR/web_early_warning/deploy/web_collector.env.example" \
    /etc/web_early_warning_web_collector.env
  echo "Created /etc/web_early_warning_web_collector.env (edit it for your environment)."
fi

systemctl daemon-reload
systemctl enable --now web_early_warning_web_collector.service
systemctl status --no-pager web_early_warning_web_collector.service || true
