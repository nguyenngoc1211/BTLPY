#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash $0"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
VENV_UVICORN="$ROOT_DIR/.venv/bin/uvicorn"
SERVICE_USER="${SERVICE_USER:-${SUDO_USER:-$(id -un)}}"
SERVICE_GROUP="${SERVICE_GROUP:-$(id -gn "$SERVICE_USER")}"

if [[ ! -x "$VENV_UVICORN" ]]; then
  echo "Missing uvicorn at: $VENV_UVICORN"
  echo "Create/install deps first:"
  echo "  cd $ROOT_DIR && python3 -m venv .venv && source .venv/bin/activate && pip install -r web_early_warning/requirements.txt"
  exit 1
fi

sed \
  -e "s#__ROOT_DIR__#$ROOT_DIR#g" \
  -e "s#__SERVICE_USER__#$SERVICE_USER#g" \
  -e "s#__SERVICE_GROUP__#$SERVICE_GROUP#g" \
  "$ROOT_DIR/web_early_warning/deploy/web_early_warning_scoring.service" \
  > /etc/systemd/system/web_early_warning_scoring.service
chmod 0644 /etc/systemd/system/web_early_warning_scoring.service

if [[ ! -f /etc/web_early_warning_scoring.env ]]; then
  install -m 0644 "$ROOT_DIR/web_early_warning/deploy/scoring.env.example" \
    /etc/web_early_warning_scoring.env
  echo "Created /etc/web_early_warning_scoring.env (edit it for your environment)."
fi

systemctl daemon-reload
systemctl enable --now web_early_warning_scoring.service
systemctl status --no-pager web_early_warning_scoring.service || true
