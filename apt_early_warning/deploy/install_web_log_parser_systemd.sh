#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash $0"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
VENV_PY="$ROOT_DIR/.venv/bin/python3"

if [[ ! -x "$VENV_PY" ]]; then
  echo "Missing venv python at: $VENV_PY"
  echo "Create/install deps first:"
  echo "  cd $ROOT_DIR && python3 -m venv .venv && source .venv/bin/activate && pip install -r apt_early_warning/requirements.txt"
  exit 1
fi

install -m 0644 "$ROOT_DIR/apt_early_warning/deploy/apt_early_warning_web_log_parser.service" \
  /etc/systemd/system/apt_early_warning_web_log_parser.service

if [[ ! -f /etc/apt_early_warning_web_log_parser.env ]]; then
  install -m 0644 "$ROOT_DIR/apt_early_warning/deploy/web_log_parser.env.example" \
    /etc/apt_early_warning_web_log_parser.env
  echo "Created /etc/apt_early_warning_web_log_parser.env (edit it for your environment)."
fi

systemctl daemon-reload
systemctl enable --now apt_early_warning_web_log_parser.service
systemctl status --no-pager apt_early_warning_web_log_parser.service || true
