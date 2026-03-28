#!/usr/bin/env bash
set -euo pipefail

EVE_PATH="${EVE_PATH:-/var/log/suricata/eve.json}"
SCORE_URL="${SCORE_URL:-http://127.0.0.1:8000/health}"
N8N_BASE_URL="${N8N_BASE_URL:-http://127.0.0.1:5678}"
COLLECTOR_SERVICE="${COLLECTOR_SERVICE:-apt_early_warning_web_collector.service}"
CHECK_SURICATA="${CHECK_SURICATA:-0}"

ok=0
warn=0

pass() {
  printf '[PASS] %s\n' "$1"
  ok=$((ok + 1))
}

fail() {
  printf '[FAIL] %s\n' "$1"
  warn=$((warn + 1))
}

section() {
  printf '\n== %s ==\n' "$1"
}

section "Suricata eve.json"
if [[ "$CHECK_SURICATA" == "0" ]]; then
  pass "Skipped Suricata check (CHECK_SURICATA=0)"
else
  if [[ -f "$EVE_PATH" ]]; then
    pass "Found eve file: $EVE_PATH"
    if [[ -r "$EVE_PATH" ]]; then
      pass "eve.json is readable"
      size="$(wc -c < "$EVE_PATH" 2>/dev/null || echo 0)"
      printf '  size_bytes=%s\n' "$size"
      tail_line="$(tail -n 1 "$EVE_PATH" 2>/dev/null || true)"
      if [[ -n "$tail_line" ]]; then
        pass "eve.json has content"
      else
        fail "eve.json exists but currently empty"
      fi
    else
      fail "eve.json exists but is not readable by current user"
    fi
  else
    fail "Missing eve file: $EVE_PATH"
  fi
fi

section "Scoring API"
if curl -fsS --max-time 3 "$SCORE_URL" >/tmp/apt_score_health.json 2>/dev/null; then
  pass "Reachable: $SCORE_URL"
  printf '  response=%s\n' "$(tr -d '\n' < /tmp/apt_score_health.json | head -c 300)"
else
  fail "Cannot reach: $SCORE_URL"
fi

section "n8n"
if curl -fsS --max-time 3 "$N8N_BASE_URL" >/dev/null 2>&1; then
  pass "Reachable: $N8N_BASE_URL"
else
  fail "Cannot reach: $N8N_BASE_URL"
fi

section "Collector Service"
if command -v systemctl >/dev/null 2>&1; then
  if ! systemctl list-unit-files >/dev/null 2>&1; then
    fail "systemctl exists but cannot access system bus (run this check on host shell)"
  elif systemctl list-unit-files 2>/dev/null | grep -q "^${COLLECTOR_SERVICE}"; then
    pass "Service installed: $COLLECTOR_SERVICE"
    state="$(systemctl is-active "$COLLECTOR_SERVICE" 2>/dev/null || true)"
    enabled="$(systemctl is-enabled "$COLLECTOR_SERVICE" 2>/dev/null || true)"
    printf '  active=%s enabled=%s\n' "${state:-unknown}" "${enabled:-unknown}"
    if [[ "$state" == "active" ]]; then
      pass "Service is active"
    else
      fail "Service is not active"
    fi
  else
    fail "Service not installed: $COLLECTOR_SERVICE"
  fi
else
  fail "systemctl not available on this host"
fi

printf '\nSummary: pass=%d fail=%d\n' "$ok" "$warn"
if (( warn > 0 )); then
  exit 1
fi
