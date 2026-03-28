#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-prod}"   # prod | test
HOST="${N8N_HOST:-127.0.0.1}"
PORT="${N8N_PORT:-5678}"
PATH_NAME="${N8N_PATH:-apt-ingest-llm-fixed}"

if [[ "$MODE" == "test" ]]; then
  URL="http://${HOST}:${PORT}/webhook-test/${PATH_NAME}"
else
  URL="http://${HOST}:${PORT}/webhook/${PATH_NAME}"
fi

echo "POST $URL"

curl -i -s -X POST "$URL" \
  -H "Content-Type: application/json" \
  --data-binary @- <<'JSON'
{
  "features": {
    "FlowDuration": 30000000,
    "TotFwdPkts": 120,
    "TotBwdPkts": 15,
    "TotLenFwdPkts": 280000,
    "TotLenBwdPkts": 4000,
    "FlowByts/s": 950000,
    "FlowPkts/s": 220,
    "Protocol": 6,
    "DstPort": 4444,
    "FlowIATMin": 0.0001,
    "FlowIATMean": 0.002,
    "FlowIATStd": 0.0008,
    "FwdPkts/s": 200,
    "BwdPkts/s": 20,
    "PktLenMean": 2100,
    "PktLenStd": 1700,
    "InitFwdWinByts": 65535,
    "InitBwdWinByts": 1024
  },
  "flow_meta": {
    "src_ip": "172.19.0.1",
    "dest_ip": "juice-shop",
    "dest_port": 4444,
    "proto": "6",
    "force_alert": true,
    "source": "manual_demo_script"
  }
}
JSON

echo
