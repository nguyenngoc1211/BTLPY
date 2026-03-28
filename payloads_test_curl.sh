#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   bash payloads_test_curl.sh score
#   bash payloads_test_curl.sh ingest
#   bash payloads_test_curl.sh ingest_force
#   bash payloads_test_curl.sh llm
#   bash payloads_test_curl.sh llm3

MODE="${1:-score}"

case "$MODE" in
  score)
    curl -s -X POST "http://127.0.0.1:8000/score" \
      -H "Content-Type: application/json" \
      --data-binary @- <<'JSON'
{
  "features": {
    "Flow Duration": 1000000,
    "Total Fwd Packet": 10,
    "Total Bwd packets": 5,
    "Total Length of Fwd Packet": 5000,
    "Total Length of Bwd Packet": 2000,
    "Flow Bytes/s": 700,
    "Flow Packets/s": 1.5
  },
  "flow_meta": {
    "src_ip": "172.19.0.1",
    "dest_ip": "juice-shop",
    "dest_port": 3000,
    "proto": "6"
  }
}
JSON
    ;;

  ingest)
    curl -s -X POST "http://127.0.0.1:5678/webhook-test/apt-ingest" \
      -H "Content-Type: application/json" \
      --data-binary @- <<'JSON'
{
  "features": {
    "FlowDuration": 20000000,
    "TotFwdPkts": 40,
    "TotBwdPkts": 40,
    "TotLenFwdPkts": 0,
    "TotLenBwdPkts": 240000,
    "FlowByts/s": 12000,
    "FlowPkts/s": 4,
    "Protocol": 6,
    "DstPort": 80,
    "FlowIATMin": 0.01,
    "FlowIATMean": 0.4,
    "FlowIATStd": 0.2,
    "FwdPkts/s": 2,
    "BwdPkts/s": 2,
    "PktLenMean": 6000,
    "PktLenStd": 300,
    "InitFwdWinByts": 0,
    "InitBwdWinByts": 0
  },
  "flow_meta": {
    "src_ip": "172.19.0.1",
    "dest_ip": "juice-shop",
    "dest_port": 80,
    "proto": "6",
    "method": "GET",
    "path": "/",
    "status": 200,
    "source": "manual_test"
  }
}
JSON
    ;;

  ingest_force)
    curl -s -X POST "http://127.0.0.1:5678/webhook/apt-ingest" \
      -H "Content-Type: application/json" \
      --data-binary @- <<'JSON'
{
  "score": {
    "stage": "APT",
    "stage_id": 1,
    "confidence": 0.999,
    "proba": {
      "Benign": 0.001,
      "APT": 0.999
    },
    "decision": "ALERT",
    "severity": "HIGH"
  },
  "features": {
    "FlowDuration": 20000000,
    "TotFwdPkts": 40,
    "TotBwdPkts": 40,
    "TotLenFwdPkts": 0,
    "TotLenBwdPkts": 240000,
    "FlowByts/s": 12000,
    "FlowPkts/s": 4,
    "Protocol": 6,
    "DstPort": 80,
    "FlowIATMin": 0.01,
    "FlowIATMean": 0.4,
    "FlowIATStd": 0.2,
    "FwdPkts/s": 2,
    "BwdPkts/s": 2,
    "PktLenMean": 6000,
    "PktLenStd": 300,
    "InitFwdWinByts": 0,
    "InitBwdWinByts": 0
  },
  "flow_meta": {
    "src_ip": "172.19.0.1",
    "dest_ip": "juice-shop",
    "dest_port": 80,
    "proto": "6",
    "method": "GET",
    "path": "/",
    "status": 200,
    "source": "manual_test_force",
    "force_alert": true
  },
  "source": "web_events"
}
JSON
    ;;

  llm)
    curl -i -s -X POST "http://127.0.0.1:5678/webhook-test/apt-ingest-llm-fixed" \
      -H "Content-Type: application/json" \
      --data-binary @- <<'JSON'
{
  "src_ip": "172.19.0.1",
  "event": "suspicious_login_burst",
  "severity": 4,
  "timestamp": "2026-03-24T14:30:00Z"
}
JSON
    ;;

  llm3)
    for payload in \
      '{"src_ip":"172.19.0.1","event":"suspicious_login_burst","severity":4,"timestamp":"2026-03-24T14:30:00Z"}' \
      '{"src_ip":"172.19.0.1","event":"admin_path_scan","severity":5,"timestamp":"2026-03-24T14:31:00Z"}' \
      '{"src_ip":"172.19.0.1","event":"token_abuse_pattern","severity":5,"timestamp":"2026-03-24T14:32:00Z"}'
    do
      curl -i -s -X POST "http://127.0.0.1:5678/webhook/apt-ingest-llm-fixed" \
        -H "Content-Type: application/json" \
        -d "$payload"
      echo
      echo "----"
    done
    ;;

  *)
    echo "Unknown mode: $MODE"
    exit 1
    ;;
esac
