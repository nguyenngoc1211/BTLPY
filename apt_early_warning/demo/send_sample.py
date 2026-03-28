#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any, Dict

import requests


def _payload(force_alert: bool) -> Dict[str, Any]:
    return {
        "features": {
            "Flow Duration": 1_000_000,
            "Total Fwd Packet": 10,
            "Total Bwd packets": 5,
            "Total Length of Fwd Packet": 5_000,
            "Total Length of Bwd Packet": 2_000,
            "Flow Bytes/s": 700,
            "Flow Packets/s": 1.5,
        },
        "flow_meta": {
            "src_ip": "1.2.3.4",
            "src_port": 1234,
            "dest_ip": "5.6.7.8",
            "dest_port": 80,
            "proto": "TCP",
            "force_alert": bool(force_alert),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Send a demo payload to the n8n webhook.")
    ap.add_argument("--url", required=True, help="n8n webhook URL, e.g. http://localhost:5678/webhook/apt-ingest")
    ap.add_argument("--force-alert", action="store_true", help="Sets flow_meta.force_alert=true")
    args = ap.parse_args()

    r = requests.post(args.url, json=_payload(args.force_alert), timeout=15)
    r.raise_for_status()

    try:
        data = r.json()
    except Exception:
        print(r.text)
        return 0

    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

