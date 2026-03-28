#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from apt_early_warning.inference_service import ScoreRequest, health, score


def main() -> int:
    ap = argparse.ArgumentParser(description="Smoke-check the APT Early Warning scoring bundle + policy.")
    ap.add_argument(
        "--force-alert",
        action="store_true",
        help="Sets flow_meta.force_alert=true to test the ALERT path end-to-end.",
    )
    args = ap.parse_args()

    h = health()
    if not h.get("bundle_loaded"):
        print(json.dumps(h, indent=2, sort_keys=True))
        return 2

    req = ScoreRequest(
        features={
            "Flow Duration": 1_000_000,
            "Total Fwd Packet": 10,
            "Total Bwd packets": 5,
            "Total Length of Fwd Packet": 5_000,
            "Total Length of Bwd Packet": 2_000,
            "Flow Bytes/s": 700,
            "Flow Packets/s": 1.5,
        },
        flow_meta={"force_alert": bool(args.force_alert)},
    )
    resp = score(req)

    print("health:")
    print(json.dumps(h, indent=2, sort_keys=True))
    print("\nsample_score:")
    print(json.dumps(resp.model_dump(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

