#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import pandas as pd
import requests


FLOWFEATURES_TO_CANONICAL: Dict[str, str] = {
    "FlowDuration": "Flow Duration",
    "TotFwdPkts": "Total Fwd Packet",
    "TotBwdPkts": "Total Bwd packets",
    "TotLenFwdPkts": "Total Length of Fwd Packet",
    "TotLenBwdPkts": "Total Length of Bwd Packet",
    "FlowByts/s": "Flow Bytes/s",
    "FlowPkts/s": "Flow Packets/s",
}

FEATURE_COLS: List[str] = list(FLOWFEATURES_TO_CANONICAL.keys())
META_COLS: List[str] = ["SrcIP", "SrcPort", "DstIP", "DstPort", "Protocol", "Timestamp"]


@dataclass(frozen=True)
class Event:
    event_id: int
    ts: datetime
    payload: Dict[str, Any]


def _normalize_label(x: object) -> str:
    s = str(x).strip().upper()
    if s == "BENIGN":
        return "Benign"
    if s == "APT":
        return "APT"
    return "Unknown"


def _safe_float(v: Any) -> float:
    try:
        f = float(v)
    except Exception:
        return 0.0
    if pd.isna(f):
        return 0.0
    if f == float("inf") or f == float("-inf"):
        return 0.0
    return f


def _choose_rows(df: pd.DataFrame, n: int, rnd: random.Random) -> pd.DataFrame:
    if n <= 0 or df.empty:
        return df.iloc[0:0]
    n = min(n, len(df))
    idx = rnd.sample(list(df.index), n)
    return df.loc[idx]


def _score_intensity(df: pd.DataFrame) -> pd.Series:
    cols = ["FlowByts/s", "FlowPkts/s", "TotLenFwdPkts", "TotLenBwdPkts"]
    safe = df[cols].apply(pd.to_numeric, errors="coerce").fillna(0.0).clip(lower=0.0)
    rank_mean = safe.rank(pct=True).mean(axis=1)
    return rank_mean


def _to_payload(row: pd.Series, campaign_id: int, phase: str, expected: str) -> Dict[str, Any]:
    features: Dict[str, float] = {}
    for source, canonical in FLOWFEATURES_TO_CANONICAL.items():
        features[canonical] = _safe_float(row.get(source))

    flow_meta = {
        "src_ip": str(row.get("SrcIP", "0.0.0.0")),
        "src_port": int(_safe_float(row.get("SrcPort"))),
        "dest_ip": str(row.get("DstIP", "0.0.0.0")),
        "dest_port": int(_safe_float(row.get("DstPort"))),
        "proto": str(row.get("Protocol", "0")),
        "src_timestamp": str(row.get("Timestamp", "")),
        "scenario_id": f"campaign-{campaign_id:03d}",
        "phase": phase,
        "expected_label": expected,
        # Keep this realistic; do not use force flags.
        "force_alert": False,
    }
    return {"features": features, "flow_meta": flow_meta}


def _interleave(
    baseline: Iterable[pd.Series],
    campaign: Iterable[pd.Series],
    baseline_every: int,
) -> List[pd.Series]:
    out: List[pd.Series] = []
    b = list(baseline)
    c = list(campaign)
    bi = 0
    for i, item in enumerate(c):
        out.append(item)
        if baseline_every > 0 and (i + 1) % baseline_every == 0 and bi < len(b):
            out.append(b[bi])
            bi += 1
    out.extend(b[bi:])
    return out


def build_scenario(
    df: pd.DataFrame,
    campaigns: int,
    baseline_window: int,
    phase_size: int,
    baseline_every: int,
    seed: int,
    min_gap_ms: int,
    max_gap_ms: int,
) -> List[Event]:
    rnd = random.Random(seed)
    working = df.copy()
    working["LabelNorm"] = working["Label"].map(_normalize_label) if "Label" in working.columns else "Unknown"
    working[FEATURE_COLS] = working[FEATURE_COLS].apply(pd.to_numeric, errors="coerce").fillna(0.0)

    benign_pool = working[working["LabelNorm"] == "Benign"]
    apt_pool = working[working["LabelNorm"] == "APT"]
    if apt_pool.empty:
        raise ValueError("Dataset does not contain 'APT' rows after normalization.")
    if benign_pool.empty:
        raise ValueError("Dataset does not contain 'BENIGN' rows after normalization.")

    apt_scored = apt_pool.assign(_intensity=_score_intensity(apt_pool))
    q1 = apt_scored["_intensity"].quantile(0.33)
    q2 = apt_scored["_intensity"].quantile(0.66)
    phase_low = apt_scored[apt_scored["_intensity"] <= q1]
    phase_mid = apt_scored[(apt_scored["_intensity"] > q1) & (apt_scored["_intensity"] <= q2)]
    phase_high = apt_scored[apt_scored["_intensity"] > q2]

    if phase_low.empty or phase_mid.empty or phase_high.empty:
        raise ValueError("Unable to split APT pool into 3 intensity phases. Need more varied rows.")

    events: List[Event] = []
    now = datetime.now(timezone.utc)
    event_id = 1

    for campaign_id in range(1, campaigns + 1):
        pre_baseline = _choose_rows(benign_pool, baseline_window, rnd)
        low_rows = _choose_rows(phase_low, phase_size, rnd)
        mid_rows = _choose_rows(phase_mid, phase_size, rnd)
        high_rows = _choose_rows(phase_high, phase_size, rnd)
        post_baseline = _choose_rows(benign_pool, baseline_window, rnd)

        sequence: List[tuple[pd.Series, str, str]] = []
        for _, row in pre_baseline.iterrows():
            sequence.append((row, "baseline_pre", "Benign"))

        mixed_low = _interleave(
            baseline=_choose_rows(benign_pool, max(1, phase_size // max(1, baseline_every)), rnd).iterrows(),
            campaign=low_rows.iterrows(),
            baseline_every=baseline_every,
        )
        for _, row in mixed_low:
            expected = "APT" if _normalize_label(row.get("Label")) == "APT" else "Benign"
            phase = "phase_1_low_signal" if expected == "APT" else "noise"
            sequence.append((row, phase, expected))

        mixed_mid = _interleave(
            baseline=_choose_rows(benign_pool, max(1, phase_size // max(1, baseline_every)), rnd).iterrows(),
            campaign=mid_rows.iterrows(),
            baseline_every=baseline_every,
        )
        for _, row in mixed_mid:
            expected = "APT" if _normalize_label(row.get("Label")) == "APT" else "Benign"
            phase = "phase_2_medium_signal" if expected == "APT" else "noise"
            sequence.append((row, phase, expected))

        mixed_high = _interleave(
            baseline=_choose_rows(benign_pool, max(1, phase_size // max(1, baseline_every)), rnd).iterrows(),
            campaign=high_rows.iterrows(),
            baseline_every=baseline_every,
        )
        for _, row in mixed_high:
            expected = "APT" if _normalize_label(row.get("Label")) == "APT" else "Benign"
            phase = "phase_3_high_signal" if expected == "APT" else "noise"
            sequence.append((row, phase, expected))

        for _, row in post_baseline.iterrows():
            sequence.append((row, "baseline_post", "Benign"))

        for row, phase, expected in sequence:
            gap = rnd.randint(min_gap_ms, max_gap_ms)
            now = now + timedelta(milliseconds=gap)
            events.append(
                Event(
                    event_id=event_id,
                    ts=now,
                    payload=_to_payload(row=row, campaign_id=campaign_id, phase=phase, expected=expected),
                )
            )
            event_id += 1

    return events


def save_jsonl(events: List[Event], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for ev in events:
            line = {
                "event_id": ev.event_id,
                "scheduled_at": ev.ts.isoformat(),
                "payload": ev.payload,
            }
            f.write(json.dumps(line, ensure_ascii=True) + "\n")


def replay(events: List[Event], url: str, delay_ms: int, timeout_s: int) -> Dict[str, Any]:
    ok = 0
    failed = 0
    alert = 0
    no_alert = 0
    http_errors: List[str] = []

    for ev in events:
        try:
            r = requests.post(url, json=ev.payload, timeout=timeout_s)
            r.raise_for_status()
            ok += 1
            try:
                resp = r.json()
            except Exception:
                resp = {}
            decision = str(resp.get("decision", "")).upper()
            if decision == "ALERT":
                alert += 1
            elif decision == "NO_ALERT":
                no_alert += 1
        except Exception as e:
            failed += 1
            http_errors.append(f"event_id={ev.event_id}: {type(e).__name__}: {e}")
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

    return {
        "sent": len(events),
        "ok": ok,
        "failed": failed,
        "alert": alert,
        "no_alert": no_alert,
        "errors": http_errors[:20],
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate a realistic defensive replay scenario from flowFeatures.csv and optionally send it to webhook."
    )
    ap.add_argument("--csv", default="flowFeatures.csv", help="Path to flowFeatures.csv")
    ap.add_argument(
        "--out-jsonl",
        default="apt_early_warning/demo/scenario_replay.jsonl",
        help="Output JSONL path.",
    )
    ap.add_argument("--campaigns", type=int, default=1, help="Number of campaign timelines to generate.")
    ap.add_argument("--baseline-window", type=int, default=30, help="Benign events before and after a campaign.")
    ap.add_argument("--phase-size", type=int, default=20, help="APT events per phase.")
    ap.add_argument(
        "--baseline-every",
        type=int,
        default=4,
        help="Inject one benign event every N campaign events in each phase.",
    )
    ap.add_argument("--seed", type=int, default=1337, help="Random seed.")
    ap.add_argument("--min-gap-ms", type=int, default=300, help="Minimum event gap in ms.")
    ap.add_argument("--max-gap-ms", type=int, default=1800, help="Maximum event gap in ms.")
    ap.add_argument("--max-events", type=int, default=0, help="Truncate to first N events (0 = no limit).")
    ap.add_argument("--url", default="", help="Webhook URL. If set, events are replayed to this endpoint.")
    ap.add_argument("--delay-ms", type=int, default=150, help="Delay between sends when --url is set.")
    ap.add_argument("--timeout-s", type=int, default=15, help="HTTP timeout per request.")
    args = ap.parse_args()

    usecols = FEATURE_COLS + META_COLS + ["Label"]
    df = pd.read_csv(args.csv, usecols=lambda c: c in set(usecols), low_memory=False)
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required feature columns: {missing}")
    if "Label" not in df.columns:
        raise ValueError("Missing required Label column in CSV.")

    events = build_scenario(
        df=df,
        campaigns=max(1, args.campaigns),
        baseline_window=max(1, args.baseline_window),
        phase_size=max(1, args.phase_size),
        baseline_every=max(1, args.baseline_every),
        seed=args.seed,
        min_gap_ms=max(1, args.min_gap_ms),
        max_gap_ms=max(args.min_gap_ms, args.max_gap_ms),
    )

    if args.max_events > 0:
        events = events[: args.max_events]

    out_path = Path(args.out_jsonl)
    save_jsonl(events=events, out_path=out_path)
    print(f"Saved scenario: {out_path} ({len(events)} events)")

    if args.url:
        summary = replay(events=events, url=args.url, delay_ms=max(0, args.delay_ms), timeout_s=max(1, args.timeout_s))
        print(json.dumps(summary, indent=2, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
