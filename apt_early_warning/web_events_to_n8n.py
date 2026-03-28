#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests

from apt_early_warning.feature_pipeline import FEATURE_PROFILES


def _parse_iso8601(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    s = str(ts).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _safe_float(v: Any) -> float:
    try:
        return float(v)
    except Exception:
        return 0.0


def _extract_payload(obj: Dict[str, Any]) -> Dict[str, Any]:
    # Accept multiple input shapes:
    # 1) {"payload":{"features":{...},"flow_meta":{...}}}
    # 2) {"features":{...},"flow_meta":{...}}
    # 3) flat flow-like event (feature keys on root)
    if isinstance(obj.get("payload"), dict):
        obj = obj["payload"]
    if isinstance(obj.get("features"), dict):
        return {
            "features": {k: _safe_float(v) for k, v in obj.get("features", {}).items()},
            "flow_meta": dict(obj.get("flow_meta") or {}),
        }

    rich_keys = set(FEATURE_PROFILES["web_monitor_rich_v2"])
    base_keys = {
        "Flow Duration",
        "Total Fwd Packet",
        "Total Bwd packets",
        "Total Length of Fwd Packet",
        "Total Length of Bwd Packet",
        "Flow Bytes/s",
        "Flow Packets/s",
    }
    features: Dict[str, float] = {}
    for k in rich_keys.union(base_keys):
        if k in obj:
            features[k] = _safe_float(obj.get(k))

    flow_meta = {
        "src_ip": str(obj.get("src_ip") or obj.get("SrcIP") or ""),
        "src_port": int(_safe_float(obj.get("src_port") or obj.get("SrcPort") or 0)),
        "dest_ip": str(obj.get("dest_ip") or obj.get("DstIP") or ""),
        "dest_port": int(_safe_float(obj.get("dest_port") or obj.get("DstPort") or 0)),
        "proto": str(obj.get("proto") or obj.get("Protocol") or ""),
        "src_timestamp": str(obj.get("timestamp") or obj.get("Timestamp") or ""),
    }
    # keep optional metadata if present
    for key in ("path", "method", "status", "host", "user_agent", "phase", "scenario_id"):
        if key in obj:
            flow_meta[key] = obj[key]
    return {"features": features, "flow_meta": flow_meta}


def tail_jsonl(path: str):
    last_inode = None
    f = None
    while True:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            time.sleep(1.0)
            continue
        except PermissionError:
            time.sleep(1.0)
            continue

        inode = (st.st_dev, st.st_ino)
        if f is None or inode != last_inode:
            if f:
                try:
                    f.close()
                except Exception:
                    pass
            f = open(path, "r", encoding="utf-8", errors="ignore")
            if last_inode is None:
                f.seek(0, os.SEEK_END)
            last_inode = inode

        line = f.readline()
        if not line:
            time.sleep(0.2)
            continue
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def _post_json(url: str, payload: Dict[str, Any], timeout_sec: int = 8) -> Dict[str, Any]:
    r = requests.post(url, json=payload, timeout=timeout_sec)
    if not r.ok:
        raise RuntimeError(f"POST {url} -> {r.status_code} {r.text[:300]}")
    try:
        return r.json()
    except Exception:
        return {}


def _init_alert_db(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc TEXT NOT NULL,
                stage TEXT,
                confidence REAL,
                severity TEXT,
                decision TEXT,
                src_ip TEXT,
                dest_ip TEXT,
                dest_port INTEGER,
                proto TEXT,
                method TEXT,
                path TEXT,
                status INTEGER,
                source TEXT,
                score_json TEXT NOT NULL,
                event_json TEXT NOT NULL
            )
            """
        )
        conn.commit()


def _save_alert(path: str, score: Dict[str, Any], payload: Dict[str, Any]) -> None:
    meta = payload.get("flow_meta") or {}
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            INSERT INTO alerts (
                ts_utc, stage, confidence, severity, decision,
                src_ip, dest_ip, dest_port, proto, method, path, status, source,
                score_json, event_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                str(score.get("stage") or ""),
                float(score.get("confidence") or 0.0),
                str(score.get("severity") or ""),
                str(score.get("decision") or ""),
                str(meta.get("src_ip") or ""),
                str(meta.get("dest_ip") or ""),
                int(_safe_float(meta.get("dest_port") or 0)),
                str(meta.get("proto") or ""),
                str(meta.get("method") or ""),
                str(meta.get("path") or ""),
                int(_safe_float(meta.get("status") or 0)),
                str(meta.get("source") or "web_events"),
                json.dumps(score, ensure_ascii=True, separators=(",", ":")),
                json.dumps(payload, ensure_ascii=True, separators=(",", ":")),
            ),
        )
        conn.commit()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--events-path",
        default=os.getenv("WEB_EVENTS_PATH", "/var/log/apt_web/events.jsonl"),
        help="Path to JSONL events file produced by web app/proxy collector.",
    )
    ap.add_argument(
        "--score-url",
        default=os.getenv("SCORE_URL", "http://127.0.0.1:8000/score"),
        help="Scoring API URL.",
    )
    ap.add_argument(
        "--n8n-webhook",
        default=os.getenv("N8N_WEBHOOK", ""),
        help="n8n webhook URL for alerts.",
    )
    ap.add_argument(
        "--alerts-db-path",
        default=os.getenv("ALERTS_DB_PATH", ""),
        help="Optional SQLite path to persist ALERT history.",
    )
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if not args.verbose:
        args.verbose = os.getenv("VERBOSE", "0") in {"1", "true", "TRUE", "yes", "YES"}
    if not args.n8n_webhook:
        raise SystemExit("Set N8N_WEBHOOK or pass --n8n-webhook.")
    if args.alerts_db_path:
        _init_alert_db(args.alerts_db_path)
        if args.verbose:
            print(f"ALERT DB: {args.alerts_db_path}", file=sys.stderr)

    for raw in tail_jsonl(args.events_path):
        try:
            payload = _extract_payload(raw)
            if not payload["features"]:
                continue
            score = _post_json(args.score_url, payload, timeout_sec=8)
            decision = str(score.get("decision") or "")
            if decision != "ALERT":
                if args.verbose:
                    print("NO_ALERT", score.get("stage"), score.get("confidence"), file=sys.stderr)
                continue
            out = {
                "score": score,
                "features": payload["features"],
                "flow_meta": payload.get("flow_meta") or {},
                "source": "web_events",
            }
            if args.alerts_db_path:
                _save_alert(args.alerts_db_path, score, payload)
            _post_json(args.n8n_webhook, out, timeout_sec=8)
            if args.verbose:
                print("ALERT", score.get("stage"), score.get("confidence"), file=sys.stderr)
        except Exception as e:
            if args.verbose:
                print(f"ERROR: {type(e).__name__}: {e}", file=sys.stderr)
            continue

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
