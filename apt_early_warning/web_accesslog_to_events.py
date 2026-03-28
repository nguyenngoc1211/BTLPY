#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, Optional, Tuple


COMMON_LOG_RE = re.compile(
    r'^(?P<src_ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<httpver>[^"]+)" '
    r'(?P<status>\d{3}) (?P<body_bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(float(v))
    except Exception:
        return default


def _parse_ts_apache(ts: str) -> datetime:
    # Example: 24/Mar/2026:18:30:10 +0700
    dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
    return dt.astimezone(timezone.utc)


def _parse_ts_guess(raw: str) -> datetime:
    s = str(raw).strip()
    if not s:
        return _now_utc()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Try ISO first.
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        pass
    # Try Apache/Nginx combined format.
    try:
        return _parse_ts_apache(s)
    except Exception:
        return _now_utc()


def _parse_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None

    # JSON log line (recommended for nginx custom log_format json).
    if line.startswith("{") and line.endswith("}"):
        try:
            obj = json.loads(line)
        except Exception:
            return None
        src_ip = str(obj.get("remote_addr") or obj.get("src_ip") or "")
        ts = _parse_ts_guess(obj.get("time_iso8601") or obj.get("timestamp") or obj.get("time_local") or "")
        method = str(obj.get("request_method") or obj.get("method") or "")
        path = str(obj.get("request_uri") or obj.get("path") or obj.get("uri") or "")
        status = _safe_int(obj.get("status"), 0)
        body_bytes = _safe_float(obj.get("body_bytes_sent") or obj.get("bytes_sent") or 0.0)
        request_time = _safe_float(obj.get("request_time"), 0.0)
        dst_port = _safe_int(obj.get("server_port") or obj.get("dst_port"), 0)
        host = str(obj.get("host") or obj.get("server_name") or "")
        user_agent = str(obj.get("http_user_agent") or obj.get("user_agent") or "")
        proto = 6
        return {
            "src_ip": src_ip,
            "ts": ts,
            "method": method,
            "path": path,
            "status": status,
            "body_bytes": body_bytes,
            "request_time": request_time,
            "dst_port": dst_port,
            "host": host,
            "user_agent": user_agent,
            "proto": proto,
        }

    # Common/combined access log line.
    m = COMMON_LOG_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    body_raw = g["body_bytes"]
    body_bytes = 0.0 if body_raw == "-" else _safe_float(body_raw, 0.0)
    return {
        "src_ip": str(g.get("src_ip") or ""),
        "ts": _parse_ts_guess(g.get("ts") or ""),
        "method": str(g.get("method") or ""),
        "path": str(g.get("path") or ""),
        "status": _safe_int(g.get("status"), 0),
        "body_bytes": body_bytes,
        "request_time": 0.0,
        "dst_port": 80,
        "host": "",
        "user_agent": str(g.get("user_agent") or ""),
        "proto": 6,
    }


@dataclass
class Bucket:
    start_ts: datetime
    end_ts: datetime
    src_ip: str
    dst_port: int
    proto: int
    host: str
    method: str
    path: str
    status_last: int
    ua_last: str

    req_count: int = 0
    total_resp_bytes: float = 0.0

    iat_count: int = 0
    iat_mean: float = 0.0
    iat_m2: float = 0.0
    iat_min: float = 0.0

    pkt_count: int = 0
    pkt_mean: float = 0.0
    pkt_m2: float = 0.0

    def update(self, ev: Dict[str, Any]) -> None:
        ts = ev["ts"]
        prev_end = self.end_ts
        if ts < self.start_ts:
            self.start_ts = ts
        if ts > self.end_ts:
            self.end_ts = ts

        self.req_count += 1
        b = max(0.0, float(ev.get("body_bytes") or 0.0))
        self.total_resp_bytes += b

        # packet-size proxy stats (response size as packet-like proxy).
        self.pkt_count += 1
        delta_pkt = b - self.pkt_mean
        self.pkt_mean += delta_pkt / self.pkt_count
        self.pkt_m2 += delta_pkt * (b - self.pkt_mean)

        # inter-arrival stats by request timestamp deltas.
        gap = 0.0
        if self.req_count > 1:
            gap = max(0.0, (ts - prev_end).total_seconds()) if ts > prev_end else 0.0
        if self.req_count > 1:
            if self.iat_count == 0:
                self.iat_min = gap
            else:
                self.iat_min = min(self.iat_min, gap)
            self.iat_count += 1
            delta_iat = gap - self.iat_mean
            self.iat_mean += delta_iat / self.iat_count
            self.iat_m2 += delta_iat * (gap - self.iat_mean)

        # keep latest context for flow_meta.
        self.status_last = _safe_int(ev.get("status"), self.status_last)
        self.ua_last = str(ev.get("user_agent") or self.ua_last)
        self.method = str(ev.get("method") or self.method)
        self.path = str(ev.get("path") or self.path)
        self.host = str(ev.get("host") or self.host)

    def to_event(self) -> Dict[str, Any]:
        duration_s = max(0.001, (self.end_ts - self.start_ts).total_seconds())
        duration_us = duration_s * 1_000_000.0
        fwd_pkts = float(self.req_count)
        bwd_pkts = float(self.req_count)
        fwd_bytes = 0.0
        bwd_bytes = float(self.total_resp_bytes)
        total_pkts = fwd_pkts + bwd_pkts

        flow_bytes_s = (fwd_bytes + bwd_bytes) / duration_s
        flow_pkts_s = total_pkts / duration_s
        fwd_pkts_s = fwd_pkts / duration_s
        bwd_pkts_s = bwd_pkts / duration_s

        pkt_var = (self.pkt_m2 / self.pkt_count) if self.pkt_count > 1 else 0.0
        pkt_std = math.sqrt(max(0.0, pkt_var))
        iat_std = math.sqrt(max(0.0, (self.iat_m2 / self.iat_count))) if self.iat_count > 1 else 0.0

        features = {
            "FlowDuration": duration_us,
            "TotFwdPkts": fwd_pkts,
            "TotBwdPkts": bwd_pkts,
            "TotLenFwdPkts": fwd_bytes,
            "TotLenBwdPkts": bwd_bytes,
            "FlowByts/s": flow_bytes_s,
            "FlowPkts/s": flow_pkts_s,
            "Protocol": float(self.proto),
            "DstPort": float(self.dst_port),
            "FlowIATMin": float(self.iat_min),
            "FlowIATMean": float(self.iat_mean),
            "FlowIATStd": float(iat_std),
            "FwdPkts/s": float(fwd_pkts_s),
            "BwdPkts/s": float(bwd_pkts_s),
            "PktLenMean": float(self.pkt_mean),
            "PktLenStd": float(pkt_std),
            "InitFwdWinByts": 0.0,
            "InitBwdWinByts": 0.0,
        }
        flow_meta = {
            "src_ip": self.src_ip,
            "dest_ip": self.host or "web-service",
            "dest_port": int(self.dst_port),
            "proto": str(self.proto),
            "method": self.method,
            "path": self.path,
            "status": int(self.status_last),
            "user_agent": self.ua_last,
            "window_start": self.start_ts.isoformat(),
            "window_end": self.end_ts.isoformat(),
            "source": "access_log",
        }
        return {"features": features, "flow_meta": flow_meta}


def tail_lines(path: str) -> Iterator[str]:
    last_inode: Optional[Tuple[int, int]] = None
    f = None
    while True:
        try:
            st = os.stat(path)
        except FileNotFoundError:
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
        yield line


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--access-log-path",
        default=os.getenv("WEB_ACCESS_LOG_PATH", "/var/log/nginx/access.log"),
        help="Path to access log (combined or json-line).",
    )
    ap.add_argument(
        "--out-events-path",
        default=os.getenv("WEB_EVENTS_PATH", "/var/log/apt_web/events.jsonl"),
        help="Output JSONL path consumed by web_events_to_n8n.py",
    )
    ap.add_argument("--window-sec", type=int, default=int(os.getenv("WEB_FLOW_WINDOW_SEC", "20")))
    ap.add_argument("--min-requests", type=int, default=int(os.getenv("WEB_FLOW_MIN_REQUESTS", "3")))
    ap.add_argument("--flush-interval-sec", type=int, default=int(os.getenv("WEB_FLOW_FLUSH_SEC", "3")))
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if not args.verbose:
        args.verbose = os.getenv("VERBOSE", "0") in {"1", "true", "TRUE", "yes", "YES"}

    out_dir = os.path.dirname(args.out_events_path) or "."
    os.makedirs(out_dir, exist_ok=True)
    buckets: Dict[Tuple[str, int, int, int], Bucket] = {}
    last_flush = time.time()

    def window_id(ts: datetime) -> int:
        return int(ts.timestamp()) // max(1, args.window_sec)

    def flush_old(force: bool = False) -> None:
        now = _now_utc()
        now_wid = window_id(now)
        to_drop = []
        for key, b in buckets.items():
            wid = key[3]
            if force or wid < now_wid:
                if b.req_count >= max(1, args.min_requests):
                    event = b.to_event()
                    with open(args.out_events_path, "a", encoding="utf-8") as fw:
                        fw.write(json.dumps(event, ensure_ascii=True) + "\n")
                    if args.verbose:
                        print(
                            f"EMIT src={b.src_ip} port={b.dst_port} req={b.req_count} dur_us={int(event['features']['FlowDuration'])}",
                            flush=True,
                        )
                to_drop.append(key)
        for k in to_drop:
            buckets.pop(k, None)

    for line in tail_lines(args.access_log_path):
        ev = _parse_line(line)
        if ev is None:
            continue
        ts: datetime = ev["ts"]
        key = (
            str(ev.get("src_ip") or ""),
            int(ev.get("dst_port") or 0),
            int(ev.get("proto") or 6),
            window_id(ts),
        )
        if key not in buckets:
            buckets[key] = Bucket(
                start_ts=ts,
                end_ts=ts,
                src_ip=key[0],
                dst_port=key[1],
                proto=key[2],
                host=str(ev.get("host") or ""),
                method=str(ev.get("method") or ""),
                path=str(ev.get("path") or ""),
                status_last=int(ev.get("status") or 0),
                ua_last=str(ev.get("user_agent") or ""),
            )
        buckets[key].update(ev)

        now = time.time()
        if now - last_flush >= max(1, args.flush_interval_sec):
            flush_old(force=False)
            last_flush = now

    flush_old(force=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
