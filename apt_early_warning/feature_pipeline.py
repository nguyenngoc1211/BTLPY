from __future__ import annotations

from typing import Dict, List

import numpy as np
import pandas as pd


FLOWFEATURES_TO_CANONICAL: Dict[str, str] = {
    "FlowDuration": "Flow Duration",
    "TotFwdPkts": "Total Fwd Packet",
    "TotBwdPkts": "Total Bwd packets",
    "TotLenFwdPkts": "Total Length of Fwd Packet",
    "TotLenBwdPkts": "Total Length of Bwd Packet",
    "FlowByts/s": "Flow Bytes/s",
    "FlowPkts/s": "Flow Packets/s",
}

CANONICAL_BASE_FEATURES: List[str] = list(FLOWFEATURES_TO_CANONICAL.values())

# Support both compact flowFeatures names and canonical names from API payloads.
CANONICAL_ALIASES: Dict[str, List[str]] = {
    "Flow Duration": ["Flow Duration", "FlowDuration"],
    "Total Fwd Packet": ["Total Fwd Packet", "TotFwdPkts"],
    "Total Bwd packets": ["Total Bwd packets", "TotBwdPkts"],
    "Total Length of Fwd Packet": ["Total Length of Fwd Packet", "TotLenFwdPkts"],
    "Total Length of Bwd Packet": ["Total Length of Bwd Packet", "TotLenBwdPkts"],
    "Flow Bytes/s": ["Flow Bytes/s", "FlowByts/s"],
    "Flow Packets/s": ["Flow Packets/s", "FlowPkts/s"],
}

FEATURE_PROFILES: Dict[str, List[str]] = {
    "legacy7": CANONICAL_BASE_FEATURES,
    "web_realtime_v1": CANONICAL_BASE_FEATURES
    + [
        "Total Packets",
        "Total Bytes",
        "Fwd Bytes/Packet",
        "Bwd Bytes/Packet",
        "Flow Bytes/Packet",
        "Fwd Packet Ratio",
        "Bwd Packet Ratio",
        "Fwd/Bwd Byte Ratio",
        "Log Flow Duration",
        "Log Flow Bytes/s",
        "Log Flow Packets/s",
    ],
    # Rich profile for web monitoring dashboards when more flow columns are available.
    # Uses original flowFeatures columns directly (not only the 7-base subset).
    "web_monitor_rich_v2": [
        "FlowDuration",
        "TotFwdPkts",
        "TotBwdPkts",
        "TotLenFwdPkts",
        "TotLenBwdPkts",
        "FlowByts/s",
        "FlowPkts/s",
        "Protocol",
        "DstPort",
        "FlowIATMin",
        "FlowIATMean",
        "FlowIATStd",
        "FwdPkts/s",
        "BwdPkts/s",
        "PktLenMean",
        "PktLenStd",
        "InitFwdWinByts",
        "InitBwdWinByts",
    ],
}


def normalize_label_binary_apt(x: object) -> str | None:
    s = str(x).strip().upper()
    if s == "BENIGN":
        return "Benign"
    if s == "APT":
        return "APT"
    return None


def _pick_first_existing_column(df: pd.DataFrame, aliases: List[str]) -> pd.Series:
    for col in aliases:
        if col in df.columns:
            return pd.to_numeric(df[col], errors="coerce")
    return pd.Series([np.nan] * len(df), index=df.index, dtype="float64")


def build_base_features_frame(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    for canonical, aliases in CANONICAL_ALIASES.items():
        out[canonical] = _pick_first_existing_column(df, aliases)
    return out.fillna(0.0).astype(float)


def engineer_features(base: pd.DataFrame) -> pd.DataFrame:
    out = base.copy()
    eps = 1e-9

    total_packets = out["Total Fwd Packet"] + out["Total Bwd packets"]
    total_bytes = out["Total Length of Fwd Packet"] + out["Total Length of Bwd Packet"]

    out["Total Packets"] = total_packets
    out["Total Bytes"] = total_bytes
    out["Fwd Bytes/Packet"] = out["Total Length of Fwd Packet"] / np.maximum(out["Total Fwd Packet"], 1.0)
    out["Bwd Bytes/Packet"] = out["Total Length of Bwd Packet"] / np.maximum(out["Total Bwd packets"], 1.0)
    out["Flow Bytes/Packet"] = total_bytes / np.maximum(total_packets, 1.0)
    out["Fwd Packet Ratio"] = out["Total Fwd Packet"] / np.maximum(total_packets, eps)
    out["Bwd Packet Ratio"] = out["Total Bwd packets"] / np.maximum(total_packets, eps)
    out["Fwd/Bwd Byte Ratio"] = out["Total Length of Fwd Packet"] / np.maximum(
        out["Total Length of Bwd Packet"], eps
    )
    out["Log Flow Duration"] = np.log1p(np.maximum(out["Flow Duration"], 0.0))
    out["Log Flow Bytes/s"] = np.log1p(np.maximum(out["Flow Bytes/s"], 0.0))
    out["Log Flow Packets/s"] = np.log1p(np.maximum(out["Flow Packets/s"], 0.0))
    return out.replace([np.inf, -np.inf], 0.0).fillna(0.0)


def transform_features(df: pd.DataFrame, profile: str) -> pd.DataFrame:
    if profile not in FEATURE_PROFILES:
        raise ValueError(f"Unknown profile: {profile}")
    base = build_base_features_frame(df)
    if profile == "legacy7":
        out = base.copy()
    else:
        out = engineer_features(base)

    # For rich profiles, pass through original columns if they exist in input.
    # This lets training/inference consume extended flowFeatures-style columns.
    for col in FEATURE_PROFILES[profile]:
        if col not in out.columns and col in df.columns:
            out[col] = pd.to_numeric(df[col], errors="coerce")
        elif col not in out.columns and col in FLOWFEATURES_TO_CANONICAL:
            # Alias fallback: if profile asks compact flowFeatures column names
            # but input carries canonical names from API payload.
            canonical = FLOWFEATURES_TO_CANONICAL[col]
            if canonical in out.columns:
                out[col] = out[canonical]
    out = out.replace([np.inf, -np.inf], 0.0).fillna(0.0)
    wanted = FEATURE_PROFILES[profile]
    return out.reindex(columns=wanted, fill_value=0.0)
