#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score

from web_early_warning.feature_pipeline import normalize_label_binary_attack, transform_features


def _fmt_mb(path: Path) -> float:
    return path.stat().st_size / (1024 * 1024)


def _canon_label(x: Any) -> str | None:
    s = str(x).strip()
    if not s:
        return None
    up = s.upper()
    if up == "BENIGN":
        return "Benign"
    if up in {"WEBATTACK", "WEB_ATTACK", "ATTACK", "APT"}:
        return "WebAttack"
    return s


def _sample_payload() -> Dict[str, float]:
    return {
        "FlowDuration": 20_000_000.0,
        "TotFwdPkts": 40.0,
        "TotBwdPkts": 40.0,
        "TotLenFwdPkts": 0.0,
        "TotLenBwdPkts": 240_000.0,
        "FlowByts/s": 12_000.0,
        "FlowPkts/s": 4.0,
        "Protocol": 6.0,
        "DstPort": 80.0,
        "FlowIATMin": 0.01,
        "FlowIATMean": 0.05,
        "FlowIATStd": 0.2,
        "FwdPkts/s": 2.0,
        "BwdPkts/s": 2.0,
        "PktLenMean": 6000.0,
        "PktLenStd": 300.0,
        "InitFwdWinByts": 0.0,
        "InitBwdWinByts": 0.0,
    }


def _predict_one(bundle: Dict[str, Any], payload: Dict[str, float]) -> Dict[str, Any]:
    model = bundle["model"]
    feature_names: List[str] = list(bundle["feature_names"])
    label_names: Dict[int, str] = {int(k): str(v) for k, v in dict(bundle["label_names"]).items()}
    meta = bundle.get("meta") or {}
    profile = str(meta.get("feature_profile") or "")

    raw_df = pd.DataFrame([payload])
    if profile:
        x_df = transform_features(raw_df, profile).reindex(columns=feature_names, fill_value=0.0)
    else:
        x_df = raw_df.reindex(columns=feature_names, fill_value=0.0)

    proba = model.predict_proba(x_df)[0]
    classes = list(getattr(model, "classes_", range(len(proba))))
    best_idx = int(np.argmax(proba))
    best_class_id = int(classes[best_idx])
    stage = _canon_label(label_names.get(best_class_id, str(best_class_id))) or str(best_class_id)
    conf = float(proba[best_idx])

    proba_map: Dict[str, float] = {}
    for i, cls in enumerate(classes):
        key = _canon_label(label_names.get(int(cls), str(cls))) or str(cls)
        proba_map[key] = max(proba_map.get(key, 0.0), float(proba[i]))
    return {"stage": stage, "confidence": conf, "proba": proba_map}


def _model_stats(path: Path, bundle: Dict[str, Any]) -> Dict[str, Any]:
    model = bundle["model"]
    feature_names: List[str] = list(bundle["feature_names"])
    label_names = {_canon_label(v) or str(v) for v in dict(bundle["label_names"]).values()}
    meta = bundle.get("meta") or {}
    booster = getattr(model, "booster_", None)

    out = {
        "file": str(path),
        "size_mb": round(_fmt_mb(path), 3),
        "feature_profile": str(meta.get("feature_profile") or ""),
        "n_features": len(feature_names),
        "labels": sorted(label_names),
        "dataset": str(meta.get("dataset") or ""),
        "task": str(meta.get("task") or ""),
    }
    if booster is not None:
        out["num_trees"] = int(booster.num_trees())
        out["num_nonzero_importance_features"] = int(np.sum(model.feature_importances_ > 0))
    return out


def _eval_on_csv(bundle: Dict[str, Any], csv_path: Path, sample_frac: float) -> Dict[str, Any]:
    df = pd.read_csv(csv_path, low_memory=False)
    if "Label" not in df.columns:
        return {"error": "CSV missing Label column"}
    df["Label"] = df["Label"].map(normalize_label_binary_attack)
    df = df.dropna(subset=["Label"])
    if sample_frac < 1.0:
        df = df.sample(frac=sample_frac, random_state=1337)

    y = df["Label"].map({"Benign": 0, "WebAttack": 1})
    mask = y.notna()
    df = df.loc[mask]
    y = y.loc[mask].astype(int)
    if df.empty:
        return {"error": "No rows left after label normalization"}

    feature_names: List[str] = list(bundle["feature_names"])
    profile = str((bundle.get("meta") or {}).get("feature_profile") or "")
    if profile:
        x_df = transform_features(df, profile).reindex(columns=feature_names, fill_value=0.0)
    else:
        x_df = df.reindex(columns=feature_names, fill_value=0.0)

    model = bundle["model"]
    proba = model.predict_proba(x_df)[:, 1]
    pred = (proba >= 0.5).astype(int)

    return {
        "rows": int(len(df)),
        "auc": float(roc_auc_score(y, proba)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "accuracy": float(accuracy_score(y, pred)),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare multiple web threat model bundles (.joblib).")
    ap.add_argument(
        "--models",
        nargs="+",
        required=True,
        help="List of model bundle paths.",
    )
    ap.add_argument("--csv", default="", help="Optional flowFeatures CSV for quick eval.")
    ap.add_argument("--sample-frac", type=float, default=0.05, help="CSV eval sample fraction in (0,1].")
    ap.add_argument("--json", action="store_true", help="Print JSON output.")
    args = ap.parse_args()

    if args.csv and not (0 < args.sample_frac <= 1):
        raise ValueError("--sample-frac must be in (0,1].")

    sample = _sample_payload()
    rows: List[Dict[str, Any]] = []

    for m in args.models:
        path = Path(m)
        bundle = joblib.load(path)
        row = _model_stats(path, bundle)
        row["sample_prediction"] = _predict_one(bundle, sample)
        if args.csv:
            row["csv_eval"] = _eval_on_csv(bundle, Path(args.csv), args.sample_frac)
        rows.append(row)

    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=True))
        return 0

    for r in rows:
        print("=" * 80)
        print(f"model: {r['file']}")
        print(f"size_mb: {r['size_mb']}")
        print(f"profile: {r['feature_profile']}  n_features: {r['n_features']}  labels: {r['labels']}")
        if "num_trees" in r:
            print(
                f"num_trees: {r['num_trees']}  nonzero_importance_features: {r['num_nonzero_importance_features']}"
            )
        sp = r["sample_prediction"]
        print(f"sample_stage: {sp['stage']}  conf: {sp['confidence']:.6f}  proba: {sp['proba']}")
        if "csv_eval" in r:
            ev = r["csv_eval"]
            if "error" in ev:
                print(f"csv_eval_error: {ev['error']}")
            else:
                print(
                    "csv_eval:"
                    f" rows={ev['rows']} auc={ev['auc']:.6f} precision={ev['precision']:.6f}"
                    f" recall={ev['recall']:.6f} f1={ev['f1']:.6f} acc={ev['accuracy']:.6f}"
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

