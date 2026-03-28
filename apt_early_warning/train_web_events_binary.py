#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

import joblib
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

from apt_early_warning.feature_pipeline import FEATURE_PROFILES, transform_features


def build_model() -> LGBMClassifier:
    return LGBMClassifier(
        objective="binary",
        n_estimators=800,
        learning_rate=0.05,
        num_leaves=63,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_lambda=1.0,
        random_state=1337,
        n_jobs=-1,
        verbosity=-1,
    )


def _is_attack_event(obj: Dict[str, Any], ua_markers: List[str], path_markers: List[str]) -> bool:
    fm = obj.get("flow_meta") or {}
    ua = str(fm.get("user_agent") or "").lower()
    path = str(fm.get("path") or "").lower()

    if fm.get("force_alert") in {True, 1, "1", "true", "TRUE", "yes", "YES"}:
        return True

    if any(m in ua for m in ua_markers):
        return True

    if any(m in path for m in path_markers):
        return True

    # Optional weak signal: repeated auth failures in generated traffic.
    status = int(fm.get("status") or 0)
    if status in {401, 403, 404, 429} and ("k6" in ua or "suspicious" in ua):
        return True

    return False


def load_events(path: str, ua_markers: List[str], path_markers: List[str]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            features = obj.get("features")
            if not isinstance(features, dict) or not features:
                continue

            rec: Dict[str, Any] = dict(features)
            rec["Label"] = "APT" if _is_attack_event(obj, ua_markers, path_markers) else "Benign"
            rows.append(rec)

    if not rows:
        raise ValueError("No valid feature rows parsed from events JSONL.")
    return pd.DataFrame(rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--events-jsonl",
        default="security-demo-lab/logs/apt/events.jsonl",
        help="Path to events JSONL produced by web_accesslog_to_events.py",
    )
    ap.add_argument(
        "--out",
        default="apt_early_warning/model_out_flowfeatures/lgbm_web_events_k6_binary.joblib",
        help="Output bundle path.",
    )
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument(
        "--feature-profile",
        choices=sorted(FEATURE_PROFILES.keys()),
        default="web_monitor_rich_v2",
        help="Feature profile used for training/inference compatibility.",
    )
    ap.add_argument(
        "--max-benign-ratio",
        type=float,
        default=3.0,
        help="Downsample Benign to at most this multiple of APT samples.",
    )
    ap.add_argument(
        "--ua-markers",
        default="k6-suspicious,k6_suspicious,manual_test_force",
        help="Comma-separated markers in flow_meta.user_agent treated as APT-like.",
    )
    ap.add_argument(
        "--path-markers",
        default="/wp-admin,../../etc/passwd,jndi:,union+select,/rest/user/login",
        help="Comma-separated markers in flow_meta.path treated as APT-like.",
    )
    args = ap.parse_args()

    ua_markers = [x.strip().lower() for x in args.ua_markers.split(",") if x.strip()]
    path_markers = [x.strip().lower() for x in args.path_markers.split(",") if x.strip()]

    df = load_events(args.events_jsonl, ua_markers=ua_markers, path_markers=path_markers)

    apt_df = df[df["Label"] == "APT"]
    benign_df = df[df["Label"] == "Benign"]
    if len(apt_df) == 0:
        raise ValueError("No APT-like rows found. Adjust --ua-markers/--path-markers or generate attack traffic first.")

    max_benign = int(max(1, args.max_benign_ratio) * len(apt_df))
    if len(benign_df) > max_benign:
        benign_df = benign_df.sample(n=max_benign, random_state=1337)

    df = pd.concat([apt_df, benign_df], ignore_index=True).sample(frac=1.0, random_state=1337)

    X = transform_features(df, args.feature_profile)
    y = df["Label"].astype(str)

    label_order = ["Benign", "APT"]
    label_to_id = {name: i for i, name in enumerate(label_order)}
    id_to_label = {i: name for i, name in enumerate(label_order)}
    y_id = y.map(label_to_id)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_id,
        test_size=args.test_size,
        random_state=1337,
        stratify=y_id,
    )

    model = build_model()
    model.fit(X_train, y_train, eval_set=[(X_test, y_test)], eval_metric="binary_logloss")

    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=label_order, digits=4))
    y_proba = model.predict_proba(X_test)[:, 1]
    print(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.6f}")
    print("Class balance:", df["Label"].value_counts().to_dict())

    bundle = {
        "model": model,
        "feature_names": list(X.columns),
        "label_names": id_to_label,
        "meta": {
            "dataset": args.events_jsonl,
            "task": "binary_benign_vs_apt_like_web_events",
            "n_rows": int(df.shape[0]),
            "n_train": int(X_train.shape[0]),
            "n_test": int(X_test.shape[0]),
            "features": list(X.columns),
            "feature_profile": args.feature_profile,
            "label_order": label_order,
            "ua_markers": ua_markers,
            "path_markers": path_markers,
        },
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out_path)
    print(f"Saved bundle -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
