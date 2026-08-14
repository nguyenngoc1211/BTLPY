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

from web_early_warning.feature_pipeline import (
    CANONICAL_ALIASES,
    FEATURE_PROFILES,
    normalize_label_binary_attack,
    transform_features,
)


def build_model() -> LGBMClassifier:
    return LGBMClassifier(
        objective="binary",
        n_estimators=500,
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

    status = int(fm.get("status") or 0)
    if status in {401, 403, 404, 429} and ("k6" in ua or "suspicious" in ua):
        return True
    return False


def load_web_events(events_jsonl: str, ua_markers: List[str], path_markers: List[str]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    with open(events_jsonl, "r", encoding="utf-8", errors="ignore") as f:
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
            rec["Label"] = "WebAttack" if _is_attack_event(obj, ua_markers, path_markers) else "Benign"
            rec["_source"] = "web_events"
            rows.append(rec)

    if not rows:
        raise ValueError("No valid feature rows from events JSONL")
    return pd.DataFrame(rows)


def load_flowfeatures(csv_path: str, sample_frac: float, feature_profile: str) -> pd.DataFrame:
    needed = set(FEATURE_PROFILES.get(feature_profile, []))
    needed.add("Label")
    for aliases in CANONICAL_ALIASES.values():
        for col in aliases:
            needed.add(col)
    df = pd.read_csv(
        csv_path,
        low_memory=False,
        usecols=lambda c: c in needed,
    )
    if "Label" not in df.columns:
        raise ValueError("Missing Label column in flowFeatures.csv")
    df["Label"] = df["Label"].map(normalize_label_binary_attack)
    df = df.dropna(subset=["Label"])
    if sample_frac < 1.0:
        df = df.sample(frac=sample_frac, random_state=1337)
    df["_source"] = "flowfeatures"
    return df


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="flowFeatures.csv")
    ap.add_argument("--events-jsonl", default="security-demo-lab/logs/web/events.jsonl")
    ap.add_argument("--out", default="web_early_warning/model_out_flowfeatures/lgbm_combined_flow_web_binary.joblib")
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--feature-profile", choices=sorted(FEATURE_PROFILES.keys()), default="web_monitor_rich_v2")
    ap.add_argument("--flow-sample-frac", type=float, default=0.05)
    ap.add_argument("--web-repeat", type=int, default=25, help="Repeat web events rows to increase web-event weight")
    ap.add_argument("--max-benign-ratio-web", type=float, default=3.0)
    ap.add_argument("--ua-markers", default="k6-suspicious,k6_suspicious,manual_test_force")
    ap.add_argument("--path-markers", default="/wp-admin,../../etc/passwd,jndi:,union+select,/rest/user/login")
    args = ap.parse_args()

    if not (0 < args.flow_sample_frac <= 1):
        raise ValueError("--flow-sample-frac must be in (0,1]")

    ua_markers = [x.strip().lower() for x in args.ua_markers.split(",") if x.strip()]
    path_markers = [x.strip().lower() for x in args.path_markers.split(",") if x.strip()]

    flow_df = load_flowfeatures(args.csv, args.flow_sample_frac, args.feature_profile)
    web_df = load_web_events(args.events_jsonl, ua_markers, path_markers)

    web_attack = web_df[web_df["Label"] == "WebAttack"]
    web_benign = web_df[web_df["Label"] == "Benign"]
    if len(web_attack) == 0:
        raise ValueError("No web-attack-like events found. Generate attack traffic first.")
    max_web_benign = int(max(1, args.max_benign_ratio_web) * len(web_attack))
    if len(web_benign) > max_web_benign:
        web_benign = web_benign.sample(n=max_web_benign, random_state=1337)
    web_df = pd.concat([web_attack, web_benign], ignore_index=True)

    if args.web_repeat > 1:
        web_df = pd.concat([web_df] * args.web_repeat, ignore_index=True)

    combined = pd.concat([flow_df, web_df], ignore_index=True).sample(frac=1.0, random_state=1337)

    X = transform_features(combined, args.feature_profile).astype("float32")
    y = combined["Label"].astype(str)

    label_order = ["Benign", "WebAttack"]
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

    print("Data sources:")
    print(flow_df["_source"].value_counts().to_dict())
    print(web_df["_source"].value_counts().to_dict())
    print("Combined labels:", combined["Label"].value_counts().to_dict())

    bundle = {
        "model": model,
        "feature_names": list(X.columns),
        "label_names": id_to_label,
        "meta": {
            "dataset": "combined_flowfeatures_plus_web_events",
            "task": "binary_benign_vs_web_attack_combined",
            "n_rows": int(combined.shape[0]),
            "n_train": int(X_train.shape[0]),
            "n_test": int(X_test.shape[0]),
            "features": list(X.columns),
            "feature_profile": args.feature_profile,
            "label_order": label_order,
            "flow_sample_frac": args.flow_sample_frac,
            "web_repeat": args.web_repeat,
            "events_jsonl": args.events_jsonl,
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
