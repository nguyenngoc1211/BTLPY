#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.model_selection import GroupShuffleSplit

from web_early_warning.feature_pipeline import (
    CANONICAL_ALIASES,
    FEATURE_PROFILES,
    normalize_label_binary_attack,
    transform_features,
)


def build_model() -> LGBMClassifier:
    return LGBMClassifier(
        objective="binary",
        n_estimators=400,
        learning_rate=0.05,
        num_leaves=31,
        min_child_samples=100,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_lambda=1.0,
        random_state=1337,
        n_jobs=-1,
        verbosity=-1,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--csv",
        default="flowFeatures.csv",
        help="Path to flowFeatures.csv",
    )
    ap.add_argument(
        "--out",
        default="web_early_warning/model_out_flowfeatures/lgbm_flowfeatures_binary.joblib",
        help="Output bundle path.",
    )
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument(
        "--feature-profile",
        choices=sorted(FEATURE_PROFILES.keys()),
        default="web_realtime_v1",
        help="Feature profile used for training/inference compatibility.",
    )
    ap.add_argument(
        "--split-mode",
        choices=["random_stratified", "srcip_group"],
        default="random_stratified",
        help="Train/test split strategy. srcip_group is stricter for anti-leakage.",
    )
    ap.add_argument(
        "--sample-frac",
        type=float,
        default=1.0,
        help="Optional down-sampling fraction in (0,1].",
    )
    args = ap.parse_args()

    # Read only columns needed by the selected feature profile to reduce RAM pressure.
    needed = set(FEATURE_PROFILES.get(args.feature_profile, []))
    needed.add("Label")
    if args.split_mode == "srcip_group":
        needed.add("SrcIP")
    for aliases in CANONICAL_ALIASES.values():
        for col in aliases:
            needed.add(col)
    df = pd.read_csv(
        args.csv,
        low_memory=False,
        usecols=lambda c: c in needed,
    )
    if "Label" not in df.columns:
        raise ValueError("Missing Label column in CSV.")
    df["Label"] = df["Label"].map(normalize_label_binary_attack)
    df = df.dropna(subset=["Label"])

    if args.sample_frac <= 0 or args.sample_frac > 1:
        raise ValueError("--sample-frac must be in (0,1].")
    if args.sample_frac < 1.0:
        df = df.sample(frac=args.sample_frac, random_state=1337)

    X = transform_features(df, args.feature_profile).astype("float32")
    y = df["Label"].astype(str)

    label_order = ["Benign", "WebAttack"]
    label_to_id = {name: i for i, name in enumerate(label_order)}
    id_to_label = {i: name for i, name in enumerate(label_order)}
    y_id = y.map(label_to_id)

    if args.split_mode == "srcip_group":
        if "SrcIP" not in df.columns:
            raise ValueError("SrcIP column is required for --split-mode srcip_group")
        groups = df["SrcIP"].astype(str).fillna("")
        gss = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=1337)
        train_idx, test_idx = next(gss.split(X, y_id, groups=groups))
        X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
        y_train, y_test = y_id.iloc[train_idx], y_id.iloc[test_idx]
    else:
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

    bundle = {
        "model": model,
        "feature_names": list(X.columns),
        "label_names": id_to_label,
        "meta": {
            "dataset": "flowFeatures.csv",
            "task": "binary_benign_vs_web_attack",
            "n_rows": int(df.shape[0]),
            "n_train": int(X_train.shape[0]),
            "n_test": int(X_test.shape[0]),
            "features": list(X.columns),
            "feature_profile": args.feature_profile,
            "split_mode": args.split_mode,
            "label_order": label_order,
            "source_columns": list(df.columns),
        },
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out_path)
    print(f"Saved bundle -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
