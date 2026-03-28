from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import sqlite3
import threading
import warnings
from typing import Any, Dict, List, Optional

warnings.filterwarnings(
    "ignore",
    message=r".*joblib will operate in serial mode.*",
    category=UserWarning,
)

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from apt_early_warning.feature_pipeline import transform_features


@dataclass(frozen=True)
class ModelBundle:
    model: Any
    feature_names: List[str]
    label_names: Dict[int, str]
    path: str
    feature_profile: str


_bundle_lock = threading.Lock()
_bundle: Optional[ModelBundle] = None
_bundle_error: Optional[str] = None


def _default_bundle_path() -> str:
    env = os.getenv("BUNDLE_PATH")
    if env:
        return env
    preferred = "apt_early_warning/model_out_flowfeatures/lgbm_flowfeatures_binary.joblib"
    return preferred


def _default_alerts_db_path() -> str:
    return os.getenv("ALERTS_DB_PATH", "/var/log/apt_web/alerts.db")


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_csv_list(name: str, default_csv: str) -> List[str]:
    raw = os.getenv(name, default_csv)
    return [s.strip() for s in raw.split(",") if s.strip()]


def _is_binary_apt_setup(labels: List[str]) -> bool:
    s = {x.strip() for x in labels}
    return "Benign" in s and "APT" in s and len(s) <= 2


def _policy_defaults(labels: List[str]) -> Dict[str, Any]:
    if _is_binary_apt_setup(labels):
        # Binary setup (Benign/APT): aggressively alert if model predicts APT.
        return {
            "alert_labels_csv": "APT",
            "min_conf_high_impact": 0.50,
            "min_conf_non_benign": 0.50,
            "policy_mode": "binary_apt",
        }
    return {
        "alert_labels_csv": "Lateral Movement,Data Exfiltration",
        "min_conf_high_impact": 0.55,
        "min_conf_non_benign": 0.80,
        "policy_mode": "staged_attack",
    }


def _load_bundle(path: str) -> ModelBundle:
    bundle = joblib.load(path)
    meta = bundle.get("meta") or {}
    return ModelBundle(
        model=bundle["model"],
        feature_names=list(bundle["feature_names"]),
        label_names=dict(bundle["label_names"]),
        path=path,
        feature_profile=str(meta.get("feature_profile") or "legacy7"),
    )


def get_bundle() -> Optional[ModelBundle]:
    global _bundle, _bundle_error
    path = _default_bundle_path()
    with _bundle_lock:
        if _bundle is not None and _bundle.path == path:
            return _bundle
        try:
            _bundle = _load_bundle(path)
            _bundle_error = None
        except Exception as e:
            _bundle = None
            _bundle_error = f"{type(e).__name__}: {e}"
        return _bundle

app = FastAPI(title="APT Early Warning - Stage Scoring API")


class ScoreRequest(BaseModel):
    features: Dict[str, float] = Field(..., description="Feature map")
    flow_meta: Optional[Dict[str, Any]] = None


class ScoreResponse(BaseModel):
    stage: str
    stage_id: int
    confidence: float
    proba: Dict[str, float]
    decision: str
    severity: str
    flow_meta: Optional[Dict[str, Any]] = None
    used_features: Dict[str, float]


def decide(stage: str, conf: float, labels: List[str]) -> tuple[str, str]:
    # Minimal SOC-style policy (configurable via env):
    # - ALERT_STAGES / ALERT_LABELS: comma-separated labels that should alert at lower confidence.
    # - ALERT_MIN_CONF_HIGH_IMPACT: threshold for labels in ALERT_STAGES/ALERT_LABELS.
    # - ALERT_MIN_CONF_NON_BENIGN: threshold for any non-Benign label.
    defaults = _policy_defaults(labels)
    default_alert_csv = defaults["alert_labels_csv"]
    alert_stages = set(
        _env_csv_list(
            "ALERT_LABELS",
            os.getenv("ALERT_STAGES", default_alert_csv),
        )
    )
    min_conf_high_impact = _env_float(
        "ALERT_MIN_CONF_HIGH_IMPACT", defaults["min_conf_high_impact"]
    )
    min_conf_non_benign = _env_float(
        "ALERT_MIN_CONF_NON_BENIGN", defaults["min_conf_non_benign"]
    )

    if stage in alert_stages and conf >= min_conf_high_impact:
        return "ALERT", "HIGH"
    if stage != "Benign" and conf >= min_conf_non_benign:
        return "ALERT", "MEDIUM"
    return "NO_ALERT", "LOW"


@app.get("/health")
def health() -> Dict[str, Any]:
    bundle = get_bundle()
    labels = list(bundle.label_names.values()) if bundle else []
    defaults = _policy_defaults(labels)
    default_alert_csv = defaults["alert_labels_csv"]
    return {
        "ok": True,
        "bundle_loaded": bundle is not None,
        "bundle_path": _default_bundle_path(),
        "bundle_error": _bundle_error,
        "policy": {
            "mode": defaults["policy_mode"],
            "alert_labels": _env_csv_list(
                "ALERT_LABELS", os.getenv("ALERT_STAGES", default_alert_csv)
            ),
            "min_conf_high_impact": _env_float(
                "ALERT_MIN_CONF_HIGH_IMPACT", defaults["min_conf_high_impact"]
            ),
            "min_conf_non_benign": _env_float(
                "ALERT_MIN_CONF_NON_BENIGN", defaults["min_conf_non_benign"]
            ),
        },
        "n_features": len(bundle.feature_names) if bundle else None,
        "n_classes": len(bundle.label_names) if bundle else None,
        "feature_profile": bundle.feature_profile if bundle else None,
    }


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest) -> ScoreResponse:
    bundle = get_bundle()
    if bundle is None:
        raise HTTPException(
            status_code=503,
            detail="Model bundle not loaded. Check BUNDLE_PATH and bundle file readability.",
        )

    # Keep payload schema stable: callers can continue sending base flow features.
    # Service expands/transforms them to the model's trained feature profile.
    raw_df = pd.DataFrame([req.features])
    transformed = transform_features(raw_df, bundle.feature_profile)
    X = transformed.reindex(columns=bundle.feature_names, fill_value=0.0)
    row = {k: float(X.iloc[0][k]) for k in bundle.feature_names}

    # LightGBM's sklearn wrapper supports predict_proba directly.
    proba = bundle.model.predict_proba(X)[0]
    classes = list(getattr(bundle.model, "classes_", range(len(proba))))
    best_idx = int(np.argmax(proba))
    stage_id = int(classes[best_idx]) if best_idx < len(classes) else best_idx
    stage = bundle.label_names.get(stage_id, str(stage_id))
    conf = float(proba[best_idx])

    proba_map: Dict[str, float] = {}
    for idx, class_id in enumerate(classes):
        key = bundle.label_names.get(int(class_id), str(class_id))
        if idx < len(proba):
            proba_map[key] = float(proba[idx])
    decision, severity = decide(stage, conf, list(bundle.label_names.values()))

    # Testing override: allow forcing the alert path end-to-end via the webhook payload.
    # Example:
    #   "flow_meta": {"force_alert": true, ...}
    force_alert = False
    if req.flow_meta is not None:
        force_alert = req.flow_meta.get("force_alert") in {True, 1, "1", "true", "TRUE", "yes", "YES"}
    if force_alert:
        decision, severity = "ALERT", "HIGH"
    return ScoreResponse(
        stage=stage,
        stage_id=stage_id,
        confidence=conf,
        proba=proba_map,
        decision=decision,
        severity=severity,
        flow_meta=req.flow_meta,
        used_features=row,
    )


@app.get("/alerts")
def alerts(limit: int = 20) -> Dict[str, Any]:
    db_path = _default_alerts_db_path()
    if limit < 1:
        limit = 1
    if limit > 500:
        limit = 500
    if not Path(db_path).exists():
        raise HTTPException(
            status_code=404,
            detail=f"Alert DB not found: {db_path}. Set ALERTS_DB_PATH or enable alert persistence in collector.",
        )

    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT id, ts_utc, stage, confidence, severity, decision,
                       src_ip, dest_ip, dest_port, proto, method, path, status, source
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"SQLite error: {e}")

    return {
        "ok": True,
        "db_path": db_path,
        "count": len(rows),
        "items": [dict(r) for r in rows],
    }
