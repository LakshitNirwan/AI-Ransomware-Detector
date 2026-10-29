"""Experimental XGBoost scoring for canonical live BTF vectors."""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from xgboost import DMatrix

ROOT = Path(__file__).resolve().parents[1]
RESULTS_ROOT = ROOT / "results"
DEFAULT_THRESHOLD = 0.50


def _latest_model():
    runs = [
        path for path in RESULTS_ROOT.glob("btf_mapped_mlran_terminal_*")
        if (path / "metrics.json").is_file() and (path / "xgboost.joblib").is_file()
    ]
    if not runs:
        raise FileNotFoundError("No saved BTF-mapped XGBoost model run was found.")
    model_dir = max(runs, key=lambda path: path.name)
    metadata = json.loads((model_dir / "metrics.json").read_text(encoding="utf-8"))
    model_features = metadata.get("model_features", [])
    if not model_features:
        raise ValueError("Saved model metadata has no input feature list.")
    model = joblib.load(model_dir / "xgboost.joblib")
    return model_dir, metadata, model_features, model


def score_btf_vector(vector: dict[str, int], threshold: float = DEFAULT_THRESHOLD) -> dict:
    """Score a canonical BTF vector in saved model feature order."""
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0 and 1")
    if not isinstance(vector, dict):
        raise TypeError("BTF vector must be a dictionary")

    model_dir, metadata, features, model = _latest_model()
    missing = [name for name in features if name not in vector]
    if missing:
        raise ValueError(f"BTF vector is missing model inputs: {missing}")
    values = [float(vector[name]) for name in features]
    if not np.isfinite(values).all() or any(value < 0 for value in values):
        raise ValueError("BTF model inputs must be finite and nonnegative")

    frame = pd.DataFrame([values], columns=features, dtype=np.float32)
    classes = list(model.classes_)
    if 1 not in classes:
        raise ValueError("Saved XGBoost model does not contain ransomware class 1")
    probability = float(model.predict_proba(frame)[0][classes.index(1)])
    prediction = int(probability >= threshold)

    contributions = model.get_booster().predict(
        DMatrix(frame, feature_names=features), pred_contribs=True
    )[0, :-1]
    ranked = np.argsort(np.abs(contributions))[::-1][:5]
    signals = [
        {
            "feature": features[index],
            "value": float(values[index]),
            "effect": "raises ransomware score" if contributions[index] > 0 else "lowers ransomware score",
            "contribution": float(contributions[index]),
        }
        for index in ranked
        if contributions[index] != 0
    ]

    return {
        "status": "prototype_live_score",
        "model": "XGBoost",
        "model_run": model_dir.name,
        "threshold": threshold,
        "probability_ransomware": probability,
        "predicted_label": "ransomware_risk" if prediction else "lower_risk",
        "alert_triggered": bool(prediction),
        "scored_model_fields": len(features),
        "top_signals": signals,
        "scope": (
            "The model was trained on MLRan-derived BTF proxy values. This score applies "
            "that model to observed BTF counts; live ETW performance still requires "
            "validation on representative labeled live captures."
        ),
        "held_out_test_rows": metadata.get("untouched_test_rows"),
    }