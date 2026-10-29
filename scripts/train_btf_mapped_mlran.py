import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, confusion_matrix)
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "dataset/processed/btf_mapped_mlran"
TRAIN_PATH = DATA_DIR / "btf_mapped_mlran_train.csv"
TEST_PATH = DATA_DIR / "btf_mapped_mlran_test.csv"
OUT_DIR = ROOT / "results/btf_mapped_mlran_reconstruction"
TARGET = "sample_type"
SEED = 42


def metrics(model, X, y, split_name):
    pred = model.predict(X).astype(int)
    proba = model.predict_proba(X)[:, 1]
    return {
        "split": split_name,
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, proba)),
        "confusion_matrix_labels_0_1": confusion_matrix(y, pred, labels=[0, 1]).tolist(),
    }


def main():
    if OUT_DIR.exists() and any(OUT_DIR.iterdir()):
        raise FileExistsError(f"Refusing to overwrite nonempty output directory: {OUT_DIR}")
    train_df = pd.read_csv(TRAIN_PATH)
    test_df = pd.read_csv(TEST_PATH)
    features = [c for c in train_df.columns if c != TARGET]
    if features != [c for c in test_df.columns if c != TARGET] or len(features) != 31:
        raise ValueError("Expected matching train/test sets with exactly 31 canonical BTF fields")
    y_full = train_df[TARGET].astype(int)
    X_full = train_df[features].astype(np.float32)
    X_train, X_val, y_train, y_val = train_test_split(
        X_full, y_full, test_size=0.2, random_state=SEED, stratify=y_full)
    constant_features = [c for c in features if X_train[c].nunique(dropna=False) <= 1]
    model_features = [c for c in features if c not in constant_features]
    X_train, X_val = X_train[model_features], X_val[model_features]
    X_test = test_df[model_features].astype(np.float32)
    y_test = test_df[TARGET].astype(int)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "feature_names.json").write_text(json.dumps(model_features, indent=2) + "\n", encoding="utf-8")
    results = []
    models = {
        "logistic_regression": LogisticRegression(max_iter=2000, class_weight="balanced", random_state=SEED),
        "random_forest": RandomForestClassifier(n_estimators=300, class_weight="balanced_subsample", n_jobs=-1, random_state=SEED),
    }
    try:
        from xgboost import XGBClassifier
        models["xgboost"] = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.05,
            subsample=0.9, colsample_bytree=0.9, objective="binary:logistic",
            eval_metric="logloss", tree_method="hist", n_jobs=-1, random_state=SEED)
    except ImportError:
        print("XGBoost unavailable in this Python environment; LR and RF will still run.", flush=True)

    print(f"Train/validation/test: {len(y_train)}/{len(y_val)}/{len(y_test)}", flush=True)
    print(f"Canonical features: {len(features)}; constants removed: {len(constant_features)}; model inputs: {len(model_features)}", flush=True)
    print("Constant features:", ", ".join(constant_features), flush=True)
    for name, model in models.items():
        print(f"Training {name}...", flush=True)
        model.fit(X_train, y_train)
        row = {"model": name, "train_rows": len(y_train), "validation_rows": len(y_val),
               "test_rows": len(y_test), "feature_count": len(model_features),
               "validation": metrics(model, X_val, y_val, "validation"),
               "untouched_test": metrics(model, X_test, y_test, "untouched_test")}
        results.append(row)
        joblib.dump(model, OUT_DIR / f"{name}.joblib")
        for split_name, X, y in (("validation", X_val, y_val), ("test", X_test, y_test)):
            pred = model.predict(X).astype(int)
            proba = model.predict_proba(X)[:, 1]
            pd.DataFrame({"y_true": y, "y_pred": pred, "probability_ransomware": proba}).to_csv(
                OUT_DIR / f"{name}_{split_name}_predictions.csv", index=False)
        print(json.dumps(row, indent=2), flush=True)

    info = {
        "experiment": "reconstructed MLRan-derived BTF proxy",
        "target": TARGET,
        "label_semantics": {"0": "goodware", "1": "ransomware"},
        "seed": SEED,
        "validation_fraction": 0.2,
        "stratified_split": True,
        "train_rows": len(train_df), "model_train_rows": len(y_train),
        "validation_rows": len(y_val), "untouched_test_rows": len(y_test),
        "canonical_feature_count": len(features), "constant_features": constant_features,
        "model_features": model_features, "models_run": [r["model"] for r in results],
        "results": results,
        "limitation": "Inputs are sums of MLRan binary feature flags grouped by reconstructed runtime categories; they are not observed BTF/ETW event counts. Historical source mapping was not recovered.",
    }
    (OUT_DIR / "metrics.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    print(f"Saved results: {OUT_DIR.relative_to(ROOT)}", flush=True)


if __name__ == "__main__":
    main()
