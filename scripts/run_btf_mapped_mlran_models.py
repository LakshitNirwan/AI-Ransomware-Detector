import json
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, confusion_matrix)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "dataset/processed/btf_mapped_mlran"
TRAIN_PATH = DATA_DIR / "btf_mapped_mlran_train.csv"
TEST_PATH = DATA_DIR / "btf_mapped_mlran_test.csv"
TARGET = "sample_type"
SEED = 42


def score(model, X, y):
    predictions = model.predict(X).astype(int)
    probabilities = model.predict_proba(X)[:, 1]
    return {
        "accuracy": float(accuracy_score(y, predictions)),
        "precision": float(precision_score(y, predictions, zero_division=0)),
        "recall": float(recall_score(y, predictions, zero_division=0)),
        "f1": float(f1_score(y, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, probabilities)),
        "confusion_matrix_labels_0_1": confusion_matrix(y, predictions, labels=[0, 1]).tolist(),
    }


def print_scores(split, values):
    print(f"  {split}:", flush=True)
    for key in ("accuracy", "precision", "recall", "f1", "roc_auc"):
        print(f"    {key}: {values[key]:.6f}", flush=True)
    matrix = values["confusion_matrix_labels_0_1"]
    print(f"    confusion matrix [TN FP; FN TP]: [{matrix[0][0]} {matrix[0][1]}; {matrix[1][0]} {matrix[1][1]}]", flush=True)


def main():
    if not TRAIN_PATH.is_file() or not TEST_PATH.is_file():
        raise FileNotFoundError("Mapped BTF proxy CSVs are missing. Run scripts/rebuild_btf_mlran_dataset.py first.")
    train = pd.read_csv(TRAIN_PATH)
    test = pd.read_csv(TEST_PATH)
    features = [c for c in train.columns if c != TARGET]
    if len(features) != 31 or features != [c for c in test.columns if c != TARGET]:
        raise ValueError("Expected identical train/test CSVs with 31 BTF features.")

    y_all = train[TARGET].astype(int)
    X_all = train[features].astype(np.float32)
    X_train, X_val, y_train, y_val = train_test_split(
        X_all, y_all, test_size=0.2, random_state=SEED, stratify=y_all)
    constants = [c for c in features if X_train[c].nunique(dropna=False) <= 1]
    model_features = [c for c in features if c not in constants]
    X_train, X_val = X_train[model_features], X_val[model_features]
    X_test = test[model_features].astype(np.float32)
    y_test = test[TARGET].astype(int)

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = ROOT / "results" / f"btf_mapped_mlran_terminal_{run_id}"
    out_dir.mkdir(parents=True, exist_ok=False)
    print("MLRan-derived BTF proxy model run", flush=True)
    print(f"Train/validation/test rows: {len(y_train)}/{len(y_val)}/{len(y_test)}", flush=True)
    print(f"Canonical features: {len(features)}; constant fields: {len(constants)}; model inputs: {len(model_features)}", flush=True)
    print("Constant fields:", ", ".join(constants), flush=True)
    print("Labels: 0=goodware, 1=ransomware", flush=True)
    print("Note: input values are sums of MLRan binary indicators, not measured ETW event counts.", flush=True)

    models = {
        "Logistic Regression": LogisticRegression(max_iter=2000, class_weight="balanced", random_state=SEED),
        "Random Forest": RandomForestClassifier(n_estimators=300, class_weight="balanced_subsample", n_jobs=-1, random_state=SEED),
        "XGBoost": XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.05,
            subsample=0.9, colsample_bytree=0.9, objective="binary:logistic",
            eval_metric="logloss", tree_method="hist", n_jobs=-1, random_state=SEED),
    }
    results = []
    for name, model in models.items():
        key = name.lower().replace(" ", "_")
        print(f"\nTraining {name}...", flush=True)
        model.fit(X_train, y_train)
        validation = score(model, X_val, y_val)
        test_metrics = score(model, X_test, y_test)
        print_scores("validation", validation)
        print_scores("untouched test", test_metrics)
        joblib.dump(model, out_dir / f"{key}.joblib")
        results.append({"model": name, "validation": validation, "untouched_test": test_metrics})

    (out_dir / "metrics.json").write_text(json.dumps({
        "seed": SEED,
        "target": TARGET,
        "train_rows": len(y_train),
        "validation_rows": len(y_val),
        "untouched_test_rows": len(y_test),
        "canonical_features": features,
        "constant_features": constants,
        "model_features": model_features,
        "results": results,
        "limitation": "MLRan-derived presence-sum proxy; not observed BTF/ETW event counts.",
    }, indent=2) + "\n", encoding="utf-8")
    print(f"\nSaved this run to: {out_dir}", flush=True)


if __name__ == "__main__":
    main()
