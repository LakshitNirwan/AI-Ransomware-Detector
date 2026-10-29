
from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
TRAIN_PATH = ROOT / "dataset" / "processed" / "mlran_train.csv"
TEST_PATH = ROOT / "dataset" / "processed" / "mlran_test.csv"
REPORT_DIR = ROOT / "dataset" / "reports"
OUTPUT_DIR = ROOT / "results" / "feature_selection"

TARGET = "sample_type"
SUBSET_SIZES = (31, 64, 100, 159)
SEED = 42


def build_models():
    return {
        "logistic_regression": LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=SEED,
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=300,
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=SEED,
        ),
        "xgboost": XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.9,
            colsample_bytree=0.9,
            objective="binary:logistic",
            eval_metric="logloss",
            tree_method="hist",
            n_jobs=-1,
            random_state=SEED,
        ),
    }


def main() -> None:
    if not TRAIN_PATH.is_file() or not TEST_PATH.is_file():
        raise FileNotFoundError("Processed train/test CSV files are missing.")

    if not REPORT_DIR.is_dir():
        raise FileNotFoundError(f"Report directory missing: {REPORT_DIR}")

    if OUTPUT_DIR.exists() and any(OUTPUT_DIR.iterdir()):
        raise FileExistsError(
            f"Output directory is not empty; refusing to overwrite: {OUTPUT_DIR}"
        )

    train = pd.read_csv(TRAIN_PATH)
    test = pd.read_csv(TEST_PATH)

    if TARGET not in train.columns or TARGET not in test.columns:
        raise ValueError(f"Missing target column {TARGET!r}.")

    all_features = [c for c in train.columns if c != TARGET]
    test_features = [c for c in test.columns if c != TARGET]

    if all_features != test_features:
        raise ValueError("Train/test feature columns or order do not match.")

    if len(all_features) != 483:
        raise ValueError(f"Expected 483 original features; got {len(all_features)}.")

    y_train = train[TARGET].astype(int)
    y_test = test[TARGET].astype(int)

    if set(y_train.unique()) != {0, 1} or set(y_test.unique()) != {0, 1}:
        raise ValueError("Expected both target labels 0 and 1 in each split.")

    output_rows = []
    started = time.time()

    for size in SUBSET_SIZES:
        selection_path = REPORT_DIR / f"mlran_selected_features_{size}.json"
        if not selection_path.is_file():
            raise FileNotFoundError(f"Missing selection file: {selection_path}")

        selection = json.loads(selection_path.read_text(encoding="utf-8"))
        features = selection.get("feature_columns", [])

        if len(features) != size or len(set(features)) != size:
            raise ValueError(f"Invalid {size}-feature selection list.")
        if not set(features).issubset(set(all_features)):
            raise ValueError(f"{size}-feature list contains unknown columns.")

        X_train = train[features].astype(np.float32)
        X_test = test[features].astype(np.float32)

        print(f"\n=== Evaluating {size} features ===", flush=True)

        for model_name, model in build_models().items():
            print(f"Training {model_name}...", flush=True)
            model.fit(X_train, y_train)

            predictions = model.predict(X_test).astype(int)
            probabilities = model.predict_proba(X_test)[:, 1]

            row = {
                "model": model_name,
                "feature_count": size,
                "train_samples": len(y_train),
                "test_samples": len(y_test),
                "accuracy": float(accuracy_score(y_test, predictions)),
                "precision": float(
                    precision_score(y_test, predictions, zero_division=0)
                ),
                "recall": float(
                    recall_score(y_test, predictions, zero_division=0)
                ),
                "f1": float(f1_score(y_test, predictions, zero_division=0)),
                "roc_auc": float(roc_auc_score(y_test, probabilities)),
                "confusion_matrix_labels_0_1": confusion_matrix(
                    y_test, predictions, labels=[0, 1]
                ).tolist(),
            }
            output_rows.append(row)
            print(json.dumps(row, indent=2), flush=True)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    metrics_path = OUTPUT_DIR / "subset_metrics.csv"
    json_path = OUTPUT_DIR / "subset_metrics.json"

    if metrics_path.exists() or json_path.exists():
        raise FileExistsError("Metrics output already exists; refusing to overwrite.")

    pd.DataFrame(output_rows).to_csv(metrics_path, index=False)
    json_path.write_text(json.dumps(output_rows, indent=2), encoding="utf-8")

    run_info = {
        "seed": SEED,
        "target": TARGET,
        "subset_sizes": list(SUBSET_SIZES),
        "train_samples": len(train),
        "test_samples": len(test),
        "elapsed_seconds": round(time.time() - started, 2),
        "models": ["logistic_regression", "random_forest", "xgboost"],
        "note": (
            "Subset ranking was performed on training data only. "
            "The fixed test set is used for comparison and should not be "
            "repeatedly used for tuning."
        ),
    }
    (OUTPUT_DIR / "run_info.json").write_text(
        json.dumps(run_info, indent=2), encoding="utf-8"
    )

    print(f"\nSaved comparison metrics to: {metrics_path}", flush=True)


if __name__ == "__main__":
    main()
