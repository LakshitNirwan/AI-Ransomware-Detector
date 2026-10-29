import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
TRAIN = ROOT / "dataset" / "processed" / "mlran_train.csv"
TEST = ROOT / "dataset" / "processed" / "mlran_test.csv"
OUT = ROOT / "results" / "baseline"
TARGET = "sample_type"
SEED = 42


def main():
    start = time.time()
    if not TRAIN.is_file() or not TEST.is_file():
        raise FileNotFoundError("Processed training/test CSV files are missing.")

    train = pd.read_csv(TRAIN)
    test = pd.read_csv(TEST)

    if TARGET not in train.columns or TARGET not in test.columns:
        raise ValueError(f"Expected target column {TARGET!r} in both datasets.")

    features = [c for c in train.columns if c != TARGET]
    if features != [c for c in test.columns if c != TARGET]:
        raise ValueError("Train/test feature columns or order do not match.")
    if len(features) != 483:
        raise ValueError(f"Expected 483 features, found {len(features)}.")
    if train[features].isna().any().any() or test[features].isna().any().any():
        raise ValueError("Missing feature values found.")
    if not set(pd.unique(train[TARGET])).issubset({0, 1, "0", "1"}):
        raise ValueError("Unexpected training labels.")
    if not set(pd.unique(test[TARGET])).issubset({0, 1, "0", "1"}):
        raise ValueError("Unexpected test labels.")

    X_train = train[features].astype(np.float32)
    X_test = test[features].astype(np.float32)
    y_train = train[TARGET].astype(int)
    y_test = test[TARGET].astype(int)

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "feature_names.json").write_text(
        json.dumps(features, indent=2), encoding="utf-8"
    )

    models = {
        "logistic_regression": LogisticRegression(
            max_iter=2000, class_weight="balanced", random_state=SEED
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=300, class_weight="balanced_subsample",
            n_jobs=-1, random_state=SEED
        ),
        "xgboost": XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.05,
            subsample=0.9, colsample_bytree=0.9,
            objective="binary:logistic", eval_metric="logloss",
            tree_method="hist", n_jobs=-1, random_state=SEED
        ),
    }

    metric_rows = []
    for name, model in models.items():
        print(f"\nTraining {name} ...", flush=True)
        model.fit(X_train, y_train)
        pred = model.predict(X_test).astype(int)
        proba = model.predict_proba(X_test)[:, 1]

        metrics = {
            "model": name,
            "train_samples": int(len(y_train)),
            "test_samples": int(len(y_test)),
            "feature_count": int(len(features)),
            "accuracy": float(accuracy_score(y_test, pred)),
            "precision": float(precision_score(y_test, pred, zero_division=0)),
            "recall": float(recall_score(y_test, pred, zero_division=0)),
            "f1": float(f1_score(y_test, pred, zero_division=0)),
            "roc_auc": float(roc_auc_score(y_test, proba)),
            "confusion_matrix_labels_0_1": confusion_matrix(
                y_test, pred, labels=[0, 1]
            ).tolist(),
        }
        metric_rows.append(metrics)

        joblib.dump(model, OUT / f"{name}.joblib")
        pd.DataFrame({
            "y_true": y_test,
            "y_pred": pred,
            "probability_ransomware": proba,
        }).to_csv(OUT / f"{name}_predictions.csv", index=False)

        (OUT / f"{name}_report.txt").write_text(
            classification_report(y_test, pred, labels=[0, 1],
                                  target_names=["benign", "ransomware"],
                                  zero_division=0),
            encoding="utf-8"
        )

        if hasattr(model, "feature_importances_"):
            importance = model.feature_importances_
        elif hasattr(model, "coef_"):
            importance = np.abs(model.coef_[0])
        else:
            importance = None

        if importance is not None:
            pd.DataFrame({
                "feature": features,
                "importance": importance,
            }).sort_values("importance", ascending=False).to_csv(
                OUT / f"{name}_feature_importance.csv", index=False
            )

        print(json.dumps(metrics, indent=2), flush=True)

    pd.DataFrame(metric_rows).to_csv(OUT / "metrics.csv", index=False)
    (OUT / "metrics.json").write_text(
        json.dumps(metric_rows, indent=2), encoding="utf-8"
    )
    run_info = {
        "seed": SEED,
        "target": TARGET,
        "features": len(features),
        "train_samples": len(train),
        "test_samples": len(test),
        "elapsed_seconds": round(time.time() - start, 2),
        "models": list(models),
        "note": "Metrics are from the surviving fixed test set; no tuning performed."
    }
    (OUT / "run_info.json").write_text(
        json.dumps(run_info, indent=2), encoding="utf-8"
    )
    print(f"\nALL MODELS FINISHED. Artifacts saved to: {OUT}", flush=True)
    print(f"Elapsed seconds: {run_info['elapsed_seconds']}", flush=True)


if __name__ == "__main__":
    main()
