import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from joblib import dump
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from features.fusion import FUSED_FEATURE_NAMES

ROOT = Path(__file__).resolve().parents[1]
TRAIN = ROOT / "dataset" / "processed" / "fused_train.csv"
TEST = ROOT / "dataset" / "processed" / "fused_test.csv"
MANIFEST = ROOT / "dataset" / "processed" / "fused_dataset_info.json"
OUT = ROOT / "results" / "fused"
TARGET = "sample_type"
SEED = 42
EXPECTED_LABELS = {0: "goodware", 1: "ransomware"}


def _validate_manifest(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(
            f"Missing {path.name}. Provide a reviewed manifest that confirms "
            "paired ETW+BTF observations and ransomware/goodware label semantics. "
            "Do not use btf_anomaly_prototype.csv as ransomware-labeled data."
        )
    info = json.loads(path.read_text(encoding="utf-8"))
    if info.get("dataset_kind") != "paired_etw_btf_ransomware":
        raise ValueError("Manifest dataset_kind must be paired_etw_btf_ransomware")
    if info.get("paired_observations") is not True:
        raise ValueError("Manifest must confirm paired ETW and BTF observations")
    if info.get("label_column") != TARGET:
        raise ValueError(f"Manifest label_column must be {TARGET!r}")
    mapping = {int(key): value for key, value in info.get("label_mapping", {}).items()}
    if mapping != EXPECTED_LABELS:
        raise ValueError("Manifest must map 0 to goodware and 1 to ransomware")
    if info.get("label_source_validated") is not True:
        raise ValueError("Manifest must confirm the ransomware label source was validated")
    if info.get("feature_names") != list(FUSED_FEATURE_NAMES):
        raise ValueError("Manifest feature_names must match the ordered fused schema")
    return info


def _drop_exact_training_duplicates(train: pd.DataFrame, test: pd.DataFrame, features: list[str]):
    """Drop columns identical on train rows; test is used only to check consistency."""
    keep: list[str] = []
    dropped: dict[str, str] = {}
    for name in features:
        match = next((prior for prior in keep if train[name].equals(train[prior])), None)
        if match is None:
            keep.append(name)
            continue
        if not test[name].equals(test[match]):
            raise ValueError(
                f"Columns {name!r} and {match!r} match in training but differ in test; "
                "resolve the schema inconsistency before training."
            )
        dropped[name] = match
    return keep, dropped


def main() -> None:
    start = time.time()
    if not TRAIN.is_file() or not TEST.is_file():
        raise FileNotFoundError(
            "Paired fused train/test CSVs are not available. Expected "
            "dataset/processed/fused_train.csv and fused_test.csv. "
            "The current MLRan tables do not contain paired ETW+BTF observations."
        )

    manifest = _validate_manifest(MANIFEST)
    train = pd.read_csv(TRAIN)
    test = pd.read_csv(TEST)
    expected_columns = list(FUSED_FEATURE_NAMES) + [TARGET]
    if list(train.columns) != expected_columns or list(test.columns) != expected_columns:
        raise ValueError("Train/test columns must match the ordered 49-feature schema plus sample_type")
    if train.empty or test.empty:
        raise ValueError("Fused train and test datasets must both contain rows")

    features = list(FUSED_FEATURE_NAMES)
    for frame, name in ((train, "train"), (test, "test")):
        if frame[features].isna().any().any():
            raise ValueError(f"Missing fused features found in {name} data")
        if not set(pd.unique(frame[TARGET])).issubset({0, 1, "0", "1"}):
            raise ValueError(f"Unexpected labels in {name} data")

    y_train = train[TARGET].astype(int)
    y_test = test[TARGET].astype(int)
    if set(y_train.unique()) != {0, 1} or set(y_test.unique()) != {0, 1}:
        raise ValueError("Both ransomware/goodware labels must occur in each split")

    kept, duplicates = _drop_exact_training_duplicates(train, test, features)
    X_train = train[kept].astype(np.float32)
    X_test = test[kept].astype(np.float32)

    from xgboost import XGBClassifier

    model = XGBClassifier(
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
    )
    model.fit(X_train, y_train)
    predictions = model.predict(X_test).astype(int)
    probabilities = model.predict_proba(X_test)[:, 1]

    metrics = {
        "model": "xgboost_fused",
        "train_samples": int(len(y_train)),
        "test_samples": int(len(y_test)),
        "candidate_feature_count": len(features),
        "trained_feature_count": len(kept),
        "dropped_exact_duplicates": duplicates,
        "dataset_kind": manifest["dataset_kind"],
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision_score(y_test, predictions, zero_division=0)),
        "recall": float(recall_score(y_test, predictions, zero_division=0)),
        "f1": float(f1_score(y_test, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
        "confusion_matrix_labels_0_1": confusion_matrix(
            y_test, predictions, labels=[0, 1]
        ).tolist(),
        "elapsed_seconds": round(time.time() - start, 3),
    }

    OUT.mkdir(parents=True, exist_ok=True)
    dump(model, OUT / "xgboost_fused.joblib")
    (OUT / "feature_names.json").write_text(json.dumps(kept, indent=2), encoding="utf-8")
    (OUT / "duplicate_features.json").write_text(
        json.dumps(duplicates, indent=2), encoding="utf-8"
    )
    (OUT / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (OUT / "classification_report.txt").write_text(
        classification_report(y_test, predictions, labels=[0, 1],
                              target_names=["goodware", "ransomware"], zero_division=0),
        encoding="utf-8",
    )
    pd.DataFrame({
        "y_true": y_test,
        "y_pred": predictions,
        "probability_ransomware": probabilities,
    }).to_csv(OUT / "predictions.csv", index=False)

    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
