import json
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "dataset/processed/btf_mapped_mlran/btf_mapped_mlran_test.csv"
MODEL_RUNS = ROOT / "results"
TARGET = "sample_type"
THRESHOLD = 0.5


def main():
    if not DATA_PATH.is_file():
        raise FileNotFoundError(f"Missing offline test data: {DATA_PATH}")
    run_dirs = [p for p in MODEL_RUNS.glob("btf_mapped_mlran_terminal_*")
                if (p / "metrics.json").is_file() and (p / "xgboost.joblib").is_file()]
    if not run_dirs:
        raise FileNotFoundError("No trained terminal XGBoost run found. Train the model first.")
    model_dir = max(run_dirs, key=lambda p: p.name)
    metadata = json.loads((model_dir / "metrics.json").read_text(encoding="utf-8"))
    features = metadata["model_features"]
    df = pd.read_csv(DATA_PATH)
    missing = [name for name in features if name not in df.columns]
    if missing or TARGET not in df.columns:
        raise ValueError(f"Test CSV does not match model inputs; missing={missing}")

    model = joblib.load(model_dir / "xgboost.joblib")
    X = df[features].astype(np.float32)
    y_true = df[TARGET].astype(int).to_numpy()
    classes = list(model.classes_)
    if 1 not in classes:
        raise ValueError("Model artifact does not contain ransomware class 1")
    probabilities = model.predict_proba(X)[:, classes.index(1)]
    y_pred = (probabilities >= THRESHOLD).astype(int)

    rows = []
    alerts = []
    for i, (truth, pred, probability) in enumerate(zip(y_true, y_pred, probabilities), start=1):
        sample_ref = f"test-row-{i:05d}"
        detected = bool(probability >= THRESHOLD)
        rows.append({
            "sample_reference": sample_ref,
            "true_label_for_evaluation_only": int(truth),
            "predicted_label": int(pred),
            "predicted_class": "ransomware" if pred else "goodware",
            "probability_ransomware": float(probability),
            "alert_generated": detected,
        })
        if detected:
            alerts.append({
                "alert_id": f"offline-alert-{i:05d}",
                "sample_reference": sample_ref,
                "alert_type": "ransomware_risk",
                "predicted_class": "ransomware",
                "probability_ransomware": float(probability),
                "threshold": THRESHOLD,
                "response_mode": "simulation_only",
                "action": "manual_review",
                "executed": False,
            })

    output_dir = ROOT / "results" / f"offline_detection_alert_demo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    output_dir.mkdir(parents=True, exist_ok=False)
    pd.DataFrame(rows).to_csv(output_dir / "test_detections.csv", index=False)
    (output_dir / "alerts.json").write_text(json.dumps(alerts, indent=2) + "\n", encoding="utf-8")
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist()
    report = {
        "mode": "offline held-out MLRan-derived BTF proxy evaluation",
        "model": str((model_dir / "xgboost.joblib").relative_to(ROOT)),
        "threshold": THRESHOLD,
        "rows_scored": len(df),
        "alert_count": len(alerts),
        "metrics": {
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1": float(f1_score(y_true, y_pred, zero_division=0)),
            "confusion_matrix_labels_0_1": cm,
        },
        "limitations": [
            "Rows are MLRan-derived feature proxies, not live process telemetry.",
            "Sample references identify CSV rows; they are not process IDs.",
            "Alerts request manual review; no system action is performed.",
        ],
        "outputs": ["test_detections.csv", "alerts.json"],
    }
    (output_dir / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("OFFLINE DETECTION AND ALERT DEMO", flush=True)
    print(f"Model: {model_dir.name}\\xgboost.joblib", flush=True)
    print(f"Test rows scored: {len(df)}", flush=True)
    print(f"Threshold: {THRESHOLD:.2f}", flush=True)
    print(f"Ransomware detections / simulated alerts: {len(alerts)}", flush=True)
    print(f"Accuracy: {report['metrics']['accuracy']:.6f}", flush=True)
    print(f"Precision: {report['metrics']['precision']:.6f}", flush=True)
    print(f"Recall: {report['metrics']['recall']:.6f}", flush=True)
    print(f"F1: {report['metrics']['f1']:.6f}", flush=True)
    print(f"Confusion matrix [TN FP; FN TP]: [{cm[0][0]} {cm[0][1]}; {cm[1][0]} {cm[1][1]}]", flush=True)
    print("First five alerts:", flush=True)
    for alert in alerts[:5]:
        print(json.dumps(alert), flush=True)
    print(f"Saved detections and alerts to: {output_dir}", flush=True)
    print("No live monitoring or response action was performed.", flush=True)


if __name__ == "__main__":
    main()
