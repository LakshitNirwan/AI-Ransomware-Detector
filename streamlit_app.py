"""Live BTF monitor and labeled MLRan test-case dashboard."""
from __future__ import annotations

import json
import sys
import ctypes
import subprocess
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import streamlit as st
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from xgboost import DMatrix

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from ml.live_btf_scoring import score_btf_vector

LIVE_CAPTURE_PATH = ROOT / "results" / "live_btf" / "latest.json"
SIMULATION_REPORT_PATH = ROOT / "results" / "live_btf" / "simulation_latest.json"
TEST_DATA_PATH = ROOT / "dataset" / "processed" / "btf_mapped_mlran" / "btf_mapped_mlran_test.csv"
RESULTS_ROOT = ROOT / "results"
TARGET = "sample_type"
THRESHOLD = 0.50

st.set_page_config(page_title="Ransomware Detection Center", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.block-container {max-width:1450px; padding-top:1.3rem;}
[data-testid="stAppViewContainer"] {background:radial-gradient(ellipse at 8% 0%,#172554 0%,#0b1220 44%,#080d17 100%);}
[data-testid="stSidebar"] {background:#0b1220; border-right:1px solid #25324a;}
div[data-testid="stMetric"] {background:rgba(18,31,52,.88); border:1px solid #263653; padding:.85rem; border-radius:14px;}
.hero {padding:1.2rem 1.4rem; border:1px solid #263653; border-radius:16px; background:linear-gradient(120deg,rgba(20,35,63,.95),rgba(13,24,42,.9)); margin-bottom:1rem;}
.eyebrow {color:#7dd3fc; font-size:.78rem; text-transform:uppercase; letter-spacing:.16em; font-weight:700;}
.scope {color:#aebed2; font-size:.84rem; padding:.65rem .85rem; border-left:3px solid #38bdf8; background:rgba(15,30,49,.72); border-radius:0 9px 9px 0;}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
  <div class="eyebrow">Windows ETW · XGBoost · 31 BTF fields</div>
  <h1 style="margin:.2rem 0">Ransomware Detection Center</h1>
  <div style="color:#b8c6da">Live process monitoring and full MLRan held-out test results</div>
</div>
""", unsafe_allow_html=True)

live_tab, mlran_tab = st.tabs(["Live monitoring", "MLRan test case"])


def load_latest_model():
    runs = [
        path for path in RESULTS_ROOT.glob("btf_mapped_mlran_terminal_*")
        if (path / "metrics.json").is_file() and (path / "xgboost.joblib").is_file()
    ]
    if not runs:
        raise FileNotFoundError("No saved BTF-mapped XGBoost model run was found.")
    run_dir = max(runs, key=lambda path: path.name)
    metadata = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
    model = joblib.load(run_dir / "xgboost.joblib")
    features = metadata.get("model_features", [])
    if not features:
        raise ValueError("Saved model metadata is missing its feature list.")
    return run_dir, metadata, features, model


@st.cache_data
def load_test_data():
    if not TEST_DATA_PATH.is_file():
        raise FileNotFoundError(f"Missing MLRan test data: {TEST_DATA_PATH}")
    return pd.read_csv(TEST_DATA_PATH)


def render_mlran_detection_example():
    """Show held-out evaluation results and one correctly detected ransomware sample."""
    st.subheader("MLRan held-out test results")
    st.caption(
        "This dashboard uses labeled test records from MLRan. It is separate from live ETW monitoring."
    )
    try:
        run_dir, metadata, model_features, model = load_latest_model()
        test_df = load_test_data()
        missing = [name for name in model_features if name not in test_df.columns]
        if TARGET not in test_df.columns or missing:
            raise ValueError(f"Test data does not match the saved model inputs: {missing}")

        X_test = test_df[model_features].astype(np.float32)
        y_true = test_df[TARGET].astype(int).to_numpy()
        classes = list(model.classes_)
        if 1 not in classes:
            raise ValueError("Saved model does not contain ransomware label 1.")
        probabilities = model.predict_proba(X_test)[:, classes.index(1)]
        predictions = (probabilities >= THRESHOLD).astype(int)
        matrix = confusion_matrix(y_true, predictions, labels=[0, 1])
        metric_cols = st.columns(5)
        metric_cols[0].metric("Test accuracy", f"{accuracy_score(y_true, predictions):.1%}")
        metric_cols[1].metric("Precision", f"{precision_score(y_true, predictions, zero_division=0):.1%}")
        metric_cols[2].metric("Recall", f"{recall_score(y_true, predictions, zero_division=0):.1%}")
        metric_cols[3].metric("F1 score", f"{f1_score(y_true, predictions, zero_division=0):.1%}")
        metric_cols[4].metric("ROC-AUC", f"{roc_auc_score(y_true, probabilities):.1%}")
        st.markdown("#### Confusion matrix · actual rows, predicted columns")
        st.dataframe(
            pd.DataFrame(matrix, index=["Actual goodware", "Actual ransomware"],
                         columns=["Predicted goodware", "Predicted ransomware"]),
            width="stretch",
        )
        st.caption(f"Untouched test split · {len(y_true):,} samples · XGBoost · threshold {THRESHOLD:.0%}")
        st.divider()
        case_ids = [f"TEST-{index + 1:04d}" for index in range(len(y_true))]
        outcomes = np.select(
            [
                (y_true == 1) & (predictions == 1),
                (y_true == 1) & (predictions == 0),
                (y_true == 0) & (predictions == 1),
            ],
            ["Correct ransomware detection", "Missed ransomware", "False positive"],
            default="Correct goodware detection",
        )
        all_cases = pd.DataFrame({
            "Test case": case_ids,
            "Dataset label": np.where(y_true == 1, "Ransomware", "Goodware"),
            "Model prediction": np.where(predictions == 1, "Ransomware", "Goodware"),
            "Ransomware score": probabilities,
            "Outcome": outcomes,
        })
        all_cases["Ransomware score"] = all_cases["Ransomware score"].map(lambda value: f"{value:.2%}")
        st.markdown("#### All held-out MLRan test cases")
        st.caption(f"Showing all {len(all_cases):,} rows from the untouched test split.")
        st.dataframe(all_cases, width="stretch", height=430, hide_index=True)
        st.download_button(
            "Download all test-case results",
            data=all_cases.to_csv(index=False).encode("utf-8"),
            file_name="mlran_held_out_test_results.csv",
            mime="text/csv",
        )
        st.divider()
        true_positives = np.flatnonzero((y_true == 1) & (predictions == 1))
        if not len(true_positives):
            st.warning("No correctly detected ransomware sample is available in this held-out split.")
            return

        st.subheader("Inspect any test case · 31-field BTF vector")

        canonical_features = metadata.get("canonical_features", [])
        file_fields = [name for name in canonical_features if name.startswith("file_activity.")]

        def file_activity_total(index):
            return sum(float(X_test.iloc[index].get(name, 0.0)) for name in file_fields)

        # Prefer a correctly detected test row with mapped file activity.
        default_case = int(sorted(
            true_positives,
            key=lambda index: (file_activity_total(int(index)) <= 0, -float(probabilities[index])),
        )[0])
        selected_case = st.selectbox(
            "Choose a test case",
            options=case_ids,
            index=default_case,
            key="mlran_case_selector",
        )
        chosen = case_ids.index(selected_case)
        actual = int(y_true[chosen])
        predicted = int(predictions[chosen])
        case_name = f"TEST-{chosen + 1:04d}"

        if predicted == 1:
            st.error(f"RANSOMWARE DETECTED · Alert raised · MLRan sample {case_name}")
        elif actual == 1:
            st.warning(f"RANSOMWARE MISSED · no alert · MLRan sample {case_name}")
        else:
            st.success(f"No ransomware alert · MLRan sample {case_name}")
        case_metrics = st.columns(4)
        case_metrics[0].metric("Dataset label", "Ransomware" if actual else "Goodware")
        case_metrics[1].metric("Model decision", "Ransomware detected" if predicted else "Lower risk")
        case_metrics[2].metric("XGBoost ransomware score", f"{probabilities[chosen]:.1%}")
        case_metrics[3].metric("Test outcome", str(outcomes[chosen]))

        mapped_vector = {
            name: float(X_test.iloc[chosen].get(name, 0.0))
            for name in canonical_features
        }
        file_values = [(name, mapped_vector[name]) for name in file_fields]
        nonzero_fields = [(name, value) for name, value in mapped_vector.items() if value != 0]
        st.markdown("**File activity represented in this sample**")
        file_metrics = st.columns(4)
        for index, operation in enumerate(("open", "read", "write", "delete")):
            file_metrics[index].metric(
                f"File {operation}",
                f"{mapped_vector.get(f'file_activity.{operation}', 0):g}",
            )
        highlight_columns = st.columns(4)
        for index, (name, value) in enumerate(sorted(nonzero_fields, key=lambda item: abs(item[1]), reverse=True)[:4]):
            highlight_columns[index].metric(name.replace("_activity.", " · "), f"{value:g}")
        st.caption(f"{len(nonzero_fields)} of 31 BTF fields have nonzero mapped values in this row.")
        st.markdown("#### 31-field BTF vector")
        st.dataframe(
            pd.DataFrame([
                {"BTF field": name, "MLRan-mapped value": value}
                for name, value in mapped_vector.items()
            ]),
            width="stretch",
            hide_index=True,
        )
        st.caption(
            "MLRan contains aggregate feature data, not filenames or per-file change records. "
            "The file_activity fields show the available mapped file behavior; specific changed files cannot be identified from this sample."
        )

        contributions = model.get_booster().predict(
            DMatrix(X_test.iloc[[chosen]], feature_names=model_features), pred_contribs=True
        )[0, :-1]
        ranked = np.argsort(np.abs(contributions))[::-1][:6]
        explanation = pd.DataFrame([
            {
                "BTF feature": model_features[index],
                "Mapped value": float(X_test.iloc[chosen][model_features[index]]),
                "Effect on score": "Raises risk" if contributions[index] > 0 else "Lowers risk",
                "Contribution": float(contributions[index]),
            }
            for index in ranked
        ])
        st.markdown("#### Model signals behind this alert")
        st.dataframe(explanation, width="stretch", hide_index=True)
        st.caption(f"Held-out MLRan test case · model artifact: {run_dir.name}")
    except Exception as exc:
        st.error(f"Could not load the MLRan ransomware example: {type(exc).__name__}: {exc}")


with live_tab:
    top_left, top_right = st.columns([1, 5])
    with top_left:
        if st.button("Refresh live capture", type="primary", use_container_width=True):
            if sys.platform != "win32" or not ctypes.windll.shell32.IsUserAnAdmin():
                st.error(
                    "Start this dashboard from Administrator PowerShell to run ETW capture from the button."
                )
            else:
                old_capture_id = None
                if LIVE_CAPTURE_PATH.is_file():
                    try:
                        old_capture_id = json.loads(
                            LIVE_CAPTURE_PATH.read_text(encoding="utf-8")
                        ).get("capture", {}).get("capture_id")
                    except (OSError, json.JSONDecodeError):
                        pass
                command = [
                    sys.executable,
                    str(ROOT / "scripts" / "run_live_btf_capture.py"),
                    "--system-wide",
                    "--seconds",
                    "30",
                ]
                try:
                    with st.spinner(
                        "Capturing system-wide activity for 30 seconds. Create or rename a safe file now..."
                    ):
                        result = subprocess.run(
                            command,
                            cwd=ROOT,
                            capture_output=True,
                            text=True,
                            timeout=180,
                            check=False,
                        )
                    new_report = (
                        json.loads(LIVE_CAPTURE_PATH.read_text(encoding="utf-8"))
                        if LIVE_CAPTURE_PATH.is_file()
                        else {}
                    )
                    new_capture_id = new_report.get("capture", {}).get("capture_id")
                    if result.returncode != 0:
                        detail = (result.stderr or result.stdout or "Capture command failed.")[-3000:]
                        st.error(f"Capture failed (exit {result.returncode}).")
                        st.code(detail)
                    elif not new_capture_id or new_capture_id == old_capture_id:
                        st.error("The capture command finished but did not write a new report.")
                    else:
                        st.success("New capture saved. Reloading the live results...")
                        st.rerun()
                except subprocess.TimeoutExpired:
                    st.error("Capture exceeded its 3-minute safety limit. Check the Administrator PowerShell session.")
                except (OSError, json.JSONDecodeError) as exc:
                    st.error(f"Could not start or read the capture: {type(exc).__name__}: {exc}")
    with top_right:
        st.caption("Click to capture all processes for 30 seconds. Create, rename, or edit a safe file while capture runs; results reload automatically when it finishes.")

    if not LIVE_CAPTURE_PATH.is_file():
        st.warning("No live capture is available yet.")
        st.code("py -3.12 ./scripts/run_live_btf_capture.py --benign-test --seconds 8", language="powershell")
    else:
        try:
            live_report = json.loads(LIVE_CAPTURE_PATH.read_text(encoding="utf-8"))
            capture = live_report.get("capture", {})
            stats = capture.get("collector_statistics", {})
            coverage = live_report.get("coverage", {})
            vector = live_report.get("btf_vector_31", {})
            file_events = live_report.get("observed_file_events", [])
            registry_events = live_report.get("observed_registry_events", [])
            process_events = live_report.get("observed_process_start_events", [])
            rule_alert = live_report.get("behavior_alert", {})
            system_wide = capture.get("mode") == "system_wide"
            selected_live_pid = None
            if system_wide:
                per_process = live_report.get("process_activity_by_pid", {})
                if per_process:
                    ordered_pids = sorted(
                        per_process,
                        key=lambda pid: (
                            int(per_process[pid].get("file_event_count", 0))
                            + int(per_process[pid].get("registry_event_count", 0))
                            + int(per_process[pid].get("process_start_count", 0))
                        ),
                        reverse=True,
                    )
                    selected_live_pid = st.selectbox(
                        "Process BTF and model result",
                        ordered_pids,
                        index=0,
                        format_func=lambda pid: (
                            f"PID {pid} · {per_process[pid].get('file_event_count', 0)} file · "
                            f"{per_process[pid].get('registry_event_count', 0)} registry"
                        ),
                        key="live_system_process_selector",
                    )
                    process_report = per_process[selected_live_pid]
                    vector = process_report.get("btf_vector_31", {})
                    rule_alert = process_report.get("behavior_alert", {})
                else:
                    vector = {}
            observable = set(coverage.get("observable_fields_in_this_collector", []))
            observed_count = sum(int(value) for name, value in vector.items() if name in observable)

            model_score = live_report.get("model_scoring", {})
            if model_score.get("status") != "prototype_live_score":
                try:
                    model_score = score_btf_vector(vector)
                except Exception as exc:
                    model_score = {"status": "unavailable", "reason": f"{type(exc).__name__}: {exc}"}

            safe_benign_test = capture.get("mode") == "safe_benign_test"
            raw_threshold_crossed = bool(model_score.get("raw_threshold_crossed", model_score.get("alert_triggered", False)))
            model_alert = raw_threshold_crossed and observed_count > 0 and not safe_benign_test
            rule_triggered = rule_alert.get("status") == "review_recommended"
            review_count = int(model_alert) + int(rule_triggered)

            st.subheader("Latest live capture")
            capture_stamp = capture.get("window_start_utc", "")
            report_updated = datetime.fromtimestamp(LIVE_CAPTURE_PATH.stat().st_mtime).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
            st.caption(
                f"Capture {capture.get('capture_id', 'legacy report')} · "
                f"started {capture_stamp or 'time unavailable'} · "
                f"mode: {capture.get('mode', 'unknown').replace('_', ' ')} · report updated {report_updated}"
            )
            if capture.get("shutdown_warning"):
                st.warning("ETW stopped slowly after the capture window. Events collected before shutdown were saved and are shown below.")
            metrics = st.columns(6)
            metrics[0].metric("Monitoring scope", "System-wide" if system_wide else str(capture.get("pid", "—")))
            metrics[1].metric("File events", len(file_events))
            metrics[2].metric("Registry events", len(registry_events))
            metrics[3].metric("Child starts", len(process_events))
            active_btf_fields = sum(1 for value in vector.values() if int(value) > 0)
            metrics[4].metric(
                "BTF fields",
                31,
                delta=f"{active_btf_fields} active for selected process",
                help="The BTF schema always has 31 fields. In system-wide mode, each process gets its own vector; counts are not mixed across processes.",
            )
            metrics[5].metric("Review signals", review_count)

            score_cols = st.columns(3)
            probability = model_score.get("probability_ransomware")
            score_cols[0].metric(
                f"XGBoost risk score · PID {selected_live_pid}" if system_wide and selected_live_pid else "XGBoost risk score",
                "Diagnostic" if safe_benign_test else f"{probability:.1%}" if probability is not None and observed_count else "No activity",
            )
            if safe_benign_test:
                decision_label = "No ransomware detected"
            else:
                decision_label = model_score.get("predicted_label", "No observed events").replace("_", " ").title()
            score_cols[1].metric("Model decision", decision_label if observed_count else "No observed events")
            score_cols[2].metric("Model threshold", f"{model_score.get('threshold', THRESHOLD):.0%}")
            if not observed_count:
                if system_wide and not per_process:
                    st.info("No file, registry, or process-start activity was observed in this capture window. Create or change a file while the system-wide capture is running, then capture again.")
                else:
                    st.info("This capture has zero observed BTF activity. Its baseline model score is not treated as an alert.")
            elif safe_benign_test:

                if raw_threshold_crossed:
                    with st.expander("Model signal details"):
                        signals = model_score.get("top_signals", [])
                        if signals:
                            st.dataframe(pd.DataFrame(signals), width="stretch", hide_index=True)
            elif model_score.get("status") == "prototype_live_score":
                if model_alert:
                    st.warning("XGBoost risk threshold crossed · manual review recommended")
                else:
                    st.success("XGBoost score is below the current threshold.")
                signals = model_score.get("top_signals", [])
                if signals:
                    with st.expander("Why did the model give this score?"):
                        st.dataframe(pd.DataFrame(signals), width="stretch", hide_index=True)
            else:
                st.error(f"Model score unavailable: {model_score.get('reason', 'No model score returned.')}")

            if capture.get("mode") == "safe_benign_test":
                if live_report.get("benign_test_activity_error"):
                    st.error(f"Safe activity generator failed: {live_report['benign_test_activity_error']}")
                elif not live_report.get("benign_test_activity_completed", False):
                    st.warning("Safe activity generator did not complete. Check the terminal capture output.")
                elif not file_events and not registry_events:
                    st.warning("Safe activity ran, but ETW attributed no events. Use the safe capture command again and confirm it runs from Administrator PowerShell.")
            st.subheader("Behavior alert")
            if rule_triggered:
                st.warning("Review recommended · rapid file-change behavior")
                st.write(rule_alert.get("reason", ""))
                evidence = rule_alert.get("evidence", {})
                rule_cols = st.columns(3)
                rule_cols[0].metric("Distinct files written", evidence.get("unique_files_written", 0))
                rule_cols[1].metric("Distinct files renamed", evidence.get("unique_files_renamed", 0))
                rule_cols[2].metric("Distinct files deleted", evidence.get("unique_files_deleted", 0))
                rule = rule_alert.get("rule", {})
                st.caption(
                    f"Rule thresholds: {rule.get('minimum_distinct_files_written', 10)} distinct writes and "
                    f"{rule.get('minimum_distinct_files_renamed_or_deleted', 5)} distinct renames or deletes."
                )
                affected = evidence.get("affected_paths", [])
                if affected:
                    st.dataframe(pd.DataFrame({"Affected path": affected}), width="stretch", hide_index=True)
            event_tabs = st.tabs(["File activity", "Registry activity", "Child processes", "31 BTF fields"])
            with event_tabs[0]:
                if file_events:
                    operation_counts = pd.Series([event.get("operation", "unknown") for event in file_events]).value_counts()
                    st.markdown("**File operations in this capture**")
                    st.dataframe(operation_counts.rename_axis("Operation").reset_index(name="Events"), width="stretch", hide_index=True)
                    st.dataframe(pd.DataFrame(file_events), width="stretch", hide_index=True)
                else:
                    st.info("No file activity was attributed in this capture.")
            with event_tabs[1]:
                if registry_events:
                    operation_counts = pd.Series([event.get("operation", "unknown") for event in registry_events]).value_counts()
                    st.markdown("**Registry operations in this capture**")
                    st.dataframe(operation_counts.rename_axis("Operation").reset_index(name="Events"), width="stretch", hide_index=True)
                    st.dataframe(pd.DataFrame(registry_events), width="stretch", hide_index=True)
                else:
                    st.info("No registry activity was attributed in this capture.")
            with event_tabs[2]:
                if process_events:
                    st.dataframe(pd.DataFrame(process_events), width="stretch", hide_index=True)
                else:
                    st.info("No child processes were attributed in this capture.")
            with event_tabs[3]:
                vector_rows = [
                    {
                        "BTF feature": name,
                        "Observed count": value,
                        "Collection": "Observed" if name in observable and value > 0 else "No event" if name in observable else "Not collected by this monitor",
                    }
                    for name, value in vector.items()
                ]
                st.dataframe(pd.DataFrame(vector_rows), width="stretch", hide_index=True)

            st.caption(
                f"Capture window: {capture.get('window_start_utc', '—')} to {capture.get('window_end_utc', '—')} · "
                f"Dropped events: {stats.get('events_dropped', 0) + stats.get('registry_events_dropped', 0)} · "
                f"Forced shutdown: {stats.get('shutdown_forced', False)}"
            )
        except Exception as exc:
            st.error(f"Could not load the live capture report: {type(exc).__name__}: {exc}")


with mlran_tab:
    render_mlran_detection_example()


