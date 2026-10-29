"""Build an explainable ransomware-like alert from synthetic events only.

No ransomware runs and no real files are created, changed, renamed, or deleted.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from alerts.file_behavior_detector import FileBehaviorDetector
from features.btf.schema import BTFVector
from features.transformation.schema import FileEvent, FileOperation
from ml.live_btf_scoring import score_btf_vector

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = ROOT / "results" / "live_btf" / "simulation_latest.json"
SIMULATED_PID = 424242


def build_simulated_report() -> dict:
    """Return a report for 12 synthetic writes and 8 synthetic renames."""
    start = datetime.now(timezone.utc)
    events: list[FileEvent] = []
    for index in range(12):
        path = f"C:/AIRD-SIMULATION/Documents/report_{index + 1:02d}.docx"
        events.append(FileEvent(
            SIMULATED_PID, (start + timedelta(milliseconds=index * 100)).isoformat(),
            FileOperation.WRITE, path, size=2048,
        ))
    for index in range(8):
        path = f"C:/AIRD-SIMULATION/Documents/report_{index + 1:02d}.docx"
        events.append(FileEvent(
            SIMULATED_PID, (start + timedelta(seconds=2, milliseconds=index * 100)).isoformat(),
            FileOperation.RENAME, path, related_path=path + ".locked", size=2048,
        ))
    for event in events:
        event.validate()

    vector = BTFVector(file_activity={"write": 12, "rename": 8}).to_flat_dict()
    alert = FileBehaviorDetector().evaluate(SIMULATED_PID, vector, events)
    model_scoring = score_btf_vector(vector)
    end = datetime.now(timezone.utc)
    return {
        "simulation": {
            "is_simulation": True,
            "title": "SAFE SIMULATED RANSOMWARE-LIKE CASE",
            "notice": (
                "Scenario replay only: generated event records. No ransomware ran "
                "and no real files were changed. This is not a live capture."
            ),
        },
        "capture": {
            "source": "Synthetic in-memory file events; no ETW session",
            "pid": None,
            "window_start_utc": start.isoformat(),
            "window_end_utc": end.isoformat(),
            "elapsed_seconds": round((end - start).total_seconds(), 3),
        },
        "coverage": {
            "canonical_btf_fields": 31,
            "observable_fields_in_this_simulation": [
                "file_activity.write", "file_activity.rename"
            ],
            "note": "Only the two listed fields contain synthetic counts.",
        },
        "observed_file_events": [
            {
                "timestamp": event.timestamp,
                "operation": event.operation.value,
                "path": event.path,
                "related_path": event.related_path,
                "size_bytes": event.size,
                "event_source": "scenario replay",
            }
            for event in events
        ],
        "btf_vector_31": vector,
        "behavior_alert": alert,
        "model_scoring": model_scoring,

    }


def write_simulated_report(path: Path = OUTPUT_PATH) -> dict:
    report = build_simulated_report()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + chr(10),
        encoding="utf-8",
    )
    return report


def main() -> int:
    report = write_simulated_report()
    alert = report["behavior_alert"]
    evidence = alert["evidence"]
    score = report["model_scoring"]
    print(f"XGBoost prototype risk score: {score.get('probability_ransomware', 0):.1%} ({score.get('predicted_label', score.get('status', 'unavailable'))})")
    print(report["simulation"]["title"])
    print(report["simulation"]["notice"])
    print(f"Alert: {alert['status']} - {alert['reason']}")
    print(
        f"Evidence: {evidence['unique_files_written']} distinct files written; "
        f"{evidence['unique_files_renamed']} renamed; "
        f"{evidence['unique_files_deleted']} deleted."
    )
    print(
        f"Thresholds: write {alert['rule']['minimum_distinct_files_written']}; "
        f"rename/delete {alert['rule']['minimum_distinct_files_renamed_or_deleted']}."
    )
    print(f"Saved simulation report: {OUTPUT_PATH}")
    return 0 if alert["status"] == "review_recommended" else 1


if __name__ == "__main__":
    raise SystemExit(main())