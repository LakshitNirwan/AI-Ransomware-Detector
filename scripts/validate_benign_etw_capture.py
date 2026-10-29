"""Run a short, PID-filtered ETW check using only self-created temp files."""
from __future__ import annotations

import ctypes
from collections import Counter
import os
import tempfile
import threading
import time
import uuid
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from monitor.etw_collector import ETWCollector


def main() -> int:
    if os.name == "nt" and not ctypes.windll.shell32.IsUserAnAdmin():
        print("ETW permission is required. Open PowerShell as Administrator, then run:")
        print("  py -3.12 .\\scripts\\validate_benign_etw_capture.py")
        return 3

    pid = os.getpid()
    temp_root = Path(tempfile.gettempdir()).resolve()
    work_dir = temp_root / f"air_benign_etw_{pid}_{uuid.uuid4().hex[:8]}"
    work_dir.mkdir()
    captured = []
    raw_samples = []
    collector = ETWCollector()
    collector.set_file_callback(captured.append)
    collector.set_raw_event_callback(raw_samples.append)
    activity_error = []

    def benign_file_activity():
        try:
            time.sleep(1.5)
            source = work_dir / "sample.txt"
            source.write_text("benign ETW validation\n", encoding="utf-8")
            source.read_text(encoding="utf-8")
            source.write_text("updated benign validation\n", encoding="utf-8")
            destination = work_dir / "sample.renamed.txt"
            source.rename(destination)
            destination.unlink()
        except Exception as exc:
            activity_error.append(f"{type(exc).__name__}: {exc}")

    activity = threading.Thread(target=benign_file_activity, name="benign-file-activity")
    try:
        activity.start()
        try:
            stats = collector.run(max_seconds=8, pid_filter=pid)
        except (RuntimeError, TimeoutError) as exc:
            print(f"ETW capture did not complete: {exc}")
            return 3

        activity.join(timeout=3)
        print(f"Process ID filter: {pid}")
        print(f"Collector statistics: {stats}")
        print(f"Attributed file events received: {len(captured)}")
        print(f"Raw payload samples received: {len(raw_samples)}")
        print("Raw event ID counts:", dict(Counter(sample["event_id"] for sample in raw_samples)))
        for sample in raw_samples:
            print(f"  RAW id={sample['event_id']} keys={sample['payload_keys']} payload={sample['payload_preview']}")
        for event in captured[:12]:
            print(
                f"  {event.timestamp} | {event.operation.value} | {event.path}"
                + (f" -> {event.related_path}" if event.related_path else "")
            )
        if activity_error:
            print(f"Benign activity error: {activity_error[0]}")
            return 1
        if not captured:
            print("No attributed file events were received; inspect provider permissions and payload mapping.")
            return 2
        print("ETW capture and shutdown completed; review payload samples above for path mapping.")
        return 0
    finally:
        activity.join(timeout=3)
        resolved = work_dir.resolve()
        if resolved.parent == temp_root and resolved.name.startswith(f"air_benign_etw_{pid}_"):
            for item in resolved.iterdir():
                if item.is_file():
                    item.unlink()
            resolved.rmdir()


if __name__ == "__main__":
    raise SystemExit(main())
