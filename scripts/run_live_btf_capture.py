"""Capture one bounded PID-filtered Windows file-activity window as BTF."""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import subprocess
import tempfile
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from alerts.file_behavior_detector import FileBehaviorDetector
from features.btf.schema import BTFVector
from features.btf.runtime_coordinator import BFTRuntimeCoordinator
from monitor.etw_collector import ETWCollector
from ml.live_btf_scoring import score_btf_vector


OBSERVED_BTF_FIELDS = (
    "file_activity.open", "file_activity.read", "file_activity.write",
    "file_activity.delete", "file_activity.rename", "file_activity.enumerate",
    "process_activity.create", "execution_activity.process_start",
    "registry_activity.open", "registry_activity.read", "registry_activity.query",
    "registry_activity.write", "registry_activity.create", "registry_activity.delete",
    "registry_activity.enumerate",
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture a bounded process or system-wide ETW window and print 31 BTF fields per process."
    )
    parser.add_argument("--pid", type=int, help="PID of the process to observe")
    parser.add_argument("--system-wide", action="store_true",
                        help="capture file, registry, and process-start events from all processes")
    parser.add_argument("--benign-test", action="store_true",
                        help="capture only a safe temporary text-file activity test from this process")
    parser.add_argument("--seconds", type=float, default=30.0, help="Capture duration, 1–120 seconds (default: 30)")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Live Kernel-File ETW capture is available only on Windows.")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("ETW permission is required. Open PowerShell as Administrator and rerun this command.")
        return 3
    if sum((bool(args.benign_test), bool(args.system_wide), args.pid is not None)) > 1:
        parser.error("choose only one of --pid, --system-wide, or --benign-test")
    if not args.benign_test and not args.system_wide and args.pid is None:
        parser.error("provide --pid, --system-wide, or use --benign-test")
    if args.pid is not None and args.pid <= 0:
        parser.error("--pid must be a positive process ID")
    if not 1 <= args.seconds <= 120:
        parser.error("--seconds must be between 1 and 120")
    if args.benign_test and args.seconds < 5:
        parser.error("--benign-test requires at least 5 seconds")

    target_pid = os.getpid() if args.benign_test else args.pid
    coordinators = {}

    def coordinator_for(pid):
        if pid not in coordinators:
            coordinators[pid] = BFTRuntimeCoordinator(pid)
        return coordinators[pid]

    if target_pid is not None:
        coordinator_for(target_pid)
    observed_events = []
    observed_process_events = []
    observed_registry_events = []
    file_events_by_pid = {}
    raw_diagnostics = []
    collector = ETWCollector()
    capture_ready = threading.Event()
    activity_completed = []
    capture_shutdown_warning = None
    collector.set_started_callback(lambda _info: capture_ready.set())

    def on_file_event(event):
        coordinator_for(event.pid).process_event(event)
        file_events_by_pid.setdefault(event.pid, []).append(event)
        observed_events.append({
            "pid": event.pid,
            "timestamp": event.timestamp,
            "operation": event.operation.value,
            "path": event.path,
            "related_path": event.related_path,
            "size_bytes": event.size,
        })
        print(f"{event.timestamp} | PID {event.pid} | {event.operation.value:<9} | {event.path}"
              + (f" -> {event.related_path}" if event.related_path else ""), flush=True)

    collector.set_file_callback(on_file_event)
    def on_process_start(process_event):
        if int(process_event.get("parent_pid", 0)) <= 0:
            return
        observed = coordinator_for(process_event["parent_pid"]).record_child_process_start(
            parent_pid=process_event["parent_pid"],
            child_pid=process_event["child_pid"],
            process_name=process_event["process_name"],
            timestamp=process_event["timestamp"],
        )
        if observed is not None:
            observed_process_events.append(observed)
            print(
                f"{observed['timestamp']} | process start | PID {observed['child_pid']} "
                f"({observed['process_name']})",
                flush=True,
            )

    collector.set_process_start_callback(on_process_start)

    def on_registry_event(registry_event):
        observed = coordinator_for(registry_event["pid"]).record_registry_activity(
            pid=registry_event["pid"],
            operation=registry_event["operation"],
            timestamp=registry_event["timestamp"],
        )
        if observed is not None:
            observed_registry_events.append({
                "pid": observed["pid"],
                "timestamp": observed["timestamp"],
                "operation": observed["operation"],
                "event_id": registry_event["event_id"],
            })
            print(
                f"{observed['timestamp']} | registry {observed['operation']}",
                flush=True,
            )

    collector.set_registry_callback(on_registry_event)
    if args.benign_test:
        collector.set_raw_event_callback(
            lambda sample: raw_diagnostics.append(sample)
            if sample.get("event_id") in {10, 12, 20, 21, 25} else None
        )
    activity_error = []

    def create_benign_activity(directory: str) -> None:
        try:
            if not capture_ready.wait(timeout=16):
                raise TimeoutError("ETW providers did not report ready; safe activity was not started.")
            time.sleep(0.2)
            source = Path(directory) / "sample.txt"
            source.write_text("safe live BTF capture\n", encoding="utf-8")
            source.read_text(encoding="utf-8")
            list(Path(directory).iterdir())
            subprocess.run(
                [sys.executable, "-c", "pass"],
                cwd=directory,
                check=True,
                capture_output=True,
                text=True,
            )
            import winreg

            registry_key_path = rf"Software\AIRD-BenignCapture-{Path(directory).name}"
            registry_key = winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER, registry_key_path, 0,
                winreg.KEY_READ | winreg.KEY_WRITE,
            )
            try:
                winreg.SetValueEx(registry_key, "Probe", 0, winreg.REG_SZ, "benign")
                winreg.QueryValueEx(registry_key, "Probe")
                winreg.DeleteValue(registry_key, "Probe")
            finally:
                winreg.CloseKey(registry_key)
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, registry_key_path)
                except FileNotFoundError:
                    pass
            source.write_text("updated safe live BTF capture\n", encoding="utf-8")
            renamed = Path(directory) / "sample.renamed.txt"
            source.rename(renamed)
            renamed.unlink()
            activity_completed.append(True)
        except Exception as exc:
            activity_error.append(f"{type(exc).__name__}: {exc}")

    with tempfile.TemporaryDirectory(prefix="air_live_btf_") as safe_dir:
        activity = (threading.Thread(target=create_benign_activity, args=(safe_dir,), daemon=True)
                    if args.benign_test else None)
        if activity is not None:
            activity.start()
        started = datetime.now(timezone.utc).isoformat()
        start_clock = time.monotonic()
        mode = "safe temporary-file check" if args.benign_test else "system-wide" if args.system_wide else "selected process"
        target_label = f"PID {target_pid}" if target_pid is not None else "all process IDs"
        print(f"Capturing {mode} ({target_label}) for up to {args.seconds:g}s...", flush=True)
        try:
            stats = collector.run(max_seconds=args.seconds, pid_filter=target_pid)
        except TimeoutError as exc:
            # Keep the events already delivered to the parent process. A provider
            # can hang during stop even after the bounded capture window ended.
            stats = dict(collector.stats)
            capture_shutdown_warning = str(exc)
            print(
                "WARNING: ETW shutdown timed out. Saving all events collected before shutdown.",
                flush=True,
            )
        if activity is not None:
            activity.join(timeout=17)
        ended = datetime.now(timezone.utc).isoformat()
        elapsed = round(time.monotonic() - start_clock, 3)
    ended = datetime.now(timezone.utc).isoformat()
    per_process = {}
    for pid, process_coordinator in coordinators.items():
        vector_for_pid = process_coordinator.btf_vector().to_flat_dict()
        process_file_events = file_events_by_pid.get(pid, [])
        process_registry_events = [event for event in observed_registry_events if event["pid"] == pid]
        process_alert = FileBehaviorDetector().evaluate(pid, vector_for_pid, process_file_events)
        per_process[str(pid)] = {
            "file_event_count": len(process_file_events),
            "registry_event_count": len(process_registry_events),
            "process_start_count": sum(event["parent_pid"] == pid for event in observed_process_events),
            "btf_vector_31": vector_for_pid,
            "behavior_alert": process_alert,
        }

    if target_pid is not None:
        vector = per_process.get(str(target_pid), {}).get("btf_vector_31", coordinator_for(target_pid).btf_vector().to_flat_dict())
        try:
            model_scoring = score_btf_vector(vector)
        except Exception as exc:
            model_scoring = {"status": "unavailable", "reason": f"{type(exc).__name__}: {exc}"}
        if args.benign_test and model_scoring.get("status") == "prototype_live_score":
            model_scoring["raw_threshold_crossed"] = bool(model_scoring.get("alert_triggered", False))
            model_scoring["alert_triggered"] = False
            model_scoring["alert_suppressed_for_known_benign_test"] = True
        behavior_alert = per_process.get(str(target_pid), {}).get("behavior_alert", {})
    else:
        vector = {}
        model_scoring = {"status": "select_process_to_score", "reason": "System-wide event totals span multiple processes. Select a PID to score its separate process-centered BTF vector."}
        behavior_alert = {"status": "system_wide_observation", "reason": "Behavior rules are evaluated separately for each process; select a PID to inspect its evidence."}
    report = {
        "capture": {
            "capture_id": uuid.uuid4().hex[:12],
            "source": "Windows Kernel-File, Kernel-Registry, and Kernel-Process ETW",
            "pid": target_pid,
            "mode": "safe_benign_test" if args.benign_test else "system_wide" if args.system_wide else "selected_process",
            "window_start_utc": started,
            "window_end_utc": ended,
            "elapsed_seconds": elapsed,
            "collector_statistics": stats,
            "shutdown_warning": capture_shutdown_warning,
        },
        "coverage": {
            "canonical_btf_fields": len(vector),
            "observable_fields_in_this_collector": list(OBSERVED_BTF_FIELDS),
            "unavailable_fields": [name for name in vector if name not in OBSERVED_BTF_FIELDS],
            "note": "Fields not collected by this collector appear as zero placeholders. Supported fields can also be zero when no matching event was attributed in the window.",
        },
        "observed_file_events": observed_events,
        "observed_process_start_events": observed_process_events,
        "observed_registry_events": observed_registry_events,
        "process_activity_by_pid": per_process,
        "raw_event_diagnostics": raw_diagnostics,
        "benign_test_activity_error": activity_error[0] if activity_error else None,
        "benign_test_activity_completed": bool(activity_completed),
        "btf_vector_31": vector,
        "behavior_alert": behavior_alert,
        "model_scoring": model_scoring,

    }
    canonical_vector = BTFVector().to_flat_dict()
    report["coverage"]["canonical_btf_fields"] = len(canonical_vector)
    report["coverage"]["unavailable_fields"] = [
        name for name in canonical_vector if name not in OBSERVED_BTF_FIELDS
    ]
    live_results = ROOT / "results" / "live_btf"
    live_results.mkdir(parents=True, exist_ok=True)
    report_path = live_results / "latest.json"
    temporary_report = live_results / f".{report['capture']['capture_id']}.tmp"
    temporary_report.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary_report.replace(report_path)
    print("\nLIVE BTF CAPTURE SUMMARY")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if args.benign_test:
        print(f"Safe temporary activity completed: {bool(activity_completed)}")
        if activity_error:
            print(f"Safe activity error: {activity_error[0]}")
    print(f"\nCapture ID: {report['capture']['capture_id']}")
    print(f"Saved latest live capture: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
