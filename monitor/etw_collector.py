"""Bounded, process-isolated Windows Kernel-File ETW capture.

The collector does not start automatically. Call ``run`` explicitly from a
Windows application entry point protected by ``if __name__ == '__main__'``.
"""
from __future__ import annotations

import math
import multiprocessing as mp
import queue
import subprocess
import sys
import time
import uuid
from collections import Counter
from types import SimpleNamespace
from typing import Callable

PROVIDER_NAME = "Microsoft-Windows-Kernel-File"
PROVIDER_GUID = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"
PROCESS_PROVIDER_NAME = "Microsoft-Windows-Kernel-Process"
PROCESS_PROVIDER_GUID = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
REGISTRY_PROVIDER_NAME = "Microsoft-Windows-Kernel-Registry"
REGISTRY_PROVIDER_GUID = "{70EB4F03-C1DE-4F73-A051-33D13D5413BD}"
REGISTRY_EVENT_MAP = {
    1: "create", 2: "open", 3: "delete", 4: "query", 5: "write",
    6: "delete", 7: "read", 8: "enumerate", 9: "enumerate",
    10: "query", 11: "write", 12: "write", 14: "query", 15: "write",
}
PROVIDER_KEYWORDS = (
    "KERNEL_FILE_KEYWORD_FILEIO",
    "KERNEL_FILE_KEYWORD_FILENAME",
    "KERNEL_FILE_KEYWORD_CREATE",
    "KERNEL_FILE_KEYWORD_READ",
    "KERNEL_FILE_KEYWORD_WRITE",
    "KERNEL_FILE_KEYWORD_DELETE_PATH",
    "KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH",
)
MAX_CAPTURE_SECONDS = 300.0
START_TIMEOUT_SECONDS = 15.0
STOP_TIMEOUT_SECONDS = 8.0
QUEUE_SIZE = 8192


def _capture_worker(output_queue, stop_signal, session_name: str, process_session_name: str, registry_session_name: str, max_seconds: float, pid_filter: int | None, capture_raw_events: bool) -> None:
    """Own the ETW session in a child process so a blocked stop is containable."""
    stats = Counter({
        "total_events": 0,
        "kernel_file": 0,
        "attributed_file": 0,
        "unattributed_file": 0,
        "path_resolved": 0,
        "path_unresolved": 0,
        "callback_errors": 0,
        "events_dropped": 0,
        "raw_event_samples": 0,
        "process_child_starts": 0,
        "process_start_events_dropped": 0,
        "registry_events": 0,
        "registry_events_dropped": 0,
    })
    active_traces = []

    try:
        if sys.platform != "win32":
            raise OSError("Kernel-File ETW capture is available only on Windows.")

        from etw import ETW, GUID, ProviderInfo
        from etw.common import RETURN_RAW_DATA_ON_ERROR
        from features.transformation.kernel_file_processor import KernelFileEventProcessor

        processor = KernelFileEventProcessor()
        data_event_ids = {
            processor.CREATE, processor.READ, processor.WRITE,
            processor.ENUMERATE, processor.RENAME_PATH, processor.DELETE_PATH
        }
        raw_diagnostic_ids = {10, 11, 12, 15, 16, 17, 18, 19, 20, 22, 26, 27, 28, 29, 30}
        raw_event_ids_seen = set()

        class PayloadView:
            def __init__(self, values):
                self._values = values if isinstance(values, dict) else {}

            def __getattr__(self, name):
                return self._values.get(name)

        def on_event(event_tuple):
            stats["total_events"] += 1
            stats["kernel_file"] += 1
            try:
                if not isinstance(event_tuple, (tuple, list)) or len(event_tuple) < 2:
                    raise ValueError("ETW callback did not provide (event_id, payload).")
                event_id, payload = event_tuple[0], event_tuple[1]
                header = payload.get("EventHeader", {}) if isinstance(payload, dict) else {}
                event_header = header.get("EventDescriptor", {}) if isinstance(header, dict) else {}
                pid = header.get("ProcessId") if isinstance(header, dict) else None
                timestamp = header.get("TimeStamp") if isinstance(header, dict) else None
                # pywintrace reports the kernel event opcode as the callback event ID.
                if event_id is None:
                    event_id = event_header.get("Opcode") or event_header.get("Id")
                if capture_raw_events and stats["raw_event_samples"] < 50 and event_id in raw_diagnostic_ids and event_id not in raw_event_ids_seen:
                    raw_sample = {
                        "event_id": event_id,
                        "process_id": pid,
                        "timestamp": str(timestamp),
                        "payload_keys": [key for key in payload if key != "EventHeader"]
                        if isinstance(payload, dict) else [],
                        "payload_preview": repr(payload)[:1600],
                    }
                    try:
                        output_queue.put(("raw_event", raw_sample), timeout=0.1)
                        stats["raw_event_samples"] += 1
                        raw_event_ids_seen.add(event_id)
                    except queue.Full:
                        stats["events_dropped"] += 1
                record = SimpleNamespace(id=event_id, process_id=pid, timestamp=timestamp)
                parsed = PayloadView(payload)
                file_event = processor.process(record, parsed)
                if file_event is None:
                    if event_id in data_event_ids:
                        stats["unattributed_file"] += 1
                        stats["path_unresolved"] += 1
                    return
                stats["attributed_file"] += 1
                stats["path_resolved"] += 1
                try:
                    output_queue.put(("file_event", file_event), timeout=0.1)
                except queue.Full:
                    stats["events_dropped"] += 1
            except Exception:
                stats["callback_errors"] += 1

        def on_process_start(event_tuple):
            try:
                if not isinstance(event_tuple, (tuple, list)) or len(event_tuple) < 2:
                    raise ValueError("Process ETW callback did not provide (event_id, payload).")
                event_id, payload = event_tuple[0], event_tuple[1]
                if event_id != 1 or not isinstance(payload, dict):
                    return
                child_pid = payload.get("ProcessID")
                parent_pid = payload.get("ParentProcessID")
                try:
                    child_pid = int(child_pid)
                    parent_pid = int(parent_pid)
                except (TypeError, ValueError):
                    return
                # ProcessStart's payload identifies the new process and parent.
                # Do not use EventHeader.ProcessId for this relationship.
                if (pid_filter is not None and parent_pid != pid_filter) or child_pid <= 0:
                    return
                header = payload.get("EventHeader", {})
                timestamp = header.get("TimeStamp") if isinstance(header, dict) else None
                process_event = {
                    "parent_pid": parent_pid,
                    "child_pid": child_pid,
                    "process_name": str(payload.get("ImageName") or "unknown"),
                    "timestamp": str(timestamp),
                }
                try:
                    output_queue.put(("process_start", process_event), timeout=0.1)
                    stats["process_child_starts"] += 1
                except queue.Full:
                    stats["process_start_events_dropped"] += 1
            except Exception:
                stats["callback_errors"] += 1

        def on_registry_event(event_tuple):
            try:
                if not isinstance(event_tuple, (tuple, list)) or len(event_tuple) < 2:
                    raise ValueError("Registry ETW callback did not provide (event_id, payload).")
                event_id, payload = event_tuple[0], event_tuple[1]
                operation = REGISTRY_EVENT_MAP.get(event_id)
                if operation is None or not isinstance(payload, dict):
                    return
                header = payload.get("EventHeader", {})
                process_id = header.get("ProcessId") if isinstance(header, dict) else None
                timestamp = header.get("TimeStamp") if isinstance(header, dict) else None
                try:
                    process_id = int(process_id)
                except (TypeError, ValueError):
                    return
                if pid_filter is not None and process_id != pid_filter:
                    return
                registry_event = {
                    "pid": process_id,
                    "operation": operation,
                    "event_id": event_id,
                    "timestamp": str(timestamp),
                }
                try:
                    output_queue.put(("registry_event", registry_event), timeout=0.1)
                    stats["registry_events"] += 1
                except queue.Full:
                    stats["registry_events_dropped"] += 1
            except Exception:
                stats["callback_errors"] += 1

        provider = ProviderInfo(
            name=PROVIDER_NAME,
            guid=GUID(PROVIDER_GUID),
            any_keywords=list(PROVIDER_KEYWORDS),
        )
        trace = ETW(
            session_name=session_name,
            providers=[provider],
            event_callback=on_event,
            pid_whitelist=[pid_filter] if pid_filter is not None else None,
            callback_data_flag=RETURN_RAW_DATA_ON_ERROR,
        )
        active_traces.append(trace)
        trace.start()

        process_provider = ProviderInfo(
            name=PROCESS_PROVIDER_NAME,
            guid=GUID(PROCESS_PROVIDER_GUID),
            any_keywords=["WINEVENT_KEYWORD_PROCESS"],
        )
        if process_provider.any_bitmask == 0:
            raise RuntimeError("Kernel-Process process keyword is not available on this Windows version.")
        process_trace = ETW(
            session_name=process_session_name,
            providers=[process_provider],
            event_callback=on_process_start,
            event_id_filters=[1],
            callback_data_flag=RETURN_RAW_DATA_ON_ERROR,
        )
        active_traces.append(process_trace)
        process_trace.start()
        registry_keywords = [
            "CreateKey", "OpenKey", "DeleteKey", "QueryKey", "SetValueKey",
            "DeleteValueKey", "QueryValueKey", "EnumerateKey", "EnumerateValueKey",
            "QueryMultipleValueKey", "SetInformationKey", "FlushKey",
            "QuerySecurityKey", "SetSecurityKey",
        ]
        registry_provider = ProviderInfo(
            name=REGISTRY_PROVIDER_NAME,
            guid=GUID(REGISTRY_PROVIDER_GUID),
            any_keywords=registry_keywords,
        )
        if registry_provider.any_bitmask == 0:
            raise RuntimeError("Kernel-Registry event keywords are not available on this Windows version.")
        registry_trace = ETW(
            session_name=registry_session_name,
            providers=[registry_provider],
            event_callback=on_registry_event,
            event_id_filters=list(REGISTRY_EVENT_MAP),
            pid_whitelist=[pid_filter] if pid_filter is not None else None,
            callback_data_flag=RETURN_RAW_DATA_ON_ERROR,
        )
        active_traces.append(registry_trace)
        registry_trace.start()
        output_queue.put(("started", {
            "session_name": session_name,
            "process_session_name": process_session_name,
            "registry_session_name": registry_session_name,
        }), timeout=2)
        deadline = time.monotonic() + max_seconds
        while not stop_signal.is_set() and time.monotonic() < deadline:
            stop_signal.wait(min(0.1, max(0.0, deadline - time.monotonic())))

        # Stop both bounded sessions; the parent watchdog can terminate this
        # worker and clean up both names if either provider hangs.
        stop_error = None
        for active_trace in reversed(active_traces):
            try:
                active_trace.stop()
            except BaseException as exc:
                stop_error = stop_error or exc
        if stop_error is not None:
            raise stop_error
        output_queue.put(("stopped", dict(stats)), timeout=2)
    except BaseException as exc:
        for active_trace in reversed(active_traces):
            try:
                active_trace.stop()
            except BaseException:
                pass
        try:
            output_queue.put(("error", {
                "type": type(exc).__name__,
                "message": str(exc),
                "stats": dict(stats),
            }), timeout=2)
        except Exception:
            pass


class ETWCollector:
    """Explicit, bounded Kernel-File capture that emits attributed FileEvents.

    ``run`` blocks for at most the capture duration plus startup/shutdown
    watchdog bounds. A caller may request early stop through an object exposing
    ``is_set()``. Each run uses a unique ETW session name.
    """

    def __init__(self):
        self.stats = {
            "total_events": 0,
            "kernel_file": 0,
            "attributed_file": 0,
            "unattributed_file": 0,
            "path_resolved": 0,
            "path_unresolved": 0,
            "callback_errors": 0,
            "events_dropped": 0,
            "raw_event_samples": 0,
            "process_child_starts": 0,
            "process_start_events_dropped": 0,
            "registry_events": 0,
            "registry_events_dropped": 0,
            "shutdown_forced": False,
            "session_cleanup": None,
        }
        self._file_callback: Callable | None = None
        self._raw_event_callback: Callable | None = None
        self._process_start_callback: Callable | None = None
        self._registry_callback: Callable | None = None
        self._started_callback: Callable | None = None

    def set_file_callback(self, callback):
        if callback is not None and not callable(callback):
            raise TypeError("file callback must be callable or None")
        self._file_callback = callback

    def set_raw_event_callback(self, callback):
        """Optionally receive bounded, PID-filtered raw payload samples for diagnostics."""
        if callback is not None and not callable(callback):
            raise TypeError("raw event callback must be callable or None")
        self._raw_event_callback = callback

    def set_process_start_callback(self, callback):
        if callback is not None and not callable(callback):
            raise TypeError("process start callback must be callable or None")
        self._process_start_callback = callback

    def set_registry_callback(self, callback):
        if callback is not None and not callable(callback):
            raise TypeError("registry callback must be callable or None")
        self._registry_callback = callback

    def set_started_callback(self, callback):
        """Call once in the parent process after all ETW providers report ready."""
        if callback is not None and not callable(callback):
            raise TypeError("started callback must be callable or None")
        self._started_callback = callback
    def _stop_orphaned_session(self, *session_names: str) -> str:
        results = []
        for session_name in session_names:
            try:
                kwargs = {
                    "capture_output": True,
                    "text": True,
                    "timeout": 5,
                    "check": False,
                }
                if hasattr(subprocess, "CREATE_NO_WINDOW"):
                    kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
                result = subprocess.run(
                    ["logman.exe", "stop", session_name, "-ets"], **kwargs
                )
                detail = (result.stdout or result.stderr or "").strip()
                results.append(f"{session_name}: exit={result.returncode}; {detail}"[:500])
            except Exception as exc:
                results.append(f"{session_name}: cleanup_failed: {type(exc).__name__}: {exc}"[:500])
        return " | ".join(results)

    def run(self, stop_event=None, max_seconds=12, pid_filter=None):
        if isinstance(max_seconds, bool) or not isinstance(max_seconds, (int, float)):
            raise TypeError("max_seconds must be numeric")
        max_seconds = float(max_seconds)
        if not math.isfinite(max_seconds) or not 0 < max_seconds <= MAX_CAPTURE_SECONDS:
            raise ValueError(f"max_seconds must be greater than 0 and at most {MAX_CAPTURE_SECONDS:g}")
        if stop_event is not None and not callable(getattr(stop_event, "is_set", None)):
            raise TypeError("stop_event must expose is_set()")
        if pid_filter is not None and (
            isinstance(pid_filter, bool) or not isinstance(pid_filter, int) or pid_filter <= 0
        ):
            raise ValueError("pid_filter must be a positive integer or None")

        self.stats = {
            "total_events": 0,
            "kernel_file": 0,
            "attributed_file": 0,
            "unattributed_file": 0,
            "path_resolved": 0,
            "path_unresolved": 0,
            "callback_errors": 0,
            "events_dropped": 0,
            "raw_event_samples": 0,
            "process_child_starts": 0,
            "process_start_events_dropped": 0,
            "registry_events": 0,
            "registry_events_dropped": 0,
            "shutdown_forced": False,
            "session_cleanup": None,
        }
        session_name = f"AIRD-KernelFile-{uuid.uuid4().hex[:12]}"
        process_session_name = f"AIRD-KernelProc-{uuid.uuid4().hex[:12]}"
        registry_session_name = f"AIRD-KernelReg-{uuid.uuid4().hex[:12]}"
        context = mp.get_context("spawn")
        output_queue = context.Queue(maxsize=QUEUE_SIZE)
        child_stop = context.Event()
        worker = context.Process(
            target=_capture_worker,
            args=(output_queue, child_stop, session_name, process_session_name, registry_session_name, max_seconds, pid_filter, self._raw_event_callback is not None),
            name="AIRD-KernelFile-ETW",
            daemon=True,
        )
        worker.start()
        started_at = time.monotonic()
        started = False
        stop_requested_at = None
        worker_error = None
        callback_error = None

        try:
            while True:
                now = time.monotonic()
                if stop_event is not None and stop_event.is_set() and stop_requested_at is None:
                    child_stop.set()
                    stop_requested_at = now

                if not started and now - started_at > START_TIMEOUT_SECONDS:
                    child_stop.set()
                    worker.terminate()
                    worker.join(timeout=2)
                    self.stats["shutdown_forced"] = True
                    self.stats["session_cleanup"] = self._stop_orphaned_session(session_name, process_session_name, registry_session_name)
                    raise TimeoutError(
                        "ETW worker did not report startup within 15 seconds; "
                        f"cleanup result: {self.stats['session_cleanup']}"
                    )

                if started and now - started_at > START_TIMEOUT_SECONDS + max_seconds + STOP_TIMEOUT_SECONDS:
                    worker.terminate()
                    worker.join(timeout=2)
                    self.stats["shutdown_forced"] = True
                    self.stats["session_cleanup"] = self._stop_orphaned_session(session_name, process_session_name, registry_session_name)
                    break

                if stop_requested_at is not None and now - stop_requested_at > STOP_TIMEOUT_SECONDS:
                    worker.terminate()
                    worker.join(timeout=2)
                    self.stats["shutdown_forced"] = True
                    self.stats["session_cleanup"] = self._stop_orphaned_session(session_name, process_session_name, registry_session_name)
                    break

                try:
                    message, payload = output_queue.get(timeout=0.1)
                except queue.Empty:
                    if not worker.is_alive():
                        break
                    continue

                if message == "started":
                    started = True
                    self.stats["session_name"] = payload["session_name"]
                    if payload.get("process_session_name"):
                        self.stats["process_session_name"] = payload["process_session_name"]
                    if payload.get("registry_session_name"):
                        self.stats["registry_session_name"] = payload["registry_session_name"]
                    if self._started_callback is not None:
                        try:
                            self._started_callback(payload)
                        except Exception as exc:
                            callback_error = exc
                            child_stop.set()
                            stop_requested_at = time.monotonic()
                elif message == "raw_event":
                    self.stats["raw_event_samples"] += 1
                    if self._raw_event_callback is not None:
                        try:
                            self._raw_event_callback(payload)
                        except Exception as exc:
                            callback_error = exc
                            if stop_requested_at is None:
                                child_stop.set()
                                stop_requested_at = time.monotonic()
                elif message == "file_event":
                    self.stats["attributed_file"] += 1
                    self.stats["path_resolved"] += 1
                    if self._file_callback is not None:
                        try:
                            self._file_callback(payload)
                        except Exception as exc:
                            callback_error = exc
                            if stop_requested_at is None:
                                child_stop.set()
                                stop_requested_at = time.monotonic()
                elif message == "process_start":
                    self.stats["process_child_starts"] += 1
                    if self._process_start_callback is not None:
                        try:
                            self._process_start_callback(payload)
                        except Exception as exc:
                            callback_error = exc
                            if stop_requested_at is None:
                                child_stop.set()
                                stop_requested_at = time.monotonic()
                elif message == "registry_event":
                    self.stats["registry_events"] += 1
                    if self._registry_callback is not None:
                        try:
                            self._registry_callback(payload)
                        except Exception as exc:
                            callback_error = exc
                            if stop_requested_at is None:
                                child_stop.set()
                                stop_requested_at = time.monotonic()
                elif message == "stopped":
                    for key, value in payload.items():
                        self.stats[key] = value
                    break
                elif message == "error":
                    worker_error = payload
                    for key, value in payload.get("stats", {}).items():
                        self.stats[key] = value
                    break

                if not worker.is_alive() and message not in ("stopped", "error"):
                    break

            worker.join(timeout=1)
            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=2)
                self.stats["shutdown_forced"] = True
                self.stats["session_cleanup"] = self._stop_orphaned_session(session_name, process_session_name, registry_session_name)
        finally:
            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=2)
            output_queue.close()
            output_queue.join_thread()
            if worker.exitcode is not None:
                worker.close()

        if callback_error is not None:
            raise RuntimeError(f"ETW callback failed: {callback_error}") from callback_error
        if worker_error is not None:
            raise RuntimeError(
                f"ETW capture failed: {worker_error['type']}: {worker_error['message']}"
            )
        if self.stats["shutdown_forced"]:
            raise TimeoutError(
                "ETW worker did not stop in time; it was terminated and a bounded session cleanup was attempted. "
                f"Cleanup result: {self.stats['session_cleanup']}"
            )
        return dict(self.stats)
