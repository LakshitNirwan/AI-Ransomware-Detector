"""Conservative, explainable live file-activity review rules.

These rules are a monitoring aid, not a trained ransomware classifier. Their
thresholds require calibration on representative benign and ransomware traces.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping

from features.transformation.schema import FileEvent, FileOperation


class FileBehaviorDetector:
    def __init__(self, min_written_files: int = 10, min_changed_files: int = 5):
        for name, value in (("min_written_files", min_written_files),
                            ("min_changed_files", min_changed_files)):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self.min_written_files = min_written_files
        self.min_changed_files = min_changed_files

    def evaluate(self, pid: int, btf_vector: Mapping[str, int], events: Iterable[FileEvent]) -> dict:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("PID must be a positive integer")
        batch = tuple(events)
        aliases: dict[str, str] = {}
        by_file: dict[str, set[FileOperation]] = defaultdict(set)
        paths: dict[str, set[str]] = defaultdict(set)
        write_events = 0
        for event in batch:
            event.validate()
            if event.pid != pid:
                raise ValueError("All file events must belong to the monitored PID")
            path_key = event.path.replace("/", "\\").casefold()
            identity = aliases.get(path_key, path_key)
            paths[identity].add(event.path)
            by_file[identity].add(event.operation)
            if event.operation == FileOperation.WRITE:
                write_events += 1
            if event.operation == FileOperation.RENAME and event.related_path:
                destination_key = event.related_path.replace("/", "\\").casefold()
                aliases[destination_key] = identity
                paths[identity].add(event.related_path)

        written = {key for key, ops in by_file.items() if FileOperation.WRITE in ops}
        renamed = {key for key, ops in by_file.items() if FileOperation.RENAME in ops}
        deleted = {key for key, ops in by_file.items() if FileOperation.DELETE in ops}
        changed = renamed | deleted
        write_count = int(btf_vector.get("file_activity.write", 0))

        triggered = (
            len(written) >= self.min_written_files
            and len(changed) >= self.min_changed_files
        )
        affected_keys = written | changed
        evidence = {
            "pid": pid,
            "window_file_events": len(batch),
            "write_events": write_count,
            "unique_files_written": len(written),
            "unique_files_renamed": len(renamed),
            "unique_files_deleted": len(deleted),
            "affected_paths": sorted(
                path for key in affected_keys for path in paths.get(key, set())
            ),
        }
        if triggered:
            reason = (
                f"This process wrote to {len(written)} distinct files and renamed or deleted "
                f"{len(changed)} distinct files in the capture window."
            )
            return {
                "status": "review_recommended",
                "alert_type": "rapid_file_change_activity",
                "classification": "heuristic_behavior_alert",
                "reason": reason,
                "rule": {
                    "minimum_distinct_files_written": self.min_written_files,
                    "minimum_distinct_files_renamed_or_deleted": self.min_changed_files,
                },
                "evidence": evidence,
                "response": {
                    "mode": "simulation_only",
                    "action": "request_manual_review",
                    "executed": False,
                },
                "limitation": "This uncalibrated rule identifies rapid file changes; it does not prove ransomware activity.",
            }
        return {
            "status": "no_rule_triggered",
            "alert_type": None,
            "classification": "heuristic_behavior_monitoring",
            "reason": "The configured rapid file-change rule was not met in this window.",
            "rule": {
                "minimum_distinct_files_written": self.min_written_files,
                "minimum_distinct_files_renamed_or_deleted": self.min_changed_files,
            },
            "evidence": evidence,
            "response": None,
            "limitation": "This uncalibrated rule does not establish that the process is benign.",
        }
