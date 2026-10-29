
from features.btf.file_event_adapter import FileEventBTFAdapter
from features.transformation.analyzer import (
    TransformationAnalyzer,
    TransformationEvidence,
)
from features.transformation.schema import FileEvent

_REGISTRY_OPERATIONS = {
    "open", "read", "query", "write", "create", "delete", "enumerate"
}


class BFTRuntimeCoordinator:
    """Coordinate transformation analysis and BTF counts for one process."""

    def __init__(self, pid: int):
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("PID must be a positive integer")

        self.pid = pid
        self.analyzer = TransformationAnalyzer(pid)
        self.adapter = FileEventBTFAdapter(pid)
        self._child_process_starts = 0
        self._child_process_events = []
        self._registry_activity = {}
        self._registry_events = []

    def process_event(self, event: FileEvent) -> TransformationEvidence:
        """Process one event and return its transformation evidence."""
        event.validate()

        if event.pid != self.pid:
            raise ValueError(
                f"Event PID {event.pid} does not match coordinator PID {self.pid}"
            )

        # Validate and analyze before incrementing BTF counts.
        # If analysis fails, this event is not counted by the adapter.
        evidence = self.analyzer.apply(event)
        self.adapter.add(event)
        return evidence

    def record_child_process_start(
        self, parent_pid: int, child_pid: int, process_name: str, timestamp: str
    ) -> dict | None:
        """Count a child process start observed for this monitored parent PID."""
        if isinstance(parent_pid, bool) or not isinstance(parent_pid, int) or parent_pid <= 0:
            raise ValueError("parent_pid must be a positive integer")
        if isinstance(child_pid, bool) or not isinstance(child_pid, int) or child_pid <= 0:
            raise ValueError("child_pid must be a positive integer")
        if not process_name or not timestamp:
            raise ValueError("process_name and timestamp are required")
        if parent_pid != self.pid:
            return None
        item = {
            "parent_pid": parent_pid,
            "child_pid": child_pid,
            "process_name": str(process_name),
            "timestamp": str(timestamp),
        }
        self._child_process_starts += 1
        self._child_process_events.append(item)
        return item

    def child_process_events(self) -> list[dict]:
        return list(self._child_process_events)

    def record_registry_activity(self, pid: int, operation: str, timestamp: str) -> dict | None:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("registry event PID must be a positive integer")
        if operation not in _REGISTRY_OPERATIONS or not timestamp:
            raise ValueError("registry operation or timestamp is invalid")
        if pid != self.pid:
            return None
        item = {"pid": pid, "operation": operation, "timestamp": str(timestamp)}
        self._registry_activity[operation] = self._registry_activity.get(operation, 0) + 1
        self._registry_events.append(item)
        return item

    def registry_events(self) -> list[dict]:
        return list(self._registry_events)

    def btf_vector(self):
        """Return the current BTF vector for this process."""
        vector = self.adapter.to_vector()
        if self._child_process_starts:
            vector.process_activity["create"] = self._child_process_starts
            vector.execution_activity["process_start"] = self._child_process_starts
        vector.registry_activity.update(self._registry_activity)
        vector.__post_init__()
        return vector
