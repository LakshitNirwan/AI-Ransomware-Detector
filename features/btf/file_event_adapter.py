from collections import Counter
from typing import Iterable

from features.btf.schema import BTFVector
from features.transformation.schema import FileEvent, FileOperation


_OPERATION_TO_BTF_EVENT = {
    FileOperation.OPEN: "open",
    FileOperation.READ: "read",
    FileOperation.WRITE: "write",
    FileOperation.CREATE: "create",
    FileOperation.DELETE: "delete",
    FileOperation.RENAME: "rename",
    FileOperation.ENUMERATE: "enumerate",
}


class FileEventBTFAdapter:
    """Convert validated file events into BTF file-activity counters."""

    def __init__(self, pid: int):
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("PID must be a positive integer")
        self.pid = pid
        self._counts = Counter()

    def add(self, event: FileEvent) -> None:
        event.validate()

        if event.pid != self.pid:
            raise ValueError(
                f"Event PID {event.pid} does not match adapter PID {self.pid}"
            )

        btf_event = _OPERATION_TO_BTF_EVENT.get(event.operation)
        if btf_event is None:
            raise ValueError(f"Unsupported file operation: {event.operation!r}")

        self._counts[btf_event] += 1

    def add_many(self, events: Iterable[FileEvent]) -> None:
        for event in events:
            self.add(event)

    def to_vector(self) -> BTFVector:
        return BTFVector(
            file_activity={
                name: self._counts[name]
                for name in _OPERATION_TO_BTF_EVENT.values()
                if self._counts[name] > 0
            }
        )


if __name__ == "__main__":
    adapter = FileEventBTFAdapter(pid=1234)
    adapter.add(
        FileEvent(
            pid=1234,
            timestamp="2026-10-20T10:00:00",
            operation=FileOperation.WRITE,
            path=r"C:\Temp\example.txt",
        )
    )
    vector = adapter.to_vector()
    assert vector.file_activity["write"] == 1
    print("Adapter smoke test passed:", vector.file_activity)
