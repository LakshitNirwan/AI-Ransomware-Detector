from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any

class BTFDimension(str, Enum):
    FILE = "file_activity"
    PROCESS = "process_activity"
    REGISTRY = "registry_activity"
    NETWORK = "network_activity"
    RESOURCE = "resource_activity"
    EXECUTION = "execution_activity"

BTF_EVENTS = {
    BTFDimension.FILE: ("open", "read", "write", "create", "delete", "rename", "enumerate"),
    BTFDimension.PROCESS: ("create", "enumerate", "open", "memory_write", "thread_context"),
    BTFDimension.REGISTRY: ("open", "read", "query", "write", "create", "delete", "enumerate"),
    BTFDimension.NETWORK: ("connect", "dns", "http", "icmp", "socket"),
    BTFDimension.RESOURCE: ("memory_allocate", "memory_protect", "handle_activity"),
    BTFDimension.EXECUTION: ("process_start", "injection", "persistence", "exception_handler"),
}

@dataclass
class BTFWindow:
    start_time: str
    end_time: str
    def to_dict(self) -> Dict[str, str]:
        return {"start_time": self.start_time, "end_time": self.end_time}

@dataclass
class BTFProcess:
    pid: int
    process_name: str
    parent_pid: int | None = None
    def to_dict(self) -> Dict[str, Any]:
        return {"pid": self.pid, "process_name": self.process_name, "parent_pid": self.parent_pid}

@dataclass
class BTFVector:
    file_activity: Dict[str, int] = field(default_factory=dict)
    process_activity: Dict[str, int] = field(default_factory=dict)
    registry_activity: Dict[str, int] = field(default_factory=dict)
    network_activity: Dict[str, int] = field(default_factory=dict)
    resource_activity: Dict[str, int] = field(default_factory=dict)
    execution_activity: Dict[str, int] = field(default_factory=dict)

    def __post_init__(self):
        values = {
            BTFDimension.FILE:self.file_activity, BTFDimension.PROCESS:self.process_activity,
            BTFDimension.REGISTRY:self.registry_activity, BTFDimension.NETWORK:self.network_activity,
            BTFDimension.RESOURCE:self.resource_activity, BTFDimension.EXECUTION:self.execution_activity}
        for dimension, mapping in values.items():
            for event, count in mapping.items():
                if event not in BTF_EVENTS[dimension]:
                    raise ValueError(f"Invalid BTF event {event!r} for {dimension.value}")
                if isinstance(count, bool) or not isinstance(count, int):
                    raise TypeError("BTF event count must be an integer")
                if count < 0:
                    raise ValueError("BTF event count cannot be negative")

    def to_flat_dict(self) -> Dict[str, int]:
        values = {
            BTFDimension.FILE:self.file_activity, BTFDimension.PROCESS:self.process_activity,
            BTFDimension.REGISTRY:self.registry_activity, BTFDimension.NETWORK:self.network_activity,
            BTFDimension.RESOURCE:self.resource_activity, BTFDimension.EXECUTION:self.execution_activity}
        return {f"{dim.value}.{event}": values[dim].get(event, 0)
                for dim, events in BTF_EVENTS.items() for event in events}

    def total_events(self) -> int:
        return sum(self.to_flat_dict().values())

@dataclass
class BTFRecord:
    process: BTFProcess
    window: BTFWindow
    vector: BTFVector
    schema_version: str = "1.0"
    def to_dict(self) -> Dict[str, Any]:
        return {"schema_version":self.schema_version, "process":self.process.to_dict(),
                "window":self.window.to_dict(), "vector":self.vector.to_flat_dict()}
    def validate(self):
        if not self.schema_version or self.process.pid <= 0 or not self.process.process_name:
            raise ValueError("Invalid BTF schema/process identity")
        if not self.window.start_time or not self.window.end_time:
            raise ValueError("BTF window times cannot be empty")
        self.vector.__post_init__()
        return True
