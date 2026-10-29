from dataclasses import dataclass
from typing import Dict, Optional
from .schema import FileEvent, FileOperation

@dataclass
class FileState:
    path: str
    exists: bool = True
    first_observed_size: Optional[int] = None
    latest_observed_size: Optional[int] = None
    size: Optional[int] = None
    content_hash: Optional[str] = None
    extension: str = ""
    read_count: int = 0
    write_count: int = 0
    create_count: int = 0
    delete_count: int = 0
    rename_count: int = 0
    def observe_size(self, size):
        if size is None: return
        if size < 0: raise ValueError("file size cannot be negative")
        if self.first_observed_size is None: self.first_observed_size = size
        self.latest_observed_size = self.size = size

class FileStateTracker:
    def __init__(self, pid: int):
        if pid <= 0: raise ValueError("PID must be positive")
        self.pid = pid
        self._files: Dict[str, FileState] = {}
    @staticmethod
    def _normalize_path(path): return path.replace("/", "\\").lower()
    def _get_or_create(self, path):
        key = self._normalize_path(path)
        if key not in self._files:
            ext = FileEvent(self.pid, "state", FileOperation.OPEN, path).extension
            self._files[key] = FileState(path=path, extension=ext)
        return self._files[key]
    def get_state(self, path): return self._files.get(self._normalize_path(path))
    def apply(self, event: FileEvent):
        event.validate()
        if event.pid != self.pid: raise ValueError("Event PID does not match tracker PID")
        state = self._get_or_create(event.path)
        if event.operation == FileOperation.OPEN: state.exists = True
        elif event.operation == FileOperation.READ:
            state.read_count += 1; state.observe_size(event.size)
        elif event.operation == FileOperation.WRITE:
            state.write_count += 1; state.observe_size(event.size)
            if event.content_hash is not None: state.content_hash = event.content_hash
        elif event.operation == FileOperation.CREATE:
            state.exists = True; state.create_count += 1; state.observe_size(event.size)
            if event.content_hash is not None: state.content_hash = event.content_hash
        elif event.operation == FileOperation.RENAME:
            state.rename_count += 1; state.exists = False
            new = self._get_or_create(event.related_path); new.exists = True
            new.observe_size(event.size if event.size is not None else state.size)
            new.content_hash = event.content_hash or state.content_hash
        elif event.operation == FileOperation.DELETE:
            state.delete_count += 1; state.exists = False
        return state
    def all_states(self): return list(self._files.values())
