from dataclasses import dataclass
from typing import Optional
from .schema import FileEvent, FileOperation
from .state_tracker import FileStateTracker, FileState

@dataclass(frozen=True)
class TransformationEvidence:
    pid: int
    original_path: str
    final_path: str
    original_extension: str
    final_extension: str
    original_size: Optional[int]
    final_size: Optional[int]
    original_hash: Optional[str]
    final_hash: Optional[str]
    content_changed: bool
    size_changed: bool
    extension_changed: bool
    renamed: bool
    deleted: bool
    original_preserved: bool
    def to_dict(self): return {k:getattr(self,k) for k in self.__dataclass_fields__}

@dataclass
class _TrackedTransformation:
    original_path: str
    original_extension: str
    original_size: Optional[int] = None
    original_hash: Optional[str] = None
    final_path: str = ""
    final_extension: str = ""
    final_size: Optional[int] = None
    final_hash: Optional[str] = None
    content_changed: bool = False
    size_changed: bool = False
    extension_changed: bool = False
    renamed: bool = False
    deleted: bool = False

class TransformationAnalyzer:
    def __init__(self, pid: int):
        if pid <= 0: raise ValueError("PID must be positive")
        self.pid = pid
        self.tracker = FileStateTracker(pid)
        self._transformations = {}
    @staticmethod
    def _key(path): return path.replace("/", "\\").lower()
    def _ensure_transformation(self, event, state_before):
        key = self._key(event.path)
        if key not in self._transformations:
            if state_before:
                values = (state_before.path, state_before.extension, state_before.size, state_before.content_hash)
            else:
                values = (event.path, event.extension, None, None)
            self._transformations[key] = _TrackedTransformation(
                original_path=values[0], original_extension=values[1], original_size=values[2],
                original_hash=values[3], final_path=event.path, final_extension=event.extension)
        return self._transformations[key]
    def apply(self, event: FileEvent):
        event.validate()
        if event.pid != self.pid: raise ValueError(f"Event PID {event.pid} does not match analyzer PID {self.pid}")
        before = self.tracker.get_state(event.path)
        t = self._ensure_transformation(event, before)
        if event.operation in (FileOperation.OPEN, FileOperation.READ):
            t.final_path, t.final_extension = event.path, event.extension
        elif event.operation == FileOperation.WRITE:
            if before:
                if before.content_hash is not None and event.content_hash is not None:
                    t.content_changed |= before.content_hash != event.content_hash
                if before.size is not None and event.size is not None:
                    t.size_changed |= before.size != event.size
            t.final_size, t.final_hash = event.size, event.content_hash
            t.final_path, t.final_extension = event.path, event.extension
        elif event.operation == FileOperation.CREATE:
            if t.original_size is None: t.original_size = event.size
            if t.original_hash is None: t.original_hash = event.content_hash
            t.final_size, t.final_hash = event.size, event.content_hash
            t.final_path, t.final_extension = event.path, event.extension
        elif event.operation == FileOperation.RENAME:
            t.renamed = True; t.final_path = event.related_path
            t.final_extension = FileEvent(self.pid, event.timestamp, FileOperation.OPEN, event.related_path).extension
            t.extension_changed |= t.original_extension != t.final_extension
            if before: t.final_size, t.final_hash = before.size, before.content_hash
        elif event.operation == FileOperation.DELETE:
            t.deleted = True; t.final_path, t.final_extension = event.path, event.extension
        self.tracker.apply(event)
        return self._build_evidence(t)
    def _build_evidence(self,t):
        return TransformationEvidence(self.pid,t.original_path,t.final_path,t.original_extension,t.final_extension,
            t.original_size,t.final_size,t.original_hash,t.final_hash,t.content_changed,t.size_changed,
            t.extension_changed,t.renamed,t.deleted,not t.renamed)
    def analyze(self, events):
        for event in events: self.apply(event)
        return [self._build_evidence(t) for t in self._transformations.values()]
