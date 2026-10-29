from dataclasses import dataclass
from enum import Enum
from pathlib import PureWindowsPath
from typing import Optional

class FileOperation(str, Enum):
    OPEN="open"; READ="read"; WRITE="write"; CREATE="create"; DELETE="delete"; RENAME="rename"; ENUMERATE="enumerate"

@dataclass(frozen=True)
class FileEvent:
    pid: int
    timestamp: str
    operation: FileOperation
    path: str
    related_path: Optional[str] = None
    size: Optional[int] = None
    content_hash: Optional[str] = None
    @property
    def extension(self):
        return PureWindowsPath(self.path).suffix.lower()
    def validate(self):
        if self.pid <= 0: raise ValueError("PID must be positive")
        if not self.timestamp: raise ValueError("timestamp cannot be empty")
        if not isinstance(self.operation, FileOperation): raise TypeError("operation must be FileOperation")
        if not self.path: raise ValueError("path cannot be empty")
        if self.size is not None and self.size < 0: raise ValueError("size cannot be negative")
        if self.operation == FileOperation.RENAME and not self.related_path:
            raise ValueError("Rename event requires related_path")
        return True
