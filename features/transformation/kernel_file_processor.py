from typing import Any
from .etw_correlator import KernelFileIdentityCorrelator
from .metadata import WindowsFileMetadata
from .schema import FileEvent, FileOperation

class KernelFileEventProcessor:
    NAME_CREATE=10; NAME_DELETE=11; CREATE=12; READ=15; WRITE=16; RENAME=19; ENUMERATE=20; DELETE_PATH=26; RENAME_PATH=27
    def __init__(self):
        self.correlator = KernelFileIdentityCorrelator()
        self.metadata = WindowsFileMetadata()
    @staticmethod
    def _get(parsed: Any, *names):
        for name in names:
            value = getattr(parsed, name, None)
            if value is not None: return value
        return None
    @staticmethod
    def _pid(record):
        pid = getattr(record, "process_id", None)
        if pid is None or pid <= 0: raise ValueError("ETW record has invalid process ID")
        return pid
    @staticmethod
    def _timestamp(record):
        value = getattr(record, "timestamp", None)
        if value is None: raise ValueError("ETW record has no timestamp")
        return str(value)
    def process(self, record: Any, parsed: Any):
        pid, timestamp = self._pid(record), self._timestamp(record)
        event_id = getattr(record, "id", None)
        if event_id is None: raise ValueError("ETW record has no event ID")
        key = self._get(parsed, "FileKey", "FileObject")
        file_object = self._get(parsed, "FileObject")
        path = self._get(parsed, "FileName", "FilePath")
        if event_id == self.NAME_CREATE:
            if key is not None and path:
                self.correlator.register_name(key, path, pid, timestamp, file_object)
            return None
        # Kernel File's CREATE event is an open/create request; it does not
        # establish that a new file was created, so represent it as OPEN.
        if event_id == self.CREATE and path:
            if key is not None:
                self.correlator.register_name(key, path, pid, timestamp, file_object)
            return FileEvent(pid, timestamp, FileOperation.OPEN, path,
                             size=self.metadata.get_size(path))
        if event_id in (self.READ, self.WRITE):
            identity = self.correlator.get(key) or self.correlator.get_by_object(file_object)
            if identity is None: return None
            self.correlator.update_timestamp(identity.file_key, timestamp, pid)
            op = FileOperation.READ if event_id == self.READ else FileOperation.WRITE
            return FileEvent(pid, timestamp, op, identity.path, size=self.metadata.get_size(identity.path))
        if event_id == self.ENUMERATE:
            identity = self.correlator.get(key) or self.correlator.get_by_object(file_object)
            directory = path or (identity.path if identity is not None else None)
            if not directory:
                return None
            return FileEvent(pid, timestamp, FileOperation.ENUMERATE, directory)
        if event_id == self.RENAME_PATH:
            if not path: return None
            identity = self.correlator.get(key) or self.correlator.get_by_object(file_object)
            if identity is None or identity.path == path: return None
            old = identity.path
            self.correlator.rename(key, path, timestamp, pid, file_object)
            return FileEvent(pid, timestamp, FileOperation.RENAME, old, related_path=path,
                             size=self.metadata.get_size(path))
        if event_id == self.DELETE_PATH:
            if not path: return None
            if key is not None: self.correlator.remove(key)
            return FileEvent(pid, timestamp, FileOperation.DELETE, path)
        if event_id == self.NAME_DELETE:
            if key is not None: self.correlator.remove(key)
        return None
