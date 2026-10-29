from dataclasses import dataclass
from typing import Any, Optional

@dataclass
class KernelFileIdentity:
    file_key: Any
    path: str
    pid: int
    timestamp: str
    file_object: Any = None

class KernelFileIdentityCorrelator:
    def __init__(self):
        self._identities = {}
        self._objects = {}
    def register_name(self, file_key, path, pid, timestamp, file_object=None):
        if file_key is not None and path:
            identity = KernelFileIdentity(file_key, str(path), pid, str(timestamp), file_object)
            self._identities[file_key] = identity
            if file_object is not None:
                self._objects[file_object] = identity
    def get(self, file_key) -> Optional[KernelFileIdentity]:
        return self._identities.get(file_key)
    def get_by_object(self, file_object) -> Optional[KernelFileIdentity]:
        if file_object is None:
            return None
        return self._objects.get(file_object)
    def update_timestamp(self, file_key, timestamp, pid=None):
        item = self._identities.get(file_key)
        if item:
            item.timestamp = str(timestamp)
            if pid is not None: item.pid = pid
    def rename(self, file_key, new_path, timestamp, pid, file_object=None):
        item = self.get(file_key) or self.get_by_object(file_object)
        if item:
            item.path, item.timestamp, item.pid = str(new_path), str(timestamp), pid
            if file_object is not None: item.file_object = file_object
            if file_key is not None: self._identities[file_key] = item
            if file_object is not None: self._objects[file_object] = item
    def remove(self, file_key):
        item = self._identities.pop(file_key, None)
        if item is not None:
            self._objects = {key: value for key, value in self._objects.items() if value is not item}
    def clear(self):
        self._identities.clear()
        self._objects.clear()
