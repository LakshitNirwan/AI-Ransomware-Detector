import ctypes, os
from pathlib import Path
from typing import Optional

class WindowsFileMetadata:
    """Resolves ETW device paths before querying current filesystem metadata."""
    def __init__(self):
        self._device_map = self._build_device_map() if os.name == "nt" else {}
    @staticmethod
    def _build_device_map():
        mapping = {}
        kernel32 = ctypes.windll.kernel32
        mask = kernel32.GetLogicalDrives()
        for index in range(26):
            if not mask & (1 << index): continue
            drive = f"{chr(ord('A') + index)}:"
            size = 1024
            while True:
                buffer = ctypes.create_unicode_buffer(size)
                result = kernel32.QueryDosDeviceW(ctypes.c_wchar_p(drive), buffer, size)
                if not result: break
                if result < size - 1:
                    if buffer.value: mapping[buffer.value.lower()] = drive
                    break
                size *= 2
        return mapping
    def to_dos_path(self, etw_path: str) -> Optional[str]:
        if not etw_path: return None
        path = etw_path.replace("/", "\\")
        if len(path) >= 2 and path[1] == ":": return path
        lower = path.lower()
        for device, drive in self._device_map.items():
            if lower == device: return drive + "\\"
            if lower.startswith(device + "\\"):
                return drive + path[len(device):]
        return None
    def file_exists(self, etw_path: str) -> bool:
        path = self.to_dos_path(etw_path)
        try: return bool(path and Path(path).is_file())
        except OSError: return False
    def get_size(self, etw_path: str) -> Optional[int]:
        path = self.to_dos_path(etw_path)
        try:
            p = Path(path) if path else None
            return p.stat().st_size if p and p.is_file() else None
        except (OSError, PermissionError): return None
