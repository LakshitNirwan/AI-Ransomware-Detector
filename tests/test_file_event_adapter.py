
import pytest

from features.btf.file_event_adapter import FileEventBTFAdapter
from features.transformation.schema import FileEvent, FileOperation


def make_event(pid, operation, path=r"C:\Temp\sample.txt", related_path=None):
    return FileEvent(
        pid=pid,
        timestamp="2026-10-20T10:00:00",
        operation=operation,
        path=path,
        related_path=related_path,
    )


def test_single_write_event_increments_btf_counter():
    adapter = FileEventBTFAdapter(pid=1234)
    adapter.add(make_event(1234, FileOperation.WRITE))

    vector = adapter.to_vector()

    assert vector.file_activity == {"write": 1}


def test_multiple_operations_are_counted():
    adapter = FileEventBTFAdapter(pid=1234)
    adapter.add_many([
        make_event(1234, FileOperation.OPEN),
        make_event(1234, FileOperation.READ),
        make_event(1234, FileOperation.WRITE),
        make_event(1234, FileOperation.WRITE),
        make_event(1234, FileOperation.CREATE),
        make_event(
            1234,
            FileOperation.RENAME,
            related_path=r"C:\Temp\renamed.txt",
        ),
        make_event(1234, FileOperation.DELETE),
    ])

    vector = adapter.to_vector()

    assert vector.file_activity == {
        "open": 1,
        "read": 1,
        "write": 2,
        "create": 1,
        "rename": 1,
        "delete": 1,
    }


def test_event_from_another_pid_is_rejected():
    adapter = FileEventBTFAdapter(pid=1234)

    with pytest.raises(ValueError, match="does not match"):
        adapter.add(make_event(5678, FileOperation.WRITE))


def test_invalid_pid_is_rejected():
    with pytest.raises(ValueError):
        FileEventBTFAdapter(pid=0)


def test_empty_adapter_produces_zero_filled_vector():
    adapter = FileEventBTFAdapter(pid=1234)

    vector = adapter.to_vector()

    assert vector.total_events() == 0
    assert vector.file_activity == {}
