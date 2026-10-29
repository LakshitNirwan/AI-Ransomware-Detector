
import pytest

from features.btf.runtime_coordinator import BFTRuntimeCoordinator
from features.transformation.schema import FileEvent, FileOperation


def make_event(pid, operation, path=r"C:\Temp\coordinator_test.txt"):
    return FileEvent(
        pid=pid,
        timestamp="2026-10-20T10:00:00",
        operation=operation,
        path=path,
        size=100,
    )


def test_event_updates_transformation_evidence_and_btf_once():
    coordinator = BFTRuntimeCoordinator(pid=1234)

    evidence = coordinator.process_event(
        make_event(1234, FileOperation.WRITE)
    )
    vector = coordinator.btf_vector()

    assert evidence.pid == 1234
    assert vector.file_activity["write"] == 1
    assert vector.total_events() == 1


def test_coordinator_rejects_event_from_another_pid():
    coordinator = BFTRuntimeCoordinator(pid=1234)

    with pytest.raises(ValueError, match="does not match"):
        coordinator.process_event(
            make_event(5678, FileOperation.WRITE)
        )

    assert coordinator.btf_vector().total_events() == 0


def test_multiple_events_are_counted_once_each():
    coordinator = BFTRuntimeCoordinator(pid=1234)

    coordinator.process_event(make_event(1234, FileOperation.OPEN))
    coordinator.process_event(make_event(1234, FileOperation.READ))
    coordinator.process_event(make_event(1234, FileOperation.WRITE))

    vector = coordinator.btf_vector()

    assert vector.file_activity == {
        "open": 1,
        "read": 1,
        "write": 1,
    }
    assert vector.total_events() == 3


def test_child_process_start_updates_two_canonical_btf_counters():
    coordinator = BFTRuntimeCoordinator(pid=1234)
    child = coordinator.record_child_process_start(
        parent_pid=1234,
        child_pid=5678,
        process_name="child.exe",
        timestamp="t1",
    )

    vector = coordinator.btf_vector()

    assert child["child_pid"] == 5678
    assert vector.process_activity == {"create": 1}
    assert vector.execution_activity == {"process_start": 1}
    assert vector.total_events() == 2


def test_unrelated_process_start_is_ignored():
    coordinator = BFTRuntimeCoordinator(pid=1234)
    assert coordinator.record_child_process_start(5678, 9012, "other.exe", "t1") is None
    assert coordinator.btf_vector().total_events() == 0


def test_registry_events_update_matching_canonical_btf_fields():
    coordinator = BFTRuntimeCoordinator(pid=1234)
    coordinator.record_registry_activity(1234, "create", "t1")
    coordinator.record_registry_activity(1234, "write", "t2")
    coordinator.record_registry_activity(1234, "read", "t3")
    coordinator.record_registry_activity(5678, "delete", "t4")

    vector = coordinator.btf_vector()

    assert vector.registry_activity == {"create": 1, "write": 1, "read": 1}
    assert vector.total_events() == 3
