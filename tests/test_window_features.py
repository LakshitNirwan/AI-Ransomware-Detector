import pytest

from features.transformation.schema import FileEvent, FileOperation
from features.transformation.window_features import (
    ETW_TRANSFORMATION_FEATURES,
    extract_etw_transformation_features,
)


def test_empty_window_has_all_eighteen_zero_features():
    result = extract_etw_transformation_features([])
    assert tuple(result) == ETW_TRANSFORMATION_FEATURES
    assert len(result) == 18
    assert set(result.values()) == {0}


def test_rename_alias_preserves_file_sequence_and_extension_change():
    events = [
        FileEvent(123, "1", FileOperation.READ, r"C:\\data\\a.txt"),
        FileEvent(123, "2", FileOperation.WRITE, r"C:\\data\\a.txt"),
        FileEvent(123, "3", FileOperation.RENAME, r"C:\\data\\a.txt", related_path=r"C:\\data\\a.locked"),
        FileEvent(123, "4", FileOperation.READ, r"C:\\data\\a.locked"),
        FileEvent(123, "5", FileOperation.WRITE, r"C:\\data\\a.locked"),
        FileEvent(123, "6", FileOperation.DELETE, r"C:\\data\\a.locked"),
    ]
    result = extract_etw_transformation_features(events)

    assert result["unique_files_observed"] == 1
    assert result["unique_files_read"] == 1
    assert result["unique_files_written"] == 1
    assert result["unique_files_renamed"] == 1
    assert result["unique_files_deleted"] == 1
    assert result["files_read_then_written"] == 1
    assert result["files_written_then_renamed"] == 1
    assert result["files_written_then_deleted"] == 1
    assert result["files_with_extension_change"] == 1
    assert result["files_with_repeated_writes"] == 1
    assert result["write_events_after_first_per_file"] == 1
    assert result["max_writes_per_file"] == 2
    assert result["files_read_written_renamed"] == 1
    assert result["files_read_written_deleted"] == 1


def test_mixed_pid_window_is_rejected():
    with pytest.raises(ValueError, match="one PID"):
        extract_etw_transformation_features([
            FileEvent(123, "1", FileOperation.READ, r"C:\\data\\a.txt"),
            FileEvent(456, "2", FileOperation.WRITE, r"C:\\data\\b.txt"),
        ])
