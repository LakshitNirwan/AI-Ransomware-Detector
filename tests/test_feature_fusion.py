import pytest

from features.btf.file_event_adapter import FileEventBTFAdapter
from features.btf.schema import BTFVector
from features.fusion import (
    BTF_FEATURE_NAMES,
    FUSED_FEATURE_NAMES,
    build_fused_feature_vector,
    build_fused_feature_vector_from_events,
)
from features.transformation.schema import FileEvent, FileOperation
from features.transformation.window_features import ETW_TRANSFORMATION_FEATURES


def test_fused_vector_is_ordered_etw_then_canonical_btf():
    events = [
        FileEvent(123, "1", FileOperation.READ, r"C:\\data\\a.txt"),
        FileEvent(123, "2", FileOperation.WRITE, r"C:\\data\\a.txt"),
    ]
    adapter = FileEventBTFAdapter(123)
    adapter.add_many(events)

    vector = build_fused_feature_vector_from_events(events, adapter.to_vector())

    assert tuple(vector) == FUSED_FEATURE_NAMES
    assert len(vector) == 49
    assert tuple(vector)[:18] == ETW_TRANSFORMATION_FEATURES
    assert tuple(vector)[18:] == BTF_FEATURE_NAMES
    assert vector["unique_files_read"] == 1
    assert vector["unique_files_written"] == 1
    assert vector["file_activity.read"] == 1
    assert vector["file_activity.write"] == 1


def test_fusion_rejects_incomplete_etw_schema():
    with pytest.raises(ValueError, match="schema mismatch"):
        build_fused_feature_vector({}, BTFVector())


def test_fusion_rejects_non_integer_etw_values():
    from features.transformation.window_features import extract_etw_transformation_features

    etw = extract_etw_transformation_features([])
    etw["unique_files_observed"] = 1.5
    with pytest.raises(ValueError, match="non-negative integer"):
        build_fused_feature_vector(etw, BTFVector())
