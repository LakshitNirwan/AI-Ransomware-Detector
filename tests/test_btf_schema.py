import pytest
from features.btf.schema import BTFVector, BTFProcess, BTFWindow, BTFRecord

def test_vector_is_flat_and_zero_fills():
    flat=BTFVector(file_activity={"read":2}).to_flat_dict()
    assert flat["file_activity.read"]==2
    assert flat["file_activity.write"]==0
    assert "execution_activity.persistence" in flat

def test_invalid_event_rejected():
    with pytest.raises(ValueError): BTFVector(file_activity={"encrypt":1})

def test_record_validation():
    r=BTFRecord(BTFProcess(123,"python.exe"),BTFWindow("start","end"),BTFVector())
    assert r.validate()
