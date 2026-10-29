import pytest
from features.transformation.schema import FileEvent, FileOperation
from features.transformation.analyzer import TransformationAnalyzer

def test_write_event_produces_evidence():
    e=TransformationAnalyzer(123).apply(FileEvent(123,"t1",FileOperation.WRITE,r"C:\test\a.txt",size=10))
    assert e.pid==123 and e.final_path.lower().endswith("a.txt")

def test_wrong_pid_rejected():
    with pytest.raises(ValueError):
        TransformationAnalyzer(123).apply(FileEvent(456,"t1",FileOperation.READ,r"C:\test\a.txt"))

def test_rename_requires_destination():
    with pytest.raises(ValueError):
        FileEvent(123,"t1",FileOperation.RENAME,r"C:\test\a.txt").validate()
