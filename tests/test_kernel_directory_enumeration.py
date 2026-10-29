from types import SimpleNamespace

from features.btf.file_event_adapter import FileEventBTFAdapter
from features.transformation.kernel_file_processor import KernelFileEventProcessor
from features.transformation.schema import FileOperation


def test_kernel_directory_enumeration_maps_to_btf_enumerate():
    processor = KernelFileEventProcessor()
    processor.correlator.register_name(
        "directory-key", r"C:\Temp", 321, "t0"
    )
    event = processor.process(
        SimpleNamespace(id=20, process_id=321, timestamp="t1"),
        SimpleNamespace(FileKey="directory-key", FileName=None, FilePath=None),
    )

    assert event.operation is FileOperation.ENUMERATE
    assert event.path == r"C:\Temp"
    adapter = FileEventBTFAdapter(321)
    adapter.add(event)
    assert adapter.to_vector().file_activity == {"enumerate": 1}


def test_unresolved_directory_enumeration_is_not_fabricated():
    processor = KernelFileEventProcessor()
    event = processor.process(
        SimpleNamespace(id=20, process_id=321, timestamp="t1"),
        SimpleNamespace(FileKey="missing-key", FileName=None, FilePath=None),
    )

    assert event is None


def test_directory_enumeration_can_resolve_by_matching_file_object():
    processor = KernelFileEventProcessor()
    processor.process(
        SimpleNamespace(id=12, process_id=321, timestamp="t0"),
        SimpleNamespace(FileName=r"C:\Temp", FileObject="object-1"),
    )
    event = processor.process(
        SimpleNamespace(id=20, process_id=321, timestamp="t1"),
        SimpleNamespace(FileKey="different-key", FileObject="object-1",
                        FileName=None, FilePath=None),
    )

    assert event.operation is FileOperation.ENUMERATE
    assert event.path == r"C:\Temp"
