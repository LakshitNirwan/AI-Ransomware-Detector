from features.transformation.kernel_file_processor import KernelFileEventProcessor


def test_processor_can_be_created_without_starting_etw():
    processor = KernelFileEventProcessor()
    assert processor.correlator is not None
    assert processor.metadata is not None


def test_captured_etw_payload_shape_is_dictionary_based():
    payload = {
        "EventHeader": {
            "ProcessId": 16120,
            "TimeStamp": 134370558406556954,
        },
        "Task Name": "CREATE",
        "FileObject": 12345,
        "FileName": r"\Device\HarddiskVolume3\Windows\SYSTEM32\kernel.appcore.dll",
    }

    assert payload["EventHeader"]["ProcessId"] == 16120
    assert payload["Task Name"] == "CREATE"
    assert payload["FileName"].startswith(r"\Device\HarddiskVolume3")
