from collections import defaultdict
from pathlib import PureWindowsPath
from typing import Iterable

from features.transformation.schema import FileEvent, FileOperation


ETW_TRANSFORMATION_FEATURES = (
    "unique_files_observed",
    "unique_files_read",
    "unique_files_written",
    "unique_files_renamed",
    "unique_files_deleted",
    "files_read_then_written",
    "files_written_then_renamed",
    "files_written_then_deleted",
    "files_with_extension_change",
    "distinct_source_extensions",
    "distinct_destination_extensions",
    "files_with_repeated_writes",
    "write_events_after_first_per_file",
    "max_writes_per_file",
    "files_with_multiple_operation_types",
    "files_with_three_operation_types",
    "files_read_written_renamed",
    "files_read_written_deleted",
)

_TRACKED_OPERATIONS = {
    FileOperation.READ,
    FileOperation.WRITE,
    FileOperation.RENAME,
    FileOperation.DELETE,
}


def _normalize(path: str) -> str:
    return path.replace("/", "\\").casefold()


def _has_ordered_sequence(operations: list[FileOperation], *sequence: FileOperation) -> bool:
    position = 0
    for operation in operations:
        if operation == sequence[position]:
            position += 1
            if position == len(sequence):
                return True
    return False


def extract_etw_transformation_features(events: Iterable[FileEvent]) -> dict[str, int]:
    """Aggregate one PID's chronologically ordered file events for one window.

    Rename destinations become aliases for the source path for the remainder of
    this input window. Since FileEvent does not carry a stable file ID, identity
    is a normalized path proxy and can conflate path reuse within a window.
    """
    aliases: dict[str, str] = {}
    per_file: dict[str, list[FileOperation]] = defaultdict(list)
    source_extensions: set[str] = set()
    destination_extensions: set[str] = set()
    extension_changed_files: set[str] = set()
    process_id: int | None = None

    for event in events:
        event.validate()
        if process_id is None:
            process_id = event.pid
        elif event.pid != process_id:
            raise ValueError("All events in a window must belong to one PID")

        path_key = _normalize(event.path)
        identity = aliases.get(path_key, path_key)
        per_file[identity]  # initialize identity, including open/create events
        source_suffix = PureWindowsPath(event.path).suffix.casefold()
        if source_suffix:
            source_extensions.add(source_suffix)

        if event.operation not in _TRACKED_OPERATIONS:
            continue
        per_file[identity].append(event.operation)

        if event.operation == FileOperation.RENAME:
            destination = event.related_path
            destination_key = _normalize(destination)
            destination_suffix = PureWindowsPath(destination).suffix.casefold()
            if destination_suffix:
                destination_extensions.add(destination_suffix)
            if source_suffix != destination_suffix:
                extension_changed_files.add(identity)
            aliases[destination_key] = identity

    by_operation = {
        operation: [ops for ops in per_file.values() if operation in ops]
        for operation in _TRACKED_OPERATIONS
    }
    reads = by_operation[FileOperation.READ]
    writes = by_operation[FileOperation.WRITE]
    renames = by_operation[FileOperation.RENAME]
    deletes = by_operation[FileOperation.DELETE]

    result = {name: 0 for name in ETW_TRANSFORMATION_FEATURES}
    result.update(
        unique_files_observed=len(per_file),
        unique_files_read=len(reads),
        unique_files_written=len(writes),
        unique_files_renamed=len(renames),
        unique_files_deleted=len(deletes),
        files_read_then_written=sum(
            _has_ordered_sequence(ops, FileOperation.READ, FileOperation.WRITE)
            for ops in per_file.values()
        ),
        files_written_then_renamed=sum(
            _has_ordered_sequence(ops, FileOperation.WRITE, FileOperation.RENAME)
            for ops in per_file.values()
        ),
        files_written_then_deleted=sum(
            _has_ordered_sequence(ops, FileOperation.WRITE, FileOperation.DELETE)
            for ops in per_file.values()
        ),
        files_with_extension_change=len(extension_changed_files),
        distinct_source_extensions=len(source_extensions),
        distinct_destination_extensions=len(destination_extensions),
        files_with_repeated_writes=sum(
            ops.count(FileOperation.WRITE) >= 2 for ops in per_file.values()
        ),
        write_events_after_first_per_file=sum(
            max(ops.count(FileOperation.WRITE) - 1, 0) for ops in per_file.values()
        ),
        max_writes_per_file=max(
            (ops.count(FileOperation.WRITE) for ops in per_file.values()), default=0
        ),
        files_with_multiple_operation_types=sum(
            len(set(ops)) >= 2 for ops in per_file.values()
        ),
        files_with_three_operation_types=sum(
            len(set(ops)) >= 3 for ops in per_file.values()
        ),
        files_read_written_renamed=sum(
            _has_ordered_sequence(
                ops, FileOperation.READ, FileOperation.WRITE, FileOperation.RENAME
            )
            for ops in per_file.values()
        ),
        files_read_written_deleted=sum(
            _has_ordered_sequence(
                ops, FileOperation.READ, FileOperation.WRITE, FileOperation.DELETE
            )
            for ops in per_file.values()
        ),
    )
    return result
