# Proposed ETW Transformation Feature Contract

Status: PROPOSED — pending runtime validation and paired labeled data.

This contract describes 18 candidate process-window features derived from validated `FileEvent` records. It deliberately excludes raw PIDs, timestamps, full paths, content hashes, and file sizes as model inputs. Events must be ordered by timestamp within one process and one fixed observation window. Rename events connect the old path to the destination path for per-file sequence metrics. The identity is a path proxy because `FileEvent` does not carry a stable file ID; path reuse within a window can conflate files.

## Candidate feature order

1. `unique_files_observed` — distinct normalized path identities touched in the window.
2. `unique_files_read` — distinct file identities with a read event.
3. `unique_files_written` — distinct file identities with a write event.
4. `unique_files_renamed` — distinct file identities with a rename event.
5. `unique_files_deleted` — distinct file identities with a delete event.
6. `files_read_then_written` — distinct identities with a read followed by a write in the window.
7. `files_written_then_renamed` — distinct identities with a write followed by a rename.
8. `files_written_then_deleted` — distinct identities with a write followed by a delete.
9. `files_with_extension_change` — distinct rename identities whose source and destination suffixes differ.
10. `distinct_source_extensions` — count of distinct non-empty source suffixes among observed files.
11. `distinct_destination_extensions` — count of distinct non-empty suffixes among rename destinations.
12. `files_with_repeated_writes` — distinct identities with at least two write events.
13. `write_events_after_first_per_file` — sum of `max(write_count - 1, 0)` across identities.
14. `max_writes_per_file` — greatest write count for any identity, or zero for an empty window.
15. `files_with_multiple_operation_types` — distinct identities with at least two of read, write, rename, and delete.
16. `files_with_three_operation_types` — distinct identities with at least three of read, write, rename, and delete.
17. `files_read_written_renamed` — distinct identities with all three operations in that temporal order.
18. `files_read_written_deleted` — distinct identities with all three operations in that temporal order.

## Relationship to BTF

BTF retains its canonical 31 counters. The five ETW operation-specific counts above are distinct-file counts or sequence summaries, not copies of BTF's raw open/read/write/create/delete/rename event counts. They may still be correlated; that is not by itself a reason to discard them. Exact duplicate columns must be deduplicated before model training, and feature selection must use training data only.

## Evidence limits and release gates

- The current Kernel-File processor emits read, write, rename, and delete `FileEvent`s. Its name-create event is identity/name evidence, not proof that a new file was created; no ETW create feature is included.
- Current file `size` values are metadata observations, not per-operation I/O byte counts. No size-derived feature is included.
- Content hashes are optional and are not currently supplied by the processor. No hash-derived feature is included.
- The current coordinator accumulates per-process state and does not enforce a fixed observation window. Windowing and event ordering must be implemented and verified before this contract is used at runtime.
- Existing MLRan data has ransomware labels but lacks the paired ETW/BTF inputs. The BTF prototype is Normal-vs-Anomaly and is not valid ransomware training data. Do not train or report final 49-feature ransomware metrics until paired, correctly labeled data exists.
- These 18 names and definitions are candidates, not a claim of predictive value. Keep only features that can be computed reliably and whose semantics are validated against collected events.
