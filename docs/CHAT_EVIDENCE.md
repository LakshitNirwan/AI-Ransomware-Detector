# Chat evidence ledger

- Project path: `C:\PERSONAL\Projects\AI-Ransomware-Detector`
- Test directory: `C:\Users\suret\AI-Ransomware-Test`
- Kernel-File provider GUID: `{EDD08927-9CC4-4E65-B970-C2560FB5C289}`
- Kernel-Process provider GUID: `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`
- Kernel-File IDs under investigation: 10, 11, 12, 15, 16, 17, 18, 19, 20, 22, 26, 27, 28, 29, 30.
- Event 10 NameCreate provides identity/name information; it is not definitive proof a new file was created.
- Event 22 QueryInformation output included Irp, FileObject, FileKey, ExtraInformation, IssuingThreadId, InfoClass.
- Event 16 Write output included ByteOffset, Irp, FileObject, FileKey, IssuingThreadId, IOSize, IOFlags, ExtraFlags.
- The same FileKey was observed across `shape_test.txt` and `shape_test.locked`.
- `IOSize` is operation I/O size, not necessarily total file size.
- Event 27 RenamePath was used to correlate old path with new path; Event 26 DeletePath was used as deletion evidence.
- BTF dimensions: file_activity (open/read/write/create/delete/rename/enumerate), process_activity (create/enumerate/open/memory_write/thread_context), registry_activity (open/read/query/write/create/delete/enumerate), network_activity (connect/dns/http/icmp/socket), resource_activity (memory_allocate/memory_protect/handle_activity), execution_activity (process_start/injection/persistence/exception_handler).
- The mapping CSV columns shown were `feature_id,feature_name,mlran_category,runtime_category,runtime_status,reason`.
- A script reported 338 XGBoost importance rows, 338 mapped rows, 0 unmapped rows. Full output was not visible.
