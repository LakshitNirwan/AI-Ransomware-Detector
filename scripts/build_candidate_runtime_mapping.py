
from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUT_PATH = ROOT / "dataset" / "reports" / "mlran_feature_evidence_review.csv"
OUTPUT_PATH = ROOT / "dataset" / "reports" / "mlran_candidate_runtime_mapping.csv"


def classify_api(api_name: str) -> tuple[str, str, str]:
    api = api_name.lower()

    # Thread and process enumeration
    rules = [
        (("ntgetcontextthread",), "thread_context_read",
         "Reads thread context; the API name alone does not establish malicious intent."),
        (("ntsetcontextthread",), "thread_context_modify",
         "Modifies thread context; validate the event source and surrounding behavior."),
        (("process32first", "process32next", "createtoolhelp32snapshot"),
         "process_snapshot_enumeration",
         "Enumerates process snapshot entries; enumeration alone does not imply malicious activity."),
        (("openscmanager",), "service_manager_access",
         "Opens the Service Control Manager; access alone does not prove service creation or modification."),
        (("createservice", "changeserviceconfig", "deleteservice"),
         "service_management_activity",
         "Service-management API; validate the operation and its result."),
        (("openservice",), "service_open_activity",
         "Opens a service handle; this alone does not prove service modification."),
        (("writeprocessmemory", "ntwritevirtualmemory"),
         "cross_process_memory_write",
         "Writes memory in another process; correlate with process identity and subsequent behavior."),
        (("virtualallocex", "ntallocatevirtualmemory"),
         "remote_process_allocation",
         "Allocates memory in a process context; allocation alone does not prove injection."),
        (("virtualalloc",), "virtual_memory_allocation",
         "Allocates virtual memory; interpret with protection changes and execution behavior."),
        (("virtualprotect", "ntprotectvirtualmemory"),
         "memory_protection_activity",
         "Changes memory protection; interpret alongside allocation and execution evidence."),
        (("createremotethread", "ntcreatethreadex"),
         "process_injection_execution",
         "Creates a thread in a process context; correlate with target process and memory behavior."),
        (("setwindowshook", "unhookwindowshook"),
         "hook_activity", "Installs or removes a hook; not inherently malicious."),
        (("addvectoredexceptionhandler", "setunhandledexceptionfilter"),
         "exception_handler_registration", "Changes exception handling; validate context."),
        (("openscmanager",), "service_manager_access",
         "Opens the Service Control Manager; access alone does not prove service modification."),
        (("createactctx",), "application_activation_context",
         "Creates an application activation context; commonly used by legitimate applications."),
        (("getnativesysteminfo", "getsysteminfo"),
         "system_information_query",
         "Queries system information; common in benign software too."),
        (("getsystemmetrics",), "system_information_query",
         "Queries system display or system metrics; not inherently malicious."),
        (("couninitialize", "cocreateinstance"),
         "com_runtime_activity",
         "Initializes or uses COM runtime functionality; not inherently malicious."),
        (("shgetfolderpath", "getspecialfolder"),
         "known_folder_path_query",
         "Queries a known folder path; not inherently malicious."),
        (("findresource", "findresourceex", "loadresource", "loadstring"),
         "embedded_resource_access",
         "Looks up or loads application resources; validate resource use and context."),
        (("regenumvalue", "regenumkey"),
         "registry_enumeration",
         "Enumerates registry values or keys; enumeration alone does not prove modification."),
        (("drawtext", "getcursorpos", "findwindow"),
         "user_interface_context_query",
         "Queries or draws user-interface information; not inherently malicious."),
        (("getfileversioninfo",),
         "file_version_metadata_query",
         "Queries file version metadata; not a file-content transformation event."),
        (("gettemppath",),
         "temporary_path_query",
         "Queries the temporary directory path; common in legitimate software."),
        (("getsystemdirectory", "getsystemwindowsdirectory"),
         "system_path_query",
         "Queries a Windows system directory path; not inherently malicious."),
        (("getdiskfreespace",),
         "disk_capacity_query",
         "Queries disk capacity; does not itself indicate destructive file activity."),
        (("writeconsole",),
         "console_output_activity",
         "Writes console output; not inherently malicious."),
        (("ldrloaddll", "loadlibrary", "ldrgetprocedureaddress"),
         "module_or_symbol_resolution",
         "Loads a module or resolves a symbol; common in benign software too."),
        (("createfile", "ntcreatefile"),
         "file_or_handle_open_activity",
         "Creates or opens a file or handle; target may be a file, device, or named pipe."),
        (("readfile", "ntreadfile"),
         "file_read_activity",
         "Reads from a file or handle; target may also be a pipe or other object."),
        (("writefile", "ntwritefile"),
         "file_or_handle_write_activity",
         "Writes to a file or handle; confirm the target is a disk file before treating it as transformation."),
        (("deletefile", "ntdeletefile"),
         "file_deletion_activity",
         "Deletes a file; correlate with path, process, and outcome."),
        (("movefile", "rename"),
         "file_rename_or_move_activity",
         "Moves or renames an object; confirm API semantics and target."),
        (("findfirstfile", "findnextfile"),
         "directory_enumeration",
         "Enumerates filesystem entries; enumeration alone is not destructive."),
        (("regopenkey", "ntopenkey"),
         "registry_open_activity",
         "Opens a registry key; access alone does not prove modification."),
        (("regquery", "ntqueryvaluekey"),
         "registry_read_activity",
         "Queries registry data; interpret with process and event context."),
        (("regsetvalue", "ntsetvaluekey"),
         "registry_write_activity",
         "Writes a registry value; validate target and operation result."),
        (("regcreatekey", "ntcreatekey"),
         "registry_key_creation",
         "Creates or opens a registry key depending on exact API semantics."),
        (("regdelete", "ntdeletekey"),
         "registry_delete_activity",
         "Deletes registry data or a key; validate exact operation and target."),
        (("internetopen", "internetconnect", "http"),
         "http_network_activity",
         "Internet or HTTP-related API; confirm actual network activity from telemetry."),
        (("getaddrinfo", "gethostbyname", "dns"),
         "dns_lookup_activity",
         "Name-resolution API; a call alone does not prove a network connection."),
        (("socket", "connect", "send", "recv"),
         "network_or_socket_activity",
         "Network/socket-related API; validate actual network events and outcomes."),
        (("getcomputername", "globalmemorystatus"),
         "system_information_query",
         "Queries system information; common in benign software too."),
        (("getuser", "getusername"),
         "user_context_query",
         "Queries user context; not inherently malicious."),
        (("ntdelayexecution", "sleep"),
         "execution_timing_activity",
         "Delay or timing API; timing alone does not prove evasion."),
        (("uuidcreate",), "identifier_generation",
         "Generates an identifier; not inherently malicious."),
        (("deviceiocontrol",), "device_control_activity",
         "Controls a device or I/O endpoint; inspect device and operation."),
        (("sendnotifymessage",), "window_message_activity",
         "Sends a window message; surrounding behavior determines relevance."),
    ]

    for tokens, category, reason in rules:
        if any(token in api for token in tokens):
            return category, "Runtime observability uncertain", reason

    return (
        "api_context_unspecified",
        "Runtime observability uncertain",
        "API semantics are not covered by a specific rule; review before runtime use.",
    )


def classify(name: str) -> tuple[str, str, str, str]:
    upper = name.upper()

    if upper.startswith("API:"):
        category, observability, reason = classify_api(name.split(":", 1)[1])
        return category, observability, "API name-based heuristic; verify source semantics", reason

    if upper.startswith("REG:"):
        if any(token in upper for token in ("QUERY", "READ", "ENUMERAT")):
            category = "registry_read_activity"
        elif any(token in upper for token in ("DELETE", "REMOVED")):
            category = "registry_delete_activity"
        elif any(token in upper for token in ("CREATE", "CREATED")):
            category = "registry_key_creation"
        elif any(token in upper for token in ("SET", "WRITE", "MODIF")):
            category = "registry_write_activity"
        elif "OPEN" in upper:
            category = "registry_open_activity"
        else:
            category = "registry_activity_unspecified"

        return (
            category,
            "Runtime observability uncertain",
            "Registry feature-name heuristic; confirm underlying event and target.",
            "Feature name suggests registry behavior but does not establish runtime availability.",
        )

    if upper.startswith("FILE:"):
        parts = upper.split(":", 2)
        operation = parts[1] if len(parts) >= 3 else parts[-1]

        file_rules = {
            "OPENED": ("file_open_activity", "Target may be a disk file, pipe, device, or other handle."),
            "OPEN": ("file_open_activity", "Target may be a disk file, pipe, device, or other handle."),
            "CREATE": ("file_open_activity", "Validate whether the operation created or opened a target."),
            "CREATED": ("file_open_activity", "Validate whether the operation created or opened a target."),
            "EXISTS": ("filesystem_presence_context", "Existence check is context, not proof of file access or modification."),
            "FAILED": ("filesystem_failure_context", "Failed operation; inspect operation type and result before inferring behavior."),
            "READ": ("file_read_activity", "Confirm whether the target is a disk file or another handle."),
            "WRITTEN": ("file_write_activity", "Target may be a pipe or handle rather than a disk file."),
            "WRITE": ("file_write_activity", "Target may be a pipe or handle rather than a disk file."),
            "RECREATED": ("file_recreation_activity", "Validate the dataset's precise event semantics."),
            "DELETED": ("file_deletion_activity", "Validate target path and event semantics."),
            "DELETE": ("file_deletion_activity", "Validate target path and event semantics."),
            "RENAMED": ("file_rename_or_move_activity", "Validate the underlying operation and target."),
            "MOVED": ("file_rename_or_move_activity", "Validate the underlying operation and target."),
        }
        category, reason = file_rules.get(
            operation,
            ("filesystem_activity_unspecified", "Filesystem-related feature name without a specific operation mapping."),
        )
        return category, "Runtime observability uncertain", "File feature-name heuristic; target and event source require validation.", reason

    if upper.startswith("DIRECTORY:"):
        if any(token in upper for token in ("ENUMERATED", "ENUMERATE", "LIST")):
            category, reason = "directory_enumeration", "Directory enumeration is not inherently destructive."
        elif any(token in upper for token in ("CREATED", "CREATE")):
            category, reason = "directory_create_activity", "Validate the event source and outcome."
        elif any(token in upper for token in ("DELETED", "DELETE", "REMOVED")):
            category, reason = "directory_deletion", "Validate the event source and outcome."
        else:
            category, reason = "directory_activity_unspecified", "Directory-related feature name without a specific operation mapping."
        return category, "Runtime observability uncertain", "Directory feature-name heuristic; confirm actual event semantics.", reason

    if upper.startswith("SYSTEM:GUID:"):
        return "system_guid_context", "Static or derived context", "GUID-valued system feature; likely identifier/context evidence, not a direct runtime event.", "Category inferred from feature name; verify what the GUID represents."

    if upper.startswith("SYSTEM:DLL_LOADED:"):
        return "module_load_activity", "Runtime observability uncertain", "DLL-loaded feature describes module context; confirm the telemetry source and whether it records a live load event.", "Module name alone is not a maliciousness verdict; correlate with process, path, and load timing."

    if upper.startswith("SYSTEM:"):
        if "PROCESS" in upper and any(token in upper for token in ("ENUM", "SNAPSHOT", "LIST")):
            category = "process_snapshot_enumeration"
        elif "PROCESS" in upper:
            category = "process_interaction_activity"
        elif "SERVICE" in upper:
            category = "service_management_context"
        elif "MEMORY" in upper or "RESOURCE" in upper:
            category = "resource_information_query"
        else:
            category = "system_activity_unspecified"
        return category, "Runtime observability uncertain", "System feature-name heuristic; validate source semantics and runtime availability.", "Category inferred from feature name and not yet verified against telemetry."

    if upper.startswith("DROP:"):
        return "dropped_artifact_context", "Static or derived context", "Drop-related feature appears to describe an artifact or analysis result rather than a live event.", "Do not treat as a runtime signal without an explicit artifact-collection design."

    if upper.startswith("SIGNATURE:"):
        return "static_or_derived_signature", "Static or derived context", "Signature-like feature appears derived from content or prior analysis.", "Runtime use requires a defined signature-generation or lookup mechanism."

    if upper.startswith("STRING:"):
        return "string_content_context", "Static or derived context", "String feature appears to describe extracted content rather than a direct runtime event.", "Runtime use requires a defined content extraction or string-matching mechanism."

    return "component_or_runtime_context", "Runtime observability uncertain", "No specific prefix rule; review feature source semantics.", "Unclassified feature-name pattern."


def main() -> None:
    if not INPUT_PATH.exists():
        raise FileNotFoundError(f"Input evidence report not found: {INPUT_PATH}")

    with INPUT_PATH.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        input_rows = list(reader)
        input_fields = reader.fieldnames or []

    required = {"feature_id", "feature_name", "runtime_category", "runtime_status"}
    missing = required - set(input_fields)
    if missing:
        raise ValueError(f"Input report missing required columns: {sorted(missing)}")

    output_rows = []
    for row in input_rows:
        existing_status = (row.get("runtime_status") or "").strip().upper()
        existing_category = (row.get("runtime_category") or "").strip()
        name = (row.get("feature_name") or "").strip()

        if existing_status in {"ABSTRACT", "EXCLUDE"}:
            candidate_category = existing_category or "existing_reviewed_category"
            candidate_status = "EXISTING_REVIEWED"
            observability_class = "Existing decision preserved"
            mapping_basis = "Preserved from existing reviewed mapping; not independently revalidated."
            review_reason = "Existing reviewed decision retained. Revisit only if new evidence justifies changing it."
        else:
            candidate_category, observability_class, mapping_basis, review_reason = classify(name)
            candidate_status = "CANDIDATE"
            if candidate_category in {
                "api_context_unspecified",
                "filesystem_activity_unspecified",
                "directory_activity_unspecified",
                "registry_activity_unspecified",
                "system_activity_unspecified",
                "component_or_runtime_context",
            }:
                candidate_status = "NEEDS_REVIEW"

        output_rows.append({
            "feature_id": row.get("feature_id", ""),
            "feature_name": name,
            "mlran_category": row.get("mlran_category", ""),
            "existing_runtime_category": existing_category,
            "existing_runtime_status": existing_status,
            "candidate_runtime_category": candidate_category,
            "candidate_status": candidate_status,
            "observability_class": observability_class,
            "mapping_basis": mapping_basis,
            "review_reason": review_reason,
            "goodware_prevalence": row.get("goodware_prevalence", ""),
            "ransomware_prevalence": row.get("ransomware_prevalence", ""),
            "mutual_information": row.get("mutual_information", ""),
            "random_forest_importance": row.get("random_forest_importance", ""),
            "combined_score": row.get("combined_score", ""),
        })

    output_fields = [
        "feature_id", "feature_name", "mlran_category",
        "existing_runtime_category", "existing_runtime_status",
        "candidate_runtime_category", "candidate_status",
        "observability_class", "mapping_basis", "review_reason",
        "goodware_prevalence", "ransomware_prevalence",
        "mutual_information", "random_forest_importance", "combined_score",
    ]

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=output_fields)
        writer.writeheader()
        writer.writerows(output_rows)

    ids = [row["feature_id"] for row in output_rows]
    status_counts = Counter(row["candidate_status"] for row in output_rows)
    category_counts = Counter(row["candidate_runtime_category"] for row in output_rows)

    print("CANDIDATE RUNTIME MAPPING")
    print(f"Input features: {len(input_rows)}")
    print(f"Output features: {len(output_rows)}")
    print(f"Unique feature IDs: {len(set(ids))}")
    print("Candidate categories:")
    for category, count in category_counts.most_common():
        print(f"  {category}: {count}")
    print("Candidate statuses:")
    for status, count in status_counts.most_common():
        print(f"  {status}: {count}")
    print(f"Output: {OUTPUT_PATH}")

    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate feature IDs detected in output.")
    if len(input_rows) != len(output_rows):
        raise ValueError("Input/output row count mismatch.")
    if set(ids) != {row["feature_id"] for row in input_rows}:
        raise ValueError("Feature IDs were not preserved exactly.")

    print("Validation: all input feature IDs preserved exactly once")
    print("Caution: name-based candidates are not validated runtime features.")


if __name__ == "__main__":
    main()
