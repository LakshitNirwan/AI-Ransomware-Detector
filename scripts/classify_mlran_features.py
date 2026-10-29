
from __future__ import annotations

import csv
from collections import Counter
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUT_PATH = ROOT / "dataset" / "reports" / "mlran_candidate_runtime_mapping.csv"
OUTPUT_PATH = ROOT / "dataset" / "reports" / "mlran_final_feature_classification.csv"
DECISION_LOG = ROOT / "docs" / "decision_log.md"


# These are provisional design decisions for the intended runtime detector.
# They do not prove that the current Windows collector observes each feature.
INCLUDE_CATEGORIES = {
    "thread_context_read",
    "thread_context_modify",
    "process_snapshot_enumeration",
    "process_enumeration",
    "service_manager_access",
    "service_open_activity",
    "service_management_activity",
    "service_management_context",
    "cross_process_memory_write",
    "remote_process_allocation",
    "virtual_memory_allocation",
    "memory_protection_activity",
    "process_injection_execution",
    "process_injection_memory_modification",
    "process_interaction",
    "process_interaction_activity",
    "process_creation_activity",
    "execution_from_user_writable_location",
    "hook_activity",
    "exception_handler_registration",
    "file_open_activity",
    "file_or_handle_open_activity",
    "file_read_activity",
    "file_write_activity",
    "file_or_handle_write_activity",
    "file_recreation_activity",
    "file_deletion_activity",
    "file_rename_or_move_activity",
    "file_state_modification",
    "filesystem_presence_context",
    "filesystem_failure_context",
    "filesystem_activity_unspecified",
    "file_metadata_query",
    "file_metadata_lookup",
    "file_version_metadata_query",
    "directory_enumeration",
    "directory_create_activity",
    "directory_create",
    "directory_deletion",
    "directory_activity_unspecified",
    "registry_read_activity",
    "registry_open_activity",
    "registry_write_activity",
    "registry_key_creation",
    "registry_delete_activity",
    "registry_enumeration",
    "registry_query_activity",
    "autorun_persistence_activity",
    "module_load_activity",
    "module_or_symbol_resolution",
    "system_information_query",
    "system_path_query",
    "known_folder_path_query",
    "temporary_path_query",
    "user_context_query",
    "user_or_known_folder_context",
    "disk_capacity_query",
    "resource_information_query",
    "application_activation_context",
    "com_runtime_activity",
    "embedded_resource_access",
    "user_interface_context_query",
    "window_message_activity",
    "console_output_activity",
    "device_control_activity",
    "execution_timing_activity",
    "identifier_generation",
    "http_network_activity",
    "icmp_network_activity",
    "dns_lookup_activity",
    "network_or_socket_activity",
    "socket_control_activity",
    "network_activity",
    "api_context",
}

EXCLUDE_CATEGORIES = {
    "string_content_context",
    "dropped_artifact_context",
    "static_or_derived_signature",
    "system_guid_context",
}


def classify(row: dict[str, str]) -> tuple[str, str, str]:
    existing_status = (row.get("existing_runtime_status") or "").strip().upper()
    category = (row.get("candidate_runtime_category") or "").strip()
    name = (row.get("feature_name") or "").strip()

    # Preserve explicit decisions already present in the reviewed mapping.
    if existing_status == "EXCLUDE":
        return (
            "EXCLUDE",
            "Preserved the existing reviewed EXCLUDE decision.",
            "Existing reviewed decision",
        )

    if existing_status == "ABSTRACT":
        return (
            "INCLUDE",
            "Preserved the existing reviewed ABSTRACT decision as an included abstract feature. "
            "This does not prove direct runtime observability.",
            "Existing reviewed decision",
        )

    # Exclude content-derived/static features from the live event input set.
    if category in EXCLUDE_CATEGORIES:
        return (
            "EXCLUDE",
            "Static, derived, or artifact-content context is not a direct runtime event "
            "in the current detector design.",
            "Rule-based provisional decision",
        )

    if category in INCLUDE_CATEGORIES:
        reason = (
            "Included as potentially relevant behavioral or contextual evidence. "
            "Validate that the Windows telemetry collector can observe this feature "
            "before using it as a live detector input."
        )

        if category in {
            "file_open_activity",
            "file_or_handle_open_activity",
            "file_read_activity",
            "file_write_activity",
            "file_or_handle_write_activity",
            "filesystem_presence_context",
            "filesystem_failure_context",
        }:
            reason += (
                " The target may be a pipe, device, failed operation, or existence check "
                "rather than a disk-file transformation."
            )

        if category in {"module_load_activity", "module_or_symbol_resolution"}:
            reason += (
                " Module loading and symbol resolution are common in benign software "
                "and are not suspicious on their own."
            )

        return "INCLUDE", reason, "Rule-based provisional decision"

    # Conservative fallback: don't claim an unspecified feature is suitable
    # for runtime use without supporting evidence.
    return (
        "EXCLUDE",
        f"No sufficiently specific runtime mapping was established for category "
        f"'{category}' (feature: {name}). Excluded provisionally pending evidence.",
        "Conservative provisional decision",
    )


def main() -> None:
    if not INPUT_PATH.exists():
        raise FileNotFoundError(
            f"Candidate mapping not found: {INPUT_PATH}\n"
            "Run: py -m scripts.build_candidate_runtime_mapping"
        )

    with INPUT_PATH.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        source_rows = list(reader)

    if not source_rows:
        raise ValueError("Candidate mapping is empty.")

    output_rows = []

    for row in source_rows:
        decision, rationale, confidence = classify(row)

        output_rows.append({
            "feature_id": row.get("feature_id", ""),
            "feature_name": row.get("feature_name", ""),
            "decision": decision,
            "decision_confidence": confidence,
            "decision_rationale": rationale,
            "candidate_runtime_category": row.get(
                "candidate_runtime_category", ""
            ),
            "candidate_status": row.get("candidate_status", ""),
            "existing_runtime_status": row.get(
                "existing_runtime_status", ""
            ),
            "observability_class": row.get("observability_class", ""),
            "goodware_prevalence": row.get("goodware_prevalence", ""),
            "ransomware_prevalence": row.get("ransomware_prevalence", ""),
            "mutual_information": row.get("mutual_information", ""),
            "random_forest_importance": row.get(
                "random_forest_importance", ""
            ),
            "combined_score": row.get("combined_score", ""),
        })

    feature_ids = [row["feature_id"] for row in output_rows]

    if len(feature_ids) != len(set(feature_ids)):
        raise ValueError("Duplicate feature IDs found.")
    if len(output_rows) != len(source_rows):
        raise ValueError("Input/output row count mismatch.")
    if any(row["decision"] not in {"INCLUDE", "EXCLUDE"} for row in output_rows):
        raise ValueError("Every feature must have an INCLUDE or EXCLUDE decision.")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(output_rows[0].keys()),
        )
        writer.writeheader()
        writer.writerows(output_rows)

    decisions = Counter(row["decision"] for row in output_rows)
    confidence_counts = Counter(
        row["decision_confidence"] for row in output_rows
    )

    print("FINAL FEATURE CLASSIFICATION")
    print(f"Features classified: {len(output_rows)}")
    print(f"Unique feature IDs: {len(set(feature_ids))}")
    print(f"INCLUDE: {decisions['INCLUDE']}")
    print(f"EXCLUDE: {decisions['EXCLUDE']}")
    print("Decision basis:")
    for label, count in confidence_counts.items():
        print(f"  {label}: {count}")
    print(f"Output: {OUTPUT_PATH}")
    print("Validation: each feature has exactly one INCLUDE/EXCLUDE decision.")

    if DECISION_LOG.exists():
        note = (
            f"\n\n## DEC-011 — Provisional binary feature classification "
            f"({date.today().isoformat()})\n\n"
            f"- Output: `{OUTPUT_PATH.relative_to(ROOT).as_posix()}`.\n"
            f"- Classified {len(output_rows)} features: "
            f"{decisions['INCLUDE']} INCLUDE and {decisions['EXCLUDE']} EXCLUDE.\n"
            "- Existing reviewed ABSTRACT decisions were preserved as INCLUDE; "
            "existing reviewed EXCLUDE decisions were preserved as EXCLUDE.\n"
            "- Other decisions are provisional, rule-based classifications, not "
            "proof of runtime observability or predictive value.\n"
            "- File/handle operations must be distinguished from disk-file "
            "transformations during runtime validation.\n"
        )
        with DECISION_LOG.open("a", encoding="utf-8") as handle:
            handle.write(note)
        print(f"Decision log updated: {DECISION_LOG}")


if __name__ == "__main__":
    main()
