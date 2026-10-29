
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SOURCE_DIR = (
    ROOT
    / "dataset"
    / "raw"
    / "mlran_repo"
    / "6_experiments"
    / "FS_MLRan_Datasets"
)

FEATURE_DICT = SOURCE_DIR / "RFE_selected_feature_names_dic.json"
SCHEMA_PATH = ROOT / "dataset" / "schemas" / "mlran_feature_schema.json"
PARTIAL_MAPPING = (
    ROOT / "dataset" / "reports" / "mlran_feature_mapping_final.csv"
)
OUTPUT = ROOT / "dataset" / "reports" / "mlran_runtime_mapping_audit.csv"


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    source_names = json.loads(FEATURE_DICT.read_text(encoding="utf-8"))

    feature_ids = [str(item) for item in schema["feature_columns"]]
    schema_names = {
        str(key): str(value)
        for key, value in schema["feature_names"].items()
    }
    source_names = {
        str(key): str(value)
        for key, value in source_names.items()
    }

    with PARTIAL_MAPPING.open(
        "r", encoding="utf-8-sig", newline=""
    ) as handle:
        partial_rows = list(csv.DictReader(handle))

    partial_by_id = {}
    for row in partial_rows:
        feature_id = row["feature_id"].strip()
        if feature_id in partial_by_id:
            raise ValueError(f"Duplicate ID in partial mapping: {feature_id}")
        partial_by_id[feature_id] = row

    if len(feature_ids) != 483 or len(set(feature_ids)) != 483:
        raise ValueError("Expected 483 unique feature IDs in schema.")

    if set(feature_ids) != set(schema_names):
        raise ValueError("Schema feature IDs and feature-name keys differ.")

    if not set(partial_by_id).issubset(set(feature_ids)):
        raise ValueError("Partial mapping contains IDs absent from schema.")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    counts = Counter()
    with OUTPUT.open("w", encoding="utf-8", newline="") as handle:
        fields = [
            "feature_id",
            "feature_name",
            "source_dictionary_name",
            "runtime_category",
            "runtime_status",
            "existing_reason",
            "classification_source",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()

        for feature_id in feature_ids:
            existing = partial_by_id.get(feature_id)
            status = (
                existing["runtime_status"].strip()
                if existing
                else "UNREVIEWED"
            )
            counts[status] += 1

            writer.writerow(
                {
                    "feature_id": feature_id,
                    "feature_name": schema_names[feature_id],
                    "source_dictionary_name": source_names.get(
                        feature_id, ""
                    ),
                    "runtime_category": (
                        existing.get("runtime_category", "").strip()
                        if existing
                        else ""
                    ),
                    "runtime_status": status,
                    "existing_reason": (
                        existing.get("reason", "").strip()
                        if existing
                        else ""
                    ),
                    "classification_source": (
                        "existing_partial_mapping"
                        if existing
                        else "not_recovered"
                    ),
                }
            )

    print("RUNTIME MAPPING AUDIT")
    print(f"Schema features: {len(feature_ids)}")
    print(f"Source dictionary entries: {len(source_names)}")
    print(f"Existing partial mapping rows: {len(partial_rows)}")
    print(f"Audit rows written: {sum(counts.values())}")
    print(f"Status counts: {dict(counts)}")
    print(f"Output: {OUTPUT}")

    if len(source_names) != 483:
        print(
            "WARNING: source dictionary does not contain exactly "
            "483 entries."
        )

    if counts["UNREVIEWED"] != 451:
        print(
            "WARNING: the number of unreviewed features differs "
            "from the expected 451."
        )

    print("Audit artifact created; runtime classification remains incomplete.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"AUDIT ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
