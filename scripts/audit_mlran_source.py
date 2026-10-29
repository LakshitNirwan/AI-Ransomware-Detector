
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (
    ROOT
    / "dataset"
    / "raw"
    / "mlran_repo"
    / "6_experiments"
    / "FS_MLRan_Datasets"
)

TRAIN_FILE = SOURCE / "MLRan_X_train_RFE.csv"
TEST_FILE = SOURCE / "MLRan_X_test_RFE.csv"
LABEL_FILE = SOURCE / "MLRan_labels.csv"
MAPPING_FILE = SOURCE / "RFE_selected_feature_names_dic.json"

METADATA_COLUMNS = {
    "sample_id",
    "sample_type",
    "family_label",
    "type_label",
}


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    if not path.is_file():
        raise FileNotFoundError(f"Required source file missing: {path}")

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError(f"CSV has no header: {path}")

        headers = list(reader.fieldnames)
        if len(headers) != len(set(headers)):
            raise ValueError(f"Duplicate column names found: {path}")

        rows = list(reader)

    return headers, rows


def label_distribution(rows: list[dict[str, str]], column: str) -> dict[str, int]:
    return dict(sorted(Counter(row[column] for row in rows).items()))


def audit_split(
    name: str,
    path: Path,
    labels: dict[str, dict[str, str]],
    mapping_keys: set[str],
) -> tuple[dict, set[str]]:
    headers, rows = read_csv(path)

    print(f"\n--- {name} ---")
    print(f"Rows: {len(rows)}")
    print(f"Columns: {len(headers)}")
    print(f"First columns: {headers[:8]}")

    missing_metadata = sorted(METADATA_COLUMNS - set(headers))
    if missing_metadata:
        raise ValueError(f"{name}: expected metadata columns missing: {missing_metadata}")

    feature_columns = [
        column for column in headers if column not in METADATA_COLUMNS
    ]

    duplicate_ids = []
    seen_ids = set()
    ids = set()
    invalid_rows = []
    label_mismatches = []
    missing_label_ids = []
    invalid_feature_values = Counter()

    for row_number, row in enumerate(rows, start=2):
        sample_id = row["sample_id"].strip()

        if not sample_id:
            invalid_rows.append(row_number)
            continue

        if sample_id in seen_ids:
            duplicate_ids.append(sample_id)

        seen_ids.add(sample_id)
        ids.add(sample_id)

        label_row = labels.get(sample_id)
        if label_row is None:
            missing_label_ids.append(sample_id)
        else:
            for column in ("sample_type", "family_label", "type_label"):
                if row[column].strip() != label_row[column].strip():
                    label_mismatches.append(
                        {
                            "sample_id": sample_id,
                            "column": column,
                            "source_value": row[column],
                            "label_value": label_row[column],
                        }
                    )

        for column in feature_columns:
            value = row[column].strip()
            if value not in {"0", "1"}:
                invalid_feature_values[column] += 1

    mapping_missing = sorted(set(feature_columns) - mapping_keys)
    mapping_extra = sorted(mapping_keys - set(feature_columns))

    result = {
        "file": str(path.relative_to(ROOT)),
        "rows": len(rows),
        "total_columns": len(headers),
        "metadata_columns": [c for c in headers if c in METADATA_COLUMNS],
        "feature_count": len(feature_columns),
        "sample_type_distribution": label_distribution(rows, "sample_type"),
        "family_label_distribution": label_distribution(rows, "family_label"),
        "type_label_distribution": label_distribution(rows, "type_label"),
        "unique_sample_ids": len(ids),
        "duplicate_sample_ids": len(duplicate_ids),
        "empty_sample_id_rows": len(invalid_rows),
        "missing_ids_in_label_file": len(missing_label_ids),
        "metadata_label_mismatches": len(label_mismatches),
        "feature_columns_missing_from_mapping": len(mapping_missing),
        "mapping_keys_not_in_features": len(mapping_extra),
        "columns_with_nonbinary_or_blank_values": len(invalid_feature_values),
        "nonbinary_or_blank_feature_cells": sum(invalid_feature_values.values()),
    }

    print(f"Metadata columns: {result['metadata_columns']}")
    print(f"Behavioral feature columns: {len(feature_columns)}")
    print(f"Sample type distribution: {result['sample_type_distribution']}")
    print(f"Unique sample IDs: {len(ids)}")
    print(f"Duplicate sample IDs: {len(duplicate_ids)}")
    print(f"Missing label IDs: {len(missing_label_ids)}")
    print(f"Label mismatches: {len(label_mismatches)}")
    print(f"Features absent from mapping: {len(mapping_missing)}")
    print(f"Mapping keys absent from features: {len(mapping_extra)}")
    print(f"Features with invalid values: {len(invalid_feature_values)}")

    if duplicate_ids:
        print(f"Duplicate ID examples: {duplicate_ids[:5]}")
    if missing_label_ids:
        print(f"Missing label ID examples: {missing_label_ids[:5]}")
    if label_mismatches:
        print(f"Label mismatch examples: {label_mismatches[:5]}")
    if mapping_missing:
        print(f"Unmapped feature examples: {mapping_missing[:10]}")
    if mapping_extra:
        print(f"Unused mapping examples: {mapping_extra[:10]}")
    if invalid_feature_values:
        print(
            "Invalid feature examples: "
            f"{dict(list(invalid_feature_values.items())[:10])}"
        )

    return result, ids


def main() -> int:
    print("MLRAN SOURCE DATA AUDIT")
    print(f"Project root: {ROOT}")
    print(f"Source directory exists: {SOURCE.is_dir()}")

    if not SOURCE.is_dir():
        print("ERROR: MLRan source directory not found.")
        return 1

    with LABEL_FILE.open("r", encoding="utf-8-sig", newline="") as handle:
        label_reader = csv.DictReader(handle)
        required = {"sample_id", "sample_type", "family_label", "type_label"}

        if not label_reader.fieldnames or not required.issubset(label_reader.fieldnames):
            raise ValueError(
                f"Unexpected label CSV schema: {label_reader.fieldnames}"
            )

        label_rows = list(label_reader)

    labels: dict[str, dict[str, str]] = {}
    duplicate_label_ids = set()

    for row in label_rows:
        sample_id = row["sample_id"].strip()
        if sample_id in labels:
            duplicate_label_ids.add(sample_id)
        labels[sample_id] = row

    with MAPPING_FILE.open("r", encoding="utf-8-sig") as handle:
        mapping = json.load(handle)

    if not isinstance(mapping, dict):
        raise ValueError("Feature mapping JSON must contain an object.")

    mapping_keys = set(mapping)

    print(f"Label rows: {len(label_rows)}")
    print(f"Unique label IDs: {len(labels)}")
    print(f"Duplicate label IDs: {len(duplicate_label_ids)}")
    print(f"Feature mapping entries: {len(mapping_keys)}")

    train_result, train_ids = audit_split(
        "TRAIN SOURCE", TRAIN_FILE, labels, mapping_keys
    )
    test_result, test_ids = audit_split(
        "TEST SOURCE", TEST_FILE, labels, mapping_keys
    )

    overlap = train_ids & test_ids

    print("\n--- SPLIT INTEGRITY ---")
    print(f"Train/test sample ID overlap: {len(overlap)}")
    if overlap:
        print(f"Overlap examples: {sorted(overlap)[:10]}")

    print("\n--- EXISTING PROCESSED FILES ---")
    for filename in (
        "mlran_train.csv",
        "mlran_test.csv",
    ):
        path = ROOT / "dataset" / "processed" / filename
        if not path.is_file():
            print(f"MISSING: {path.relative_to(ROOT)}")
            continue

        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle)
            header = next(reader, [])
            print(
                f"{path.relative_to(ROOT)}: "
                f"{len(header)} columns; first columns={header[:8]}"
            )

    print("\n--- AUDIT SUMMARY ---")
    print(
        json.dumps(
            {
                "label_rows": len(label_rows),
                "duplicate_label_ids": len(duplicate_label_ids),
                "train": train_result,
                "test": test_result,
                "train_test_id_overlap": len(overlap),
            },
            indent=2,
        )
    )

    print("\nAudit finished. No source or processed data files were modified.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"AUDIT ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
