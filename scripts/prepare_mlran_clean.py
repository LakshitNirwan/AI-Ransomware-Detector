
from __future__ import annotations

import csv
import json
import sys
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

OUTPUT = ROOT / "dataset" / "processed"
SCHEMA_OUTPUT = ROOT / "dataset" / "schemas" / "mlran_feature_schema.json"

TRAIN_SOURCE = SOURCE / "MLRan_X_train_RFE.csv"
TEST_SOURCE = SOURCE / "MLRan_X_test_RFE.csv"
MAPPING_SOURCE = SOURCE / "RFE_selected_feature_names_dic.json"

METADATA_COLUMNS = {
    "sample_id",
    "sample_type",
    "family_label",
    "type_label",
}
TARGET = "sample_type"


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    if not path.is_file():
        raise FileNotFoundError(f"Missing input file: {path}")

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError(f"Missing CSV header: {path}")

        headers = list(reader.fieldnames)
        if len(headers) != len(set(headers)):
            raise ValueError(f"Duplicate CSV columns: {path}")

        rows = list(reader)

    if not rows:
        raise ValueError(f"No data rows in {path}")

    return headers, rows


def validate_and_convert(
    name: str,
    path: Path,
    expected_features: list[str],
) -> tuple[list[dict[str, int]], list[str]]:
    headers, rows = read_csv(path)

    missing = METADATA_COLUMNS - set(headers)
    if missing:
        raise ValueError(f"{name}: missing required metadata: {sorted(missing)}")

    feature_columns = [c for c in headers if c not in METADATA_COLUMNS]

    if feature_columns != expected_features:
        raise ValueError(
            f"{name}: feature names/order differ from training schema."
        )

    output_rows: list[dict[str, int]] = []
    seen_ids: set[str] = set()

    for row_number, row in enumerate(rows, start=2):
        sample_id = row["sample_id"].strip()

        if not sample_id:
            raise ValueError(f"{name}: empty sample_id at row {row_number}")

        if sample_id in seen_ids:
            raise ValueError(f"{name}: duplicate sample_id {sample_id}")

        seen_ids.add(sample_id)

        target_value = row[TARGET].strip()
        if target_value not in {"0", "1"}:
            raise ValueError(
                f"{name}: invalid target {target_value!r} at row {row_number}"
            )

        converted: dict[str, int] = {}

        for column in expected_features:
            value = row[column].strip()
            if value not in {"0", "1"}:
                raise ValueError(
                    f"{name}: feature {column!r} has invalid value "
                    f"{value!r} at row {row_number}"
                )
            converted[column] = int(value)

        converted[TARGET] = int(target_value)
        output_rows.append(converted)

    print(
        f"{name}: {len(output_rows)} rows, "
        f"{len(expected_features)} features + target; "
        f"{len(seen_ids)} unique sample IDs"
    )

    return output_rows, sorted(seen_ids)


def write_csv(path: Path, rows: list[dict[str, int]], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write a temporary sibling first, then replace the destination.
    temporary = path.with_suffix(path.suffix + ".tmp")

    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

    temporary.replace(path)


def main() -> int:
    print("MLRAN CLEAN PREPROCESSING")
    print(f"Project root: {ROOT}")

    with MAPPING_SOURCE.open("r", encoding="utf-8-sig") as handle:
        mapping = json.load(handle)

    if not isinstance(mapping, dict) or not mapping:
        raise ValueError("Feature mapping must be a non-empty JSON object.")

    train_headers, _ = read_csv(TRAIN_SOURCE)
    test_headers, _ = read_csv(TEST_SOURCE)

    train_features = [
        column for column in train_headers if column not in METADATA_COLUMNS
    ]
    test_features = [
        column for column in test_headers if column not in METADATA_COLUMNS
    ]

    if train_features != test_features:
        raise ValueError("Train/test feature columns or ordering differ.")

    if len(train_features) != 483:
        raise ValueError(f"Expected 483 behavioral features; got {len(train_features)}")

    if set(mapping) != set(train_features):
        raise ValueError(
            "Feature mapping keys do not exactly match the source feature columns."
        )

    train_rows, train_ids = validate_and_convert(
        "TRAIN", TRAIN_SOURCE, train_features
    )
    test_rows, test_ids = validate_and_convert(
        "TEST", TEST_SOURCE, train_features
    )

    overlap = set(train_ids) & set(test_ids)
    if overlap:
        raise ValueError(
            f"Train/test sample ID overlap detected: {sorted(overlap)[:10]}"
        )

    output_columns = train_features + [TARGET]

    train_output = OUTPUT / "mlran_train.csv"
    test_output = OUTPUT / "mlran_test.csv"

    write_csv(train_output, train_rows, output_columns)
    write_csv(test_output, test_rows, output_columns)

    schema = {
        "dataset": "MLRan",
        "source": "MLRan_X_train_RFE.csv and MLRan_X_test_RFE.csv",
        "target_column": TARGET,
        "target_semantics": {
            "0": "goodware",
            "1": "ransomware",
        },
        "metadata_excluded": sorted(METADATA_COLUMNS),
        "feature_count": len(train_features),
        "feature_columns": train_features,
        "feature_names": {
            feature: mapping[feature] for feature in train_features
        },
        "train_rows": len(train_rows),
        "test_rows": len(test_rows),
        "train_test_sample_id_overlap": len(overlap),
    }

    SCHEMA_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    schema_tmp = SCHEMA_OUTPUT.with_suffix(".json.tmp")
    schema_tmp.write_text(
        json.dumps(schema, indent=2),
        encoding="utf-8",
    )
    schema_tmp.replace(SCHEMA_OUTPUT)

    print("\nOUTPUT FILES")
    print(f"Train: {train_output}")
    print(f"Test:  {test_output}")
    print(f"Schema: {SCHEMA_OUTPUT}")
    print(f"Feature count: {len(train_features)}")
    print(f"Train/test ID overlap: {len(overlap)}")
    print("Metadata columns excluded from model input: yes")
    print("Preprocessing validation: valid")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"PREPROCESSING ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
