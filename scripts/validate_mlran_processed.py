
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "dataset" / "processed"
SCHEMA_PATH = ROOT / "dataset" / "schemas" / "mlran_feature_schema.json"

TRAIN_PATH = DATA_DIR / "mlran_train.csv"
TEST_PATH = DATA_DIR / "mlran_test.csv"

FORBIDDEN_FEATURES = {
    "sample_id",
    "family_label",
    "type_label",
}

EXPECTED_TARGET = "sample_type"
EXPECTED_FEATURE_COUNT = 483


def load_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    if not path.is_file():
        raise FileNotFoundError(f"Missing processed dataset: {path}")

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError(f"Missing CSV header: {path}")

        headers = list(reader.fieldnames)
        if len(headers) != len(set(headers)):
            raise ValueError(f"Duplicate columns found in {path.name}")

        rows = list(reader)

    if not rows:
        raise ValueError(f"Dataset is empty: {path.name}")

    return headers, rows


def validate_split(
    name: str,
    path: Path,
    expected_features: list[str],
) -> tuple[set[str], dict[str, int]]:
    headers, rows = load_csv(path)

    if headers != expected_features + [EXPECTED_TARGET]:
        raise ValueError(
            f"{name}: header/order mismatch. "
            f"Expected {EXPECTED_FEATURE_COUNT} features plus target."
        )

    leaked = FORBIDDEN_FEATURES.intersection(headers)
    if leaked:
        raise ValueError(f"{name}: metadata leakage detected: {sorted(leaked)}")

    if len(headers) != EXPECTED_FEATURE_COUNT + 1:
        raise ValueError(f"{name}: expected 484 columns; got {len(headers)}")

    sample_ids: set[str] = set()
    target_counts: Counter[str] = Counter()

    for row_number, row in enumerate(rows, start=2):
        target = row[EXPECTED_TARGET].strip()
        if target not in {"0", "1"}:
            raise ValueError(
                f"{name}: invalid target {target!r} at row {row_number}"
            )
        target_counts[target] += 1

        for feature in expected_features:
            value = row[feature].strip()
            if value not in {"0", "1"}:
                raise ValueError(
                    f"{name}: invalid value {value!r} in {feature!r}, "
                    f"row {row_number}"
                )

    print(f"\n{name}")
    print(f"Rows: {len(rows)}")
    print(f"Columns: {len(headers)}")
    print(f"Behavioral features: {len(expected_features)}")
    print(f"Target distribution: {dict(sorted(target_counts.items()))}")
    print("Feature values: binary")
    print("Metadata leakage: none")

    return sample_ids, dict(target_counts)


def main() -> int:
    if not SCHEMA_PATH.is_file():
        raise FileNotFoundError(f"Missing schema: {SCHEMA_PATH}")

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    features = schema.get("feature_columns")
    if not isinstance(features, list):
        raise ValueError("Schema feature_columns must be a list.")

    if len(features) != EXPECTED_FEATURE_COUNT:
        raise ValueError(
            f"Expected {EXPECTED_FEATURE_COUNT} features in schema; "
            f"found {len(features)}"
        )

    if len(features) != len(set(features)):
        raise ValueError("Duplicate feature names in schema.")

    if schema.get("target_column") != EXPECTED_TARGET:
        raise ValueError("Unexpected target column in schema.")

    if set(features) & FORBIDDEN_FEATURES:
        raise ValueError("Schema contains forbidden metadata features.")

    print("INDEPENDENT MLRAN PROCESSED-DATA VALIDATION")
    print(f"Project root: {ROOT}")

    _, train_counts = validate_split("TRAIN", TRAIN_PATH, features)
    _, test_counts = validate_split("TEST", TEST_PATH, features)

    if train_counts != {"0": 2040, "1": 1865}:
        raise ValueError(f"Unexpected train target distribution: {train_counts}")

    if test_counts != {"0": 510, "1": 465}:
        raise ValueError(f"Unexpected test target distribution: {test_counts}")

    if schema.get("train_rows") != 3905:
        raise ValueError("Schema train_rows does not match expected row count.")

    if schema.get("test_rows") != 975:
        raise ValueError("Schema test_rows does not match expected row count.")

    print("\nVALIDATION RESULTS")
    print("Train row count: valid")
    print("Test row count: valid")
    print("Feature schema: valid")
    print("Target distributions: valid")
    print("Metadata leakage: none")
    print("Processed dataset contract: valid")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"VALIDATION ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
