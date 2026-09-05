from pathlib import Path
import json
import pandas as pd


# --------------------------------------------------
# Paths
# --------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent

MLRAN_DIR = (
    ROOT
    / "dataset"
    / "raw"
    / "mlran_repo"
    / "6_experiments"
    / "FS_MLRan_Datasets"
)

OUTPUT_DIR = ROOT / "dataset" / "processed"
SCHEMA_DIR = ROOT / "dataset" / "schemas"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
SCHEMA_DIR.mkdir(parents=True, exist_ok=True)


TRAIN_FILE = MLRAN_DIR / "MLRan_X_train_RFE.csv"
TEST_FILE = MLRAN_DIR / "MLRan_X_test_RFE.csv"
FEATURE_MAP_FILE = MLRAN_DIR / "RFE_selected_feature_names_dic.json"


# --------------------------------------------------
# Load data
# --------------------------------------------------

print("Loading MLRan datasets...")

train = pd.read_csv(TRAIN_FILE)
test = pd.read_csv(TEST_FILE)

with open(FEATURE_MAP_FILE, "r", encoding="utf-8") as f:
    feature_map = json.load(f)

print(f"Train shape: {train.shape}")
print(f"Test shape:  {test.shape}")


# --------------------------------------------------
# Validate structure
# --------------------------------------------------

metadata_columns = [
    "sample_id",
    "sample_type",
    "family_label",
    "type_label",
]

feature_columns = [
    column
    for column in train.columns
    if column not in metadata_columns
]

print(f"Behavioral features: {len(feature_columns)}")


# --------------------------------------------------
# Validate train/test feature consistency
# --------------------------------------------------

assert feature_columns == [
    column
    for column in test.columns
    if column not in metadata_columns
], "Train/test feature mismatch."


# --------------------------------------------------
# Create binary target
#
# 0 = goodware
# 1 = ransomware
# --------------------------------------------------

train_target = train["sample_type"].astype(int)
test_target = test["sample_type"].astype(int)


# --------------------------------------------------
# Validate labels
# --------------------------------------------------

valid_labels = {0, 1}

assert set(train_target.unique()).issubset(valid_labels)
assert set(test_target.unique()).issubset(valid_labels)

# --------------------------------------------------
# Keep only ML features + target
# --------------------------------------------------

train_processed = train[["sample_id"] + feature_columns].copy()
train_processed["target"] = train_target.values

test_processed = test[["sample_id"] + feature_columns].copy()
test_processed["target"] = test_target.values
# --------------------------------------------------
# Convert behavioral features to numeric
# --------------------------------------------------

train_processed[feature_columns] = (
    train_processed[feature_columns]
    .apply(pd.to_numeric, errors="coerce")
    .fillna(0)
)

test_processed[feature_columns] = (
    test_processed[feature_columns]
    .apply(pd.to_numeric, errors="coerce")
    .fillna(0)
)


# --------------------------------------------------
# Save processed datasets
# --------------------------------------------------

train_output = OUTPUT_DIR / "mlran_train.csv"
test_output = OUTPUT_DIR / "mlran_test.csv"

train_processed.to_csv(train_output, index=False)
test_processed.to_csv(test_output, index=False)


# --------------------------------------------------
# Create feature schema
# --------------------------------------------------

schema = {
    "dataset": "MLRan",
    "task": "binary ransomware detection",
    "target": {
        "name": "target",
        "0": "goodware",
        "1": "ransomware",
    },
    "metadata_columns_removed": metadata_columns,
    "feature_count": len(feature_columns),
    "features": [
        {
            "id": feature,
            "name": feature_map.get(str(feature), "UNKNOWN")
        }
        for feature in feature_columns
    ],
}


schema_output = SCHEMA_DIR / "mlran_feature_schema.json"

with open(schema_output, "w", encoding="utf-8") as f:
    json.dump(schema, f, indent=2)


# --------------------------------------------------
# Summary
# --------------------------------------------------

print("\nMLRan preprocessing complete.")

print("\nTraining distribution:")
print(train_processed["target"].value_counts().sort_index())

print("\nTesting distribution:")
print(test_processed["target"].value_counts().sort_index())

print(f"\nSaved:")
print(train_output)
print(test_output)
print(schema_output)