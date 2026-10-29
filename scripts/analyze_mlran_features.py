from pathlib import Path
import json
import pandas as pd


# --------------------------------------------------
# Paths
# --------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent

DATASET = ROOT / "dataset" / "processed" / "mlran_train.csv"
SCHEMA = ROOT / "dataset" / "schemas" / "mlran_feature_schema.json"


# --------------------------------------------------
# Load data
# --------------------------------------------------

df = pd.read_csv(DATASET)

with open(SCHEMA, "r", encoding="utf-8") as f:
    schema = json.load(f)


# Map feature IDs to actual behavioral names
feature_names = {
    str(item["id"]): item["name"]
    for item in schema["features"]
}


features = [
    column
    for column in df.columns
    if column not in ["sample_id", "target"]
]


print("=" * 80)
print("MLRAN — BEHAVIORAL FEATURE ANALYSIS")
print("=" * 80)

print(f"\nSamples: {len(df)}")
print(f"Behavioral features: {len(features)}")


# --------------------------------------------------
# Feature categories
# --------------------------------------------------

categories = {
    "API": [],
    "FILE": [],
    "DIRECTORY": [],
    "REGISTRY": [],
    "DLL": [],
    "STRING": [],
    "DROP": [],
    "SIGNATURE": [],
    "OTHER": [],
}


for feature_id in features:

    name = str(feature_names.get(str(feature_id), feature_id))
    upper = name.upper()

    if "API:" in upper:
        categories["API"].append(name)

    elif "FILE:" in upper:
        categories["FILE"].append(name)

    elif "DIRECTORY:" in upper:
        categories["DIRECTORY"].append(name)

    elif "REG:" in upper or "REGISTRY" in upper:
        categories["REGISTRY"].append(name)

    elif "DLL:" in upper:
        categories["DLL"].append(name)

    elif "STRING:" in upper:
        categories["STRING"].append(name)

    elif "DROP:" in upper:
        categories["DROP"].append(name)

    elif "SIGNATURE:" in upper:
        categories["SIGNATURE"].append(name)

    else:
        categories["OTHER"].append(name)


# --------------------------------------------------
# Print categories
# --------------------------------------------------

print("\n" + "=" * 80)
print("FEATURE CATEGORIES")
print("=" * 80)

for category, items in categories.items():

    print(f"\n{category}: {len(items)} features")

    for item in items[:15]:
        print(f"  - {item}")

    if len(items) > 15:
        print(f"  ... and {len(items) - 15} more")


# --------------------------------------------------
# Overall feature prevalence
# --------------------------------------------------

print("\n" + "=" * 80)
print("MOST COMMON BEHAVIORAL FEATURES")
print("=" * 80)

prevalence = df[features].mean().sort_values(ascending=False)

for feature_id, value in prevalence.head(30).items():

    name = feature_names.get(str(feature_id), feature_id)

    print(f"{name:<65} {value:.3f}")


# --------------------------------------------------
# Ransomware vs Goodware prevalence
# --------------------------------------------------

goodware = df[df["target"] == 0]
ransomware = df[df["target"] == 1]

goodware_prevalence = goodware[features].mean()
ransomware_prevalence = ransomware[features].mean()

difference = ransomware_prevalence - goodware_prevalence

comparison = pd.DataFrame({
    "feature_id": features,
    "feature_name": [
        feature_names.get(str(f), f)
        for f in features
    ],
    "goodware_prevalence": [
        goodware_prevalence[f]
        for f in features
    ],
    "ransomware_prevalence": [
        ransomware_prevalence[f]
        for f in features
    ],
    "difference": [
        difference[f]
        for f in features
    ],
})

comparison["absolute_difference"] = comparison["difference"].abs()

comparison = comparison.sort_values(
    "absolute_difference",
    ascending=False
)


# --------------------------------------------------
# Most discriminative features
# --------------------------------------------------

print("\n" + "=" * 80)
print("MOST DISCRIMINATIVE FEATURES")
print("=" * 80)

print(
    comparison[
        [
            "feature_name",
            "goodware_prevalence",
            "ransomware_prevalence",
            "difference",
        ]
    ]
    .head(30)
    .to_string(index=False)
)


# --------------------------------------------------
# Save analysis
# --------------------------------------------------

OUTPUT = ROOT / "dataset" / "reports" / "mlran_feature_analysis.csv"

comparison.to_csv(OUTPUT, index=False)

print("\n" + "=" * 80)
print("ANALYSIS COMPLETE")
print("=" * 80)

print(f"\nSaved feature analysis to:")
print(OUTPUT)