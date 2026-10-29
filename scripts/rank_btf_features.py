from pathlib import Path
import json

import pandas as pd
from sklearn.feature_selection import mutual_info_classif
from sklearn.ensemble import RandomForestClassifier


# --------------------------------------------------
# Paths
# --------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent

DATASET = ROOT / "dataset" / "processed" / "mlran_train.csv"
SCHEMA = ROOT / "dataset" / "schemas" / "mlran_feature_schema.json"
OUTPUT = ROOT / "dataset" / "reports" / "btf_feature_ranking.csv"


# --------------------------------------------------
# Load
# --------------------------------------------------

df = pd.read_csv(DATASET)

with open(SCHEMA, "r", encoding="utf-8") as f:
    schema = json.load(f)


feature_names = {
    str(item["id"]): item["name"]
    for item in schema["features"]
}


features = [
    c for c in df.columns
    if c not in ["sample_id", "target"]
]

X = df[features]
y = df["target"]


# --------------------------------------------------
# Class prevalence
# --------------------------------------------------

goodware = df[df["target"] == 0]
ransomware = df[df["target"] == 1]

goodware_rate = goodware[features].mean()
ransomware_rate = ransomware[features].mean()

enrichment = ransomware_rate - goodware_rate


# --------------------------------------------------
# Mutual information
# --------------------------------------------------

print("Calculating mutual information...")

mi = mutual_info_classif(
    X,
    y,
    discrete_features=True,
    random_state=42
)

mi_scores = pd.Series(mi, index=features)


# --------------------------------------------------
# Random Forest importance
# --------------------------------------------------

print("Training feature-ranking Random Forest...")

model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X, y)

rf_importance = pd.Series(
    model.feature_importances_,
    index=features
)


# --------------------------------------------------
# Build ranking table
# --------------------------------------------------

ranking = pd.DataFrame({
    "feature_id": features,

    "feature_name": [
        feature_names.get(str(f), f)
        for f in features
    ],

    "goodware_prevalence": [
        goodware_rate[f]
        for f in features
    ],

    "ransomware_prevalence": [
        ransomware_rate[f]
        for f in features
    ],

    "ransomware_enrichment": [
        enrichment[f]
        for f in features
    ],

    "mutual_information": [
        mi_scores[f]
        for f in features
    ],

    "random_forest_importance": [
        rf_importance[f]
        for f in features
    ],
})


# --------------------------------------------------
# Candidate ransomware signals
# --------------------------------------------------

ranking["ransomware_signal"] = (
    (ranking["ransomware_enrichment"] > 0)
    &
    (ranking["mutual_information"] > 0)
)


# --------------------------------------------------
# Combined score
# --------------------------------------------------

ranking["combined_score"] = (
    ranking["ransomware_enrichment"].clip(lower=0)
    * 0.4
    +
    ranking["mutual_information"]
    * 0.3
    +
    ranking["random_forest_importance"]
    * 0.3
)


# --------------------------------------------------
# Sort
# --------------------------------------------------

ranking = ranking.sort_values(
    "combined_score",
    ascending=False
)


# --------------------------------------------------
# Save
# --------------------------------------------------

ranking.to_csv(OUTPUT, index=False)


# --------------------------------------------------
# Display
# --------------------------------------------------

print("\n" + "=" * 90)
print("TOP RANSOMWARE-ENRICHED BTF CANDIDATES")
print("=" * 90)

print(
    ranking[
        [
            "feature_name",
            "goodware_prevalence",
            "ransomware_prevalence",
            "ransomware_enrichment",
            "mutual_information",
            "random_forest_importance",
            "combined_score",
        ]
    ]
    .head(40)
    .to_string(index=False)
)

print("\n" + "=" * 90)
print("Saved:")
print(OUTPUT)