
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif

ROOT = Path(__file__).resolve().parents[1]
TRAIN_PATH = ROOT / "dataset" / "processed" / "mlran_train.csv"
SCHEMA_PATH = ROOT / "dataset" / "schemas" / "mlran_feature_schema.json"
REPORT_DIR = ROOT / "dataset" / "reports"

RANKING_PATH = REPORT_DIR / "mlran_feature_selection_ranking.csv"
SUBSET_SIZES = (31, 64, 100, 159)
SEED = 42


def main() -> None:
    # Refuse to overwrite any output.
    planned_outputs = [
        RANKING_PATH,
        *(REPORT_DIR / f"mlran_selected_features_{n}.json"
          for n in SUBSET_SIZES),
    ]
    existing = [str(path) for path in planned_outputs if path.exists()]
    if existing:
        raise FileExistsError(
            "Refusing to overwrite existing outputs:\n" + "\n".join(existing)
        )

    if not TRAIN_PATH.is_file() or not SCHEMA_PATH.is_file():
        raise FileNotFoundError("Training CSV or schema file is missing.")

    with SCHEMA_PATH.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)

    target = schema["target_column"]
    feature_columns = schema["feature_columns"]
    feature_names = schema["feature_names"]

    df = pd.read_csv(TRAIN_PATH)

    if list(df.columns) != feature_columns + [target]:
        raise ValueError("Training columns do not match the schema and order.")
    if len(feature_columns) != 483 or schema["feature_count"] != 483:
        raise ValueError("Expected exactly 483 features.")
    if set(df[target].astype(int).unique()) != {0, 1}:
        raise ValueError("Expected both target labels 0 and 1.")
    if df[feature_columns].isna().any().any():
        raise ValueError("Missing feature values detected.")

    X = df[feature_columns].astype(np.uint8)
    y = df[target].astype(int)

    if not X.isin([0, 1]).all().all():
        raise ValueError("Expected all feature values to be binary.")

    print(f"Training rows: {len(df)}")
    print(f"Features: {len(feature_columns)}")
    print("Calculating mutual information...", flush=True)

    mi = mutual_info_classif(
        X,
        y,
        discrete_features=True,
        random_state=SEED,
    )

    print("Training Random Forest for feature ranking...", flush=True)
    forest = RandomForestClassifier(
        n_estimators=300,
        random_state=SEED,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )
    forest.fit(X, y)

    goodware_rate = X.loc[y == 0].mean()
    ransomware_rate = X.loc[y == 1].mean()
    enrichment = ransomware_rate - goodware_rate

    # Rank each metric to avoid adding raw scores with different scales.
    ranking = pd.DataFrame({
        "feature_column": feature_columns,
        "feature_name": [feature_names[c] for c in feature_columns],
        "goodware_prevalence": goodware_rate.to_numpy(),
        "ransomware_prevalence": ransomware_rate.to_numpy(),
        "ransomware_enrichment": enrichment.to_numpy(),
        "mutual_information": mi,
        "random_forest_importance": forest.feature_importances_,
    })

    ranking["mi_rank"] = ranking["mutual_information"].rank(
        ascending=False, method="average"
    )
    ranking["forest_rank"] = ranking["random_forest_importance"].rank(
        ascending=False, method="average"
    )
    ranking["enrichment_rank"] = ranking["ransomware_enrichment"].rank(
        ascending=False, method="average"
    )
    ranking["mean_rank"] = ranking[
        ["mi_rank", "forest_rank", "enrichment_rank"]
    ].mean(axis=1)

    ranking = ranking.sort_values(
        ["mean_rank", "feature_column"], ascending=[True, True]
    ).reset_index(drop=True)
    ranking.insert(0, "selection_rank", np.arange(1, len(ranking) + 1))

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ranking.to_csv(RANKING_PATH, index=False)

    for size in SUBSET_SIZES:
        selected = ranking.head(size)["feature_column"].tolist()
        output = REPORT_DIR / f"mlran_selected_features_{size}.json"
        output.write_text(
            json.dumps({
                "dataset": "MLRan",
                "target_column": target,
                "selection_method": (
                    "Mean rank of mutual information, Random Forest "
                    "importance, and ransomware enrichment"
                ),
                "training_rows": len(df),
                "available_features": len(feature_columns),
                "selected_feature_count": size,
                "seed": SEED,
                "feature_columns": selected,
                "feature_names": {
                    column: feature_names[column] for column in selected
                },
            }, indent=2),
            encoding="utf-8",
        )
        print(f"Saved {size}-feature list: {output}")

    print(f"Saved ranking: {RANKING_PATH}")
    print("Feature selection completed. No test data was loaded.")


if __name__ == "__main__":
    main()
