
import csv
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "dataset" / "reports"
SCHEMA_PATH = ROOT / "dataset" / "schemas" / "mlran_feature_schema.json"
MAPPING_PATH = REPORTS / "mlran_feature_mapping_final.csv"
ANALYSIS_PATH = REPORTS / "mlran_feature_analysis.csv"
RANKING_PATH = REPORTS / "btf_feature_ranking.csv"
OUTPUT_PATH = REPORTS / "mlran_feature_evidence_review.csv"


def read_csv(path):
    if not path.is_file():
        raise FileNotFoundError(f"Required input is missing: {path}")

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError(f"CSV has no header: {path}")
        return list(reader)


def index_unique(rows, key, label):
    result = {}
    for row in rows:
        value = row.get(key, "").strip()
        if not value:
            raise ValueError(f"{label} contains an empty {key}")
        if value in result:
            raise ValueError(f"{label} contains duplicate {key}: {value}")
        result[value] = row
    return result


def number(row, field, label):
    try:
        value = float(row[field])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"Invalid numeric field {label}.{field}") from exc

    if not math.isfinite(value):
        raise ValueError(f"Non-finite numeric field {label}.{field}")
    return value


def main():
    with SCHEMA_PATH.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)

    feature_ids = schema.get("feature_columns")
    feature_names = schema.get("feature_names")

    if not isinstance(feature_ids, list) or not isinstance(feature_names, dict):
        raise ValueError(
            "Schema must contain feature_columns and feature_names"
        )

    feature_ids = [str(value) for value in feature_ids]
    expected_ids = set(feature_ids)

    if len(feature_ids) != 483 or len(expected_ids) != 483:
        raise ValueError("Expected exactly 483 unique schema feature IDs")

    missing_names = [
        feature_id for feature_id in feature_ids
        if feature_id not in feature_names
        or not isinstance(feature_names[feature_id], str)
    ]
    if missing_names:
        raise ValueError(f"Missing schema feature names: {missing_names[:10]}")

    mapping = index_unique(
        read_csv(MAPPING_PATH), "feature_id", "mapping"
    )
    analysis = index_unique(
        read_csv(ANALYSIS_PATH), "feature_id", "feature analysis"
    )
    ranking = index_unique(
        read_csv(RANKING_PATH), "feature_id", "BTF ranking"
    )

    for label, indexed in (
        ("mapping", mapping),
        ("feature analysis", analysis),
        ("BTF ranking", ranking),
    ):
        extra = set(indexed) - expected_ids
        if extra:
            raise ValueError(
                f"{label} has IDs outside the schema: {sorted(extra)[:10]}"
            )

    if set(analysis) != expected_ids:
        raise ValueError("Feature analysis does not cover all 483 schema IDs")
    if set(ranking) != expected_ids:
        raise ValueError("BTF ranking does not cover all 483 schema IDs")

    fields = [
        "feature_id",
        "feature_name",
        "mapping_feature_name",
        "mlran_category",
        "runtime_category",
        "runtime_status",
        "reason",
        "goodware_prevalence",
        "ransomware_prevalence",
        "prevalence_difference",
        "absolute_difference",
        "ransomware_enrichment",
        "mutual_information",
        "random_forest_importance",
        "ransomware_signal",
        "combined_score",
        "review_priority",
        "name_whitespace_note",
    ]

    output_rows = []
    whitespace_warnings = []

    for feature_id in feature_ids:
        schema_name = feature_names[feature_id]
        a = analysis[feature_id]
        r = ranking[feature_id]
        m = mapping.get(feature_id, {})

        for label, source_row in (("analysis", a), ("ranking", r)):
            source_name = source_row.get("feature_name", "")

            # Compare exact names first. If only whitespace differs,
            # record it for review instead of silently changing the name.
            if source_name != schema_name:
                if source_name.strip() == schema_name.strip():
                    whitespace_warnings.append(
                        (feature_id, label, repr(schema_name), repr(source_name))
                    )
                else:
                    raise ValueError(
                        f"Substantive feature-name mismatch for {feature_id} "
                        f"in {label}: {source_name!r} != {schema_name!r}"
                    )

        mapping_name = m.get("feature_name", "")
        if m and mapping_name != schema_name:
            if mapping_name.strip() != schema_name.strip():
                raise ValueError(
                    f"Substantive mapping-name mismatch for {feature_id}: "
                    f"{mapping_name!r} != {schema_name!r}"
                )
            whitespace_warnings.append(
                (feature_id, "mapping", repr(schema_name), repr(mapping_name))
            )

        status = m.get("runtime_status", "").strip() or "UNREVIEWED"
        if status not in {"ABSTRACT", "EXCLUDE", "UNREVIEWED"}:
            raise ValueError(
                f"Unexpected runtime status {status!r} for {feature_id}"
            )

        signal = r.get("ransomware_signal", "").strip().lower()
        if signal not in {"true", "false"}:
            raise ValueError(
                f"Unexpected ransomware_signal {signal!r} for {feature_id}"
            )

        goodware_prevalence = number(a, "goodware_prevalence", "analysis")
        ransomware_prevalence = number(a, "ransomware_prevalence", "analysis")
        difference = number(a, "difference", "analysis")
        absolute_difference = number(a, "absolute_difference", "analysis")
        enrichment = number(r, "ransomware_enrichment", "ranking")
        mutual_information = number(r, "mutual_information", "ranking")
        importance = number(r, "random_forest_importance", "ranking")
        combined_score = number(r, "combined_score", "ranking")

        if not 0 <= goodware_prevalence <= 1:
            raise ValueError(f"Invalid goodware prevalence for {feature_id}")
        if not 0 <= ransomware_prevalence <= 1:
            raise ValueError(f"Invalid ransomware prevalence for {feature_id}")

        if status != "UNREVIEWED":
            priority = "EXISTING_CLASSIFICATION"
        elif signal == "true" or combined_score > 0:
            priority = "HIGH_STATISTICAL_SIGNAL"
        else:
            priority = "REVIEW_REQUIRED"

        output_rows.append({
            "feature_id": feature_id,
            "feature_name": schema_name,
            "mapping_feature_name": mapping_name,
            "mlran_category": m.get("mlran_category", ""),
            "runtime_category": m.get("runtime_category", ""),
            "runtime_status": status,
            "reason": m.get("reason", ""),
            "goodware_prevalence": goodware_prevalence,
            "ransomware_prevalence": ransomware_prevalence,
            "prevalence_difference": difference,
            "absolute_difference": absolute_difference,
            "ransomware_enrichment": enrichment,
            "mutual_information": mutual_information,
            "random_forest_importance": importance,
            "ransomware_signal": signal,
            "combined_score": combined_score,
            "review_priority": priority,
            "name_whitespace_note": "",
        })

    # Put name discrepancies in the output so they are visible and auditable.
    warnings_by_id = {}
    for feature_id, source, schema_repr, report_repr in whitespace_warnings:
        note = (
            f"{source}: schema={schema_repr}; report={report_repr}"
        )
        warnings_by_id.setdefault(feature_id, []).append(note)

    for row in output_rows:
        notes = warnings_by_id.get(row["feature_id"], [])
        row["name_whitespace_note"] = " | ".join(notes)

    REPORTS.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(output_rows)

    status_counts = {}
    priority_counts = {}
    for row in output_rows:
        status = row["runtime_status"]
        priority = row["review_priority"]
        status_counts[status] = status_counts.get(status, 0) + 1
        priority_counts[priority] = priority_counts.get(priority, 0) + 1

    print("FEATURE EVIDENCE REPORT")
    print("Schema features:", len(feature_ids))
    print("Analysis features:", len(analysis))
    print("Ranking features:", len(ranking))
    print("Existing mapping rows:", len(mapping))
    print("Output rows:", len(output_rows))
    print("Runtime status counts:", status_counts)
    print("Review priority counts:", priority_counts)
    print("Whitespace-only name discrepancies:", len(whitespace_warnings))
    for item in whitespace_warnings:
        print(
            f"WARNING feature {item[0]} ({item[1]}): "
            f"schema={item[2]}, report={item[3]}"
        )
    print("Output:", OUTPUT_PATH)
    print("Validation: IDs, names, numeric evidence, and statuses checked")
    print("Note: statistical priority does not determine runtime suitability.")


if __name__ == "__main__":
    main()
