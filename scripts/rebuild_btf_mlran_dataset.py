import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRAIN_IN = ROOT / "dataset/processed/mlran_train.csv"
TEST_IN = ROOT / "dataset/processed/mlran_test.csv"
MAPPING_IN = ROOT / "dataset/reports/mlran_candidate_runtime_mapping.csv"
OUT_DIR = ROOT / "dataset/processed/btf_mapped_mlran"
TARGET = "sample_type"

# Explicit semantic mapping from the saved MLRan runtime-category ledger to
# the canonical BTF schema. Values are source-presence flags, not telemetry counts.
BTF_TO_RUNTIME_CATEGORIES = {
    "file_activity.open": ["file_open_activity"],
    "file_activity.read": ["file_read_activity"],
    "file_activity.write": ["file_write_activity"],
    "file_activity.create": ["file_recreation_activity", "directory_create", "directory_create_activity"],
    "file_activity.delete": ["file_state_modification", "directory_deletion"],
    "file_activity.rename": [],
    "file_activity.enumerate": ["directory_enumeration"],
    "process_activity.create": ["process_creation_activity"],
    "process_activity.enumerate": ["process_enumeration", "process_snapshot_enumeration"],
    "process_activity.open": ["process_interaction"],
    "process_activity.memory_write": ["cross_process_memory_write"],
    "process_activity.thread_context": ["thread_context_modify", "thread_context_read"],
    "registry_activity.open": ["registry_open_activity"],
    "registry_activity.read": ["registry_read_activity"],
    "registry_activity.query": ["registry_query_activity"],
    "registry_activity.write": ["registry_write_activity"],
    "registry_activity.create": ["registry_key_creation"],
    "registry_activity.delete": ["registry_delete_activity"],
    "registry_activity.enumerate": ["registry_enumeration"],
    "network_activity.connect": [],
    "network_activity.dns": ["dns_lookup_activity"],
    "network_activity.http": ["http_network_activity"],
    "network_activity.icmp": ["icmp_network_activity"],
    "network_activity.socket": ["network_or_socket_activity"],
    "resource_activity.memory_allocate": ["virtual_memory_allocation", "remote_process_allocation"],
    "resource_activity.memory_protect": ["memory_protection_activity"],
    "resource_activity.handle_activity": [],
    "execution_activity.process_start": [],
    "execution_activity.injection": ["process_injection_execution", "process_injection_memory_modification"],
    "execution_activity.persistence": ["autorun_persistence_activity"],
    "execution_activity.exception_handler": ["exception_handler_registration"],
}


def read_csv(path):
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        return reader.fieldnames, rows


def main():
    mapping_fields, mapping_rows = read_csv(MAPPING_IN)
    required_mapping = {"feature_id", "feature_name", "candidate_runtime_category"}
    if not required_mapping.issubset(mapping_fields or []):
        raise ValueError(f"Mapping ledger must contain {sorted(required_mapping)}")
    category_to_sources = {}
    for row in mapping_rows:
        category = (row.get("candidate_runtime_category") or "").strip()
        if category:
            category_to_sources.setdefault(category, []).append({
                "feature_id": str(row["feature_id"]),
                "feature_name": row["feature_name"],
            })

    canonical = list(BTF_TO_RUNTIME_CATEGORIES)
    manifest = {"mapping_type": "MLRan presence-sum proxy; not observed BTF/ETW event counts",
                "source_mapping_file": str(MAPPING_IN.relative_to(ROOT)),
                "target_column": TARGET, "canonical_btf_feature_count": len(canonical),
                "features": {}}
    source_ids = set()
    for target, categories in BTF_TO_RUNTIME_CATEGORIES.items():
        sources = [item for category in categories for item in category_to_sources.get(category, [])]
        manifest["features"][target] = {
            "source_runtime_categories": categories,
            "source_features": sources,
            "source_feature_count": len(sources),
            "mapping_status": "mapped" if sources else "unsupported_zero",
            "aggregation": "sum of source binary flags" if sources else "constant zero",
        }
        source_ids.update(item["feature_id"] for item in sources)

    train_fields, train_rows = read_csv(TRAIN_IN)
    test_fields, test_rows = read_csv(TEST_IN)
    if not train_fields or not test_fields or TARGET not in train_fields or TARGET not in test_fields:
        raise ValueError(f"Both source splits must contain target {TARGET!r}")
    if train_fields != test_fields:
        raise ValueError("MLRan train/test columns differ")
    missing = source_ids - set(train_fields)
    if missing:
        raise ValueError(f"Mapped feature IDs missing from MLRan CSV: {sorted(missing)}")

    def transform(rows, out_path):
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=canonical + [TARGET])
            writer.writeheader()
            for row in rows:
                output = {}
                for target, categories in BTF_TO_RUNTIME_CATEGORIES.items():
                    ids = [item["feature_id"] for category in categories
                           for item in category_to_sources.get(category, [])]
                    output[target] = sum(int(float(row[col])) for col in ids)
                output[TARGET] = int(row[TARGET])
                writer.writerow(output)

    train_out = OUT_DIR / "btf_mapped_mlran_train.csv"
    test_out = OUT_DIR / "btf_mapped_mlran_test.csv"
    transform(train_rows, train_out)
    transform(test_rows, test_out)
    manifest["train_rows"] = len(train_rows)
    manifest["test_rows"] = len(test_rows)
    manifest["mapped_feature_count"] = sum(bool(v["source_feature_count"]) for v in manifest["features"].values())
    manifest["unsupported_zero_features"] = [k for k, v in manifest["features"].items() if not v["source_feature_count"]]
    manifest["warning"] = "This reconstructed proxy is not the missing historical BTF mapping and cannot establish equivalence to the slide results."
    (OUT_DIR / "mapping_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {train_out.relative_to(ROOT)}: {len(train_rows)} rows")
    print(f"Wrote {test_out.relative_to(ROOT)}: {len(test_rows)} rows")
    print(f"Canonical columns: {len(canonical)}; mapped: {manifest['mapped_feature_count']}; unsupported zero: {len(manifest['unsupported_zero_features'])}")
    print("Unsupported-zero fields:", ", ".join(manifest["unsupported_zero_features"]))
    print(f"Mapping manifest: {(OUT_DIR / 'mapping_manifest.json').relative_to(ROOT)}")


if __name__ == "__main__":
    main()
