import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from features.btf.schema import BTF_EVENTS, BTFDimension, BTFVector

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "dataset" / "raw" / "os_kernel" / "os_kernel_power_dataset.csv"
OUT_DIR = ROOT / "dataset" / "processed"
OUT_CSV = OUT_DIR / "btf_anomaly_prototype.csv"
OUT_INFO = OUT_DIR / "btf_anomaly_prototype_info.json"

# Only mappings supported by the source's syscall column.
SYSCALL_MAP = {
    "open": (BTFDimension.FILE, "open"),
    "read": (BTFDimension.FILE, "read"),
    "write": (BTFDimension.FILE, "write"),
    "close": None,  # No matching BTF event; deliberately not relabeled.
    "execve": (BTFDimension.EXECUTION, "process_start"),
    "ioctl": None,
    "mmap": None,
}

def main():
    if not SOURCE.exists():
        raise FileNotFoundError(f"Missing source dataset: {SOURCE}")

    df = pd.read_csv(SOURCE)
    required = {"Timestamp", "Syscall", "PID", "Process_Name", "Label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="raise")
    feature_names = [
        f"{dimension.value}.{event}"
        for dimension, events in BTF_EVENTS.items()
        for event in events
    ]

    rows = []
    for (pid, process_name), group in df.groupby(
        ["PID", "Process_Name"], sort=True
    ):
        group = group.sort_values("Timestamp")
        counts = {dimension: {} for dimension in BTF_EVENTS}
        for _, event in group.iterrows():
            mapping = SYSCALL_MAP.get(str(event["Syscall"]).lower())
            if mapping is None:
                continue
            dimension, event_name = mapping
            counts[dimension][event_name] = (
                counts[dimension].get(event_name, 0) + 1
            )

        vector = BTFVector(
            file_activity=counts[BTFDimension.FILE],
            execution_activity=counts[BTFDimension.EXECUTION],
        )
        flat = vector.to_flat_dict()
        labels = group["Label"].astype(str).str.strip().str.lower()
        if not labels.isin({"normal", "anomaly"}).all():
            raise ValueError(f"Unexpected labels for PID {pid}: {sorted(labels.unique())}")

        # Mixed labels stay mixed/ambiguous and are excluded from supervised rows.
        unique_labels = set(labels.unique())
        if len(unique_labels) != 1:
            continue

        row = {
            "pid": int(pid),
            "process_name": str(process_name),
            "window_start": group["Timestamp"].min().isoformat(),
            "window_end": group["Timestamp"].max().isoformat(),
            **flat,
            "label": 1 if next(iter(unique_labels)) == "anomaly" else 0,
        }
        rows.append(row)

    out = pd.DataFrame(rows)
    columns = ["pid", "process_name", "window_start", "window_end"] + feature_names + ["label"]
    if out.empty:
        raise ValueError("No single-label process groups remain; cannot build supervised dataset.")

    out = out[columns]
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out.to_csv(OUT_CSV, index=False)

    info = {
        "dataset_type": "prototype_only",
        "task": "Normal-vs-Anomaly",
        "not_validated_as_ransomware_labels": True,
        "source": str(SOURCE.relative_to(ROOT)),
        "label_mapping": {"0": "Normal", "1": "Anomaly"},
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "mapping_policy": "Only open/read/write/execve are mapped; unsupported syscalls are not relabeled.",
        "window_policy": "Grouped by PID and process name over the full source duration; mixed-label groups excluded.",
        "rows_written": len(out),
        "rows_excluded_for_mixed_labels": int(
            df.groupby(["PID", "Process_Name"])["Label"].nunique().gt(1).sum()
        ),
        "label_counts": {
            str(k): int(v) for k, v in out["label"].value_counts().sort_index().items()
        },
    }
    OUT_INFO.write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")

    print(f"Wrote dataset: {OUT_CSV.relative_to(ROOT)}")
    print(f"Wrote metadata: {OUT_INFO.relative_to(ROOT)}")
    print(f"Rows: {len(out)}")
    print(f"Feature count: {len(feature_names)}")
    print("Label counts:", info["label_counts"])
    print("Excluded mixed-label process groups:", info["rows_excluded_for_mixed_labels"])
    print("WARNING: This is a Normal-vs-Anomaly prototype, not validated ransomware training data.")

if __name__ == "__main__":
    main()


