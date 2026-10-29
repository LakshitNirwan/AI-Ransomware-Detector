import csv
from collections import Counter, defaultdict
from pathlib import Path

path = Path("dataset/reports/mlran_final_feature_classification.csv")

with path.open("r", encoding="utf-8-sig", newline="") as f:
    rows = list(csv.DictReader(f))

groups = defaultdict(Counter)

for row in rows:
    name = row.get("feature_name", "")
    category = name.split(":", 1)[0] if ":" in name else "OTHER"
    decision = row.get("decision", "")
    groups[category][decision] += 1

print(f"Total rows: {len(rows)}")
print()
print(f"{'CATEGORY':<15} {'INCLUDE':>8} {'EXCLUDE':>8} {'TOTAL':>8}")

for category, counts in sorted(groups.items()):
    included = counts["INCLUDE"]
    excluded = counts["EXCLUDE"]
    print(
        f"{category:<15} {included:>8} {excluded:>8} "
        f"{included + excluded:>8}"
    )

print()
print("Overall decisions:", dict(Counter(
    row.get("decision", "") for row in rows
)))