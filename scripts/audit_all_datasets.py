from pathlib import Path
import pandas as pd

for p in sorted(Path("dataset").rglob("*.csv")):
    try:
        df = pd.read_csv(p, low_memory=False)
        labels = [
            c for c in df.columns
            if any(k in c.lower() for k in ("label", "class", "target", "family", "type", "status"))
        ]
        print(f"\n{'=' * 80}\nFILE: {p}\nSHAPE: {df.shape}")
        print("COLUMNS:", list(df.columns))
        print("LABEL-LIKE COLUMNS:", labels)
        for c in labels:
            print(f"  VALUES in {c!r}:", df[c].value_counts(dropna=False).head(12).to_dict())
    except Exception as e:
        print(f"\nFILE: {p}\nERROR: {e}")
