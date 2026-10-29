"""Partial scaffold. Chat reported 338 importance rows, all mapped, but not full source."""
from pathlib import Path
import pandas as pd
def main():
    path=Path("dataset/reports/mlran_feature_mapping_final.csv")
    if not path.exists(): raise SystemExit(f"Missing {path}")
    df=pd.read_csv(path)
    print("Rows in recovered partial mapping:",len(df))
    print("Columns:",list(df.columns))
    print("Original importance input and complete script were not available.")
if __name__=="__main__": main()
