# Reconstructed BTF-style MLRan experiment

## What was regenerated

The source MLRan splits were mapped to the repository's canonical 31 BTF field order. For each BTF field, the mapping groups MLRan binary columns by the saved `candidate_runtime_category` labels and sums those 0/1 values. The exact source feature IDs and names for every output field are in `dataset/processed/btf_mapped_mlran/mapping_manifest.json`; the mapping rule is in `scripts/rebuild_btf_mlran_dataset.py`.

This produces a reproducible **MLRan-derived BTF proxy**. A summed value means how many mapped MLRan indicators were present in that sample. It is not a count of ETW events observed from a process.

## Dataset and split

- Source train: 3,905 rows; source test: 975 rows.
- Canonical output: 31 fields plus `sample_type`.
- The same four fields shown as constant in the prior slide were constant here: `file_activity.rename`, `network_activity.connect`, `resource_activity.handle_activity`, and `execution_activity.process_start`.
- Model inputs: 27 fields.
- Training portion: 3,124 rows; validation portion: 781 rows; untouched test: 975 rows.
- Label: `sample_type` (0 = goodware, 1 = ransomware).

## Reconstructed model results

| Model | Test accuracy | Precision | Recall | F1 | ROC-AUC | Test confusion matrix (TN, FP; FN, TP) |
|---|---:|---:|---:|---:|---:|---|
| Logistic Regression | 92.31% | 87.36% | 98.06% | 92.40% | 96.46% | 444, 66; 9, 456 |
| Random Forest | 92.92% | 88.52% | 97.85% | 92.95% | 97.96% | 451, 59; 10, 455 |
| XGBoost | 92.92% | 89.60% | 96.34% | 92.85% | 97.62% | 458, 52; 17, 448 |

## Comparison with the prior screenshots

The screenshot confusion matrices were LR `447, 63; 26, 439`, RF `451, 59; 18, 447`, and XGBoost `456, 54; 48, 417`. The regenerated data has the same row counts, 31-to-27 feature reduction, and same four constant fields, but its model results are not identical. That means this is a strong structural reconstruction, not proof that the historical source-to-BTF assignments or original model settings were recovered exactly.

## Files

- Mapping rule: `scripts/rebuild_btf_mlran_dataset.py`
- Generated train/test CSVs and source-level manifest: `dataset/processed/btf_mapped_mlran/`
- Training scripts: `scripts/train_btf_mapped_mlran.py` and `scripts/train_btf_mapped_mlran_xgboost.py`
- Models, predictions, and full-precision metrics: `results/btf_mapped_mlran_reconstruction/`
