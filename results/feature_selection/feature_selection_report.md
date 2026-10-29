# MLRan Feature-Selection Evaluation Report

## 1. Objective

Evaluate reduced subsets of the existing 483 MLRan binary features for ransomware-versus-goodware classification. This experiment performs feature ranking and selection over the existing processed dataset; it does not implement new runtime telemetry extraction.

## 2. Dataset and method

- Training samples: 3,905
- Test samples: 975
- Original feature count: 483
- Target: `sample_type` (0 = goodware, 1 = ransomware)
- Feature subset sizes evaluated: 31, 64, 100, 159
- Classifiers: Logistic Regression, Random Forest, XGBoost
- Random seed: 42

Feature ranking used mutual information, Random Forest feature importance, and ransomware-versus-goodware prevalence enrichment. The three ranking positions were averaged to produce the combined ranking. Feature ranking was performed using training data only.

The fixed test set was used to compare the selected subsets. Results are recorded in `subset_metrics.csv` and `subset_metrics.json`; run metadata is recorded in `run_info.json`.

## 3. Reduced-subset results

| Features | Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---:|---|---:|---:|---:|---:|---:|
| 31 | Logistic Regression | 82.77% | 85.27% | 77.20% | 81.04% | 94.30% |
| 31 | Random Forest | 90.36% | 89.72% | 90.11% | 89.91% | 97.08% |
| 31 | XGBoost | 90.26% | 89.87% | 89.68% | 89.77% | 97.04% |
| 64 | Logistic Regression | 94.05% | 91.28% | 96.77% | 93.95% | 98.49% |
| 64 | Random Forest | 95.28% | 93.02% | 97.42% | 95.17% | 98.59% |
| 64 | XGBoost | 94.67% | 92.75% | 96.34% | 94.51% | 98.92% |
| 100 | Logistic Regression | 95.69% | 95.10% | 95.91% | 95.50% | 99.07% |
| 100 | Random Forest | 95.49% | 96.06% | 94.41% | 95.23% | 99.08% |
| 100 | XGBoost | 96.00% | 95.71% | 95.91% | 95.81% | 99.26% |
| 159 | Logistic Regression | 97.33% | 96.60% | 97.85% | 97.22% | 99.44% |
| 159 | Random Forest | 95.69% | 96.08% | 94.84% | 95.45% | 99.17% |
| 159 | XGBoost | 96.92% | 95.79% | 97.85% | 96.81% | 99.46% |

## 4. Previously recorded 483-feature baselines

These are previously saved results, not models retrained as part of the subset evaluation.

| Features | Model | Accuracy | F1 | ROC-AUC |
|---:|---|---:|---:|---:|
| 483 | Logistic Regression | 98.15% | 98.08% | 99.68% |
| 483 | Random Forest | 96.41% | 96.26% | 99.52% |
| 483 | XGBoost | 96.72% | 96.60% | 99.58% |

## 5. Interpretation

- The 31-feature subset showed the largest performance reduction.
- The 64-feature subset improved substantially over the 31-feature subset.
- The 100-feature subset produced competitive results, particularly with XGBoost.
- The 159-feature subset was the strongest reduced-feature candidate in this comparison. Logistic Regression achieved 97.33% accuracy and 97.22% F1; XGBoost achieved 99.46% ROC-AUC.
- The recorded 483-feature Logistic Regression baseline remained stronger on accuracy and F1 than any reduced subset in this experiment.

A reasonable next candidate for further validation is the 159-feature subset. It should not yet be treated as the final production feature set.

## 6. Limitations and caveats

1. The 483-feature baseline values came from previously saved metrics and were not reproduced in this run.
2. The fixed test set was used to compare multiple subset sizes and models. Selecting a final model based on these results makes the test set part of the selection process. A separate holdout set or nested validation procedure is needed for an unbiased final estimate.
3. The metrics measure performance on the existing processed MLRan dataset. They do not establish generalization to unseen ransomware families, other datasets, or live systems.
4. This experiment selects existing MLRan features. It does not establish that ETW collection, runtime feature extraction, BTF population, or end-to-end live detection is implemented or validated.

## 7. Artifacts

- `dataset/reports/mlran_feature_selection_ranking.csv`
- `dataset/reports/mlran_selected_features_31.json`
- `dataset/reports/mlran_selected_features_64.json`
- `dataset/reports/mlran_selected_features_100.json`
- `dataset/reports/mlran_selected_features_159.json`
- `results/feature_selection/subset_metrics.csv`
- `results/feature_selection/subset_metrics.json`
- `results/feature_selection/run_info.json`

## 8. Conclusion

Feature selection reduced the input from 483 features to subsets of 31, 64, 100, and 159 features. In this experiment, the 159-feature subset offered the strongest reduced-feature results, while the recorded full-feature Logistic Regression baseline remained the performance reference. Further validation is required before choosing a final subset or making production-readiness claims.
