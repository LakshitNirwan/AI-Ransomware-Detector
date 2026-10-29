# AI Ransomware Detector — Decision Log



This file is the authoritative record of important project decisions.



Decision status:

- PROPOSED = under consideration

- TESTED = implemented/tested but not yet permanently locked

- LOCKED = approved and should not be changed casually

- REJECTED = considered and deliberately discarded

- REOPENED = previously locked but reopened because new evidence invalidated it



---



## DEC-001 — Primary ML Model



Status: LOCKED



Decision:

Use XGBoost as the primary ML classifier.



Reason:

The project uses structured/tabular behavioral features. XGBoost also supports the feature-importance and explanation workflow planned for the project.



Evidence:

XGBoost baseline was trained and evaluated on MLRan.



Date:

2026-09-05



---



## DEC-002 — Remove Dataset Metadata From ML Features



Status: LOCKED



Decision:

Do not use sample\_id, sample\_type, family\_label, or type\_label as ML input features.



Reason:

These are dataset metadata/labels rather than behavioral evidence.



Evidence:

Verified processed MLRan train/test matrices contain 483 behavioral features plus target.



Date:

2026-09-05



---



## DEC-003 — MLRan Abstract Feature Baseline



Status: LOCKED



Decision:

Use the 159 features classified as ABSTRACT for the cleaner MLRan baseline.



Reason:

The project separates runtime-representable behavioral abstractions from features that are overly specific, static, contextual, or otherwise unsuitable for the proposed runtime representation.



Evidence:

Final MLRan feature mapping:

159 ABSTRACT

324 EXCLUDE



Date:

2026-09-05



---



## DEC-004 — BTF Dimensions



Status: LOCKED



Decision:

BTF uses six dimensions:



1\. file\_activity

2\. process\_activity

3\. registry\_activity

4\. network\_activity

5\. resource\_activity

6\. execution\_activity



Reason:

These provide the canonical process-centered behavioral representation used by the current architecture.



Evidence:

BTF schema implemented and validated.



Date:

2026-09-05



---



## DEC-005 — BTF Feature Count



Status: LOCKED



Decision:

The canonical BTF vector contains 31 event-count features.



Breakdown:

- File: 7

- Process: 5

- Registry: 7

- Network: 5

- Resource: 3

- Execution: 4



Evidence:

Schema validation returned BTF FEATURES: 31.



Date:

2026-09-05



---



## DEC-006 — Process-Centered BTF



Status: LOCKED



Decision:

Each BTF is associated with one process/PID and its observation window.



Reason:

The proposed detector needs to associate behavior with the process responsible for file activity.



Evidence:

Process isolation test returned ISOLATION: True.



Date:

2026-09-05



---



## DEC-007 — Raw Telemetry vs ML Features



Status: LOCKED



Decision:

Raw telemetry fields such as paths, PIDs, timestamps, and provider-specific identifiers may be retained for correlation, investigation, and explanation, but they are not automatically treated as ML features.



Reason:

The runtime representation should use generalized behavioral abstractions rather than blindly feeding provider-specific identifiers into the classifier.



Date:

2026-09-05



---



## DEC-008 — Research Direction



Status: LOCKED AS RESEARCH DIRECTION



Decision:

Investigate whether combining process behavioral context with process-aware destructive file-transformation evidence can improve discrimination between ransomware and legitimate bulk file-processing activity.



Important:

This is a research question, not a proven result.



Evidence required:

Controlled experiments comparing appropriate feature configurations and benign workloads.



Date:

2026-09-05


---

## DEC-009 — Recovered Dataset Preprocessing Contract

Status: TESTED

Decision:

Use the source MLRan train and test splits. Exclude sample_id, family_label, and type_label from model inputs. Retain sample_type as the binary target.

Evidence:

Source audit and independent processed-data validation confirmed 3,905 training rows, 975 test rows, 483 binary behavioral features, target distributions of 2,040/1,865 in train and 510/465 in test, and zero source train/test sample-ID overlap.

Processed CSVs contain 483 behavioral features plus sample_type (484 columns). The feature schema is saved at dataset/schemas/mlran_feature_schema.json.

Date:

2026-10-19

---

## DEC-010 — Historical Experiment Results Must Be Reproduced

Status: TESTED

Decision:

Treat existing experiment-log metrics as historical records, not as newly reproduced results in the recovery workspace.

Reason:

The current Python 3.15 environment does not have pytest, pandas, numpy, scikit-learn, or xgboost installed. Reproduction requires a compatible environment and a documented run.

Evidence:

Package availability inspection reported all five packages as NOT INSTALLED.

Date:

2026-10-19


## DEC-011 — Provisional binary feature classification (2026-10-19)

- Output: `dataset/reports/mlran_final_feature_classification.csv`.
- Classified 483 features: 221 INCLUDE and 262 EXCLUDE.
- Existing reviewed ABSTRACT decisions were preserved as INCLUDE; existing reviewed EXCLUDE decisions were preserved as EXCLUDE.
- Other decisions are provisional, rule-based classifications, not proof of runtime observability or predictive value.
- File/handle operations must be distinguished from disk-file transformations during runtime validation.


## DEC-011 — Provisional binary feature classification (2026-10-19)

- Output: `dataset/reports/mlran_final_feature_classification.csv`.
- Classified 483 features: 221 INCLUDE and 262 EXCLUDE.
- Existing reviewed ABSTRACT decisions were preserved as INCLUDE; existing reviewed EXCLUDE decisions were preserved as EXCLUDE.
- Other decisions are provisional, rule-based classifications, not proof of runtime observability or predictive value.
- File/handle operations must be distinguished from disk-file transformations during runtime validation.
