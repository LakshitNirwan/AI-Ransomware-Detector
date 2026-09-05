\# AI Ransomware Detector — Decision Log



This file is the authoritative record of important project decisions.



Decision status:

\- PROPOSED = under consideration

\- TESTED = implemented/tested but not yet permanently locked

\- LOCKED = approved and should not be changed casually

\- REJECTED = considered and deliberately discarded

\- REOPENED = previously locked but reopened because new evidence invalidated it



\---



\## DEC-001 — Primary ML Model



Status: LOCKED



Decision:

Use XGBoost as the primary ML classifier.



Reason:

The project uses structured/tabular behavioral features. XGBoost also supports the feature-importance and explanation workflow planned for the project.



Evidence:

XGBoost baseline was trained and evaluated on MLRan.



Date:

2026-09-05



\---



\## DEC-002 — Remove Dataset Metadata From ML Features



Status: LOCKED



Decision:

Do not use sample\_id, sample\_type, family\_label, or type\_label as ML input features.



Reason:

These are dataset metadata/labels rather than behavioral evidence.



Evidence:

Verified processed MLRan train/test matrices contain 483 behavioral features plus target.



Date:

2026-09-05



\---



\## DEC-003 — MLRan Abstract Feature Baseline



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



\---



\## DEC-004 — BTF Dimensions



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



\---



\## DEC-005 — BTF Feature Count



Status: LOCKED



Decision:

The canonical BTF vector contains 31 event-count features.



Breakdown:

\- File: 7

\- Process: 5

\- Registry: 7

\- Network: 5

\- Resource: 3

\- Execution: 4



Evidence:

Schema validation returned BTF FEATURES: 31.



Date:

2026-09-05



\---



\## DEC-006 — Process-Centered BTF



Status: LOCKED



Decision:

Each BTF is associated with one process/PID and its observation window.



Reason:

The proposed detector needs to associate behavior with the process responsible for file activity.



Evidence:

Process isolation test returned ISOLATION: True.



Date:

2026-09-05



\---



\## DEC-007 — Raw Telemetry vs ML Features



Status: LOCKED



Decision:

Raw telemetry fields such as paths, PIDs, timestamps, and provider-specific identifiers may be retained for correlation, investigation, and explanation, but they are not automatically treated as ML features.



Reason:

The runtime representation should use generalized behavioral abstractions rather than blindly feeding provider-specific identifiers into the classifier.



Date:

2026-09-05



\---



\## DEC-008 — Research Direction



Status: LOCKED AS RESEARCH DIRECTION



Decision:

Investigate whether combining process behavioral context with process-aware destructive file-transformation evidence can improve discrimination between ransomware and legitimate bulk file-processing activity.



Important:

This is a research question, not a proven result.



Evidence required:

Controlled experiments comparing appropriate feature configurations and benign workloads.



Date:

2026-09-05

