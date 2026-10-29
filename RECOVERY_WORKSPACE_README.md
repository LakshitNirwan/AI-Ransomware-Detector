# AI Ransomware Detector — Recovery Workspace

This workspace combines:
1. The `AI-Ransomware-Detector-main.zip` archive as the dataset/project-tree source.
2. Files from the partial chat-based recovery archive, overlaid only when the base file was absent or zero bytes (except README.md, which was replaced with the more informative recovery README).

## Important: not a complete restoration

The recovered chat archive explicitly says it is partial. Some recovered files are scaffolding/inferred, especially:
- `monitor/etw_collector.py`
- `features/transformation/schema.py`
- `features/transformation/state_tracker.py`
- `features/transformation/etw_correlator.py`
- `scripts/*`
- `tests/*`

Evidence-backed recovered files include:
- `features/btf/schema.py`
- `features/transformation/metadata.py`
- `features/transformation/kernel_file_processor.py`
- `features/transformation/analyzer.py`
- `features/transformation/correlator.py`

## Dataset warning — read before training

The archive contains the MLRan source files and processed CSVs. The *current processed CSVs in the base archive are stale*: their header has 485 columns and includes `sample_id`, while the recorded locked contract is 483 behavioral features plus target (484 columns), with metadata excluded. Do not train from `dataset/processed/mlran_train.csv` or `mlran_test.csv` until they have been regenerated and validated using a corrected preprocessing script that removes `sample_id` from model input.

The source MLRan files are under:
`dataset/raw/mlran_repo/6_experiments/FS_MLRan_Datasets/`

## What to treat as authoritative

- Use `docs/decision_log.md` as the historical decision record, but note it predates the latest runtime integration work.
- Use `RECOVERY_MANIFEST.json` and `docs/CHAT_EVIDENCE.md` to distinguish recovered evidence from scaffolding.
- Do not claim ETW transformation, feature fusion, or end-to-end detection is complete solely because related files exist.
- Do not assume models/reports from the lost local repository were recovered unless present in this workspace.

## First recovery checkpoint

1. Keep this ZIP unchanged as a recovery snapshot.
2. Extract to a new folder, not over an existing project.
3. Verify the dataset source files and processed CSV schema.
4. Correct and rerun MLRan preprocessing before training.
5. Reconstruct missing source files from version control/chat evidence and validate each subsystem before proceeding.
