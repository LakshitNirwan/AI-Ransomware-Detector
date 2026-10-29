# Recovery Implementation Status

Updated: 2026-10-25

## Completed and verified

- Confirmed MLRan target semantics: `sample_type` 0 = goodware, 1 = ransomware.
- Preserved the canonical 31-feature BTF schema.
- Added a proposed 18-feature ETW transformation contract and an extractor for one process window.
- Added strict ETW-then-BTF fusion with 49 candidate inputs.
- Added training-only exact-duplicate removal; test rows are used only to confirm that a dropped duplicate remains identical.
- Added a fused XGBoost training entry point that requires paired ransomware-labeled data and a reviewed metadata manifest.
- Added a runtime service that connects event batches to prediction, thresholded alerts, and a simulation-only response record.
- Verified focused extraction/fusion/training checks and safe runtime integration.
- Full repository suite: 27 passed.

## Pending evidence and integration

- The ETW-18 list is a proposal. Validate every feature against collected event behavior before treating it as final.
- No paired ETW+BTF ransomware/goodware train and test splits are present. The fused trainer correctly stops without them; no fused model metrics are available.
- The BTF prototype is Normal-vs-Anomaly and is not ransomware-labeled training data.
- The ETW collector is still a recovery scaffold that raises `RuntimeError`. No live ETW session was started.
- The runtime service accepts a caller-bounded event batch. Fixed-window collection and ordering are not yet implemented.
- Runtime integration was verified with a stub model. A real saved model, calibrated threshold, and real-data end-to-end run remain pending.
- The response layer only returns a simulation record; it does not isolate, suspend, terminate, or modify processes or files.

## Next gates

1. Validate the ETW feature contract using safely collected, labeled observations.
2. Obtain paired ETW+BTF ransomware/goodware windows with a defensible label source and split policy.
3. Train and evaluate on those splits; report exact duplicate reductions and held-out metrics.
4. Re-run the runtime path using the saved model and real collected windows, keeping response simulation-only.
