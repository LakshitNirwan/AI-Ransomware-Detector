# AI-Ransomware-Detector — chat-based recovery

This is a **partial reconstruction**, not a byte-for-byte recovery of the lost repository. It combines code visible in chat excerpts with clearly labelled scaffolding for missing components.

Observed original path: `C:\PERSONAL\Projects\AI-Ransomware-Detector`
Observed Windows test path: `C:\Users\suret\AI-Ransomware-Test`

## Evidence-backed project areas
- Windows ETW telemetry, especially Microsoft-Windows-Kernel-File and Kernel-Process.
- FileKey/FileObject correlation and file-operation normalization.
- File transformation evidence.
- Process-centred Behavioral Threat Fingerprint (BTF).
- MLRan feature mapping and XGBoost importance enrichment.

## Run
Python 3.10+:
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py -m pytest
```
ETW collection is Windows-specific and typically requires an elevated terminal.

## Critical limitation
The full original repository, full MLRan data, complete 338-row XGBoost importance output, trained models, full ETW collector and all original tests were not present in the chat excerpts. See `RECOVERY_MANIFEST.json`. Do not present this as a complete original recovery.
