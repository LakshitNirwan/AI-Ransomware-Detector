import json
from pathlib import Path

from joblib import load

from features.fusion import FUSED_FEATURE_NAMES

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = ROOT / "results" / "fused" / "xgboost_fused.joblib"
DEFAULT_FEATURES = ROOT / "results" / "fused" / "feature_names.json"


def load_fused_model(model_path: str | Path = DEFAULT_MODEL,
                     feature_names_path: str | Path = DEFAULT_FEATURES):
    model_path = Path(model_path)
    feature_names_path = Path(feature_names_path)
    if not model_path.is_file() or not feature_names_path.is_file():
        raise FileNotFoundError(
            "A validated fused model artifact is unavailable. Train only after paired "
            "ETW+BTF ransomware-labeled splits and their manifest are provided."
        )
    names = json.loads(feature_names_path.read_text(encoding="utf-8"))
    if not isinstance(names, list) or not names or len(names) != len(set(names)):
        raise ValueError("Saved feature_names.json must be a non-empty unique list")
    if not set(names).issubset(FUSED_FEATURE_NAMES):
        raise ValueError("Saved model feature names are outside the current fused schema")
    canonical_order = [name for name in FUSED_FEATURE_NAMES if name in set(names)]
    if names != canonical_order:
        raise ValueError("Saved model feature order does not match ETW-then-BTF schema order")
    return load(model_path), names
