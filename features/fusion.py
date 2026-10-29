from collections.abc import Mapping

from features.btf.schema import BTFVector
from features.transformation.window_features import (
    ETW_TRANSFORMATION_FEATURES,
    extract_etw_transformation_features,
)


BTF_FEATURE_NAMES = tuple(BTFVector().to_flat_dict())
FUSED_FEATURE_NAMES = ETW_TRANSFORMATION_FEATURES + BTF_FEATURE_NAMES

if len(FUSED_FEATURE_NAMES) != len(set(FUSED_FEATURE_NAMES)):
    raise RuntimeError("ETW and BTF feature names must be unique")


def build_fused_feature_vector(etw_features: Mapping[str, int], btf_vector: BTFVector) -> dict[str, int]:
    """Return the ordered ETW-then-BTF model vector after strict schema checks."""
    if not isinstance(btf_vector, BTFVector):
        raise TypeError("btf_vector must be a BTFVector")

    if set(etw_features) != set(ETW_TRANSFORMATION_FEATURES):
        missing = sorted(set(ETW_TRANSFORMATION_FEATURES) - set(etw_features))
        extra = sorted(set(etw_features) - set(ETW_TRANSFORMATION_FEATURES))
        raise ValueError(f"ETW feature schema mismatch; missing={missing}, extra={extra}")

    btf_features = btf_vector.to_flat_dict()
    if tuple(btf_features) != BTF_FEATURE_NAMES:
        raise ValueError("BTF feature order does not match the canonical schema")

    vector = {}
    for name in ETW_TRANSFORMATION_FEATURES:
        value = etw_features[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"ETW feature {name!r} must be a non-negative integer")
        vector[name] = value
    vector.update(btf_features)

    if tuple(vector) != FUSED_FEATURE_NAMES:
        raise RuntimeError("Fused feature order does not match its schema")
    return vector


def build_fused_feature_vector_from_events(events, btf_vector: BTFVector) -> dict[str, int]:
    """Extract the ETW block from a single-window event iterable and fuse it."""
    return build_fused_feature_vector(
        extract_etw_transformation_features(events),
        btf_vector,
    )
