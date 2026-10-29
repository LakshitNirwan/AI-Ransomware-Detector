from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class RansomwareAlert:
    pid: int
    probability: float
    threshold: float
    model_feature_count: int
    alert_type: str = "ransomware_risk"
    response_mode: str = "simulation_only"

    def to_dict(self):
        return asdict(self)


class AlertEngine:
    """Create a review alert at an explicitly configured probability threshold."""

    def __init__(self, threshold: float):
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
            raise TypeError("threshold must be numeric")
        if not 0 < threshold < 1:
            raise ValueError("threshold must be between 0 and 1")
        self.threshold = float(threshold)

    def evaluate(self, pid: int, probability: float, model_feature_count: int):
        if pid <= 0:
            raise ValueError("PID must be positive")
        if not 0 <= probability <= 1:
            raise ValueError("probability must be between 0 and 1")
        if probability < self.threshold:
            return None
        return RansomwareAlert(
            pid=pid,
            probability=float(probability),
            threshold=self.threshold,
            model_feature_count=model_feature_count,
        )


class SafeResponseSimulator:
    """Describe a simulated response without controlling processes or files."""

    def respond(self, alert: RansomwareAlert | None):
        if alert is None:
            return None
        return {
            "mode": "simulation_only",
            "action": "would_request_isolation_review",
            "executed": False,
            "pid": alert.pid,
            "reason": "Alert threshold reached; no system changes were made.",
        }
