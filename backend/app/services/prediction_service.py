from features.btf.file_event_adapter import FileEventBTFAdapter
from features.btf.schema import BTFVector
from features.fusion import build_fused_feature_vector_from_events
from features.transformation.schema import FileEvent
from alerts.alert_engine import AlertEngine, SafeResponseSimulator
from ml.model_loader import load_fused_model
from ml.predict import FusedPredictor


class FusedPredictionService:
    """Score one caller-bounded process window; telemetry collection is external."""

    def __init__(self, predictor: FusedPredictor, threshold: float):
        self.predictor = predictor
        self.alert_engine = AlertEngine(threshold)
        self.response_simulator = SafeResponseSimulator()

    @classmethod
    def from_artifacts(cls, threshold: float, model_path=None, feature_names_path=None):
        kwargs = {}
        if model_path is not None:
            kwargs["model_path"] = model_path
        if feature_names_path is not None:
            kwargs["feature_names_path"] = feature_names_path
        model, feature_names = load_fused_model(**kwargs)
        return cls(FusedPredictor(model, feature_names), threshold)

    def process_window(self, pid: int, events) -> dict:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("PID must be a positive integer")
        batch = tuple(events)
        adapter = FileEventBTFAdapter(pid)
        adapter.add_many(batch)
        btf_vector: BTFVector = adapter.to_vector()
        vector = build_fused_feature_vector_from_events(batch, btf_vector)
        probability = self.predictor.ransomware_probability(vector)
        active_model_signals = [
            {"feature": name, "value": vector[name]}
            for name in self.predictor.feature_names
            if vector[name] > 0
        ]
        observed_file_events = [
            {
                "timestamp": event.timestamp,
                "operation": event.operation.value,
                "path": event.path,
                "related_path": event.related_path,
                "size_bytes": event.size,
            }
            for event in batch
        ]
        evidence = {
            "status": "file_events_received" if observed_file_events else "no_file_events_received",
            "model_signals": active_model_signals,
            "observed_file_events": observed_file_events,
            "interpretation": (
                "Model inputs and file operations from this process window are supporting evidence; "
                "they do not establish that any one operation caused ransomware."
            ),
        }

        alert = self.alert_engine.evaluate(
            pid, probability, len(self.predictor.feature_names)
        )
        alert_payload = alert.to_dict() if alert else None
        if alert_payload is not None:
            alert_payload["evidence"] = evidence
        simulated_response = self.response_simulator.respond(alert)
        return {
            "pid": pid,
            "probability_ransomware": probability,
            "predicted_label": int(probability >= self.alert_engine.threshold),
            "candidate_feature_count": len(vector),
            "model_feature_count": len(self.predictor.feature_names),
            "alert": alert_payload,
            "evidence": evidence,
            "simulated_response": simulated_response,
        }
