from alerts.alert_engine import AlertEngine, SafeResponseSimulator
from backend.app.services.prediction_service import FusedPredictionService
from features.transformation.schema import FileEvent, FileOperation


class _FixedModel:
    classes_ = [0, 1]

    def predict_proba(self, frame):
        assert len(frame) == 1
        return [[0.08, 0.92]]


def test_prediction_alert_and_response_are_simulation_only():
    service = FusedPredictionService(
        predictor=__import__("ml.predict", fromlist=["FusedPredictor"]).FusedPredictor(
            _FixedModel(), ["unique_files_written"]
        ),
        threshold=0.8,
    )
    result = service.process_window(
        321,
        [FileEvent(321, "1", FileOperation.WRITE, r"C:\\data\\sample.txt")],
    )

    assert result["probability_ransomware"] == 0.92
    assert result["predicted_label"] == 1
    assert result["candidate_feature_count"] == 49
    assert result["model_feature_count"] == 1
    assert result["alert"]["alert_type"] == "ransomware_risk"
    assert result["alert"]["evidence"] == result["evidence"]
    assert result["evidence"]["status"] == "file_events_received"
    assert result["evidence"]["observed_file_events"] == [
        {
            "timestamp": "1",
            "operation": "write",
            "path": r"C:\\data\\sample.txt",
            "related_path": None,
            "size_bytes": None,
        }
    ]
    assert "do not establish" in result["evidence"]["interpretation"]
    assert result["simulated_response"]["mode"] == "simulation_only"
    assert result["simulated_response"]["executed"] is False


def test_alert_engine_emits_nothing_below_threshold():
    assert AlertEngine(0.8).evaluate(321, 0.5, 1) is None


def test_safe_simulator_does_not_act_without_an_alert():
    assert SafeResponseSimulator().respond(None) is None
