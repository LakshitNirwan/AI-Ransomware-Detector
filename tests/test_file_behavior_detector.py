from alerts.file_behavior_detector import FileBehaviorDetector
from features.transformation.schema import FileEvent, FileOperation


def test_benign_single_file_activity_does_not_trigger_rule():
    events = [
        FileEvent(123, "1", FileOperation.WRITE, r"C:\Temp\sample.txt"),
        FileEvent(123, "2", FileOperation.RENAME, r"C:\Temp\sample.txt",
                  related_path=r"C:\Temp\sample.renamed.txt"),
    ]
    result = FileBehaviorDetector().evaluate(123, {}, events)

    assert result["status"] == "no_rule_triggered"
    assert result["response"] is None


def test_multiple_file_changes_create_explainable_simulated_alert():
    events = []
    for index in range(10):
        path = rf"C:\Temp\doc{index}.txt"
        events.append(FileEvent(123, f"{index}-w", FileOperation.WRITE, path))
    for index in range(5):
        path = rf"C:\Temp\doc{index}.txt"
        events.append(FileEvent(123, f"{index}-r", FileOperation.RENAME, path,
                                related_path=rf"C:\Temp\doc{index}.locked"))

    result = FileBehaviorDetector().evaluate(123, {}, events)

    assert result["status"] == "review_recommended"
    assert result["alert_type"] == "rapid_file_change_activity"
    assert "10 distinct files" in result["reason"]
    assert len(result["evidence"]["affected_paths"]) == 15
    assert r"C:\Temp\doc0.locked" in result["evidence"]["affected_paths"]
    assert result["response"]["mode"] == "simulation_only"
    assert result["response"]["executed"] is False
