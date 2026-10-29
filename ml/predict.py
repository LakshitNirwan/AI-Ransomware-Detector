import math

import pandas as pd


class FusedPredictor:
    def __init__(self, model, feature_names):
        if not feature_names or len(feature_names) != len(set(feature_names)):
            raise ValueError("feature_names must be a non-empty unique list")
        self.model = model
        self.feature_names = tuple(feature_names)

    def ransomware_probability(self, feature_vector: dict[str, int]) -> float:
        missing = [name for name in self.feature_names if name not in feature_vector]
        if missing:
            raise ValueError(f"Feature vector is missing model inputs: {missing}")
        values = [feature_vector[name] for name in self.feature_names]
        if any(isinstance(value, bool) or not isinstance(value, (int, float))
               or not math.isfinite(value) for value in values):
            raise ValueError("Model inputs must be finite numeric values")

        frame = pd.DataFrame([values], columns=self.feature_names)
        probabilities = self.model.predict_proba(frame)
        classes = list(getattr(self.model, "classes_", (0, 1)))
        if 1 not in classes:
            raise ValueError("Loaded model has no ransomware class (label 1)")
        probability = float(probabilities[0][classes.index(1)])
        if not math.isfinite(probability) or not 0 <= probability <= 1:
            raise ValueError("Model returned an invalid ransomware probability")
        return probability
