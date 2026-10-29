import pandas as pd
import pytest

from ml.train_fused import _drop_exact_training_duplicates


def test_drops_only_exact_duplicates_found_in_training_rows():
    train = pd.DataFrame({"keep": [1, 2, 3], "duplicate": [1, 2, 3], "other": [3, 2, 1]})
    test = pd.DataFrame({"keep": [4, 5], "duplicate": [4, 5], "other": [5, 4]})

    kept, dropped = _drop_exact_training_duplicates(
        train, test, ["keep", "duplicate", "other"]
    )

    assert kept == ["keep", "other"]
    assert dropped == {"duplicate": "keep"}


def test_duplicate_relationship_must_hold_in_test_split():
    train = pd.DataFrame({"keep": [1, 2], "duplicate": [1, 2]})
    test = pd.DataFrame({"keep": [4, 5], "duplicate": [4, 6]})

    with pytest.raises(ValueError, match="differ in test"):
        _drop_exact_training_duplicates(train, test, ["keep", "duplicate"])
