from orchidkit.transforms import normalize_drift


def test_normalize_drift():
    assert normalize_drift("Cedar  ") == "Cedar"
