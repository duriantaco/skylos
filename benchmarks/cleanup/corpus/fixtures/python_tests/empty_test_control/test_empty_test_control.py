def normalize_tag(value):
    return value.strip().lower()


def test_normalize_tag():
    assert normalize_tag("  Release  ") == "release"
