def test_opted_out():
    assert True


test_opted_out.__dict__["__test__"] = False


def test_removed():
    assert True


globals().pop("test_removed")
