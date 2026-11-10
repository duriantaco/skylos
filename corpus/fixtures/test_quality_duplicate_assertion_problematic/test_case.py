def payload():
    return (1, 2, 3)


def test_payload_size():
    actual = len(payload())
    assert actual == 3
    assert actual == 3
