def payload():
    return (1, 2, 3)


def test_payload_size():
    items = payload()
    actual = len(items)
    assert actual == 3
    assert items[0] == 1
