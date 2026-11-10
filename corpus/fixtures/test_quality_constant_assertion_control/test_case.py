def total(items):
    return sum(items)


def test_receipt_total():
    assert total([2, 2]) == 4
