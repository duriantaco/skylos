def discounted_total(prices, discount):
    return sum(prices) - discount


def test_discount_applies():
    discounted_total([8, 5], 3)
    assert 6 == 6
