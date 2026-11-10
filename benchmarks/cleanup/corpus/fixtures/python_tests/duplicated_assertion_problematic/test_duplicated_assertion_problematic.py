def shipping_label(city, postal_code):
    return f"{city.upper()} {postal_code}"


def test_shipping_label():
    label = shipping_label("Riga", "1050")
    assert label == "RIGA 1050"
    assert label == "RIGA 1050"
