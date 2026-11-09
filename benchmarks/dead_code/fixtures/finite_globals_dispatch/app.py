def scale_a(value):
    return value * 2


def scale_b(value):
    return value * 3


def transform(value, name):
    selected = globals()[name]
    return selected(value)


print(transform(2, "scale_a"))
