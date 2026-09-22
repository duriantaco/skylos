"""Text transformations shared by the command and its test suite."""


def normalize_cobalt(value):
    return value.lstrip()


def normalize_amber(value):
    return value.strip()


def normalize_drift(value):
    return value.rstrip()


def normalize_birch(value):
    return value.casefold().strip()
