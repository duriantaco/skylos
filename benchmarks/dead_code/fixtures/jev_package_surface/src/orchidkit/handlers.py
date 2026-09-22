"""Profile processors resolved through the installed command's JSON config."""

from orchidkit.transforms import normalize_amber, normalize_cobalt


def handle_amber(value):
    return normalize_amber(value).upper()


def handle_birch(value):
    return value.strip().title()


def handle_cobalt(value):
    return normalize_cobalt(value).swapcase()


def handle_drift(value):
    return value.replace(" ", "-")
