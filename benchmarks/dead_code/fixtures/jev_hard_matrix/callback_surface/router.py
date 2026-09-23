import callbacks


CALLBACKS = {
    "agate": callbacks.paint_agate,
    "caper": callbacks.paint_caper,
    "ecru": callbacks.paint_ecru,
    "gold": callbacks.paint_gold,
    "ivory": callbacks.paint_ivory,
    "khaki": callbacks.paint_khaki,
}

STEPS = ("agate", "caper", "ecru", "gold", "ivory", "khaki")


def render():
    return [CALLBACKS[name]() for name in STEPS]
