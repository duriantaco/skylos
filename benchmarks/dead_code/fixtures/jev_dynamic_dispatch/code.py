import sys


def handler_a():
    return 1


def handler_b():
    return 2


def handler_c():
    return 3


def handler_d():
    return 4


module = sys.modules[__name__]
first = "handler_a"
getattr(module, first)()
second = "handler_b"
globals()[second]()
handler_d()
