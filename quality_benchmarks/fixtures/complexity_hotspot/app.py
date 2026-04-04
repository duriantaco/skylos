def branchy_handler(flag_a, flag_b, flag_c):
    if flag_a:
        if flag_b:
            return 1
        return 2
    if flag_c:
        return 3
    return 4


def simple_handler():
    return 1
