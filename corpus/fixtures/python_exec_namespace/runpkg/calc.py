import bisect


def evaluate(text):
    return eval(text, {"__builtins__": {}})
