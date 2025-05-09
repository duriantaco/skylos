from . import module3

def unused_in_init():
    """This function is defined in __init__.py but never called."""
    return "I'm unused in __init__"