def used_function():
    """This function is called and should not be reported as dead code."""
    return "I am used"


def unused_function():
    """This function is never called and should be reported as dead code."""
    return "I am never used"


def another_used_function():
    """This function is called and should not be reported as dead code."""
    used_function()
    return "I am also used"


another_used_function()
