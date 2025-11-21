def exported_function():
    """This function is exported through the package __init__.py"""
    return "Exported function result"


def internal_function():
    """This function is used internally but not exported."""
    return "Internal function result"


def unused_function():
    """This function is never used or exported."""
    return "Unused function result"


result = internal_function()
