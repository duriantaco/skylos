def directly_called():
    """This function is called directly and should not be reported as dead."""
    return "Called directly"

def called_via_getattr():
    """This function is called via getattr and might be reported as dead by static analysis."""
    return "Called via getattr"

def called_via_globals():
    """This function is called via globals() and might be reported as dead by static analysis."""
    return "Called via globals"

def truly_unused():
    """This function is never called and should be reported as dead."""
    return "Never called"

print(directly_called())

import sys
current_module = sys.modules[__name__]

func_name = "called_via_getattr"
dynamic_func = getattr(current_module, func_name)
print(dynamic_func())

func_name = "called_via_globals"
func = globals()[func_name]
print(func())

attr_name = "called_via_getattr"
print(getattr(current_module, attr_name)())