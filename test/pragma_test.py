def used_function():
    """This is used"""
    return 42

def unused_with_pragma():  # pragma: no skylos
    """This function should be ignored"""
    return "ignored"

class UnusedClassWithPragma:  # pragma: no skylos
    """This class should be ignored"""
    pass

def really_unused_no_pragma():
    """This should be reported as unused - NO pragma"""
    pass

# Actually use the first function
result = used_function()
print(result)
