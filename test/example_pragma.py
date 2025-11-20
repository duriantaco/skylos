"""Example module to demonstrate pragma support"""

def used_function():
    """This function is used"""
    return 42

def unused_with_pragma():  # pragma: no skylos
    """This function has pragma, so it should be IGNORED"""
    return "ignored by pragma"

class UnusedClassWithPragma:  # pragma: no skylos
    """This class has pragma, so it should be IGNORED"""
    def method(self):
        pass

def really_unused_no_pragma():
    """This function is unused AND has NO pragma - should be REPORTED"""
    return "should be reported as unused"

# Actually call the used function
if __name__ == "__main__":
    result = used_function()
    print(f"Result: {result}")
