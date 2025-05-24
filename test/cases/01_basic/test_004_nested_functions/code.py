def outer_function():
    """This function is called and contains nested functions."""
    
    def used_inner():
        """This nested function is called and should not be reported as dead."""
        return "Used inner function"
    
    def unused_inner():
        """This nested function is never called and should be reported as dead."""
        return "Unused inner function"
    
    result = used_inner()
    return result

def outer_with_return():
    """This function returns a nested function."""
    
    def inner_returned():
        """This function is returned and potentially used elsewhere."""
        return "Inner function that gets returned"
    
    def unused_inner():
        """This nested function is never called or returned."""
        return "Never used"
    
    return inner_returned

print(outer_function())

func = outer_with_return()
print(func())