def exported_used_function():
    """This function is exported and used by another module."""
    return "I am used by another module"

def exported_unused_function():
    """This function is exported but never used by the importing module."""
    return "I am exported but unused"

def internal_used_function():
    """This function is used internally but not exported."""
    return "I am used internally"

def internal_unused_function():
    """This function is neither used internally nor exported."""
    return "I am completely unused"

class ExportedUsedClass:
    """This class is exported and instantiated by another module."""
    def __init__(self):
        self.value = "I am instantiated elsewhere"
    
    def used_method(self):
        """This method is called by the importing module."""
        return self.value
    
    def unused_method(self):
        """This method is never called by the importing module."""
        return f"Unused: {self.value}"

class ExportedUnusedClass:
    """This class is exported but never instantiated."""
    def __init__(self):
        self.value = "I am never instantiated"
    
    def method(self):
        """This method is never called."""
        return self.value

class InternalClass:
    """This class is not exported and only used internally."""
    def __init__(self):
        self.value = "Internal use only"
    
    def method(self):
        """This method is called internally."""
        return self.value

result = internal_used_function()
internal_obj = InternalClass()
internal_result = internal_obj.method()