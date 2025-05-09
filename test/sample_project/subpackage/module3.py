## sample_project/subpackage/module3.py
from module1 import used_function

class TestClass:
    def __init__(self):
        """Magic method that should be considered as used even if not explicitly called."""
        self.data = "test"
    
    def __str__(self):
        """Another magic method that should be considered used."""
        return self.data
    
    def used_method(self):
        """This method is called directly."""
        return "Used method"
    
    def unused_method(self):
        """This method is never called."""
        return "Unused method"
    
    def indirect_method(self):
        """This method is called through a variable."""
        return "Called indirectly"

def decorator(func):
    """A simple decorator."""
    def wrapper(*args, **kwargs):
        print("Calling decorated function")
        return func(*args, **kwargs)
    return wrapper

@decorator
def decorated_function():
    """This function is used through its decorator."""
    return "I'm decorated"

def not_decorated():
    """This function is not used anywhere."""
    return "I'm not decorated or used"

def called_in_main():
    """This function is called in the main block."""
    return "Called in main"

obj = TestClass()
print(obj.used_method())

method = obj.indirect_method
print(method())

print(decorated_function())

if __name__ == "__main__":
    called_in_main()