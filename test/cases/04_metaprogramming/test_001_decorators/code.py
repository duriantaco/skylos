"""
Metaprogramming test - decorator patterns.

This case tests detection of functions and methods with decorators,
and the ability to track usage through decorators.
"""

def decorator(func):
    """Simple decorator that wraps a function."""
    def wrapper(*args, **kwargs):
        print(f"Calling {func.__name__}")
        return func(*args, **kwargs)
    return wrapper

def unused_decorator(func):
    """Decorator that is defined but never used."""
    def wrapper(*args, **kwargs):
        print(f"This decorator is never used")
        return func(*args, **kwargs)
    return wrapper

@decorator
def decorated_function():
    """Function with a decorator."""
    return "I am decorated"

def undecorated_function():
    """Regular function without decorator."""
    return "I am not decorated"

@decorator
def decorated_but_unused():
    """Function with decorator but never called."""
    return "I am decorated but unused"

class DecoratedClass:
    """Class with decorated methods."""
    
    @decorator
    def decorated_method(self):
        """Method with a decorator."""
        return "Decorated method"
    
    @decorator
    def unused_decorated_method(self):
        """Method with decorator but never called."""
        return "Decorated but unused method"
    
    def regular_method(self):
        """Regular method without decorator."""
        return "Regular method"

# Call functions and methods
decorated_function()
undecorated_function()

obj = DecoratedClass()
obj.decorated_method()
obj.regular_method()