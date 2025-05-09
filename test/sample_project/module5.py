## module5.py
from module4 import used_in_module5, unused_despite_import
import module4

def unused_function():
    """Never called anywhere"""
    return "unused in module5"

def used_by_module6():
    """Called by module6"""
    return used_in_module5()

def decorator_unused(func):
    """Never used as decorator"""
    return func

def decorator_used(func):
    """Used as decorator"""
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper

@decorator_used
def decorated_but_unused():
    """Decorated but never called"""
    return "decorated but unused"

@decorator_used
def decorated_and_used():
    """Decorated and called"""
    return "decorated and used"

def undecorated_unused():
    """Not decorated, not called"""
    return "completely unused"

decorated_and_used()
used_in_module5()