import sys
sys.path.append('../..')

from module1 import used_function
from module2 import wrapper
import module4

def module11_unused():
    """Never used anywhere"""
    return "module11 unused"

def module11_used_by_module12():
    """Used by module12"""
    return used_function()

def module11_another_unused():
    """Another unused function in deep module"""
    return "another unused in 11"

class Module11Class:
    def __init__(self):
        self.data = wrapper()
    
    def used_method(self):
        """Used by module12"""
        return self.data
    
    def unused_method(self):
        """Never used"""
        return "unused method in module11"
    
    def deeply_unused_method(self):
        """Another unused method"""
        return "deeply unused"

used_function()
wrapper()
obj = module4.Module4Class()
obj.used_by_module6()

m11 = Module11Class()
m11.used_method()