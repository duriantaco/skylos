## sample_project/subpackage2/folder1/module12.py
from .module11 import module11_used_by_module12, Module11Class
from ...module1 import used_function
from ...module2 import wrapper

def module12_unused():
    """Unused in module12"""
    return "unused in 12"

def module12_used_by_folder2():
    """Used by another nested module"""
    return module11_used_by_module12()

def module12_another_unused():
    """Another unused function"""
    return "another unused"

class Module12Class:
    def __init__(self):
        self.m11 = Module11Class()
    
    def used_method(self):
        """Used somewhere else"""
        return self.m11.used_method()
    
    def unused_method(self):
        """Never used"""
        return "unused in module12"

module11_used_by_module12()
used_function()
wrapper()

obj = Module11Class()
obj.used_method()