## sample_project/subpackage2/folder2/folder1/module10.py
from ....module1 import used_function
from ....module2 import wrapper

from ...folder1.module11 import Module11Class
from ...folder1.module12 import module12_used_by_folder2

try:
    import module4
except ImportError:
    import sys
    sys.path.append('../../../..')
    import module4

def module10_deeply_unused():
    """Never used - deep nested unused function"""
    return "deeply unused in module10"

def module10_used_by_sibling():
    """Used by module15 in same folder"""
    return "used by sibling"

def module10_another_unused():
    """Another unused function in deep location"""
    return "another unused"

class Module10Class:
    def __init__(self):
        self.data = used_function()
        self.wrapper_result = wrapper()
        self.m11 = Module11Class()
    
    def used_method(self):
        """Used by module15"""
        return self.data + self.wrapper_result
    
    def unused_method(self):
        """Never used"""
        return "unused method in deep module10"
    
    def deeply_nested_unused(self):
        """Very deeply nested unused method"""
        return "deeply nested unused"
    
    def cross_branch_method(self):
        """Uses cross-branch imports - used by test"""
        return self.m11.used_method()

used_function()
wrapper()
module12_used_by_folder2()

obj4 = module4.Module4Class()
obj4.used_by_module6()