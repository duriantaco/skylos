## sample_project/subpackage/module7.py
import sys
from ..module6 import Module6Class
from . import module3

def unused_in_subpackage():
    """Never called"""
    return "unused in subpackage"

def used_by_module8():
    """Called by module8"""
    obj = Module6Class()
    return obj.used_property

class SubpackageClass:
    def __init__(self):
        self.test_class = module3.TestClass()
    
    def unused_method(self):
        """Never called"""
        return "unused subpackage method"
    
    def used_method(self):
        """Used in module8"""
        return self.test_class.used_method()

def parse_args():
    """Used in main block"""
    return sys.argv[1:] if len(sys.argv) > 1 else []

def helper_unused():
    """Not used in main block"""
    return "helper unused"

def helper_used():
    """Used in main block"""
    return "helper used"

if __name__ == "__main__":
    args = parse_args()
    helper_used()
