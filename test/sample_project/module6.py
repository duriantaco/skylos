## module6.py
from module4 import Module4Class
from module5 import used_by_module6, decorated_and_used

class Module6Class:
    def __init__(self):
        self.m4 = Module4Class()
    
    @property
    def used_property(self):
        """Used property"""
        return self.m4.used_by_module6()
    
    @property
    def unused_property(self):
        """Never accessed"""
        return "unused property"
    
    def method_used_indirectly(self):
        """Called through variable"""
        return used_by_module6()
    
    def completely_unused_method(self):
        """Never called"""
        return "totally unused"
    
    @staticmethod
    def static_unused():
        """Static method never called"""
        return "static unused"
    
    @classmethod
    def class_method_unused(cls):
        """Class method never called"""
        return "class method unused"

obj = Module6Class()
print(obj.used_property)

method_ref = obj.method_used_indirectly
method_ref()

used_by_module6()
decorated_and_used()