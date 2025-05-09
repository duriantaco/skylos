## module4.py
from module1 import used_function
from module2 import wrapper

def deeply_unused():
    """Never called anywhere"""
    return "I'm deeply unused"

def used_in_module5():
    """Called by module5"""
    return used_function()

def unused_despite_import():
    """Module5 imports this but never calls it"""
    return "imported but not called"

class Module4Class:
    def __init__(self):
        self.value = 42
    
    def used_by_module6(self):
        """Used by module6"""
        return self.value
    
    def totally_unused_method(self):
        """Never called"""
        return "unused method"
    
    def chained_method1(self):
        """Used in chain"""
        return self
    
    def chained_method2(self):
        """Used in chain"""
        return self
    
    def unused_chain_method(self):
        """Never used in chain"""
        return self
    
    def final_chain(self):
        """End of chain"""
        return "done"

result = Module4Class().chained_method1().chained_method2().final_chain()