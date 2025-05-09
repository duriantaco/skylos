from module1 import func1_used_by_module3
from module2 import func2_used
import module4

def func3_used():
    return func2_used()

def func3_unused():
    '''Never used'''
    return "unused"

class Module3Class:
    def __init__(self):
        self.data = func1_used_by_module3()
    
    def used_method(self):
        '''Used by module6'''
        return self.data
    
    def unused_method(self):
        '''Never used'''
        return "unused"

func1_used_by_module3()
module4.func4_used()