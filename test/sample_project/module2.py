# module2.py
from module1 import used_function

def another_unused():
    """This function is also never called."""
    return "I'm also unused!"

def wrapper():
    """This function calls used_function from module1."""
    return used_function()

print(wrapper())