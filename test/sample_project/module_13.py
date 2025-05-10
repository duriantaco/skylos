import os 
import sys
import json

def test_function():
    pass

def used_function():
    test = sys.modules[__name__]
    test.test_function = test_function
    return "I'm used!"

def unused_function():
    """This function is never called."""
    return "I'm unused!"