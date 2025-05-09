## module8.py
from subpackage.module7 import used_by_module8, SubpackageClass

def completely_isolated_unused():
    """Never imported or called"""
    return "completely isolated"

def another_unused_function():
    """Never called"""
    return "another unused"

def main():
    """Main function"""
    result = used_by_module8()
    obj = SubpackageClass()
    obj.used_method()
    return result

def unused_in_main_module():
    """Not called even in main module"""
    return "unused in main"

if __name__ == "__main__":
    main()