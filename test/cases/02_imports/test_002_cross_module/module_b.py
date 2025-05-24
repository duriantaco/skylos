from module_a import (
    exported_used_function,      # used
    exported_unused_function,    # no use
    ExportedUsedClass,           # init
    ExportedUnusedClass,         # no init
)

def function_using_imports():
    """Function that uses imports from module_a."""
    result = exported_used_function()
    
    obj = ExportedUsedClass()
    class_result = obj.used_method()
    
    return f"{result} and {class_result}"

output = function_using_imports()
print(f"Output: {output}")