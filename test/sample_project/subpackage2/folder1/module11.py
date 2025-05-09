## sample_project/subpackage2/folder1/module11.py
def super_nested_unused():
    """Super deeply nested and unused"""
    return "super nested unused"

def super_nested_used():
    """Used somewhere"""
    return "super nested used"

class DeepNestedClass:
    def unused_deep_method(self):
        """Unused method in deep nested class"""
        return "unused deep"
    
    def used_deep_method(self):
        """Used by module9"""
        return "used deep"