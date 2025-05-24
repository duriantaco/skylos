#!/usr/bin/env python3

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, '/Users/oha/skylos')

from skylos.analyzer import analyze, Skylos

class SkylosTest:
    def __init__(self):
        self.test_dir = None
        self.tests_passed = 0
        self.tests_failed = 0
        
    def setup_test_directory(self):
        """Create a temporary directory with test Python files"""
        self.test_dir = tempfile.mkdtemp(prefix="skylos_test_")
        print(f"Creating test directory: {self.test_dir}")
        
        self.create_test_files()
        
    def create_test_files(self):
        """Create various test Python files"""
        
        test1_content = '''
import os
import sys  # unused import
import json
from pathlib import Path  # unused import
from collections import defaultdict

def used_function():
    """This function is used"""
    return "used"

def unused_function():
    """This function is not used"""
    return "unused"

def another_used_function():
    """Another used function"""
    result = used_function()
    data = defaultdict(list)
    return json.dumps({"result": result})

class UsedClass:
    """This class is used"""
    def __init__(self):
        self.value = "used"
        
    def method(self):
        return self.value

class UnusedClass:
    """This class is not used"""
    def __init__(self):
        self.value = "unused"

# Usage
instance = UsedClass()
result = another_used_function()
'''
        
        test2_content = '''
import unittest

class TestClass(unittest.TestCase):
    """Test class - test methods should be ignored"""
    
    def test_something(self):
        """Test method - should be ignored"""
        pass
        
    def test_another_thing(self):
        """Another test method - should be ignored"""
        pass
        
    def helper_method(self):
        """Non-test method in test class"""
        pass

class RegularClass:
    """Regular class with magic methods"""
    
    def __init__(self, value):
        self.value = value
        
    def __str__(self):
        """Magic method - should be ignored"""
        return str(self.value)
        
    def __eq__(self, other):
        """Magic method - should be ignored"""
        return self.value == other.value
        
    def regular_method(self):
        """Regular method"""
        return self.value * 2
        
    def unused_method(self):
        """Unused regular method"""
        return "unused"

# Only create instance, don't call regular_method
obj = RegularClass(42)
print(obj)  # This calls __str__
'''
        
        pkg_dir = Path(self.test_dir) / "testpkg"
        pkg_dir.mkdir()
        
        init_content = '''
"""Test package init file"""
from .module1 import exported_function
from .module2 import ExportedClass

def init_function():
    """Function in __init__.py - should be considered exported"""
    return "from init"

def _private_init_function():
    """Private function in __init__.py"""
    return "private"
'''
        
        module1_content = '''
"""Module 1 in test package"""

def exported_function():
    """This function is exported via __init__.py"""
    return "exported"

def non_exported_function():
    """This function is not exported"""
    return "not exported"

def _private_function():
    """Private function"""
    return "private"
'''
        
        module2_content = '''
"""Module 2 in test package"""

class ExportedClass:
    """This class is exported via __init__.py"""
    
    def __init__(self):
        self.value = "exported"
        
    def method(self):
        return self.value

class NonExportedClass:
    """This class is not exported but is used internally"""
    
    def __init__(self):
        self.value = "not exported"

class TrulyUnusedClass:
    """This class is truly unused"""
    
    def __init__(self):
        self.value = "unused"

def utility_function():
    """Utility function used internally"""
    return "utility"

# Internal usage
_internal = NonExportedClass()
result = utility_function()
'''
        
        test3_content = '''
"""Complex scenarios test file"""
import importlib

# Dynamic import - makes analysis uncertain
module_name = "json"
json_module = importlib.import_module(module_name)

def function_with_dynamic_usage():
    """Function that might be called dynamically"""
    return "dynamic"

def definitely_unused():
    """Definitely unused function"""
    return "unused"

class BaseClass:
    """Base class"""
    
    def base_method(self):
        return "base"

class DerivedClass(BaseClass):
    """Derived class"""
    
    def __init__(self):
        super().__init__()
        
    def derived_method(self):
        return "derived"
        
    def unused_derived_method(self):
        return "unused derived"

# Create instance but only use inherited method
derived = DerivedClass()
result = derived.base_method()

# Simulate dynamic function call without using sys
func_name = "function_with_dynamic_usage"
if hasattr(globals(), func_name):
    globals()[func_name]()
'''
        
        with open(Path(self.test_dir) / "test1.py", "w") as f:
            f.write(test1_content)
            
        with open(Path(self.test_dir) / "test2.py", "w") as f:
            f.write(test2_content)
            
        with open(pkg_dir / "__init__.py", "w") as f:
            f.write(init_content)
            
        with open(pkg_dir / "module1.py", "w") as f:
            f.write(module1_content)
            
        with open(pkg_dir / "module2.py", "w") as f:
            f.write(module2_content)
            
        with open(Path(self.test_dir) / "test3.py", "w") as f:
            f.write(test3_content)
    
    def run_analyzer(self, confidence_threshold=60):
        """Run the Skylos analyzer on the test directory"""
        print(f"\nRunning Skylos analyzer with confidence threshold: {confidence_threshold}")
        try:
            result = analyze(self.test_dir, confidence_threshold)
            return json.loads(result)
        except AttributeError as e:
            if "_get_base_classes" in str(e):
                print("\n⚠️  ERROR: Missing _get_base_classes method in Skylos class")
                print("This is a bug in the analyzer code. Please add the following method to the Skylos class:")
                print("""
    def _get_base_classes(self, class_name):
        \"\"\"Get base classes for a given class name\"\"\"
        if class_name not in self.defs:
            return []
        
        class_def = self.defs[class_name]
        
        # If the class definition has base class information, return it
        if hasattr(class_def, 'base_classes'):
            return class_def.base_classes
        
        # For now, return empty list as simplified implementation
        return []
                """)
                print("\nAlternatively, you can comment out the test method detection in _apply_heuristics")
                raise
            else:
                raise
    
    def assert_contains(self, items, name_pattern, description):
        """Helper to check if a pattern exists in the results"""
        found = any(item.get('name', '') == name_pattern for item in items)
        if found:
            print(f"✓ PASS: {description}")
            self.tests_passed += 1
        else:
            print(f"✗ FAIL: {description}")
            print(f"   Expected to find item with exact name '{name_pattern}' in:")
            for item in items:
                print(f"     - {item.get('name', 'unnamed')}")
            self.tests_failed += 1
        return found
    
    def assert_not_contains(self, items, name_pattern, description):
        """Helper to check if a pattern does NOT exist in the results"""
        found = any(item.get('name', '') == name_pattern for item in items)
        if not found:
            print(f"✓ PASS: {description}")
            self.tests_passed += 1
        else:
            print(f"✗ FAIL: {description}")
            print(f"   Expected NOT to find item with exact name '{name_pattern}' but found:")
            for item in items:
                if item.get('name', '') == name_pattern:
                    print(f"     - {item.get('name', 'unnamed')}")
            self.tests_failed += 1
        return not found
    
    def test_basic_unused_detection(self, results):
        """Test basic unused function/class/import detection"""
        print("\n=== Testing Basic Unused Detection ===")
        
        unused_functions = results.get('unused_functions', [])
        unused_imports = results.get('unused_imports', [])
        unused_classes = results.get('unused_classes', [])
        
        self.assert_contains(unused_functions, 'unused_function', 
                           "Detects unused function")
        self.assert_contains(unused_classes, 'UnusedClass', 
                           "Detects unused class")
        self.assert_contains(unused_imports, 'sys', 
                           "Detects unused import (sys)")
        self.assert_contains(unused_imports, 'Path', 
                           "Detects unused import (pathlib.Path)")
        
        self.assert_not_contains(unused_functions, 'used_function', 
                               "Does not flag used function")
        self.assert_not_contains(unused_functions, 'another_used_function', 
                               "Does not flag another used function") 
        self.assert_not_contains(unused_classes, 'UsedClass', 
                               "Does not flag used class")
        self.assert_not_contains(unused_imports, 'json', 
                               "Does not flag used import (json)")
        self.assert_not_contains(unused_imports, 'defaultdict', 
                               "Does not flag used import (defaultdict)")
    
    def test_magic_and_test_methods(self, results):
        """Test that magic methods and test methods are ignored"""
        print("\n=== Testing Magic Methods and Test Methods ===")
        
        unused_functions = results.get('unused_functions', [])
        
        self.assert_not_contains(unused_functions, '__str__', 
                               "Does not flag magic method __str__")
        self.assert_not_contains(unused_functions, '__eq__', 
                               "Does not flag magic method __eq__")
        self.assert_not_contains(unused_functions, '__init__', 
                               "Does not flag magic method __init__")
        
        self.assert_not_contains(unused_functions, 'test_something', 
                               "Does not flag test method")
        self.assert_not_contains(unused_functions, 'test_another_thing', 
                               "Does not flag another test method")
        
        self.assert_contains(unused_functions, 'RegularClass.unused_method', 
                           "Flags unused regular method")
    
    def test_package_exports(self, results):
        """Test package export detection"""
        print("\n=== Testing Package Exports ===")
        
        unused_functions = results.get('unused_functions', [])
        unused_classes = results.get('unused_classes', [])
        
        self.assert_not_contains(unused_functions, 'exported_function', 
                               "Does not flag exported function")
        self.assert_not_contains(unused_classes, 'ExportedClass', 
                               "Does not flag exported class")
        self.assert_not_contains(unused_functions, 'init_function', 
                               "Does not flag function in __init__.py")
        
        self.assert_contains(unused_functions, 'non_exported_function', 
                           "Flags non-exported function")
        self.assert_contains(unused_classes, 'TrulyUnusedClass', 
                           "Flags non-exported class")
    
    def test_confidence_threshold(self):
        """Test different confidence thresholds"""
        print("\n=== Testing Confidence Thresholds ===")
        
        results_high = self.run_analyzer(90)
        
        results_low = self.run_analyzer(30)
        
        high_count = (len(results_high.get('unused_functions', [])) + 
                     len(results_high.get('unused_imports', [])) + 
                     len(results_high.get('unused_classes', [])))
        
        low_count = (len(results_low.get('unused_functions', [])) + 
                    len(results_low.get('unused_imports', [])) + 
                    len(results_low.get('unused_classes', [])))
        
        if low_count >= high_count:
            print(f"✓ PASS: Lower threshold finds more/equal items ({low_count} vs {high_count})")
            self.tests_passed += 1
        else:
            print(f"✗ FAIL: Lower threshold should find more items ({low_count} vs {high_count})")
            self.tests_failed += 1
    
    def print_detailed_results(self, results):
        """Print detailed analysis results"""
        print("\n=== Detailed Results ===")
        
        print(f"\nUnused Functions ({len(results.get('unused_functions', []))}):")
        for func in results.get('unused_functions', []):
            print(f"  - {func.get('name')} at line {func.get('line', '?')} in {func.get('file', '?')}")
        
        print(f"\nUnused Imports ({len(results.get('unused_imports', []))}):")
        for imp in results.get('unused_imports', []):
            print(f"  - {imp.get('name')} at line {imp.get('line', '?')} in {imp.get('file', '?')}")
        
        print(f"\nUnused Classes ({len(results.get('unused_classes', []))}):")
        for cls in results.get('unused_classes', []):
            print(f"  - {cls.get('name')} at line {cls.get('line', '?')} in {cls.get('file', '?')}")
    
    def run_all_tests(self):
        """Run all tests"""
        try:
            print("Starting Skylos Analyzer Tests...")
            self.setup_test_directory()
            
            results = self.run_analyzer()
            
            self.print_detailed_results(results)
            
            self.test_basic_unused_detection(results)
            self.test_magic_and_test_methods(results)
            self.test_package_exports(results)
            self.test_confidence_threshold()
            
            print(f"\n=== Test Summary ===")
            print(f"Tests Passed: {self.tests_passed}")
            print(f"Tests Failed: {self.tests_failed}")
            print(f"Success Rate: {self.tests_passed/(self.tests_passed + self.tests_failed)*100:.1f}%")
            
            if self.tests_failed == 0:
                print("\n🎉 All tests passed!")
            else:
                print(f"\n⚠️  {self.tests_failed} test(s) failed")
                
        except AttributeError as e:
            if "_get_base_classes" in str(e):
                print("\n❌ Cannot continue testing due to missing method in analyzer")
                print("Please fix the analyzer code first using the provided fix above.")
                return False
            else:
                raise
        except Exception as e:
            print(f"\n❌ Unexpected error during testing: {e}")
            raise
        finally:
            if self.test_dir and os.path.exists(self.test_dir):
                shutil.rmtree(self.test_dir)
                print(f"\nCleaned up test directory: {self.test_dir}")
        
        return True

def main():
    """Main test runner"""
    test_runner = SkylosTest()
    test_runner.run_all_tests()

if __name__ == "__main__":
    main()