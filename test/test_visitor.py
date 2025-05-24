#!/usr/bin/env python3

import ast
import unittest
from pathlib import Path
import tempfile

from skylos.visitor import Visitor, Definition, PYTHON_BUILTINS, DYNAMIC_PATTERNS

class TestDefinition(unittest.TestCase):
    """Test the Definition class."""
    
    def test_definition_creation(self):
        """Test basic definition creation."""
        definition = Definition("module.function", "function", "test.py", 10)
        
        self.assertEqual(definition.name, "module.function")
        self.assertEqual(definition.type, "function")
        self.assertEqual(definition.filename, "test.py")
        self.assertEqual(definition.line, 10)
        self.assertEqual(definition.simple_name, "function")
        self.assertEqual(definition.confidence, 100)
        self.assertEqual(definition.references, 0)
        self.assertFalse(definition.is_exported)
        
    def test_definition_to_dict_function(self):
        """Test to_dict method for functions."""
        definition = Definition("mymodule.my_function", "function", "test.py", 5)
        result = definition.to_dict()
        
        expected = {
            "name": "my_function",
            "full_name": "mymodule.my_function", 
            "simple_name": "my_function",
            "type": "function",
            "file": "test.py",
            "basename": "test.py",
            "line": 5,
            "confidence": 100,
            "references": 0
        }
        
        self.assertEqual(result, expected)
    
    def test_definition_to_dict_method(self):
        """Test to_dict method for methods."""
        definition = Definition("mymodule.MyClass.my_method", "method", "test.py", 15)
        result = definition.to_dict()
        
        # show last two parts for methods
        self.assertEqual(result["name"], "MyClass.my_method")
        self.assertEqual(result["full_name"], "mymodule.MyClass.my_method")
        self.assertEqual(result["simple_name"], "my_method")
        
    def test_init_file_detection(self):
        """Test detection of __init__.py files."""
        definition = Definition("pkg.func", "function", "/path/to/__init__.py", 1)
        self.assertTrue(definition.in_init)
        
        definition2 = Definition("pkg.func", "function", "/path/to/module.py", 1)
        self.assertFalse(definition2.in_init)

class TestVisitor(unittest.TestCase):
    """Test the Visitor class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False)
        self.visitor = Visitor("test_module", self.temp_file.name)
    
    def tearDown(self):
        """Clean up test fixtures."""
        Path(self.temp_file.name).unlink()
    
    def parse_and_visit(self, code):
        """Helper method to parse code and visit with the visitor."""
        tree = ast.parse(code)
        self.visitor.visit(tree)
        return self.visitor
    
    def test_simple_function(self):
        """Test detection of simple function definitions."""
        code = """
def my_function():
    pass
"""
        visitor = self.parse_and_visit(code)
        
        self.assertEqual(len(visitor.defs), 1)
        definition = visitor.defs[0]
        self.assertEqual(definition.type, "function")
        self.assertEqual(definition.simple_name, "my_function")
        
    def test_class_with_methods(self):
        """Test detection of classes and methods."""
        code = """
class MyClass:
    def __init__(self):
        pass
    
    def method(self):
        pass
"""
        visitor = self.parse_and_visit(code)
        
        # technically should find class and two methods
        self.assertEqual(len(visitor.defs), 3)
        
        class_def = next(d for d in visitor.defs if d.type == "class")
        self.assertEqual(class_def.simple_name, "MyClass")
        
        methods = [d for d in visitor.defs if d.type == "method"]
        self.assertEqual(len(methods), 2)
        method_names = {m.simple_name for m in methods}
        self.assertEqual(method_names, {"__init__", "method"})
    
    def test_imports(self):
        """Test import statement detection."""
        code = """
import os
import sys as system
from pathlib import Path
from collections import defaultdict, Counter
"""
        visitor = self.parse_and_visit(code)
        
        imports = [d for d in visitor.defs if d.type == "import"]
        self.assertTrue(len(imports) >= 4)
        
        self.assertEqual(visitor.alias["system"], "sys")
        self.assertEqual(visitor.alias["Path"], "pathlib.Path")
        self.assertEqual(visitor.alias["defaultdict"], "collections.defaultdict")
    
    def test_nested_functions(self):
        """Test nested function detection."""
        code = """
def outer():
    def inner():
        def deeply_nested():
            pass
        return deeply_nested()
    return inner()
"""
        visitor = self.parse_and_visit(code)
        
        functions = [d for d in visitor.defs if d.type == "function"]
        self.assertEqual(len(functions), 3)
        
        names = {f.name for f in functions}
        expected_names = {
            "test_module.outer",
            "test_module.outer.inner", 
            "test_module.outer.inner.deeply_nested"
        }
        self.assertEqual(names, expected_names)
    
    def test_getattr_detection(self):
        """Test detection of getattr calls."""
        code = """
obj = SomeClass()
value = getattr(obj, 'attribute_name')
check = hasattr(obj, 'other_attr')
"""
        visitor = self.parse_and_visit(code)
        
        ref_names = {ref[0] for ref in visitor.refs}
        self.assertIn('attribute_name', ref_names)
        self.assertIn('other_attr', ref_names)
    
    def test_all_detection(self):
        """Test __all__ detection."""
        code = """
__all__ = ['function1', 'Class1', 'CONSTANT']

def function1():
    pass

class Class1:
    pass

CONSTANT = 42
"""
        visitor = self.parse_and_visit(code)
        
        ref_names = {ref[0] for ref in visitor.refs}
        self.assertIn('function1', ref_names)
        self.assertIn('Class1', ref_names)
        self.assertIn('CONSTANT', ref_names)
    
    def test_builtin_detection(self):
        """Test that builtins are correctly identified."""
        code = """
def my_function():
    result = len([1, 2, 3])
    print(result)
    data = list(range(10))
    return data
"""
        visitor = self.parse_and_visit(code)
        
        ref_names = {ref[0] for ref in visitor.refs}
        builtins_found = ref_names & PYTHON_BUILTINS
        expected_builtins = {'len', 'print', 'list', 'range'}
        self.assertTrue(expected_builtins.issubset(builtins_found))

class TestConstants(unittest.TestCase):
    """Test the module constants."""
    
    def test_python_builtins(self):
        """Test that important builtins are included."""
        important_builtins = {'print', 'len', 'str', 'int', 'list', 'dict', 'range'}
        self.assertTrue(important_builtins.issubset(PYTHON_BUILTINS))
    
    def test_dynamic_patterns(self):
        """Test dynamic pattern constants."""
        expected_patterns = {'getattr', 'globals', 'eval', 'exec'}
        self.assertTrue(expected_patterns.issubset(DYNAMIC_PATTERNS))

if __name__ == '__main__':
    unittest.main(verbosity=2)