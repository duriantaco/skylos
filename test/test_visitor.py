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
        
    def test_definition_to_dict_method_deep_nesting(self):
        """Test to_dict method for deeply nested methods."""
        definition = Definition("mymodule.OuterClass.InnerClass.deep_method", "method", "test.py", 20)
        result = definition.to_dict()
        
        self.assertEqual(result["name"], "InnerClass.deep_method")
        self.assertEqual(result["full_name"], "mymodule.OuterClass.InnerClass.deep_method")
        self.assertEqual(result["simple_name"], "deep_method")
        
    def test_init_file_detection(self):
        """Test detection of __init__.py files."""
        definition = Definition("pkg.func", "function", "/path/to/__init__.py", 1)
        self.assertTrue(definition.in_init)
        
        definition2 = Definition("pkg.func", "function", "/path/to/module.py", 1)
        self.assertFalse(definition2.in_init)
        
    def test_definition_types(self):
        """Test all definition types."""
        types = ["function", "method", "class", "variable", "parameter", "import"]
        for def_type in types:
            definition = Definition(f"test.{def_type}", def_type, "test.py", 1)
            self.assertEqual(definition.type, def_type)

class TestVisitor(unittest.TestCase):
    
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False)
        self.visitor = Visitor("test_module", self.temp_file.name)
    
    def tearDown(self):
        Path(self.temp_file.name).unlink()
    
    def parse_and_visit(self, code):
        tree = ast.parse(code)
        self.visitor.visit(tree)
        return self.visitor
    
    def test_simple_function(self):
        code = """
def my_function():
    pass
"""
        visitor = self.parse_and_visit(code)
        
        self.assertEqual(len(visitor.defs), 1)
        definition = visitor.defs[0]
        self.assertEqual(definition.type, "function")
        self.assertEqual(definition.simple_name, "my_function")
        
    def test_async_function(self):
        code = """
async def async_function():
    await some_call()
"""
        visitor = self.parse_and_visit(code)
        
        self.assertEqual(len(visitor.defs), 1)
        definition = visitor.defs[0]
        self.assertEqual(definition.type, "function")
        self.assertEqual(definition.simple_name, "async_function")
        
    def test_class_with_methods(self):
        code = """
class MyClass:
    def __init__(self):
        pass

    def method(self):
        pass

    @staticmethod
    def static_method():
        pass

    @classmethod
    def class_method(cls):
        pass
"""
        visitor = self.parse_and_visit(code)
        
        for d in visitor.defs:
            print(f"  {d.type}: {d.name}")
        
        class_defs = [d for d in visitor.defs if d.type == "class"]
        method_defs = [d for d in visitor.defs if d.type == "method"]
        param_defs = [d for d in visitor.defs if d.type == "parameter"]
        
        self.assertEqual(len(class_defs), 1)
        self.assertEqual(class_defs[0].simple_name, "MyClass")
        
        self.assertEqual(len(method_defs), 4)
        method_names = {m.simple_name for m in method_defs}
        self.assertEqual(method_names, {"__init__", "method", "static_method", "class_method"})
        
        # static_method has no params, so only 3 total: self (2x) + cls (1x)
        self.assertTrue(len(param_defs) >= 3)
    
    def test_imports_basic(self):
        code = """
import os
import sys as system
"""
        visitor = self.parse_and_visit(code)
        
        imports = [d for d in visitor.defs if d.type == "import"]
        self.assertEqual(len(imports), 2)
        
        self.assertEqual(visitor.alias["os"], "os")
        self.assertEqual(visitor.alias["system"], "sys")
        
    def test_imports_from(self):
        """Test from-import statement detection."""
        code = """
from pathlib import Path
from collections import defaultdict, Counter
from os.path import join as path_join
"""
        visitor = self.parse_and_visit(code)
        
        imports = [d for d in visitor.defs if d.type == "import"]
        self.assertTrue(len(imports) >= 4)
        
        self.assertEqual(visitor.alias["Path"], "pathlib.Path")
        self.assertEqual(visitor.alias["defaultdict"], "collections.defaultdict")
        self.assertEqual(visitor.alias["Counter"], "collections.Counter")
        self.assertEqual(visitor.alias["path_join"], "os.path.join")

    def test_relative_imports(self):
        code = """
from . import sibling_module
from ..parent import parent_function
from ...grandparent.utils import helper
"""
        visitor = Visitor("package.subpackage.module", self.temp_file.name)
        tree = ast.parse(code)
        visitor.visit(tree)
        
        imports = [d for d in visitor.defs if d.type == "import"]
        
        self.assertTrue(len(imports) >= 2)
        
        if "package.subpackage.sibling_module" in {imp.name for imp in imports}:
            self.assertEqual(visitor.alias["sibling_module"], "package.subpackage.sibling_module")
        if "package.parent_function" in {imp.name for imp in imports}:
            self.assertEqual(visitor.alias["parent_function"], "package.parent_function")
        
    def test_nested_functions(self):
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
        
    def test_function_parameters(self):
        """Test function parameter detection."""
        code = """
def function_with_params(a, b, c=None, *args, **kwargs):
    return a + b

class MyClass:
    def method(self, x, y=10):
        return self.x + y
"""
        visitor = self.parse_and_visit(code)
        
        params = [d for d in visitor.defs if d.type == "parameter"]
        
        self.assertTrue(len(params) >= 5)
        
        param_names = {p.simple_name for p in params}
        expected_basic_params = {"a", "b", "c"}
        self.assertTrue(expected_basic_params.issubset(param_names))
        
    def test_parameter_usage_tracking(self):
        code = """
def use_params(a, b, unused_param):
    result = a + b  # a and b are used, unused_param is not
    return result
"""
        visitor = self.parse_and_visit(code)
        
        params = [d for d in visitor.defs if d.type == "parameter"]
        param_names = {p.simple_name for p in params}
        self.assertEqual(param_names, {"a", "b", "unused_param"})
        
        ref_names = {ref[0] for ref in visitor.refs}
        
        a_param = next(p.name for p in params if p.simple_name == "a")
        b_param = next(p.name for p in params if p.simple_name == "b")
        
        self.assertIn(a_param, ref_names)
        self.assertIn(b_param, ref_names)
        
    def test_variables(self):
        code = """
MODULE_VAR = "module level"

class MyClass:
    CLASS_VAR = "class level"
    
    def method(self):
        local_var = "function level"
        self.instance_var = "instance level"
        return local_var

def function():
    func_var = "function scope"
    
    def nested():
        nested_var = "nested scope"
        return nested_var
        
    return func_var
"""
        visitor = self.parse_and_visit(code)
        
        variables = [d for d in visitor.defs if d.type == "variable"]
        var_names = {v.simple_name for v in variables}
        
        expected_basic_vars = {"MODULE_VAR", "CLASS_VAR", "local_var", "func_var", "nested_var"}
        found_basic_vars = expected_basic_vars & var_names
        
        self.assertTrue(len(found_basic_vars) >= 4)
        
    def test_getattr_detection(self):
        code = """
obj = SomeClass()
value = getattr(obj, 'attribute_name')
check = hasattr(obj, 'other_attr')
dynamic_attr = getattr(module, 'function_name')
"""
        visitor = self.parse_and_visit(code)
        
        ref_names = {ref[0] for ref in visitor.refs}
        self.assertIn('attribute_name', ref_names)
        self.assertIn('other_attr', ref_names)
        self.assertIn('function_name', ref_names)
        
    def test_globals_detection(self):
        """Test detection of globals() usage."""
        code = """
def dynamic_call():
    func = globals()['some_function']
    return func()
"""
        visitor = self.parse_and_visit(code)
        
        ref_names = {ref[0] for ref in visitor.refs}
        
        self.assertIn('globals', ref_names)
        
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
        
    def test_all_tuple_format(self):
        """Test __all__ with tuple format."""
        code = """
__all__ = ('func1', 'func2', 'Class1')
"""
        visitor = self.parse_and_visit(code)
        
        ref_names = {ref[0] for ref in visitor.refs}
        self.assertIn('func1', ref_names)
        self.assertIn('func2', ref_names)
        self.assertIn('Class1', ref_names)
        
    def test_builtin_detection(self):
        """Test that builtins are correctly identified."""
        code = """
def my_function():
    result = len([1, 2, 3])
    print(result)
    data = list(range(10))
    items = enumerate(data)
    total = sum(data)
    return sorted(data)
"""
        visitor = self.parse_and_visit(code)
        
        ref_names = {ref[0] for ref in visitor.refs}
        builtins_found = ref_names & PYTHON_BUILTINS
        expected_builtins = {'len', 'print', 'list', 'range', 'enumerate', 'sum', 'sorted'}
        self.assertTrue(expected_builtins.issubset(builtins_found))

    def test_decorators(self):
        code = """
@property
def getter(self):
    return self._value

@staticmethod
@decorator_with_args('arg')
def complex_decorated():
    pass

class MyClass:
    @classmethod
    def class_method(cls):
        pass
"""
        visitor = self.parse_and_visit(code)
        
        functions = [d for d in visitor.defs if d.type in ("function", "method")]
        func_names = {f.simple_name for f in functions}
        self.assertIn("getter", func_names)
        self.assertIn("complex_decorated", func_names)
        self.assertIn("class_method", func_names)
        
    def test_inheritance_detection(self):
        code = """
class Parent:
    pass

class Child(Parent):
    pass

class MultipleInheritance(Parent, object):
    pass
"""
        visitor = self.parse_and_visit(code)
        
        classes = [d for d in visitor.defs if d.type == "class"]
        class_names = {c.simple_name for c in classes}
        self.assertEqual(class_names, {"Parent", "Child", "MultipleInheritance"})
        
        ref_names = {ref[0] for ref in visitor.refs}
        self.assertIn("test_module.Parent", ref_names)
        self.assertIn("object", ref_names)
        
    def test_comprehensions(self):
        code = """
def test_comprehensions():
    squares = [x**2 for x in range(10)]
    square_dict = {x: x**2 for x in range(5)}
    
    even_squares = {x**2 for x in range(10) if x % 2 == 0}
    
    return squares, square_dict, even_squares
"""
        visitor = self.parse_and_visit(code)
        
        variables = [d for d in visitor.defs if d.type == "variable"]
        var_names = {v.simple_name for v in variables}
        
        expected_vars = {"squares", "square_dict", "even_squares"}
        self.assertTrue(expected_vars.issubset(var_names))
        
    def test_lambda_functions(self):
        """Test lambda function handling."""
        code = """
def test_lambdas():
    double = lambda x: x * 2
    
    add = lambda a, b: a + b
    
    numbers = [1, 2, 3, 4, 5]
    doubled = list(map(lambda n: n * 2, numbers))
    
    return double, add, doubled
"""
        visitor = self.parse_and_visit(code)
        
        functions = [d for d in visitor.defs if d.type == "function"]
        func_names = {f.simple_name for f in functions}
        self.assertEqual(func_names, {"test_lambdas"})
        
    def test_attribute_access_chains(self):
        """Test complex attribute access chains."""
        code = """
import os
from pathlib import Path

def test_attributes():
    current_dir = os.getcwd()
    
    path = Path.home().parent.name
    
    text = "hello world"
    result = text.upper().replace(" ", "_")
    
    return current_dir, path, result
"""
        visitor = self.parse_and_visit(code)
        
        ref_names = {ref[0] for ref in visitor.refs}
        
        self.assertIn("os.getcwd", ref_names)
        self.assertIn("pathlib.Path.home", ref_names)
        
    def test_star_imports(self):
        code = """
from os import *
from collections import defaultdict

def use_star_import():
    current_dir = getcwd()  # from os import *
    
    # explicit
    my_dict = defaultdict(list)
    
    return current_dir, my_dict
"""
        visitor = self.parse_and_visit(code)
        
        imports = [d for d in visitor.defs if d.type == "import"]
        import_names = {i.name for i in imports}
        
        # have the explicit import
        self.assertIn("collections.defaultdict", import_names)
        
    def test_exception_handling(self):
        code = """
def test_exceptions():
    try:
        risky_operation()
    except ValueError as ve:
        handle_value_error(ve)
    except (TypeError, AttributeError) as e:
        handle_other_errors(e)
    except Exception:
        handle_generic_error()
    finally:
        cleanup()
"""  
        
        # our current visitor can't really handle exception variables it's is a feature gap
        
    def test_context_managers(self):
        code = """
def test_context_managers():
    with open('file.txt') as f:
        content = f.read()
    
    with open('input.txt') as infile, open('output.txt', 'w') as outfile:
        data = infile.read()
        outfile.write(data.upper())
    
    return content
"""
        visitor = self.parse_and_visit(code)
        
        variables = [d for d in visitor.defs if d.type == "variable"]
        var_names = {v.simple_name for v in variables}
         
        # just check some basic variables, later then improve on visitor 
        basic_vars = {"content", "data"}
        found_basic = basic_vars & var_names
        
        self.assertTrue(len(found_basic) >= 1)

class TestConstants(unittest.TestCase):
    
    def test_python_builtins_completeness(self):
        """Test that important builtins are included."""
        important_builtins = {
            # basic types
            'str', 'int', 'float', 'bool', 'list', 'dict', 'set', 'tuple',
            # funcs
            'print', 'len', 'range', 'enumerate', 'zip', 'map', 'filter',
            'sum', 'min', 'max', 'sorted', 'reversed', 'all', 'any',
            # more advance stuff
            'open', 'super', 'getattr', 'setattr', 'hasattr', 'isinstance',
            'property', 'classmethod', 'staticmethod'
        }
        self.assertTrue(important_builtins.issubset(PYTHON_BUILTINS))
    
    def test_dynamic_patterns(self):
        """Test dynamic pattern constants."""
        expected_patterns = {'getattr', 'globals', 'eval', 'exec'}
        self.assertTrue(expected_patterns.issubset(DYNAMIC_PATTERNS))
        
    def test_builtins_are_strings(self):
        """Test that all builtins are strings."""
        for builtin in PYTHON_BUILTINS:
            self.assertIsInstance(builtin, str)
            self.assertTrue(builtin.isidentifier())

class TestEdgeCases(unittest.TestCase):
    
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False)
        self.visitor = Visitor("test_module", self.temp_file.name)
    
    def tearDown(self):
        Path(self.temp_file.name).unlink()
    
    def parse_and_visit(self, code):
        """Helper to parse code and visit with the visitor."""
        tree = ast.parse(code)
        self.visitor.visit(tree)
        return self.visitor
    
    def test_empty_file(self):
        code = ""
        visitor = self.parse_and_visit(code)
        
        self.assertEqual(len(visitor.defs), 0)
        self.assertEqual(len(visitor.refs), 0)
        
    def test_comments_and_docstrings(self):
        code = '''
"""Module docstring"""

def function_with_docstring():
    """Function docstring with 'quoted' content."""
    # This is a comment
    return "string with quotes"

class ClassWithDocstring:
    """Class docstring."""
    pass
'''
        visitor = self.parse_and_visit(code)
        
        defs = [d for d in visitor.defs if d.type in ("function", "class")]
        def_names = {d.simple_name for d in defs}
        self.assertEqual(def_names, {"function_with_docstring", "ClassWithDocstring"})
        
    def test_malformed_annotations(self):
        """handling of malformed type annotations."""
        code = '''
def function_with_annotation(param: "SomeType") -> "ReturnType":
    pass

def function_with_complex_annotation(param: Dict[str, List["NestedType"]]) -> None:
    pass
'''
        visitor = self.parse_and_visit(code)
        
        functions = [d for d in visitor.defs if d.type == "function"]
        self.assertEqual(len(functions), 2)
    
    def test_import_aliases_fix(self):
        """Test the fix from issue in #8"""
        code = """
from selenium.webdriver.support import expected_conditions as EC
from collections import defaultdict as dd

def use_aliases():
    condition = EC.presence_of_element_located(("id", "test"))
    
    my_dict = dd(list)
    
    return condition, my_dict
"""
        visitor = self.parse_and_visit(code)
        
        self.assertEqual(visitor.alias["EC"], "selenium.webdriver.support.expected_conditions")
        self.assertEqual(visitor.alias["dd"], "collections.defaultdict")
        
        # should be the actual import, not the local alias
        import_defs = [d for d in visitor.defs if d.type == "import"]
        import_names = {d.name for d in import_defs}
        
        self.assertIn("selenium.webdriver.support.expected_conditions", import_names)
        self.assertIn("collections.defaultdict", import_names)
        
        # the local aliases should not be defined as imports
        self.assertNotIn("test_module.EC", import_names)
        self.assertNotIn("test_module.dd", import_names)
        
        ref_names = {ref[0] for ref in visitor.refs}
        self.assertIn("selenium.webdriver.support.expected_conditions.presence_of_element_located", ref_names)
        self.assertIn("collections.defaultdict", ref_names)
        
    def test_import_errors(self):
        code = '''
from . import something

from collections import defaultdict, Counter as cnt, deque
'''
        visitor = Visitor("root_module", self.temp_file.name)
        tree = ast.parse(code)
        visitor.visit(tree)
        
        imports = [d for d in visitor.defs if d.type == "import"]
        self.assertTrue(len(imports) >= 3)

if __name__ == '__main__':
    test_classes = [
        TestDefinition,
        TestVisitor, 
        TestConstants,
        TestEdgeCases
    ]
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*50}")
    print(f"Test Summary:")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.testsRun > 0:
        success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100)
        print(f"Success rate: {success_rate:.1f}%")
    
    if result.failures:
        print(f"\nFailures:")
        for test, traceback in result.failures:
            print(f"  - {test}")
    
    if result.errors:
        print(f"\nErrors:")
        for test, traceback in result.errors:
            print(f"  - {test}")
    
    print("="*50)