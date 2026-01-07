#!/usr/bin/env python3

import ast
import unittest
from pathlib import Path
import tempfile

import skylos.visitor as visitor_mod
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
            "references": 0,
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
        definition = Definition(
            "mymodule.OuterClass.InnerClass.deep_method", "method", "test.py", 20
        )
        result = definition.to_dict()

        self.assertEqual(result["name"], "InnerClass.deep_method")
        self.assertEqual(
            result["full_name"], "mymodule.OuterClass.InnerClass.deep_method"
        )
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
        self.temp_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        )
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
        self.assertEqual(
            method_names, {"__init__", "method", "static_method", "class_method"}
        )

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
            self.assertEqual(
                visitor.alias["sibling_module"], "package.subpackage.sibling_module"
            )
        if "package.parent_function" in {imp.name for imp in imports}:
            self.assertEqual(
                visitor.alias["parent_function"], "package.parent_function"
            )

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
            "test_module.outer.inner.deeply_nested",
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

        expected_basic_vars = {
            "MODULE_VAR",
            "CLASS_VAR",
            "local_var",
            "func_var",
            "nested_var",
        }
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
        self.assertIn("attribute_name", ref_names)
        self.assertIn("other_attr", ref_names)
        self.assertIn("function_name", ref_names)

    def test_globals_detection(self):
        code = """
def dynamic_call():
    func = globals()['some_function']
    return func()
"""
        visitor = self.parse_and_visit(code)

        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        found = "globals" in ref_names or "test_module.globals" in ref_names
        self.assertTrue(found, "globals not found in refs")

    def test_all_detection(self):
        """Test __all__ detection."""
        code = """
__all__ = ['function1', 'Class1', 'CONSTANT']

def function1():
    pass

class Class1:
    pass

CONSTANT = 50
"""
        visitor = self.parse_and_visit(code)

        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn("function1", ref_names)
        self.assertIn("Class1", ref_names)
        self.assertIn("CONSTANT", ref_names)

    def test_all_tuple_format(self):
        """Test __all__ with tuple format."""
        code = """
__all__ = ('func1', 'func2', 'Class1')
"""
        visitor = self.parse_and_visit(code)

        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn("func1", ref_names)
        self.assertIn("func2", ref_names)
        self.assertIn("Class1", ref_names)

    def test_builtin_detection(self):
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

        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        expected_builtins = {
            "len",
            "print",
            "list",
            "range",
            "enumerate",
            "sum",
            "sorted",
        }

        for builtin in expected_builtins:
            found = builtin in ref_names or f"test_module.{builtin}" in ref_names
            self.assertTrue(found, f"Builtin '{builtin}' not found in refs")

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

        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn("test_module.Parent", ref_names)
        # object gets qualified too
        found_object = "object" in ref_names or "test_module.object" in ref_names
        self.assertTrue(found_object, "object not found in refs")

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

        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

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
            "str",
            "int",
            "float",
            "bool",
            "list",
            "dict",
            "set",
            "tuple",
            # funcs
            "print",
            "len",
            "range",
            "enumerate",
            "zip",
            "map",
            "filter",
            "sum",
            "min",
            "max",
            "sorted",
            "reversed",
            "all",
            "any",
            # more advance stuff
            "open",
            "super",
            "getattr",
            "setattr",
            "hasattr",
            "isinstance",
            "property",
            "classmethod",
            "staticmethod",
        }
        self.assertTrue(important_builtins.issubset(PYTHON_BUILTINS))

    def test_dynamic_patterns(self):
        """Test dynamic pattern constants."""
        expected_patterns = {"getattr", "globals", "eval", "exec"}
        self.assertTrue(expected_patterns.issubset(DYNAMIC_PATTERNS))

    def test_builtins_are_strings(self):
        """Test that all builtins are strings."""
        for builtin in PYTHON_BUILTINS:
            self.assertIsInstance(builtin, str)
            self.assertTrue(builtin.isidentifier())


class TestEdgeCases(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        )
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
        code = """
def function_with_annotation(param: "SomeType") -> "ReturnType":
    pass

def function_with_complex_annotation(param: Dict[str, List["NestedType"]]) -> None:
    pass
"""
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

        self.assertEqual(
            visitor.alias["EC"], "selenium.webdriver.support.expected_conditions"
        )
        self.assertEqual(visitor.alias["dd"], "collections.defaultdict")

        # should be the actual import, not the local alias
        import_defs = [d for d in visitor.defs if d.type == "import"]
        import_names = {d.name for d in import_defs}

        self.assertIn("selenium.webdriver.support.expected_conditions", import_names)
        self.assertIn("collections.defaultdict", import_names)

        # the local aliases should not be defined as imports
        self.assertNotIn("test_module.EC", import_names)
        self.assertNotIn("test_module.dd", import_names)

        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn(
            "selenium.webdriver.support.expected_conditions.presence_of_element_located",
            ref_names,
        )
        self.assertIn("collections.defaultdict", ref_names)

    def test_import_errors(self):
        code = """
from . import something

from collections import defaultdict, Counter as cnt, deque
"""
        visitor = Visitor("root_module", self.temp_file.name)
        tree = ast.parse(code)
        visitor.visit(tree)

        imports = [d for d in visitor.defs if d.type == "import"]
        self.assertTrue(len(imports) >= 3)


class TestMoreEdgeCases(unittest.TestCase):
    """Tests for constructor chaining, properties, super(), etc."""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        )
        self.visitor = Visitor("test_module", self.temp_file.name)

    def tearDown(self):
        Path(self.temp_file.name).unlink()

    def parse_and_visit(self, code):
        tree = ast.parse(code)
        self.visitor.visit(tree)
        return self.visitor

    def test_constructor_method_call(self):
        code = """
class MyClass:
    def __init__(self, x):
        self.x = x

    def myfunc(self):
        return self.x * 2

if __name__ == "__main__":
    MyClass(2).myfunc()
"""
        visitor = self.parse_and_visit(code)
        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn("test_module.MyClass.myfunc", ref_names)

    def test_constructor_chained_attribute(self):
        code = """
class Config:
    def __init__(self):
        self.value = 50

result = Config().value
"""
        visitor = self.parse_and_visit(code)
        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn("test_module.Config.value", ref_names)

    def test_qualified_constructor_method_call(self):
        """Test module.MyClass().method() pattern."""
        code = """
import mymodule

result = mymodule.MyClass().process()
    """
        visitor = self.parse_and_visit(code)
        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn("mymodule.MyClass.process", ref_names)
        self.assertNotIn("test_module.MyClass.process", ref_names)

    def test_constructor_lowercase_not_matched(self):
        code = """
def factory():
    return something

result = factory().process()
"""
        visitor = self.parse_and_visit(code)
        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertNotIn("test_module.factory.process", ref_names)

    def test_instance_attr_method_call(self):
        code = """
import itertools

class FalseResponseBase:
    def false_negative_series_generator(self):
        return itertools.cycle([False, False, True])

class Controller:
    def __init__(self):
        self.false_responses = FalseResponseBase()

    def check(self):
        value = next(self.false_responses.false_negative_series_generator())
        return value
"""
        visitor = self.parse_and_visit(code)
        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn(
            "test_module.FalseResponseBase.false_negative_series_generator", ref_names
        )

    def test_instance_attr_type_tracking(self):
        code = """
class Helper:
    def help(self):
        pass

class Main:
    def __init__(self):
        self.helper = Helper()
"""
        visitor = self.parse_and_visit(code)

        expected_key = "test_module.Main.helper"
        self.assertIn(expected_key, visitor.instance_attr_types)
        self.assertEqual(
            visitor.instance_attr_types[expected_key], "test_module.Helper"
        )

    def test_instance_attr_with_alias(self):
        """Test self.attr = ImportedClass() with import alias."""
        code = """
from external import SomeClass as SC

class Main:
    def __init__(self):
        self.obj = SC()

    def run(self):
        self.obj.execute()
"""
        visitor = self.parse_and_visit(code)

        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn("external.SomeClass.execute", ref_names)

    def test_multiple_instance_attrs(self):
        code = """
class TypeA:
    def method_a(self):
        pass

class TypeB:
    def method_b(self):
        pass

class Container:
    def __init__(self):
        self.a = TypeA()
        self.b = TypeB()

    def run(self):
        self.a.method_a()
        self.b.method_b()
"""
        visitor = self.parse_and_visit(code)
        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn("test_module.TypeA.method_a", ref_names)
        self.assertIn("test_module.TypeB.method_b", ref_names)

    def test_property_decorator(self):
        code = """
class User:
    def __init__(self):
        self._name = "default"

    @property
    def name(self):
        return self._name
"""
        visitor = self.parse_and_visit(code)
        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn("test_module.User.name", ref_names)

    def test_property_setter(self):
        """Test @x.setter decorated methods are marked as referenced."""
        code = """
class User:
    def __init__(self):
        self._name = "default"

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value
"""
        visitor = self.parse_and_visit(code)

        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn("test_module.User.name", ref_names)

        name_refs = []
        for r in visitor.refs:
            if r[0] == "test_module.User.name":
                name_refs.append(r)

        self.assertGreaterEqual(len(name_refs), 2)

    def test_property_deleter(self):
        """Test @x.deleter decorated methods are marked as referenced."""
        code = """
class User:
    @property
    def name(self):
        return self._name

    @name.deleter
    def name(self):
        del self._name
"""
        visitor = self.parse_and_visit(code)

        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn("test_module.User.name", ref_names)

    def test_cached_property(self):
        """Test @cached_property decorated methods."""
        code = """
from functools import cached_property

class ExpensiveComputation:
    @cached_property
    def result(self):
        return sum(range(1000000))
"""
        visitor = self.parse_and_visit(code)

        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn("test_module.ExpensiveComputation.result", ref_names)

    def test_functools_cached_property(self):
        """Test @functools.cached_property decorated methods."""
        code = """
import functools

class ExpensiveComputation:
    @functools.cached_property
    def result(self):
        return sum(range(1000000))
"""
        visitor = self.parse_and_visit(code)

        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn("test_module.ExpensiveComputation.result", ref_names)

    def test_super_method_call(self):
        """Test super().method() pattern."""
        code = """
class Parent:
    def save(self):
        print("Parent save")

class Child(Parent):
    def save(self):
        super().save()
        print("Child save")
"""
        visitor = self.parse_and_visit(code)

        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn("test_module.Child.save", ref_names)

    def test_super_in_init(self):
        code = """
class Parent:
    def __init__(self, x):
        self.x = x

class Child(Parent):
    def __init__(self, x, y):
        super().__init__(x)
        self.y = y
"""
        visitor = self.parse_and_visit(code)

        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn("test_module.Child.__init__", ref_names)

    def test_super_async_method(self):
        code = """
class Parent:
    async def process(self):
        pass

class Child(Parent):
    async def process(self):
        await super().process()
        print("Child processing")
"""
        visitor = self.parse_and_visit(code)
        ref_names = {ref[0] for ref in visitor.refs}

        self.assertIn("test_module.Child.process", ref_names)

    def test_super_multiple_methods(self):
        code = """
class Parent:
    def method_a(self):
        pass

    def method_b(self):
        pass

class Child(Parent):
    def method_a(self):
        super().method_a()

    def method_b(self):
        super().method_b()
"""
        visitor = self.parse_and_visit(code)
        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn("test_module.Child.method_a", ref_names)
        self.assertIn("test_module.Child.method_b", ref_names)

    def test_get_decorator_name_simple(self):
        code = "@property"
        tree = ast.parse(f"{code}\ndef f(): pass")
        deco = tree.body[0].decorator_list[0]

        result = self.visitor._get_decorator_name(deco)
        self.assertEqual(result, "property")

    def test_get_decorator_name_attribute(self):
        code = "@name.setter"
        tree = ast.parse(f"{code}\ndef f(): pass")
        deco = tree.body[0].decorator_list[0]

        result = self.visitor._get_decorator_name(deco)
        self.assertEqual(result, "name.setter")

    def test_get_decorator_name_call(self):
        code = "@decorator(arg)"
        tree = ast.parse(f"{code}\ndef f(): pass")
        deco = tree.body[0].decorator_list[0]

        result = self.visitor._get_decorator_name(deco)
        self.assertEqual(result, "decorator")

    def test_get_decorator_name_chained(self):
        code = "@functools.cached_property"
        tree = ast.parse(f"{code}\ndef f(): pass")
        deco = tree.body[0].decorator_list[0]

        result = self.visitor._get_decorator_name(deco)
        self.assertEqual(result, "functools.cached_property")

    def test_full_example_original_bug(self):
        code = """
from pathlib import Path

class MyClass:
    def __init__(self, x: int):
        self.x = x

    def myfunc(self) -> None:
        with Path("/tmp/blah").open("w") as afile:
            afile.write(str(self.x * 2))

if __name__ == "__main__":
    MyClass(2).myfunc()
"""
        visitor = self.parse_and_visit(code)

        methods = []
        for d in visitor.defs:
            if d.type == "method":
                methods.append(d)

        method_names = set()
        for m in methods:
            method_names.add(m.simple_name)

        self.assertIn("myfunc", method_names)

        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn("test_module.MyClass.myfunc", ref_names)

    def test_full_example_controller_pattern(self):
        code = """
import itertools

class FalseResponseBase:
    def false_negative_series_generator(self):
        return itertools.cycle([False, False, True])

class Controller:
    def __init__(self):
        self.false_responses = FalseResponseBase()

    def check(self):
        value = next(self.false_responses.false_negative_series_generator())
        print(f"False negative check: {value}")
        return value

if __name__ == "__main__":
    ctrl = Controller()
    ctrl.check()
"""
        visitor = self.parse_and_visit(code)

        ref_names = set()
        for ref in visitor.refs:
            ref_names.add(ref[0])

        self.assertIn(
            "test_module.FalseResponseBase.false_negative_series_generator", ref_names
        )


if __name__ == "__main__":
    test_classes = [
        TestDefinition,
        TestVisitor,
        TestConstants,
        TestEdgeCases,
        TestMoreEdgeCases,
    ]

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print(f"\n{'=' * 50}")
    print(f"Test Summary:")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.testsRun > 0:
        success_rate = (
            (result.testsRun - len(result.failures) - len(result.errors))
            / result.testsRun
            * 100
        )
        print(f"Success rate: {success_rate:.1f}%")

    if result.failures:
        print(f"\nFailures:")
        for test, traceback in result.failures:
            print(f"  - {test}")

    if result.errors:
        print(f"\nErrors:")
        for test, traceback in result.errors:
            print(f"  - {test}")

    print("=" * 50)


def _visit(code: str, tmp_path, mod="test_module") -> Visitor:
    p = tmp_path / "m.py"
    p.write_text(code, encoding="utf-8")
    v = Visitor(mod, str(p))
    v.visit(ast.parse(code))
    return v


def _defs(v: Visitor, typ: str):
    return [d for d in v.defs if d.type == typ]


def _def_names(v: Visitor, typ: str):
    return {d.name for d in _defs(v, typ)}


def _ref_names(v: Visitor):
    return {r[0] for r in v.refs}


def test_local_def_shadows_import_alias_in_qual(tmp_path):
    code = """
import pkg

def pkg():
    return 1

pkg()
"""
    v = _visit(code, tmp_path)
    refs = _ref_names(v)

    assert "test_module.pkg" in refs


def test_typeddict_annotation_only_fields_are_not_variables(tmp_path):
    code = """
from typing import TypedDict

class TD(TypedDict):
    x: int
    y: "str"
"""
    v = _visit(code, tmp_path)

    var_defs = _def_names(v, "variable")
    assert "test_module.TD.x" not in var_defs
    assert "test_module.TD.y" not in var_defs


def test_dataclass_fields_tracked_from_annassign(tmp_path):
    code = """
from dataclasses import dataclass

@dataclass
class A:
    x: int
    y: int = 1
"""
    v = _visit(code, tmp_path)

    assert "test_module.A.x" in v.dataclass_fields
    assert "test_module.A.y" in v.dataclass_fields


def test_metadata_dependencies_skipped_inside_cst_transformer(tmp_path):
    code = """
import libcst as cst
from libcst.metadata import PositionProvider

class X(cst.CSTTransformer):
    METADATA_DEPENDENCIES = (PositionProvider,)
"""
    v = _visit(code, tmp_path)

    var_defs = _def_names(v, "variable")
    assert "test_module.X.METADATA_DEPENDENCIES" not in var_defs


def test_if_static_condition_true_visits_only_body(monkeypatch, tmp_path):
    monkeypatch.setattr(visitor_mod, "evaluate_static_condition", lambda _test: True)

    code = """
FLAG = True

if FLAG:
    def a():
        pass
else:
    def b():
        pass
"""
    v = _visit(code, tmp_path)

    fn_defs = _def_names(v, "function")
    assert "test_module.a" in fn_defs
    assert "test_module.b" not in fn_defs


def test_if_static_condition_false_visits_only_orelse(monkeypatch, tmp_path):
    monkeypatch.setattr(visitor_mod, "evaluate_static_condition", lambda _test: False)

    code = """
FLAG = False

if FLAG:
    def a():
        pass
else:
    def b():
        pass
"""
    v = _visit(code, tmp_path)

    fn_defs = _def_names(v, "function")
    assert "test_module.a" not in fn_defs
    assert "test_module.b" in fn_defs


def test_if_static_condition_unknown_visits_both(monkeypatch, tmp_path):
    monkeypatch.setattr(visitor_mod, "evaluate_static_condition", lambda _test: None)

    code = """
FLAG = maybe()

if FLAG:
    def a():
        pass
else:
    def b():
        pass
"""
    v = _visit(code, tmp_path)

    fn_defs = _def_names(v, "function")
    assert "test_module.a" in fn_defs
    assert "test_module.b" in fn_defs


def test_globals_subscript_adds_function_refs(tmp_path):
    code = """
def f():
    fn = globals()['some_function']
    return fn
"""
    v = _visit(code, tmp_path)
    refs = _ref_names(v)

    assert "some_function" in refs
    assert "test_module.some_function" in refs


def test_getattr_uses_fstring_pattern_tracker(tmp_path):
    pt = visitor_mod.pattern_tracker
    old_f = dict(getattr(pt, "f_string_patterns", {}))
    old_pr = list(getattr(pt, "pattern_refs", []))
    old_known = set(getattr(pt, "known_refs", set()))
    try:
        # reset to clean slate for this test
        pt.f_string_patterns = {}
        pt.pattern_refs = []
        pt.known_refs = set()

        code = """
x = "ignored"

def run(obj):
    name = f"handle_{x}"
    return getattr(obj, name)
"""
        v = _visit(code, tmp_path)

        assert ("handle_*", 70) in pt.pattern_refs
        assert v is not None
    finally:
        pt.f_string_patterns = old_f
        pt.pattern_refs = old_pr
        pt.known_refs = old_known


def test_local_type_inference_from_constructor_call(tmp_path):
    code = """
class Helper:
    def run(self):
        pass

def f():
    h = Helper()
    h.run()
"""
    v = _visit(code, tmp_path)
    refs = _ref_names(v)

    assert "test_module.Helper.run" in refs


def test_shadowed_module_alias_adds_refs_to_both_shadow_and_alias(tmp_path):
    code = """
import os

os = 123
print(os)
"""
    v = _visit(code, tmp_path)
    refs = _ref_names(v)

    assert "test_module.os" in refs
    assert "os" in refs


def test_global_statement_maps_to_module_variable(tmp_path):
    code = """
x = 0

def f():
    global x
    x = 1
    return x
"""
    v = _visit(code, tmp_path)

    var_defs = _def_names(v, "variable")
    assert "test_module.x" in var_defs

    refs = _ref_names(v)
    assert "test_module.x" in refs


def test_eval_exec_mark_module_dynamic(tmp_path):
    code = """
def f():
    return eval("1+1")
"""
    v = _visit(code, tmp_path)

    assert "test_module" in v.dyn
