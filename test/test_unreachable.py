import unittest
import ast
from skylos.rules.quality.unreachable import UnreachableCodeRule


class TestUnreachableCodeRule(unittest.TestCase):
    def setUp(self):
        self.rule = UnreachableCodeRule()
        self.context = {"filename": "test_sample.py"}

    def _analyze(self, source_code):
        """
        parse code and run the rule on the first function definition found
        """
        tree = ast.parse(source_code)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                return self.rule.visit_node(node, self.context) or []
            if isinstance(node, (ast.For, ast.While)):
                return self.rule.visit_node(node, self.context) or []
        return []

    def test_no_issues_clean_code(self):
        code = """
def clean_function():
    x = 1
    y = 2
    return x + y
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 0, "Should not flag valid code.")

    def test_simple_return_unreachable(self):
        code = """
def dead_code():
    return True
    print("unreachable")
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 4)
        self.assertIn("follows a return", findings[0]["message"])

    def test_raise_unreachable(self):
        code = """
def error_func():
    raise ValueError("Stop")
    x = 100  # Unreachable
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 4)

    def test_break_in_loop(self):
        code = """
def loop_func():
    for i in range(10):
        if i > 5:
            break
            print("unreachable")     
"""
        tree = ast.parse(code)
        if_node = tree.body[0].body[0].body[0]
        findings = self.rule.visit_node(if_node, self.context)

        self.assertIsNotNone(findings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 6)

    def test_continue_unreachable(self):
        code = """
def loop_func():
    for i in range(10):
        continue
        print("unreachable")
"""
        tree = ast.parse(code)
        for_node = tree.body[0].body[0]
        findings = self.rule.visit_node(for_node, self.context)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 5)

    def test_if_else_both_return(self):
        code = """
def check_branches(x):
    if x > 0:
        return 1
    else:
        return 2
    
    print("unreachable")
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 8)

    def test_if_else_partial_return(self):
        code = """
def check_branches(x):
    if x > 0:
        return 1
    else:
        x = 2
        # No return here
    
    print("Reachable!")
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 0, "Should not flag")

    def test_if_without_else(self):
        code = """
def check_branches(x):
    if x > 0:
        return 1
    
    print("Reachable")
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 0)

    def test_nested_if_else_termination(self):
        code = """
def complex_logic(x, y):
    if x:
        if y:
            return 1
        else:
            return 2
    else:
        raise ValueError("Bad")  
    print("unreachable")
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 10)

    def test_flag_only_first_unreachable(self):
        code = """
def noise():
    return
    print("First unreachable line")
    print("Second unreachable line")
    x = 1 + 1
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 4)


if __name__ == "__main__":
    unittest.main()
