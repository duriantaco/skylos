import ast
from skylos.rules.quality.structure import ArgCountRule, FunctionLengthRule


def check_code(rule, code, filename="test.py"):
    tree = ast.parse(code)
    findings = []
    context = {"filename": filename, "mod": "test_mod"}

    for node in ast.walk(tree):
        res = rule.visit_node(node, context)
        if res:
            findings.extend(res)
    return findings


class TestArgCountRule:
    def test_too_many_args(self):
        code = """
def my_func(a, b, c, d, e, f):
    pass
        """
        rule = ArgCountRule(max_args=5)

        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-C303"
        assert findings[0]["value"] == 6
        assert "Function has 6 arguments" in findings[0]["message"]

    def test_exact_limit_is_fine(self):
        code = """
def my_func(a, b, c, d, e): 
    pass
        """
        rule = ArgCountRule(max_args=5)

        findings = check_code(rule, code)
        assert len(findings) == 0

    def test_ignores_self_and_cls(self):
        code = """
class MyClass:
    def instance_method(self, a, b, c, d, e): 
        pass
    
    @classmethod
    def class_method(cls, a, b, c, d, e): 
        pass
"""
        rule = ArgCountRule(max_args=5)
        findings = check_code(rule, code)
        assert len(findings) == 0

    def test_counts_kwonly_args(self):
        code = """
def my_func(a, b, *, c, d, e, f): 
    pass
        """
        rule = ArgCountRule(max_args=5)

        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["value"] == 6

    def test_async_function(self):
        code = """
async def my_func(a, b, c, d, e, f): 
    pass
        """
        rule = ArgCountRule(max_args=5)

        findings = check_code(rule, code)
        assert len(findings) == 1


class TestFunctionLengthRule:
    def test_short_function(self):
        code = """
def short():
    print('1')
    print('2')
"""
        rule = FunctionLengthRule(max_lines=10)
        findings = check_code(rule, code)
        assert len(findings) == 0

    def test_long_function(self):
        body = "\n".join([f"   print({i})" for i in range(11)])
        code = f"def long_func():\n{body}"

        rule = FunctionLengthRule(max_lines=10)
        findings = check_code(rule, code)

        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-C304"
        assert findings[0]["value"] > 10

    def test_high_severity_for_huge_function(self):
        body = "\n".join([f"   print({i})" for i in range(105)])
        code = f"def huge_func():\n{body}"

        rule = FunctionLengthRule(max_lines=50)
        findings = check_code(rule, code)

        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"

    def test_medium_severity_for_medium_function(self):
        body = "\n".join([f"   print({i})" for i in range(60)])
        code = f"def medium_func():\n{body}"

        rule = FunctionLengthRule(max_lines=50)
        findings = check_code(rule, code)

        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"
