import ast
from skylos.rules.quality.nesting import NestingRule


def check_code(rule, code, filename="test.py"):
    tree = ast.parse(code)
    findings = []
    context = {"filename": filename, "mod": "test_module"}

    for node in ast.walk(tree):
        res = rule.visit_node(node, context)
        if res:
            findings.extend(res)
    return findings


class TestNestingRule:
    def test_flat_function(self):
        code = """
def flat():
    x = 1
    y = 2
    return x + y
"""
        rule = NestingRule(threshold=3)
        findings = check_code(rule, code)
        assert len(findings) == 0

    def test_shallow_nesting(self):
        code = """
def shallow():
    if True:
        for x in range(10):
            if x > 5:
                print(x)
"""
        rule = NestingRule(threshold=3)
        findings = check_code(rule, code)
        assert len(findings) == 0

    def test_deep_nesting_trigger(self):
        code = """
def deep():
    if True: 
        for x in range(10):
            if x > 5:
                while True:
                    break
"""
        rule = NestingRule(threshold=3)
        findings = check_code(rule, code)

        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-Q302"
        assert findings[0]["value"] == 4
        assert findings[0]["severity"] == "MEDIUM"
        assert "test_module.deep" in findings[0]["name"]

    def test_severity_levels(self):
        rule = NestingRule(threshold=2)

        code_high = """
def high_nesting():
    if a:
        if b:
            if c:
                if d:
                    if e: 
                        pass
"""
        findings = check_code(rule, code_high)
        assert len(findings) == 1
        assert findings[0]["value"] == 5
        assert findings[0]["severity"] == "HIGH"

    def test_ignore_inner_function_def(self):
        code = """
def outer():
    if True:
        def inner():
            if True:
                pass
        x = 1
"""
        rule = NestingRule(threshold=1)

        findings = check_code(rule, code)
        assert len(findings) == 0

    def test_try_except_finally(self):
        code = """
def complex_try():
    try:
        if True:
            pass
    except ValueError:
        for i in x:
            pass
    finally:
        while True:
            pass
"""
        rule = NestingRule(threshold=1)
        findings = check_code(rule, code)

        assert len(findings) == 1
        assert findings[0]["value"] == 2
