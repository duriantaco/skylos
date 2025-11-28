import ast
from skylos.rules.quality.complexity import ComplexityRule


def check_code(rule, code, filename="test.py"):
    tree = ast.parse(code)
    findings = []
    context = {"filename": filename, "mod": "test_module"}

    for node in ast.walk(tree):
        res = rule.visit_node(node, context)
        if res:
            findings.extend(res)
    return findings


class TestComplexityRule:
    def test_simple_function(self):
        code = """
def simple():
    print("hello")
    return True
"""
        rule = ComplexityRule(threshold=10)
        findings = check_code(rule, code)
        assert len(findings) == 0

    def test_warn_complexity(self):
        body = "\n".join([f"    if x == {i}: pass" for i in range(10)])
        code = f"def complex_warn(x):\n{body}"

        rule = ComplexityRule(threshold=10)
        findings = check_code(rule, code)

        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-Q301"
        assert findings[0]["value"] == 11
        assert findings[0]["severity"] == "WARN"
        assert "test_module.complex_warn" in findings[0]["name"]

    def test_high_complexity(self):
        body = "\n".join([f"    if x == {i}: pass" for i in range(20)])
        code = f"def complex_high(x):\n{body}"

        rule = ComplexityRule(threshold=10)
        findings = check_code(rule, code)

        assert len(findings) == 1
        assert findings[0]["value"] == 21
        assert findings[0]["severity"] == "HIGH"

    def test_critical_complexity(self):
        body = "\n".join([f"    if x == {i}: pass" for i in range(30)])
        code = f"def complex_critical(x):\n{body}"

        rule = ComplexityRule(threshold=10)
        findings = check_code(rule, code)

        assert len(findings) == 1
        assert findings[0]["value"] == 31
        assert findings[0]["severity"] == "CRITICAL"

    def test_async_function(self):
        body = "\n".join([f"    if x == {i}: pass" for i in range(10)])
        code = f"async def async_complex(x):\n{body}"

        rule = ComplexityRule(threshold=10)
        findings = check_code(rule, code)

        assert len(findings) == 1
        assert findings[0]["value"] == 11

    def test_boolean_operators_count(self):
        code = """
def bool_complexity(a, b, c, d, e, f, g, h, i, j, k):
    if a and b and c and d and e and f and g and h and i and j and k:
        pass
"""
        rule = ComplexityRule(threshold=10)
        findings = check_code(rule, code)

        assert len(findings) == 1
        assert findings[0]["value"] >= 12
