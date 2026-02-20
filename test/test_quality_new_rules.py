import ast
from skylos.rules.quality.logic import UnusedExceptVarRule, ReturnConsistencyRule
from skylos.rules.quality.class_size import GodClassRule


def check_code(rule, code, filename="test.py"):
    tree = ast.parse(code)
    findings = []
    context = {"filename": filename, "mod": "test_module"}
    for node in ast.walk(tree):
        res = rule.visit_node(node, context)
        if res:
            findings.extend(res)
    return findings


# ── UnusedExceptVarRule (SKY-L005) ──────────────────────────────────


class TestUnusedExceptVar:
    def test_unused_exception_variable(self):
        code = "try:\n    pass\nexcept ValueError as e:\n    print('oops')\n"
        findings = check_code(UnusedExceptVarRule(), code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-L005"
        assert "e" in findings[0]["message"]

    def test_used_exception_variable(self):
        code = "try:\n    pass\nexcept ValueError as e:\n    print(e)\n"
        findings = check_code(UnusedExceptVarRule(), code)
        assert len(findings) == 0

    def test_bare_except_no_var(self):
        code = "try:\n    pass\nexcept:\n    pass\n"
        findings = check_code(UnusedExceptVarRule(), code)
        assert len(findings) == 0

    def test_underscore_convention(self):
        code = "try:\n    pass\nexcept ValueError as _:\n    print('ignored')\n"
        # _ is still flagged — no special-casing (user can suppress via skylos:ignore)
        findings = check_code(UnusedExceptVarRule(), code)
        assert len(findings) == 1

    def test_multiple_except_one_unused(self):
        code = (
            "try:\n"
            "    pass\n"
            "except ValueError as e:\n"
            "    print('oops')\n"
            "except TypeError as e2:\n"
            "    print(e2)\n"
        )
        findings = check_code(UnusedExceptVarRule(), code)
        # e is unused, e2 is used
        assert len(findings) == 1
        assert findings[0]["name"] == "e"

    def test_used_in_logging(self):
        code = (
            "import logging\n"
            "try:\n"
            "    pass\n"
            "except Exception as exc:\n"
            "    logging.error(exc)\n"
        )
        findings = check_code(UnusedExceptVarRule(), code)
        assert len(findings) == 0


# ── ReturnConsistencyRule (SKY-L006) ────────────────────────────────


class TestReturnConsistency:
    def test_inconsistent_explicit_return_vs_bare_return(self):
        """return value on one path, bare return on another."""
        code = "def f(x):\n    if x > 0:\n        return x * 2\n    return\n"
        findings = check_code(ReturnConsistencyRule(), code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-L006"
        assert "inconsistent" in findings[0]["message"].lower()

    def test_consistent_return_value(self):
        code = "def f(x):\n    if x > 0:\n        return x * 2\n    return 0\n"
        findings = check_code(ReturnConsistencyRule(), code)
        assert len(findings) == 0

    def test_consistent_return_none(self):
        code = "def f(x):\n    if x > 0:\n        return\n    return\n"
        findings = check_code(ReturnConsistencyRule(), code)
        assert len(findings) == 0

    def test_explicit_return_none_mixed(self):
        code = "def f(x):\n    if x > 0:\n        return x\n    return None\n"
        findings = check_code(ReturnConsistencyRule(), code)
        assert len(findings) == 1

    def test_async_function_inconsistent(self):
        code = "async def f(x):\n    if x > 0:\n        return x\n    return\n"
        findings = check_code(ReturnConsistencyRule(), code)
        assert len(findings) == 1

    def test_nested_function_not_confused(self):
        code = (
            "def outer(x):\n"
            "    def inner():\n"
            "        return 42\n"
            "    if x:\n"
            "        return x\n"
            "    return 0\n"
        )
        findings = check_code(ReturnConsistencyRule(), code)
        assert len(findings) == 0

    def test_only_implicit_return_no_flag(self):
        """Only one return path + implicit None — rule doesn't detect implicit."""
        code = "def f(x):\n    if x > 0:\n        return x * 2\n"
        findings = check_code(ReturnConsistencyRule(), code)
        assert len(findings) == 0


# ── GodClassRule (SKY-Q501) ─────────────────────────────────────────


class TestGodClass:
    def _make_big_class(self, method_count, attr_count):
        """Generate a class with method_count methods, each setting a unique attr."""
        methods = ""
        for i in range(method_count):
            methods += f"    def m{i}(self):\n        self.attr{i} = {i}\n"
        # If we need more attrs than methods, pack extras into __init__
        if attr_count > method_count:
            init_body = ""
            for i in range(method_count, attr_count):
                init_body += f"        self.attr{i} = {i}\n"
            methods = f"    def __init__(self):\n{init_body}" + methods
        return f"class BigClass:\n{methods}"

    def test_too_many_methods(self):
        code = self._make_big_class(method_count=21, attr_count=5)
        findings = check_code(GodClassRule(), code)
        rule_ids = [f["rule_id"] for f in findings]
        assert "SKY-Q501" in rule_ids
        method_finding = [
            f for f in findings if isinstance(f["value"], int) and f["value"] >= 21
        ][0]
        assert method_finding["threshold"] == 20

    def test_too_many_attributes(self):
        code = self._make_big_class(method_count=5, attr_count=16)
        findings = check_code(GodClassRule(), code)
        rule_ids = [f["rule_id"] for f in findings]
        assert "SKY-Q501" in rule_ids
        attr_finding = [f for f in findings if f["value"] == 16][0]
        assert attr_finding["threshold"] == 15

    def test_both_violations(self):
        code = self._make_big_class(method_count=21, attr_count=16)
        findings = check_code(GodClassRule(), code)
        assert len(findings) == 2

    def test_small_class_safe(self):
        code = (
            "class SmallClass:\n"
            "    def __init__(self):\n"
            "        self.x = 1\n"
            "    def do_thing(self):\n"
            "        pass\n"
        )
        findings = check_code(GodClassRule(), code)
        assert len(findings) == 0

    def test_custom_thresholds(self):
        code = self._make_big_class(method_count=6, attr_count=4)
        findings = check_code(GodClassRule(max_methods=5, max_attributes=3), code)
        # 6 methods > 5 limit, 6 attrs > 3 limit
        method_findings = [
            f
            for f in findings
            if isinstance(f["value"], int) and f["value"] >= 6 and f["threshold"] == 5
        ]
        attr_findings = [
            f
            for f in findings
            if isinstance(f["value"], int) and f["value"] >= 4 and f["threshold"] == 3
        ]
        assert len(method_findings) >= 1
        assert len(attr_findings) >= 1
