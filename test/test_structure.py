import ast
from skylos.rules.quality.structure import ArgCountRule, FunctionLengthRule


def check_code(rule, code, filename="test.py", project_root=None):
    tree = ast.parse(code)
    findings = []
    # The quality scan always passes the source; C304 reads comments from it.
    context = {
        "filename": filename,
        "mod": "test_mod",
        "source": code,
        "project_root": project_root,
    }

    for node in ast.walk(tree):
        res = rule.visit_node(node, context)
        if res:
            findings.extend(res)
    return findings


class TestArgCountRule:
    def test_required_parameters_do_not_imply_positional_call_order(self):
        code = (
            "def configure(a, b, c, d, e, f): pass\n"
            "configure(f=6, e=5, d=4, c=3, b=2, a=1)\n"
        )
        [finding] = check_code(ArgCountRule(), code)
        assert finding["value"] == 6
        assert finding["argument_evidence"]["positional_or_keyword"] == 6
        assert "Callers must pass" not in finding["message"]
        assert "actual call sites" in finding["message"]

    def test_positional_only_signature_keeps_the_same_measurement(self):
        [finding] = check_code(
            ArgCountRule(), "def configure(a, b, c, d, e, f, /): pass\n"
        )
        assert finding["value"] == 6
        assert finding["argument_evidence"]["positional_only"] == 6
        assert finding["argument_evidence"]["positional_or_keyword"] == 0

    def test_too_many_args(self):
        code = """
def my_func(self, b, c, d, e, f):
    pass
        """
        rule = ArgCountRule(max_args=5)

        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-C303"
        assert findings[0]["value"] == 6
        assert "Function has 6 required positional arguments" in findings[0]["message"]

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
    def instance_method(this, a, b, c, d, e, /):
        pass
    
    @classmethod
    def class_method(owner, a, b, c, d, e, /):
        pass
"""
        rule = ArgCountRule(max_args=5)
        findings = check_code(rule, code)
        assert len(findings) == 0

    def test_counts_kwonly_args_toward_total_only(self):
        code = """
class Service:
    @custom
    def my_func(this, a, b, *, c, d, e, f):
        pass
        """
        rule = ArgCountRule(max_args=5, max_total=5)

        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["value"] == 6
        assert findings[0]["severity"] == "LOW"
        assert "at least 6 total parameters" in findings[0]["message"]
        assert "4 keyword-only" in findings[0]["message"]
        assert findings[0]["required_argument_range"] == [2, 3]
        assert findings[0]["total_parameter_range"] == [6, 7]

    def test_required_kwonly_args_are_not_positional_arity(self):
        code = """
def configure(*, host, port, user, password, database, timeout):
    pass
        """
        rule = ArgCountRule(max_args=5)

        assert check_code(rule, code) == []

    def test_total_breakdown_names_keyword_only(self):
        code = """
def wide(a, *, b, c, d, e, f, g, h, i, j, k=1):
    pass
        """
        findings = check_code(ArgCountRule(max_args=5), code)

        assert len(findings) == 1
        assert findings[0]["value"] == 11
        assert findings[0]["severity"] == "LOW"
        assert (
            "(1 required positional, 0 optional positional, 10 keyword-only)"
            in findings[0]["message"]
        )

    def test_skips_test_and_example_code(self, tmp_path):
        code = """
def helper(a, b, c, d, e, f, g):
    pass
        """
        rule = ArgCountRule(max_args=5)

        (tmp_path / "pyproject.toml").write_text('[project]\nname="fixture-app"\n')
        (tmp_path / "examples").mkdir()
        (tmp_path / "examples" / "demo.py").write_text(code)
        assert check_code(rule, code, "tests/helpers.py", tmp_path) == []
        assert check_code(rule, code, "examples/demo.py", tmp_path) == []
        assert len(check_code(rule, code, "src/app.py", tmp_path)) == 1

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

    def test_counts_code_lines_not_comments_blanks_or_docstrings(self):
        lines = ["def padded():", '    """Doc.', *["    doc"] * 10, '    """']
        for i in range(45):
            lines += [f"    # step {i}", f"    x{i} = {i}", ""]
        code = "\n".join(lines) + "\n"

        findings = check_code(FunctionLengthRule(max_lines=50), code)

        assert findings == []

    def test_nested_docstrings_are_not_code(self):
        lines = ["def outer():", "    def inner():", '        """Doc.']
        lines += ["        doc"] * 60
        lines += ['        """', "        return 1", "    return inner"]
        code = "\n".join(lines) + "\n"

        assert check_code(FunctionLengthRule(max_lines=10), code) == []

    def test_reports_code_lines_from_def_line(self):
        body = "\n".join(f"    v{i} = {i}" for i in range(55))
        code = f"@decorator\ndef long_func():\n    # note\n\n{body}\n"

        findings = check_code(FunctionLengthRule(max_lines=50), code)

        assert len(findings) == 1
        assert findings[0]["value"] == 56
        assert "Function has 56 code lines (limit: 50)" in findings[0]["message"]

    def test_medium_severity_for_medium_function(self):
        body = "\n".join([f"   print({i})" for i in range(60)])
        code = f"def medium_func():\n{body}"

        rule = FunctionLengthRule(max_lines=50)
        findings = check_code(rule, code)

        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"
