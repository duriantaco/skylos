import ast
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.quality.logic import UnusedExceptVarRule, ReturnConsistencyRule
from skylos.rules.quality.class_size import GodClassRule, GodFileRule
from skylos.rules.quality import clones


def _write_project_source(root, relative, source):
    assert write_text_no_symlink(
        root / "pyproject.toml", '[project]\nname="fixture-app"\n'
    )
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, source, encoding="utf-8")


def check_code(rule, code, filename="test.py", project_root=None):
    tree = ast.parse(code)
    findings = []
    context = {
        "filename": filename,
        "mod": "test_module",
        "source": code,
        "project_root": project_root,
    }
    for node in ast.walk(tree):
        res = rule.visit_node(node, context)
        if res:
            findings.extend(res)
    return findings


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

    def test_underscore_convention_is_not_flagged(self):
        code = "try:\n    raise ValueError\nexcept ValueError as _:\n    pass\n"
        findings = check_code(UnusedExceptVarRule(), code)
        assert len(findings) == 0

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


class TestReturnConsistency:
    def test_inconsistent_explicit_return_vs_bare_return(self):
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

    def test_explicit_return_none_mixed_is_consistent(self):
        # PEP 8 asks for exactly this: an explicit ``return None``.
        code = "def f(x):\n    if x > 0:\n        return x\n    return None\n"
        findings = check_code(ReturnConsistencyRule(), code)
        assert len(findings) == 0

    def test_bare_return_next_to_explicit_none_still_flagged(self):
        code = (
            "def f(x):\n"
            "    if x > 0:\n"
            "        return x\n"
            "    if x < 0:\n"
            "        return None\n"
            "    return\n"
        )
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
        code = "def f(x):\n    if x > 0:\n        return x * 2\n"
        findings = check_code(ReturnConsistencyRule(), code)
        assert len(findings) == 0


class TestGodClass:
    def _make_big_class(self, method_count, attr_count):
        methods = ""
        for i in range(method_count):
            methods += f"    def m{i}(self):\n        self.attr{i} = {i}\n"
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
        code = code.replace("(self)", "(this, /)").replace("self.", "this.")
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
            "        def update_other(self):\n"
            + "".join(f"            self.other{i} = None\n" for i in range(16))
        )
        findings = check_code(GodClassRule(), code)
        assert len(findings) == 0

    def test_dunder_methods_do_not_count_toward_method_limit(self):
        dunders = [f"__d{i}__" for i in range(10)]
        body = "".join(f"    def {name}(self):\n        return 1\n" for name in dunders)
        body += "".join(f"    def m{i}(self):\n        return 1\n" for i in range(20))
        code = f"class Mapping:\n{body}"

        assert check_code(GodClassRule(), code) == []

        code += "    def m20(self):\n        return 1\n"
        findings = check_code(GodClassRule(), code)
        assert len(findings) == 1
        assert findings[0]["value"] == 21
        assert findings[0]["dunder_methods"] == 10
        assert "dunder protocol methods are not counted" in findings[0]["message"]

    def test_skips_test_and_example_code(self, tmp_path):
        code = self._make_big_class(method_count=21, attr_count=16)

        collected = code.replace("class BigClass:", "class TestBigClass:").replace(
            "def m", "def test_m"
        )
        assert check_code(GodClassRule(), collected, "tests/test_big.py", tmp_path) == []
        # A folder name does not make an ordinary helper a collected test.
        assert len(check_code(GodClassRule(), code, "tests/test_big.py", tmp_path)) == 2
        _write_project_source(tmp_path, "examples/big.py", code)
        assert check_code(GodClassRule(), code, "examples/big.py", tmp_path) == []
        assert len(check_code(GodClassRule(), code, "pkg/big.py", tmp_path)) == 2

    def test_custom_thresholds(self):
        code = self._make_big_class(method_count=6, attr_count=4)
        findings = check_code(GodClassRule(max_methods=5, max_attributes=3), code)
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


class TestGodFile:
    def test_too_many_code_lines(self):
        code = "\n".join(f"x{i} = {i}" for i in range(11))
        findings = check_code(
            GodFileRule(
                max_lines=10,
                max_definitions=99,
                max_top_level_definitions=99,
            ),
            code,
        )

        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-Q502"
        assert findings[0]["metric"] == "code_lines"
        assert findings[0]["value"] == 11
        assert findings[0]["threshold"] == 10

    def test_too_many_definitions(self):
        code = "\n".join(f"def f{i}():\n    return {i}" for i in range(6))
        findings = check_code(
            GodFileRule(
                max_lines=99,
                max_definitions=5,
                max_top_level_definitions=99,
            ),
            code,
        )

        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-Q502"
        assert findings[0]["metric"] == "total_definitions"
        assert findings[0]["total_definitions"] == 6
        assert findings[0]["top_level_definitions"] == 6

    def test_docstring_lines_are_not_code_lines(self):
        doc = '"""Module doc.\n' + "doc line\n" * 20 + '"""\n'
        func = 'def f():\n    """Doc.\n' + "    more\n" * 10 + '    """\n    return 1\n'
        code = doc + "# a comment\n\n" + func
        rule = GodFileRule(max_lines=2, max_definitions=99, max_top_level_definitions=99)

        assert check_code(rule, code) == []

        code += "x = 1\n"
        findings = check_code(rule, code)
        assert findings[0]["code_lines"] == 3
        assert "3 code lines, not counting blank, comment or docstring lines" in (
            findings[0]["message"]
        )

    def test_nested_functions_are_not_definitions(self):
        code = "".join(
            f"def outer{i}():\n    def inner():\n        return 1\n    return inner\n"
            for i in range(3)
        )
        code += "class Box:\n    def get(self):\n        return 1\n"
        findings = check_code(
            GodFileRule(max_lines=99, max_definitions=4, max_top_level_definitions=99),
            code,
        )

        assert len(findings) == 1
        assert findings[0]["total_definitions"] == 5
        assert findings[0]["class_count"] == 1
        assert findings[0]["function_count"] == 4
        assert "5 classes, functions and methods outside function bodies" in (
            findings[0]["message"]
        )

    def test_skips_test_and_example_code(self, tmp_path):
        code = "\n".join(f"def f{i}():\n    return {i}" for i in range(6))
        rule = GodFileRule(max_lines=99, max_definitions=5, max_top_level_definitions=99)

        assert check_code(rule, code, "tests/test_many.py", tmp_path) == []
        _write_project_source(tmp_path, "examples/many.py", code)
        assert check_code(rule, code, "examples/many.py", tmp_path) == []
        assert len(check_code(rule, code, "pkg/many.py", tmp_path)) == 1

    def test_small_file_safe(self):
        code = (
            "def load_user():\n"
            "    return 1\n\n"
            "class UserService:\n"
            "    def get(self):\n"
            "        return load_user()\n"
        )
        findings = check_code(
            GodFileRule(
                max_lines=20,
                max_definitions=10,
                max_top_level_definitions=10,
            ),
            code,
        )

        assert len(findings) == 0


class TestCloneFragments:
    def _fragments(self, code, path, project_root=None):
        from pathlib import Path

        return clones.extract_fragments(
            Path(path), code, clones.CloneConfig(), project_root=project_root
        )

    def test_docstring_and_comment_padding_do_not_reach_size_gate(self):
        code = (
            "def padded(value):\n"
            '    """Doc.\n\n    line\n    line\n    line\n    """\n'
            "    # comment\n"
            "    first = value + 1\n"
            "    # comment\n"
            "    second = first * 2\n"
            "    return second\n"
        )
        assert self._fragments(code, "pkg/padded.py") == []

    def test_long_signature_over_one_statement_is_not_a_fragment(self):
        params = "".join(f"        p{i},\n" for i in range(8))
        args = "".join(f"            p{i},\n" for i in range(5))
        code = (
            f"def build(\n{params}):\n"
            f"    return make(\n{args}    )\n"
        )
        assert self._fragments(code, "pkg/forward.py") == []

    def test_four_statements_over_eight_code_lines_is_a_fragment(self):
        code = (
            "def merge(base, extra):\n"
            "    merged = dict(base)\n"
            "    for key, value in extra.items():\n"
            "        merged[key] = value\n"
            "    return sorted(\n"
            "        merged.items(),\n"
            "        key=str,\n"
            "    )\n"
        )
        fragments = self._fragments(code, "pkg/merge.py")
        assert [fragment.name for fragment in fragments] == ["merge"]

    def test_test_code_is_skipped_by_project_relative_path(self, tmp_path):
        code = (
            "def merge(base, extra):\n"
            "    merged = dict(base)\n"
            "    for key, value in extra.items():\n"
            "        merged[key] = value\n"
            "    return sorted(\n"
            "        merged.items(),\n"
            "        key=str,\n"
            "    )\n"
        )
        app_named_test = tmp_path / "pkg" / "test_helpers.py"
        app_named_test.parent.mkdir()
        app_named_test.write_text(code)

        # Extraction retains test fragments: group analysis can then keep
        # mixed groups and test modules imported by production code.
        assert len(self._fragments(code, tmp_path / "tests" / "x.py", tmp_path)) == 1
        assert len(self._fragments(code, tmp_path / "conftest.py", tmp_path)) == 1
        _write_project_source(tmp_path, "examples/x.py", code)
        _write_project_source(tmp_path, "docs/x.py", code)
        assert self._fragments(code, tmp_path / "examples" / "x.py", tmp_path) == []
        assert self._fragments(code, tmp_path / "docs" / "x.py", tmp_path) == []
        # Shipped code named test_* without a test framework is still scanned.
        assert len(self._fragments(code, app_named_test, tmp_path)) == 1

    def test_member_label_uses_project_relative_path(self, tmp_path):
        fragment = clones.Fragment(
            file_path=str(tmp_path / "tests" / "a" / "x.py"),
            start_line=3,
            end_line=12,
            name="Spider",
            kind="class",
            node_count=20,
            text_norm="",
            ast_norm_type2="",
            ast_norm_type3="",
        )

        assert (
            clones.clone_member_label(fragment, tmp_path)
            == "tests/a/x.py:3-12 (class Spider)"
        )
