"""Static test-quality checks must preserve real runtime and helper checks."""

import ast
import textwrap
from types import SimpleNamespace

import pytest

from skylos.done.inventory import _dead_nodes
from skylos.rules.quality.test_assertions import (
    ConstantTestAssertionRule,
    EmptyTestRule,
)


def _check(rule, code, *, framework="pytest", fixture_backed=False):
    source = textwrap.dedent(code).lstrip("\n")
    tree = ast.parse(source)
    function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "test_case"
    )
    subject = SimpleNamespace(
        node=function,
        name="test_case",
        framework=framework,
        dead_nodes=frozenset(_dead_nodes(function)),
        fixture_backed=fixture_backed,
    )
    context = {
        "filename": "tests/test_example.py",
        "source": source,
        "_test_quality_module": tree,
    }
    return rule.check(subject, context)


@pytest.mark.parametrize(
    "condition",
    [
        "True",
        "1",
        "'ready'",
        "1 == 1",
        "2 > 1",
        "not False",
        "True and 3 > 2",
        "False or True",
        "1 + 1 == 2",
        "'a' in 'ready'",
        "None is None",
        "(False, 'message')",
        "[0]",
    ],
)
def test_constant_true_assertions_have_literal_source_proof(condition):
    findings = _check(
        ConstantTestAssertionRule(), f"def test_case():\n    assert {condition}\n"
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "SKY-L040"
    assert finding["severity"] == "LOW"
    assert finding["line"] == 2
    assert finding["evidence"]["constant_truth"] is True
    assert finding["evidence"]["proof"] == "literal-only constant expression"
    assert finding["evidence"]["review_action"]


@pytest.mark.parametrize(
    "condition",
    [
        "False",
        "0",
        "None",
        "''",
        "[]",
        "()",
        "1 == 2",
        "2 < 1",
        "value",
        "value == value",
        "value is value",
        "nan == nan",
        "float('nan') == float('nan')",
        "result.status == 200",
        "check_result()",
        "True or check_result()",
        "True or result",
        "(value, 'message')",
        "[check_result()]",
        "[item for item in values]",
        "(observed := True)",
        "f'{value}'",
        "{'ready': True}",
    ],
)
def test_runtime_and_false_conditions_are_not_claimed_constant_true(condition):
    assert not _check(
        ConstantTestAssertionRule(), f"def test_case():\n    assert {condition}\n"
    )


def test_assertion_message_is_not_executed_or_confused_with_its_condition():
    findings = _check(
        ConstantTestAssertionRule(),
        "def test_case():\n    assert True, build_failure_message()\n",
    )
    assert len(findings) == 1


@pytest.mark.parametrize(
    "body",
    [
        "if False:\n        assert True",
        "return\n    assert True",
        "try:\n        assert True\n    except AssertionError:\n        pass",
        "with contextlib.suppress(AssertionError):\n        assert True",
        "def helper():\n        assert True\n    helper()",
        "class Helper:\n        assert True\n    Helper()",
    ],
)
def test_dead_or_nested_assertions_do_not_become_test_findings(body):
    assert not _check(ConstantTestAssertionRule(), "def test_case():\n    " + body)


def test_async_runtime_branch_keeps_its_literal_assertion_visible():
    findings = _check(
        ConstantTestAssertionRule(),
        "async def test_case():\n    if await ready():\n        assert True\n",
    )
    assert [finding["line"] for finding in findings] == [3]


@pytest.mark.parametrize(
    "body",
    [
        "pass",
        "...",
        "'Reserved integration test.'",
        "'Reserved integration test.'\n    pass",
        "'Reserved integration test.'\n    ...\n    pass",
    ],
)
def test_only_literal_placeholder_bodies_are_empty_tests(body):
    findings = _check(EmptyTestRule(), "def test_case():\n    " + body)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-L041"
    assert findings[0]["line"] == 1
    assert findings[0]["severity"] == "LOW"
    assert findings[0]["evidence"]["body_kind"] == "literal_placeholders_only"


@pytest.mark.parametrize(
    "body",
    [
        "assert observed == expected",
        "assert_helper(observed)",
        "ping_service()",
        "with pytest.raises(ValueError):\n        parse_invalid_input()",
        "with self.assertRaises(ValueError):\n        parse_invalid_input()",
        "self.assertEqual(observed, expected)",
        "return smoke_probe()",
        "raise NotImplementedError",
        "def helper():\n        assert observed == expected\n    helper()",
        "value = build_result()",
        "if False:\n        assert observed",
        "pass\n    'A string after pass is not a docstring.'",
    ],
)
def test_helpers_raises_smoke_calls_and_runtime_work_are_not_empty(body):
    assert not _check(EmptyTestRule(), "def test_case():\n    " + body)


@pytest.mark.parametrize(
    "parameters", ["client", "client=None", "*, client", "*args", "**kwargs"]
)
def test_fixture_or_runtime_inputs_prevent_an_empty_test_claim(parameters):
    assert not _check(EmptyTestRule(), f"def test_case({parameters}):\n    pass\n")


def test_usefixtures_backed_placeholder_is_preserved():
    assert not _check(
        EmptyTestRule(), "def test_case():\n    pass\n", fixture_backed=True
    )


def test_unittest_bound_instance_does_not_hide_a_real_placeholder():
    findings = _check(
        EmptyTestRule(), "def test_case(self):\n    pass\n", framework="unittest"
    )
    assert len(findings) == 1
    assert not _check(
        EmptyTestRule(),
        "def test_case(self, extra=None):\n    pass\n",
        framework="unittest",
    )


def test_async_placeholder_is_reported_without_running_it():
    assert len(_check(EmptyTestRule(), "async def test_case():\n    ...\n")) == 1


@pytest.mark.parametrize(
    ("parameters", "expected"), [("self", 1), ("instance", 1), ("self, client", 0)]
)
def test_pytest_method_receiver_is_not_confused_with_fixture_inputs(
    tmp_path, parameters, expected
):
    source = f"class TestCases:\n    def test_case({parameters}):\n        pass\n"
    filename = tmp_path / "test_methods.py"
    filename.write_text(source, encoding="utf-8")
    findings = (
        EmptyTestRule().visit_node(
            ast.parse(source),
            {"filename": str(filename), "source": source, "project_root": tmp_path},
        )
        or []
    )
    assert len(findings) == expected
    if findings:
        assert findings[0]["name"] == "TestCases.test_case"
        assert findings[0]["line"] == 2
        assert "fixtures or setup" in findings[0]["message"]
        assert "skip" not in findings[0]["evidence"]["review_action"]


def test_oversized_literal_conditions_are_left_for_review():
    condition = " and ".join(["True"] * 130)
    assert not _check(
        ConstantTestAssertionRule(), f"def test_case():\n    assert {condition}\n"
    )


def test_module_visitor_parses_target_source_without_importing_it(tmp_path):
    marker = tmp_path / "executed"
    filename = tmp_path / "test_static_only.py"
    source = (
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed')\n"
        "def test_case():\n"
        "    assert True\n"
    )
    filename.write_text(source, encoding="utf-8")
    findings = ConstantTestAssertionRule().visit_node(
        ast.parse(source),
        {"filename": str(filename), "source": source, "project_root": tmp_path},
    )
    assert findings and findings[0]["line"] == 4
    assert not marker.exists()
