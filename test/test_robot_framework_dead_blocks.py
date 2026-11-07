"""Only potentially executed Robot rows prove object method usage."""

import json

import pytest

from skylos.analyzer import analyze


VALUES = """\
class Item:
    def used(self): return 1
    def unselected(self): return 2
class Other:
    def used(self): return 3
OBJ = Item()
OTHER = Other()
"""


def _scan(tmp_path, body, values=VALUES, extra=""):
    (tmp_path / "values.py").write_text(values)
    (tmp_path / "suite.robot").write_text(
        "*** Settings ***\nVariables    values.py\n"
        + extra
        + "*** Test Cases ***\nExample\n"
        + body
    )
    report = json.loads(
        analyze(
            str(tmp_path),
            conf=60,
            grep_verify=False,
            grep_cache=False,
            trace_file=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not report.get("analysis_errors")
    assert report["analysis_summary"]["total_files"] > 0
    roots = {
        row["name"]
        for row in report["analysis_summary"]["dead_code_liveness"]["rescued"]
        if row["reason"].startswith("robot_")
    }
    unused = {row["full_name"] for row in report["unused_functions"]}
    return roots, unused


def _precise(roots, unused):
    assert "values.Item.used" in roots
    assert "values.Item.used" not in unused
    assert "values.Item.unselected" not in roots
    assert "values.Item.unselected" in unused
    assert "values.Other.used" not in roots
    assert "values.Other.used" in unused


@pytest.mark.parametrize("condition", ["${False}", "False", "0", "0.0"])
def test_false_if_keeps_only_the_live_else(tmp_path, condition):
    roots, unused = _scan(
        tmp_path,
        f"    IF    {condition}\n        Log    ${{OBJ.unselected()}}\n"
        "    ELSE\n        Log    ${OBJ.used()}\n    END\n",
    )
    _precise(roots, unused)


def test_taken_if_does_not_evaluate_later_condition_or_else(tmp_path):
    roots, unused = _scan(
        tmp_path,
        "    IF    ${True}\n        Log    ${OBJ.used()}\n"
        "    ELSE IF    ${OBJ.unselected()}\n        No Operation\n"
        "    ELSE\n        Log    ${OBJ.unselected()}\n    END\n",
    )
    _precise(roots, unused)


def test_first_true_else_if_excludes_other_branches(tmp_path):
    roots, unused = _scan(
        tmp_path,
        "    IF    False\n        Log    ${OBJ.unselected()}\n"
        "    ELSE IF    1\n        Log    ${OBJ.used()}\n"
        "    ELSE\n        Log    ${OBJ.unselected()}\n    END\n",
    )
    _precise(roots, unused)


def test_nested_end_restores_the_enclosing_execution_state(tmp_path):
    roots, unused = _scan(
        tmp_path,
        "    IF    False\n        IF    True\n"
        "            Log    ${OBJ.unselected()}\n        END\n    END\n"
        "    Log    ${OBJ.used()}\n",
    )
    _precise(roots, unused)


@pytest.mark.parametrize("condition", ["${False}", "0"])
def test_false_while_body_is_dead(tmp_path, condition):
    roots, unused = _scan(
        tmp_path,
        f"    WHILE    {condition}\n        Log    ${{OBJ.unselected()}}\n"
        "    END\n    Log    ${OBJ.used()}\n",
    )
    _precise(roots, unused)


@pytest.mark.parametrize(
    "iteration",
    [
        "IN    @{EMPTY}",
        "IN    &{EMPTY}",
        "IN RANGE    0",
        "IN RANGE    2    2",
        "IN ENUMERATE    @{EMPTY}",
        "IN ZIP    @{EMPTY}    @{EMPTY}",
    ],
)
def test_empty_literal_for_body_is_dead(tmp_path, iteration):
    roots, unused = _scan(
        tmp_path,
        f"    FOR    ${{item}}    {iteration}\n"
        "        Log    ${OBJ.unselected()}\n    END\n"
        "    Log    ${OBJ.used()}\n",
    )
    _precise(roots, unused)


@pytest.mark.parametrize(
    "body",
    [
        "    WHILE    True\n        Log    ${OBJ.used()}\n        BREAK\n    END\n",
        "    FOR    ${item}    IN    value\n        Log    ${OBJ.used()}\n    END\n",
        "    FOR    ${item}    IN RANGE    1\n        Log    ${OBJ.used()}\n    END\n",
    ],
)
def test_nonempty_loops_keep_the_selected_method(tmp_path, body):
    _precise(*_scan(tmp_path, body))


@pytest.mark.parametrize(
    "body",
    [
        "    IF    False    Log    ${OBJ.unselected()}    ELSE    Log    ${OBJ.used()}\n",
        "    IF    True    Log    ${OBJ.used()}    ELSE    Log    ${OBJ.unselected()}\n",
        "    IF    0    Log    ${OBJ.unselected()}    ELSE IF    1    Log    ${OBJ.used()}    ELSE    Log    ${OBJ.unselected()}\n",
        "    IF    False    Log    ${OBJ.unselected()}\n    Log    ${OBJ.used()}\n",
    ],
)
def test_inline_if_filters_only_the_unreachable_segments(tmp_path, body):
    _precise(*_scan(tmp_path, body))


def test_unknown_condition_remains_conservative(tmp_path):
    roots, unused = _scan(
        tmp_path,
        "    IF    ${FLAG}\n        Log    ${OBJ.used()}\n"
        "    ELSE\n        Log    ${OBJ.unselected()}\n    END\n",
        VALUES + "import os\nFLAG = bool(os.getenv('FLAG'))\n",
    )
    assert {"values.Item.used", "values.Item.unselected"} <= roots
    assert "values.Other.used" in unused


def test_lowercase_keyword_named_if_is_not_a_native_block(tmp_path):
    roots, unused = _scan(
        tmp_path,
        "    if    ${False}\n    Log    ${OBJ.used()}\n",
        extra="*** Keywords ***\nif\n    [Arguments]    ${flag}\n    No Operation\n",
    )
    _precise(roots, unused)


def test_dead_assignment_does_not_replace_the_later_live_provider(tmp_path):
    roots, unused = _scan(
        tmp_path,
        "    IF    False\n        ${OBJ}=    Set Variable    replacement\n"
        "    END\n    Log    ${OBJ.used()}\n",
    )
    _precise(roots, unused)


def test_empty_loop_assignment_does_not_replace_the_provider(tmp_path):
    roots, unused = _scan(
        tmp_path,
        "    FOR    ${OBJ}    IN    @{EMPTY}\n        No Operation\n"
        "    END\n    Log    ${OBJ.used()}\n",
    )
    _precise(roots, unused)


def test_loop_binding_replaces_the_provider_in_reachable_body(tmp_path):
    roots, unused = _scan(
        tmp_path,
        "    FOR    ${OBJ}    IN    replacement\n        Log    ${OBJ.used()}\n    END\n",
    )
    assert "values.Item.used" not in roots
    assert "values.Item.used" in unused


def test_pipe_table_uses_the_same_block_guard(tmp_path):
    (tmp_path / "values.py").write_text(VALUES)
    (tmp_path / "suite.robot").write_text(
        "| *** Settings *** |\n| Variables | values.py |\n"
        "| *** Test Cases *** |\n| Example |\n"
        "| | IF | ${False} |\n| | Log | ${OBJ.unselected()} |\n"
        "| | ELSE |\n| | Log | ${OBJ.used()} |\n| | END |\n"
    )
    report = json.loads(
        analyze(
            str(tmp_path),
            grep_verify=False,
            grep_cache=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not report.get("analysis_errors")
    roots = {
        r["name"]
        for r in report["analysis_summary"]["dead_code_liveness"]["rescued"]
        if r["reason"].startswith("robot_")
    }
    _precise(roots, {r["full_name"] for r in report["unused_functions"]})


@pytest.mark.parametrize("block", ["TRY", "GROUP    example"])
def test_other_native_end_blocks_do_not_end_an_outer_false_if(tmp_path, block):
    roots, unused = _scan(
        tmp_path,
        f"    IF    False\n        {block}\n            No Operation\n        END\n"
        "        Log    ${OBJ.unselected()}\n    END\n    Log    ${OBJ.used()}\n",
    )
    _precise(roots, unused)


@pytest.mark.parametrize("value", [True, False])
def test_native_boolean_can_be_replaced_by_a_python_variable_provider(tmp_path, value):
    body = (
        "    IF    ${False}\n        Log    ${OBJ.used()}\n"
        "    ELSE\n        Log    ${OBJ.unselected()}\n    END\n"
    )
    roots, unused = _scan(tmp_path, body, VALUES + f"FALSE = {value}\n")
    selected, dead = ("used", "unselected") if value else ("unselected", "used")
    assert f"values.Item.{selected}" in roots
    assert f"values.Item.{selected}" not in unused
    assert f"values.Item.{dead}" not in roots
    assert f"values.Item.{dead}" in unused


def test_native_boolean_can_be_replaced_by_a_robot_variable_table(tmp_path):
    roots, unused = _scan(
        tmp_path,
        "    IF    ${False}\n        Log    ${OBJ.used()}\n    END\n",
        extra="*** Variables ***\n${False}    True\n",
    )
    _precise(roots, unused)


def test_native_empty_can_be_replaced_by_a_python_variable_provider(tmp_path):
    roots, unused = _scan(
        tmp_path,
        "    FOR    ${item}    IN    @{EMPTY}\n        Log    ${OBJ.used()}\n    END\n",
        VALUES + "EMPTY = (1,)\n",
    )
    _precise(roots, unused)


def test_test_local_boolean_write_does_not_leak_into_the_next_test(tmp_path):
    roots, unused = _scan(
        tmp_path,
        "    Set Test Variable    ${False}    ${True}\n"
        "Second\n    IF    ${False}\n        Log    ${OBJ.unselected()}\n"
        "    ELSE\n        Log    ${OBJ.used()}\n    END\n",
    )
    _precise(roots, unused)


@pytest.mark.parametrize("setter", ["Set Suite Variable", "Set Global Variable"])
def test_suite_boolean_write_can_affect_later_tests(tmp_path, setter):
    roots, unused = _scan(
        tmp_path,
        f"    {setter}    ${{False}}    ${{True}}\n"
        "Second\n    IF    ${False}\n        Log    ${OBJ.used()}\n    END\n",
    )
    _precise(roots, unused)


def test_mutated_python_empty_is_not_a_zero_iteration_proof(tmp_path):
    roots, unused = _scan(
        tmp_path,
        "    FOR    ${item}    IN    @{EMPTY}\n        Log    ${OBJ.used()}\n    END\n",
        VALUES + "EMPTY = []\nEMPTY.append(1)\n",
    )
    _precise(roots, unused)


def test_python_global_writer_is_not_a_false_boolean_proof(tmp_path):
    roots, unused = _scan(
        tmp_path,
        "    IF    ${False}\n        Log    ${OBJ.used()}\n    END\n",
        VALUES
        + "FALSE = False\ndef update():\n    global FALSE\n    FALSE = True\nupdate()\n",
    )
    _precise(roots, unused)


def test_unexported_boolean_does_not_override_the_native_value(tmp_path):
    roots, unused = _scan(
        tmp_path,
        "    IF    ${False}\n        Log    ${OBJ.unselected()}\n"
        "    ELSE\n        Log    ${OBJ.used()}\n    END\n",
        VALUES + 'FALSE = True\n__all__ = ["OBJ", "OTHER"]\n',
    )
    assert "values.Item.used" in roots
    assert "values.Item.unselected" not in roots
    assert "values.Other.used" not in roots
    # __all__ exposes the object instances to other consumers. Existing
    # receiver uncertainty can retain their methods independently of Robot.


@pytest.mark.parametrize("name", ["$False", r"\${False}", "${False}"])
@pytest.mark.parametrize(
    "setter",
    ["Set Test Variable", "BuiltIn.Set Test Variable", "BuiltIn.SetTestVariable"],
)
def test_setter_name_spellings_can_replace_native_booleans(tmp_path, name, setter):
    roots, unused = _scan(
        tmp_path,
        f"    {setter}    {name}    ${{True}}\n"
        "    IF    ${False}\n        Log    ${OBJ.used()}\n    END\n",
    )
    _precise(roots, unused)


@pytest.mark.parametrize("name", ["$OBJ", r"\${OBJ}", "${OBJ}"])
@pytest.mark.parametrize("setter", ["Set Test Variable", "BuiltIn.SetTestVariable"])
def test_setter_name_spellings_do_not_prove_the_replaced_receiver(
    tmp_path, name, setter
):
    roots, unused = _scan(
        tmp_path, f"    {setter}    {name}    ${{OTHER}}\n    Log    ${{OBJ.used()}}\n"
    )
    assert "values.Item.used" not in roots
    assert "values.Item.used" in unused
