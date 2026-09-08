"""Static lock-order regressions; no fixture locks or workers are executed."""

import ast
import json
from collections import Counter

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.quality.concurrency import (
    LOCK_ORDER_RULE_ID,
    LockOrderRule,
    _iter_lock_pairs,
)


def _function(name, groups, async_with=False):
    prefix = "async " if async_with else ""
    lines = [f"{prefix}def {name}():"]
    for depth, group in enumerate(groups, start=1):
        lines.append("    " * depth + f"{prefix}with {', '.join(group)}:")
    lines.append("    " * (len(groups) + 1) + "pass")
    return "\n".join(lines) + "\n"


def _findings(source):
    return LockOrderRule().visit_node(ast.parse(source), {"filename": "app.py"}) or []


def _pairs(groups, *, async_with=False, held=()):
    tree = ast.parse(_function("worker", groups, async_with))
    return Counter(
        (first, second, guards)
        for first, second, _, guards in _iter_lock_pairs(tree.body[0].body, held)
    )


@pytest.mark.parametrize("async_with", [False, True], ids=["with", "async-with"])
@pytest.mark.parametrize("reverse_functions", [False, True])
def test_reported_non_adjacent_reversal_is_detected(async_with, reverse_functions):
    functions = [
        _function("first", [("lock_a", "lock_b", "lock_c")], async_with),
        _function("second", [("lock_c", "lock_a")], async_with),
    ]
    if reverse_functions:
        functions.reverse()
    source = "".join(functions)
    findings = _findings(source)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == LOCK_ORDER_RULE_ID
    assert finding["severity"] == "HIGH"
    assert finding["file"] == "app.py"
    assert finding["line"] == 5
    assert "lock_a -> lock_c" in finding["message"]
    assert "lock_c -> lock_a" in finding["message"]


@pytest.mark.parametrize("async_with", [False, True])
def test_four_locks_record_all_six_pairs_with_correct_guards(async_with):
    actual = _pairs([("lock_a", "lock_b", "lock_c", "lock_d")], async_with=async_with)
    expected = Counter(
        {
            ("lock_a", "lock_b", frozenset()): 1,
            ("lock_a", "lock_c", frozenset()): 1,
            ("lock_a", "lock_d", frozenset()): 1,
            ("lock_b", "lock_c", frozenset({"lock_a"})): 1,
            ("lock_b", "lock_d", frozenset({"lock_a"})): 1,
            ("lock_c", "lock_d", frozenset({"lock_a", "lock_b"})): 1,
        }
    )
    assert actual == expected


@pytest.mark.parametrize("async_with", [False, True])
@pytest.mark.parametrize("held", [(), ("outer_lock", "outer_mutex")])
@pytest.mark.parametrize(
    "items",
    [
        ("lock_a", "lock_b", "lock_c"),
        ("lock_a", "lock_b", "lock_c", "lock_d"),
        ("lock_a", "lock_b", "lock_a", "lock_c"),
        ("lock_a", "resource()", "lock_b", "lock_c"),
        ("self.lock_a", "self.lock_b", "self.lock_c"),
        ("get_lock_a()", "get_lock_b()", "get_lock_c()"),
        ("lock_a as first", "lock_b as second", "lock_c as third"),
        ("resource() as lock_alias", "resource_b()"),
    ],
)
def test_compound_pairs_match_equivalent_nested_statements(items, held, async_with):
    compound = _pairs([items], held=held, async_with=async_with)
    nested = _pairs([(item,) for item in items], held=held, async_with=async_with)
    assert compound == nested
    assert all(first != second for first, second, _ in compound)


@pytest.mark.parametrize("async_with", [False, True])
@pytest.mark.parametrize(
    ("first_groups", "second_groups", "expected_count"),
    [
        (
            [("guard_lock", "lock_a", "lock_b", "lock_c")],
            [("guard_lock", "lock_c", "lock_a")],
            0,
        ),
        (
            [("guard_lock",), ("lock_a", "lock_b", "lock_c")],
            [("guard_lock",), ("lock_c", "lock_a")],
            0,
        ),
        (
            [("first_guard_lock",), ("lock_a", "lock_b", "lock_c")],
            [("second_guard_lock",), ("lock_c", "lock_a")],
            1,
        ),
        (
            [("guard_lock",), ("lock_a", "lock_b", "lock_c")],
            [("lock_c", "lock_a")],
            1,
        ),
    ],
    ids=[
        "shared-compound-guard",
        "shared-nested-guard",
        "different-guards",
        "one-guard",
    ],
)
def test_outer_guards_only_suppress_serialized_orders(
    first_groups, second_groups, expected_count, async_with
):
    source = _function("first", first_groups, async_with) + _function(
        "second", second_groups, async_with
    )
    findings = _findings(source)
    assert len(findings) == expected_count
    if expected_count:
        assert "lock_a -> lock_c" in findings[0]["message"]


@pytest.mark.parametrize("async_with", [False, True])
def test_intervening_lock_is_not_an_outer_guard(async_with):
    source = _function(
        "first", [("lock_a", "middle_lock", "lock_c")], async_with
    ) + _function("second", [("lock_c", "middle_lock", "lock_a")], async_with)
    findings = _findings(source)
    assert any(
        "lock_a -> lock_c" in finding["message"]
        and "lock_c -> lock_a" in finding["message"]
        for finding in findings
    )


@pytest.mark.parametrize("async_with", [False, True])
def test_consistent_non_adjacent_order_stays_clean(async_with):
    source = _function(
        "first", [("lock_a", "lock_b", "lock_c", "lock_d")], async_with
    ) + _function("second", [("lock_a", "lock_c", "lock_d")], async_with)
    assert _findings(source) == []


@pytest.mark.parametrize("async_with", [False, True])
def test_repeated_same_lock_does_not_create_a_self_pair(async_with):
    source = _function("worker", [("lock_a", "lock_a", "lock_a")], async_with)
    # Self-deadlock detection is outside this rule's reversed-pair heuristic.
    assert _findings(source) == []
    assert _pairs([("lock_a", "lock_a", "lock_a")], async_with=async_with) == Counter()


@pytest.mark.parametrize("async_with", [False, True])
def test_sequential_with_blocks_do_not_hold_locks_across_blocks(async_with):
    prefix = "async " if async_with else ""
    source = (
        f"{prefix}def first():\n"
        f"    {prefix}with lock_a:\n"
        "        pass\n"
        f"    {prefix}with lock_b, lock_c:\n"
        "        pass\n"
    ) + _function("second", [("lock_c", "lock_a")], async_with)
    assert _findings(source) == []


@pytest.mark.parametrize("async_with", [False, True])
def test_released_guard_does_not_suppress_a_later_reversal(async_with):
    prefix = "async " if async_with else ""
    source = (
        f"{prefix}def first():\n"
        f"    {prefix}with guard_lock:\n"
        "        pass\n"
        f"    {prefix}with lock_a, lock_b, lock_c:\n"
        "        pass\n"
    ) + _function("second", [("guard_lock", "lock_c", "lock_a")], async_with)
    findings = _findings(source)
    assert len(findings) == 1
    assert "lock_a -> lock_c" in findings[0]["message"]


@pytest.mark.parametrize("async_with", [False, True])
def test_non_adjacent_reversal_reaches_analyzer_json(tmp_path, monkeypatch, async_with):
    from skylos.analyzer import analyze

    source = _function(
        "first", [("lock_a", "lock_b", "lock_c")], async_with
    ) + _function("second", [("lock_c", "lock_a")], async_with)
    path = tmp_path / "app.py"
    assert write_text_no_symlink(path, source, encoding="utf-8")
    monkeypatch.setenv("SKYLOS_JOBS", "1")

    result = json.loads(analyze(str(tmp_path), enable_quality=True, grep_verify=False))
    findings = [
        finding
        for finding in result.get("quality", [])
        if finding["rule_id"] == LOCK_ORDER_RULE_ID
    ]
    assert len(findings) == 1
    assert findings[0]["file"] == str(path)
    assert findings[0]["line"] == 5
    assert "lock_a -> lock_c" in findings[0]["message"]
