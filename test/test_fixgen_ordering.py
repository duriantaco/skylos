"""Ordering checks use inert source text; fixture modules never execute."""

import ast
from itertools import permutations

import pytest

from skylos.remediation.fixgen import (
    _build_dependency_dag,
    _topological_sort,
    apply_patches,
    generate_removal_plan,
    generate_unified_diff,
    validate_patches,
)


CHAIN = {"A": ["B"], "B": ["C"], "C": ["D"], "D": []}
DIAMOND = {"A": ["B", "C"], "B": ["D"], "C": ["D"], "D": []}
KEY_ORDERS = list(permutations("ABCD"))


def _assert_edge_order(dag, result):
    assert len(result) == len(dag)
    assert set(result) == set(dag)
    positions = {name: index for index, name in enumerate(result)}
    for caller, callees in dag.items():
        for callee in callees:
            if callee in dag:
                assert positions[caller] < positions[callee], (dag, result)


def test_reversed_chain_matches_issue_816():
    dag = {"D": [], "C": ["D"], "B": ["C"], "A": ["B"]}
    assert _topological_sort(dag) == ["A", "B", "C", "D"]


@pytest.mark.parametrize("graph", [CHAIN, DIAMOND], ids=["chain", "diamond"])
@pytest.mark.parametrize("keys", KEY_ORDERS, ids=lambda keys: "".join(keys))
def test_every_chain_and_diamond_key_order_respects_edges(graph, keys):
    dag = {key: list(graph[key]) for key in keys}
    snapshot = {key: list(value) for key, value in dag.items()}
    _assert_edge_order(dag, _topological_sort(dag))
    assert dag == snapshot


@pytest.mark.parametrize(
    "dag",
    [
        {"D": [], "C": ["D"], "B": ["C", "C"], "A": ["B"]},
        {"D": [], "C": ["D"], "B": ["C"], "A": ["B", "external"]},
        {"isolated": [], "C": [], "B": ["C"], "A": ["B"]},
    ],
    ids=["duplicate-edge", "external-callee", "disconnected"],
)
def test_edge_controls_keep_only_selected_nodes(dag):
    _assert_edge_order(dag, _topological_sort(dag))


def test_dependency_builder_filters_external_and_self_calls():
    findings = [{"full_name": name} for name in "DCBA"]
    definitions = {name: {"calls": list(callees)} for name, callees in CHAIN.items()}
    definitions["A"]["calls"] = ["B", "B", "external", "A"]
    definitions["D"]["calls"] = ["D", "external"]
    dag = _build_dependency_dag(findings, definitions)
    assert dag["A"] == ["B", "B"]
    assert dag["D"] == []
    _assert_edge_order(dag, _topological_sort(dag))


@pytest.mark.parametrize(
    "dag",
    [
        {"A": ["A"]},
        {"B": ["A"], "A": ["B"]},
        {"C": [], "B": ["A", "C"], "A": ["B"], "D": ["D"]},
    ],
    ids=["self-cycle", "mutual-cycle", "cycles-with-tail"],
)
def test_cycles_are_deterministic_and_include_each_node_once(dag):
    expected = _topological_sort(dag)
    assert len(expected) == len(dag)
    assert set(expected) == set(dag)
    # A cycle cannot satisfy every edge. Require repeatability for this input,
    # not a particular cycle order or an impossible topological guarantee.
    for _ in range(3):
        assert _topological_sort(dag) == expected


def _removal_fixture(tmp_path, cross_file):
    if cross_file:
        sources = {
            "callers.py": (
                "from helpers import C\n\n"
                "def A():\n    return B()\n\n"
                "def B():\n    return C()\n\n"
                "KEEP_LIVE = 7\n"
            ),
            "helpers.py": (
                "def C():\n    return D()\n\ndef D():\n    return 4\n\nKEEP_LIVE = 7\n"
            ),
        }
    else:
        sources = {
            "module.py": (
                "def A():\n    return B()\n\n"
                "def B():\n    return C()\n\n"
                "def C():\n    return D()\n\n"
                "def D():\n    return 4\n\n"
                "KEEP_LIVE = 7\n"
            )
        }
    originals = {}
    findings = []
    definitions = {name: {"calls": list(callees)} for name, callees in CHAIN.items()}
    for filename, source in sources.items():
        path = tmp_path / filename
        with path.open("x", encoding="utf-8") as stream:
            stream.write(source)
        originals[str(path)] = source
        for node in ast.parse(source).body:
            if isinstance(node, ast.FunctionDef):
                name, kind = node.name, "function"
            elif isinstance(node, ast.ImportFrom):
                # Remove the selected import too, so no dangling import remains.
                name, kind = "C_import", "import"
                definitions[name] = {"calls": ["C"]}
            else:
                continue
            findings.append(
                {
                    "full_name": name,
                    "type": kind,
                    "file": str(path),
                    "line": node.lineno,
                }
            )
    return originals, findings, definitions


@pytest.mark.parametrize("cross_file", [False, True], ids=["same-file", "cross-file"])
@pytest.mark.parametrize("mode", ["delete", "comment"])
def test_plan_diff_and_application_keep_bottom_up_order(tmp_path, cross_file, mode):
    originals, findings, definitions = _removal_fixture(tmp_path, cross_file)
    orders = [
        findings,
        list(reversed(findings)),
        findings[1:] + findings[:1],
        findings[::2] + findings[1::2],
    ]
    expected = None
    for order in orders:
        plan = generate_removal_plan(order, definitions, tmp_path, mode=mode)
        assert len(plan) == len(findings)
        assert [(p.file_path, -p.line_range[0]) for p in plan] == sorted(
            (p.file_path, -p.line_range[0]) for p in plan
        )
        for earlier, later in zip(plan, plan[1:]):
            if earlier.file_path == later.file_path:
                assert later.line_range[1] < earlier.line_range[0]
        diff = generate_unified_diff(plan, tmp_path)
        dry = apply_patches(plan, tmp_path, dry_run=True, backup=False)
        assert diff
        assert validate_patches(plan, tmp_path) == []
        assert apply_patches(list(reversed(plan)), tmp_path, dry_run=True) == dry
        snapshot = (plan, diff, dry)
        if expected is None:
            expected = snapshot
        else:
            assert snapshot == expected
        for filename, source in originals.items():
            assert (tmp_path / filename).read_text(encoding="utf-8") == source

    plan, _, dry = expected
    applied = apply_patches(plan, tmp_path, dry_run=False, backup=False)
    assert applied == dry
    expected_ast = ast.dump(ast.parse("KEEP_LIVE = 7\n"))
    for filename, content in applied.items():
        assert (tmp_path / filename).read_text(encoding="utf-8") == content
        assert ast.dump(ast.parse(content)) == expected_ast
    assert not list(tmp_path.glob("*.bak"))
