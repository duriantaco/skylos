"""Tests for CWE mapping, new quality rules, and SARIF CWE output."""

from __future__ import annotations

import ast
import json
import textwrap

import pytest

from skylos.rules.quality.standards import (
    CWE_MAP,
    STANDARD_REFS,
    enrich_finding,
    get_cwe_taxa,
)
from skylos.rules.quality.logic import (
    DuplicateStringLiteralRule,
    TooManyReturnsRule,
    BooleanTrapRule,
)
from skylos.sarif_exporter import SarifExporter


# ---------------------------------------------------------------------------
# CWE mapping
# ---------------------------------------------------------------------------


class TestCWEMapping:
    def test_all_logic_rules_mapped(self):
        for rid in ["SKY-L001", "SKY-L002", "SKY-L007", "SKY-L011", "SKY-L014"]:
            assert rid in CWE_MAP, f"{rid} missing from CWE_MAP"

    def test_multi_cwe_rule(self):
        assert len(CWE_MAP["SKY-L011"]) == 2

    def test_complexity_rules_mapped(self):
        assert "SKY-Q301" in CWE_MAP
        assert "SKY-Q302" in CWE_MAP

    def test_standard_refs(self):
        assert "McCabe Cyclomatic Complexity" in STANDARD_REFS["SKY-Q301"]
        assert "ISO/IEC 9126" in STANDARD_REFS["SKY-Q702"]


class TestEnrichFinding:
    def test_enriches_known_rule(self):
        f = {"rule_id": "SKY-L008"}
        enrich_finding(f)
        assert f["cwe"] == [
            {
                "id": "CWE-772",
                "name": "Missing Release of Resource after Effective Lifetime",
            }
        ]

    def test_enriches_with_standard_refs(self):
        f = {"rule_id": "SKY-Q701"}
        enrich_finding(f)
        assert "CK Metrics: CBO (Coupling Between Objects)" in f["standard_refs"]

    def test_unknown_rule_gets_empty(self):
        f = {"rule_id": "CUSTOM-FOO"}
        enrich_finding(f)
        assert f["cwe"] == []
        assert f["standard_refs"] == []


class TestGetCWETaxa:
    def test_returns_unique_entries(self):
        taxa = get_cwe_taxa()
        ids = [t["id"] for t in taxa]
        assert len(ids) == len(set(ids))

    def test_entry_format(self):
        taxa = get_cwe_taxa()
        for t in taxa:
            assert "id" in t
            assert "name" in t
            assert "shortDescription" in t
            assert "text" in t["shortDescription"]


# ---------------------------------------------------------------------------
# DuplicateStringLiteralRule (SKY-L027)
# ---------------------------------------------------------------------------


class TestDuplicateStringLiteralRule:
    def _run(self, code, threshold=3):
        rule = DuplicateStringLiteralRule(threshold=threshold)
        tree = ast.parse(textwrap.dedent(code))
        ctx = {"filename": "app.py"}
        return rule.visit_node(tree, ctx)

    def test_detects_duplicates(self):
        code = """
x = "hello world"
y = "hello world"
z = "hello world"
"""
        results = self._run(code)
        assert results is not None
        assert len(results) == 1
        assert results[0]["value"] == 3
        assert results[0]["severity"] == "LOW"

    def test_escalates_severity(self):
        code = "\n".join([f'x{i} = "repeated string"' for i in range(7)])
        results = self._run(code)
        assert results[0]["severity"] == "MEDIUM"

    def test_skips_short_strings(self):
        code = """
a = "ab"
b = "ab"
c = "ab"
"""
        assert self._run(code) is None

    def test_skips_test_files(self):
        rule = DuplicateStringLiteralRule()
        code = """
x = "hello world"
y = "hello world"
z = "hello world"
"""
        tree = ast.parse(textwrap.dedent(code))
        assert rule.visit_node(tree, {"filename": "test_foo.py"}) is None

    def test_skips_docstrings(self):
        code = '''
def foo():
    """This is a long docstring value"""
    pass

def bar():
    """This is a long docstring value"""
    pass

def baz():
    """This is a long docstring value"""
    pass
'''
        assert self._run(code) is None

    def test_below_threshold(self):
        code = """
x = "hello world"
y = "hello world"
"""
        assert self._run(code) is None


# ---------------------------------------------------------------------------
# TooManyReturnsRule (SKY-L028)
# ---------------------------------------------------------------------------


class TestTooManyReturnsRule:
    def _run(self, code, threshold=5):
        rule = TooManyReturnsRule(threshold=threshold)
        tree = ast.parse(textwrap.dedent(code))
        ctx = {"filename": "app.py"}
        results = []
        for node in ast.walk(tree):
            r = rule.visit_node(node, ctx)
            if r:
                results.extend(r)
        return results

    def test_detects_too_many(self):
        code = """
def foo(x):
    if x == 1: return 1
    if x == 2: return 2
    if x == 3: return 3
    if x == 4: return 4
    if x == 5: return 5
    return 0
"""
        results = self._run(code)
        assert len(results) == 1
        assert results[0]["value"] == 6
        assert results[0]["severity"] == "LOW"

    def test_escalates_severity(self):
        lines = ["def foo(x):"]
        for i in range(10):
            lines.append(f"    if x == {i}: return {i}")
        code = "\n".join(lines)
        results = self._run(code)
        assert results[0]["severity"] == "MEDIUM"

    def test_below_threshold(self):
        code = """
def foo(x):
    if x: return 1
    return 0
"""
        assert self._run(code) == []

    def test_ignores_nested_functions(self):
        code = """
def outer():
    def inner():
        return 1
        return 2
        return 3
        return 4
        return 5
    return 0
"""
        results = self._run(code, threshold=5)
        # outer has 1 return, inner has 5 — only inner triggers
        assert len(results) == 1
        assert results[0]["name"] == "inner"


# ---------------------------------------------------------------------------
# BooleanTrapRule (SKY-L029)
# ---------------------------------------------------------------------------


class TestBooleanTrapRule:
    def _run(self, code):
        rule = BooleanTrapRule()
        tree = ast.parse(textwrap.dedent(code))
        ctx = {"filename": "app.py"}
        results = []
        for node in ast.walk(tree):
            r = rule.visit_node(node, ctx)
            if r:
                results.extend(r)
        return results

    def test_detects_bool_default(self):
        code = """
def foo(x, flag=True):
    pass
"""
        results = self._run(code)
        assert len(results) == 1
        assert results[0]["simple_name"] == "flag"

    def test_detects_bool_annotation(self):
        code = """
def bar(x, enable: bool):
    pass
"""
        results = self._run(code)
        assert len(results) == 1
        assert results[0]["simple_name"] == "enable"

    def test_skips_allowed_names(self):
        code = """
def foo(verbose=True, debug=False, force=True):
    pass
"""
        assert self._run(code) == []

    def test_skips_dunder(self):
        code = """
def __init__(self, flag=True):
    pass
"""
        assert self._run(code) == []

    def test_skips_self_cls(self):
        code = """
def foo(self, flag=True):
    pass
"""
        results = self._run(code)
        assert len(results) == 1
        assert results[0]["simple_name"] == "flag"

    def test_no_false_positives_on_non_bool(self):
        code = """
def foo(x, y=42, z="hello"):
    pass
"""
        assert self._run(code) == []


# ---------------------------------------------------------------------------
# SARIF CWE output
# ---------------------------------------------------------------------------


class TestSarifCWE:
    def test_sarif_includes_taxonomies(self):
        findings = [
            {
                "rule_id": "SKY-L001",
                "message": "test",
                "severity": "HIGH",
                "file": "x.py",
                "line": 1,
                "col": 0,
                "cwe": [{"id": "CWE-1321", "name": "test"}],
            },
        ]
        sarif = SarifExporter(findings).generate()
        assert "taxonomies" in sarif["runs"][0]
        taxa = sarif["runs"][0]["taxonomies"]
        assert taxa[0]["name"] == "CWE"

    def test_sarif_rule_has_relationships(self):
        findings = [
            {
                "rule_id": "SKY-L008",
                "message": "test",
                "severity": "MEDIUM",
                "file": "x.py",
                "line": 1,
                "col": 0,
                "cwe": [{"id": "CWE-772", "name": "Missing Release"}],
            },
        ]
        sarif = SarifExporter(findings).generate()
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert "relationships" in rules[0]
        assert rules[0]["relationships"][0]["target"]["id"] == "CWE-772"

    def test_sarif_no_cwe_no_relationships(self):
        findings = [
            {
                "rule_id": "CUSTOM-1",
                "message": "test",
                "severity": "LOW",
                "file": "x.py",
                "line": 1,
                "col": 0,
            },
        ]
        sarif = SarifExporter(findings).generate()
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert "relationships" not in rules[0]
