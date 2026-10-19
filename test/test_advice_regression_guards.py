"""Preserve real source and policy findings while grouping optional advice."""

import ast
from copy import deepcopy

import pytest

from test.fixture_paths import write_fixture

from skylos.reporting.advice_display import (
    FileAnnotationDisplay,
    combine_advice,
    complexity_display,
)
from skylos.reporting.advice_scope import advice_source_context
from skylos.rules.quality._scope import is_non_production_function_scope
from skylos.rules.quality.complexity import CognitiveComplexityRule, ComplexityRule
from skylos.rules.quality.logic_maintainability import TooManyReturnsRule
from skylos.rules.quality.nesting import NestingRule
from skylos.rules.quality.practices import TypeAnnotationPracticeRule
from skylos.rules.quality.structure import FunctionLengthRule


BRANCHY = (
    "def branchy(value):\n"
    + "".join(
        f"    if value == {index}:\n        if value > {index}:\n            return {index}\n"
        for index in range(12)
    )
    + "    return None\n"
)


def _write(root, relative, source):
    return write_fixture(root, relative, source, overwrite=True)


def _metric_rows(path, root, source=BRANCHY):
    context = {"filename": str(path), "project_root": str(root), "source": source}
    rules = (
        ComplexityRule(),
        CognitiveComplexityRule(),
        NestingRule(threshold=1),
        FunctionLengthRule(max_lines=5),
        TooManyReturnsRule(),
    )
    tree = ast.parse(source)
    return [
        finding
        for rule in rules
        for node in ast.walk(tree)
        for finding in rule.visit_node(node, context) or ()
    ]


@pytest.mark.parametrize("folder", ["_vendor", "vendor", "third_party"])
def test_vendor_folder_does_not_override_first_party_ownership(tmp_path, folder):
    _write(tmp_path, "pyproject.toml", '[project]\nname="shop"\n')
    path = _write(tmp_path, f"src/shop/{folder}/owned.py", BRANCHY)
    _write(
        path.parent,
        "README",
        "This package is derived from https://upstream.invalid/source, "
        "but rewritten and independently maintained here as first-party code.\n",
    )
    _write(path.parent, "LICENSE", "Copyright and permission to copy.\n")
    finding = {"rule_id": "SKY-Q301", "file": str(path), "line": 1}
    assert advice_source_context(finding, tmp_path) is None


@pytest.mark.parametrize("folder", ["bench", "examples", "docs_src"])
def test_shipped_sample_named_subpackage_keeps_all_five_function_metrics(
    tmp_path, folder
):
    _write(tmp_path, "pyproject.toml", '[project]\nname="shop"\n')
    _write(tmp_path, "src/shop/__init__.py", "")
    path = _write(tmp_path, f"src/shop/{folder}/service.py", BRANCHY)
    rows = _metric_rows(path, tmp_path)
    assert {row["rule_id"] for row in rows} == {
        "SKY-Q301",
        "SKY-Q306",
        "SKY-Q302",
        "SKY-C304",
        "SKY-L028",
    }
    assert next(row["value"] for row in rows if row["rule_id"] == "SKY-Q301") == 25


@pytest.mark.parametrize("package", ["docs", "scripts", "tools"])
def test_declared_shipped_tooling_named_package_remains_production(tmp_path, package):
    _write(tmp_path, "pyproject.toml", f'[project]\nname="{package}"\n')
    _write(tmp_path, f"{package}/__init__.py", "")
    path = _write(tmp_path, f"{package}/service.py", BRANCHY)
    finding = {"rule_id": "SKY-Q301", "file": str(path), "line": 1}
    assert advice_source_context(finding, tmp_path) is None
    assert len(_metric_rows(path, tmp_path)) == 5


def test_function_scope_rechecks_rewritten_source_at_the_same_path(tmp_path):
    path = _write(tmp_path, "test_service.py", "def test_case():\n    assert True\n")
    context = {"filename": str(path), "project_root": str(tmp_path)}
    assert is_non_production_function_scope(context) is True
    path.write_text(BRANCHY, encoding="utf-8")
    assert is_non_production_function_scope(context) is False
    assert {row["rule_id"] for row in _metric_rows(path, tmp_path)} == {
        "SKY-Q301",
        "SKY-Q306",
        "SKY-Q302",
        "SKY-C304",
        "SKY-L028",
    }


def test_function_scope_rechecks_changed_pytest_selection(tmp_path):
    source = BRANCHY.replace("branchy", "test_case")
    path = _write(tmp_path, "custom/case_service.py", source)
    config = _write(
        tmp_path,
        "pyproject.toml",
        '[tool.pytest.ini_options]\npython_files=["case_*.py"]\ntestpaths=["custom"]\n',
    )
    context = {"filename": str(path), "project_root": str(tmp_path)}
    assert is_non_production_function_scope(context) is True
    config.write_text(
        '[tool.pytest.ini_options]\npython_files=["case_*.py"]\ntestpaths=["elsewhere"]\n',
        encoding="utf-8",
    )
    assert is_non_production_function_scope(context) is False


def test_function_scope_rechecks_changed_package_identity(tmp_path):
    config = _write(tmp_path, "pyproject.toml", '[project]\nname="other"\n')
    _write(tmp_path, "example/__init__.py", "")
    path = _write(tmp_path, "example/service.py", BRANCHY)
    context = {"filename": str(path), "project_root": str(tmp_path)}
    assert is_non_production_function_scope(context) is True
    config.write_text('[project]\nname="example"\n', encoding="utf-8")
    assert is_non_production_function_scope(context) is False


@pytest.mark.parametrize(
    "relative", ["pkg/api.py", "examples/api.py", "docs/extension.py"]
)
def test_partial_signature_policy_cannot_be_overridden_by_scope_or_placeholder(
    tmp_path, relative
):
    source = "def public(value: int, _context) -> int:\n    return value\n"
    path = _write(tmp_path, relative, source)
    _write(
        tmp_path,
        "pyproject.toml",
        f'[tool.mypy]\nfiles=["{relative}"]\ndisallow_incomplete_defs=true\n',
    )
    rows = TypeAnnotationPracticeRule().visit_node(
        ast.parse(source),
        {"filename": str(path), "project_root": str(tmp_path), "source": source},
    )
    assert [(row["rule_id"], row["value"]) for row in rows] == [
        ("SKY-T101", "_context")
    ]
    from skylos.core.gatekeeper import check_gate
    from skylos.reporting.advice_policy import apply_advice_policy

    result = apply_advice_policy({"quality": rows}, project_root=tmp_path)
    assert result["quality"][0]["listing"]["listed"] is True
    assert check_gate(result, {"gate": {"max_quality": 0}})[0] is False


@pytest.mark.parametrize("parameter", ["_context", "ignored_cache", "unused_meta"])
def test_optional_placeholder_exemption_does_not_falsify_coverage(tmp_path, parameter):
    source = (
        "__all__=['public']\n"
        f"def public(value: int, {parameter}) -> int:\n    return value\n"
    )
    path = _write(tmp_path, "api.py", source)
    context = {"filename": str(path), "project_root": str(tmp_path), "source": source}
    assert (
        TypeAnnotationPracticeRule(coverage_advice=True).visit_node(
            ast.parse(source), context
        )
        is None
    )
    assert context["annotation_coverage"]["missing_parameter_annotations"] == 1
    assert context["annotation_coverage"]["definitions_with_complete_annotations"] == 0
    assert context["annotation_coverage"]["unreported_missing_definitions"] == 1


def _annotation(rule, line, *, severity="LOW"):
    return {
        "rule_id": rule,
        "kind": "typing",
        "type": "function",
        "name": f"public_{line}",
        "simple_name": f"public_{line}",
        "file": "/project/api.py",
        "line": line,
        "severity": severity,
        "message": f"{rule} original evidence at {line}",
    }


@pytest.mark.parametrize(
    "second_rules", [("SKY-T101", "SKY-T102"), ("SKY-T101",), ("SKY-T102",)]
)
def test_file_annotation_group_flattens_precombined_function_records(second_rules):
    originals = [_annotation("SKY-T101", 1), _annotation("SKY-T102", 1)] + [
        _annotation(rule, 10, severity="HIGH") for rule in second_rules
    ]
    before = deepcopy(originals)
    rows = combine_advice(("quality", row) for row in originals)
    assert len(rows) == 1
    display = complexity_display(rows[0][1])
    assert isinstance(display, FileAnnotationDisplay)
    assert list(display.findings) == originals
    assert originals == before
    assert rows[0][1]["severity"] == "HIGH"
    assert display.message.startswith("2 functions in this file miss annotations.")
    assert combine_advice(rows) == rows


def test_existing_file_group_accepts_another_original_annotation():
    originals = [_annotation("SKY-T102", 1), _annotation("SKY-T102", 10)]
    grouped = combine_advice(("quality", row) for row in originals)
    extra = _annotation("SKY-T101", 20)
    result = combine_advice([*grouped, ("quality", extra)])
    assert len(result) == 1
    assert list(complexity_display(result[0][1]).findings) == [*originals, extra]


@pytest.mark.parametrize(
    "invalid", [["/project/api.py"], {"path": "/project/api.py"}, ""]
)
def test_unknown_annotation_file_evidence_stays_separate(invalid):
    malformed = {**_annotation("SKY-T101", 1), "file": invalid}
    valid = _annotation("SKY-T102", 10)
    rows = combine_advice([("quality", malformed), ("quality", valid)])
    assert rows == [("quality", malformed), ("quality", valid)]
