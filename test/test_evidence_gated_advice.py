"""The scan lists advice only with evidence; every other check is counted.

One result feeds the terminal, JSON, gates and uploads. These tests cover the
default advice set, the function-metric agreement rule, per-file annotation
entries, folder conventions, and that missing evidence keeps advice visible.
"""

import json

import pytest

from test.fixture_paths import write_fixture

from skylos.reporting.advice_display import advice_display_counts, combine_advice
from skylos.reporting.advice_evidence import corroborated
from skylos.reporting.advice_policy import optional_advice_reason, prepare_advice_view
from skylos.reporting.advice_scope import advice_source_context
from skylos.reporting.finding_types import iter_result_findings


def _metric(rule, file, line=10, name="handler"):
    return {
        "rule_id": rule,
        "kind": "quality",
        "type": "function",
        "name": name,
        "simple_name": name,
        "file": file,
        "line": line,
        "col": 0,
        "value": 20,
        "threshold": 10,
        "severity": "MEDIUM",
        "message": f"{rule} over",
    }


@pytest.mark.parametrize(
    "rules, expected",
    [
        ({"SKY-Q301", "SKY-Q306"}, True),
        ({"SKY-Q306", "SKY-Q302"}, True),
        ({"SKY-Q301", "SKY-C304"}, False),
        ({"SKY-Q301", "SKY-Q302"}, False),
        ({"SKY-Q306"}, False),
    ],
)
def test_two_agreeing_complexity_measures(rules, expected):
    assert corroborated(rules) is expected


def test_python_function_metrics_need_agreeing_complexity_measures(tmp_path):
    file = str(tmp_path / "app.py")
    result = {
        "quality": [
            _metric("SKY-Q301", file, line=10, name="flat"),
            _metric("SKY-C304", file, line=10, name="flat"),
            _metric("SKY-Q301", file, line=40, name="tangled"),
            _metric("SKY-Q306", file, line=40, name="tangled"),
            _metric("SKY-Q306", file, line=70, name="nested"),
            _metric("SKY-Q302", file, line=70, name="nested"),
        ]
    }
    view, visibility = prepare_advice_view(result)
    shown = {(row["name"], row["rule_id"]) for row in view["quality"]}
    assert shown == {
        ("tangled", "SKY-Q301"),
        ("tangled", "SKY-Q306"),
        ("nested", "SKY-Q306"),
        ("nested", "SKY-Q302"),
    }
    assert dict(visibility.reasons) == {"single_dimension": 2}
    assert len(result["quality"]) == 6  # the input result is not modified


def test_languages_without_cognitive_complexity_keep_function_metrics(tmp_path):
    file = str(tmp_path / "app.go")
    result = {"quality": [_metric("SKY-Q301", file), _metric("SKY-C304", file)]}
    view, visibility = prepare_advice_view(result)
    assert view is result and not visibility.omitted_checks


def test_unknown_function_identity_keeps_metrics_visible(tmp_path):
    file = str(tmp_path / "app.py")
    unnamed = _metric("SKY-Q301", file)
    unnamed["name"] = unnamed["simple_name"] = None
    result = {"quality": [unnamed, _metric("SKY-Q301", file), _metric("SKY-C304", file)]}
    view, visibility = prepare_advice_view(result)
    assert view is result and not visibility.omitted_checks


@pytest.mark.parametrize(
    "rule_id",
    ["SKY-L027", "SKY-C303", "SKY-Q501", "SKY-Q502", "SKY-C401", "SKY-L004", "SKY-P401"],
)
def test_advice_outside_the_default_set_is_measured_not_listed(tmp_path, rule_id):
    finding = {
        "rule_id": rule_id,
        "kind": "quality",
        "name": "x",
        "file": str(tmp_path / "service.py"),
        "line": 3,
        "value": 30,
        "threshold": 3,
        "message": "measured",
    }
    assert optional_advice_reason(finding, "quality", project_root=tmp_path) == "measurement"
    view, visibility = prepare_advice_view({"quality": [finding]}, project_root=tmp_path)
    assert view["quality"] == []
    assert dict(visibility.rules) == {rule_id: 1}
    assert "--all-advice lists them" in visibility.message


def test_defect_and_review_findings_are_never_filtered(tmp_path):
    defect = {
        "rule_id": "SKY-L001",
        "kind": "quality",
        "name": "f",
        "file": str(tmp_path / "service.py"),
        "line": 3,
        "message": "Mutable default argument",
    }
    view, visibility = prepare_advice_view({"quality": [defect]}, project_root=tmp_path)
    assert view["quality"] == [defect] or visibility.omitted_checks == 0


def _annotation(file, line, rule="SKY-T102", name="handler"):
    return {
        "rule_id": rule,
        "kind": "typing",
        "type": "function",
        "name": name,
        "file": file,
        "line": line,
        "severity": "LOW",
        "message": f"Public function '{name}' is missing a return type annotation.",
    }


def test_annotation_advice_is_one_entry_per_file_listing_every_line():
    result = {
        "quality": [
            _annotation("/p/types.py", 40, name="resolve_total"),
            _annotation("/p/types.py", 12, rule="SKY-T101", name="resolve_id"),
            _annotation("/p/types.py", 12, name="resolve_id"),
            _annotation("/p/other.py", 7, name="run"),
        ]
    }
    rows = [row for _category, row in combine_advice(iter_result_findings(result))]
    assert len(rows) == 2
    grouped = next(row for row in rows if row["file"] == "/p/types.py")
    lines = grouped["message"].splitlines()
    assert lines[0] == "2 functions in this file miss annotations."
    assert [line.split(":")[0] for line in lines[1:]] == ["Line 12", "Line 12", "Line 40"]
    assert advice_display_counts(result)["advice"] == 2
    assert len(result["quality"]) == 4  # every function stays a finding


def _advice(path):
    return {
        "rule_id": "SKY-Q301",
        "kind": "quality",
        "type": "function",
        "name": "f",
        "file": str(path),
        "line": 1,
        "value": 20,
        "threshold": 10,
        "message": "complex",
    }


def _write(root, relative, text):
    return write_fixture(root, relative, text, overwrite=True)


def test_folder_conventions_need_confirming_file_facts(tmp_path):
    (tmp_path / ".git").mkdir()
    nested_test = _write(tmp_path, "pkg/images/tests/test_views.py", "import pytest\n")
    nested_helper = _write(tmp_path, "pkg/images/tests/helpers.py", "VALUE = 1\n")
    vendored = _write(tmp_path, "pkg/_vendor/lib/core.py", "VALUE = 1\n")
    _write(
        tmp_path,
        "pkg/_vendor/lib/README",
        "This directory is copied from https://upstream.invalid/library.\n",
    )
    _write(tmp_path, "pkg/_vendor/lib/LICENSE", "Copyright and permission to copy.\n")
    tooling = _write(tmp_path, ".semgrep/rules/check.py", "VALUE = 1\n")
    docs = _write(tmp_path, "docs/conf_ext.py", "VALUE = 1\n")
    generated = _write(
        tmp_path,
        "pkg/stem.js",
        "// Generated from dutch.sbl by Snowball 3.0.1\nvar x = 1;\n",
    )
    declared = _write(tmp_path, "pkg/declared.js", "function value() { return 1; }\n")
    _write(tmp_path, ".gitattributes", "pkg/declared.js linguist-generated\n")
    mentions = _write(
        tmp_path, "pkg/schema.py", '"""Schemas generated by the model."""\nVALUE = 1\n'
    )
    application = _write(tmp_path, "pkg/service.py", "VALUE = 1\n")
    expected = {
        nested_test: "test",
        nested_helper: None,
        vendored: "vendored",
        tooling: "tooling",
        docs: "tooling",
        generated: None,
        declared: "generated",
        mentions: None,
        application: None,
    }
    for path, reason in expected.items():
        assert advice_source_context(_advice(path), tmp_path) == reason, path


def test_generated_context_requires_declaration_or_bundle_structure(tmp_path):
    header = "// Generated from schema.def by ExampleGenerator 1.0\n"
    ordinary = _write(tmp_path, "src/service.js", header + "export function work(value) { return value; }\n")
    assert advice_source_context(_advice(ordinary), tmp_path) is None
    (tmp_path / ".gitattributes").write_text("src/service.js linguist-generated\n")
    assert advice_source_context(_advice(ordinary), tmp_path) == "generated"
    (tmp_path / ".gitattributes").write_text("# src/service.js linguist-generated\n")
    assert advice_source_context(_advice(ordinary), tmp_path) is None

    bundle = _write(tmp_path, "bundle.js", """(() => {
      var __webpack_modules__ = {0: function(module) { module.exports = 1; }};
      function __webpack_require__(id) {
        var module = {exports: {}};
        __webpack_modules__[id](module, module.exports, __webpack_require__);
        return module.exports;
      }
      __webpack_require__(0);
    })();
    """)
    assert advice_source_context(_advice(bundle), tmp_path) == "generated"


def test_scan_result_is_the_view_every_consumer_reads(tmp_path):
    from skylos.analyzer import analyze

    (tmp_path / "app.py").write_text(
        "def flat(x):\n"
        + "".join(f"    if x == {i}:\n        return {i}\n" for i in range(12))
        + "    return None\n"
    )
    focused = json.loads(
        analyze(str(tmp_path), enable_quality=True, grep_verify=False, all_advice=False)
    )
    everything = json.loads(
        analyze(str(tmp_path), enable_quality=True, grep_verify=False, all_advice=True)
    )
    def rule_ids(result):
        return sorted(row["rule_id"] for row in result["quality"])

    assert "SKY-Q301" in rule_ids(everything)
    assert "SKY-Q301" in rule_ids(focused)
    assert not next(row for row in focused["quality"] if row["rule_id"] == "SKY-Q301")["listing"]["listed"]
    visibility = focused["advice_visibility"]
    assert visibility["reasons"].get("single_dimension", 0) >= 1
    assert visibility["omitted_checks"] == (
        visibility["total_checks"]
        - focused["analysis_summary"]["listed_finding_type_counts"]["advice"]
    )
    view, recorded = prepare_advice_view(focused)
    assert "SKY-Q301" not in rule_ids(view)
    assert len(focused["quality"]) == len(everything["quality"])
    assert recorded.omitted_checks == visibility["omitted_checks"]
