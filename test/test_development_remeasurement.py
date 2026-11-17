"""Frozen-label remeasurement cannot credit missing/foreign declarations."""

import importlib.util
from pathlib import Path

_PATH = (
    Path(__file__).resolve().parents[1]
    / "benchmarks/review_2026_11_17/ground_truth_audit/run_development_remeasurement.py"
)
_SPEC = importlib.util.spec_from_file_location("development_remeasurement", _PATH)
runner = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(runner)


def test_wrong_owner_at_same_line_cannot_satisfy_used_fact(tmp_path):
    fact = {"kind": "used", "file": "x.go", "line": 10, "symbol": "Left.Match"}
    report = {
        "definitions": {
            "x": {"file": str(tmp_path / "x.go"), "line": 10, "name": "Right.Match"}
        }
    }
    assert (
        runner.evaluate([fact], report, tmp_path)[0]["outcome"]
        == "incomplete_extraction"
    )


def test_missing_extraction_is_not_safe_credit(tmp_path):
    fact = {"kind": "unused", "file": "x.go", "line": 10, "symbol": "Left.Match"}
    assert (
        runner.evaluate([fact], {}, tmp_path)[0]["outcome"] == "incomplete_extraction"
    )


def test_exact_go_test_method_can_be_scored_when_engine_extracts_it(tmp_path):
    fact = {"truth": "unused", "file": "x_test.go", "line": 10, "symbol": "Left.Match"}
    record = {
        "file": str(tmp_path / "x_test.go"),
        "line": 10,
        "name": "package.Left.Match",
    }
    report = {"definitions": {"x": record}, "unused_functions": [record]}
    assert runner.evaluate([fact], report, tmp_path)[0]["outcome"] == "true_positive"


def test_security_must_match_rule_and_exact_location(tmp_path):
    fact = {
        "kind": "security_absent",
        "file": "x.js",
        "line": 10,
        "start_line": 10,
        "end_line": 10,
        "rule_id": "SKY-D212",
    }
    report = {
        "definitions": {
            "x": {"file": str(tmp_path / "x.js"), "line": 1, "name": "helper"}
        },
        "danger": [{"file": str(tmp_path / "x.js"), "line": 11, "rule_id": "SKY-D212"}],
    }
    assert (
        runner.evaluate([fact], report, tmp_path)[0]["outcome"]
        == "retained_safe_control"
    )


def test_bad_frozen_pickle_location_stays_incomplete(tmp_path):
    (tmp_path / "x.py").write_text("obj = object()\nresult = loads(dumps(obj))\n")
    fact = {
        "kind": "security_absent",
        "file": "x.py",
        "line": 1,
        "property": "untrusted_deserialization",
        "start_line": 1,
        "end_line": 1,
    }
    assert (
        runner.evaluate([fact], {}, tmp_path)[0]["outcome"]
        == "incomplete_label_location"
    )


def test_unknown_source_fact_earns_no_credit(tmp_path):
    assert (
        runner.evaluate([{"kind": "unknown"}], {}, tmp_path)[0]["outcome"] == "unscored"
    )
