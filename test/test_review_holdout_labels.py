"""Absence earns credit only for an applicable, parsed, complete target."""

from pathlib import Path
import runpy


evaluate = runpy.run_path(str(Path(__file__).parents[1] / "benchmarks" /
                             "review_2026_11_17" / "run_holdouts.py"))["evaluate"]


def example(tmp_path, kind="used"):
    label = {"kind": kind, "file": "view.ts", "symbol": "render", "line": 8,
             "rule_id": "SKY-D226", "start_line": 12, "end_line": 12}
    target = {"id": "example", "labels": [label]}
    report = {"definitions": {"View.render": {"name": "View.render", "line": 8,
                                              "file": str(tmp_path / "view.ts")}}}
    return target, report


def test_missing_parse_cannot_earn_absence_credit(tmp_path):
    target, _ = example(tmp_path)
    assert evaluate(target, {}, tmp_path, [])[0]["outcome"] == "incomplete"


def test_analysis_error_cannot_earn_absence_credit(tmp_path):
    target, report = example(tmp_path)
    assert evaluate(target, report, tmp_path, ["engine failed"])[0]["outcome"] == "incomplete"


def test_reported_owner_is_a_false_positive_for_used_method(tmp_path):
    target, report = example(tmp_path)
    report["unused_classes"] = [{"name": "View", "file": str(tmp_path / "view.ts"), "line": 2}]
    assert evaluate(target, report, tmp_path, [])[0]["outcome"] == "false_positive"


def test_wrong_file_or_line_does_not_match_security_label(tmp_path):
    target, report = example(tmp_path, "security_absent")
    report["danger"] = [
        {"rule_id": "SKY-D226", "file": str(tmp_path / "other.ts"), "line": 12},
        {"rule_id": "SKY-D226", "file": str(tmp_path / "view.ts"), "line": 20},
    ]
    assert evaluate(target, report, tmp_path, [])[0]["outcome"] == "retained_control"
    report["danger"].append({"rule_id": "SKY-D226", "file": str(tmp_path / "view.ts"), "line": 12})
    assert evaluate(target, report, tmp_path, [])[0]["outcome"] == "false_positive"


def test_unsupported_sink_earns_no_pass_credit(tmp_path):
    target, report = example(tmp_path, "security_absent")
    override = dict(target["labels"][0], target_id="example", score_eligible=False,
                    status="not_applicable", reason="sink unsupported")
    assert evaluate(target, report, tmp_path, [], [override])[0]["outcome"] == "not_applicable"
