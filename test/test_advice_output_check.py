"""The saved-report checker detects evidence loss, not only changed counts."""

import copy

import pytest

from scripts import check_advice_output as checker


def _report():
    return {
        "quality": [
            {
                "rule_id": rule,
                "type": "function",
                "name": "process",
                "file": "/project/app.py",
                "line": 1,
                "col": 0,
                "value": value,
                "threshold": threshold,
                "message": f"Independent measurement: {rule}",
                "severity": "HIGH",
                "evidence": {"source": rule, "extra": [1, 2, 3]},
            }
            for rule, value, threshold in (
                ("SKY-Q301", 15, 10),
                ("SKY-Q306", 22, 15),
                ("SKY-C304", 120, 80),
            )
        ],
        "danger": [{"rule_id": "SKY-D211", "file": "/project/app.py", "line": 5}],
        "analysis_summary": {},
    }


def test_checker_recovers_every_metric_and_keeps_risk_records(tmp_path):
    report = _report()
    before = copy.deepcopy(report)
    result = checker.check_report(report, tmp_path)
    assert result["raw_advice_checks"] == 3
    assert result["all_advice_entries"] == result["focused_advice_entries"] == 1
    assert result["raw_json_unchanged"] and result["raw_gate_unchanged"]
    assert result["risk_records_unchanged"] and result["lossless_grouping"]
    assert report == before


def test_checker_verifies_shared_marks_and_keeps_unlisted_records(tmp_path):
    from skylos.reporting.advice_policy import apply_advice_policy

    report = _report()
    report["quality"][0]["rule_id"] = "SKY-L027"
    marked = apply_advice_policy(report, project_root=tmp_path)
    assert len(marked["quality"]) == 3
    result = checker.check_report(marked, tmp_path)
    assert result["shared_listing_verified"]
    assert result["optional_advice_checks"] > 0
    assert len(marked["quality"]) == 3


def test_checker_rejects_incomplete_versioned_marks(tmp_path):
    from skylos.reporting.advice_policy import apply_advice_policy

    report = apply_advice_policy(_report(), project_root=tmp_path)
    report["quality"][0].pop("listing")
    with pytest.raises(AssertionError, match="unmarked finding"):
        checker.check_report(report, tmp_path)


def test_checker_rejects_a_renderer_that_drops_original_records(monkeypatch, tmp_path):
    monkeypatch.setattr(checker, "combine_advice", lambda rows: [])
    with pytest.raises(AssertionError, match="cannot recover every original"):
        checker.check_report(_report(), tmp_path)


def test_checker_rejects_a_view_that_changes_raw_evidence(monkeypatch, tmp_path):
    prepare = checker.prepare_advice_view

    def corrupt(result, **kwargs):
        view, visibility = prepare(result, **kwargs)
        result["danger"][0]["line"] = 999
        return view, visibility

    monkeypatch.setattr(checker, "prepare_advice_view", corrupt)
    with pytest.raises(
        AssertionError, match="cannot recover every original|mutated raw JSON"
    ):
        checker.check_report(_report(), tmp_path)


def test_checker_reads_regular_json_with_a_size_bound(tmp_path):
    report = tmp_path / "report.json"
    report.write_text('{"quality": []}')
    assert checker._load_json(report) == {"quality": []}
    with pytest.raises(ValueError, match="size limit"):
        checker._load_json(report, max_bytes=2)


def test_checker_rejects_symlinked_input_reports(tmp_path):
    report = tmp_path / "report.json"
    report.write_text('{"quality": []}')
    alias = tmp_path / "alias.json"
    try:
        alias.symlink_to(report)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="regular JSON file"):
        checker._load_json(alias)
