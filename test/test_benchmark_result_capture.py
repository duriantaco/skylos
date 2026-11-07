import copy
import json

import pytest

from skylos.benchmarks import dead_code, security


@pytest.fixture(params=[security, dead_code], ids=["security", "dead_code"])
def benchmark(request):
    return request.param


def _manifest(tmp_path, benchmark, *, unsupported=False):
    case_dir = tmp_path / "sample"
    case_dir.mkdir()
    (case_dir / "app.py").write_text("def reserve():\n    return 1\n")
    expect = (
        {"present": {"danger": ["SKY-D216"]}, "absent": {"danger": ["SKY-D211"]}}
        if benchmark is security
        else {
            "unused": [{"kind": "function", "file": "app.py", "symbol": "reserve"}],
            "used": [{"kind": "function", "file": "app.py", "symbol": "measure"}],
        }
    )
    case = {
        "id": "sample",
        "path": "sample",
        "description": "Raw output capture contract.",
        "taxonomy": ["precision_guard"],
        "source": {"repo": "https://github.com/example/project", "license": "MIT"},
        "expect": expect,
    }
    cases = [case]
    if unsupported:
        cases.append({**case, "id": "unsupported", "languages": ["java"]})
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"version": 1, "cases": cases}))
    return path, case


def _report():
    return {
        "analysis_summary": {"total_files": 1, "analysis_error_count": 0},
        "analysis_errors": [],
        "danger": [
            {
                "rule_id": "SKY-D216",
                "file": "app.py",
                "line": 3,
                "evidence": {"source": "request.args", "sink": "requests.get"},
            }
        ],
        "unused_functions": [
            {"file": "app.py", "simple_name": "reserve", "full_name": "reserve"}
        ],
        "quality": [{"rule_id": "SKY-Q999", "message": "Additional raw evidence"}],
        "assessment": {"coverage": {"status": "complete"}},
    }


def _scan_result(monkeypatch, benchmark, report):
    monkeypatch.setattr(benchmark, "_scan_case_with_scanner", lambda *a, **k: report)


def test_capture_retains_full_report_and_ungraded_evidence(
    tmp_path, monkeypatch, benchmark
):
    path, case = _manifest(tmp_path, benchmark)
    report = _report()
    _scan_result(monkeypatch, benchmark, report)
    captured = []

    result = benchmark.run_case(
        case, path, capture_result=lambda case_id, raw: captured.append((case_id, raw))
    )

    assert result["scored"] is True
    assert result["true_positives"] == result["true_negatives"] == 1
    assert result["failures"] == []
    assert captured == [("sample", report)]
    assert captured[0][1] is not report
    assert captured[0][1]["quality"][0]["message"] == "Additional raw evidence"
    assert captured[0][1]["danger"][0]["evidence"]["sink"] == "requests.get"


def test_capture_mutation_cannot_change_grading(tmp_path, monkeypatch, benchmark):
    path, case = _manifest(tmp_path, benchmark)
    report = _report()
    original = copy.deepcopy(report)
    _scan_result(monkeypatch, benchmark, report)

    def mutate(case_id, raw):
        raw["danger"][0]["rule_id"] = "SKY-D211"
        raw["unused_functions"][0]["simple_name"] = "measure"
        raw["analysis_errors"].append({"kind": "syntax_error"})

    result = benchmark.run_case(case, path, capture_result=mutate)

    assert report == original
    assert result["scored"] is True
    assert result["true_positives"] == result["true_negatives"] == 1
    assert result["failures"] == []


@pytest.mark.parametrize(
    "report", [None, [], {}, {"analysis_summary": {"total_files": 0}}]
)
def test_capture_retains_invalid_report_without_awarding_a_pass(
    tmp_path, monkeypatch, benchmark, report
):
    path, case = _manifest(tmp_path, benchmark)
    _scan_result(monkeypatch, benchmark, report)
    captured = []

    result = benchmark.run_case(
        case, path, capture_result=lambda case_id, raw: captured.append((case_id, raw))
    )

    assert captured == [("sample", report)]
    assert result["scored"] is False
    assert result["analysis_status"] == "incomplete"
    assert result["true_positives"] == result["true_negatives"] == 0
    assert {failure["failure_type"] for failure in result["failures"]} == {"analysis"}


def test_capture_cannot_repair_an_incomplete_report(tmp_path, monkeypatch, benchmark):
    path, case = _manifest(tmp_path, benchmark)
    report = _report()
    report["analysis_errors"] = [{"kind": "syntax_error", "file": "app.py"}]
    original = copy.deepcopy(report)
    _scan_result(monkeypatch, benchmark, report)

    def repair(case_id, raw):
        assert raw["analysis_errors"] == original["analysis_errors"]
        raw["analysis_errors"].clear()

    result = benchmark.run_case(case, path, capture_result=repair)

    assert report == original
    assert result["scored"] is False
    assert result["true_positives"] == result["true_negatives"] == 0


def test_manifest_captures_only_scanned_cases(tmp_path, monkeypatch, benchmark):
    path, _ = _manifest(tmp_path, benchmark, unsupported=True)
    report = _report()
    _scan_result(monkeypatch, benchmark, report)
    captured = []

    result = benchmark.run_manifest(
        path,
        scanner="bandit" if benchmark is security else "ruff",
        capture_result=lambda case_id, raw: captured.append((case_id, raw)),
    )

    assert captured == [("sample", report)]
    assert result["case_count"] == 1
    assert result["skipped_case_count"] == 1
    assert result["skipped_cases"][0]["id"] == "unsupported"


def test_default_manifest_does_not_forward_a_new_keyword(
    tmp_path, monkeypatch, benchmark
):
    path, _ = _manifest(tmp_path, benchmark)
    _scan_result(monkeypatch, benchmark, _report())
    original = benchmark.run_case

    def legacy_adapter(case, manifest_path, **kwargs):
        assert "capture_result" not in kwargs
        return original(case, manifest_path, **kwargs)

    monkeypatch.setattr(benchmark, "run_case", legacy_adapter)
    result = benchmark.run_manifest(path, capture_result=None)

    assert result["failure_count"] == 0
    assert result["scored_case_count"] == 1


def test_capture_storage_time_is_outside_analysis_budget(
    tmp_path, monkeypatch, benchmark
):
    path, case = _manifest(tmp_path, benchmark)
    case["budget"] = {"max_seconds": 2.0}
    clock = [0.0]
    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: clock[0])

    def scan(*args, **kwargs):
        clock[0] += 1.0
        return _report()

    def capture(case_id, raw):
        clock[0] += 100.0

    monkeypatch.setattr(benchmark, "_scan_case_with_scanner", scan)
    result = benchmark.run_case(case, path, capture_result=capture)

    assert clock[0] == 101.0
    assert result["elapsed_seconds"] == 1.0
    assert result["failures"] == []


def test_capture_failure_propagates(tmp_path, monkeypatch, benchmark):
    path, case = _manifest(tmp_path, benchmark)
    _scan_result(monkeypatch, benchmark, _report())

    def fail_capture(case_id, raw):
        raise OSError("Unable to retain eval evidence")

    with pytest.raises(OSError, match="Unable to retain eval evidence"):
        benchmark.run_case(case, path, capture_result=fail_capture)
