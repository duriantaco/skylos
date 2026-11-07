"""C++ corpus parity for supported file-local free-function analysis."""

import copy
import json
from pathlib import Path

import pytest

from skylos.benchmarks import dead_code
from skylos.visitors.languages.cpp import core


MANIFEST = Path(__file__).resolve().parents[1] / "benchmarks/dead_code/manifest.json"
LABELS = {
    "cpp-direct-call-chain": {
        "used": ["main", "render", "normalize"],
        "unused": ["summarize"],
    },
    "cpp-address-taken-callback": {
        "used": ["main", "parse_record"],
        "unused": ["serialize_record"],
    },
}


def _case(case_id):
    return copy.deepcopy(
        next(
            case
            for case in dead_code.load_manifest(MANIFEST)["cases"]
            if case["id"] == case_id
        )
    )


@pytest.mark.parametrize("case_id", LABELS)
def test_cpp_cases_register_both_liveness_polarities(case_id):
    case = _case(case_id)
    assert case["languages"] == ["cpp"]
    assert "cpp" in case["taxonomy"]
    assert case["symbol_identity"] == "qualified"
    for mode, symbols in LABELS[case_id].items():
        assert case["expect"][mode] == [
            {"kind": "function", "file": "main.cpp", "symbol": symbol}
            for symbol in symbols
        ]


@pytest.mark.parametrize("case_id", LABELS)
def test_cpp_native_source_reports_only_unreferenced_free_functions(
    monkeypatch, case_id
):
    case = _case(case_id)
    original = dead_code.analyze
    captures = []

    def capture(*args, **kwargs):
        kwargs.update(
            grep_cache=False,
            trace_file=False,
            enable_ai_defects=False,
            enable_dependency_hallucinations=False,
            enable_sca=False,
        )
        raw = original(*args, **kwargs)
        captures.append(json.loads(raw))
        return raw

    monkeypatch.setattr(dead_code, "analyze", capture)
    result = dead_code.run_case(case, MANIFEST, strict_labels=True)
    assert len(captures) == 1
    report = captures[0]
    assert report["analysis_summary"]["total_files"] == 1
    assert report["analysis_summary"]["languages"] == {"C++": 1}
    assert not report.get("analysis_errors")
    assert {item["full_name"] for item in report.get("unused_functions", [])} == set(
        LABELS[case_id]["unused"]
    )
    assert result["true_positives"] == len(LABELS[case_id]["unused"])
    assert result["true_negatives"] == len(LABELS[case_id]["used"])
    assert result["false_positives"] == result["false_negatives"] == 0
    assert result["unlabeled_finding_count"] == 0
    assert result["failures"] == []


@pytest.mark.parametrize("case_id", LABELS)
def test_cpp_pair_catches_live_report_and_dead_omission(monkeypatch, case_id):
    case = _case(case_id)
    live = LABELS[case_id]["used"][0]

    def scan(path, case, **kwargs):
        return {
            "analysis_summary": {"total_files": 1, "analysis_error_count": 0},
            "analysis_errors": [],
            "unused_functions": [{"file": str(path / "main.cpp"), "full_name": live}],
        }

    monkeypatch.setattr(dead_code, "_scan_case_with_scanner", scan)
    result = dead_code.run_case(case, MANIFEST, strict_labels=True)
    assert result["false_positives"] == 1
    assert result["false_negatives"] == 1
    assert result["true_positives"] == 0
    assert {failure["mode"] for failure in result["failures"]} == {"used", "unused"}


@pytest.mark.parametrize("scanner", ["vulture", "ruff"])
def test_cpp_cases_skip_python_only_competitors(monkeypatch, scanner):
    def forbidden(*args, **kwargs):
        raise AssertionError("A Python-only scanner must not run for C++ cases")

    monkeypatch.setattr(dead_code, "_scan_case_with_scanner", forbidden)
    result = dead_code.run_manifest(
        MANIFEST, selected_cases=set(LABELS), scanner=scanner
    )
    assert result["case_count"] == 0
    assert result["skipped_case_count"] == 2
    assert result["scores"]["overall_score"] == 0
    assert result["score_unavailable_reason"] == "no_valid_cases"


def test_cpp_missing_grammar_is_unscored(monkeypatch):
    original = dead_code.analyze
    reports = []

    def capture(*args, **kwargs):
        kwargs.update(
            grep_cache=False, trace_file=False, enable_dependency_hallucinations=False
        )
        raw = original(*args, **kwargs)
        reports.append(json.loads(raw))
        return raw

    monkeypatch.setattr(core, "CPP_LANG", None)
    monkeypatch.setattr(dead_code, "analyze", capture)
    result = dead_code.run_case(
        _case("cpp-direct-call-chain"), MANIFEST, strict_labels=True
    )
    assert any(
        error["kind"] == "cpp_parser_unavailable"
        for error in reports[0]["analysis_errors"]
    )
    assert result["scored"] is False
    assert result["true_positives"] == result["true_negatives"] == 0
    assert result["scores"]["overall_score"] == 0
