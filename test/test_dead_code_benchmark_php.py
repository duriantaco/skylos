"""PHP corpus schema, scoring, static scans and competitor language limits."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from skylos.benchmarks import dead_code


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "benchmarks" / "dead_code" / "manifest.json"


def _php_case(name):
    if name == "direct":
        path = "fixtures/php_direct_calls"
        used = [("function", "format_value"), ("function", "normalize_value")]
        unused = [("function", "parse_value")]
    else:
        path = "fixtures/php_member_calls"
        used = [
            ("class", "Formatter"),
            ("function", "format"),
            ("function", "normalize"),
        ]
        unused = [("function", "summarize")]

    def labels(items):
        return [
            {"kind": kind, "file": "app.php", "symbol": symbol}
            for kind, symbol in items
        ]

    return {
        "id": f"php-{name}-calls",
        "path": path,
        "description": "Native PHP source-owned calls and unreferenced siblings.",
        "languages": ["php"],
        "taxonomy": ["php", "basic_detection", "precision_guard"],
        "importance": "high",
        "source": {
            "repo": "https://github.com/duriantaco/skylos",
            "license": "Apache-2.0",
            "notes": "Original static-only PHP corpus fixture.",
        },
        "scan": {"confidence": 60, "grep_verify": True},
        "budget": {"max_seconds": 5.0},
        "expect": {"used": labels(used), "unused": labels(unused)},
    }


def test_php_language_is_valid_without_requiring_language_taxonomy():
    case = _php_case("direct")
    case["taxonomy"] = ["basic_detection", "precision_guard"]
    assert dead_code.validate_manifest({"version": 1, "cases": [case]}, MANIFEST) == [
        case
    ]


def test_php_language_taxonomy_is_valid():
    case = _php_case("member")
    assert dead_code.validate_manifest({"version": 1, "cases": [case]}, MANIFEST) == [
        case
    ]


@pytest.mark.parametrize("name", ["direct", "member"])
def test_php_fixtures_pass_static_scoring_with_nonzero_source_counts(monkeypatch, name):
    original = dead_code.analyze
    captures = []

    def capture(*args, **kwargs):
        kwargs.update(
            grep_cache=False,
            trace_file=False,
            enable_dependency_hallucinations=False,
        )
        raw = original(*args, **kwargs)
        report = json.loads(raw)
        captures.append(report)
        return raw

    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.setattr(dead_code, "analyze", capture)
    case = _php_case(name)
    result = dead_code.run_case(case, MANIFEST, strict_labels=True)
    assert len(captures) == 1
    assert captures[0]["analysis_summary"]["total_files"] == 1
    assert not captures[0].get("analysis_errors")
    assert result["true_positives"] == len(case["expect"]["unused"])
    assert result["true_negatives"] == len(case["expect"]["used"])
    assert result["false_positives"] == result["false_negatives"] == 0
    assert result["unlabeled_finding_count"] == 0
    assert result["failures"] == []


@pytest.mark.parametrize("name", ["direct", "member"])
def test_php_scoring_detects_both_live_report_and_dead_omission(monkeypatch, name):
    case = _php_case(name)
    live = next(x for x in case["expect"]["used"] if x["kind"] == "function")

    def fake_analysis(scan_target, **kwargs):
        # The staged fixture really contains one PHP source file. This tests
        # accounting only, and does not claim a detector result.
        count = len(list(Path(scan_target).rglob("*.php")))
        return json.dumps(
            {
                "analysis_summary": {"total_files": count, "analysis_error_count": 0},
                "analysis_errors": [],
                "unused_functions": [
                    {
                        "file": str(Path(scan_target) / live["file"]),
                        "name": live["symbol"],
                        "simple_name": live["symbol"],
                        "confidence": 100,
                    }
                ],
            }
        )

    monkeypatch.setattr(dead_code, "analyze", fake_analysis)
    result = dead_code.run_case(case, MANIFEST, strict_labels=True)
    assert result["true_positives"] == 0
    assert result["false_positives"] == 1
    assert result["false_negatives"] == 1
    assert result["true_negatives"] == len(case["expect"]["used"]) - 1
    assert {failure["mode"] for failure in result["failures"]} == {"used", "unused"}


@pytest.mark.parametrize("scanner", ["vulture", "ruff"])
def test_python_only_competitors_skip_php_without_running(monkeypatch, scanner):
    cases = [_php_case("direct"), _php_case("member")]
    monkeypatch.setattr(
        dead_code,
        "load_manifest",
        lambda path: {"version": 1, "cases": deepcopy(cases)},
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("a Python-only competitor must not scan PHP")

    monkeypatch.setattr(dead_code, "_scan_case_with_scanner", forbidden)
    summary = dead_code.run_manifest(MANIFEST, scanner=scanner)
    assert summary["case_count"] == 0
    assert summary["skipped_case_count"] == 2
    assert {row["id"] for row in summary["skipped_cases"]} == {
        case["id"] for case in cases
    }
    assert all(row["languages"] == ["php"] for row in summary["skipped_cases"])
