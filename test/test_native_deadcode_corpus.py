"""Rust/Dart source corpus parity through the native benchmark entry point."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from skylos.benchmarks import dead_code


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "benchmarks/dead_code/manifest.json"
# Frozen source-backed truth. Owner-qualified method names must stay distinct.
CASES = {
    "rust-direct-calls": {
        "id": "rust-direct-calls",
        "path": "fixtures/rust_direct_calls",
        "description": "Closed source calls retain the selected "
        "implementation and report unreferenced "
        "siblings.",
        "languages": ["rust"],
        "taxonomy": ["rust", "basic_detection", "precision_guard"],
        "importance": "high",
        "source": {
            "repo": "https://github.com/duriantaco/skylos",
            "license": "Apache-2.0",
            "notes": "Original static-only corpus fixture; "
            "target programs are never executed.",
        },
        "scan": {"confidence": 40, "grep_verify": False},
        "budget": {"max_seconds": 5.0},
        "expect": {
            "used": [
                {"kind": "function", "file": "main.rs", "symbol": "main"},
                {"kind": "function", "file": "main.rs", "symbol": "render"},
                {"kind": "function", "file": "main.rs", "symbol": "normalize"},
            ],
            "unused": [{"kind": "function", "file": "main.rs", "symbol": "summarize"}],
        },
        "symbol_identity": "qualified",
    },
    "rust-member-owners": {
        "id": "rust-member-owners",
        "path": "fixtures/rust_member_owners",
        "description": "Concrete receiver calls retain only the selected member owner.",
        "languages": ["rust"],
        "taxonomy": ["rust", "basic_detection", "precision_guard"],
        "importance": "high",
        "source": {
            "repo": "https://github.com/duriantaco/skylos",
            "license": "Apache-2.0",
            "notes": "Original static-only corpus fixture; "
            "target programs are never executed.",
        },
        "scan": {"confidence": 40, "grep_verify": False},
        "budget": {"max_seconds": 5.0},
        "expect": {
            "used": [
                {"kind": "function", "file": "main.rs", "symbol": "main"},
                {"kind": "class", "file": "main.rs", "symbol": "TextCodec"},
                {"kind": "class", "file": "main.rs", "symbol": "BinaryCodec"},
                {"kind": "function", "file": "main.rs", "symbol": "TextCodec.process"},
                {"kind": "function", "file": "main.rs", "symbol": "TextCodec.measure"},
            ],
            "unused": [
                {"kind": "function", "file": "main.rs", "symbol": "TextCodec.snapshot"},
                {
                    "kind": "function",
                    "file": "main.rs",
                    "symbol": "BinaryCodec.process",
                },
            ],
        },
        "symbol_identity": "qualified",
    },
    "dart-direct-calls": {
        "id": "dart-direct-calls",
        "path": "fixtures/dart_direct_calls",
        "description": "Closed source calls retain the selected "
        "implementation and report unreferenced "
        "siblings.",
        "languages": ["dart"],
        "taxonomy": ["dart", "basic_detection", "precision_guard"],
        "importance": "high",
        "source": {
            "repo": "https://github.com/duriantaco/skylos",
            "license": "Apache-2.0",
            "notes": "Original static-only corpus fixture; "
            "target programs are never executed.",
        },
        "scan": {"confidence": 60, "grep_verify": False},
        "budget": {"max_seconds": 5.0},
        "expect": {
            "used": [
                {"kind": "function", "file": "main.dart", "symbol": "main"},
                {"kind": "function", "file": "main.dart", "symbol": "_render"},
                {"kind": "function", "file": "main.dart", "symbol": "_normalize"},
            ],
            "unused": [
                {"kind": "function", "file": "main.dart", "symbol": "_summarize"}
            ],
        },
        "symbol_identity": "qualified",
    },
    "dart-member-owners": {
        "id": "dart-member-owners",
        "path": "fixtures/dart_member_owners",
        "description": "Concrete receiver calls retain only the selected member owner.",
        "languages": ["dart"],
        "taxonomy": ["dart", "basic_detection", "precision_guard"],
        "importance": "high",
        "source": {
            "repo": "https://github.com/duriantaco/skylos",
            "license": "Apache-2.0",
            "notes": "Original static-only corpus fixture; "
            "target programs are never executed.",
        },
        "scan": {"confidence": 60, "grep_verify": False},
        "budget": {"max_seconds": 5.0},
        "expect": {
            "used": [
                {"kind": "function", "file": "main.dart", "symbol": "main"},
                {"kind": "class", "file": "main.dart", "symbol": "TextCodec"},
                {"kind": "class", "file": "main.dart", "symbol": "BinaryCodec"},
                {"kind": "function", "file": "main.dart", "symbol": "TextCodec.run"},
                {
                    "kind": "function",
                    "file": "main.dart",
                    "symbol": "TextCodec._process",
                },
                {
                    "kind": "function",
                    "file": "main.dart",
                    "symbol": "TextCodec._measure",
                },
            ],
            "unused": [
                {
                    "kind": "function",
                    "file": "main.dart",
                    "symbol": "TextCodec._snapshot",
                },
                {
                    "kind": "function",
                    "file": "main.dart",
                    "symbol": "BinaryCodec._process",
                },
            ],
        },
        "symbol_identity": "qualified",
    },
}


def _case(case_id):
    return deepcopy(CASES[case_id])


def _dart_extra(case):
    if "dart" in case["languages"]:
        pytest.importorskip(
            "tree_sitter_dart_orchard",
            reason='needs the optional "skylos[dart]" extra',
        )


@pytest.mark.parametrize("case_id", CASES)
def test_native_language_cases_are_registered_with_frozen_pair_labels(case_id):
    expected = _case(case_id)
    checked_in = next(
        case
        for case in dead_code.load_manifest(MANIFEST)["cases"]
        if case["id"] == case_id
    )
    assert checked_in == expected
    assert expected["expect"]["used"]
    assert expected["expect"]["unused"]
    assert expected["symbol_identity"] == "qualified"
    if "rust" in expected["languages"]:
        # Rust's existing experimental confidence cap is an explicit opt-in.
        assert expected["scan"]["confidence"] == 40


@pytest.mark.parametrize("case_id", CASES)
def test_native_language_pairs_report_only_the_unreferenced_owner(monkeypatch, case_id):
    case = _case(case_id)
    _dart_extra(case)
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
    language = case["languages"][0].title()
    assert report["analysis_summary"]["languages"] == {language: 1}
    assert not report.get("analysis_errors")
    # Assert raw identities independently of benchmark score normalization.
    assert {item["full_name"] for item in report.get("unused_functions", [])} == {
        item["symbol"] for item in case["expect"]["unused"]
    }
    assert result["scored"] is True
    assert result["true_positives"] == len(case["expect"]["unused"])
    assert result["true_negatives"] == len(case["expect"]["used"])
    assert result["false_positives"] == result["false_negatives"] == 0
    assert result["unlabeled_finding_count"] == 0
    assert result["failures"] == []


@pytest.mark.parametrize("case_id", CASES)
def test_native_language_pair_detects_a_live_report_and_dead_omissions(
    monkeypatch, case_id
):
    case = _case(case_id)
    live = next(item for item in case["expect"]["used"] if item["kind"] == "function")

    def fake_report(path, ignored_case):
        # Accounting control: this fixture truly contains one source file.
        return {
            "analysis_summary": {"total_files": 1, "analysis_error_count": 0},
            "analysis_errors": [],
            "unused_functions": [
                {
                    "file": str(path / live["file"]),
                    "name": live["symbol"],
                    "full_name": live["symbol"],
                    "simple_name": live["symbol"].split(".")[-1],
                }
            ],
        }

    monkeypatch.setattr(dead_code, "_scan_case", fake_report)
    result = dead_code.run_case(case, MANIFEST, strict_labels=True)
    assert result["true_positives"] == 0
    assert result["false_positives"] == 1
    assert result["false_negatives"] == len(case["expect"]["unused"])
    assert result["true_negatives"] == len(case["expect"]["used"]) - 1
    assert {failure["mode"] for failure in result["failures"]} == {"used", "unused"}


@pytest.mark.parametrize("scanner", ["vulture", "ruff"])
def test_python_only_scanners_skip_rust_and_dart_without_running(monkeypatch, scanner):
    monkeypatch.setattr(
        dead_code,
        "load_manifest",
        lambda path: {"version": 1, "cases": [_case(case_id) for case_id in CASES]},
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("Python-only scanners must not process Rust/Dart fixtures")

    monkeypatch.setattr(dead_code, "_scan_case_with_scanner", forbidden)
    summary = dead_code.run_manifest(MANIFEST, scanner=scanner)
    assert summary["case_count"] == 0
    assert summary["skipped_case_count"] == len(CASES)
    assert {row["id"] for row in summary["skipped_cases"]} == set(CASES)
    assert summary["scores"]["overall_score"] == 0
    assert summary["score_unavailable_reason"] == "no_valid_cases"


def test_missing_dart_engine_is_unscored_instead_of_a_clean_benchmark(monkeypatch):
    monkeypatch.setattr("skylos.visitors.languages.dart.core.DART_LANG", None)
    original = dead_code.analyze
    reports = []

    def capture(*args, **kwargs):
        raw = original(*args, **kwargs)
        reports.append(json.loads(raw))
        return raw

    monkeypatch.setattr(dead_code, "analyze", capture)
    case = _case("dart-direct-calls")
    result = dead_code.run_case(case, MANIFEST, strict_labels=True)
    assert len(reports) == 1
    assert reports[0]["analysis_summary"]["total_files"] == 1
    assert (
        reports[0]["analysis_summary"]["language_engines"]["dart"]["status"]
        == "partial"
    )
    assert any(
        error.get("error_type") == "DartGrammarUnavailable"
        for error in reports[0]["analysis_errors"]
    )
    assert result["scored"] is False
    assert result["analysis_status"] == "incomplete"
    assert all(
        result[key] == 0
        for key in (
            "true_positives",
            "false_positives",
            "false_negatives",
            "true_negatives",
        )
    )
    assert result["scores"]["overall_score"] == 0
    assert {failure["failure_type"] for failure in result["failures"]} == {"analysis"}


def test_rust_syntax_failure_does_not_grant_used_symbol_credit(tmp_path, monkeypatch):
    (tmp_path / "main.rs").write_text("fn main() { let value = ; }\n", encoding="utf-8")
    original = dead_code.analyze
    reports = []

    def capture(*args, **kwargs):
        raw = original(*args, **kwargs)
        reports.append(json.loads(raw))
        return raw

    monkeypatch.setattr(dead_code, "analyze", capture)
    case = _case("rust-direct-calls")
    case["path"] = str(tmp_path)
    result = dead_code.run_case(case, MANIFEST, strict_labels=True)
    assert len(reports) == 1
    assert reports[0]["analysis_summary"]["total_files"] == 1
    assert any(
        error.get("kind") == "syntax_error" for error in reports[0]["analysis_errors"]
    )
    assert result["scored"] is False
    assert result["true_negatives"] == result["true_positives"] == 0
    assert result["scores"]["overall_score"] == 0
    assert {failure["failure_type"] for failure in result["failures"]} == {"analysis"}
