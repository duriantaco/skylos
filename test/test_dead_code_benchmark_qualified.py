"""A qualified corpus must distinguish owners and reject ambiguous reports."""

import copy
import json

import pytest

from skylos.benchmarks import dead_code


def _manifest(tmp_path, *, identity="qualified"):
    root = tmp_path / "case"
    root.mkdir()
    (root / "Main.kt").write_text(
        "class Live { fun process() { println(1) } }\n"
        "class Dormant { fun process() { println(2) } }\n"
        "fun main() { Live().process(); Dormant() }\n",
        encoding="utf-8",
    )
    case = {
        "id": "owner-identity",
        "path": "case",
        "description": "Only one of two same-spelled owner methods is used.",
        "taxonomy": ["basic_detection", "precision_guard"],
        "source": {"repo": "https://github.com/example/project", "license": "MIT"},
        "expect": {
            "unused": [
                {"kind": "function", "file": "Main.kt", "symbol": "Dormant.process"}
            ],
            "used": [{"kind": "function", "file": "Main.kt", "symbol": "Live.process"}],
        },
    }
    if identity != "omitted":
        case["symbol_identity"] = identity
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"version": 1, "cases": [case]}), encoding="utf-8")
    return path


def _mock_findings(monkeypatch, findings):
    def scan(path, case, *, scanner):
        # This is an accounting fixture with a real one-file source scope;
        # it does not substitute for native language corpus scan receipts.
        records = copy.deepcopy(findings)
        for record in records:
            record.setdefault("file", str(path / "Main.kt"))
        return {
            "analysis_summary": {"total_files": 1, "analysis_error_count": 0},
            "analysis_errors": [],
            "unused_functions": records,
        }

    monkeypatch.setattr(dead_code, "_scan_case_with_scanner", scan)


def test_qualified_owner_finding_does_not_report_the_live_same_named_method(
    tmp_path, monkeypatch
):
    path = _manifest(tmp_path)
    _mock_findings(
        monkeypatch,
        [{"full_name": "Dormant.process", "name": "process", "simple_name": "process"}],
    )
    summary = dead_code.run_manifest(path, strict_labels=True)
    assert summary["failure_count"] == 0
    assert summary["counts"] == {
        "true_positives": 1,
        "false_positives": 0,
        "false_negatives": 0,
        "true_negatives": 1,
    }
    assert summary["cases"][0]["findings_by_kind"] == {"function": 1}
    assert summary["cases"][0]["unlabeled_finding_count"] == 0


def test_qualified_reporting_the_live_owner_still_fails_both_contracts(
    tmp_path, monkeypatch
):
    path = _manifest(tmp_path)
    _mock_findings(
        monkeypatch, [{"full_name": "Live.process", "simple_name": "process"}]
    )
    summary = dead_code.run_manifest(path, strict_labels=True)
    assert summary["counts"]["false_positives"] == 1
    assert summary["counts"]["false_negatives"] == 1
    assert summary["counts"]["true_positives"] == 0
    assert summary["counts"]["true_negatives"] == 0


def test_unlabeled_third_owner_is_one_distinct_finding(tmp_path, monkeypatch):
    path = _manifest(tmp_path)
    _mock_findings(
        monkeypatch,
        [{"full_name": "Other.process", "name": "process", "simple_name": "process"}],
    )
    summary = dead_code.run_manifest(path, strict_labels=True)
    assert summary["counts"] == {
        "true_positives": 0,
        "false_positives": 1,
        "false_negatives": 1,
        "true_negatives": 1,
    }
    assert summary["cases"][0]["unlabeled_findings"] == [
        "function:Main.kt:Other.process"
    ]


def test_qualified_aliases_are_explicit_and_do_not_duplicate_findings(
    tmp_path, monkeypatch
):
    path = _manifest(tmp_path)
    manifest = json.loads(path.read_text())
    manifest["cases"][0]["expect"]["unused"][0]["aliases"] = ["package.Dormant.process"]
    path.write_text(json.dumps(manifest))
    _mock_findings(
        monkeypatch,
        [{"full_name": "package.Dormant.process", "simple_name": "process"}],
    )
    summary = dead_code.run_manifest(path, strict_labels=True)
    assert summary["failure_count"] == 0
    assert summary["counts"]["true_positives"] == 1
    assert summary["cases"][0]["findings_by_kind"] == {"function": 1}


@pytest.mark.parametrize(
    "record",
    [
        {"simple_name": "process"},
        {"name": "Dormant.process", "simple_name": "process"},
        {"full_name": "", "simple_name": "process"},
        {"full_name": "   ", "name": "Dormant.process"},
        {"full_name": ["Dormant.process"]},
        {"full_name": "Dormant.process", "file": ""},
    ],
)
def test_ambiguous_qualified_symbol_reports_are_unscored(tmp_path, monkeypatch, record):
    path = _manifest(tmp_path)
    _mock_findings(monkeypatch, [record])
    summary = dead_code.run_manifest(path, strict_labels=True)
    assert summary["cases"][0]["scored"] is False
    assert summary["failure_count"] > 0
    assert all(value == 0 for value in summary["counts"].values())
    assert summary["scores"]["overall_score"] == 0


@pytest.mark.parametrize("identity", [None, "", "owners", True, []])
def test_invalid_identity_modes_are_rejected(tmp_path, identity):
    path = _manifest(tmp_path, identity=identity)
    with pytest.raises(ValueError, match="symbol_identity"):
        dead_code.validate_manifest(dead_code.load_manifest(path), path)


@pytest.mark.parametrize("identity", ["simple", "qualified"])
def test_documented_identity_modes_validate(tmp_path, identity):
    path = _manifest(tmp_path, identity=identity)
    assert dead_code.validate_manifest(dead_code.load_manifest(path), path)


def test_omitted_identity_keeps_legacy_basename_behavior(tmp_path, monkeypatch):
    path = _manifest(tmp_path, identity="omitted")
    _mock_findings(
        monkeypatch, [{"full_name": "Dormant.process", "simple_name": "process"}]
    )
    summary = dead_code.run_manifest(path, strict_labels=True)
    assert summary["counts"]["true_positives"] == 1
    assert summary["counts"]["false_positives"] == 1
    assert summary["cases"][0]["unlabeled_finding_count"] == 0
