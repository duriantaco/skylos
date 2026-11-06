"""Native C#/Kotlin corpus coverage and accounting failure controls."""

import copy
import json
from pathlib import Path

import pytest

from skylos.benchmarks import dead_code


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "benchmarks/dead_code/manifest.json"
CHALLENGE = ROOT / "benchmarks/dead_code/adversarial_manifest.json"
DEFAULT_CASES = {
    "csharp-private-call-chain": ("C#", 1),
    "csharp-top-level-owner-identity": ("C#", 2),
    "kotlin-private-call-chain": ("Kotlin", 1),
    "kotlin-owner-call-identity": ("Kotlin", 1),
}


def _case(case_id, manifest=MANIFEST):
    return next(
        case
        for case in dead_code.load_manifest(manifest)["cases"]
        if case["id"] == case_id
    )


def _mock_report_in_scope(monkeypatch, report, original_root):
    def scan(path, case, *, scanner):
        staged = copy.deepcopy(report)
        for category in dead_code.CATEGORY_TO_KIND:
            for finding in staged.get(category, []):
                if not isinstance(finding, dict) or not finding.get("file"):
                    continue
                relative = Path(finding["file"]).resolve().relative_to(original_root)
                finding["file"] = str(path / relative)
        return staged

    monkeypatch.setattr(dead_code, "_scan_case_with_scanner", scan)


@pytest.mark.parametrize("case_id", DEFAULT_CASES)
def test_managed_native_pairs_detect_missing_dead_and_reported_live_symbols(
    monkeypatch, case_id
):
    case = _case(case_id)
    assert case["symbol_identity"] == "qualified"
    captures = []
    original = dead_code.analyze

    def capture(path, **kwargs):
        kwargs.update(
            grep_cache=False,
            trace_file=False,
            enable_ai_defects=False,
            enable_dependency_hallucinations=False,
            enable_sca=False,
        )
        raw = original(path, **kwargs)
        captures.append((Path(path).resolve(), json.loads(raw)))
        return raw

    monkeypatch.setattr(dead_code, "analyze", capture)
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "[]")
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    result = dead_code.run_case(case, MANIFEST, strict_labels=True)
    assert len(captures) == 1
    original_root, report = captures[0]
    language, sources = DEFAULT_CASES[case_id]
    assert report["analysis_summary"]["total_files"] == sources
    assert report["analysis_summary"]["languages"] == {language: sources}
    assert not report.get("analysis_errors")
    assert result["scored"] is True
    assert result["failures"] == [], json.dumps(result, indent=2)
    assert result["true_positives"] == len(case["expect"]["unused"])
    assert result["true_negatives"] == len(case["expect"]["used"])
    assert result["unlabeled_finding_count"] == 0

    # This removes a real, source-backed finding without changing completeness
    # metadata. A detector that drops the dead symbol must fail the same case.
    dead = case["expect"]["unused"][0]
    category = dead_code.KIND_TO_CATEGORY[dead["kind"]]
    missing = copy.deepcopy(report)
    missing[category] = [
        finding
        for finding in missing.get(category, [])
        if finding.get("full_name") != dead["symbol"]
    ]
    _mock_report_in_scope(monkeypatch, missing, original_root)
    result = dead_code.run_case(case, MANIFEST, strict_labels=True)
    assert result["false_negatives"] == 1
    assert result["false_positives"] == 0

    # Conversely, a native live method must still trigger the used-side guard
    # when it is incorrectly appended to the detector report.
    live = next(item for item in case["expect"]["used"] if item["kind"] == "function")
    noisy = copy.deepcopy(report)
    noisy.setdefault("unused_functions", []).append(
        {
            "file": str(original_root / live["file"]),
            "full_name": live["symbol"],
            "simple_name": live["symbol"].rsplit(".", 1)[-1],
        }
    )
    _mock_report_in_scope(monkeypatch, noisy, original_root)
    result = dead_code.run_case(case, MANIFEST, strict_labels=True)
    assert result["false_positives"] == 1
    assert result["false_negatives"] == 0


@pytest.mark.parametrize("scanner", ["vulture", "ruff"])
def test_python_only_competitors_skip_managed_cases_without_running(
    monkeypatch, scanner
):
    def forbidden(*args, **kwargs):
        raise AssertionError("a Python-only scanner must not scan C# or Kotlin")

    monkeypatch.setattr(dead_code, "_scan_case_with_scanner", forbidden)
    summary = dead_code.run_manifest(
        MANIFEST, selected_cases=set(DEFAULT_CASES), scanner=scanner
    )
    assert summary["case_count"] == 0
    assert summary["skipped_case_count"] == 4
    assert {case["id"] for case in summary["skipped_cases"]} == set(DEFAULT_CASES)


def test_static_entrypoint_owner_challenge_preserves_the_used_class_contract():
    case = _case("csharp-owner-call-identity", CHALLENGE)
    assert case["symbol_identity"] == "qualified"
    used = {
        (item["kind"], item["file"], item["symbol"]) for item in case["expect"]["used"]
    }
    assert ("class", "Program.cs", "Portfolio.Program") in used
    assert ("function", "Program.cs", "Portfolio.Program.Main") in used
    assert case["expect"]["unused"] == [
        {"kind": "function", "file": "Workers.cs", "symbol": "Secondary.Worker.Process"}
    ]
