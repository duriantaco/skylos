"""Native Rust/C# quality controls with positive coverage and exact locations."""

from pathlib import Path

import pytest

from skylos.benchmarks import quality
from skylos.reporting.listing import is_listed


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "benchmarks/quality/manifest.json"
CONTRACTS = {
    "rust-unreachable": ("Rust", "main.rs", [("SKY-UC002", 4)]),
    "rust-conditional-return": ("Rust", "main.rs", []),
    "rust-duplicate-bodies": ("Rust", "main.rs", [("SKY-Q305", 6)]),
    "rust-distinct-bodies": ("Rust", "main.rs", []),
    "csharp-unreachable": ("C#", "Example.cs", [("SKY-UC002", 4)]),
    "csharp-conditional-return": ("C#", "Example.cs", []),
    "csharp-conditional-compilation": ("C#", "Example.cs", []),
}


@pytest.mark.parametrize("name", CONTRACTS)
def test_native_quality_pairs_match_exact_rules_locations_and_coverage(
    name, monkeypatch
):
    language, filename, expected = CONTRACTS[name]
    case = next(
        case
        for case in quality.load_manifest(MANIFEST)["cases"]
        if case["id"] == "quality-corpus-" + name
    )
    captured = []
    scan = quality._scan_case

    def capture(*args, **kwargs):
        report = scan(*args, **kwargs)
        captured.append(report)
        return report

    monkeypatch.setattr(quality, "_scan_case", capture)
    result = quality.run_case(case, MANIFEST)
    report = captured[0]
    assert result["scored"] is True
    assert result["failures"] == []
    assert report["analysis_summary"]["languages"] == {language: 1}
    assert report["analysis_summary"]["total_files"] == 1
    assert not report.get("analysis_errors")
    # The corpus contracts name these source rules. Repository-policy advice
    # remains in the native report and is not relabelled as a source defect.
    findings = [
        row
        for row in report.get("quality", [])
        if row.get("rule_id") in {"SKY-UC002", "SKY-Q305"}
    ]
    assert [
        (row["rule_id"], Path(row["file"]).name, row["line"]) for row in findings
    ] == [(rule, filename, line) for rule, line in expected]
    assert all(is_listed(row, "quality") for row in findings)
