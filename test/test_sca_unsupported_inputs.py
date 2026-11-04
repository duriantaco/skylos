"""Dependency files Skylos does not read are named, never skipped silently."""

from __future__ import annotations

import json

import pytest

from skylos.core.gate_incomplete import incomplete_analysis_reasons
from skylos.core.gatekeeper import (
    _sca_required_coverage_reasons,
    sca_coverage_warnings,
)
from skylos.core.sca_baseline import dependency_scan_complete
from skylos.core.sca_coverage import (
    UNSUPPORTED_INPUTS_COVERAGE_STATUS,
    unsupported_inputs_line,
)
from skylos.reporting.assessment_display import dependency_coverage_lines
from skylos.rules.sca import vulnerability_scanner as scanner


def _write(root, rel, text=""):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest fixture under tmp_path


def _names(receipt, key="unsupported_inputs"):
    return sorted(entry["name"] for entry in receipt[key])


def test_repo_with_only_unread_dependency_files_names_them(tmp_path):
    _write(tmp_path, "Package.resolved", "{}")
    _write(tmp_path, "Gemfile", 'gem "rack", "2.2.3"\n')

    receipt = scanner.collect_dependencies(tmp_path).receipt

    assert receipt["status"] == "no_supported_manifests"
    assert receipt["complete"] is False
    assert receipt["unsupported_lockfile_count"] == 1
    assert receipt["unsupported_manifest_count"] == 1
    assert receipt["unsupported_ecosystems"] == ["RubyGems", "SwiftPM"]
    assert _names(receipt) == ["Gemfile", "Package.resolved"]
    result = {"analysis_summary": {"sca_coverage": receipt}}
    [warning] = sca_coverage_warnings(result)
    assert "Package.resolved" in warning and "SwiftPM: not supported yet" in warning
    assert "Gemfile.lock is read" in warning
    assert "no supported dependency manifests found" not in warning


def test_mixed_repo_is_not_complete_but_not_an_operational_failure(
    tmp_path, monkeypatch
):
    _write(
        tmp_path,
        "package.json",
        json.dumps({"name": "x", "dependencies": {"left-pad": "1.3.0"}}),
    )
    _write(tmp_path, "ios/Podfile.lock", "PODS:\n")
    monkeypatch.setattr(
        scanner,
        "_query_osv_batch",
        lambda deps, cache: scanner.OsvQueryResult(
            [], receipt={"status": "complete", "complete": True}
        ),
    )

    receipt = scanner.scan_dependencies(tmp_path).receipt

    assert receipt["status"] == UNSUPPORTED_INPUTS_COVERAGE_STATUS
    assert receipt["complete"] is False
    assert receipt["supported_inputs_complete"] is True
    assert receipt["queried_dependency_count"] == 1
    assert _names(receipt) == ["Podfile.lock"]
    result = {"analysis_summary": {"sca_coverage": receipt}}
    # A coverage limit, not a reason for exit 2.
    assert incomplete_analysis_reasons(result) == []
    # The supported part can still be baselined.
    assert dependency_scan_complete(result) is True
    [warning] = sca_coverage_warnings(result)
    assert warning.startswith("SCA coverage limited: 1 dependencies queried.")
    assert "Podfile.lock (CocoaPods: not supported yet)" in warning
    lines = dependency_coverage_lines(result["analysis_summary"])
    assert any(line.startswith("Dependency files not read:") for line in lines)
    # Required coverage still fails, with the specific reason only.
    reasons = [
        str(r) for r in _sca_required_coverage_reasons(receipt, require_resolved=False)
    ]
    assert reasons == [
        "Required SCA coverage incomplete: unsupported dependency manifest or lockfile inventory"
    ]


@pytest.mark.parametrize(
    ("files", "ecosystem"),
    [
        (("Package.resolved",), "SwiftPM"),
        (("Podfile.lock",), "CocoaPods"),
        (("mix.lock",), "Hex"),
        (("Gemfile",), "RubyGems"),
        (("build.gradle", "build.gradle.kts"), "Gradle"),
    ],
)
def test_other_ecosystems_are_named(tmp_path, files, ecosystem):
    for name in files:
        _write(tmp_path, name)

    receipt = scanner.collect_dependencies(tmp_path).receipt

    assert _names(receipt) == sorted(files)
    assert receipt["unsupported_ecosystems"] == [ecosystem]
    assert ecosystem in unsupported_inputs_line(receipt)


def test_go_sum_next_to_modern_go_mod_is_not_a_gap(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/x\n\ngo 1.21\n")
    _write(tmp_path, "go.sum", "")

    receipt = scanner.collect_dependencies(tmp_path).receipt

    assert receipt["unsupported_lockfile_count"] == 0
    assert _names(receipt, "skipped_inputs") == ["go.sum"]
    assert "read from go.mod" in receipt["skipped_inputs"][0]["reason"]
    assert receipt["status"] != UNSUPPORTED_INPUTS_COVERAGE_STATUS


def test_go_sum_next_to_pre_117_go_mod_is_a_gap(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/x\n\ngo 1.16\n")
    _write(tmp_path, "go.sum", "")

    receipt = scanner.collect_dependencies(tmp_path).receipt

    assert receipt["unsupported_lockfile_count"] == 1
    assert "before 1.17" in receipt["unsupported_inputs"][0]["reason"]


def test_binary_bun_lockfile_named_unless_text_lockfile_present(tmp_path):
    _write(tmp_path, "a/package.json", '{"name": "a"}')
    _write(tmp_path, "a/bun.lockb", "")
    _write(tmp_path, "b/package.json", '{"name": "b"}')
    _write(tmp_path, "b/bun.lockb", "")
    _write(tmp_path, "b/bun.lock", '{"lockfileVersion": 1, "packages": {}}')

    receipt = scanner.collect_dependencies(tmp_path).receipt

    [entry] = receipt["unsupported_inputs"]
    assert entry["file"].endswith("a/bun.lockb")
    assert "--save-text-lockfile" in entry["reason"]
    assert _names(receipt, "skipped_inputs") == ["bun.lockb"]
    assert receipt["supported_lockfile_count"] == 1


def test_vendored_copies_are_not_the_projects_manifests(tmp_path):
    _write(tmp_path, "vendor/acme/lib/composer.json", "{}")

    receipt = scanner.collect_dependencies(tmp_path).receipt

    assert receipt["unsupported_manifest_count"] == 0
    assert receipt["unsupported_inputs"] == []


def test_examples_are_bounded_counts_are_not(tmp_path):
    for index in range(30):
        _write(tmp_path, f"modules/m{index}/build.gradle")

    receipt = scanner.collect_dependencies(tmp_path).receipt

    assert receipt["unsupported_manifest_count"] == 30
    assert len(receipt["unsupported_inputs"]) == scanner.MAX_UNSUPPORTED_INPUT_EXAMPLES
    assert "more in sca_coverage.unsupported_inputs" in unsupported_inputs_line(receipt)
