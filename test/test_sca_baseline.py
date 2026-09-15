import copy
import json
from pathlib import Path

import pytest

from skylos.core.baseline import filter_new_findings, load_baseline, save_baseline
from skylos.core.sca_baseline import dependency_fingerprints, dependency_scan_complete


def finding(root, **metadata):
    path = str(root / "package-lock.json")
    return {
        "rule_id": "SKY-SCA-GHSA-test-one",
        "file": path,
        "line": 10,
        "severity": "HIGH",
        "metadata": {
            "ecosystem": "npm",
            "package_name": "example",
            "package_version": "1.0.0",
            "vuln_id": "GHSA-test-one",
            "advisory_status": "complete",
            "dependency_occurrences": [
                {"file": path, "line": 10, "dependency_roots": [""]}
            ],
            **metadata,
        },
    }


def result(*findings, complete=True):
    return {
        "dependency_vulnerabilities": list(findings),
        "analysis_summary": {
            "dependency_vulnerabilities_count": len(findings),
            "sca_coverage": {
                "status": "complete" if complete else "incomplete",
                "complete": complete,
                "category_complete": False,
                "dependency_count": 17,
            },
        },
    }


def saved(root, report):
    save_baseline(root, report)
    return load_baseline(root)


def test_dependency_roundtrip_preserves_evidence_and_coverage(tmp_path):
    report = result(finding(tmp_path))
    before = copy.deepcopy(report)
    baseline = saved(tmp_path, report)
    filtered = filter_new_findings(report, baseline, project_root=tmp_path)
    assert filtered["dependency_vulnerabilities"] == []
    assert (
        filtered["baseline_dependency_vulnerabilities"]
        == report["dependency_vulnerabilities"]
    )
    assert filtered["analysis_summary"]["dependency_vulnerabilities_count"] == 0
    assert (
        filtered["analysis_summary"]["sca_coverage"]
        == report["analysis_summary"]["sca_coverage"]
    )
    assert baseline["counts"]["dependency_vulnerabilities"] == 1
    assert baseline["dependency_baseline"]["captured_count"] == 1
    assert report == before


def test_lines_and_checkout_root_do_not_define_identity(tmp_path):
    report = result(finding(tmp_path))
    baseline = saved(tmp_path, report)
    relocated = finding(Path("/different/checkout"))
    relocated["line"] = 300
    relocated["metadata"]["dependency_occurrences"][0]["line"] = 300
    filtered = filter_new_findings(
        result(relocated), baseline, project_root="/different/checkout"
    )
    assert filtered["dependency_vulnerabilities"] == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("package_name", "other"),
        ("package_version", "1.0.1"),
        ("ecosystem", "Go"),
        ("vuln_id", "GHSA-test-two"),
    ],
)
def test_changed_identity_is_new(tmp_path, field, value):
    baseline = saved(tmp_path, result(finding(tmp_path)))
    changed = finding(tmp_path, **{field: value})
    if field == "vuln_id":
        changed["rule_id"] = f"SKY-SCA-{value}"
    assert filter_new_findings(result(changed), baseline, project_root=tmp_path)[
        "dependency_vulnerabilities"
    ] == [changed]


@pytest.mark.parametrize(
    "change", ["file", "workspace", "extra_occurrence", "dev", "optional", "severity"]
)
def test_new_usage_scope_remains_visible(tmp_path, change):
    original = finding(tmp_path)
    baseline = saved(tmp_path, result(original))
    current = copy.deepcopy(original)
    occurrence = current["metadata"]["dependency_occurrences"][0]
    if change == "file":
        current["file"] = occurrence["file"] = str(tmp_path / "other/package-lock.json")
    elif change == "workspace":
        occurrence["dependency_roots"].append("packages/new-app")
    elif change == "extra_occurrence":
        current["metadata"]["dependency_occurrences"].append(
            {"file": str(tmp_path / "other/package.json")}
        )
    elif change == "severity":
        current["severity"] = "CRITICAL"
    else:
        occurrence[f"dependency_{change}"] = True
    assert filter_new_findings(result(current), baseline, project_root=tmp_path)[
        "dependency_vulnerabilities"
    ] == [current]


def test_root_and_group_order_do_not_define_identity(tmp_path):
    original = finding(tmp_path)
    occurrence = original["metadata"]["dependency_occurrences"][0]
    occurrence["dependency_roots"] = ["app", "worker"]
    occurrence["dependency_groups"] = ["production", "lint"]
    baseline = saved(tmp_path, result(original))
    occurrence["dependency_roots"].reverse()
    occurrence["dependency_groups"].reverse()
    assert (
        filter_new_findings(result(original), baseline, project_root=tmp_path)[
            "dependency_vulnerabilities"
        ]
        == []
    )


@pytest.mark.parametrize("change", ["peer", "patch", "workspace", "platform"])
def test_pnpm_snapshot_context_changes_remain_new(tmp_path, change):
    original = finding(tmp_path)
    original["file"] = str(tmp_path / "pnpm-lock.yaml")
    occurrence = original["metadata"]["dependency_occurrences"][0]
    occurrence.update(
        file=original["file"],
        package_path="example@1.0.0(react@18.0.0)",
        dependency_roots=["packages/app"],
        dependency_markers={"os": ["linux"]},
    )
    baseline = saved(tmp_path, result(original))
    current = copy.deepcopy(original)
    changed = current["metadata"]["dependency_occurrences"][0]
    if change == "peer":
        changed["package_path"] = "example@1.0.0(react@19.0.0)"
    elif change == "patch":
        changed["package_path"] = "example@1.0.0(patch_hash=abc)(react@18.0.0)"
    elif change == "workspace":
        changed["dependency_roots"].append("packages/worker")
    else:
        changed["dependency_markers"] = {"os": ["linux", "darwin"]}
    assert filter_new_findings(result(current), baseline, project_root=tmp_path)[
        "dependency_vulnerabilities"
    ] == [current]


def test_pnpm_line_movement_does_not_change_snapshot_identity(tmp_path):
    original = finding(tmp_path)
    original["file"] = str(tmp_path / "pnpm-lock.yaml")
    occurrence = original["metadata"]["dependency_occurrences"][0]
    occurrence.update(file=original["file"], package_path="example@1.0.0(react@18.0.0)")
    baseline = saved(tmp_path, result(original))
    original["line"] = occurrence["line"] = 300
    assert (
        filter_new_findings(result(original), baseline, project_root=tmp_path)[
            "dependency_vulnerabilities"
        ]
        == []
    )


def test_pypi_names_are_canonical_but_npm_names_are_not(tmp_path):
    old = finding(tmp_path, ecosystem="PyPI", package_name="My_Package")
    new = finding(tmp_path, ecosystem="PyPI", package_name="my-package")
    baseline = saved(tmp_path, result(old))
    assert (
        filter_new_findings(result(new), baseline, project_root=tmp_path)[
            "dependency_vulnerabilities"
        ]
        == []
    )
    old["metadata"]["ecosystem"] = new["metadata"]["ecosystem"] = "npm"
    assert dependency_fingerprints(old, tmp_path) != dependency_fingerprints(
        new, tmp_path
    )


@pytest.mark.parametrize(
    "metadata",
    [
        {"package_name": ""},
        {"package_version": None},
        {"ecosystem": "unknown"},
        {"vuln_id": "../bad"},
        {"vuln_id": "GHSA-another-id"},
        {"advisory_status": "unavailable"},
        {"dependency_occurrences": []},
        {"dependency_occurrences": [None]},
        {"dependency_occurrences": "bad"},
        {"dependency_occurrences": [{"file": "../outside/package.json"}]},
        {
            "dependency_occurrences": [
                {"file": "package-lock.json", "dependency_roots": "app"}
            ]
        },
    ],
)
def test_ambiguous_identity_never_suppresses(tmp_path, metadata):
    item = finding(tmp_path, **metadata)
    baseline = saved(tmp_path, result(item))
    assert baseline["dependency_baseline"]["captured_count"] == 0
    assert baseline["dependency_baseline"]["unmatched_count"] == 1
    assert filter_new_findings(result(item), baseline, project_root=tmp_path)[
        "dependency_vulnerabilities"
    ] == [item]


@pytest.mark.parametrize(
    "section",
    [
        None,
        {},
        [],
        {"version": True, "fingerprints": []},
        {"version": 999, "fingerprints": []},
        {"version": 1, "fingerprints": ["bad"]},
        {"version": 1, "fingerprints": [None]},
    ],
)
def test_legacy_or_bad_schema_does_not_suppress(tmp_path, section):
    item = finding(tmp_path)
    baseline = {
        "fingerprints": [f"{item['rule_id']}:{item['file']}:10"],
        "dependency_baseline": section,
    }
    assert filter_new_findings(result(item), baseline, project_root=tmp_path)[
        "dependency_vulnerabilities"
    ] == [item]


@pytest.mark.parametrize(
    "receipt",
    [
        None,
        {},
        {"status": "complete", "complete": False},
        {"status": "incomplete", "complete": True},
        {"status": "unknown", "complete": True},
        {"status": "complete", "complete": 1},
    ],
)
def test_incomplete_receipt_never_hides_known_finding(tmp_path, receipt):
    item = finding(tmp_path)
    baseline = saved(tmp_path, result(item))
    report = result(item)
    report["analysis_summary"]["sca_coverage"] = receipt
    assert not dependency_scan_complete(report)
    filtered = filter_new_findings(report, baseline, project_root=tmp_path)
    assert filtered["dependency_vulnerabilities"] == [item]
    assert filtered["analysis_summary"]["sca_coverage"] == receipt


def test_incomplete_snapshot_has_no_dependency_suppression_data(tmp_path):
    baseline = saved(tmp_path, result(finding(tmp_path), complete=False))
    assert "dependency_baseline" not in baseline


def test_malformed_receipt_or_severity_is_not_suppression_evidence(tmp_path):
    report = result(finding(tmp_path))
    report["analysis_summary"]["sca_coverage"]["status"] = []
    assert not dependency_scan_complete(report)
    item = finding(tmp_path)
    item["severity"] = []
    assert dependency_fingerprints(item, tmp_path) is None


def test_explicit_empty_override_cannot_fall_back_to_local_baseline(tmp_path):
    report = result(finding(tmp_path))
    baseline = saved(tmp_path, report)
    filtered = filter_new_findings(
        report, baseline, project_root=tmp_path, dependency_baseline={}
    )
    assert (
        filtered["dependency_vulnerabilities"] == report["dependency_vulnerabilities"]
    )


def test_explicit_policy_disable_keeps_all_findings(tmp_path):
    report = result(finding(tmp_path))
    baseline = saved(tmp_path, report)
    filtered = filter_new_findings(
        report,
        baseline,
        project_root=tmp_path,
        dependency_disabled_reason="strict_requires_full_findings",
    )
    assert (
        filtered["dependency_vulnerabilities"] == report["dependency_vulnerabilities"]
    )


def test_baseline_save_rejects_symlink_and_keeps_target(tmp_path):
    baseline_dir = tmp_path / ".skylos"
    baseline_dir.mkdir()
    target = tmp_path / "original.json"
    target.write_text("original")
    (baseline_dir / "baseline.json").symlink_to(target)
    with pytest.raises(OSError):
        save_baseline(tmp_path, result(finding(tmp_path)))
    assert target.read_text() == "original"
    assert load_baseline(tmp_path) is None


def test_invalid_or_non_object_baseline_is_unavailable(tmp_path):
    directory = tmp_path / ".skylos"
    directory.mkdir()
    path = directory / "baseline.json"
    for content in ("{broken", "[]", "null"):
        path.write_text(content)
        assert load_baseline(tmp_path) is None


def test_baseline_fingerprints_do_not_store_checkout_paths(tmp_path):
    baseline = saved(tmp_path, result(finding(tmp_path)))
    assert str(tmp_path) not in json.dumps(baseline)
