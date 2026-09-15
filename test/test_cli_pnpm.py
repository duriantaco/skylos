"""pnpm CLI JSON, SARIF, exit codes and baselines with mocked advisory HTTP."""

import pytest

from skylos.core.baseline import save_baseline
from test.test_cli_sca_baseline import (
    local_baseline_environment as local_baseline_environment,
)
from test.test_cli_sca_sarif import (
    RULE_ID,
    _assert_matching_dependency_reports,
    _run_cli,
    osv as osv,
    project as project,
)
from test.test_sca_pnpm import _document, _write_lockfile


@pytest.mark.parametrize("version", [6, 9])
def test_cli_pnpm_json_sarif_and_gate_agree(project, monkeypatch, osv, version):
    lockfile = _write_lockfile(project, _document(version))

    exit_code, result, sarif = _run_cli(project, monkeypatch)

    assert exit_code == 1
    _assert_matching_dependency_reports(result, sarif, lockfile)
    assert result["analysis_summary"]["sca_coverage"]["complete"] is True
    finding = result["dependency_vulnerabilities"][0]
    assert finding["metadata"]["package_name"] == "example"
    assert finding["metadata"]["lockfile_version"] == version
    assert finding["metadata"]["dependency_roots"] == [""]
    assert finding["metadata"]["fixed_version"] == "9.9.9"
    assert finding["severity"] == "HIGH"


@pytest.mark.parametrize("version", [6, 9])
@pytest.mark.parametrize("force", [False, True])
def test_cli_pnpm_detail_failure_keeps_both_reports_and_exit_two(
    project, monkeypatch, osv, version, force
):
    lockfile = _write_lockfile(project, _document(version))
    osv.fail_details = True

    exit_code, result, sarif = _run_cli(
        project, monkeypatch, *(("--force",) if force else ())
    )

    assert exit_code == 2
    _assert_matching_dependency_reports(result, sarif, lockfile)
    assert result["analysis_summary"]["sca_coverage"]["complete"] is False
    metadata = result["dependency_vulnerabilities"][0]["metadata"]
    assert metadata["advisory_status"] == "unavailable"
    assert metadata["advisory_error"] == "advisory_transport_error"
    assert metadata["fixed_version"] is None


@pytest.mark.parametrize("version", [6, 9])
def test_cli_pnpm_incomplete_graph_retains_known_findings_with_force(
    project, monkeypatch, osv, version
):
    lockfile = _write_lockfile(
        project,
        _document(
            version,
            packages={"example@1.2.3": {"dependencies": {"missing": "2.0.0"}}},
        ),
    )

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--force")

    assert exit_code == 2
    _assert_matching_dependency_reports(result, sarif, lockfile)
    assert result["analysis_summary"]["sca_coverage"]["complete"] is False
    assert result["dependency_vulnerabilities"][0]["metadata"]["advisory_status"] == (
        "complete"
    )


@pytest.mark.parametrize(
    "content",
    ["lockfileVersion: [\n", "lockfileVersion: '999.0'\npackages: {}\n"],
    ids=["malformed", "unsupported-version"],
)
def test_cli_pnpm_invalid_lockfile_writes_reports_and_fails(
    project, monkeypatch, osv, content
):
    lockfile = project / "pnpm-lock.yaml"
    lockfile.write_text(  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
        content, encoding="utf-8"
    )

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--force")

    assert exit_code == 2
    assert result["dependency_vulnerabilities"] == []
    assert sarif["runs"][0]["results"] == []
    assert result["analysis_summary"]["sca_coverage"]["complete"] is False
    assert osv.queries == []


@pytest.mark.parametrize("version", [6, 9])
def test_cli_pnpm_clean_advisory_response_passes(project, monkeypatch, osv, version):
    _write_lockfile(project, _document(version))
    osv.vulnerable = False

    exit_code, result, sarif = _run_cli(project, monkeypatch)

    assert exit_code == 0
    assert result["dependency_vulnerabilities"] == []
    assert sarif["runs"][0]["results"] == []
    assert result["analysis_summary"]["sca_coverage"]["complete"] is True
    assert osv.advisory_requests == []


@pytest.mark.parametrize("version", [6, 9])
def test_cli_pnpm_baseline_filters_only_known_findings(
    project, monkeypatch, osv, version
):
    _write_lockfile(project, _document(version))
    initial_exit, initial, _ = _run_cli(project, monkeypatch)
    assert initial_exit == 1
    save_baseline(project, initial)

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")

    assert exit_code == 0
    assert result["dependency_vulnerabilities"] == []
    assert sarif["runs"][0]["results"] == []
    assert [
        item["rule_id"] for item in result["baseline_dependency_vulnerabilities"]
    ] == [RULE_ID]
    assert result["analysis_summary"]["dependency_baseline"]["existing_count"] == 1


@pytest.mark.parametrize("version", [6, 9])
@pytest.mark.parametrize("change", ["promote_to_runtime", "new_workspace"])
def test_cli_pnpm_baseline_keeps_new_dependency_usage(
    project, monkeypatch, osv, version, change
):
    root = {"devDependencies": {"example": {"specifier": "1.2.3", "version": "1.2.3"}}}
    document = _document(version, importers={".": root})
    lockfile = _write_lockfile(project, document)
    initial_exit, initial, _ = _run_cli(project, monkeypatch)
    assert initial_exit == 1
    save_baseline(project, initial)
    if change == "promote_to_runtime":
        root["dependencies"] = root.pop("devDependencies")
    else:
        document["importers"]["packages/new-consumer"] = {
            "devDependencies": {"example": {"specifier": "1.2.3", "version": "1.2.3"}}
        }
    _write_lockfile(project, document)

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")

    assert exit_code == 1
    _assert_matching_dependency_reports(result, sarif, lockfile)
    assert result.get("baseline_dependency_vulnerabilities", []) == []
    assert result["analysis_summary"]["dependency_baseline"]["new_count"] == 1


@pytest.mark.parametrize("version", [6, 9])
def test_cli_pnpm_baseline_cannot_hide_an_advisory_failure(
    project, monkeypatch, osv, version
):
    lockfile = _write_lockfile(project, _document(version))
    initial_exit, initial, _ = _run_cli(project, monkeypatch)
    assert initial_exit == 1
    save_baseline(project, initial)
    osv.fail_details = True

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline", "--force")

    assert exit_code == 2
    _assert_matching_dependency_reports(result, sarif, lockfile)
    assert result.get("baseline_dependency_vulnerabilities", []) == []
    assert (
        result["analysis_summary"]["dependency_baseline"]["status"] == "scan_incomplete"
    )
