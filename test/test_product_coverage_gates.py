"""Requested coverage must be visible and distinguish failures from limits."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.config import load_config
from skylos.core.gatekeeper import (
    build_summary_markdown,
    check_gate,
    run_gate_interaction,
    sca_coverage_warnings,
)
from skylos.rules.config import scan_config_files
from skylos.rules.config.cicd import github_actions
from test.test_cli_sca_sarif import _run_cli, osv as osv, project as project
from test.test_git_hook_regressions import _git


REQUIRED_SCA = {
    "gate": {"coverage": {"required": ["sca"], "require_resolved_versions": True}}
}


def _sca_receipt(**overrides):
    receipt = {
        "status": "complete",
        "complete": True,
        "supported_manifest_candidate_count": 1,
        "dependency_count": 0,
        "queried_dependency_count": 0,
        "unresolved_dependency_count": 0,
        "unresolved_lockfile_dependency_count": 0,
        "unsupported_lockfile_count": 0,
    }
    receipt.update(overrides)
    return receipt


def _workflow(root, text):
    path = root / ".github" / "workflows" / "ci.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")  # skylos: ignore[SKY-D324] all callers use fresh pytest tmp_path roots and fixed ci.yml
    return path


@pytest.mark.parametrize("text", ["jobs: [\n", "- not-a-workflow\n", "", "self: &self {child: *self}\n"])
def test_unsafe_yaml_is_an_analysis_error_without_source_excerpt(tmp_path, text):
    path = _workflow(tmp_path, text)
    errors = []
    assert scan_config_files(tmp_path, analysis_errors=errors) == []
    assert len(errors) == 1
    assert errors[0]["kind"] == "config_parse_error"
    assert errors[0]["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    assert errors[0]["file"] == str(path)
    assert errors[0]["component"] == "github_actions"
    assert "child" not in errors[0]["message"]


def test_action_parser_unavailable_is_reported(tmp_path, monkeypatch):
    _workflow(tmp_path, 'name: CI\n"on": push\njobs: {}\n')
    monkeypatch.setattr(github_actions, "yaml", None)
    errors = []
    assert github_actions.scan_github_actions(tmp_path, analysis_errors=errors) == []
    assert errors[0]["kind"] == "config_parser_unavailable"


@pytest.mark.parametrize("reason", ["size", "symlink", "utf8", "broken_symlink"])
def test_unreadable_action_file_is_not_a_clean_scan(tmp_path, monkeypatch, reason):
    path = _workflow(tmp_path, "name: CI\n")
    if reason == "size":
        monkeypatch.setattr(github_actions, "MAX_YAML_BYTES", 1)
    elif reason == "utf8":
        path.write_bytes(b"name: \xff\n")
    else:
        path.unlink()
        target = tmp_path / "outside.yml"
        if reason == "symlink":
            target.write_text("name: outside\n", encoding="utf-8")
        path.symlink_to(target)
    errors = []
    assert github_actions.scan_github_actions(tmp_path, analysis_errors=errors) == []
    assert errors[0]["kind"] == "config_read_error"
    assert errors[0]["file"] == str(path)


@pytest.mark.parametrize("with_source", [False, True])
def test_analyzer_propagates_actions_coverage_with_or_without_source(tmp_path, with_source):
    path = _workflow(tmp_path, "jobs: [\n")
    if with_source:
        (tmp_path / "app.py").write_text("value = 1\nprint(value)\n", encoding="utf-8")
    result = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    assert len(result["analysis_errors"]) == 1
    assert result["analysis_errors"][0]["file"] == str(path)
    assert result["analysis_summary"]["analysis_error_count"] == 1
    assert run_gate_interaction(result=result, config={}, strict=True, force=True, advisory=True) == 2


def test_diff_does_not_block_on_an_unselected_malformed_workflow(tmp_path, monkeypatch):
    _workflow(tmp_path, "jobs: [\n")
    source = tmp_path / "app.py"
    source.write_text("value = 1\nprint(value)\n", encoding="utf-8")
    monkeypatch.setenv("SKYLOS_DIFF_BASE", "HEAD")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.name", "Skylos Tests")
    _git(tmp_path, "config", "user.email", "skylos-tests@example.invalid")
    _git(tmp_path, "add", "--", "app.py", ".github/workflows/ci.yml")
    _git(tmp_path, "commit", "-qm", "fixture baseline")
    result = json.loads(analyze(str(tmp_path), enable_danger=True, changed_files={str(source)}, grep_verify=False))
    assert result["analysis_errors"] == []


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize(
    "receipt, phrase",
    [
        (None, "not recorded"),
        ({"status": "no_supported_manifests", "complete": False}, "no supported"),
        (_sca_receipt(status="complete_with_unresolved_versions", unresolved_dependency_count=1), "must be resolved"),
        (_sca_receipt(unsupported_lockfile_count=1), "unsupported"),
    ],
)
def test_required_sca_policy_rejects_missing_or_limited_coverage(receipt, phrase, strict):
    result = {"analysis_summary": {}}
    if receipt is not None:
        result["analysis_summary"]["sca_coverage"] = receipt
    passed, reasons = check_gate(result, REQUIRED_SCA, strict=strict)
    assert passed is False
    assert any(phrase in reason for reason in reasons)
    assert run_gate_interaction(result=result, config=REQUIRED_SCA, strict=strict) == 1


@pytest.mark.parametrize("status", ["incomplete", "unavailable", "unknown"])
def test_required_sca_operational_failures_stay_exit_two(status):
    result = {"analysis_summary": {"sca_coverage": {"status": status, "complete": False}}}
    assert run_gate_interaction(result=result, config=REQUIRED_SCA, force=True, advisory=True) == 2


def test_supported_empty_dependency_inventory_satisfies_required_coverage():
    result = {"analysis_summary": {"sca_coverage": _sca_receipt()}}
    assert check_gate(result, REQUIRED_SCA) == (True, [])


def test_unresolved_versions_are_optional_policy_not_operational_failure():
    result = {"analysis_summary": {"sca_coverage": _sca_receipt(status="complete_with_unresolved_versions", unresolved_dependency_count=1)}}
    config = {"gate": {"coverage": {"required": ["sca"]}}}
    assert check_gate(result, config) == (True, [])
    assert "unresolved versions" in sca_coverage_warnings(result)[0]


@pytest.mark.parametrize(
    "field, phrase",
    [
        ("supported_manifest_candidate_count", "no supported"),
        ("dependency_count", "missing query accounting"),
        ("queried_dependency_count", "missing query accounting"),
        ("unresolved_dependency_count", "resolution was not verified"),
        ("unresolved_lockfile_dependency_count", "resolution was not verified"),
    ],
)
@pytest.mark.parametrize("invalid", [None, True, -1, "0", 0.5, 9_007_199_254_740_992])
def test_required_sca_rejects_missing_or_invalid_inventory_accounting(field, phrase, invalid):
    receipt = _sca_receipt(**{field: invalid})
    if invalid is None:
        del receipt[field]
    passed, reasons = check_gate({"analysis_summary": {"sca_coverage": receipt}}, REQUIRED_SCA)
    assert passed is False
    assert any(phrase in reason for reason in reasons)


@pytest.mark.parametrize(
    "overrides",
    [
        {"dependency_count": 1, "queried_dependency_count": 0, "query": {"complete": True}},
        {"dependency_count": 1, "queried_dependency_count": 1},
        {"dependency_count": 1, "queried_dependency_count": 1, "query": {"complete": False}},
        {"dependency_count": 1, "queried_dependency_count": 1, "query": {"complete": "true"}},
    ],
)
def test_required_sca_requires_every_dependency_and_a_completed_query(overrides):
    result = {"analysis_summary": {"sca_coverage": _sca_receipt(**overrides)}}
    passed, reasons = check_gate(result, REQUIRED_SCA)
    assert passed is False
    assert reasons == ["Required SCA coverage incomplete: not every inventoried dependency was queried"]


def test_fully_queried_inventory_satisfies_required_coverage():
    result = {"analysis_summary": {"sca_coverage": _sca_receipt(
        dependency_count=2,
        queried_dependency_count=2,
        query={"complete": True},
    )}}
    assert check_gate(result, REQUIRED_SCA) == (True, [])


def test_integer_valued_json_numbers_match_cloud_accounting():
    result = {"analysis_summary": {"sca_coverage": _sca_receipt(
        supported_manifest_candidate_count=1.0,
        dependency_count=0.0,
        queried_dependency_count=0.0,
        unresolved_dependency_count=0.0,
        unresolved_lockfile_dependency_count=0.0,
    )}}
    assert check_gate(result, REQUIRED_SCA) == (True, [])


@pytest.mark.parametrize("field", ["unsupported_manifest_count", "unsupported_lockfile_count"])
def test_required_sca_rejects_supported_inventory_mixed_with_unsupported_formats(field):
    result = {"analysis_summary": {"sca_coverage": _sca_receipt(**{field: 1})}}
    passed, reasons = check_gate(result, REQUIRED_SCA)
    assert passed is False
    assert any("unsupported dependency manifest or lockfile" in reason for reason in reasons)


@pytest.mark.parametrize("field", ["unsupported_manifest_count", "unsupported_lockfile_count"])
@pytest.mark.parametrize("invalid", [None, True, -1, "0", 0.5, 9_007_199_254_740_992])
def test_required_sca_rejects_explicit_malformed_unsupported_accounting(field, invalid):
    result = {"analysis_summary": {"sca_coverage": _sca_receipt(**{field: invalid})}}
    passed, reasons = check_gate(result, REQUIRED_SCA)
    assert passed is False
    assert reasons == ["Required SCA coverage incomplete: invalid unsupported inventory accounting"]


def test_legacy_receipts_may_omit_unsupported_format_counters():
    receipt = _sca_receipt()
    receipt.pop("unsupported_lockfile_count")
    assert "unsupported_manifest_count" not in receipt
    assert check_gate({"analysis_summary": {"sca_coverage": receipt}}, REQUIRED_SCA) == (True, [])


def test_largest_safe_integer_supported_inventory_count_is_valid():
    receipt = _sca_receipt(supported_manifest_candidate_count=9_007_199_254_740_991)
    assert check_gate({"analysis_summary": {"sca_coverage": receipt}}, REQUIRED_SCA) == (True, [])


@pytest.mark.parametrize("invalid", [None, True, 1, ["complete"], {"status": "complete"}])
def test_required_sca_rejects_malformed_completion_status_without_crashing(invalid):
    result = {"analysis_summary": {"sca_coverage": _sca_receipt(status=invalid)}}
    passed, reasons = check_gate(result, REQUIRED_SCA)
    assert passed is False
    assert reasons == ["Required SCA coverage incomplete: supported dependency inventory was not completed"]


@pytest.mark.parametrize(
    "overrides",
    [{"unresolved_dependency_count": 1}, {"unresolved_lockfile_dependency_count": 1},
     {"status": "complete_with_unresolved_versions"}],
)
def test_resolved_policy_rejects_hidden_unresolved_versions(overrides):
    result = {"analysis_summary": {"sca_coverage": _sca_receipt(**overrides)}}
    passed, reasons = check_gate(result, REQUIRED_SCA)
    assert passed is False
    assert any("must be resolved" in reason for reason in reasons)


@pytest.mark.parametrize("resolved", [True, "true"])
def test_resolved_versions_setting_alone_implies_required_sca(resolved):
    config = {"gate": {"coverage": {"require_resolved_versions": resolved}}}
    assert check_gate({}, config)[0] is False
    assert check_gate({"analysis_summary": {"sca_coverage": _sca_receipt()}}, config) == (True, [])
    incomplete = {"analysis_summary": {"sca_coverage": _sca_receipt(unresolved_dependency_count=1)}}
    assert check_gate(incomplete, config)[0] is False


@pytest.mark.parametrize("resolved", [False, "false", "True", 1])
def test_other_resolved_policy_values_do_not_enable_required_coverage(resolved):
    config = {"gate": {"coverage": {"require_resolved_versions": resolved}}}
    assert check_gate({}, config) == (True, [])


def test_repo_cannot_loosen_synced_required_coverage(tmp_path, monkeypatch):
    monkeypatch.delenv("SKYLOS_CONFIG_FILE", raising=False)
    monkeypatch.delenv("SKYLOS_POLICY_BASE", raising=False)
    config_dir = tmp_path / ".skylos"
    config_dir.mkdir()
    (config_dir / "config.yaml").write_text(
        "gate:\n  coverage:\n    required: [sca]\n    require_resolved_versions: true\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        '[tool.skylos.gate.coverage]\nrequired = []\nrequire_resolved_versions = false\n',
        encoding="utf-8",
    )
    config = load_config(tmp_path)
    assert config["gate"]["coverage"] == REQUIRED_SCA["gate"]["coverage"]
    assert check_gate({}, config)[0] is False


@pytest.mark.parametrize("strict", [False, True])
def test_real_cli_gate_rejects_required_unresolved_versions(project, monkeypatch, osv, strict):
    (project / "requirements.txt").write_text("requests>=2\n", encoding="utf-8")  # skylos: ignore[SKY-D324] project fixture creates fresh tmp_path/project
    (project / "pyproject.toml").write_text(  # skylos: ignore[SKY-D324] project fixture creates fresh tmp_path/project
        '[tool.skylos.gate.coverage]\nrequired = ["sca"]\nrequire_resolved_versions = true\n',
        encoding="utf-8",
    )
    code, report, _ = _run_cli(project, monkeypatch, *(("--strict",) if strict else ()))
    assert code == 1
    assert report["analysis_summary"]["sca_coverage"]["status"] == "complete_with_unresolved_versions"
    assert report["analysis_errors"] == []
    assert osv.queries == []


def test_real_cli_malformed_actions_fail_incomplete(project, monkeypatch, osv):
    _workflow(project, "jobs: [\n")
    code, report, _ = _run_cli(project, monkeypatch, "--danger", "--force")
    assert code == 2
    assert report["analysis_errors"][0]["kind"] == "config_parse_error"


def test_real_pr_cannot_remove_base_coverage_requirement(project, monkeypatch, osv):
    monkeypatch.delenv("SKYLOS_POLICY_BASE", raising=False)
    monkeypatch.setenv("SKYLOS_DIFF_BASE", "HEAD")
    (project / "requirements.txt").write_text("requests>=2\n", encoding="utf-8")  # skylos: ignore[SKY-D324] project fixture creates fresh tmp_path/project
    config_path = project / "pyproject.toml"
    config_path.write_text(  # skylos: ignore[SKY-D324] fixed pyproject.toml in the fresh pytest project fixture
        '[tool.skylos.gate.coverage]\nrequired = ["sca"]\nrequire_resolved_versions = true\n',
        encoding="utf-8",
    )
    _git(project, "init", "-q")
    _git(project, "config", "user.name", "Skylos Tests")
    _git(project, "config", "user.email", "skylos-tests@example.invalid")
    _git(project, "add", "--", "pyproject.toml", "requirements.txt")
    _git(project, "commit", "-qm", "fixture baseline")
    config_path.write_text(  # skylos: ignore[SKY-D324] same fixture-owned regular pyproject.toml created above
        '[tool.skylos.gate.coverage]\nrequired = []\nrequire_resolved_versions = false\n',
        encoding="utf-8",
    )
    code, report, _ = _run_cli(project, monkeypatch, "--diff", "HEAD")
    assert code == 1
    assert report["analysis_summary"]["sca_coverage"]["status"] == "complete_with_unresolved_versions"
    assert osv.queries == []


def test_real_cli_required_sca_rejects_unsupported_only_project(project, monkeypatch, osv):
    (project / "Cargo.toml").write_text(  # skylos: ignore[SKY-D324] fixed Cargo.toml under the fresh pytest project fixture
        '[package]\nname = "test"\nversion = "0.1.0"\n', encoding="utf-8"
    )
    config_dir = project / ".skylos"
    config_dir.mkdir()
    (config_dir / "config.yaml").write_text(  # skylos: ignore[SKY-D324] fresh fixture-owned .skylos directory and fixed config.yaml
        "gate:\n  coverage:\n    required: [sca]\n", encoding="utf-8"
    )
    code, report, _ = _run_cli(project, monkeypatch)
    assert code == 1
    assert report["analysis_summary"]["sca_coverage"]["status"] == "no_supported_manifests"
    assert osv.queries == []


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("status, expected", [(None, False), ("not_connected", False), ("not_scanned", False), ("unsupported", False), ("complete", True)])
def test_required_custom_rules_use_coverage_receipt(strict, status, expected):
    config = {"gate": {"coverage": {"required": ["custom_rules"]}}}
    result = {"analysis_summary": {}}
    if status is not None:
        result["analysis_summary"]["custom_rules_coverage"] = {"status": status}
    passed, reasons = check_gate(result, config, strict=strict)
    assert passed is expected
    if not expected:
        assert reasons == ["Required custom rule coverage missing: configured rules were not checked"]


def test_required_custom_rules_operational_failure_remains_incomplete():
    config = {"gate": {"coverage": {"required": ["custom_rules"]}}}
    result = {
        "analysis_summary": {"custom_rules_coverage": {"status": "unavailable"}},
        "analysis_errors": [{"kind": "custom_rules_unavailable", "rule_id": "SKY-ANALYSIS-INCOMPLETE"}],
    }
    assert run_gate_interaction(result=result, config=config, force=True, advisory=True) == 2


def test_unknown_required_category_cannot_silently_pass():
    config = {"gate": {"coverage": {"required": ["unsupported-check"]}}}
    passed, reasons = check_gate({}, config)
    assert passed is False
    assert reasons == ["Unsupported required coverage categories: unsupported-check"]


def test_cicd_gate_prints_dependency_coverage_limitations(capsys):
    result = {"analysis_summary": {"sca_coverage": {"status": "no_supported_manifests", "complete": False}}}
    assert run_gate_interaction(result=result, config={}) == 0
    assert "SCA coverage limited" in capsys.readouterr().out
    assert "no supported dependency manifests found" in build_summary_markdown(result, True, [])
