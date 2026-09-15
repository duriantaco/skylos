"""Baseline CLI options and safe dependency-baseline creation."""

import json
from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock

import pytest

from skylos.commands import baseline_cmd
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS
from skylos.core.baseline import filter_new_findings, load_baseline
from skylos.core import review_decisions


def _result(root: Path, *, status="complete", complete=True):
    return {
        "project_root": str(root),
        "unused_functions": [{"name": "old_helper", "file": "app.py", "line": 1}],
        "dependency_vulnerabilities": [
            {
                "rule_id": "SKY-SCA-GHSA-test-existing",
                "file": str(root / "package-lock.json"),
                "line": 7,
                "category": "DEPENDENCY",
                "severity": "HIGH",
                "metadata": {
                    "vuln_id": "GHSA-test-existing",
                    "ecosystem": "npm",
                    "package_name": "example",
                    "package_version": "1.0.0",
                    "advisory_status": "complete",
                },
            }
        ],
        "analysis_summary": {
            "sca_count": 1,
            "sca_coverage": {
                "status": status,
                "complete": complete,
                "category_complete": False,
            },
        },
    }


@pytest.fixture
def command_env(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    console = Mock()
    analyze = Mock(return_value=json.dumps(_result(project)))
    monkeypatch.setattr(baseline_cmd, "Console", lambda: console)
    monkeypatch.setattr(baseline_cmd, "run_analyze", analyze)
    monkeypatch.setattr(baseline_cmd, "load_config", lambda root, config_file=None: {})
    monkeypatch.setattr(baseline_cmd, "resolve_config_file_path", lambda: None)
    monkeypatch.setattr(
        review_decisions, "review_scan_requirements", lambda root: (False, False)
    )
    monkeypatch.setattr(
        review_decisions,
        "apply_trusted_review_decisions",
        lambda result, root: result,
    )
    return project, analyze, console


@pytest.mark.parametrize("argv", [[], ["."]])
def test_default_baseline_keeps_existing_scan_options_without_sca(
    command_env, monkeypatch, argv
):
    project, analyze, _console = command_env
    analyze.return_value = json.dumps({"unused_functions": [{"name": "legacy"}]})
    save = Mock(return_value=project / ".skylos" / "baseline.json")
    monkeypatch.setattr(baseline_cmd, "save_baseline", save)

    assert baseline_cmd.run_baseline_command(argv) == 0

    analyze.assert_called_once_with(
        ".",
        enable_danger=True,
        enable_quality=True,
        enable_secrets=True,
        enable_ai_defects=True,
        exclude_folders=sorted(DEFAULT_EXCLUDE_FOLDERS),
    )
    save.assert_called_once_with(
        str(project.resolve()), {"unused_functions": [{"name": "legacy"}]}
    )


@pytest.mark.parametrize("argv", [["--sca"], ["--sca", "."], [".", "--sca"]])
def test_sca_flag_before_or_after_path_enables_dependency_scan(command_env, argv):
    project, analyze, _console = command_env

    assert baseline_cmd.run_baseline_command(argv) == 0

    assert analyze.call_args.args == (".",)
    assert analyze.call_args.kwargs["enable_sca"] is True
    assert load_baseline(project) is not None


@pytest.mark.parametrize("argv", [["--sc"], ["--unknown"], [".", "extra"]])
def test_invalid_arguments_do_not_scan_or_write(command_env, argv):
    project, analyze, _console = command_env

    with pytest.raises(SystemExit) as exc:
        baseline_cmd.run_baseline_command(argv)

    assert exc.value.code == 2
    analyze.assert_not_called()
    assert not (project / ".skylos").exists()


def test_help_explains_sca_network_opt_in_without_scanning(command_env, capsys):
    project, analyze, _console = command_env

    with pytest.raises(SystemExit) as exc:
        baseline_cmd.run_baseline_command(["--help"])

    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "--sca" in help_text
    assert "Queries OSV" in help_text
    analyze.assert_not_called()
    assert not (project / ".skylos").exists()


@pytest.mark.parametrize("status", ["complete", "complete_with_unresolved_versions"])
def test_complete_sca_saves_dependency_findings_and_counts(command_env, status):
    project, analyze, console = command_env
    result = _result(project, status=status)
    analyze.return_value = json.dumps(result)

    assert baseline_cmd.run_baseline_command([".", "--sca"]) == 0

    baseline = load_baseline(project)
    assert baseline["counts"]["dependency_vulnerabilities"] == 1
    assert baseline["counts"]["unused_functions"] == 1
    assert (
        filter_new_findings(result, baseline, project_root=project)[
            "dependency_vulnerabilities"
        ]
        == []
    )
    assert any(
        "2 existing findings captured" in str(call)
        for call in console.print.call_args_list
    )


@pytest.mark.parametrize(
    "receipt",
    [
        None,
        {},
        [],
        {"status": "incomplete", "complete": False},
        {"status": "unavailable", "complete": False},
        {"status": "unknown", "complete": False},
        {"status": "incomplete", "complete": True},
        {"status": "complete", "complete": False},
        {"status": "complete"},
        {"status": "complete", "complete": "true"},
        {"status": "complete", "complete": 1},
        {"status": "future-status", "complete": True},
        {"status": "no_supported_manifests", "complete": False},
    ],
)
@pytest.mark.parametrize("existing", [False, True])
def test_unconfirmed_sca_scan_does_not_create_or_replace_baseline(
    command_env, receipt, existing
):
    project, analyze, console = command_env
    baseline_path = project / ".skylos" / "baseline.json"
    previous = '{"fingerprints": ["previous"], "counts": {}}\n'
    if existing:
        baseline_path.parent.mkdir()
        baseline_path.write_text(previous, encoding="utf-8")
    result = _result(project)
    result["analysis_summary"]["sca_coverage"] = receipt
    analyze.return_value = json.dumps(result)

    assert baseline_cmd.run_baseline_command(["--sca"]) == 2

    if existing:
        assert baseline_path.read_text(encoding="utf-8") == previous
    else:
        assert not baseline_path.parent.exists()
    assert any(
        "Baseline not saved" in str(call) for call in console.print.call_args_list
    )
    if isinstance(receipt, dict) and receipt.get("status") == "no_supported_manifests":
        assert any(
            "No supported dependency files" in str(call)
            for call in console.print.call_args_list
        )


@pytest.mark.parametrize("summary", [None, [], {}, {"sca_count": 1}])
def test_missing_sca_summary_refuses_save(command_env, summary):
    project, analyze, _console = command_env
    result = _result(project)
    result["analysis_summary"] = summary
    analyze.return_value = json.dumps(result)

    assert baseline_cmd.run_baseline_command(["--sca"]) == 2
    assert not (project / ".skylos").exists()


@pytest.mark.parametrize("argv", [[], ["--sca"]])
@pytest.mark.parametrize("error_kind", ["analysis_errors", "incomplete_languages"])
def test_incomplete_non_dependency_analysis_also_preserves_baseline(
    command_env, argv, error_kind
):
    project, analyze, _console = command_env
    baseline_path = project / ".skylos" / "baseline.json"
    baseline_path.parent.mkdir()
    baseline_path.write_text("original baseline", encoding="utf-8")
    result = _result(project)
    if error_kind == "analysis_errors":
        result["analysis_errors"] = [{"file": "app.py", "message": "unreadable"}]
    else:
        result["analysis_summary"]["incomplete_languages"] = ["Python"]
    analyze.return_value = json.dumps(result)

    assert baseline_cmd.run_baseline_command(argv) == 2
    assert baseline_path.read_text(encoding="utf-8") == "original baseline"


@pytest.mark.parametrize("raw_result", ["not JSON", "[]", "null", "true", "1"])
def test_malformed_scan_result_does_not_write(command_env, raw_result):
    project, analyze, _console = command_env
    analyze.return_value = raw_result

    assert baseline_cmd.run_baseline_command(["--sca"]) == 2
    assert not (project / ".skylos").exists()


@pytest.mark.parametrize(
    "error", [OSError("io"), RuntimeError("scan"), ValueError("data")]
)
def test_scan_exception_does_not_write(command_env, error):
    project, analyze, _console = command_env
    analyze.side_effect = error

    assert baseline_cmd.run_baseline_command(["--sca"]) == 2
    assert not (project / ".skylos").exists()


@pytest.mark.parametrize("error", [OSError("write"), ValueError("unsafe path")])
def test_save_failure_returns_clear_error(command_env, monkeypatch, error):
    _project, _analyze, console = command_env
    monkeypatch.setattr(baseline_cmd, "save_baseline", Mock(side_effect=error))

    assert baseline_cmd.run_baseline_command(["--sca"]) == 2
    assert any(
        "could not be safely written" in str(call)
        for call in console.print.call_args_list
    )


@pytest.mark.parametrize("target_kind", ["directory", "subdirectory", "file"])
def test_save_root_matches_normal_scan_root(command_env, monkeypatch, target_kind):
    from skylos.cli import _resolve_main_project_root

    project, analyze, _console = command_env
    (project / ".git").mkdir()
    nested = project / "nested"
    nested.mkdir()
    source = nested / "app.py"
    source.write_text("pass\n", encoding="utf-8")
    target = {
        "directory": project,
        "subdirectory": nested,
        "file": source,
    }[target_kind]
    root = _resolve_main_project_root([str(target)])
    analyze.return_value = json.dumps(_result(root))
    save = Mock(return_value=root / ".skylos" / "baseline.json")
    monkeypatch.setattr(baseline_cmd, "save_baseline", save)

    assert baseline_cmd.run_baseline_command([str(target), "--sca"]) == 0

    assert save.call_args.args[0] == str(root)
    assert analyze.call_args.args == (str(target),)
    assert not (source / ".skylos").exists()


def test_subdirectory_baseline_does_not_overwrite_repository_baseline(command_env):
    project, analyze, _console = command_env
    (project / ".git").mkdir()
    existing = project / ".skylos" / "baseline.json"
    existing.parent.mkdir()
    existing.write_text("repository baseline", encoding="utf-8")
    nested = project / "packages" / "app"
    nested.mkdir(parents=True)
    analyze.return_value = json.dumps(_result(nested))

    assert baseline_cmd.run_baseline_command([str(nested), "--sca"]) == 0

    assert existing.read_text(encoding="utf-8") == "repository baseline"
    assert load_baseline(nested)["counts"]["dependency_vulnerabilities"] == 1


def test_incomplete_scan_cannot_be_hidden_by_review_projection(
    command_env, monkeypatch
):
    project, analyze, _console = command_env
    result = _result(project, status="incomplete", complete=False)
    analyze.return_value = json.dumps(result)
    project_reviews = Mock(return_value=deepcopy(_result(project)))
    monkeypatch.setattr(
        review_decisions, "apply_trusted_review_decisions", project_reviews
    )

    assert baseline_cmd.run_baseline_command(["--sca"]) == 2

    project_reviews.assert_not_called()
    assert not (project / ".skylos").exists()
