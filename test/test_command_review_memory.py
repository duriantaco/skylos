from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import skylos
import skylos.cli as cli
from skylos.commands import baseline_cmd, cicd_cmd, scan_cmd
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS
from skylos.core import baseline as baseline_store
from skylos.core import review_decisions


def _scan_result(project_root: Path) -> dict:
    return {
        "project_root": str(project_root),
        "analysis_summary": {"total_files": 1, "danger_count": 2},
        "danger": [
            {
                "rule_id": "SKY-D201",
                "file": str(project_root / "reviewed.py"),
                "line": 4,
                "severity": "HIGH",
            },
            {
                "rule_id": "SKY-D211",
                "file": str(project_root / "baseline.py"),
                "line": 8,
                "severity": "HIGH",
            },
        ],
        "reliability": [],
        "ai_defects": [],
        "quality": [],
        "secrets": [],
        "unused_functions": [],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
        "unused_parameters": [],
    }


def _project_first_finding(result: dict) -> dict:
    projected = deepcopy(result)
    reviewed = dict(projected["danger"].pop(0))
    reviewed["category"] = "SECURITY"
    reviewed["review_decision"] = {"decision_id": "decision-1"}
    reviewed["_skylos_trusted_review"] = True
    projected["reviewed_findings"] = [reviewed]
    projected["reviewed_findings_summary"] = {
        "suppressed_count": 1,
        "active_decision_count": 1,
        "ambiguous_match_count": 0,
    }
    projected["analysis_summary"]["danger_count"] = 1
    projected["analysis_summary"]["reviewed_findings"] = dict(
        projected["reviewed_findings_summary"]
    )
    return projected


def test_baseline_projects_reviews_before_save_with_effective_scan_context(
    tmp_path, monkeypatch
):
    project = tmp_path / "repo"
    project.mkdir()
    raw = _scan_result(project)
    projected = _project_first_finding(raw)
    events: list[str] = []
    analyze_call = {}
    saved = {}

    def fake_analyze(path, **kwargs):
        events.append("analyze")
        analyze_call.update({"path": path, "kwargs": kwargs})
        return json.dumps(raw)

    def fake_apply(result, project_root, **kwargs):
        events.append("project")
        assert result == raw
        assert project_root == project.resolve()
        assert kwargs == {}
        return projected

    def fake_save(path, result):
        events.append("save")
        saved.update({"path": path, "result": result})
        return project / ".skylos" / "baseline.json"

    monkeypatch.setattr(baseline_cmd, "run_analyze", fake_analyze)
    monkeypatch.setattr(baseline_cmd, "save_baseline", fake_save)
    monkeypatch.setattr(baseline_cmd, "Console", Mock)
    monkeypatch.setattr(
        baseline_cmd,
        "load_config",
        lambda root, config_file=None: {"exclude": ["generated"]},
    )
    monkeypatch.setattr(baseline_cmd, "resolve_config_file_path", lambda: None)
    monkeypatch.setattr(
        review_decisions, "review_scan_requirements", lambda root: (True, True)
    )
    monkeypatch.setattr(review_decisions, "apply_trusted_review_decisions", fake_apply)

    assert baseline_cmd.run_baseline_command([str(project)]) == 0

    assert events == ["analyze", "project", "save"]
    assert analyze_call["path"] == str(project)
    kwargs = analyze_call["kwargs"]
    assert kwargs["include_review_context"] is True
    assert kwargs["include_review_proofs"] is True
    assert kwargs["enable_danger"] is True
    assert kwargs["enable_quality"] is True
    assert kwargs["enable_secrets"] is True
    assert kwargs["enable_ai_defects"] is True
    assert set(kwargs["exclude_folders"]) == DEFAULT_EXCLUDE_FOLDERS | {"generated"}
    assert saved == {"path": str(project), "result": projected}
    assert saved["result"]["danger"] == [raw["danger"][1]]


def test_baseline_avoids_review_analysis_overhead_without_active_v2_state(
    tmp_path, monkeypatch
):
    project = tmp_path / "repo"
    project.mkdir()
    captured = {}

    def fake_analyze(path, **kwargs):
        captured.update(kwargs)
        return json.dumps(_scan_result(project))

    monkeypatch.setattr(baseline_cmd, "run_analyze", fake_analyze)
    monkeypatch.setattr(baseline_cmd, "save_baseline", lambda path, result: project)
    monkeypatch.setattr(baseline_cmd, "Console", Mock)
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

    assert baseline_cmd.run_baseline_command([str(project)]) == 0
    assert "include_review_context" not in captured
    assert "include_review_proofs" not in captured


def test_cicd_direct_scan_projects_reviews_before_gate(tmp_path, monkeypatch):
    project = tmp_path / "repo"
    project.mkdir()
    raw = _scan_result(project)
    projected = _project_first_finding(raw)
    events: list[str] = []
    analyze_call = {}

    def fake_analyze(path, **kwargs):
        events.append("analyze")
        analyze_call.update({"path": path, "kwargs": kwargs})
        return json.dumps(raw)

    def fake_apply(result, project_root, **kwargs):
        events.append("project")
        assert result == raw
        assert project_root == project.resolve()
        assert kwargs == {}
        return projected

    def fake_gate(**kwargs):
        events.append("gate")
        assert kwargs["result"] == projected
        return 0

    monkeypatch.setattr(skylos, "analyze", fake_analyze)
    monkeypatch.setattr(
        review_decisions, "review_scan_requirements", lambda root: (True, True)
    )
    monkeypatch.setattr(review_decisions, "apply_trusted_review_decisions", fake_apply)
    monkeypatch.setattr(
        cicd_cmd, "resolve_config_file_path", lambda: None, raising=False
    )

    def load_config(_root):
        return {"exclude": ["generated"], "gate": {}}

    exit_code = cicd_cmd.run_cicd_command(
        ["gate", str(project)],
        console_factory=Mock,
        load_config_func=load_config,
        run_gate_interaction_func=fake_gate,
        emit_github_annotations_func=Mock(),
    )

    assert exit_code == 0
    assert events == ["analyze", "project", "gate"]
    kwargs = analyze_call["kwargs"]
    assert kwargs["include_review_context"] is True
    assert kwargs["include_review_proofs"] is True
    assert set(kwargs["exclude_folders"]) == DEFAULT_EXCLUDE_FOLDERS | {"generated"}


def test_cicd_direct_scan_is_lazy_and_input_reports_remain_raw(tmp_path, monkeypatch):
    project = tmp_path / "repo"
    project.mkdir()
    raw = _scan_result(project)
    projected = _project_first_finding(raw)
    analyze_kwargs = {}
    apply_mock = Mock(side_effect=lambda result, root: result)
    requirement_mock = Mock(return_value=(False, False))

    def fake_analyze(path, **kwargs):
        analyze_kwargs.update(kwargs)
        return json.dumps(raw)

    monkeypatch.setattr(skylos, "analyze", fake_analyze)
    monkeypatch.setattr(review_decisions, "review_scan_requirements", requirement_mock)
    monkeypatch.setattr(review_decisions, "apply_trusted_review_decisions", apply_mock)

    args = SimpleNamespace(input_file=None, path=str(project), diff_base=None)
    direct, exit_code = cicd_cmd._cicd_load_results(
        args,
        console_factory=Mock,
        load_config_func=lambda root: {},
    )

    assert exit_code == 0
    assert direct == raw
    assert "include_review_context" not in analyze_kwargs
    assert "include_review_proofs" not in analyze_kwargs
    requirement_mock.assert_called_once_with(project.resolve())
    apply_mock.assert_called_once()

    report = project / "results.json"
    report.write_text(json.dumps(projected), encoding="utf-8")
    apply_mock.reset_mock()
    requirement_mock.reset_mock()

    imported, exit_code = cicd_cmd._cicd_load_results(
        SimpleNamespace(input_file=str(report)),
        console_factory=Mock,
        load_config_func=lambda root: {},
    )

    assert exit_code == 0
    assert imported == projected
    requirement_mock.assert_not_called()
    apply_mock.assert_not_called()


def test_main_scan_projects_before_baseline_and_keeps_review_audit_for_upload(
    tmp_path, monkeypatch
):
    project = tmp_path / "repo"
    project.mkdir()
    raw = _scan_result(project)
    projected = _project_first_finding(raw)
    baseline = {
        "fingerprints": [
            f"SKY-D211:{raw['danger'][1]['file']}:{raw['danger'][1]['line']}"
        ]
    }
    events: list[str] = []
    uploaded = {}
    filter_new_findings = baseline_store.filter_new_findings

    def fake_apply(result, project_root, **kwargs):
        events.append("project")
        assert result == {**raw, "provenance": None}
        assert project_root == project.resolve()
        assert kwargs == {"include_identities": True}
        return projected

    def filter_after_projection(result, saved_baseline):
        events.append("baseline")
        assert result["reviewed_findings"] == projected["reviewed_findings"]
        assert saved_baseline == baseline
        return filter_new_findings(result, saved_baseline)

    def fake_upload(result, **kwargs):
        events.append("upload")
        uploaded.update(deepcopy(result))
        return {"success": True, "quality_gate_passed": True}

    fake_logger = Mock()
    fake_logger.console = Mock()
    monkeypatch.chdir(project)
    monkeypatch.setattr(cli, "setup_logger", lambda: fake_logger)
    monkeypatch.setattr(cli, "run_analyze", lambda *args, **kwargs: json.dumps(raw))
    monkeypatch.setattr(cli, "load_config", lambda *args, **kwargs: {})
    monkeypatch.setattr(cli, "upload_report", fake_upload)
    monkeypatch.setattr(
        review_decisions, "review_scan_requirements", lambda root: (False, False)
    )
    monkeypatch.setattr(review_decisions, "apply_trusted_review_decisions", fake_apply)
    monkeypatch.setattr(baseline_store, "load_baseline", lambda root: baseline)
    monkeypatch.setattr(baseline_store, "filter_new_findings", filter_after_projection)
    monkeypatch.setattr("builtins.print", Mock())

    scan_cmd.run_scan_command(
        [
            str(project),
            "--format",
            "json",
            "--baseline",
            "--upload",
            "--no-provenance",
        ],
        cli_module=cli,
    )

    assert events == ["project", "baseline", "upload"]
    assert uploaded["danger"] == []
    assert uploaded["reviewed_findings"] == projected["reviewed_findings"]
    assert uploaded["reviewed_findings_summary"]["suppressed_count"] == 1
