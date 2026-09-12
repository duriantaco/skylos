from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import skylos.cli as cli
from skylos.core import review_decisions
from skylos.core.review_context import build_analysis_review_context
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.llm.schemas import (
    AnalysisResult,
    CodeLocation,
    Confidence,
    Finding,
    IssueType,
    Severity,
)


_CI_KEYS = (
    "CI",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_JOB",
    "CI_PIPELINE_ID",
    "BUILD_BUILDID",
    "CIRCLE_WORKFLOW_ID",
    "BUILD_TAG",
)


def _reviewed_agent_finding(tmp_path, monkeypatch):
    home = tmp_path / "home"
    cloud_cache = home / "reviewed-findings"
    local_cache = home / "local-review-decisions"
    monkeypatch.setattr(
        review_decisions,
        "_cache_root",
        lambda value=None: (
            Path(value).expanduser() if value is not None else cloud_cache
        ),
    )
    monkeypatch.setattr(
        review_decisions,
        "_local_cache_root",
        lambda value=None: (
            Path(value).expanduser() if value is not None else local_cache
        ),
    )
    for key in _CI_KEYS:
        monkeypatch.delenv(key, raising=False)

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    source = repo / "app.py"
    assert write_text_no_symlink(source, "open(path).write('unsafe')\n")
    finding = {
        "rule_id": "SKY-D215",
        "file": str(source),
        "line": 1,
        "symbol": "write_report",
        "severity": "HIGH",
        "message": "unsafe path",
        "_category": "security",
        "_source": "static+llm",
        "_confidence": "high",
        "model": "gpt-4.1",
        "provider": "openai",
    }
    context = build_analysis_review_context(
        repo,
        repo,
        config={},
        threshold=10,
        exclude_folders=[],
        requested_changed_files=None,
        effective_changed_files=None,
        enable_secrets=True,
        enable_danger=True,
        enable_quality=True,
        enable_ai_defects=True,
        enable_sca=False,
        enable_dependency_hallucinations=False,
        grep_verify=True,
        trace_file=None,
        required_config_rules=None,
        dependency_bump_diff_base=None,
        custom_rules_data=None,
        extra_visitors=None,
        analysis_scope={"kind": "repository", "complete_repository": True},
        environ={},
    )
    normalized = cli._normalize_agent_findings([finding], repo)
    result = cli._agent_findings_to_result_json(normalized, review_context=context)
    identity = review_decisions.annotate_result_identities(result, repo)["danger"][0]
    review_decisions.record_local_decision(
        repo,
        {
            "decision_id": "agent-review-1",
            "fingerprint_version": identity["fingerprint_version"],
            "stable_fingerprint": identity["stable_fingerprint"],
            "context_hash": identity["context_hash"],
            "rule_revision": identity["rule_revision"],
            "rule_id": identity["rule_id"],
            "file_path": identity["file_path"],
            "line_number": 1,
            "disposition": "false_positive",
            "reason": "validated safe wrapper",
            "created_at": "2026-09-12T00:00:00Z",
            "language": identity["language"],
            "symbol": identity["symbol"],
            "section": identity["section"],
            "category": "SECURITY",
        },
    )
    return repo, finding, context


def _run_agent_scan(repo, finding, context, *arguments, upload_response=None):
    console = MagicMock()
    upload = MagicMock(
        return_value=upload_response or {"success": True, "quality_gate_passed": True}
    )
    printed = MagicMock()
    argv = ["skylos", "agent", "scan", str(repo), *arguments]

    def run_pipeline_with_context(**kwargs):
        kwargs["stats_out"]["review_context"] = context
        return [finding]

    with (
        patch.object(cli.sys, "argv", argv),
        patch("skylos.cli.Console", return_value=console),
        patch("skylos.cli._ensure_llm_support", return_value=True),
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.run_pipeline", side_effect=run_pipeline_with_context),
        patch("skylos.cli.upload_report", upload),
        patch("skylos.cli._upload_agent_run_best_effort"),
        patch("builtins.print", printed),
    ):
        with pytest.raises(SystemExit) as error:
            cli.main()
    return error.value.code, console, printed, upload


@pytest.mark.parametrize("output_format", ["table", "json"])
def test_agent_scan_outputs_only_active_findings_after_review_projection(
    tmp_path,
    monkeypatch,
    output_format,
):
    repo, finding, context = _reviewed_agent_finding(tmp_path, monkeypatch)

    code, console, printed, _upload = _run_agent_scan(
        repo,
        finding,
        context,
        "--format",
        output_format,
    )

    assert code == 0
    if output_format == "json":
        json_calls = [
            call.args[0]
            for call in printed.call_args_list
            if call.args
            and isinstance(call.args[0], str)
            and call.args[0].lstrip().startswith("[")
        ]
        assert len(json_calls) == 1
        assert json.loads(json_calls[0]) == []
    else:
        rendered = [
            str(call.args[0]) for call in console.print.call_args_list if call.args
        ]
        assert any("Total findings: 0" in value for value in rendered)
        assert any("No issues found" in value for value in rendered)
        assert all("unsafe path" not in value for value in rendered)


def test_agent_scan_strict_passes_when_only_finding_is_reviewed(
    tmp_path,
    monkeypatch,
):
    repo, finding, context = _reviewed_agent_finding(tmp_path, monkeypatch)

    code, _console, _printed, _upload = _run_agent_scan(
        repo,
        finding,
        context,
        "--strict",
    )

    assert code == 0


def test_agent_scan_upload_retains_locally_reviewed_raw_finding(
    tmp_path,
    monkeypatch,
):
    repo, finding, context = _reviewed_agent_finding(tmp_path, monkeypatch)

    code, _console, _printed, upload = _run_agent_scan(
        repo,
        finding,
        context,
        "--upload",
    )

    assert code == 0
    upload.assert_called_once()
    report = upload.call_args.args[0]
    assert report["danger"] == []
    assert len(report["reviewed_findings"]) == 1
    reviewed = report["reviewed_findings"][0]
    assert reviewed["rule_id"] == "SKY-D215"
    assert reviewed["message"] == "unsafe path"
    assert reviewed["review_decision"]["decision_id"] == "agent-review-1"
    assert reviewed["review_decision"]["disposition"] == "false_positive"


def test_agent_projection_preserves_analyzer_review_context(tmp_path, monkeypatch):
    repo, finding, context = _reviewed_agent_finding(tmp_path, monkeypatch)
    normalized = cli._normalize_agent_findings([finding], repo)
    result = cli._agent_findings_to_result_json(
        normalized,
        review_context=context,
    )
    identity = review_decisions.annotate_result_identities(result, repo)["danger"][0]
    review_decisions.record_local_decision(
        repo,
        {
            "decision_id": "agent-context-review",
            "fingerprint_version": identity["fingerprint_version"],
            "stable_fingerprint": identity["stable_fingerprint"],
            "context_hash": identity["context_hash"],
            "rule_revision": identity["rule_revision"],
            "rule_id": identity["rule_id"],
            "file_path": identity["file_path"],
            "line_number": 1,
            "disposition": "false_positive",
            "reason": "reviewed with exact analyzer inputs",
            "created_at": "2026-09-12T00:00:00Z",
            "language": identity["language"],
            "symbol": identity["symbol"],
            "section": identity["section"],
            "category": "SECURITY",
        },
    )

    active, projected = cli._apply_agent_review_memory(
        normalized,
        repo,
        review_context=context,
    )

    assert active == []
    assert projected["reviewed_findings"][0]["review_decision"]["decision_id"] == (
        "agent-context-review"
    )


def test_agent_scan_cloud_gate_rejection_exits_one_after_local_review(
    tmp_path,
    monkeypatch,
):
    repo, finding, context = _reviewed_agent_finding(tmp_path, monkeypatch)

    code, _console, _printed, upload = _run_agent_scan(
        repo,
        finding,
        context,
        "--upload",
        upload_response={"success": True, "quality_gate_passed": False},
    )

    assert code == 1
    upload.assert_called_once()
    report = upload.call_args.args[0]
    assert report["danger"] == []
    assert len(report["reviewed_findings"]) == 1


def test_agent_security_scan_does_not_apply_inert_review_memory(
    tmp_path,
    monkeypatch,
):
    repo, raw_finding, _context = _reviewed_agent_finding(tmp_path, monkeypatch)
    finding = Finding(
        rule_id=raw_finding["rule_id"],
        issue_type=IssueType.SECURITY,
        severity=Severity.HIGH,
        message=raw_finding["message"],
        location=CodeLocation(file=str(repo / "app.py"), line=1),
        confidence=Confidence.HIGH,
        symbol=raw_finding["symbol"],
    )
    original_result = AnalysisResult(findings=[finding], files_analyzed=1)
    assert original_result.has_blockers() is True
    taskflow = MagicMock(result=original_result)
    analyzer = MagicMock()
    console = MagicMock()

    with (
        patch.object(
            cli.sys,
            "argv",
            ["skylos", "agent", "scan", str(repo), "--security"],
        ),
        patch("skylos.cli.Console", return_value=console),
        patch("skylos.cli._ensure_llm_support", return_value=True),
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli._is_tty", return_value=False),
        patch("skylos.cli.llm_estimate_cost", return_value=(10, 0.01)),
        patch("skylos.cli.SkylosLLM", return_value=analyzer),
        patch("skylos.cli.run_security_taskflow", return_value=taskflow),
        patch("skylos.cli._apply_agent_review_memory") as apply_reviews,
    ):
        with pytest.raises(SystemExit) as error:
            cli.main()

    assert error.value.code == 1
    apply_reviews.assert_not_called()
    analyzer.print_results.assert_called_once()
    rendered_result = analyzer.print_results.call_args.args[0]
    assert rendered_result.findings == [finding]
    rendered = [str(call.args[0]) for call in console.print.call_args_list if call.args]
    assert all("previously reviewed" not in value.lower() for value in rendered)
