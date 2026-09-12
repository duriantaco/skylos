from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import skylos.cli as cli
from skylos.core.review_context import (
    LLM_REVIEW_CONTEXT_SCHEMA,
    build_analysis_review_context,
    review_context_is_valid,
)
from skylos.core.review_decisions import (
    REVIEW_SCHEMA,
    REVIEW_SCHEMA_VERSION,
    annotate_result_identities,
    apply_review_decisions,
)
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.llm.schemas import (
    CodeLocation,
    Confidence,
    Finding,
    IssueType,
    Severity,
)
from skylos.pipeline import run_pipeline


def _agent_args(**overrides):
    values = {
        "upload": True,
        "llm_only": True,
        "static_only": False,
        "skip_verification": True,
        "with_fixes": False,
        "quiet": True,
        "provider": None,
        "base_url": None,
        "min_confidence": "low",
        "verification_mode": "production",
        "prompt_templates": None,
        "prompt_template_root": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _quality_finding(source: Path) -> Finding:
    return Finding(
        rule_id="SKY-Q401",
        issue_type=IssueType.QUALITY,
        severity=Severity.MEDIUM,
        message="Blocking operation in async handler",
        location=CodeLocation(file=str(source), line=2),
        confidence=Confidence.HIGH,
        symbol="handler",
        explanation="The call blocks the event loop.",
        suggestion="Use the asynchronous API.",
    )


def _run_llm_only(repo: Path):
    source = repo / "app.py"
    assert write_text_no_symlink(
        source,
        "async def handler():\n    blocking_call()\n",
    )
    llm = MagicMock()
    llm.return_value.analyze_files.return_value = MagicMock(
        findings=[_quality_finding(source)]
    )
    stats = {}
    with (
        patch("skylos.analyzer.analyze") as static_analyze,
        patch("skylos.llm.analyzer.SkylosLLM", llm),
        patch(
            "skylos.core.review_decisions.review_scan_requirements",
            return_value=(False, False),
        ),
    ):
        findings = run_pipeline(
            path=str(repo),
            model="gpt-4.1",
            api_key="fake-key",
            agent_args=_agent_args(),
            console=MagicMock(),
            exclude_folders=[".git", "vendor"],
            stats_out=stats,
            provider="openai",
            base_url="https://api.example.test/v1",
            project_root=repo,
            project_config={"exclude": ["vendor"], "complexity": 10},
        )
    static_analyze.assert_not_called()
    return findings, stats, llm


def _static_review_context(repo: Path):
    return build_analysis_review_context(
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


def _hybrid_static_result(repo: Path, review_context):
    source = repo / "app.py"
    return {
        "definitions": {
            "app.handler": {
                "name": "handler",
                "file": str(source),
                "line": 1,
                "type": "function",
            }
        },
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_parameters": [],
        "unused_classes": [],
        "danger": [],
        "reliability": [],
        "ai_defects": [],
        "quality": [
            {
                "file": str(source),
                "line": 5,
                "name": "helper",
                "message": "Helper has avoidable branching",
                "rule_id": "SKY-Q301",
                "severity": "MEDIUM",
                "confidence": 80,
            }
        ],
        "secrets": [],
        "analysis_summary": {"review_context": review_context},
    }


def _run_hybrid(repo: Path, review_context):
    source = repo / "app.py"
    static_result = _hybrid_static_result(repo, review_context)
    llm = MagicMock()
    llm.return_value.analyze_files.return_value = MagicMock(
        findings=[_quality_finding(source)]
    )
    stats = {}
    with (
        patch("skylos.analyzer.analyze", return_value=json.dumps(static_result)),
        patch("skylos.llm.analyzer.SkylosLLM", llm),
        patch(
            "skylos.core.review_decisions.review_scan_requirements",
            return_value=(False, False),
        ),
    ):
        findings = run_pipeline(
            path=str(repo),
            model="gpt-4.1",
            api_key="fake-key",
            agent_args=_agent_args(llm_only=False),
            console=MagicMock(),
            stats_out=stats,
            provider="openai",
            project_root=repo,
            project_config={},
        )
    return findings, stats, static_result


def _decision_from_identity(identity, decision_id):
    return {
        "decision_id": decision_id,
        "fingerprint_version": identity["fingerprint_version"],
        "stable_fingerprint": identity["stable_fingerprint"],
        "context_hash": identity["context_hash"],
        "rule_revision": identity["rule_revision"],
        "rule_id": identity["rule_id"],
        "file_path": identity["file_path"],
        "line_number": identity["line_number"],
        "disposition": "false_positive",
        "reason": "Reviewed in Cloud",
        "created_at": "2026-09-12T00:00:00Z",
        "language": identity["language"],
        "symbol": identity["symbol"],
        "section": identity["section"],
        "category": "QUALITY",
    }


def test_llm_only_upload_emits_context_bound_v2_identity(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)

    findings, stats, llm = _run_llm_only(repo)

    context = stats["review_context"]
    assert context["schema"] == LLM_REVIEW_CONTEXT_SCHEMA
    assert review_context_is_valid(context)
    assert context["scope"]["effective_files"]["count"] == 1
    assert context["analyzer"]["model"] == "gpt-4.1"
    assert context["analyzer"]["provider"] == "openai"
    assert findings[0]["provider"] == "openai"
    assert findings[0]["prompt_revision"].startswith("sha256:")
    config = llm.call_args.args[0]
    assert config.provider == "openai"
    assert config.prompt_templates == {}

    result = cli._agent_findings_to_result_json(
        findings,
        review_context=context,
    )
    annotated = annotate_result_identities(result, repo)
    identity = annotated["quality"][0]
    assert identity["fingerprint_version"] == "skylos-finding-v2"

    decision = {
        "decision_id": "cloud-llm-review-1",
        "fingerprint_version": identity["fingerprint_version"],
        "stable_fingerprint": identity["stable_fingerprint"],
        "context_hash": identity["context_hash"],
        "rule_revision": identity["rule_revision"],
        "rule_id": identity["rule_id"],
        "file_path": identity["file_path"],
        "line_number": identity["line_number"],
        "disposition": "false_positive",
        "reason": "Reviewed in Cloud",
        "created_at": "2026-09-12T00:00:00Z",
        "language": identity["language"],
        "symbol": identity["symbol"],
        "section": identity["section"],
        "category": "QUALITY",
    }
    next_findings, next_stats, _next_llm = _run_llm_only(repo)
    assert next_stats["review_context"] == context
    next_result = cli._agent_findings_to_result_json(
        next_findings,
        review_context=next_stats["review_context"],
    )
    projected = apply_review_decisions(
        next_result,
        {
            "schema": REVIEW_SCHEMA,
            "version": REVIEW_SCHEMA_VERSION,
            "decisions": [decision],
        },
        repo,
        require_review_context=True,
    )
    assert projected["quality"] == []
    assert projected["reviewed_findings"][0]["review_decision"]["decision_id"] == (
        "cloud-llm-review-1"
    )


def test_hybrid_llm_identity_matches_unchanged_run_without_changing_static_identity(
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    source = repo / "app.py"
    source.write_text(
        "async def handler():\n"
        "    blocking_call()\n"
        "\n"
        "\n"
        "def helper():\n"
        "    if enabled():\n"
        "        return 1\n"
        "    return 0\n",
        encoding="utf-8",
    )
    static_context = _static_review_context(repo)

    findings, stats, raw_static = _run_hybrid(repo, static_context)

    assert stats["review_context"] == static_context
    static_finding = next(item for item in findings if item["_source"] == "static")
    llm_finding = next(item for item in findings if item["_source"] == "llm")
    assert "_llm_analysis_context_hash" not in static_finding
    assert llm_finding["_llm_analysis_context_hash"].startswith("sha256:")

    hybrid_result = cli._agent_findings_to_result_json(
        findings,
        review_context=static_context,
    )
    hybrid_annotated = annotate_result_identities(hybrid_result, repo)
    hybrid_by_rule = {item["rule_id"]: item for item in hybrid_annotated["quality"]}
    ordinary_static = annotate_result_identities(raw_static, repo)["quality"][0]
    assert (
        hybrid_by_rule["SKY-Q301"]["stable_fingerprint"]
        == ordinary_static["stable_fingerprint"]
    )
    assert hybrid_by_rule["SKY-Q301"]["context_hash"] == ordinary_static["context_hash"]

    llm_identity = hybrid_by_rule["SKY-Q401"]
    decision = _decision_from_identity(llm_identity, "cloud-hybrid-review-1")
    next_findings, next_stats, _ = _run_hybrid(repo, static_context)
    next_result = cli._agent_findings_to_result_json(
        next_findings,
        review_context=next_stats["review_context"],
    )
    projected = apply_review_decisions(
        next_result,
        {
            "schema": REVIEW_SCHEMA,
            "version": REVIEW_SCHEMA_VERSION,
            "decisions": [decision],
        },
        repo,
        require_review_context=True,
    )
    assert [item["rule_id"] for item in projected["quality"]] == ["SKY-Q301"]
    assert projected["reviewed_findings"][0]["rule_id"] == "SKY-Q401"


def test_hybrid_llm_identity_resurfaces_when_selected_source_input_changes(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    source = repo / "app.py"
    source.write_text(
        "async def handler():\n"
        "    blocking_call()\n"
        "\n"
        "\n"
        "def helper():\n"
        "    value = 1\n"
        "    value += 2\n"
        "    return value\n",
        encoding="utf-8",
    )
    static_context = _static_review_context(repo)
    findings, _stats, _raw_static = _run_hybrid(repo, static_context)
    first_llm_finding = next(item for item in findings if item["_source"] == "llm")
    first_llm_context = first_llm_finding["_llm_analysis_context_hash"]
    first_result = cli._agent_findings_to_result_json(
        findings,
        review_context=static_context,
    )
    first_identity = next(
        item
        for item in annotate_result_identities(first_result, repo)["quality"]
        if item["rule_id"] == "SKY-Q401"
    )
    decision = _decision_from_identity(first_identity, "cloud-hybrid-review-2")

    source.write_text(
        "async def handler():\n"
        "    blocking_call()\n"
        "\n"
        "\n"
        "def helper():\n"
        "    value = 1\n"
        "    value += 3\n"
        "    return value\n",
        encoding="utf-8",
    )
    changed_findings, changed_stats, _ = _run_hybrid(repo, static_context)
    changed_llm_finding = next(
        item for item in changed_findings if item["_source"] == "llm"
    )
    assert changed_llm_finding["_llm_analysis_context_hash"] != first_llm_context

    changed_result = cli._agent_findings_to_result_json(
        changed_findings,
        review_context=changed_stats["review_context"],
    )
    changed_identity = next(
        item
        for item in annotate_result_identities(changed_result, repo)["quality"]
        if item["rule_id"] == "SKY-Q401"
    )
    assert (
        changed_identity["stable_fingerprint"] == first_identity["stable_fingerprint"]
    )
    assert changed_identity["context_hash"] != first_identity["context_hash"]

    projected = apply_review_decisions(
        changed_result,
        {
            "schema": REVIEW_SCHEMA,
            "version": REVIEW_SCHEMA_VERSION,
            "decisions": [decision],
        },
        repo,
        require_review_context=True,
    )
    assert "SKY-Q401" in [item["rule_id"] for item in projected["quality"]]
    assert projected.get("reviewed_findings", []) == []


def test_hybrid_prompt_revision_failure_skips_only_llm_identity(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text(
        "async def handler():\n    blocking_call()\n\n\ndef helper():\n    return 1\n",
        encoding="utf-8",
    )
    static_context = _static_review_context(repo)

    with patch("skylos.llm.prompts.analysis_prompt_revision", return_value=None):
        findings, stats, _raw_static = _run_hybrid(repo, static_context)

    result = cli._agent_findings_to_result_json(
        findings,
        review_context=stats["review_context"],
    )
    annotated = annotate_result_identities(result, repo)
    by_rule = {item["rule_id"]: item for item in annotated["quality"]}
    assert by_rule["SKY-Q301"]["fingerprint_version"] == "skylos-finding-v2"
    assert "fingerprint_version" not in by_rule["SKY-Q401"]


def test_llm_only_prompt_revision_failure_does_not_mint_identity(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("async def handler():\n    blocking_call()\n", encoding="utf-8")
    llm = MagicMock()
    llm.return_value.analyze_files.return_value = MagicMock(
        findings=[_quality_finding(source)]
    )
    stats = {}

    with (
        patch("skylos.analyzer.analyze") as static_analyze,
        patch("skylos.llm.analyzer.SkylosLLM", llm),
        patch(
            "skylos.core.review_decisions.review_scan_requirements",
            return_value=(False, False),
        ),
        patch("skylos.llm.prompts.analysis_prompt_revision", return_value=None),
    ):
        findings = run_pipeline(
            path=str(repo),
            model="gpt-4.1",
            api_key="fake-key",
            agent_args=_agent_args(),
            console=MagicMock(),
            stats_out=stats,
            provider="openai",
            project_root=repo,
            project_config={},
        )

    static_analyze.assert_not_called()
    assert not review_context_is_valid(stats["review_context"])
    result = cli._agent_findings_to_result_json(
        findings,
        review_context=stats["review_context"],
    )
    annotated = annotate_result_identities(result, repo)
    assert "fingerprint_version" not in annotated["quality"][0]


def test_agent_cli_passes_resolved_llm_review_inputs_to_pipeline(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    source = repo / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    template = tmp_path / "review.md"
    template.write_text("Check tenant boundaries.\n", encoding="utf-8")
    project_config = {"exclude": ["generated"]}
    pipeline = MagicMock(return_value=[])

    with (
        patch.object(
            cli.sys,
            "argv",
            [
                "skylos",
                "agent",
                "scan",
                str(repo),
                "--llm-only",
                "--provider",
                "anthropic",
                "--prompt-template",
                f"review={template}",
            ],
        ),
        patch("skylos.cli.Console", return_value=MagicMock()),
        patch("skylos.cli._ensure_llm_support", return_value=True),
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=(
                "anthropic",
                "fake-key",
                "https://gateway.example.test/v1",
                False,
            ),
        ),
        patch("skylos.cli.load_config", return_value=project_config),
        patch("skylos.cli.run_pipeline", pipeline),
        patch("skylos.cli._upload_agent_run_best_effort"),
    ):
        with pytest.raises(SystemExit) as error:
            cli.main()

    assert error.value.code == 0
    kwargs = pipeline.call_args.kwargs
    assert kwargs["provider"] == "anthropic"
    assert kwargs["base_url"] == "https://gateway.example.test/v1"
    assert kwargs["project_root"] == repo
    assert kwargs["project_config"] == project_config
    passed_args = kwargs["agent_args"]
    assert passed_args.prompt_templates == {"review": str(template)}
    assert passed_args.prompt_template_root == Path("/")
