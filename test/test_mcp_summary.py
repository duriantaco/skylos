from __future__ import annotations

import json
from unittest.mock import Mock

import skylos_mcp.server as mcp_server
from skylos_mcp.server import (
    _architecture_payload,
    _health_score_payload,
    _make_summary,
    _register_tools,
)


class _FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self):
        def decorate(fn):
            self.tools[fn.__name__] = fn
            return fn

        return decorate

    def resource(self, *_args, **_kwargs):
        def decorate(fn):
            return fn

        return decorate


def test_make_summary_includes_workspace_report_when_present():
    result = {
        "analysis_summary": {"total_files": 1, "monorepo_detected": True},
        "workspaces": {
            "root_package": {"name": "@repo/root"},
            "packages": [{"name": "@repo/app"}],
            "diagnostics": [],
        },
    }

    summary = _make_summary(result)

    assert summary["analysis_summary"]["monorepo_detected"] is True
    assert summary["workspaces"]["root_package"]["name"] == "@repo/root"


def test_make_summary_omits_empty_workspace_report():
    result = {
        "analysis_summary": {"total_files": 1},
        "workspaces": {
            "root_package": None,
            "packages": [],
            "diagnostics": [],
        },
    }

    summary = _make_summary(result)

    assert "workspaces" not in summary


def test_make_summary_preserves_analysis_errors():
    error = {
        "rule_id": "SKY-ANALYSIS-INCOMPLETE",
        "kind": "grep_budget_exhausted",
    }
    summary = _make_summary(
        {
            "analysis_summary": {"total_files": 1},
            "analysis_errors": [error],
        }
    )

    assert summary["analysis_errors"] == [error]


def test_generate_fix_rejects_explicit_incomplete_grep_summary(
    monkeypatch, tmp_path
):
    import skylos.analyzer as analyzer_module
    import skylos.deadcode.collect as dead_code_module

    fake = _FakeMCP()
    _register_tools(fake)
    monkeypatch.setattr(mcp_server, "_gate", lambda _tool_name: None)
    monkeypatch.setattr(
        analyzer_module,
        "analyze",
        lambda *_args, **_kwargs: json.dumps(
            {
                "analysis_summary": {
                    "grep_verify": {"complete": False, "status": "incomplete"}
                },
                "analysis_errors": [],
            }
        ),
    )
    collect = Mock(side_effect=AssertionError("must not collect partial findings"))
    monkeypatch.setattr(dead_code_module, "collect_dead_code_findings", collect)

    result = json.loads(fake.tools["generate_fix"](str(tmp_path), apply=True))

    assert result["error"] == "Cannot generate fixes from incomplete analysis."
    collect.assert_not_called()


def test_generate_fix_rejects_incomplete_static_analysis(monkeypatch, tmp_path):
    import skylos.analyzer as analyzer_module
    import skylos.deadcode.collect as dead_code_module

    fake = _FakeMCP()
    _register_tools(fake)
    monkeypatch.setattr(mcp_server, "_gate", lambda _tool_name: None)
    monkeypatch.setattr(
        analyzer_module,
        "analyze",
        lambda *_args, **_kwargs: json.dumps(
            {
                "analysis_summary": {},
                "analysis_errors": [
                    {
                        "rule_id": "SKY-ANALYSIS-INCOMPLETE",
                        "kind": "grep_budget_exhausted",
                    }
                ],
            }
        ),
    )
    collect = Mock(side_effect=AssertionError("must not collect partial findings"))
    monkeypatch.setattr(dead_code_module, "collect_dead_code_findings", collect)

    result = json.loads(
        fake.tools["generate_fix"](str(tmp_path), apply=True)
    )

    assert result["error"] == "Cannot generate fixes from incomplete analysis."
    assert result["analysis_errors"][0]["kind"] == "grep_budget_exhausted"
    collect.assert_not_called()


def test_verify_dead_code_rejects_incomplete_static_analysis(
    monkeypatch, tmp_path
):
    import skylos.analyzer as analyzer_module
    import skylos.llm.verify_orchestrator as verify_module

    fake = _FakeMCP()
    _register_tools(fake)
    monkeypatch.setattr(mcp_server, "_gate", lambda _tool_name: None)
    monkeypatch.setattr(
        analyzer_module,
        "analyze",
        lambda *_args, **_kwargs: json.dumps(
            {
                "analysis_summary": {
                    "grade_unavailable_reason": "analysis_incomplete"
                },
                "analysis_errors": [
                    {
                        "rule_id": "SKY-ANALYSIS-INCOMPLETE",
                        "kind": "grep_budget_exhausted",
                    }
                ],
                "unused_functions": [{"full_name": "app.orphan"}],
            }
        ),
    )
    verify = Mock(side_effect=AssertionError("must not verify partial analysis"))
    monkeypatch.setattr(verify_module, "run_verification", verify)

    result = json.loads(fake.tools["verify_dead_code"](str(tmp_path)))

    assert result["error"] == (
        "Cannot verify dead code from incomplete analysis."
    )
    assert result["analysis_errors"][0]["kind"] == "grep_budget_exhausted"
    verify.assert_not_called()


def test_generate_fix_rejects_incomplete_direct_grep(monkeypatch, tmp_path):
    import skylos.analyzer as analyzer_module
    import skylos.core.grep_verify as grep_verify_module
    import skylos.deadcode.collect as dead_code_module
    import skylos.remediation.fixgen as fixgen_module

    class IncompleteVerdicts(dict):
        complete = False
        candidate_count = 1
        incomplete_reason = "budget_exhausted"

    finding = {
        "name": "orphan",
        "full_name": "app.orphan",
        "file": str(tmp_path / "app.py"),
        "line": 1,
        "type": "function",
    }
    fake = _FakeMCP()
    _register_tools(fake)
    monkeypatch.setattr(mcp_server, "_gate", lambda _tool_name: None)
    monkeypatch.setenv("SKYLOS_GREP_BUDGET", "0.25")
    monkeypatch.setattr(
        analyzer_module,
        "analyze",
        lambda *_args, **_kwargs: json.dumps(
            {
                "analysis_summary": {},
                "analysis_errors": [],
                "definitions": {},
            }
        ),
    )
    monkeypatch.setattr(
        dead_code_module,
        "collect_dead_code_findings",
        lambda _result: [finding],
    )
    grep = Mock(return_value=IncompleteVerdicts())
    monkeypatch.setattr(grep_verify_module, "grep_verify_findings", grep)
    plan = Mock(side_effect=AssertionError("must not plan from partial grep"))
    monkeypatch.setattr(fixgen_module, "generate_removal_plan", plan)

    result = json.loads(
        fake.tools["generate_fix"](str(tmp_path), apply=True)
    )

    assert "grep verification did not complete" in result["error"]
    assert result["grep_verify"]["complete"] is False
    assert result["grep_verify"]["time_budget_seconds"] == 0.25
    assert grep.call_args.kwargs["time_budget"] == 0.25
    plan.assert_not_called()


def test_generate_fix_keeps_complete_mapping_compatibility(monkeypatch, tmp_path):
    import skylos.analyzer as analyzer_module
    import skylos.core.grep_verify as grep_verify_module
    import skylos.deadcode.collect as dead_code_module
    import skylos.remediation.fixgen as fixgen_module

    finding = {
        "name": "orphan",
        "full_name": "app.orphan",
        "file": str(tmp_path / "app.py"),
        "line": 1,
        "type": "function",
    }
    fake = _FakeMCP()
    _register_tools(fake)
    monkeypatch.setattr(mcp_server, "_gate", lambda _tool_name: None)
    monkeypatch.setattr(
        analyzer_module,
        "analyze",
        lambda *_args, **_kwargs: json.dumps(
            {
                "analysis_summary": {},
                "analysis_errors": [],
                "definitions": {},
            }
        ),
    )
    monkeypatch.setattr(
        dead_code_module,
        "collect_dead_code_findings",
        lambda _result: [finding],
    )
    monkeypatch.setattr(
        grep_verify_module,
        "grep_verify_findings",
        lambda *_args, **_kwargs: {},
    )
    plan = Mock(return_value=[])
    monkeypatch.setattr(fixgen_module, "generate_removal_plan", plan)
    monkeypatch.setattr(fixgen_module, "validate_patches", lambda *_args: [])
    monkeypatch.setattr(
        fixgen_module,
        "generate_unified_diff",
        lambda _patches, _target: "",
    )
    monkeypatch.setattr(
        fixgen_module,
        "generate_fix_summary",
        lambda _patches: {"files": 0},
    )
    monkeypatch.setattr(mcp_server, "_store_result", Mock())

    result = json.loads(fake.tools["generate_fix"](str(tmp_path)))

    assert result["patches"] == 0
    assert result["errors"] == []
    plan.assert_called_once_with(
        [finding],
        {},
        str(tmp_path),
        mode="delete",
        min_safety=0.0,
    )


def test_architecture_payload_filters_architecture_findings():
    result = {
        "analysis_summary": {"quality_count": 2},
        "architecture_metrics": {"layer_policy": {"violation_count": 1}},
        "quality": [
            {"rule_id": "SKY-Q805", "kind": "architecture", "name": "domain"},
            {"rule_id": "SKY-L014", "kind": "logic", "name": "password"},
        ],
    }

    payload = _architecture_payload(result)

    assert payload["architecture_metrics"]["layer_policy"]["violation_count"] == 1
    assert [finding["rule_id"] for finding in payload["findings"]] == ["SKY-Q805"]


def test_health_score_payload_summarizes_counts_and_grade():
    result = {
        "analysis_summary": {
            "quality_count": 3,
            "danger_count": 1,
            "secrets_count": 0,
            "sca_count": 2,
        },
        "grade": {
            "overall": {"score": 88, "letter": "B+"},
            "categories": {
                "quality": {
                    "score": 82,
                    "letter": "B-",
                    "key_issue": "Architecture layer violation",
                },
                "secrets": {
                    "score": 100,
                    "letter": "A+",
                    "key_issue": "No secrets found",
                },
            },
        },
        "unused_functions": [{"name": "old"}],
        "architecture_metrics": {
            "layer_policy": {"violation_count": 1},
            "system_metrics": {"architecture_fitness": 0.91},
        },
    }

    payload = _health_score_payload(result)

    assert payload["grade"]["overall"]["letter"] == "B+"
    assert payload["counts"]["dead_code"] == 1
    assert payload["counts"]["architecture_policy_violations"] == 1
    assert payload["architecture_fitness"] == 0.91
    assert payload["top_issues"] == [
        {"category": "quality", "key_issue": "Architecture layer violation"}
    ]


def test_load_result_rejects_path_traversal_run_id(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp_server, "RESULTS_DIR", tmp_path)
    mcp_server._results_cache.clear()

    assert mcp_server._load_result("../latest") is None
    assert mcp_server._load_result("latest/../../secret") is None


def test_mcp_remediate_rejects_test_cmd(monkeypatch):
    class FakeMCP:
        def __init__(self):
            self.tools = {}

        def tool(self):
            def decorate(fn):
                self.tools[fn.__name__] = fn
                return fn

            return decorate

        def resource(self, *_args, **_kwargs):
            def decorate(fn):
                return fn

            return decorate

    fake = FakeMCP()
    _register_tools(fake)
    monkeypatch.setattr(mcp_server, "_gate", lambda _tool_name: None)

    result = fake.tools["remediate"](".", test_cmd="true; touch /tmp/marker")

    assert "does not accept test_cmd" in result


def test_mcp_verify_change_returns_shared_schema(monkeypatch):
    class FakeMCP:
        def __init__(self):
            self.tools = {}

        def tool(self):
            def decorate(fn):
                self.tools[fn.__name__] = fn
                return fn

            return decorate

        def resource(self, *_args, **_kwargs):
            def decorate(fn):
                return fn

            return decorate

    fake = FakeMCP()
    _register_tools(fake)
    monkeypatch.setattr(mcp_server, "_gate", lambda _tool_name: None)
    monkeypatch.setattr(
        mcp_server,
        "_verify_change_impl",
        lambda **_kwargs: {
            "schema_version": 1,
            "tool": "verify_change",
            "status": "pass",
            "target": {"path": ".", "file": "app.py", "range": None},
            "findings": [],
            "summary": "No AI-code issues found",
        },
    )

    result = json.loads(fake.tools["verify_change"](path=".", file="app.py"))

    assert result["schema_version"] == 1
    assert result["tool"] == "verify_change"
    assert result["status"] == "pass"


def test_mcp_verify_agent_passthrough(monkeypatch):
    class FakeMCP:
        def __init__(self):
            self.tools = {}

        def tool(self):
            def decorate(fn):
                self.tools[fn.__name__] = fn
                return fn

            return decorate

        def resource(self, *_args, **_kwargs):
            def decorate(fn):
                return fn

            return decorate

    fake = FakeMCP()
    _register_tools(fake)
    monkeypatch.setattr(mcp_server, "_gate", lambda _tool_name: None)
    monkeypatch.setattr(
        mcp_server,
        "_verify_agent_impl",
        lambda **_kwargs: {
            "schema_version": 1,
            "tool": "verify_agent",
            "path": ".",
            "integrations_found": 0,
            "defense_score": {"score_pct": 100},
            "failed_checks": [],
            "summary": "Defense score 100% (SECURE); 0 failed check(s)",
        },
    )

    result = json.loads(fake.tools["verify_agent"](path="."))

    assert result["schema_version"] == 1
    assert result["tool"] == "verify_agent"
    assert result["failed_checks"] == []


def test_mcp_verify_agent_real_impl_on_fixture(monkeypatch, tmp_path):
    class FakeMCP:
        def __init__(self):
            self.tools = {}

        def tool(self):
            def decorate(fn):
                self.tools[fn.__name__] = fn
                return fn

            return decorate

        def resource(self, *_args, **_kwargs):
            def decorate(fn):
                return fn

            return decorate

    target = tmp_path / "agent"
    target.mkdir()
    (target / "app.py").write_text(
        """
import openai
from flask import request
client = openai.OpenAI()

def run():
    msg = request.get_json()["message"]
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": msg}],
    )
    return eval(response.choices[0].message.content)
""",
        encoding="utf-8",
    )

    fake = FakeMCP()
    _register_tools(fake)
    monkeypatch.setattr(mcp_server, "_gate", lambda _tool_name: None)

    result = json.loads(
        fake.tools["verify_agent"](path=str(target), fail_on="critical")
    )

    assert result["schema_version"] == 1
    assert result["tool"] == "verify_agent"
    assert result["integrations_found"] >= 1
    assert result["failed_checks"], "guardrail-free fixture must fail checks"
    assert len(result["attestation"]["digest"]) == 64
    assert result["gate"] == {
        "fail_on": "critical",
        "min_score": None,
        "passed": False,
    }
    assert result["owasp"]["framework"] == "llm"
    assert result["owasp"]["version"] == "2025"
    failed_ids = {check["plugin_id"] for check in result["failed_checks"]}
    assert "no-dangerous-sink" in failed_ids


def test_mcp_verify_agent_rejects_missing_path(monkeypatch):
    class FakeMCP:
        def __init__(self):
            self.tools = {}

        def tool(self):
            def decorate(fn):
                self.tools[fn.__name__] = fn
                return fn

            return decorate

        def resource(self, *_args, **_kwargs):
            def decorate(fn):
                return fn

            return decorate

    fake = FakeMCP()
    _register_tools(fake)
    monkeypatch.setattr(mcp_server, "_gate", lambda _tool_name: None)

    result = json.loads(fake.tools["verify_agent"](path="/nonexistent/nowhere"))

    assert "error" in result
