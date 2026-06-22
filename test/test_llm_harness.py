import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from skylos.llm.harness import (
    HarnessBudget,
    HarnessBudgetExceeded,
    HarnessReplayError,
    HarnessRunner,
    HarnessToolRegistry,
    default_verification_tool_registry,
    load_harness_replay,
    run_verification_harness,
)
from skylos.llm.agents import AgentConfig, DeadCodeAgent


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def test_runner_records_step_and_writes_jsonl_trace(tmp_path):
    trace_root = tmp_path / "runs"
    runner = HarnessRunner(
        kind="verification",
        project_root=tmp_path,
        run_id="run-one",
        trace_root=trace_root,
    )

    output = runner.run_step(
        "verify",
        lambda: {"verified_findings": [{"name": "old"}]},
        input_summary={"finding_count": 1},
        output_summary=lambda result: {
            "verified_findings": len(result["verified_findings"])
        },
    )
    runner.finish()

    assert output == {"verified_findings": [{"name": "old"}]}
    assert runner.run.status == "completed"
    assert runner.run.steps[0].output_summary == {"verified_findings": 1}

    trace_path = trace_root / "run-one" / "events.jsonl"
    events = _read_jsonl(trace_path)
    assert [event["event"] for event in events] == [
        "run_started",
        "step_started",
        "step_completed",
        "run_completed",
    ]
    assert events[-1]["status"] == "completed"
    assert events[-1]["trace_path"] == str(trace_path)

    state = _read_json(trace_root / "run-one" / "state.json")
    summary = _read_json(trace_root / "run-one" / "summary.json")
    assert state["current_phase"] is None
    assert state["completed_phases"] == ["verify"]
    assert summary["status"] == "completed"
    assert summary["completed_phases"] == ["verify"]


def test_runner_records_registered_tool_call(tmp_path):
    trace_root = tmp_path / "runs"
    registry = HarnessToolRegistry()
    registry.register(
        "grep_refs",
        category="deterministic",
        description="Find static references.",
    )
    runner = HarnessRunner(
        kind="verification",
        project_root=tmp_path,
        run_id="tool-run",
        trace_root=trace_root,
        tool_registry=registry,
    )

    with runner.step("candidate_selection") as step:
        result = runner.run_tool(
            "grep_refs",
            lambda: ["app.py:1: old()"],
            input_summary={"query": "old"},
            output_summary=lambda matches: {"matches": len(matches)},
        )
        step.set_output_summary(to_verify=1)
        live_events = _read_jsonl(trace_root / "tool-run" / "events.jsonl")
        assert [event["event"] for event in live_events] == [
            "run_started",
            "step_started",
            "tool_started",
            "tool_completed",
        ]
    runner.finish()

    assert result == ["app.py:1: old()"]
    events = _read_jsonl(trace_root / "tool-run" / "events.jsonl")
    assert [event["event"] for event in events] == [
        "run_started",
        "step_started",
        "tool_started",
        "tool_completed",
        "step_completed",
        "run_completed",
    ]

    state = _read_json(trace_root / "tool-run" / "state.json")
    summary = _read_json(trace_root / "tool-run" / "summary.json")
    assert state["metadata"]["registered_tools"] == [
        {
            "name": "grep_refs",
            "category": "deterministic",
            "description": "Find static references.",
        }
    ]
    assert state["tool_calls"][0]["name"] == "grep_refs"
    assert state["tool_calls"][0]["phase"] == "candidate_selection"
    assert state["tool_calls"][0]["status"] == "completed"
    assert state["tool_calls"][0]["input_summary"] == {"query": "old"}
    assert state["tool_calls"][0]["output_summary"] == {"matches": 1}
    assert summary["tool_call_count"] == 1


def test_runner_rejects_unknown_registered_tool(tmp_path):
    runner = HarnessRunner(
        kind="verification",
        project_root=tmp_path,
        tool_registry=HarnessToolRegistry(),
    )

    with pytest.raises(KeyError, match="unknown harness tool"):
        runner.run_tool("missing", lambda: None)

    assert runner.run.tool_calls == []


def test_runner_live_usage_survives_failed_step_without_double_counting(tmp_path):
    runner = HarnessRunner(
        kind="verification",
        project_root=tmp_path,
        run_id="failed-live-usage",
        trace_root=tmp_path / "runs",
    )

    with pytest.raises(RuntimeError, match="after call"):
        with runner.step("verify_findings") as step:
            runner.update_usage(llm_calls=1)
            step.set_output_summary(llm_calls=1)
            raise RuntimeError("after call")

    state = _read_json(tmp_path / "runs" / "failed-live-usage" / "state.json")
    summary = _read_json(tmp_path / "runs" / "failed-live-usage" / "summary.json")
    assert state["status"] == "failed"
    assert state["budget_used"]["llm_calls"] == 1
    assert summary["budget_used"]["llm_calls"] == 1


def test_default_verification_tool_registry_lists_expected_tools():
    registry = default_verification_tool_registry()

    assert {
        "entry_discovery",
        "deterministic_suppression",
        "batch_verify",
        "graph_verify",
        "suppression_audit",
        "survivor_challenge",
    }.issubset({tool.name for tool in registry.list()})


def test_runner_artifacts_form_replayable_golden_trace(tmp_path):
    trace_root = tmp_path / "runs"
    runner = HarnessRunner(
        kind="verification",
        project_root=tmp_path,
        run_id="golden-replay",
        trace_root=trace_root,
        metadata={"fixture": "golden"},
    )
    runner.update_usage(findings=2)

    target = {
        "fingerprint": "fp-old",
        "name": "app.old",
        "file": "app.py",
        "line": 1,
        "type": "function",
    }
    with runner.step(
        "candidate_selection",
        input_summary={"finding_count": 2, "max_verify": 1},
    ) as step:
        runner.record_decision(
            phase="candidate_selection",
            code="sent_to_llm",
            target=target,
            details={"verdict": None},
        )
        step.set_output_summary(to_verify=1, llm_calls=0)

    with runner.step(
        "verify_findings",
        input_summary={"candidate_count": 1, "batch_mode": False},
    ) as step:
        runner.record_decision(
            phase="verify_findings",
            code="verified_true_positive",
            target=target,
            details={"verdict": "TRUE_POSITIVE"},
        )
        step.set_output_summary(llm_calls=1, verified_true_positive=1)

    runner.finish()

    run_dir = trace_root / "golden-replay"
    events = _read_jsonl(run_dir / "events.jsonl")
    state = _read_json(run_dir / "state.json")
    summary = _read_json(run_dir / "summary.json")

    replay = {
        "events": [event["event"] for event in events],
        "phases": [step["name"] for step in state["steps"]],
        "completed_phases": summary["completed_phases"],
        "decisions": [
            {
                "phase": decision["phase"],
                "code": decision["code"],
                "name": decision["target"]["name"],
                "verdict": decision["details"]["verdict"],
            }
            for decision in state["decisions"]
        ],
        "budget_used": {
            key: summary["budget_used"][key]
            for key in ("steps", "findings", "llm_calls", "fixes")
        },
    }

    assert replay == {
        "events": [
            "run_started",
            "step_started",
            "step_completed",
            "step_started",
            "step_completed",
            "run_completed",
        ],
        "phases": ["candidate_selection", "verify_findings"],
        "completed_phases": ["candidate_selection", "verify_findings"],
        "decisions": [
            {
                "phase": "candidate_selection",
                "code": "sent_to_llm",
                "name": "app.old",
                "verdict": None,
            },
            {
                "phase": "verify_findings",
                "code": "verified_true_positive",
                "name": "app.old",
                "verdict": "TRUE_POSITIVE",
            },
        ],
        "budget_used": {
            "steps": 2,
            "findings": 2,
            "llm_calls": 1,
            "fixes": 0,
        },
    }


def test_harness_replay_validates_runner_artifacts(tmp_path):
    trace_root = tmp_path / "runs"
    registry = HarnessToolRegistry()
    registry.register("grep_refs", category="deterministic")
    runner = HarnessRunner(
        kind="verification",
        project_root=tmp_path,
        run_id="replay-ok",
        trace_root=trace_root,
        tool_registry=registry,
    )

    with runner.step("candidate_selection"):
        runner.run_tool(
            "grep_refs",
            lambda: ["app.py:1: old()"],
            output_summary=lambda matches: {"matches": len(matches)},
        )
    runner.finish()

    replay = load_harness_replay(trace_root / "replay-ok")

    assert replay.ok
    replay.assert_valid()
    assert replay.event_names() == [
        "run_started",
        "step_started",
        "tool_started",
        "tool_completed",
        "step_completed",
        "run_completed",
    ]
    assert replay.phase_sequence() == ["candidate_selection"]
    assert replay.tool_sequence() == ["grep_refs"]


def test_harness_replay_reports_corrupted_summary(tmp_path):
    trace_root = tmp_path / "runs"
    runner = HarnessRunner(
        kind="verification",
        project_root=tmp_path,
        run_id="replay-corrupt",
        trace_root=trace_root,
    )
    runner.run_step("verify", lambda: {})
    runner.finish()

    summary_path = trace_root / "replay-corrupt" / "summary.json"
    summary = _read_json(summary_path)
    summary["phase_count"] = 99
    summary_path.write_text(json.dumps(summary), encoding="utf-8")

    replay = load_harness_replay(trace_root / "replay-corrupt")

    assert not replay.ok
    assert any(issue.code == "phase_count_mismatch" for issue in replay.issues)
    with pytest.raises(HarnessReplayError, match="phase_count_mismatch"):
        replay.assert_valid()


def test_runner_enforces_step_budget(tmp_path):
    runner = HarnessRunner(
        kind="verification",
        project_root=tmp_path,
        budget=HarnessBudget(max_steps=0),
    )

    with pytest.raises(HarnessBudgetExceeded, match="step budget"):
        runner.run_step("verify", lambda: {})


def test_runner_sanitizes_trace_run_id(tmp_path):
    runner = HarnessRunner(
        kind="verification",
        project_root=tmp_path,
        run_id="../bad/id",
        trace_root=tmp_path / "runs",
    )

    runner.finish()

    assert runner.run.run_id == "bad_id"
    assert (tmp_path / "runs" / "bad_id" / "events.jsonl").exists()
    assert (tmp_path / "runs" / "bad_id" / "state.json").exists()
    assert (tmp_path / "runs" / "bad_id" / "summary.json").exists()


def test_verification_harness_wraps_existing_verifier(tmp_path):
    finding = {
        "name": "old_func",
        "file": str(tmp_path / "app.py"),
        "line": 1,
        "references": 0,
    }
    result = {
        "verified_findings": [finding],
        "new_dead_code": [],
        "entry_points": [],
        "stats": {"total_findings": 1, "llm_calls": 2},
    }

    with patch(
        "skylos.llm.harness.verification.run_verification",
        return_value=result,
    ) as mock_run:
        harness_result = run_verification_harness(
            findings=[finding],
            defs_map={"app.old_func": {"name": "app.old_func"}},
            project_root=tmp_path,
            harness_run_id="verify-one",
            harness_trace_root=tmp_path / "runs",
            harness_budget=HarnessBudget(max_findings=2, max_llm_calls=2),
            model="test-model",
            api_key="test-key",
            max_verify=10,
            max_challenge=5,
            quiet=True,
        )

    assert harness_result.output == result
    assert harness_result.run.kind == "verification"
    assert harness_result.run.status == "completed"
    assert harness_result.run.trace_path is not None
    mock_run.assert_called_once()
    assert mock_run.call_args.kwargs["harness_runner"] is not None
    assert mock_run.call_args.kwargs["harness_budget"].max_llm_calls == 2


def test_verification_harness_writes_default_project_trace(tmp_path):
    result = {
        "verified_findings": [],
        "new_dead_code": [],
        "entry_points": [],
        "stats": {"total_findings": 0, "llm_calls": 0},
    }

    with patch(
        "skylos.llm.harness.verification.run_verification",
        return_value=result,
    ):
        harness_result = run_verification_harness(
            findings=[],
            defs_map={},
            project_root=tmp_path,
            harness_run_id="default-trace",
            quiet=True,
        )

    trace_path = tmp_path / ".skylos" / "runs" / "default-trace" / "events.jsonl"
    assert harness_result.run.trace_path == str(trace_path)
    events = _read_jsonl(trace_path)
    assert events[-1]["event"] == "run_completed"
    assert events[-1]["status"] == "completed"


def test_verification_harness_rejects_findings_over_budget(tmp_path):
    findings = [
        {"name": "one", "file": str(tmp_path / "a.py"), "line": 1},
        {"name": "two", "file": str(tmp_path / "b.py"), "line": 1},
    ]

    with patch("skylos.llm.harness.verification.run_verification") as mock_run:
        with pytest.raises(HarnessBudgetExceeded, match="findings budget"):
            run_verification_harness(
                findings=findings,
                defs_map={},
                project_root=tmp_path,
                harness_run_id="too-many-findings",
                harness_budget=HarnessBudget(max_findings=1),
                quiet=True,
            )

    mock_run.assert_not_called()
    events = _read_jsonl(tmp_path / ".skylos" / "runs" / "too-many-findings" / "events.jsonl")
    assert events[-1]["status"] == "failed"
    assert "findings budget" in events[-1]["error"]
    state = _read_json(tmp_path / ".skylos" / "runs" / "too-many-findings" / "state.json")
    summary = _read_json(tmp_path / ".skylos" / "runs" / "too-many-findings" / "summary.json")
    assert state["budget_used"]["findings"] == 2
    assert summary["status"] == "failed"


def test_verification_harness_rejects_llm_calls_over_budget(tmp_path):
    result = {
        "verified_findings": [],
        "new_dead_code": [],
        "entry_points": [],
        "stats": {"total_findings": 1, "llm_calls": 3},
    }

    with patch(
        "skylos.llm.harness.verification.run_verification",
        return_value=result,
    ):
        with pytest.raises(HarnessBudgetExceeded, match="LLM call budget"):
            run_verification_harness(
                findings=[{"name": "old", "file": str(tmp_path / "a.py"), "line": 1}],
                defs_map={},
                project_root=tmp_path,
                harness_run_id="over-budget",
                harness_trace_root=tmp_path / "runs",
                harness_budget=HarnessBudget(max_llm_calls=2),
                quiet=True,
            )

    events = _read_jsonl(tmp_path / "runs" / "over-budget" / "events.jsonl")
    assert events[-1]["status"] == "failed"
    assert "LLM call budget" in events[-1]["error"]


def test_verification_harness_traces_verifier_exception(tmp_path):
    with patch(
        "skylos.llm.harness.verification.run_verification",
        side_effect=RuntimeError("verifier exploded"),
    ):
        with pytest.raises(RuntimeError, match="verifier exploded"):
            run_verification_harness(
                findings=[],
                defs_map={},
                project_root=tmp_path,
                harness_run_id="verifier-failed",
                quiet=True,
            )

    events = _read_jsonl(tmp_path / ".skylos" / "runs" / "verifier-failed" / "events.jsonl")
    assert [event["event"] for event in events] == [
        "run_started",
        "run_completed",
    ]
    assert events[-1]["status"] == "failed"
    assert "RuntimeError: verifier exploded" in events[-1]["error"]


def test_verification_harness_blocks_entry_discovery_before_llm_call(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname = 'demo'\n")

    with patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent") as MockAgent:
        with pytest.raises(HarnessBudgetExceeded, match="before entry_discovery"):
            run_verification_harness(
                findings=[],
                defs_map={},
                project_root=project,
                harness_run_id="blocked-entry",
                harness_budget=HarnessBudget(max_llm_calls=0),
                model="test-model",
                api_key="test-key",
                quiet=True,
            )

    MockAgent.return_value._call_llm.assert_not_called()
    events = _read_jsonl(project / ".skylos" / "runs" / "blocked-entry" / "events.jsonl")
    assert [event["event"] for event in events] == [
        "run_started",
        "step_started",
        "step_failed",
        "run_completed",
    ]
    assert events[2]["name"] == "entry_discovery"
    assert "before entry_discovery" in events[-1]["error"]
    state = _read_json(project / ".skylos" / "runs" / "blocked-entry" / "state.json")
    summary = _read_json(project / ".skylos" / "runs" / "blocked-entry" / "summary.json")
    assert state["failed_phase"] == "entry_discovery"
    assert state["budget_used"]["llm_calls"] == 0
    assert summary["failed_phase"] == "entry_discovery"
    assert summary["budget_remaining"]["llm_calls"] == 0


def test_verification_harness_allows_no_config_entry_discovery_with_zero_llm_budget(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    with patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent") as MockAgent:
        harness_result = run_verification_harness(
            findings=[],
            defs_map={},
            project_root=project,
            harness_run_id="no-config-entry",
            harness_budget=HarnessBudget(max_llm_calls=0),
            model="test-model",
            api_key="test-key",
            quiet=True,
        )

    MockAgent.return_value._call_llm.assert_not_called()
    assert harness_result.output["stats"]["llm_calls"] == 0
    state = _read_json(project / ".skylos" / "runs" / "no-config-entry" / "state.json")
    summary = _read_json(project / ".skylos" / "runs" / "no-config-entry" / "summary.json")
    assert state["status"] == "completed"
    assert state["budget_used"]["llm_calls"] == 0
    assert summary["budget_remaining"]["llm_calls"] == 0


def test_verification_harness_runs_real_verifier_with_mocked_agent(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname = 'demo'\n")
    source_file = project / "main.py"
    source_file.write_text("def old_func():\n    pass\n")

    findings = [
        {
            "name": "old_func",
            "full_name": "main.old_func",
            "file": str(source_file),
            "line": 1,
            "confidence": 75,
            "references": 0,
            "type": "function",
            "calls": [],
            "called_by": [],
        }
    ]
    defs_map = {
        "main.old_func": {
            "name": "main.old_func",
            "file": str(source_file),
            "line": 1,
            "type": "function",
        }
    }

    def mock_llm(system, user):
        if "entry point" in system.lower() or "entry point" in user.lower():
            return json.dumps({"entry_points": []})
        if "survivor" in system.lower() or "heuristic" in system.lower():
            return json.dumps(
                {
                    "is_dead": True,
                    "rationale": "spurious match",
                    "heuristic_assessment": "spurious",
                }
            )
        return json.dumps({"verdict": "TRUE_POSITIVE", "rationale": "no callers"})

    with patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent") as MockAgent:
        MockAgent.return_value._call_llm.side_effect = mock_llm
        harness_result = run_verification_harness(
            findings=findings,
            defs_map=defs_map,
            project_root=project,
            harness_run_id="real-verifier",
            model="test-model",
            api_key="test-key",
            max_verify=10,
            max_challenge=5,
            quiet=True,
        )

    assert harness_result.output["stats"]["total_findings"] == 1
    assert harness_result.output["verified_findings"][0]["_llm_verdict"] == "TRUE_POSITIVE"
    step_names = [step.name for step in harness_result.run.steps]
    assert step_names == [
        "entry_discovery",
        "candidate_selection",
        "haiku_prefilter",
        "verify_findings",
        "suppression_audit",
        "propagate_alive",
        "survivor_challenge",
        "finalize",
    ]
    assert harness_result.run.steps[-1].output_summary["verified_findings"] == 1
    tool_names = [call.name for call in harness_result.run.tool_calls]
    assert {
        "entry_discovery",
        "deterministic_suppression",
        "graph_verify",
        "survivor_local_scan",
        "survivor_discovery",
    }.issubset(set(tool_names))
    events = _read_jsonl(project / ".skylos" / "runs" / "real-verifier" / "events.jsonl")
    assert events[-1]["status"] == "completed"
    replay = load_harness_replay(project / ".skylos" / "runs" / "real-verifier")
    replay.assert_valid()
    assert replay.phase_sequence() == step_names
    assert replay.tool_sequence() == tool_names
    state = _read_json(project / ".skylos" / "runs" / "real-verifier" / "state.json")
    summary = _read_json(project / ".skylos" / "runs" / "real-verifier" / "summary.json")
    assert state["current_phase"] is None
    assert state["completed_phases"] == step_names
    assert [call["name"] for call in state["tool_calls"]] == tool_names
    assert state["budget_used"]["findings"] == 1
    assert state["budget_used"]["llm_calls"] == 2
    assert summary["completed_phases"] == step_names
    assert summary["tool_call_count"] == len(tool_names)
    assert summary["decision_count"] >= 2
    decision_codes = {decision["code"] for decision in state["decisions"]}
    assert "sent_to_llm" in decision_codes
    assert "verified_true_positive" in decision_codes


def test_dead_code_agent_verify_candidates_uses_harness(tmp_path):
    expected = {"verified_findings": [], "new_dead_code": [], "stats": {}}
    agent = DeadCodeAgent(AgentConfig(model="test-model", api_key="test-key"))

    with patch("skylos.llm.harness.run_verification_harness") as mock_harness:
        mock_harness.return_value = SimpleNamespace(output=expected)
        result = agent.verify_candidates(
            findings=[],
            defs_map={},
            project_root=tmp_path,
            max_verify=3,
            batch_mode=False,
            quiet=True,
            verification_mode="judge_all",
        )

    assert result == expected
    mock_harness.assert_called_once()
    kwargs = mock_harness.call_args.kwargs
    assert kwargs["project_root"] == str(tmp_path)
    assert kwargs["model"] == "test-model"
    assert kwargs["api_key"] == "test-key"
    assert kwargs["max_verify"] == 3
    assert kwargs["batch_mode"] is False
    assert kwargs["quiet"] is True
    assert kwargs["verification_mode"] == "judge_all"


def test_dead_code_agent_challenge_survivors_uses_harness(tmp_path):
    expected = {"verified_findings": [], "new_dead_code": [], "stats": {}}
    config = AgentConfig(model="test-model", api_key="test-key")
    config.provider = "test-provider"
    config.base_url = "https://example.test/v1"
    agent = DeadCodeAgent(config)
    survivors = [
        {
            "name": "maybe_used",
            "full_name": "app.maybe_used",
            "file": str(tmp_path / "app.py"),
            "line": 1,
            "type": "function",
        }
    ]

    with patch("skylos.llm.harness.run_verification_harness") as mock_harness:
        mock_harness.return_value = SimpleNamespace(output=expected)
        result = agent.challenge_survivors(
            survivors=survivors,
            defs_map={"app.maybe_used": {"name": "app.maybe_used"}},
            project_root=tmp_path,
            max_challenge=7,
            quiet=True,
        )

    assert result == expected
    assert survivors[0]["_is_survivor"] is True
    mock_harness.assert_called_once()
    kwargs = mock_harness.call_args.kwargs
    assert kwargs["findings"] == survivors
    assert kwargs["project_root"] == str(tmp_path)
    assert kwargs["model"] == "test-model"
    assert kwargs["api_key"] == "test-key"
    assert kwargs["provider"] == "test-provider"
    assert kwargs["base_url"] == "https://example.test/v1"
    assert kwargs["max_verify"] == 7
    assert kwargs["max_challenge"] == 7
    assert kwargs["enable_survivor_challenge"] is True
    assert kwargs["batch_mode"] is True
    assert kwargs["quiet"] is True
