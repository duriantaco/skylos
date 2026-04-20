import json
import sys
from unittest.mock import Mock, patch

import pytest

import skylos.cli as cli
from skylos.debt.advisor import (
    DebtAdvisor,
    _parse_json_object,
    _safe_excerpt,
    _user_prompt,
    augment_hotspots_with_advisories,
)
from skylos.debt.baseline import compare_to_baseline, save_baseline
from skylos.debt.engine import (
    build_debt_snapshot,
    collect_debt_signals,
    run_debt_analysis,
)
from skylos.debt.policy import _parse_policy, load_policy
from skylos.debt.report import format_debt_table
from skylos.debt.result import (
    DebtAdvisory,
    DebtHotspot,
    DebtScore,
    DebtSignal,
    DebtSnapshot,
)
from skylos.debt.scoring import build_hotspots


SAMPLE_RESULT = {
    "analysis_summary": {"total_files": 3, "total_loc": 500},
    "quality": [
        {
            "rule_id": "SKY-Q301",
            "severity": "HIGH",
            "file": "/repo/app/services.py",
            "line": 20,
            "name": "process_order",
            "message": "Cyclomatic complexity is 18 (threshold: 10)",
            "value": 18,
            "threshold": 10,
        },
        {
            "rule_id": "SKY-Q804",
            "severity": "HIGH",
            "file": "/repo/app/core.py",
            "line": 1,
            "name": "app.core",
            "message": "Dependency inversion violation",
        },
    ],
    "unused_functions": [
        {
            "name": "legacy_worker",
            "file": "/repo/app/legacy.py",
            "line": 8,
            "confidence": 92,
        }
    ],
    "unused_imports": [],
    "unused_variables": [],
    "unused_classes": [],
    "unused_parameters": [],
}


def _snapshot(project: str) -> DebtSnapshot:
    signal = DebtSignal(
        fingerprint="complexity:SKY-Q301:app/services.py:20:process_order",
        dimension="complexity",
        rule_id="SKY-Q301",
        severity="HIGH",
        file="app/services.py",
        line=20,
        subject="process_order",
        message="Cyclomatic complexity is 18 (threshold: 10)",
        points=14.0,
    )
    hotspot = DebtHotspot(
        fingerprint="hotspot:app/services.py",
        file="app/services.py",
        score=14.0,
        signal_count=1,
        dimension_count=1,
        primary_dimension="complexity",
        signals=[signal],
    )
    score = DebtScore(
        total_points=14.0,
        normalizer=2.0,
        score_pct=93,
        risk_rating="LOW",
        hotspot_count=1,
        signal_count=1,
    )
    return DebtSnapshot(
        version="1.0",
        timestamp="2026-03-28T00:00:00+00:00",
        project=project,
        files_scanned=3,
        total_loc=500,
        score=score,
        hotspots=[hotspot],
        summary={},
    )


def test_collect_debt_signals_maps_dimensions_and_dead_code():
    signals = collect_debt_signals(
        SAMPLE_RESULT,
        project_root=cli.Path("/repo"),
    )

    dimensions = {(signal.rule_id, signal.dimension) for signal in signals}
    assert ("SKY-Q301", "complexity") in dimensions
    assert ("SKY-Q804", "architecture") in dimensions
    assert ("SKY-U001", "dead_code") in dimensions


def test_collect_debt_signals_filters_to_changed_files():
    signals = collect_debt_signals(
        SAMPLE_RESULT,
        project_root=cli.Path("/repo"),
        changed_files=["/repo/app/services.py"],
    )

    assert len(signals) == 1
    assert signals[0].file == "app/services.py"
    assert signals[0].dimension == "complexity"


def test_run_debt_analysis_builds_snapshot():
    with patch(
        "skylos.debt.engine.run_analyze", return_value=json.dumps(SAMPLE_RESULT)
    ):
        snapshot = run_debt_analysis("/repo")

    assert snapshot.files_scanned == 3
    assert snapshot.total_loc == 500
    assert snapshot.score.hotspot_count == len(snapshot.hotspots)
    assert snapshot.summary["dimensions"]["complexity"] == 1


def test_run_debt_analysis_changed_mode_keeps_project_score_and_filters_hotspots():
    with patch(
        "skylos.debt.engine.run_analyze", return_value=json.dumps(SAMPLE_RESULT)
    ):
        full_snapshot = run_debt_analysis("/repo")
        changed_snapshot = run_debt_analysis(
            "/repo",
            changed_files=["/repo/app/services.py"],
        )

    assert full_snapshot.score.score_pct == changed_snapshot.score.score_pct
    assert full_snapshot.score.total_points == changed_snapshot.score.total_points
    assert changed_snapshot.score.hotspot_count == 3
    assert len(changed_snapshot.hotspots) == 1
    assert changed_snapshot.hotspots[0].file == "app/services.py"
    assert changed_snapshot.summary["scope"]["score"] == "project"
    assert changed_snapshot.summary["scope"]["hotspots"] == "changed"


def test_build_debt_snapshot_reuses_static_result():
    snapshot = build_debt_snapshot(SAMPLE_RESULT, project_root="/repo")

    assert snapshot.files_scanned == 3
    assert snapshot.total_loc == 500
    assert snapshot.score.hotspot_count == len(snapshot.hotspots)
    assert snapshot.summary["dimensions"]["complexity"] == 1


def test_build_hotspots_changed_files_raise_priority_not_structural_score():
    signals = collect_debt_signals(
        SAMPLE_RESULT,
        project_root=cli.Path("/repo"),
    )

    unchanged_hotspots = build_hotspots(signals)
    changed_hotspots = build_hotspots(
        signals,
        changed_files={"app/services.py"},
    )

    by_file = {hotspot.file: hotspot for hotspot in unchanged_hotspots}
    changed_by_file = {hotspot.file: hotspot for hotspot in changed_hotspots}

    assert changed_by_file["app/services.py"].score == by_file["app/services.py"].score
    assert (
        changed_by_file["app/services.py"].priority_score
        > by_file["app/services.py"].priority_score
    )


def test_compare_to_baseline_marks_worsened_unchanged_and_resolved():
    snapshot = _snapshot("/repo")
    baseline = {
        "hotspots": [
            {"fingerprint": "hotspot:app/services.py", "score": 10.0},
            {"fingerprint": "hotspot:app/old.py", "score": 8.0},
        ]
    }

    counts = compare_to_baseline(snapshot, baseline)

    assert snapshot.hotspots[0].baseline_status == "worsened"
    assert counts["worsened"] == 1
    assert counts["resolved"] == 1


def test_compare_to_baseline_changed_scope_does_not_count_unseen_resolved():
    snapshot = _snapshot("/repo")
    snapshot.summary["scope"] = {"score": "project", "hotspots": "changed"}
    baseline = {
        "hotspots": [
            {"fingerprint": "hotspot:app/services.py", "score": 10.0},
            {"fingerprint": "hotspot:app/old.py", "score": 8.0},
        ]
    }

    counts = compare_to_baseline(snapshot, baseline)

    assert snapshot.hotspots[0].baseline_status == "worsened"
    assert counts["worsened"] == 1
    assert counts["resolved"] == 0


def test_save_baseline_normalizes_changed_scope_to_project(tmp_path):
    snapshot = _snapshot(str(tmp_path))
    snapshot.all_hotspots = list(snapshot.hotspots)
    snapshot.summary["scope"] = {"score": "project", "hotspots": "changed"}
    snapshot.summary["project_hotspot_count"] = 1
    snapshot.summary["visible_hotspot_count"] = 1
    snapshot.summary["baseline"] = {"resolved": 0}

    path = save_baseline(tmp_path, snapshot)
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["summary"]["scope"]["hotspots"] == "project"
    assert "baseline" not in payload["summary"]


def test_parse_policy_accepts_gate_and_report():
    policy = _parse_policy(
        {
            "gate": {"min_score": 80, "fail_on_status": "new_or_worsened"},
            "report": {"top": 15},
        }
    )

    assert policy.gate_min_score == 80
    assert policy.gate_fail_on_status == "new_or_worsened"
    assert policy.report_top == 15


def test_parse_policy_rejects_invalid_status():
    with pytest.raises(ValueError):
        _parse_policy({"gate": {"fail_on_status": "boom"}})


def test_load_policy_discovers_from_start_path(tmp_path):
    project = tmp_path / "repo"
    src = project / "src"
    src.mkdir(parents=True)
    (project / "skylos-debt.yaml").write_text(
        "report:\n  top: 3\n",
        encoding="utf-8",
    )

    policy = load_policy(start_path=src)

    assert policy is not None
    assert policy.report_top == 3


def test_augment_hotspots_with_advisories_sets_advisory(tmp_path):
    services = tmp_path / "app" / "services.py"
    services.parent.mkdir(parents=True)
    services.write_text(
        "def process_order(order):\n"
        "    if order:\n"
        "        return order\n"
        "    return None\n",
        encoding="utf-8",
    )
    snapshot = _snapshot(str(tmp_path))

    with patch("skylos.debt.advisor.LiteLLMAdapter") as mock_adapter_cls:
        mock_adapter_cls.return_value.complete.return_value = json.dumps(
            {
                "summary": "The hotspot concentrates branching logic in one service function.",
                "root_cause": "Control flow and responsibility are mixed in the same routine.",
                "refactor_steps": [
                    "Extract validation into a helper.",
                    "Split decision branches into named functions.",
                ],
                "remediation_notes": ["Keep behavior covered with regression tests."],
                "confidence": "medium",
            }
        )

        advised = augment_hotspots_with_advisories(
            snapshot.hotspots,
            project_root=tmp_path,
            model="gpt-4.1",
            api_key="test-key",
        )

    assert advised == 1
    assert snapshot.hotspots[0].advisory is not None
    assert (
        snapshot.hotspots[0].advisory.summary
        == "The hotspot concentrates branching logic in one service function."
    )
    assert snapshot.hotspots[0].advisory.refactor_steps[0].startswith("Extract")


def test_safe_excerpt_returns_context_and_missing_file_is_empty(tmp_path):
    services = tmp_path / "app.py"
    services.write_text(
        "line 1\n"
        "line 2\n"
        "line 3\n"
        "line 4\n"
        "line 5\n",
        encoding="utf-8",
    )

    excerpt = _safe_excerpt(services, 3, radius=1)

    assert excerpt == "2: line 2\n3: line 3\n4: line 4"
    assert _safe_excerpt(tmp_path / "missing.py", 3) == ""


def test_parse_json_object_handles_plain_fenced_and_invalid_payloads():
    assert _parse_json_object('{"summary":"ok"}') == {"summary": "ok"}
    assert _parse_json_object('```json\n{"summary":"ok"}\n```') == {
        "summary": "ok"
    }
    assert _parse_json_object("not json") is None
    assert _parse_json_object("") is None


def test_user_prompt_includes_signals_architecture_and_excerpt(tmp_path):
    services = tmp_path / "app" / "services.py"
    services.parent.mkdir(parents=True)
    services.write_text(
        "\n".join(f"line {idx}" for idx in range(1, 31)) + "\n",
        encoding="utf-8",
    )
    snapshot = _snapshot(str(tmp_path))

    prompt = _user_prompt(
        snapshot.hotspots[0],
        project_root=tmp_path,
        architecture_metrics={
            "system_metrics": {
                "mean_distance": 1.2,
                "architecture_fitness": 0.8,
                "dip_violations": 3,
            }
        },
    )

    assert "Hotspot:" in prompt
    assert "- [SKY-Q301] Cyclomatic complexity is 18 (threshold: 10)" in prompt
    assert "Architecture context:" in prompt
    assert "- mean_distance=1.2" in prompt
    assert "[app/services.py:20]" in prompt


def test_debt_advisor_summarize_hotspot_normalizes_payload(tmp_path):
    services = tmp_path / "app" / "services.py"
    services.parent.mkdir(parents=True)
    services.write_text(
        "def process_order(order):\n"
        "    if order:\n"
        "        return order\n"
        "    return None\n",
        encoding="utf-8",
    )
    snapshot = _snapshot(str(tmp_path))
    advisor = DebtAdvisor(model="gpt-4.1")
    advisor.adapter = Mock(
        complete=Mock(
            return_value=json.dumps(
                {
                    "summary": "The hotspot concentrates branching logic.",
                    "root_cause": "Control flow and responsibility are mixed.",
                    "refactor_steps": ["Extract validation.", "", "Split branches."],
                    "remediation_notes": ["Keep regression coverage.", ""],
                    "confidence": "BOGUS",
                }
            )
        )
    )

    advisory = advisor.summarize_hotspot(snapshot.hotspots[0], project_root=tmp_path)

    assert advisory is not None
    assert advisory.confidence == "medium"
    assert advisory.refactor_steps == ["Extract validation.", "Split branches."]
    assert advisory.remediation_notes == ["Keep regression coverage."]


def test_debt_advisor_summarize_hotspot_returns_none_for_incomplete_payload(tmp_path):
    services = tmp_path / "app" / "services.py"
    services.parent.mkdir(parents=True)
    services.write_text(
        "def process_order(order):\n"
        "    if order:\n"
        "        return order\n"
        "    return None\n",
        encoding="utf-8",
    )
    snapshot = _snapshot(str(tmp_path))
    advisor = DebtAdvisor(model="gpt-4.1")
    advisor.adapter = Mock(
        complete=Mock(
            return_value=json.dumps(
                {
                    "summary": "",
                    "root_cause": "Control flow and responsibility are mixed.",
                    "refactor_steps": [],
                    "remediation_notes": [],
                    "confidence": "low",
                }
            )
        )
    )

    advisory = advisor.summarize_hotspot(snapshot.hotspots[0], project_root=tmp_path)

    assert advisory is None


def test_format_debt_table_renders_changed_scope_empty_state_and_baseline():
    snapshot = _snapshot("/repo")
    snapshot.hotspots = []
    snapshot.summary["scope"] = {"score": "project", "hotspots": "changed"}
    snapshot.summary["project_hotspot_count"] = 3
    snapshot.summary["baseline"] = {
        "new": 1,
        "worsened": 2,
        "improved": 0,
        "unchanged": 4,
        "resolved": 1,
    }

    rendered = format_debt_table(snapshot)

    assert "Skylos Technical Debt Report" in rendered
    assert "Hotspots: 0 shown (3 project total)" in rendered
    assert "View: changed files only" in rendered
    assert "Baseline: 1 new | 2 worsened | 0 improved | 4 unchanged | 1 resolved" in rendered
    assert "No debt hotspots found in changed files." in rendered


def test_format_debt_table_renders_hotspot_advisory_and_delta():
    snapshot = _snapshot("/repo")
    hotspot = snapshot.hotspots[0]
    hotspot.priority_score = 16.5
    hotspot.baseline_status = "worsened"
    hotspot.score_delta = 1.25
    hotspot.advisory = DebtAdvisory(
        summary="Split summary and detail formatting into helpers.",
        root_cause="One function owns several output branches.",
        refactor_steps=[
            "Extract summary line builders.",
            "Move hotspot rendering into a helper.",
            "Keep advisory formatting isolated.",
        ],
    )

    rendered = format_debt_table(snapshot)

    assert (
        "1. app/services.py | score=14.00 | priority=16.50 | "
        "signals=1 | dimensions=complexity | worsened (+1.25)"
    ) in rendered
    assert "advisor: Split summary and detail formatting into helpers." in rendered
    assert "step: Extract summary line builders." in rendered
    assert "step: Move hotspot rendering into a helper." in rendered
    assert "step: Keep advisory formatting isolated." not in rendered


def test_format_debt_table_orders_by_priority_and_applies_top_limit():
    snapshot = _snapshot("/repo")
    hotspot = snapshot.hotspots[0]
    hotspot.priority_score = 10.0

    second_signal = DebtSignal(
        fingerprint="maintainability:SKY-L027:app/core.py:8:app.core",
        dimension="maintainability",
        rule_id="SKY-L027",
        severity="MEDIUM",
        file="app/core.py",
        line=8,
        subject="app.core",
        message="String literal repeated 5 times (threshold: 3)",
        points=9.0,
    )
    second_hotspot = DebtHotspot(
        fingerprint="hotspot:app/core.py",
        file="app/core.py",
        score=9.0,
        signal_count=1,
        dimension_count=1,
        primary_dimension="maintainability",
        priority_score=18.0,
        signals=[second_signal],
    )
    snapshot.hotspots.append(second_hotspot)

    rendered = format_debt_table(snapshot, top=1)

    assert "1. app/core.py | score=9.00 | priority=18.00" in rendered
    assert "app/services.py" not in rendered


def test_cli_debt_json_outputs_snapshot_and_exits_zero(tmp_path, monkeypatch):
    snapshot = _snapshot(str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["skylos", "debt", str(tmp_path), "--json"])

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("builtins.print") as mock_print,
        patch("skylos.cli.Console", return_value=Mock()),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    payload = json.loads(mock_print.call_args.args[0])
    assert payload["score"]["score_pct"] == 93
    assert payload["hotspots"][0]["file"] == "app/services.py"


def test_cli_debt_with_agent_includes_advisory_in_json(tmp_path, monkeypatch):
    snapshot = _snapshot(str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "debt", str(tmp_path), "--json", "--with-agent"],
    )

    def _augment(hotspots, **kwargs):
        hotspots[0].advisory = DebtAdvisory(
            summary="Start by isolating the branching service logic.",
            root_cause="The function owns too many decision paths.",
            refactor_steps=["Extract branch handlers."],
            remediation_notes=["Add regression tests first."],
            confidence="medium",
            model="gpt-4.1",
        )
        return 1

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "test-key", None, False),
        ),
        patch(
            "skylos.debt.augment_hotspots_with_advisories",
            side_effect=_augment,
        ),
        patch("builtins.print") as mock_print,
        patch("skylos.cli.Console", return_value=Mock()),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    payload = json.loads(mock_print.call_args.args[0])
    assert payload["summary"]["agent"]["advised_hotspots"] == 1
    assert (
        payload["hotspots"][0]["advisory"]["summary"]
        == "Start by isolating the branching service logic."
    )


def test_cli_debt_fail_on_status_uses_baseline_comparison(tmp_path, monkeypatch):
    snapshot = _snapshot(str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "skylos",
            "debt",
            str(tmp_path),
            "--baseline",
            "--fail-on-status",
            "new",
        ],
    )

    def _mark_new(current_snapshot, baseline):
        current_snapshot.hotspots[0].baseline_status = "new"
        current_snapshot.summary["baseline"] = {"new": 1}
        return {"new": 1}

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("skylos.debt.load_baseline", return_value={"hotspots": []}),
        patch("skylos.debt.compare_to_baseline", side_effect=_mark_new),
        patch("skylos.cli.Console", return_value=Mock()),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 1


def test_cli_debt_uses_project_policy_for_report_top(tmp_path, monkeypatch):
    snapshot = _snapshot(str(tmp_path))
    (tmp_path / "skylos-debt.yaml").write_text(
        "report:\n  top: 1\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["skylos", "debt", str(tmp_path)])

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("skylos.debt.format_debt_table", return_value="ok") as mock_table,
        patch("skylos.cli.Console", return_value=Mock()),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    assert mock_table.call_args.kwargs["top"] == 1


def test_cli_debt_top_flag_overrides_policy_report_top(tmp_path, monkeypatch):
    snapshot = _snapshot(str(tmp_path))
    (tmp_path / "skylos-debt.yaml").write_text(
        "report:\n  top: 1\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["skylos", "debt", str(tmp_path), "--top", "2"])

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("skylos.debt.format_debt_table", return_value="ok") as mock_table,
        patch("skylos.cli.Console", return_value=Mock()),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    assert mock_table.call_args.kwargs["top"] == 2


def test_cli_debt_save_baseline_requires_project_root_scan(tmp_path, monkeypatch):
    project = tmp_path / "repo"
    target = project / "src"
    target.mkdir(parents=True)
    snapshot = _snapshot(str(project))
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "debt", str(target), "--save-baseline"],
    )
    mock_console = Mock()

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("skylos.debt.save_baseline") as mock_save,
        patch("skylos.cli.Console", return_value=mock_console),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 1
    mock_save.assert_not_called()
    message = mock_console.print.call_args.args[0]
    assert "--save-baseline only supports project-root scans" in message


def test_cli_debt_history_requires_project_root_scan(tmp_path, monkeypatch):
    project = tmp_path / "repo"
    target = project / "src"
    target.mkdir(parents=True)
    snapshot = _snapshot(str(project))
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "debt", str(target), "--history"],
    )
    mock_console = Mock()

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("skylos.debt.append_history") as mock_history,
        patch("skylos.cli.Console", return_value=mock_console),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 1
    mock_history.assert_not_called()
    message = mock_console.print.call_args.args[0]
    assert "--history only supports project-root scans" in message
