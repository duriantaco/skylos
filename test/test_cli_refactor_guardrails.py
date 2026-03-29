import json
import sys
import types
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

import skylos.cli as cli
from skylos.debt.result import DebtHotspot, DebtScore, DebtSnapshot


def _debt_snapshot(project: Path, *, hotspot_scope: str = "project") -> DebtSnapshot:
    hotspot = DebtHotspot(
        fingerprint="hotspot:app/services.py",
        file="app/services.py",
        score=27.87,
        priority_score=38.87,
        signal_count=2,
        dimension_count=2,
        primary_dimension="complexity",
        baseline_status="worsened",
    )
    score = DebtScore(
        total_points=27.87,
        normalizer=4.0,
        score_pct=68,
        risk_rating="MEDIUM",
        hotspot_count=2,
        signal_count=3,
        scope="project",
    )
    return DebtSnapshot(
        version="1.0",
        timestamp="2026-03-28T00:00:00+00:00",
        project=str(project),
        files_scanned=4,
        total_loc=120,
        score=score,
        hotspots=[hotspot],
        all_hotspots=[hotspot],
        summary={
            "scope": {"score": "project", "hotspots": hotspot_scope},
            "project_hotspot_count": 2,
            "visible_hotspot_count": 1 if hotspot_scope == "changed" else 2,
            "changed_files": ["app/services.py", "web/app.js"]
            if hotspot_scope == "changed"
            else [],
        },
    )


def _progress_ctx():
    cm = Mock()
    cm.__enter__ = Mock(return_value=Mock(add_task=Mock(return_value="t")))
    cm.__exit__ = Mock(return_value=False)
    return cm


def test_cli_guardrail_commands_dispatch_exits_zero(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["skylos", "commands"])

    with (
        patch("skylos.help.print_flat_commands") as mock_commands,
        patch("skylos.cli.Console", return_value=Mock()),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_commands.assert_called_once()


def test_cli_guardrail_tour_dispatch_exits_zero(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["skylos", "tour"])

    with (
        patch("skylos.tour.run_tour") as mock_tour,
        patch("skylos.cli.Console", return_value=Mock()),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_tour.assert_called_once()


def test_cli_guardrail_badge_dispatch_exits_zero(monkeypatch):
    console = Mock()
    fake_pyperclip = types.SimpleNamespace(copy=Mock())
    monkeypatch.setattr(sys, "argv", ["skylos", "badge"])

    with (
        patch("skylos.commands.badge_cmd.Console", return_value=console),
        patch.dict(sys.modules, {"pyperclip": fake_pyperclip}),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    fake_pyperclip.copy.assert_called_once()


def test_cli_guardrail_credits_dispatch_exits_zero(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["skylos", "credits"])

    with (
        patch("skylos.commands.credits_cmd.run_credits_command", return_value=0) as mock_credits,
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_credits.assert_called_once_with()


def test_cli_guardrail_doctor_dispatch_exits_zero(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["skylos", "doctor"])

    with (
        patch("skylos.commands.doctor_cmd.run_doctor_command", return_value=0) as mock_doctor,
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_doctor.assert_called_once_with()


def test_cli_guardrail_init_dispatch_exits_zero(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["skylos", "init"])

    with (
        patch("skylos.commands.init_cmd.run_init_command", return_value=0) as mock_init,
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_init.assert_called_once_with()


def test_cli_guardrail_whitelist_dispatch_preserves_argv(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "whitelist", "handle_*", "--reason", "Called via getattr"],
    )

    with (
        patch(
            "skylos.commands.whitelist_cmd.run_whitelist_command", return_value=0
        ) as mock_whitelist,
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_whitelist.assert_called_once_with(
        ["handle_*", "--reason", "Called via getattr"]
    )


def test_whitelist_command_parser_preserves_reason_and_show_flags():
    with patch("skylos.commands.whitelist_cmd.run_whitelist") as mock_whitelist:
        from skylos.commands.whitelist_cmd import run_whitelist_command

        exit_code = run_whitelist_command(
            ["handle_*", "--reason", "Called via getattr", "--show"]
        )

    assert exit_code == 0
    mock_whitelist.assert_called_once_with(
        pattern="handle_*", reason="Called via getattr", show=True
    )


def test_cli_guardrail_clean_dispatch_preserves_argv(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["skylos", "clean", "pkg"])

    with (
        patch("skylos.commands.clean_cmd.run_clean_command", return_value=0) as mock_clean,
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_clean.assert_called_once_with(["pkg"])


def test_cli_guardrail_whoami_dispatch_exits_zero(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["skylos", "whoami"])

    with (
        patch("skylos.commands.whoami_cmd.run_whoami_command", return_value=0) as mock_whoami,
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_whoami.assert_called_once_with()


def test_cli_guardrail_login_dispatch_exits_zero(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["skylos", "login"])

    with (
        patch("skylos.commands.login_cmd.run_login_command", return_value=0) as mock_login,
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_login.assert_called_once_with()


def test_cli_guardrail_sync_dispatch_preserves_argv(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["skylos", "sync", "status"])

    with (
        patch("skylos.commands.sync_cmd.run_sync_command", return_value=0) as mock_sync,
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_sync.assert_called_once_with(["status"])


def test_cli_guardrail_city_dispatch_preserves_argv(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "city", "repo", "--json", "--quality", "--confidence", "75"],
    )

    with (
        patch("skylos.commands.city_cmd.run_city_command", return_value=0) as mock_city,
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_city.assert_called_once_with(["repo", "--json", "--quality", "--confidence", "75"])


def test_cli_guardrail_discover_dispatch_preserves_argv(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "discover", "repo", "--json", "--exclude", "venv"],
    )

    with (
        patch(
            "skylos.commands.discover_cmd.run_discover_command", return_value=0
        ) as mock_discover,
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_discover.assert_called_once_with(["repo", "--json", "--exclude", "venv"])


def test_cli_guardrail_defend_dispatch_preserves_argv(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "defend", "repo", "--json", "--fail-on", "high"],
    )

    with (
        patch("skylos.cli.run_defend_command", return_value=0) as mock_defend,
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_defend.assert_called_once_with(["repo", "--json", "--fail-on", "high"])


def test_cli_guardrail_ingest_dispatch_preserves_argv(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "ingest", "claude-security", "--input", "scan.json", "--json"],
    )

    with (
        patch("skylos.cli.run_ingest_command", return_value=0) as mock_ingest,
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_ingest.assert_called_once_with(
        ["claude-security", "--input", "scan.json", "--json"]
    )


def test_cli_guardrail_debt_dispatch_preserves_argv(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "debt", "repo", "--changed", "--json"],
    )

    with (
        patch("skylos.cli.run_debt_command", return_value=0) as mock_debt,
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_debt.assert_called_once_with(["repo", "--changed", "--json"])


def test_cli_guardrail_provenance_dispatch_preserves_argv(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "provenance", "repo", "--json", "--diff-base", "origin/main"],
    )

    with (
        patch("skylos.cli.run_provenance_command", return_value=0) as mock_provenance,
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_provenance.assert_called_once_with(
        ["repo", "--json", "--diff-base", "origin/main"]
    )


def test_cli_guardrail_cicd_dispatch_preserves_argv(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "cicd", "gate", "--input", "results.json", "--strict"],
    )

    with (
        patch("skylos.cli.run_cicd_command", return_value=0) as mock_cicd,
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_cicd.assert_called_once_with(["gate", "--input", "results.json", "--strict"])


def test_cli_guardrail_baseline_subcommand_writes_baseline(tmp_path, monkeypatch):
    target = tmp_path / "repo"
    target.mkdir()
    baseline_path = target / ".skylos" / "baseline.json"
    result = {
        "unused_functions": [{"name": "legacy_worker"}],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }
    console = Mock()
    monkeypatch.setattr(sys, "argv", ["skylos", "baseline", str(target)])

    with (
        patch(
            "skylos.commands.baseline_cmd.run_analyze",
            return_value=json.dumps(result),
        ) as mock_analyze,
        patch(
            "skylos.commands.baseline_cmd.save_baseline",
            return_value=baseline_path,
        ) as mock_save,
        patch("skylos.commands.baseline_cmd.Console", return_value=console),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_analyze.assert_called_once_with(str(target))
    mock_save.assert_called_once()


def test_baseline_command_defaults_to_current_directory():
    result = {
        "unused_functions": [],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }

    with (
        patch(
            "skylos.commands.baseline_cmd.run_analyze",
            return_value=json.dumps(result),
        ) as mock_analyze,
        patch(
            "skylos.commands.baseline_cmd.save_baseline",
            return_value=Path(".skylos/baseline.json"),
        ),
        patch("skylos.commands.baseline_cmd.Console", return_value=Mock()),
    ):
        from skylos.commands.baseline_cmd import run_baseline_command

        exit_code = run_baseline_command([])

    assert exit_code == 0
    mock_analyze.assert_called_once_with(".")


def test_doctor_command_reports_core_statuses(tmp_path):
    repo = tmp_path / "repo"
    workflow = repo / ".github" / "workflows"
    workflow.mkdir(parents=True)
    (repo / "pyproject.toml").write_text("[tool.skylos]\nexclude=['venv']\n", encoding="utf-8")
    (workflow / "skylos.yml").write_text("name: skylos\n", encoding="utf-8")

    home = tmp_path / "home"
    rules = home / ".skylos" / "rules"
    rules.mkdir(parents=True)
    (rules / "community.yml").write_text("rules: []\n", encoding="utf-8")

    console = Mock()

    with (
        patch("skylos.commands.doctor_cmd.Console", return_value=console),
        patch("skylos.commands.doctor_cmd.platform.python_version", return_value="3.12.1"),
        patch("skylos.commands.doctor_cmd._rust_available", return_value=True),
        patch("skylos.commands.doctor_cmd._llm_available", return_value=True),
        patch("skylos.commands.doctor_cmd._interactive_available", return_value=True),
        patch("skylos.commands.doctor_cmd.load_config", return_value={"exclude": ["venv"]}),
        patch("skylos.commands.doctor_cmd.Path.cwd", return_value=repo),
        patch("skylos.commands.doctor_cmd.Path.home", return_value=home),
        patch("skylos.api.get_project_token", return_value="tok"),
        patch("skylos.api.get_credit_balance", return_value={"plan": "free", "balance": 5}),
    ):
        from skylos.commands.doctor_cmd import run_doctor_command

        exit_code = run_doctor_command()

    assert exit_code == 0
    printed = " ".join(str(call.args[0]) for call in console.print.call_args_list if call.args)
    assert "Python 3.12.1" in printed
    assert "Skylos 4.1.4" in printed
    assert "Cloud connected" in printed
    assert "pyproject.toml [tool.skylos] config found" in printed
    assert "GitHub Actions workflow found" in printed
    assert "community rule pack(s) installed" in printed


def test_city_command_json_output_prints_topology(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    topology = {"buildings": [{"name": "sample.py"}]}

    with (
        patch("skylos.commands.city_cmd.Console", return_value=Mock()),
        patch("skylos.commands.city_cmd.Progress", return_value=_progress_ctx()),
        patch("skylos.commands.city_cmd.load_config", return_value={"exclude": ["venv"]}),
        patch("skylos.commands.city_cmd.run_analyze", return_value=json.dumps({"unused_functions": []})) as mock_analyze,
        patch("skylos.city.generate_topology", return_value=topology),
        patch("builtins.print") as mock_print,
    ):
        from skylos.commands.city_cmd import run_city_command

        exit_code = run_city_command([str(target), "--json"])

    assert exit_code == 0
    mock_analyze.assert_called_once()
    assert mock_print.call_args.args[0] == json.dumps(topology, indent=2)


def test_discover_command_json_output_prints_report(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    payload = '{"integrations": []}'

    with (
        patch("skylos.commands.discover_cmd.Console", return_value=Mock()),
        patch("skylos.commands.discover_cmd.Progress", return_value=_progress_ctx()),
        patch("skylos.discover.detector._collect_python_files", return_value=[target / "app.py"]) as mock_collect,
        patch("skylos.discover.detector.detect_integrations", return_value=([], {})) as mock_detect,
        patch("skylos.discover.report.format_json", return_value=payload),
        patch("builtins.print") as mock_print,
    ):
        from skylos.commands.discover_cmd import run_discover_command

        exit_code = run_discover_command([str(target), "--json"])

    assert exit_code == 0
    mock_collect.assert_called_once()
    mock_detect.assert_called_once()
    mock_print.assert_called_once_with(payload)


def test_defend_command_json_output_prints_empty_report(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    console = Mock()

    with (
        patch("skylos.defend.policy.load_policy", return_value=None),
        patch(
            "skylos.discover.detector._collect_python_files",
            return_value=[target / "app.py"],
        ) as mock_collect,
        patch(
            "skylos.discover.detector.detect_integrations",
            return_value=([], {}),
        ) as mock_detect,
        patch("builtins.print") as mock_print,
    ):
        from skylos.commands.defend_cmd import run_defend_command

        exit_code = run_defend_command(
            [str(target), "--json"],
            console_factory=lambda: console,
            progress_factory=lambda *args, **kwargs: _progress_ctx(),
        )

    assert exit_code == 0
    mock_collect.assert_called_once()
    mock_detect.assert_called_once()
    payload = json.loads(mock_print.call_args.args[0])
    assert payload["summary"]["integrations_found"] == 0
    assert payload["summary"]["score_pct"] == 100
    assert payload["ops_score"]["rating"] == "EXCELLENT"


def test_ingest_command_json_output_prints_normalized_result():
    console = Mock()
    result = {"success": True, "result": {"danger": []}, "findings_count": 0}

    with (
        patch("skylos.ingest.ingest_claude_security", return_value=result) as mock_ingest,
        patch("builtins.print") as mock_print,
    ):
        from skylos.commands.ingest_cmd import run_ingest_command

        exit_code = run_ingest_command(
            ["claude-security", "--input", "scan.json", "--json", "--no-upload"],
            console_factory=lambda: console,
        )

    assert exit_code == 0
    mock_ingest.assert_called_once_with(
        "scan.json",
        upload=False,
        token=None,
        cross_reference_path=None,
    )
    assert json.loads(mock_print.call_args.args[0]) == {"danger": []}
    console.print.assert_called_once_with("[green]Ingested 0 findings[/green]")


def test_provenance_command_json_output_prints_report(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    report = Mock()
    report.to_dict.return_value = {"summary": {"total_files": 0}, "agent_files": []}

    with (
        patch("skylos.provenance.analyze_provenance", return_value=report) as mock_analyze,
        patch("builtins.print") as mock_print,
    ):
        from skylos.commands.provenance_cmd import run_provenance_command

        exit_code = run_provenance_command(
            [str(target), "--json"],
            console_factory=lambda: Mock(),
            progress_factory=lambda *args, **kwargs: _progress_ctx(),
            get_git_root_func=lambda: None,
        )

    assert exit_code == 0
    mock_analyze.assert_called_once_with(str(target.resolve()), base_ref=None)
    assert json.loads(mock_print.call_args.args[0])["summary"]["total_files"] == 0


def test_cicd_gate_command_reads_input_and_returns_gate_exit(tmp_path):
    results_path = tmp_path / "results.json"
    results_path.write_text(json.dumps({"project_root": str(tmp_path), "danger": []}))
    from skylos.commands.cicd_cmd import run_cicd_command
    mock_gate = Mock(return_value=0)

    exit_code = run_cicd_command(
        ["gate", "--input", str(results_path), "--strict"],
        console_factory=lambda: Mock(),
        load_config_func=lambda path: {},
        run_gate_interaction_func=mock_gate,
        emit_github_annotations_func=Mock(),
    )

    assert exit_code == 0
    assert mock_gate.call_args.kwargs["strict"] is True
    assert mock_gate.call_args.kwargs["result"]["project_root"] == str(tmp_path)


def test_cli_guardrail_static_json_output_passthrough(monkeypatch):
    result = {
        "unused_functions": [{"name": "unused_func", "file": "test.py", "line": 10}],
        "unused_imports": [],
        "unused_parameters": [],
        "unused_variables": [],
        "unused_classes": [],
        "analysis_summary": {"total_files": 1, "excluded_folders": []},
    }
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "test_path", "--json", "--no-provenance"],
    )

    with (
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)) as mock_analyze,
        patch("skylos.cli.setup_logger"),
        patch("skylos.cli.Progress") as mock_progress,
        patch("builtins.print") as mock_print,
    ):
        mock_progress.return_value.__enter__.return_value = Mock(add_task=Mock())
        cli.main()

    mock_analyze.assert_called_once()
    mock_print.assert_called_once_with(json.dumps(result))


def test_cli_guardrail_debt_changed_json_keeps_project_scope(tmp_path, monkeypatch):
    snapshot = _debt_snapshot(tmp_path, hotspot_scope="changed")
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "debt", str(tmp_path), "--changed", "--json"],
    )

    with (
        patch("skylos.cli.get_git_changed_files", return_value=[tmp_path / "app/services.py"]),
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("skylos.debt.load_policy", return_value=None),
        patch("skylos.cli.Console", return_value=Mock()),
        patch("builtins.print") as mock_print,
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    payload = json.loads(mock_print.call_args.args[0])
    assert payload["score"]["scope"] == "project"
    assert payload["summary"]["scope"]["score"] == "project"
    assert payload["summary"]["scope"]["hotspots"] == "changed"
    assert payload["hotspots"][0]["priority_score"] == 38.87


def test_cli_guardrail_debt_subdir_save_baseline_rejected(tmp_path, monkeypatch):
    project = tmp_path / "repo"
    target = project / "src"
    target.mkdir(parents=True)
    snapshot = _debt_snapshot(project)
    console = Mock()
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "debt", str(target), "--save-baseline"],
    )

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("skylos.debt.load_policy", return_value=None),
        patch("skylos.debt.save_baseline") as mock_save,
        patch("skylos.cli.Console", return_value=console),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 1
    mock_save.assert_not_called()
    assert "--save-baseline only supports project-root scans" in console.print.call_args.args[0]


def test_cli_guardrail_debt_top_flag_overrides_policy(tmp_path, monkeypatch):
    snapshot = _debt_snapshot(tmp_path)
    policy = Mock(report_top=1, gate_min_score=None, gate_fail_on_status=None)
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "debt", str(tmp_path), "--top", "2"],
    )

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("skylos.debt.load_policy", return_value=policy),
        patch("skylos.debt.format_debt_table", return_value="ok") as mock_table,
        patch("skylos.cli.Console", return_value=Mock()),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    assert mock_table.call_args.kwargs["top"] == 2
