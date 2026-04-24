import io
import json
from unittest.mock import patch

from rich.console import Console
from rich.progress import Progress

from skylos.commands.suite_cmd import run_suite_command


def _console_factory():
    return Console(file=io.StringIO(), force_terminal=False, color_system=None)


def _noop_upload(*_args, **_kwargs):
    return {"success": True}


def _static_result(project_root: str) -> dict:
    return {
        "analysis_summary": {"total_files": 3, "total_loc": 120},
        "danger": [
            {
                "rule_id": "SKY-D201",
                "severity": "HIGH",
                "file": f"{project_root}/app.py",
                "line": 8,
                "message": "SQL injection",
            }
        ],
        "quality": [
            {
                "rule_id": "SKY-Q301",
                "severity": "HIGH",
                "file": f"{project_root}/app.py",
                "line": 12,
                "name": "handler",
                "message": "Cyclomatic complexity is 12 (threshold: 10)",
                "value": 12,
                "threshold": 10,
            }
        ],
        "secrets": [
            {
                "file": f"{project_root}/settings.py",
                "line": 2,
                "provider": "generic",
                "message": "Hardcoded secret",
            }
        ],
        "unused_functions": [
            {
                "name": "legacy",
                "file": f"{project_root}/legacy.py",
                "line": 3,
                "confidence": 92,
            }
        ],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
        "unused_parameters": [],
    }


def test_suite_json_outputs_combined_sections(tmp_path, capsys):
    static_result = _static_result(str(tmp_path))

    with (
        patch(
            "skylos.defend.policy.load_policy",
            return_value=None,
        ),
        patch(
            "skylos.rules.sca.vulnerability_scanner.scan_dependencies",
            return_value=[],
        ),
    ):
        exit_code = run_suite_command(
            [str(tmp_path), "--json", "--no-provenance"],
            console_factory=_console_factory,
            progress_factory=Progress,
            parse_exclude_folders_func=lambda **kwargs: [],
            load_config_func=lambda _path: {},
            run_analyze_func=lambda *_args, **_kwargs: json.dumps(static_result),
            get_git_root_func=lambda: None,
            upload_report_func=_noop_upload,
            upload_defense_report_func=_noop_upload,
            upload_debt_report_func=_noop_upload,
        )

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["summary"]["static"]["dead_code"] == 1
    assert payload["summary"]["static"]["security"] == 1
    assert payload["summary"]["static"]["quality"] == 1
    assert payload["summary"]["static"]["secrets"] == 1
    assert payload["debt"]["score"]["hotspot_count"] == len(payload["debt"]["hotspots"])
    assert payload["defense"]["summary"]["integrations_found"] == 0
    assert payload["provenance"]["enabled"] is False
    assert (
        payload["defense"]["note"]
        == "AI defense currently scans Python direct SDK integrations only."
    )


def test_suite_rejects_file_paths(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("print('hi')\n", encoding="utf-8")

    exit_code = run_suite_command(
        [str(target)],
        console_factory=_console_factory,
        progress_factory=Progress,
        parse_exclude_folders_func=lambda **kwargs: [],
        load_config_func=lambda _path: {},
        run_analyze_func=lambda *_args, **_kwargs: "{}",
        get_git_root_func=lambda: None,
        upload_report_func=_noop_upload,
        upload_defense_report_func=_noop_upload,
        upload_debt_report_func=_noop_upload,
    )

    assert exit_code == 1


def test_main_suite_subcommand_calls_run_suite_and_exits(monkeypatch):
    import skylos.cli as cli

    monkeypatch.setattr(cli.sys, "argv", ["skylos", "suite", "."])
    with patch("skylos.commands.suite_cmd.run_suite_command", return_value=0) as runner:
        try:
            cli.main()
        except SystemExit as exc:
            assert exc.code == 0
        else:
            raise AssertionError("Expected SystemExit")

    runner.assert_called_once()
    assert runner.call_args.args == (["."],)
    assert runner.call_args.kwargs["console_factory"] is cli.Console
    assert runner.call_args.kwargs["progress_factory"] is cli.Progress
    assert (
        runner.call_args.kwargs["parse_exclude_folders_func"]
        is cli.parse_exclude_folders
    )
    assert runner.call_args.kwargs["load_config_func"] is cli.load_config
    assert runner.call_args.kwargs["run_analyze_func"] is cli.run_analyze
    assert callable(runner.call_args.kwargs["get_git_root_func"])
    assert callable(runner.call_args.kwargs["upload_report_func"])
    assert callable(runner.call_args.kwargs["upload_defense_report_func"])
    assert callable(runner.call_args.kwargs["upload_debt_report_func"])


def test_suite_json_upload_passes_quiet_and_selected_categories(tmp_path, capsys):
    static_result = _static_result(str(tmp_path))
    static_upload = patch(
        "skylos.commands.suite_cmd.run_suite",
        return_value={
            "static": static_result,
            "debt": {
                "score": {"score_pct": 82, "signal_count": 4},
                "hotspots": [{"file": "app.py"}],
                "summary": {},
            },
            "defense": {"summary": {"score_pct": 100}},
            "provenance": {"enabled": False},
            "summary": {
                "static": {
                    "dead_code": 1,
                    "security": 1,
                    "quality": 1,
                    "secrets": 1,
                }
            },
        },
    )

    with (
        static_upload,
        patch("skylos.commands.suite_cmd.format_suite_json", return_value='{"ok":true}'),
    ):
        uploaded = {}

        def _upload_static(payload, **kwargs):
            uploaded["static_payload"] = payload
            uploaded["static_kwargs"] = kwargs
            return {"success": True}

        def _upload_defense(payload, **kwargs):
            uploaded["defense_payload"] = payload
            uploaded["defense_kwargs"] = kwargs
            return {"success": True}

        def _upload_debt(payload, **kwargs):
            uploaded["debt_payload"] = payload
            uploaded["debt_kwargs"] = kwargs
            return {"success": True}

        exit_code = run_suite_command(
            [
                str(tmp_path),
                "--json",
                "--upload",
                "--families",
                "static,debt",
                "--static-categories",
                "quality,dead_code",
            ],
            console_factory=_console_factory,
            progress_factory=Progress,
            parse_exclude_folders_func=lambda **kwargs: [],
            load_config_func=lambda _path: {},
            run_analyze_func=lambda *_args, **_kwargs: json.dumps(static_result),
            get_git_root_func=lambda: None,
            upload_report_func=_upload_static,
            upload_defense_report_func=_upload_defense,
            upload_debt_report_func=_upload_debt,
        )

    assert exit_code == 0
    assert capsys.readouterr().out.strip() == '{"ok":true}'
    assert uploaded["static_kwargs"]["quiet"] is True
    assert uploaded["debt_kwargs"]["quiet"] is True
    assert uploaded["static_kwargs"]["scan_bundle_id"]
    assert uploaded["debt_kwargs"]["scan_bundle_id"]
    assert (
        uploaded["static_kwargs"]["scan_bundle_id"]
        == uploaded["debt_kwargs"]["scan_bundle_id"]
    )
    assert "defense_payload" not in uploaded
    assert "danger" not in uploaded["static_payload"]
    assert "quality" in uploaded["static_payload"]
    assert "unused_functions" in uploaded["static_payload"]


def test_suite_upload_exits_nonzero_when_static_quality_gate_fails(tmp_path):
    static_result = _static_result(str(tmp_path))

    with (
        patch(
            "skylos.commands.suite_cmd.run_suite",
            return_value={
                "static": static_result,
                "debt": {"score": {}, "hotspots": [], "summary": {}},
                "defense": {"summary": {"score_pct": 100}},
                "provenance": {"enabled": False},
                "summary": {"static": {}},
            },
        ),
        patch("skylos.commands.suite_cmd.format_suite_table", return_value="suite"),
    ):
        exit_code = run_suite_command(
            [str(tmp_path), "--upload", "--families", "static"],
            console_factory=_console_factory,
            progress_factory=Progress,
            parse_exclude_folders_func=lambda **kwargs: [],
            load_config_func=lambda _path: {},
            run_analyze_func=lambda *_args, **_kwargs: json.dumps(static_result),
            get_git_root_func=lambda: None,
            upload_report_func=lambda *_args, **_kwargs: {
                "success": True,
                "quality_gate_passed": False,
            },
            upload_defense_report_func=_noop_upload,
            upload_debt_report_func=_noop_upload,
        )

    assert exit_code == 1
