import io
import json
from unittest.mock import patch

from rich.console import Console
from rich.progress import Progress

from skylos.commands.suite_cmd import run_suite_command


def _console_factory():
    return Console(file=io.StringIO(), force_terminal=False, color_system=None)


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
