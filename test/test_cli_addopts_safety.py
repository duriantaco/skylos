from skylos.cli_core.main_parser import build_main_parser, parse_main_cli_args
from skylos.core.cli_shared import load_addopts, sanitize_addopts


def test_load_addopts_rejects_pyproject_command_injection(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.skylos]
addopts = [".", "--", "sh", "-c", "touch SHOULD_NOT_RUN"]
""",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    assert load_addopts() == []


def test_sanitize_addopts_keeps_safe_scan_options_only():
    assert sanitize_addopts(
        [
            "--json",
            "--confidence",
            "80",
            "--severity=high",
            "--exclude-folder",
            "vendor",
            "--trace",
            "--coverage",
            "--allow-coverage-execution",
            "--pytest-fixtures",
            "--upload",
            "--force",
            "-f",
            "--output",
            "/tmp/report.json",
        ]
    ) == [
        "--json",
        "--confidence",
        "80",
        "--severity=high",
        "--exclude-folder",
        "vendor",
    ]


def test_parse_main_cli_args_never_gets_command_from_addopts():
    parser = build_main_parser(version="test")

    args = parse_main_cli_args(
        parser,
        ["."],
        addopts_loader=lambda: ["--json", "--", "sh", "-c", "id"],
    )

    assert args.json is True
    assert args.path == ["."]
    assert args.command == []


def test_parse_main_cli_args_still_accepts_user_command_separator():
    parser = build_main_parser(version="test")

    args = parse_main_cli_args(
        parser,
        [".", "--", "echo", "ok"],
        addopts_loader=lambda: ["--json"],
    )

    assert args.json is True
    assert args.path == ["."]
    assert args.command == ["echo", "ok"]
