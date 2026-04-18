import json
from unittest.mock import Mock, patch

import pytest

import skylos.cli as cli


def test_agent_pre_commit_scans_only_staged_source_files(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (repo / "notes.txt").write_text("hello\n", encoding="utf-8")

    console = Mock()
    staged = Mock(stdout="app.py\nnotes.txt\n", returncode=0)
    unstaged = Mock(stdout="", returncode=0)
    result = {
        "unused_functions": [],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
        "danger": [
            {
                "rule_id": "SKY-D201",
                "file": "app.py",
                "line": 3,
                "severity": "HIGH",
                "message": "SQL injection",
            },
            {
                "rule_id": "SKY-D202",
                "file": "other.py",
                "line": 9,
                "severity": "HIGH",
                "message": "Command injection",
            },
        ],
        "quality": [],
        "secrets": [],
    }

    with (
        patch("sys.argv", ["skylos", "agent", "pre-commit", str(repo)]),
        patch("skylos.cli.Console", return_value=console),
        patch("skylos.cli.setup_logger"),
        patch("skylos.cli.find_project_root", return_value=repo),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.parse_exclude_folders", return_value=set()),
        patch("skylos.cli.subprocess.run", side_effect=[staged, unstaged]),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)) as mock_analyze,
        patch("skylos.baseline.load_baseline", return_value=None),
    ):
        with pytest.raises(SystemExit) as exc_info:
            cli.main()

    assert exc_info.value.code == 1
    assert mock_analyze.call_args.kwargs["changed_files"] == {
        str((repo / "app.py").resolve())
    }
    assert mock_analyze.call_args.kwargs["grep_verify"] is False

    printed = " ".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    assert "Commit check:" in printed
    assert "Checks security, secrets, and quality only." in printed
    assert "app.py:3" in printed
    assert "other.py" not in printed
    assert "issue(s) found in staged files" in printed
    assert "Full repo and diff-aware enforcement run in CI." in printed
    assert "fix the issues below and commit again" in printed


def test_agent_pre_commit_includes_staged_config_files(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("SAFE_VALUE=1\n", encoding="utf-8")

    console = Mock()
    staged = Mock(stdout=".env\n", returncode=0)
    staged_blob = Mock(stdout="API_KEY=test\n", returncode=0)
    seen_ctx = {}

    def fake_scan_ctx(ctx):
        seen_ctx["lines"] = list(ctx["lines"])
        return []

    with (
        patch("sys.argv", ["skylos", "agent", "pre-commit", str(repo)]),
        patch("skylos.cli.Console", return_value=console),
        patch("skylos.cli.setup_logger"),
        patch("skylos.cli.find_project_root", return_value=repo),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.parse_exclude_folders", return_value=set()),
        patch("skylos.cli.subprocess.run", side_effect=[staged, staged_blob]),
        patch("skylos.cli.run_analyze") as mock_analyze,
        patch("skylos.rules.secrets.scan_ctx", side_effect=fake_scan_ctx),
        patch("skylos.baseline.load_baseline", return_value=None),
    ):
        with pytest.raises(SystemExit) as exc_info:
            cli.main()

    assert exc_info.value.code == 0
    mock_analyze.assert_not_called()
    assert "".join(seen_ctx["lines"]) == "API_KEY=test\n"

    printed = " ".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    assert "reviewing 1 config staged file(s)" in printed
    assert "Config-only change detected: running secrets check only." in printed
    assert "No staged security, secrets, or quality issues" in printed


def test_agent_pre_commit_uses_staged_snapshot_for_untracked_source_changes(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('working tree')\n", encoding="utf-8")
    (repo / "other.py").write_text("print('other')\n", encoding="utf-8")

    snapshot_root = tmp_path / "snapshot"
    console = Mock()
    staged = Mock(stdout="app.py\n", returncode=0)
    dirty_status = Mock(stdout="?? other.py\n", returncode=0)
    checkout = Mock(stdout="", returncode=0)
    result = {
        "unused_functions": [],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
        "danger": [
            {
                "rule_id": "SKY-D201",
                "file": str((snapshot_root / "app.py").resolve()),
                "line": 3,
                "severity": "HIGH",
                "message": "SQL injection",
            }
        ],
        "quality": [],
        "secrets": [],
    }

    class FakeTempDir:
        def __init__(self, path):
            self.name = str(path)

        def cleanup(self):
            pass

    def fake_run(cmd, **kwargs):
        if cmd == ["git", "diff", "--cached", "--name-only"]:
            return staged
        if cmd == ["git", "status", "--porcelain", "--untracked-files=all"]:
            return dirty_status
        if cmd[:4] == ["git", "checkout-index", "--all", "--force"]:
            snapshot_root.mkdir()
            (snapshot_root / "app.py").write_text(
                "print('staged snapshot')\n", encoding="utf-8"
            )
            (snapshot_root / "other.py").write_text(
                "print('snapshot other')\n", encoding="utf-8"
            )
            return checkout
        raise AssertionError(f"Unexpected command: {cmd}")

    with (
        patch("sys.argv", ["skylos", "agent", "pre-commit", str(repo)]),
        patch("skylos.cli.Console", return_value=console),
        patch("skylos.cli.setup_logger"),
        patch("skylos.cli.find_project_root", return_value=repo),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.parse_exclude_folders", return_value=set()),
        patch("skylos.cli.tempfile.TemporaryDirectory", return_value=FakeTempDir(snapshot_root)),
        patch("skylos.cli.subprocess.run", side_effect=fake_run),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)) as mock_analyze,
        patch("skylos.baseline.load_baseline", return_value=None),
    ):
        with pytest.raises(SystemExit) as exc_info:
            cli.main()

    assert exc_info.value.code == 1
    assert mock_analyze.call_args.args[0] == str(snapshot_root)
    assert mock_analyze.call_args.kwargs["changed_files"] == {
        str((snapshot_root / "app.py").resolve())
    }

    printed = " ".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    assert "Using staged git snapshot for exact commit results." in printed
    assert "app.py:3" in printed
    assert str(snapshot_root) not in printed


def test_agent_pre_commit_reports_skipped_unsupported_staged_files(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (repo / "logo.png").write_bytes(b"png")

    console = Mock()
    staged = Mock(stdout="app.py\nlogo.png\n", returncode=0)
    unstaged = Mock(stdout="", returncode=0)
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
        patch("sys.argv", ["skylos", "agent", "pre-commit", str(repo)]),
        patch("skylos.cli.Console", return_value=console),
        patch("skylos.cli.setup_logger"),
        patch("skylos.cli.find_project_root", return_value=repo),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.parse_exclude_folders", return_value=set()),
        patch("skylos.cli.subprocess.run", side_effect=[staged, unstaged]),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.baseline.load_baseline", return_value=None),
    ):
        with pytest.raises(SystemExit) as exc_info:
            cli.main()

    assert exc_info.value.code == 0
    printed = " ".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    assert "Skipped 1 unsupported staged file(s)." in printed


def test_agent_pre_commit_handles_only_unsupported_staged_files(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "notes.md").write_text("# hi\n", encoding="utf-8")

    console = Mock()
    staged = Mock(stdout="notes.md\n", returncode=0)

    with (
        patch("sys.argv", ["skylos", "agent", "pre-commit", str(repo)]),
        patch("skylos.cli.Console", return_value=console),
        patch("skylos.cli.setup_logger"),
        patch("skylos.cli.find_project_root", return_value=repo),
        patch("skylos.cli.subprocess.run", return_value=staged),
    ):
        with pytest.raises(SystemExit) as exc_info:
            cli.main()

    assert exc_info.value.code == 0
    printed = " ".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    assert "No staged source or config files to analyze" in printed
    assert "skipped 1 unsupported staged file(s)" in printed.lower()
