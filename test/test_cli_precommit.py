import json
from pathlib import Path
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
    cached_diff = Mock(
        stdout=(
            "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -3 +3 @@\n"
        ),
        returncode=0,
    )
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

    def fake_run(cmd, **kwargs):
        if cmd == ["git", "diff", "--cached", "--name-only"]:
            return staged
        if cmd[:4] == ["git", "diff", "--cached", "--unified=0"]:
            return cached_diff
        if cmd == ["git", "status", "--porcelain", "--untracked-files=all"]:
            return unstaged
        raise AssertionError(f"Unexpected command: {cmd}")

    with (
        patch("sys.argv", ["skylos", "agent", "pre-commit", str(repo)]),
        patch("skylos.cli.Console", return_value=console),
        patch("skylos.cli.setup_logger"),
        patch("skylos.cli.find_project_root", return_value=repo),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.parse_exclude_folders", return_value=set()),
        patch("skylos.cli.subprocess.run", side_effect=fake_run),
        patch("skylos.core.baseline.load_baseline", return_value=None),
    ):
        with patch("skylos.cli.run_analyze") as mock_analyze:

            def fake_analyze(*args, **kwargs):
                kwargs["progress_callback"](1, 1, Path(repo / "app.py"))
                return json.dumps(result)

            mock_analyze.side_effect = fake_analyze
            with pytest.raises(SystemExit) as exc_info:
                cli.main()

    assert exc_info.value.code == 1
    assert mock_analyze.call_args.args[0] == [str((repo / "app.py").resolve())]
    assert mock_analyze.call_args.kwargs["changed_files"] == {
        str((repo / "app.py").resolve())
    }
    assert mock_analyze.call_args.kwargs["grep_verify"] is False

    printed = " ".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    assert "Commit check:" in printed
    assert (
        "Checks security, secrets, and high-signal quality regressions on production source/config."
        in printed
    )
    assert "Commit check progress:" in printed
    assert "[1/1] app.py" in printed
    assert "app.py:3" in printed
    assert "other.py" not in printed
    assert "issue(s) found in staged files" in printed
    assert "Full repo and diff-aware enforcement run in CI." in printed
    assert "fix the issues below and commit again" in printed
    assert "hook blocked the commit before Git created a new commit" in printed


def test_agent_pre_commit_includes_staged_config_files(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("SAFE_VALUE=1\n", encoding="utf-8")

    console = Mock()
    staged = Mock(stdout=".env\n", returncode=0)
    cached_diff = Mock(
        stdout=("diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n"),
        returncode=0,
    )
    staged_blob = Mock(stdout="API_KEY=test\n", returncode=0)
    seen_ctx = {}

    def fake_scan_ctx(ctx, **kwargs):
        seen_ctx["lines"] = list(ctx["lines"])
        return []

    def fake_run(cmd, **kwargs):
        if cmd == ["git", "diff", "--cached", "--name-only"]:
            return staged
        if cmd[:4] == ["git", "diff", "--cached", "--unified=0"]:
            return cached_diff
        if cmd == ["git", "show", ":.env"]:
            return staged_blob
        raise AssertionError(f"Unexpected command: {cmd}")

    with (
        patch("sys.argv", ["skylos", "agent", "pre-commit", str(repo)]),
        patch("skylos.cli.Console", return_value=console),
        patch("skylos.cli.setup_logger"),
        patch("skylos.cli.find_project_root", return_value=repo),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.parse_exclude_folders", return_value=set()),
        patch("skylos.cli.subprocess.run", side_effect=fake_run),
        patch("skylos.cli.run_analyze") as mock_analyze,
        patch("skylos.rules.secrets.scan_ctx", side_effect=fake_scan_ctx),
        patch("skylos.core.baseline.load_baseline", return_value=None),
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
    assert "Checks secrets only." in printed
    assert "Running secrets check only." in printed
    assert "No staged security, secrets, or quality issues" in printed


def test_agent_pre_commit_uses_staged_snapshot_for_untracked_source_changes(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('working tree')\n", encoding="utf-8")
    (repo / "other.py").write_text("print('other')\n", encoding="utf-8")

    snapshot_root = tmp_path / "snapshot"
    console = Mock()
    staged = Mock(stdout="app.py\n", returncode=0)
    cached_diff = Mock(
        stdout=(
            "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -3 +3 @@\n"
        ),
        returncode=0,
    )
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
        if cmd[:4] == ["git", "diff", "--cached", "--unified=0"]:
            return cached_diff
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
        patch(
            "skylos.cli.tempfile.TemporaryDirectory",
            return_value=FakeTempDir(snapshot_root),
        ),
        patch("skylos.cli.subprocess.run", side_effect=fake_run),
        patch(
            "skylos.cli.run_analyze", return_value=json.dumps(result)
        ) as mock_analyze,
        patch("skylos.core.baseline.load_baseline", return_value=None),
    ):
        with pytest.raises(SystemExit) as exc_info:
            cli.main()

    assert exc_info.value.code == 1
    assert mock_analyze.call_args.args[0] == [str((snapshot_root / "app.py").resolve())]
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
    cached_diff = Mock(
        stdout=(
            "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n"
        ),
        returncode=0,
    )
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

    def fake_run(cmd, **kwargs):
        if cmd == ["git", "diff", "--cached", "--name-only"]:
            return staged
        if cmd[:4] == ["git", "diff", "--cached", "--unified=0"]:
            return cached_diff
        if cmd == ["git", "status", "--porcelain", "--untracked-files=all"]:
            return unstaged
        raise AssertionError(f"Unexpected command: {cmd}")

    with (
        patch("sys.argv", ["skylos", "agent", "pre-commit", str(repo)]),
        patch("skylos.cli.Console", return_value=console),
        patch("skylos.cli.setup_logger"),
        patch("skylos.cli.find_project_root", return_value=repo),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.parse_exclude_folders", return_value=set()),
        patch("skylos.cli.subprocess.run", side_effect=fake_run),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.core.baseline.load_baseline", return_value=None),
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


def test_agent_pre_commit_scans_staged_test_files_for_secrets_only(tmp_path):
    repo = tmp_path / "repo"
    (repo / "test").mkdir(parents=True)
    (repo / "test" / "test_rules.py").write_text(
        "def test_ok():\n    pass\n", encoding="utf-8"
    )

    console = Mock()
    staged = Mock(stdout="test/test_rules.py\n", returncode=0)
    cached_diff = Mock(
        stdout=(
            "diff --git a/test/test_rules.py b/test/test_rules.py\n"
            "--- a/test/test_rules.py\n"
            "+++ b/test/test_rules.py\n"
            "@@ -1 +1 @@\n"
        ),
        returncode=0,
    )
    staged_blob = Mock(stdout="def test_ok():\n    pass\n", returncode=0)
    seen_ignore_tests = []

    def fake_scan_ctx(ctx, *, ignore_tests=True, **kwargs):
        seen_ignore_tests.append(ignore_tests)
        return []

    def fake_run(cmd, **kwargs):
        if cmd == ["git", "diff", "--cached", "--name-only"]:
            return staged
        if cmd[:4] == ["git", "diff", "--cached", "--unified=0"]:
            return cached_diff
        if cmd == ["git", "show", ":test/test_rules.py"]:
            return staged_blob
        raise AssertionError(f"Unexpected command: {cmd}")

    with (
        patch("sys.argv", ["skylos", "agent", "pre-commit", str(repo)]),
        patch("skylos.cli.Console", return_value=console),
        patch("skylos.cli.setup_logger"),
        patch("skylos.cli.find_project_root", return_value=repo),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.parse_exclude_folders", return_value=set()),
        patch("skylos.cli.subprocess.run", side_effect=fake_run),
        patch("skylos.rules.secrets.scan_ctx", side_effect=fake_scan_ctx),
        patch("skylos.core.baseline.load_baseline", return_value=None),
    ):
        with pytest.raises(SystemExit) as exc_info:
            cli.main()

    assert exc_info.value.code == 0
    assert seen_ignore_tests == [False]
    printed = " ".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    assert "reviewing 1 test staged file(s)" in printed
    assert "Checks secrets only." in printed
    assert "Staged test files are secrets-only in local commit checks." in printed
    assert "No staged security, secrets, or quality issues" in printed


def test_agent_pre_commit_scans_staged_benchmark_files_for_secrets_only(tmp_path):
    repo = tmp_path / "repo"
    (repo / "benchmarks/agent_review" / "fixtures").mkdir(parents=True)
    bench_file = repo / "benchmarks/agent_review" / "fixtures" / "demo" / "app.py"
    bench_file.parent.mkdir(parents=True)
    bench_file.write_text("def demo():\n    pass\n", encoding="utf-8")

    console = Mock()
    staged = Mock(
        stdout="benchmarks/agent_review/fixtures/demo/app.py\n",
        returncode=0,
    )
    cached_diff = Mock(
        stdout=(
            "diff --git a/benchmarks/agent_review/fixtures/demo/app.py "
            "b/benchmarks/agent_review/fixtures/demo/app.py\n"
            "--- a/benchmarks/agent_review/fixtures/demo/app.py\n"
            "+++ b/benchmarks/agent_review/fixtures/demo/app.py\n"
            "@@ -1 +1 @@\n"
        ),
        returncode=0,
    )
    staged_blob = Mock(stdout="def demo():\n    pass\n", returncode=0)
    seen_ignore_tests = []

    def fake_scan_ctx(ctx, *, ignore_tests=True, **kwargs):
        seen_ignore_tests.append(ignore_tests)
        return []

    def fake_run(cmd, **kwargs):
        if cmd == ["git", "diff", "--cached", "--name-only"]:
            return staged
        if cmd[:4] == ["git", "diff", "--cached", "--unified=0"]:
            return cached_diff
        if cmd == ["git", "show", ":benchmarks/agent_review/fixtures/demo/app.py"]:
            return staged_blob
        raise AssertionError(f"Unexpected command: {cmd}")

    with (
        patch("sys.argv", ["skylos", "agent", "pre-commit", str(repo)]),
        patch("skylos.cli.Console", return_value=console),
        patch("skylos.cli.setup_logger"),
        patch("skylos.cli.find_project_root", return_value=repo),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.parse_exclude_folders", return_value=set()),
        patch("skylos.cli.subprocess.run", side_effect=fake_run),
        patch("skylos.rules.secrets.scan_ctx", side_effect=fake_scan_ctx),
        patch("skylos.core.baseline.load_baseline", return_value=None),
    ):
        with pytest.raises(SystemExit) as exc_info:
            cli.main()

    assert exc_info.value.code == 0
    assert seen_ignore_tests == [False]
    printed = " ".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    assert "reviewing 1 benchmark staged file(s)" in printed
    assert "Checks secrets only." in printed
    assert "Staged benchmark files are secrets-only in local commit checks." in printed
    assert "No staged security, secrets, or quality issues" in printed


def test_agent_pre_commit_scans_staged_test_files_for_secrets_alongside_source(
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (repo / "test").mkdir()
    (repo / "test" / "test_rules.py").write_text(
        "API_KEY='real-secret'\n",
        encoding="utf-8",
    )

    console = Mock()
    staged = Mock(stdout="app.py\ntest/test_rules.py\n", returncode=0)
    cached_diff = Mock(
        stdout=(
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1 +1 @@\n"
            "diff --git a/test/test_rules.py b/test/test_rules.py\n"
            "--- a/test/test_rules.py\n"
            "+++ b/test/test_rules.py\n"
            "@@ -1 +1 @@\n"
        ),
        returncode=0,
    )
    unstaged = Mock(stdout="", returncode=0)
    staged_blob = Mock(stdout="API_KEY='real-secret'\n", returncode=0)
    result = {
        "unused_functions": [],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }

    def fake_scan_ctx(ctx, *, ignore_tests=True, **kwargs):
        assert ctx["relpath"] == "test/test_rules.py"
        assert ignore_tests is False
        return [
            {
                "rule_id": "SKY-S101",
                "file": "test/test_rules.py",
                "line": 1,
                "severity": "CRITICAL",
                "message": "Potential OpenAI secret detected",
            }
        ]

    def fake_run(cmd, **kwargs):
        if cmd == ["git", "diff", "--cached", "--name-only"]:
            return staged
        if cmd[:4] == ["git", "diff", "--cached", "--unified=0"]:
            return cached_diff
        if cmd == ["git", "status", "--porcelain", "--untracked-files=all"]:
            return unstaged
        if cmd == ["git", "show", ":test/test_rules.py"]:
            return staged_blob
        raise AssertionError(f"Unexpected command: {cmd}")

    with (
        patch("sys.argv", ["skylos", "agent", "pre-commit", str(repo)]),
        patch("skylos.cli.Console", return_value=console),
        patch("skylos.cli.setup_logger"),
        patch("skylos.cli.find_project_root", return_value=repo),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.parse_exclude_folders", return_value=set()),
        patch("skylos.cli.subprocess.run", side_effect=fake_run),
        patch(
            "skylos.cli.run_analyze", return_value=json.dumps(result)
        ) as mock_analyze,
        patch("skylos.rules.secrets.scan_ctx", side_effect=fake_scan_ctx),
        patch("skylos.core.baseline.load_baseline", return_value=None),
    ):
        with pytest.raises(SystemExit) as exc_info:
            cli.main()

    assert exc_info.value.code == 1
    assert mock_analyze.call_args.args[0] == [str((repo / "app.py").resolve())]
    printed = " ".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    assert "Potential OpenAI secret detected" in printed
    assert "test/test_rules.py:1" in printed
    assert "Staged test files are secrets-only in local commit checks." in printed


def test_agent_pre_commit_filters_non_regression_findings_to_changed_lines(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")

    console = Mock()
    staged = Mock(stdout="app.py\n", returncode=0)
    cached_diff = Mock(
        stdout=(
            "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -3 +3 @@\n"
        ),
        returncode=0,
    )
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
            }
        ],
        "quality": [
            {
                "rule_id": "SKY-Q001",
                "file": "app.py",
                "line": 40,
                "severity": "HIGH",
                "message": "Old whole-file noise",
            },
            {
                "rule_id": "SKY-L021",
                "file": "app.py",
                "line": 80,
                "severity": "HIGH",
                "message": "Security control regression: TLS verification downgraded from verify=True to verify=False",
            },
        ],
        "secrets": [],
    }

    def fake_run(cmd, **kwargs):
        if cmd == ["git", "diff", "--cached", "--name-only"]:
            return staged
        if cmd[:4] == ["git", "diff", "--cached", "--unified=0"]:
            return cached_diff
        if cmd == ["git", "status", "--porcelain", "--untracked-files=all"]:
            return unstaged
        raise AssertionError(f"Unexpected command: {cmd}")

    with (
        patch("sys.argv", ["skylos", "agent", "pre-commit", str(repo)]),
        patch("skylos.cli.Console", return_value=console),
        patch("skylos.cli.setup_logger"),
        patch("skylos.cli.find_project_root", return_value=repo),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.parse_exclude_folders", return_value=set()),
        patch("skylos.cli.subprocess.run", side_effect=fake_run),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.core.baseline.load_baseline", return_value=None),
    ):
        with pytest.raises(SystemExit) as exc_info:
            cli.main()

    assert exc_info.value.code == 1
    printed = " ".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    assert "app.py:3" in printed
    assert "TLS verification downgraded" in printed
    assert "Old whole-file noise" not in printed


def test_agent_pre_commit_deletion_only_diffs_drop_whole_file_noise(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")

    console = Mock()
    staged = Mock(stdout="app.py\n", returncode=0)
    cached_diff = Mock(
        stdout=(
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -3,1 +3,0 @@\n"
            "-dangerous_call()\n"
        ),
        returncode=0,
    )
    unstaged = Mock(stdout="", returncode=0)
    result = {
        "unused_functions": [],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
        "danger": [],
        "quality": [
            {
                "rule_id": "SKY-Q001",
                "file": "app.py",
                "line": 40,
                "severity": "HIGH",
                "message": "Old whole-file noise",
            },
            {
                "rule_id": "SKY-L021",
                "file": "app.py",
                "line": 3,
                "severity": "HIGH",
                "message": "Security control regression: validation call was removed",
            },
        ],
        "secrets": [],
    }

    def fake_run(cmd, **kwargs):
        if cmd == ["git", "diff", "--cached", "--name-only"]:
            return staged
        if cmd[:4] == ["git", "diff", "--cached", "--unified=0"]:
            return cached_diff
        if cmd == ["git", "status", "--porcelain", "--untracked-files=all"]:
            return unstaged
        raise AssertionError(f"Unexpected command: {cmd}")

    with (
        patch("sys.argv", ["skylos", "agent", "pre-commit", str(repo)]),
        patch("skylos.cli.Console", return_value=console),
        patch("skylos.cli.setup_logger"),
        patch("skylos.cli.find_project_root", return_value=repo),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.parse_exclude_folders", return_value=set()),
        patch("skylos.cli.subprocess.run", side_effect=fake_run),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.core.baseline.load_baseline", return_value=None),
    ):
        with pytest.raises(SystemExit) as exc_info:
            cli.main()

    assert exc_info.value.code == 1
    printed = " ".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    assert "validation call was removed" in printed
    assert "Old whole-file noise" not in printed


def test_agent_pre_commit_suppresses_structural_quality_noise_locally(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "taskflow.py").write_text("def f():\n    return 1\n", encoding="utf-8")

    console = Mock()
    staged = Mock(stdout="taskflow.py\n", returncode=0)
    cached_diff = Mock(
        stdout=(
            "diff --git a/taskflow.py b/taskflow.py\n"
            "--- a/taskflow.py\n"
            "+++ b/taskflow.py\n"
            "@@ -1 +1 @@\n"
        ),
        returncode=0,
    )
    unstaged = Mock(stdout="", returncode=0)
    result = {
        "unused_functions": [],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
        "danger": [],
        "quality": [
            {
                "rule_id": "SKY-Q301",
                "file": "taskflow.py",
                "line": 1,
                "severity": "MEDIUM",
                "message": "Function is 54 lines long (limit: 50).",
            },
            {
                "rule_id": "SKY-Q302",
                "file": "taskflow.py",
                "line": 1,
                "severity": "LOW",
                "message": "String literal 'result' repeated 3 times (threshold: 3).",
            },
        ],
        "secrets": [],
    }

    def fake_run(cmd, **kwargs):
        if cmd == ["git", "diff", "--cached", "--name-only"]:
            return staged
        if cmd[:4] == ["git", "diff", "--cached", "--unified=0"]:
            return cached_diff
        if cmd == ["git", "status", "--porcelain", "--untracked-files=all"]:
            return unstaged
        raise AssertionError(f"Unexpected command: {cmd}")

    with (
        patch("sys.argv", ["skylos", "agent", "pre-commit", str(repo)]),
        patch("skylos.cli.Console", return_value=console),
        patch("skylos.cli.setup_logger"),
        patch("skylos.cli.find_project_root", return_value=repo),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.parse_exclude_folders", return_value=set()),
        patch("skylos.cli.subprocess.run", side_effect=fake_run),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.core.baseline.load_baseline", return_value=None),
    ):
        with pytest.raises(SystemExit) as exc_info:
            cli.main()

    assert exc_info.value.code == 0
    printed = " ".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    assert "non-blocking quality finding(s)" in printed
    assert "No staged security, secrets, or quality issues" in printed
    assert "Function is 54 lines long" not in printed
