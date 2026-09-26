"""`--diff REF` / `--diff-base REF` must include uncommitted work.

Local agents run `skylos . -a --diff HEAD` before committing; a REF...HEAD-only
comparison silently reported zero findings for staged, unstaged and untracked
changes.
"""

import json
import shutil
import subprocess
import sys

import pytest

import skylos.cli as cli
from skylos.cicd.review import get_changed_line_ranges

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git required")


def _git(repo, *args):
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=test",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=repo,
        check=True,
        capture_output=True,
    )


SAFE = "def ok():\n    return 1\n"
UNSAFE = SAFE + "\n\ndef run(cmd):\n    import os\n    os.system('ls ' + cmd)\n"


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    for name in ("committed.py", "staged.py", "unstaged.py", "untouched.py"):
        (tmp_path / name).write_text(SAFE)
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "base")
    _git(tmp_path, "tag", "base")

    (tmp_path / "committed.py").write_text(UNSAFE)
    _git(tmp_path, "commit", "-q", "-am", "committed change")

    (tmp_path / "staged.py").write_text(UNSAFE)
    _git(tmp_path, "add", "staged.py")
    (tmp_path / "unstaged.py").write_text(UNSAFE)
    (tmp_path / "untracked.py").write_text(UNSAFE)
    (tmp_path / ".gitignore").write_text("ignored.py\n")
    (tmp_path / "ignored.py").write_text(UNSAFE)
    return tmp_path


def _files(ranges):
    return {r["file"] for r in ranges}


def test_working_tree_ranges_cover_committed_staged_unstaged_and_untracked(repo):
    ranges = get_changed_line_ranges(
        "base", cwd=repo, raise_on_error=True, include_working_tree=True
    )
    files = _files(ranges)
    assert {"committed.py", "staged.py", "unstaged.py", "untracked.py"} <= files
    assert "untouched.py" not in files
    assert "ignored.py" not in files


def test_committed_only_mode_is_unchanged_for_pr_review(repo):
    ranges = get_changed_line_ranges("base", cwd=repo, raise_on_error=True)
    assert _files(ranges) == {"committed.py"}


def test_diff_head_sees_only_uncommitted_work(repo):
    ranges = get_changed_line_ranges(
        "HEAD", cwd=repo, raise_on_error=True, include_working_tree=True
    )
    assert _files(ranges) >= {"staged.py", "unstaged.py", "untracked.py"}
    assert "committed.py" not in _files(ranges)


def test_working_tree_mode_rejects_unknown_ref(repo):
    with pytest.raises(ValueError, match="Cannot compare"):
        get_changed_line_ranges(
            "no-such-ref", cwd=repo, raise_on_error=True, include_working_tree=True
        )


def _run_cli_json(monkeypatch, repo, argv):
    monkeypatch.chdir(repo)
    monkeypatch.setattr(cli.sys, "argv", ["skylos", ".", *argv])
    printed = []
    monkeypatch.setattr(
        "builtins.print",
        lambda *a, **k: printed.append(a[0] if a else "")
        if k.get("file") not in (sys.stderr,)
        else None,
    )
    try:
        cli.main()
    except SystemExit as exc:
        assert exc.code in (0, 1, None)
    payload = next(p for p in printed if isinstance(p, str) and p.startswith("{"))
    return json.loads(payload)


def _danger_files(data):
    return {
        str(item.get("file", "")).rsplit("/", 1)[-1] for item in data.get("danger", [])
    }


def test_cli_diff_head_reports_uncommitted_injection(monkeypatch, repo):
    data = _run_cli_json(
        monkeypatch, repo, ["--danger", "--diff", "HEAD", "--format", "json"]
    )
    files = _danger_files(data)
    assert {"staged.py", "unstaged.py", "untracked.py"} <= files
    assert "committed.py" not in files
    assert "ignored.py" not in files


def test_cli_diff_base_includes_working_tree_files(monkeypatch, repo):
    data = _run_cli_json(
        monkeypatch,
        repo,
        ["--danger", "--diff-base", "base", "--format", "json", "--no-provenance"],
    )
    files = _danger_files(data)
    assert {"committed.py", "staged.py", "unstaged.py", "untracked.py"} <= files
    assert "untouched.py" not in files


def _run_cli_exit(monkeypatch, repo, argv):
    monkeypatch.chdir(repo)
    monkeypatch.setattr(cli.sys, "argv", ["skylos", ".", *argv])
    printed = []
    monkeypatch.setattr(
        "builtins.print",
        lambda *a, **k: printed.append(a[0] if a else "")
        if k.get("file") not in (sys.stderr,)
        else None,
    )
    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = exc.code or 0
    payload = next(p for p in printed if isinstance(p, str) and p.startswith("{"))
    return code, json.loads(payload)


@pytest.fixture
def broken_repo(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / "broken.py").write_text("def f(:\n    pass\n")
    (tmp_path / "broken.ts").write_text("function g( {\n")
    (tmp_path / "ok.py").write_text(SAFE)
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "base")
    (tmp_path / "ok.py").write_text(SAFE + "\nok()\n")
    return tmp_path


@pytest.mark.parametrize("flag", ["--diff-base", "--diff"])
def test_unparseable_files_outside_diff_are_warnings(monkeypatch, broken_repo, flag):
    code, data = _run_cli_exit(
        monkeypatch, broken_repo, [flag, "HEAD", "--format", "json", "--no-provenance"]
    )
    assert code == 0
    assert data["analysis_errors"] == []
    warned = {w["file"].rsplit("/", 1)[-1] for w in data["analysis_warnings"]}
    assert warned == {"broken.py", "broken.ts"}
    assert all(w["outside_diff"] for w in data["analysis_warnings"])
    assert data["analysis_summary"]["analysis_warning_count"] == 2


@pytest.mark.parametrize("flag", ["--diff-base", "--diff"])
def test_unparseable_file_inside_diff_still_blocks(monkeypatch, broken_repo, flag):
    (broken_repo / "broken.ts").write_text(  # skylos: ignore[SKY-D324] fixed file in pytest tmp_path fixture
        "function g( {\n\n"
    )
    code, data = _run_cli_exit(
        monkeypatch, broken_repo, [flag, "HEAD", "--format", "json", "--no-provenance"]
    )
    assert code == 2
    assert [e["file"].rsplit("/", 1)[-1] for e in data["analysis_errors"]] == [
        "broken.ts"
    ]
    warned = {w["file"].rsplit("/", 1)[-1] for w in data["analysis_warnings"]}
    assert warned == {"broken.py"}


def test_split_keeps_non_file_errors_blocking(tmp_path):
    from skylos.analyzer import _split_outside_diff_analysis_errors

    outside = tmp_path / "outside.py"
    outside.write_text(  # skylos: ignore[SKY-D324] fixed filename under pytest tmp_path
        "x = (\n"
    )
    errors = [
        {"file": str(outside), "kind": "syntax_error"},
        {"file": str(tmp_path), "kind": "go_engine_error"},  # a directory
        {"kind": "engine_unavailable"},
    ]
    kept, warnings = _split_outside_diff_analysis_errors(errors, set())
    assert [e["kind"] for e in kept] == ["go_engine_error", "engine_unavailable"]
    assert [w["kind"] for w in warnings] == ["syntax_error"]
    assert _split_outside_diff_analysis_errors(errors, None) == (errors, [])


@pytest.mark.parametrize("flag", ["--diff-base", "--diff"])
def test_delete_only_edit_that_breaks_parsing_still_blocks(
    monkeypatch, broken_repo, flag
):
    (broken_repo / "valid.ts").write_text(  # skylos: ignore[SKY-D324] fixed file in pytest tmp_path fixture
        "export function g() {\n  return 1;\n}\n"
    )
    _git(broken_repo, "add", "valid.ts")
    _git(broken_repo, "commit", "-q", "-m", "valid")
    (broken_repo / "valid.ts").write_text(  # skylos: ignore[SKY-D324] same pytest fixture file created above
        "export function g() {\n  return 1;\n"
    )
    code, data = _run_cli_exit(
        monkeypatch, broken_repo, [flag, "HEAD", "--format", "json", "--no-provenance"]
    )
    assert code == 2
    assert [e["file"].rsplit("/", 1)[-1] for e in data["analysis_errors"]] == [
        "valid.ts"
    ]
