"""Cleanup diff is display selection over a complete, pinned project scan."""

from copy import deepcopy
import io
import json
import os
import shlex
import subprocess
import sys

import pytest

from skylos.cleanup_state import STATE_PATH, load_cleanup_state
from skylos.commands.cleanup_cmd import run_cleanup_command


def _git(root, *args):
    result = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.name", "Cleanup test")
    _git(tmp_path, "config", "user.email", "cleanup@example.test")
    (tmp_path / ".gitignore").write_text(".skylos/\nignored/\n", encoding="utf-8")
    for name in ("committed", "staged", "unstaged", "unchanged"):
        (tmp_path / f"{name}.py").write_text("value = 1\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "baseline")
    return tmp_path


def _raw(root, names):
    return {
        "analysis_errors": [],
        "analysis_summary": {
            "total_files": len(list(root.glob("*.py"))),
            "grade_categories": ["quality", "ai_defects", "dead_code"],
            "ai_verification": {"state": "complete"},
            "comparison_scope": {"scan_path": str(root), "complete_repository": True},
        },
        "quality": [
            {
                "rule_id": "SKY-L033",
                "file": str(root / name),
                "line": 1,
                "name": name,
                "severity": "MEDIUM",
                "message": "Statement has no effect",
            }
            for name in names
        ],
        "ai_defects": [],
        "unused_imports": [],
    }


def _run(root, *args, analyze=None):
    output = io.StringIO()
    code = run_cleanup_command(
        [str(root), "--format", "json", *args], stdout=output, analyze_func=analyze
    )
    return code, json.loads(output.getvalue())


def test_diff_selects_committed_staged_unstaged_untracked_and_preserves_full_scan(repo):
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "committed.py").write_text("value = 2\n", encoding="utf-8")
    _git(repo, "add", "committed.py")
    _git(repo, "commit", "-qm", "committed change")
    (repo / "staged.py").write_text("value = 3\n", encoding="utf-8")
    _git(repo, "add", "staged.py")
    (repo / "unstaged.py").write_text("value = 4\n", encoding="utf-8")
    (repo / "untracked.py").write_text("value = 5\n", encoding="utf-8")
    names = ["committed.py", "staged.py", "unstaged.py", "untracked.py", "unchanged.py"]
    seen = []

    def scan(path, **options):
        seen.append((path, options, os.environ.get("SKYLOS_DIFF_BASE")))
        return _raw(repo, names)

    code, report = _run(repo, "--diff", base, analyze=scan)
    assert code == 0, report
    changed = set(names) - {"unchanged.py"}
    assert {task["file"] for task in report["tasks"]} == changed
    assert all(task["change_relation"] == "changed_file" for task in report["tasks"])
    assert report["selection"]["finding_newness"] == "not_assessed"
    assert set(report["selection"]["changed_files"]) == changed
    assert report["selection"]["worktree_dirty"] is True
    assert report["selection"]["excluded_tasks"] == 1
    assert len(report["state"]["tasks"]) == 5
    assert seen[0][0] == str(repo)
    assert seen[0][1].get("changed_files") is None
    assert seen[0][2] == base
    assert report["tasks"][0]["scope"]["diff_base_sha"] == base
    assert report["analysis_summary"]["comparison_scope"]["complete_repository"] is True
    assert all("unchanged.py" not in group["files"] for group in report["groups"])


@pytest.mark.parametrize("as_file", [False, True])
def test_diff_path_selects_locally_but_analyzes_git_root(repo, as_file):
    subdir = repo / "src"
    subdir.mkdir()
    source = subdir / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    _git(repo, "add", "src/app.py")
    _git(repo, "commit", "-qm", "subdirectory source")
    source.write_text("value = 2\n", encoding="utf-8")
    (repo / "unstaged.py").write_text("value = 3\n", encoding="utf-8")
    seen = []

    def scan(path, **_options):
        seen.append(path)
        return _raw(repo, ["src/app.py", "unstaged.py"])

    target = source if as_file else subdir
    code, report = _run(target, "--diff", "HEAD", analyze=scan)
    assert code == 0, report
    assert seen == [str(repo)]
    assert [task["file"] for task in report["tasks"]] == ["src/app.py"]
    assert report["project_root"] == str(repo)
    assert report["selection"]["path"] == str(target)
    assert len(report["state"]["tasks"]) == 2


def test_no_changed_files_keep_inventory_and_incomplete_analysis_honest(repo):
    def scan(*_a, **_kw):
        return _raw(repo, ["unchanged.py"])

    code, report = _run(repo, "--diff", "HEAD", analyze=scan)
    assert code == 0 and report["status"] == "clear"
    assert report["tasks"] == [] and report["selection"]["changed_files"] == []
    record = next(iter(report["state"]["tasks"].values()))
    assert record["status"] == "open"

    def incomplete(*_a, **_kw):
        raw = scan()
        raw["analysis_errors"] = [{"kind": "syntax_error", "file": "unchanged.py"}]
        return raw

    code, report = _run(repo, "--diff", "HEAD", analyze=incomplete)
    assert code == 2 and report["status"] == "incomplete"
    assert next(iter(report["state"]["tasks"].values()))["status"] == "open"


def test_diff_selection_does_not_create_absence_or_share_other_baselines(repo):
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "committed.py").write_text("value = 2\n", encoding="utf-8")
    _git(repo, "add", "committed.py")
    _git(repo, "commit", "-qm", "second comparison")
    current = _git(repo, "rev-parse", "HEAD")

    def scan(*_a, **_kw):
        return _raw(repo, ["committed.py", "unchanged.py"])

    _, full_selection = _run(repo, "--diff", base, analyze=scan)
    first_key = full_selection["state"]["scope_id"]
    _, no_selection = _run(repo, "--diff", current, analyze=scan)
    assert no_selection["state"]["scope_id"] != first_key
    saved = load_cleanup_state(repo)
    assert len(saved["scopes"]) == 2
    assert all(
        task["status"] == "open"
        for task in saved["scopes"][first_key]["tasks"].values()
    )
    _, same_base = _run(repo, "--diff", base, analyze=scan)
    assert same_base["state"]["scope_id"] == first_key
    assert all(task["history"] == [] for task in same_base["state"]["tasks"].values())


@pytest.mark.parametrize("previous", [None, "parent-value"])
def test_pinned_diff_environment_is_restored_after_scan_error(
    repo, monkeypatch, previous
):
    if previous is None:
        monkeypatch.delenv("SKYLOS_DIFF_BASE", raising=False)
    else:
        monkeypatch.setenv("SKYLOS_DIFF_BASE", previous)
    head = _git(repo, "rev-parse", "HEAD")

    def scan(*_a, **_kw):
        assert os.environ["SKYLOS_DIFF_BASE"] == head
        raise RuntimeError("scan interrupted")

    code, report = _run(repo, "--diff", "HEAD", analyze=scan)
    assert code == 2 and report["status"] == "incomplete"
    assert os.environ.get("SKYLOS_DIFF_BASE") == previous
    assert not (repo / STATE_PATH).exists()


@pytest.mark.parametrize("change", ["head", "config"])
def test_scan_mutation_is_rejected_before_history_can_close_tasks(repo, change):
    _, initial = _run(
        repo, "--diff", "HEAD", analyze=lambda *_a, **_kw: _raw(repo, ["unchanged.py"])
    )
    original = (repo / STATE_PATH).read_bytes()

    def scan(*_a, **_kw):
        if change == "head":
            _git(repo, "commit", "--allow-empty", "-qm", "head changed during scan")
        else:
            (repo / "pyproject.toml").write_text(
                '[tool.skylos]\nexclude = ["vendor"]\n', encoding="utf-8"
            )
        return _raw(repo, [])

    code, report = _run(repo, "--diff", "HEAD", analyze=scan)
    assert code == 2 and report["status"] == "incomplete"
    assert (repo / STATE_PATH).read_bytes() == original
    assert next(iter(initial["state"]["tasks"].values()))["status"] == "open"


def test_ref_label_moves_without_retargeting_the_pinned_scan(repo):
    base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "branch", "baseline")
    (repo / "committed.py").write_text("value = 2\n", encoding="utf-8")
    _git(repo, "add", "committed.py")
    _git(repo, "commit", "-qm", "new head")

    def scan(*_a, **_kw):
        _git(repo, "branch", "-f", "baseline", "HEAD")
        assert os.environ["SKYLOS_DIFF_BASE"] == base
        return _raw(repo, ["committed.py"])

    code, report = _run(repo, "--diff", "baseline", analyze=scan)
    assert code == 0
    assert report["selection"]["base_sha"] == base
    assert report["selection"]["merge_base_sha"] == base


def test_ignored_symlink_and_outside_sources_cannot_enter_diff_selection(repo):
    (repo / "pyproject.toml").write_text(
        '[tool.skylos]\nexclude = ["excluded"]\n', encoding="utf-8"
    )
    for directory in ("excluded", "ignored", "real"):
        (repo / directory).mkdir()
        (repo / directory / "app.py").write_text("value = 2\n", encoding="utf-8")
    outside = repo.parent / "outside.py"
    outside.write_text("outside = True\n", encoding="utf-8")
    (repo / "linked.py").symlink_to(outside)
    (repo / "linked_dir").symlink_to(repo / "real", target_is_directory=True)
    (repo / "unstaged.py").write_text("value = 3\n", encoding="utf-8")
    code, report = _run(
        repo,
        "--diff",
        "HEAD",
        analyze=lambda *_a, **_kw: _raw(
            repo,
            [
                "excluded/app.py",
                "ignored/app.py",
                "linked.py",
                "linked_dir/app.py",
                "unstaged.py",
            ],
        ),
    )
    assert code == 0
    assert [task["file"] for task in report["tasks"]] == ["unstaged.py"]
    assert "linked.py" not in report["selection"]["changed_files"]
    assert not any(
        path.startswith("linked_dir/") for path in report["selection"]["changed_files"]
    )
    assert outside.read_text() == "outside = True\n"


def test_diff_preserves_literal_filenames_and_reports_deletion(repo):
    filename = "untracked\nsource.py"
    (repo / filename).write_text("value = 2\n", encoding="utf-8")
    (repo / "unchanged.py").unlink()
    code, report = _run(
        repo, "--diff", "HEAD", analyze=lambda *_a, **_kw: _raw(repo, [filename])
    )
    assert code == 0
    assert [task["file"] for task in report["tasks"]] == [filename]
    assert report["selection"]["deleted_files"] == ["unchanged.py"]


def test_git_worktree_path_whitespace_is_not_trimmed(repo):
    renamed = repo.with_name(repo.name + " ")
    repo.rename(renamed)
    (renamed / "unstaged.py").write_text("value = 2\n", encoding="utf-8")
    code, report = _run(
        renamed,
        "--diff",
        "HEAD",
        analyze=lambda *_a, **_kw: _raw(renamed, ["unstaged.py"]),
    )
    assert code == 0, report
    assert report["project_root"] == str(renamed)
    assert [task["file"] for task in report["tasks"]] == ["unstaged.py"]


@pytest.mark.parametrize("base", ["", "missing-ref", "--all", "HEAD\n"])
def test_invalid_diff_base_fails_before_analyzing_or_writing_history(repo, base):
    code, report = _run(
        repo,
        f"--diff={base}",
        analyze=lambda *_a, **_kw: pytest.fail("invalid baseline must not scan"),
    )
    assert code == 2 and report["status"] == "incomplete"
    assert not (repo / STATE_PATH).exists()


def test_non_git_diff_is_incomplete(tmp_path):
    code, report = _run(
        tmp_path,
        "--diff",
        "HEAD",
        analyze=lambda *_a, **_kw: pytest.fail("non-Git target must not scan"),
    )
    assert code == 2 and report["status"] == "incomplete"
    assert not (tmp_path / STATE_PATH).exists()


@pytest.mark.parametrize("flag", ["--from-report", "--history"])
def test_diff_rejects_unbound_saved_report_and_history(repo, flag):
    arguments = [str(repo), "--diff", "HEAD", flag]
    if flag == "--from-report":
        arguments.append("saved.json")
    with pytest.raises(SystemExit) as failure:
        run_cleanup_command(arguments)
    assert failure.value.code == 2


@pytest.mark.parametrize("flag", ["--next", "--top"])
def test_context_and_model_advice_respect_display_limit(repo, monkeypatch, flag):
    raw = _raw(repo, ["committed.py", "staged.py", "unstaged.py"])
    captured = []

    def context(tasks, *_a, **_kw):
        captured.append([task["id"] for task in tasks])
        return {"files": [{"file": "committed.py"}]}

    def review(_context, tasks, _adapter):
        captured.append([task["id"] for task in tasks])
        return {"status": "complete", "advice": []}

    monkeypatch.setattr("skylos.cleanup_context.build_cleanup_context", context)
    monkeypatch.setattr("skylos.cleanup_context.review_cleanup_context", review)
    monkeypatch.setattr(
        "skylos.commands.cleanup_cmd._review_adapter", lambda _args: object()
    )
    args = [flag] if flag == "--next" else [flag, "1"]
    code, report = _run(
        repo, *args, "--review", analyze=lambda *_a, **_kw: deepcopy(raw)
    )
    assert code == 0
    displayed = [task["id"] for task in report["tasks"]]
    assert len(displayed) == 1
    assert captured == [displayed, displayed]


def test_diff_context_excludes_unchanged_task_even_when_it_has_higher_priority(
    repo, monkeypatch
):
    (repo / "unstaged.py").write_text("value = 2\n", encoding="utf-8")
    raw = _raw(repo, ["unchanged.py", "unstaged.py"])
    raw["quality"][0]["severity"] = "CRITICAL"
    captured = []

    def context(tasks, root, **_options):
        assert root == repo
        captured.extend(tasks)
        return {"files": []}

    monkeypatch.setattr("skylos.cleanup_context.build_cleanup_context", context)
    code, report = _run(
        repo,
        "--diff",
        "HEAD",
        "--context",
        "--top",
        "1",
        analyze=lambda *_a, **_kw: deepcopy(raw),
    )
    assert code == 0
    assert [task["file"] for task in captured] == ["unstaged.py"]
    assert [task["id"] for task in captured] == [task["id"] for task in report["tasks"]]


def test_actual_diff_providers_run_with_full_context_and_pinned_base(repo):
    (repo / "cli.py").write_text(
        'import argparse\np = argparse.ArgumentParser()\np.add_argument("--old-flag")\n',
        encoding="utf-8",
    )
    (repo / "test_app.py").write_text(
        "def test_value():\n    value = 2\n    assert value == 2\n", encoding="utf-8"
    )
    _git(repo, "add", "cli.py", "test_app.py")
    _git(repo, "commit", "-qm", "test and CLI contracts")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "cli.py").write_text(
        "import argparse\np = argparse.ArgumentParser()\n", encoding="utf-8"
    )
    (repo / "test_app.py").write_text(
        "def test_value():\n    value = 2\n    assert value\n", encoding="utf-8"
    )
    _git(repo, "add", "cli.py", "test_app.py")
    _git(repo, "commit", "-qm", "removed contracts")
    code, report = _run(
        repo, "--diff", base, "--all-advice", "--top", "100", "--no-state"
    )
    assert code == 0, report
    rows = report["tasks"] + report["advisories"]
    assert {"SKY-A101", "SKY-A104"} <= {task["rule_id"] for task in rows}
    assert report["analysis_summary"]["comparison_scope"]["changed_files_only"] is False


def test_diff_apply_verifies_unchanged_files_and_rejects_head_mutation(repo):
    file = repo / "unstaged.py"
    file.write_text("import math\nvalue = 1\n", encoding="utf-8")
    (repo / "test_cleanup_run.py").write_text(
        "import unstaged\n\ndef test_value():\n    assert unstaged.value == 1\n",
        encoding="utf-8",
    )
    scans = []

    def scan(path, **options):
        scans.append(
            (path, options.get("changed_files"), os.environ.get("SKYLOS_DIFF_BASE"))
        )
        raw = _raw(repo, [])
        if "import math" in file.read_text():
            raw["unused_imports"] = [
                {"file": str(file), "line": 1, "name": "math", "confidence": 100}
            ]
        return raw

    _, initial = _run(repo, "--diff", "HEAD", analyze=scan)
    task_id = initial["tasks"][0]["id"]
    command = shlex.join([sys.executable, "-m", "pytest", "-q", "test_cleanup_run.py"])
    code, applied = _run(
        repo,
        "--diff",
        "HEAD",
        "--task",
        task_id,
        "--apply",
        "--test-cmd",
        command,
        analyze=scan,
    )
    assert code == 0, applied
    assert applied["execution"]["status"] == "verified"
    assert len(scans) == 3 and all(
        path == str(repo) and changed is None for path, changed, _base in scans
    )
    assert len({base for _path, _changed, base in scans}) == 1
    assert (
        applied["execution"]["baseline"]["head_sha"] == initial["selection"]["head_sha"]
    )

    file.write_text("import math\nvalue = 1\n", encoding="utf-8")
    command = shlex.join(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--allow-empty",
            "-qm",
            "changed head",
        ]
    )
    code, rejected = _run(
        repo,
        "--diff",
        "HEAD",
        "--task",
        task_id,
        "--apply",
        "--test-cmd",
        command,
        analyze=scan,
    )
    assert code == 2, rejected
    assert rejected["execution"]["status"] == "incomplete"
    assert "HEAD changed" in rejected["execution"]["rescan"]["error"]
    saved = load_cleanup_state(repo)
    assert (
        saved["scopes"][rejected["state"]["scope_id"]]["last_scan"]["complete"] is False
    )


def test_new_defect_in_unchanged_file_fails_rescan_and_rolls_back(repo):
    file = repo / "unstaged.py"
    original = "import math\nvalue = 1\n"
    file.write_text(original, encoding="utf-8")

    def scan(*_a, **_kw):
        if "import math" in file.read_text():
            raw = _raw(repo, [])
            raw["unused_imports"] = [
                {"file": str(file), "line": 1, "name": "math", "confidence": 100}
            ]
            return raw
        return _raw(repo, ["unchanged.py"])

    _, plan = _run(repo, "--diff", "HEAD", analyze=scan)
    task_id = plan["tasks"][0]["id"]
    command = shlex.join([sys.executable, "-c", "pass"])
    code, report = _run(
        repo,
        "--diff",
        "HEAD",
        "--task",
        task_id,
        "--apply",
        "--test-cmd",
        command,
        analyze=scan,
    )
    assert code == 1, report
    receipt = report["execution"]
    assert receipt["status"] == "failed" and receipt["rolled_back"] is True
    assert receipt["rescan"]["new_findings"][0]["file"] == str(repo / "unchanged.py")
    assert "unchanged.py" not in report["selection"]["changed_files"]
    assert file.read_text() == original


@pytest.mark.parametrize("change", ["head", "config"])
def test_mutation_during_rescan_stays_incomplete(repo, change):
    file = repo / "unstaged.py"
    file.write_text("import math\nvalue = 1\n", encoding="utf-8")
    scans = []

    def scan(*_a, **_kw):
        scans.append(True)
        raw = _raw(repo, [])
        if "import math" in file.read_text():
            raw["unused_imports"] = [
                {"file": str(file), "line": 1, "name": "math", "confidence": 100}
            ]
        elif change == "head":
            _git(repo, "commit", "--allow-empty", "-qm", "head changed during rescan")
        else:
            (repo / "pyproject.toml").write_text(
                '[tool.skylos]\nexclude = ["vendor"]\n', encoding="utf-8"
            )
        return raw

    _, plan = _run(repo, "--diff", "HEAD", analyze=scan)
    command = shlex.join([sys.executable, "-c", "pass"])
    code, report = _run(
        repo,
        "--diff",
        "HEAD",
        "--task",
        plan["tasks"][0]["id"],
        "--apply",
        "--test-cmd",
        command,
        analyze=scan,
    )
    assert code == 2, report
    assert report["execution"]["status"] == "incomplete"
    assert report["execution"]["rescan"]["status"] == "incomplete"
    assert len(scans) == 3


def test_task_outside_changed_selection_cannot_authorize_a_patch(repo):
    (repo / "unstaged.py").write_text("value = 2\n", encoding="utf-8")
    raw = _raw(repo, ["unstaged.py", "unchanged.py"])
    _, report = _run(repo, "--diff", "HEAD", analyze=lambda *_a, **_kw: deepcopy(raw))
    outside_id = next(
        task_id
        for task_id, task in report["state"]["tasks"].items()
        if task["file"] == "unchanged.py"
    )
    original = (repo / "unchanged.py").read_bytes()
    code, preview = _run(
        repo,
        "--diff",
        "HEAD",
        "--task",
        outside_id,
        analyze=lambda *_a, **_kw: deepcopy(raw),
    )
    assert code == 2 and "edit" not in preview
    assert (repo / "unchanged.py").read_bytes() == original
