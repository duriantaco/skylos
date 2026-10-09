"""Generated state in .skylos/ stays out of `git status`; committed files do not."""

import subprocess
from pathlib import Path

import pytest

from skylos.core.safe_cache_io import (
    load_project_json_cache,
    save_project_json_cache,
    write_text_no_symlink,
)


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=True
    ).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    return tmp_path


@pytest.mark.parametrize(
    "cache_path",
    [
        ".skylos/cache/dependency_versions.json",
        ".skylos/cache/runs/v1/trace/run.json",
        ".skylos/index/v1/reference_graph.json",
        ".skylos/contribution/events.json",
    ],
)
def test_generated_state_does_not_show_in_git_status(repo, cache_path):
    assert save_project_json_cache(repo, cache_path, {"ok": True})

    top = Path(cache_path).parts[1]
    assert (repo / ".skylos" / top / ".gitignore").read_text() == "*\n"
    assert _git(repo, "status", "--porcelain", "--untracked-files=all") == ""


def test_files_people_commit_in_skylos_dir_stay_visible(repo):
    assert save_project_json_cache(repo, ".skylos/cache/grep_results.json", {})
    for name in ("config.yaml", "baseline.json", "ai-contract.yml"):
        assert write_text_no_symlink(repo / ".skylos" / name, "x\n")

    status = _git(repo, "status", "--porcelain", "--untracked-files=all")

    assert sorted(status.splitlines()) == [
        "?? .skylos/ai-contract.yml",
        "?? .skylos/baseline.json",
        "?? .skylos/config.yaml",
    ]
    assert not (repo / ".skylos" / ".gitignore").exists()


def test_existing_ignore_file_is_left_alone(repo):
    cache = repo / ".skylos" / "cache"
    cache.mkdir(parents=True)
    assert write_text_no_symlink(cache / ".gitignore", "# mine\n*.json\n")

    assert save_project_json_cache(repo, ".skylos/cache/x.json", {})

    assert (cache / ".gitignore").read_text() == "# mine\n*.json\n"


def test_reading_a_cache_creates_nothing(repo):
    assert load_project_json_cache(repo, ".skylos/cache/missing.json") == {}
    assert not (repo / ".skylos").exists()
