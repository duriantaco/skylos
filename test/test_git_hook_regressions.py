"""Git-hook scan context must preserve the analyzer's selected source files."""

import json
import os
import subprocess
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.constants import parse_exclude_folders
from skylos.core.safe_cache_io import write_text_no_symlink


_ORIGINAL = (
    "import html\n\n"
    "def format_label(value: str) -> str:\n"
    "    return html.escape(value)\n"
)
_EDITED = "def format_label(value: str) -> str:\n    return value.upper()\n"
_CONFIG = (
    '[tool.skylos]\nexclude = ["output", "skip_*.py"]\n\n'
    "[tool.skylos.gate]\nmax_quality = 0\n"
)
_CONTRACT_CONFIG = (
    "\n[[tool.skylos.security_contracts]]\n"
    'id = "label-dependency"\n'
    'framework = "fastapi"\n'
    'file = "routes.py"\n'
    'handler = "show_label"\n'
    'guards = ["normalize_label"]\n'
)
_CONTRACT_ORIGINAL = (
    "from fastapi import APIRouter, Depends\n\n"
    "router = APIRouter()\n\n"
    "def normalize_label():\n"
    "    return 'example'\n\n"
    "@router.get('/label')\n"
    "def show_label(label=Depends(normalize_label)):\n"
    "    return {'label': label}\n"
)
_CONTRACT_EDITED = (
    "from fastapi import APIRouter\n\n"
    "router = APIRouter()\n\n"
    "@router.get('/label')\n"
    "def show_label():\n"
    "    return {'label': 'example'}\n"
)


def _git(repo, *args):
    git_env = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    result = subprocess.run(
        [
            "git",
            "-c",
            f"core.hooksPath={repo / '.disabled-hooks'}",
            "-c",
            "commit.gpgsign=false",
            "-C",
            str(repo),
            *args,
        ],
        capture_output=True,
        text=True,
        check=True,
        env=git_env,
    )
    return result.stdout.strip()


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, content)


def _commit(repo, *paths):
    _git(repo, "add", "--", *paths)
    _git(repo, "commit", "-qm", "fixture baseline")


@pytest.fixture(params=["ordinary", "linked"])
def git_checkout(tmp_path, request):
    repo = tmp_path / "source"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Skylos Tests")
    _git(repo, "config", "user.email", "skylos-tests@example.invalid")
    _write(repo / "pyproject.toml", _CONFIG)
    _write(repo / "pkg" / "pyproject.toml", _CONFIG)
    _write(repo / "pkg" / "app.py", _ORIGINAL)
    _commit(repo, "pyproject.toml", "pkg/pyproject.toml", "pkg/app.py")
    if request.param == "linked":
        checkout = tmp_path / "linked"
        _git(repo, "worktree", "add", "-q", "-b", "scan-checkout", str(checkout))
        return checkout
    return repo


def _hook_environment(repo, monkeypatch):
    git_dir = _git(repo, "rev-parse", "--absolute-git-dir")
    monkeypatch.setenv("GIT_DIR", git_dir)
    monkeypatch.delenv("GIT_WORK_TREE", raising=False)
    monkeypatch.setenv("GIT_PREFIX", "")
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.chdir(repo / "pkg")


def _regressions(target, **kwargs):
    payload = json.loads(
        analyze(target, enable_quality=True, grep_verify=False, **kwargs)
    )
    assert "error" not in payload, payload
    return [
        finding
        for finding in payload.get("quality", [])
        if finding.get("rule_id") == "SKY-L021"
    ]


def test_clean_subdirectory_scan_in_git_hook_has_no_regressions(
    git_checkout, monkeypatch
):
    repo = git_checkout
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    assert _git(repo, "status", "--porcelain") == ""
    assert _regressions(str(repo / "pkg")) == []

    _hook_environment(repo, monkeypatch)

    assert _regressions(".") == []


@pytest.mark.parametrize("staged", [False, True], ids=["unstaged", "staged"])
@pytest.mark.parametrize("explicit", [False, True], ids=["automatic", "explicit"])
def test_git_hook_reports_real_edit_at_its_existing_source_path(
    git_checkout, monkeypatch, staged, explicit
):
    repo = git_checkout
    app = repo / "pkg" / "app.py"
    _write(app, _EDITED)
    if staged:
        _git(repo, "add", "--", "pkg/app.py")
    _hook_environment(repo, monkeypatch)
    options = {"changed_files": {str(app)}} if explicit else {}

    findings = _regressions(".", **options)

    assert findings, "The real tracked edit must still be checked in a hook"
    assert {Path(finding["file"]).resolve() for finding in findings} == {app.resolve()}
    assert all(Path(finding["file"]).is_file() for finding in findings)
    assert any("anitization" in finding["message"] for finding in findings)


@pytest.mark.parametrize(
    "relative_path",
    ["output/format.py", "skip_formatter.py", "debug.log", "README.md"],
)
@pytest.mark.parametrize("explicit", [False, True], ids=["automatic", "explicit"])
def test_git_hook_skips_excluded_and_non_source_changes(
    git_checkout, monkeypatch, relative_path, explicit
):
    repo = git_checkout
    changed = repo / "pkg" / relative_path
    _write(changed, _ORIGINAL)
    _commit(repo, f"pkg/{relative_path}")
    _write(changed, _EDITED)
    _hook_environment(repo, monkeypatch)
    options = {"changed_files": {str(changed)}} if explicit else {}

    assert _regressions(".", **options) == []


def test_git_hook_explicit_include_restores_config_excluded_source(
    git_checkout, monkeypatch
):
    repo = git_checkout
    included = repo / "pkg" / "output" / "format.py"
    still_excluded = repo / "pkg" / "skip_formatter.py"
    for path in (included, still_excluded):
        _write(path, _ORIGINAL)
    _commit(repo, "pkg/output/format.py", "pkg/skip_formatter.py")
    for path in (included, still_excluded):
        _write(path, _EDITED)
    _hook_environment(repo, monkeypatch)
    excludes = parse_exclude_folders(
        include_folders=["output"],
        config_exclude_folders=["output", "skip_*.py"],
    )

    findings = _regressions(".", exclude_folders=sorted(excludes))

    assert findings, "An explicit include must restore the real edited source"
    assert {Path(finding["file"]).resolve() for finding in findings} == {
        included.resolve()
    }


@pytest.mark.parametrize("scope", ["repo", "directory", "file", "file-list"])
def test_git_hook_regressions_stay_inside_selected_scan_targets(
    git_checkout, monkeypatch, scope
):
    repo = git_checkout
    app = repo / "pkg" / "app.py"
    neighbor = repo / "pkg" / "neighbor.py"
    outside = repo / "sibling.py"
    _write(neighbor, _ORIGINAL)
    _write(outside, _ORIGINAL)
    _commit(repo, "pkg/neighbor.py", "sibling.py")
    for path in (app, neighbor, outside):
        _write(path, _EDITED)
    _hook_environment(repo, monkeypatch)
    targets = {
        "repo": (str(repo), {app, neighbor, outside}),
        "directory": (str(repo / "pkg"), {app, neighbor}),
        "file": (str(app), {app}),
        "file-list": ([str(app), str(outside)], {app, outside}),
    }
    target, expected = targets[scope]

    findings = _regressions(target)

    assert {Path(finding["file"]).resolve() for finding in findings} == {
        path.resolve() for path in expected
    }


@pytest.mark.parametrize("explicit", [False, True], ids=["automatic", "explicit"])
def test_deleted_source_is_not_a_surviving_control_regression(
    git_checkout, monkeypatch, explicit
):
    repo = git_checkout
    removed = repo / "pkg" / "app.py"
    removed.unlink()
    _write(repo / "pkg" / "remaining.py", "label = 'still here'\n")
    _hook_environment(repo, monkeypatch)
    options = {"changed_files": {str(removed)}} if explicit else {}

    assert _regressions(".", **options) == []


def _prepare_contract(repo, relative_path="routes.py"):
    contract_config = _CONTRACT_CONFIG.replace(
        'file = "routes.py"', f'file = "{relative_path}"'
    )
    _write(repo / "pkg" / "pyproject.toml", _CONFIG + contract_config)
    route = repo / "pkg" / relative_path
    _write(route, _CONTRACT_ORIGINAL)
    # A same-named root file must not replace the subproject's committed source.
    _write(repo / "routes.py", _CONTRACT_EDITED)
    _commit(repo, "pkg/pyproject.toml", f"pkg/{relative_path}", "routes.py")
    return route


def _contract_regressions(target, **kwargs):
    payload = json.loads(
        analyze(target, enable_danger=True, grep_verify=False, **kwargs)
    )
    assert "error" not in payload, payload
    return [
        finding
        for finding in payload.get("danger", [])
        if finding.get("rule_id") == "SKY-SC001"
    ]


@pytest.mark.parametrize("keep_dependency", [True, False], ids=["kept", "removed"])
def test_git_hook_contract_reads_subproject_base_blob(
    git_checkout, monkeypatch, keep_dependency
):
    repo = git_checkout
    route = _prepare_contract(repo)
    current = (
        _CONTRACT_ORIGINAL.replace("'example'", "'updated'")
        if keep_dependency
        else _CONTRACT_EDITED
    )
    _write(route, current)
    _hook_environment(repo, monkeypatch)

    findings = _contract_regressions(".")

    if keep_dependency:
        assert findings == []
    else:
        assert len(findings) == 1
        assert Path(findings[0]["file"]).resolve() == route.resolve()
        assert "normalize_label" in findings[0]["message"]


def test_git_hook_deleted_contracted_source_still_reports(git_checkout, monkeypatch):
    repo = git_checkout
    route = _prepare_contract(repo)
    route.unlink()
    _hook_environment(repo, monkeypatch)

    findings = _contract_regressions(".")

    assert len(findings) == 1
    assert Path(findings[0]["file"]).resolve() == route.resolve()
    assert "normalize_label" in findings[0]["message"]


def test_git_hook_explicit_include_restores_config_excluded_contract(
    git_checkout, monkeypatch
):
    repo = git_checkout
    route = _prepare_contract(repo, "output/routes.py")
    _write(route, _CONTRACT_EDITED)
    _hook_environment(repo, monkeypatch)
    excludes = parse_exclude_folders(
        include_folders=["output"],
        config_exclude_folders=["output", "skip_*.py"],
    )

    findings = _contract_regressions(".", exclude_folders=sorted(excludes))

    assert len(findings) == 1
    assert Path(findings[0]["file"]).resolve() == route.resolve()
    assert "normalize_label" in findings[0]["message"]


def test_git_hook_file_target_does_not_evaluate_sibling_contract(
    git_checkout, monkeypatch
):
    repo = git_checkout
    route = _prepare_contract(repo)
    _write(route, _CONTRACT_EDITED)
    _hook_environment(repo, monkeypatch)

    assert _contract_regressions(str(repo / "pkg" / "app.py")) == []


def test_contract_empty_changed_selection_does_not_evaluate_all_files(
    git_checkout, monkeypatch
):
    from skylos.config import load_config
    from skylos.security.contracts import detect_security_contract_regressions

    repo = git_checkout
    route = _prepare_contract(repo)
    _write(route, _CONTRACT_EDITED)
    _hook_environment(repo, monkeypatch)
    project = repo / "pkg"
    config = load_config(project)
    config["security_contracts"][0]["file"] = "pkg/routes.py"

    assert detect_security_contract_regressions(repo, config, changed_files=set()) == []
