import json
import os
import shutil
import subprocess

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


_GIT_ENV = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_PREFIX",
    "GIT_INTERNAL_SUPER_PREFIX",
)


def _git(repo, *args):
    env = dict(os.environ)
    for key in _GIT_ENV:
        env.pop(key, None)
    return subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _commit(repo, message):
    return _git(
        repo,
        "-c",
        "user.name=Skylos Test",
        "-c",
        "user.email=skylos-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        message,
    )


def _manifest(version, dependency_version=None):
    dependency_version = dependency_version or version
    return (
        '[project]\nname = "example-app"\n'
        f'version = "{version}"\n'
        f'dependencies = ["example-library>={dependency_version}"]\n'
    )


@pytest.fixture
def repo(tmp_path, monkeypatch):
    if shutil.which("git") is None:
        pytest.skip("git is required")
    for key in (*_GIT_ENV, "SKYLOS_DIFF_BASE", "GITHUB_BASE_REF"):
        monkeypatch.delenv(key, raising=False)
    root = tmp_path / "working repo"
    root.mkdir()
    _git(root, "init", "-q")
    assert write_text_no_symlink(root / "pyproject.toml", _manifest("1.2.3"))
    _git(root, "add", "pyproject.toml")
    _commit(root, "initial version")
    return root


def _analyze(repo, **kwargs):
    return json.loads(
        analyze(
            str(repo),
            conf=0,
            enable_ai_defects=True,
            enable_dependency_hallucinations=False,
            **kwargs,
        )
    )


def _bumps(result):
    return [f for f in result.get("ai_defects", []) if f["rule_id"] == "SKY-A106"]


@pytest.mark.parametrize("with_source", [False, True])
def test_analyzer_reports_mirrored_bump_with_and_without_source(repo, with_source):
    if with_source:
        assert write_text_no_symlink(repo / "app.py", "answer = 42\n")
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))

    findings = _bumps(_analyze(repo))

    assert len(findings) == 1
    assert findings[0]["file"] == str(repo / "pyproject.toml")
    assert findings[0]["line"] == 4
    assert findings[0]["severity"] == "LOW"
    assert findings[0]["metadata"]["signal_only"] is True
    assert findings[0]["metadata"]["blocking_recommended"] is False


def test_analyzer_reports_committed_pr_bump(repo, monkeypatch):
    base = _git(repo, "rev-parse", "HEAD")
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))
    _git(repo, "add", "pyproject.toml")
    _commit(repo, "release version")
    monkeypatch.setenv("SKYLOS_DIFF_BASE", base)

    findings = _bumps(_analyze(repo, changed_files={str(repo / "pyproject.toml")}))

    assert len(findings) == 1
    assert findings[0]["line"] == 4


@pytest.mark.parametrize("with_source", [False, True])
def test_analyzer_respects_project_ignore(repo, with_source):
    if with_source:
        assert write_text_no_symlink(repo / "app.py", "answer = 42\n")
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))

    result = _analyze(repo, project_config_overrides={"ignore": ["SKY-A106"]})

    assert _bumps(result) == []


def test_analyzer_does_not_enable_advisory_without_ai_defects(repo):
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))

    result = json.loads(analyze(str(repo), enable_dependency_hallucinations=False))

    assert _bumps(result) == []


def test_single_dependency_file_uses_ancestor_project_evidence(repo):
    requirements = repo / "requirements-dev.txt"
    assert write_text_no_symlink(requirements, "other-library==1.2.3\n")
    _git(repo, "add", "requirements-dev.txt")
    _commit(repo, "add development requirement")
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))
    assert write_text_no_symlink(requirements, "other-library==1.2.4\n")

    findings = _bumps(_analyze(requirements))

    assert len(findings) == 1
    assert findings[0]["file"] == str(requirements)
    assert findings[0]["line"] == 1


def test_explicit_empty_changed_files_does_not_scan_local_changes(repo):
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))

    assert _bumps(_analyze(repo, changed_files=set())) == []


def test_pr_does_not_mix_committed_project_with_working_dependency(repo, monkeypatch):
    base = _git(repo, "rev-parse", "HEAD")
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4", "1.2.3"))
    _git(repo, "add", "pyproject.toml")
    _commit(repo, "change project version only")
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))
    monkeypatch.setenv("SKYLOS_DIFF_BASE", base)

    assert _bumps(_analyze(repo)) == []


def test_pr_findings_use_committed_snapshot_even_with_dirty_worktree(repo, monkeypatch):
    base = _git(repo, "rev-parse", "HEAD")
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))
    _git(repo, "add", "pyproject.toml")
    _commit(repo, "release version")
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4", "9.0.0"))
    monkeypatch.setenv("SKYLOS_DIFF_BASE", base)

    assert len(_bumps(_analyze(repo))) == 1


def test_pr_uses_merge_base_not_new_base_tip(repo, monkeypatch):
    initial = _git(repo, "rev-parse", "HEAD")
    _git(repo, "switch", "-c", "release")
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))
    _git(repo, "add", "pyproject.toml")
    _commit(repo, "release version")
    _git(repo, "switch", "-c", "base-moved", initial)
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.5"))
    _git(repo, "add", "pyproject.toml")
    _commit(repo, "independent base update")
    _git(repo, "switch", "release")
    monkeypatch.setenv("SKYLOS_DIFF_BASE", "base-moved")

    assert len(_bumps(_analyze(repo))) == 1


def test_invalid_base_does_not_fall_back_to_local_changes(repo, monkeypatch):
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))
    monkeypatch.setenv("SKYLOS_DIFF_BASE", "missing-branch")

    assert _bumps(_analyze(repo)) == []


@pytest.mark.parametrize("with_source", [False, True])
def test_detector_error_does_not_stop_other_analysis(repo, monkeypatch, with_source):
    from skylos.rules.ai_defect import dependency_bump_scan

    if with_source:
        assert write_text_no_symlink(repo / "app.py", "answer = 42\n")

    def fail(*args, **kwargs):
        raise RuntimeError("detector failure")

    monkeypatch.setattr(dependency_bump_scan, "scan_mirrored_dependency_bumps", fail)

    result = _analyze(repo)

    assert "analysis_summary" in result
    assert _bumps(result) == []


def test_nested_project_relative_paths_and_excludes(repo):
    from skylos.rules.ai_defect.dependency_bump_scan import (
        scan_mirrored_dependency_bumps,
    )

    component = repo / "component"
    component.mkdir()
    assert write_text_no_symlink(component / "pyproject.toml", _manifest("2.0.0"))
    assert write_text_no_symlink(component / "requirements-dev.txt", "library>=2.0.0\n")
    _git(repo, "add", "component/pyproject.toml", "component/requirements-dev.txt")
    _commit(repo, "add separate project")
    assert write_text_no_symlink(component / "pyproject.toml", _manifest("2.0.1"))
    assert write_text_no_symlink(component / "requirements-dev.txt", "library>=2.0.1\n")

    findings = scan_mirrored_dependency_bumps(
        component,
        scan_paths=component,
        changed_files={"pyproject.toml", "requirements-dev.txt"},
        exclude_folders=["requirements*.txt"],
    )

    assert len(findings) == 1
    assert findings[0]["file"] == str(component / "pyproject.toml")


def test_ordinary_dependency_update_without_project_change_is_quiet(repo):
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.3", "1.2.4"))

    assert _bumps(_analyze(repo)) == []


def test_nested_scan_defaults_to_requested_project_not_entire_git_repo(repo):
    from skylos.rules.ai_defect.dependency_bump_scan import (
        scan_mirrored_dependency_bumps,
    )

    component = repo / "component"
    component.mkdir()
    assert write_text_no_symlink(component / "pyproject.toml", _manifest("2.0.0"))
    _git(repo, "add", "component/pyproject.toml")
    _commit(repo, "add separate project")
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))
    assert write_text_no_symlink(component / "pyproject.toml", _manifest("2.0.1"))

    findings = scan_mirrored_dependency_bumps(component)

    assert len(findings) == 1
    assert findings[0]["file"] == str(component / "pyproject.toml")


def test_advisory_does_not_read_git_external_diff_output(repo, monkeypatch):
    from skylos.rules.ai_defect import dependency_bump_scan

    seen = []
    original = dependency_bump_scan.GitContext.run

    def record(context, *args):
        seen.append(args)
        return original(context, *args)

    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))
    monkeypatch.setattr(dependency_bump_scan.GitContext, "run", record)

    assert len(dependency_bump_scan.scan_mirrored_dependency_bumps(repo)) == 1
    diff_calls = [args for args in seen if args[0] == "diff"]
    assert len(diff_calls) == 1
    assert "--no-ext-diff" in diff_calls[0]
    assert "--no-textconv" in diff_calls[0]


def test_staged_bump_uses_index_even_when_worktree_has_other_versions(repo):
    from skylos.rules.ai_defect.dependency_bump_scan import (
        scan_mirrored_dependency_bumps,
    )

    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))
    _git(repo, "add", "pyproject.toml")
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.5", "8.0.0"))

    findings = scan_mirrored_dependency_bumps(repo, staged=True)

    assert len(findings) == 1
    assert findings[0]["file"] == str(repo / "pyproject.toml")
    assert "1.2.4" in findings[0]["message"]
    assert "1.2.5" not in findings[0]["message"]


def test_staged_comparison_does_not_mix_in_unstaged_dependency_change(repo):
    from skylos.rules.ai_defect.dependency_bump_scan import (
        scan_mirrored_dependency_bumps,
    )

    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4", "1.2.3"))
    _git(repo, "add", "pyproject.toml")
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))

    assert scan_mirrored_dependency_bumps(repo, staged=True) == []


def test_staged_requirements_use_staged_ancestor_metadata(repo):
    from skylos.rules.ai_defect.dependency_bump_scan import (
        scan_mirrored_dependency_bumps,
    )

    requirements = repo / "requirements-dev.txt"
    assert write_text_no_symlink(requirements, "other-library==1.2.3\n")
    _git(repo, "add", "requirements-dev.txt")
    _commit(repo, "add requirement")
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))
    assert write_text_no_symlink(requirements, "other-library==1.2.4\n")
    _git(repo, "add", "pyproject.toml", "requirements-dev.txt")
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("9.0.0"))

    findings = scan_mirrored_dependency_bumps(
        repo, staged=True, changed_files={"requirements-dev.txt"}
    )

    assert len(findings) == 1
    assert findings[0]["file"] == str(requirements)


@pytest.mark.parametrize(
    "scope", [{"changed_files": set()}, {"exclude_folders": ["pyproject.toml"]}]
)
def test_staged_comparison_respects_requested_scope(repo, scope):
    from skylos.rules.ai_defect.dependency_bump_scan import (
        scan_mirrored_dependency_bumps,
    )

    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))
    _git(repo, "add", "pyproject.toml")

    assert scan_mirrored_dependency_bumps(repo, staged=True, **scope) == []


def test_staged_comparison_uses_head_instead_of_pr_base(repo):
    from skylos.rules.ai_defect.dependency_bump_scan import (
        scan_mirrored_dependency_bumps,
    )

    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))
    _git(repo, "add", "pyproject.toml")

    assert (
        len(scan_mirrored_dependency_bumps(repo, staged=True, diff_base="missing-base"))
        == 1
    )


def test_staged_comparison_ignores_worktree_only_bumps(repo):
    from skylos.rules.ai_defect.dependency_bump_scan import (
        scan_mirrored_dependency_bumps,
    )

    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))

    assert scan_mirrored_dependency_bumps(repo, staged=True) == []


def test_staged_comparison_freezes_index_blob_ids(repo, monkeypatch):
    from skylos.rules.ai_defect import dependency_bump_scan

    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))
    _git(repo, "add", "pyproject.toml")
    original = dependency_bump_scan.GitContext.run

    def change_index_after_read(context, *args):
        result = original(context, *args)
        if args[0] == "ls-files":
            assert write_text_no_symlink(
                repo / "pyproject.toml", _manifest("1.2.5", "8.0.0")
            )
            _git(repo, "add", "pyproject.toml")
        return result

    monkeypatch.setattr(dependency_bump_scan.GitContext, "run", change_index_after_read)

    findings = dependency_bump_scan.scan_mirrored_dependency_bumps(repo, staged=True)

    assert len(findings) == 1
    assert findings[0]["metadata"]["dependency_new_version"] == "1.2.4"


def test_staged_directory_scope_does_not_require_worktree_directory(repo):
    from skylos.rules.ai_defect.dependency_bump_scan import (
        scan_mirrored_dependency_bumps,
    )

    component = repo / "component"
    component.mkdir()
    assert write_text_no_symlink(component / "pyproject.toml", _manifest("2.0.0"))
    _git(repo, "add", "component/pyproject.toml")
    _commit(repo, "add component")
    assert write_text_no_symlink(component / "pyproject.toml", _manifest("2.0.1"))
    _git(repo, "add", "component/pyproject.toml")
    component.rename(repo / "moved-component")

    findings = scan_mirrored_dependency_bumps(repo, staged=True, scan_paths=component)

    assert len(findings) == 1
    assert findings[0]["file"] == str(component / "pyproject.toml")


def test_split_setup_dependency_locations_stay_in_the_same_project(repo):
    from skylos.cicd.review import filter_findings_to_diff
    from skylos.rules.ai_defect.dependency_bump_scan import (
        scan_mirrored_dependency_bumps,
    )

    component = repo / "component"
    component.mkdir()
    old_setup = (
        "from setuptools import setup\n"
        "setup(\n"
        "    name='component',\n"
        "    version='2.0.0',\n"
        "    install_requires=[\n"
        "        'other-library=='\n"
        "        '2.0.0',\n"
        "    ],\n"
        ")\n"
    )
    assert write_text_no_symlink(component / "setup.py", old_setup)
    _git(repo, "add", "component/setup.py")
    _commit(repo, "add static packaging metadata")
    assert write_text_no_symlink(
        component / "setup.py", old_setup.replace("2.0.0", "2.0.1")
    )
    _git(repo, "add", "component/setup.py")

    findings = scan_mirrored_dependency_bumps(repo, staged=True)

    assert len(findings) == 1
    assert findings[0]["line"] == 7
    assert findings[0]["related_locations"][0]["file"] == str(component / "setup.py")
    assert (
        filter_findings_to_diff(
            findings, [{"file": "component/setup.py", "start": 7, "end": 7}]
        )
        == findings
    )
