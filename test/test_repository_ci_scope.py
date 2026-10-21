"""Repository CI contracts survive selected-source scans and unrelated edits."""

import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from skylos import cli
from skylos.analyzer import analyze
from skylos.core.git_context import GitContext
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.config import scan_config_files

_WORKFLOW = (
    "name: CI\n"
    "on:\n"
    "  push:\n"
    "    branches: [main]\n"
    "jobs:\n"
    "  test:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: actions/checkout@v4\n"
    "      - uses: someorg/build-action@v1\n"
    "      - run: echo hello\n"
    "  release:\n"
    "    runs-on: ubuntu-latest\n"
    "    permissions:\n"
    "      contents: write\n"
    "    steps:\n"
    "      - uses: actions/checkout@v4\n"
    "      - uses: someorg/build-action@v1\n"
)
# Any security finding fails the gate: the point is that repository CI findings
# reach it, whatever their severity (an unpinned GitHub-owned action is LOW).
_CONFIG = "[tool.skylos]\n\n[tool.skylos.gate]\nmax_security = 0\n"
_SOURCE = "answer = 42\nprint(answer)\n"
_RULE_COUNTS = Counter({"SKY-D291": 1, "SKY-D292": 2, "SKY-D293": 1})
_RECORD_SIGNATURES = {
    ("SKY-D291", "MEDIUM", 1),
    ("SKY-D292", "LOW", 9),
    ("SKY-D292", "HIGH", 10),
    ("SKY-D293", "MEDIUM", 17),
}


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text, encoding="utf-8")
    return path


def _git(repo: Path, *args: str) -> str:
    # Only the test's private fixture is mutated; global hooks and signing are off.
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    return subprocess.run(
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
        check=True,
        text=True,
        capture_output=True,
        env=env,
    ).stdout.strip()


def _create_repo(repo: Path) -> Path:
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Skylos Tests")
    _git(repo, "config", "user.email", "skylos-tests@example.invalid")
    _write(repo / "pyproject.toml", _CONFIG)
    _write(repo / "README.md", "Fixture repository\n")
    _write(repo / "src" / "app.py", _SOURCE)
    _write(repo / ".github" / "workflows" / "ci.yml", _WORKFLOW)
    _git(
        repo,
        "add",
        "--",
        "pyproject.toml",
        "README.md",
        "src/app.py",
        ".github/workflows/ci.yml",
    )
    _git(repo, "commit", "-qm", "fixture baseline")
    return repo


@pytest.fixture
def repository(tmp_path, monkeypatch):
    # This contract is a local full scan, independent of the runner's PR identity.
    for key in tuple(os.environ):
        if key.startswith(("GIT_", "GITHUB_", "GITLAB_", "SKYLOS_")) or key == "CI":
            monkeypatch.delenv(key)
    repo = _create_repo(tmp_path / "repo")
    monkeypatch.chdir(repo)
    return repo


def _edit_readme(repo: Path, state: str) -> None:
    if state in {"dirty-readme", "staged-readme"}:
        _write(repo / "README.md", "Unrelated documentation edit\n")
        if state == "staged-readme":
            _git(repo, "add", "--", "README.md")
    elif state == "untracked-only":
        _write(repo / "notes.md", "Untracked documentation\n")


def _analyze(target: Path | list[Path], **kwargs):
    selected = (
        [str(path) for path in target] if isinstance(target, list) else str(target)
    )
    return json.loads(
        analyze(
            selected,
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            grep_cache=False,
            **kwargs,
        )
    )


def _workflow_records(result, repo: Path):
    path = repo / ".github" / "workflows" / "ci.yml"
    return [item for item in result.get("danger", []) if Path(item["file"]) == path]


def _assert_workflow(result, repo: Path) -> None:
    findings = _workflow_records(result, repo)
    assert len(findings) == len(_RECORD_SIGNATURES)
    assert Counter(item["rule_id"] for item in findings) == _RULE_COUNTS
    assert {
        (item["rule_id"], item["severity"], item["line"]) for item in findings
    } == _RECORD_SIGNATURES
    assert result.get("analysis_errors", []) == []


@pytest.mark.parametrize("target", [".", "src"])
@pytest.mark.parametrize(
    "state", ["clean", "dirty-readme", "staged-readme", "untracked-only"]
)
def test_full_analysis_keeps_repository_ci_findings(repository, target, state):
    baseline = _workflow_records(_analyze(repository), repository)
    _edit_readme(repository, state)
    result = _analyze(repository / target)
    _assert_workflow(result, repository)
    assert _workflow_records(result, repository) == baseline


@pytest.mark.parametrize("target", [".", "src"])
@pytest.mark.parametrize(
    "state", ["clean", "dirty-readme", "staged-readme", "untracked-only"]
)
def test_cli_gate_keeps_repository_ci_findings(
    repository, target, state, monkeypatch, capsys
):
    _edit_readme(repository, state)
    # Disconnect the optional Cloud loader only; detectors and gate run normally.
    monkeypatch.setattr("skylos.cloud.sync.get_token", lambda: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "skylos",
            target,
            "--danger",
            "--gate",
            "--format",
            "json",
            "--no-upload",
            "--no-provenance",
            "--no-grep-verify",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    result = json.loads(capsys.readouterr().out)
    _assert_workflow(result, repository)
    assert result["gate"]["passed"] is False


@pytest.mark.parametrize("selection", ["empty", "source-only"])
def test_explicit_changed_files_do_not_include_unchanged_repository_ci(
    repository, selection
):
    changed = set() if selection == "empty" else {str(repository / "src" / "app.py")}
    result = _analyze(repository / "src", changed_files=changed)
    assert _workflow_records(result, repository) == []
    assert result.get("analysis_errors", []) == []


@pytest.mark.parametrize("relative", [False, True], ids=["absolute", "repo-relative"])
def test_explicit_workflow_selection_reaches_repository_ci_outside_src(
    repository, relative
):
    workflow = repository / ".github" / "workflows" / "ci.yml"
    changed = str(workflow.relative_to(repository)) if relative else str(workflow)
    result = _analyze(repository / "src", changed_files={changed})
    _assert_workflow(result, repository)


def test_repository_ci_does_not_expand_other_config_or_language_scopes(repository):
    _write(
        repository / "Dockerfile",
        "FROM ubuntu:latest\nADD https://example.invalid/file /file\n",
    )
    _write(
        repository / "sibling" / "Dockerfile",
        "FROM ubuntu:latest\nADD https://example.invalid/file /file\n",
    )
    sibling_workflow = _write(
        repository / "sibling" / ".github" / "workflows" / "ci.yml", _WORKFLOW
    )
    _write(repository / "sibling" / "broken.py", "def broken(:\n    pass\n")
    _write(repository / "sibling" / "broken.ts", "export function broken( {\n")
    # Prove the sibling workflow is a real finding rather than a harmless fixture.
    assert (
        len(_workflow_records(_analyze(repository / "sibling"), repository / "sibling"))
        == len(_RECORD_SIGNATURES)
    )
    assert sibling_workflow.is_file()
    result = _analyze(repository / "src")
    _assert_workflow(result, repository)
    assert {Path(item["file"]) for item in result["danger"]} == {
        repository / ".github" / "workflows" / "ci.yml"
    }
    assert result["analysis_summary"]["total_files"] == 1


def test_nested_repository_scan_does_not_import_outer_ci_contract(repository):
    nested = _create_repo(repository / "nested")
    result = _analyze(nested / "src")
    _assert_workflow(result, nested)
    assert _workflow_records(result, repository) == []
    assert {Path(item["file"]) for item in result["danger"]} == {
        nested / ".github" / "workflows" / "ci.yml"
    }


def test_source_file_string_keeps_its_existing_narrow_config_scope(repository):
    result = _analyze(repository / "src" / "app.py")
    assert _workflow_records(result, repository) == []
    assert result.get("analysis_errors", []) == []


def test_empty_selected_source_directory_still_checks_repository_ci(repository):
    empty = repository / "empty-src"
    empty.mkdir()
    result = _analyze(empty)
    _assert_workflow(result, repository)
    assert result["analysis_summary"]["total_files"] == 0


def test_root_gitlab_ci_contract_is_checked_without_sibling_gitlab_configs(repository):
    root_ci = _write(
        repository / ".gitlab-ci.yml",
        "include:\n  - remote: https://example.invalid/ci.yml\n",
    )
    _write(
        repository / "sibling" / ".gitlab-ci.yml",
        "include:\n  - remote: https://example.invalid/sibling.yml\n",
    )
    result = _analyze(repository / "src")
    _assert_workflow(result, repository)
    gitlab = [item for item in result["danger"] if item["rule_id"] == "SKY-D315"]
    assert len(gitlab) == 1
    assert Path(gitlab[0]["file"]) == root_ci


@pytest.mark.parametrize("target", ["src", "empty-src"])
def test_linked_worktree_checks_its_own_ci_contract(repository, tmp_path, target):
    linked = tmp_path / "linked"
    _git(repository, "worktree", "add", "-q", "-b", "fixture-linked", str(linked))
    assert (linked / ".git").is_file()
    if target == "empty-src":
        (linked / "empty-src").mkdir()
    result = _analyze(linked / target)
    _assert_workflow(result, linked)
    assert _workflow_records(result, repository) == []
    assert result["analysis_summary"]["total_files"] == (1 if target == "src" else 0)


def test_nested_project_metadata_does_not_replace_actual_git_ci_root(repository):
    project = repository / "projects" / "library"
    _write(project / "pyproject.toml", _CONFIG)
    _write(project / "src" / "app.py", _SOURCE)
    result = _analyze(project / "src")
    _assert_workflow(result, repository)
    assert result["analysis_summary"]["total_files"] == 1


@pytest.mark.parametrize("component", ["github", "workflows", "workflow", "gitlab"])
def test_repository_ci_symlink_components_are_not_followed(
    repository, tmp_path, component
):
    if component == "gitlab":
        target = _write(
            repository / ".gitlab-ci.yml",
            "include:\n  - remote: https://example.invalid/ci.yml\n",
        )
    else:
        target = {
            "github": repository / ".github",
            "workflows": repository / ".github" / "workflows",
            "workflow": repository / ".github" / "workflows" / "ci.yml",
        }[component]
    outside = tmp_path / ("outside-" + component)
    target.rename(outside)
    target.symlink_to(outside, target_is_directory=component in {"github", "workflows"})
    result = _analyze(repository / "src")
    assert result.get("analysis_errors", []) == []
    if component == "gitlab":
        _assert_workflow(result, repository)
        assert not any(item["rule_id"] == "SKY-D315" for item in result["danger"])
    else:
        assert result.get("danger", []) == []
    assert result["analysis_summary"]["total_files"] == 1


@pytest.mark.parametrize("failure", ["missing-git", "timeout"])
def test_optional_git_proof_failure_keeps_selected_docker_findings(
    repository, monkeypatch, failure
):
    dockerfile = _write(
        repository / "src" / "Dockerfile",
        "FROM ubuntu:latest\nADD https://example.invalid/file /file\n",
    )
    baseline = [
        item
        for item in scan_config_files(repository / "src")
        if Path(item["file"]) == dockerfile
    ]
    assert baseline

    def unavailable(self, *args, **kwargs):
        if failure == "missing-git":
            raise FileNotFoundError("git unavailable in fixture")
        raise subprocess.TimeoutExpired(["git", *args], 10)

    monkeypatch.setattr(GitContext, "run", unavailable)
    findings = scan_config_files(repository / "src")
    assert findings == baseline


@pytest.mark.parametrize("relative", [False, True], ids=["absolute", "repo-relative"])
def test_explicit_workflow_selector_normalizes_parent_components(repository, relative):
    selector = Path("src") / ".." / ".github" / "workflows" / "ci.yml"
    if not relative:
        selector = repository / selector
    result = _analyze(repository / "src", changed_files={str(selector)})
    _assert_workflow(result, repository)


def test_file_list_across_nested_repositories_does_not_import_outer_ci(repository):
    projects = repository / "projects"
    _write(projects / "pyproject.toml", _CONFIG)
    first = _create_repo(projects / "first")
    second = _create_repo(projects / "second")
    selected = [_write(first / "app.py", _SOURCE), _write(second / "app.py", _SOURCE)]
    result = _analyze(selected)
    assert _workflow_records(result, repository) == []
    assert result.get("analysis_errors", []) == []
    assert result["analysis_summary"]["total_files"] == 2


def test_file_list_with_nested_metadata_in_one_worktree_keeps_actual_root_ci(
    repository,
):
    projects = repository / "projects"
    _write(projects / "pyproject.toml", _CONFIG)
    selected = [
        _write(projects / "first" / "app.py", _SOURCE),
        _write(projects / "second" / "app.py", _SOURCE),
    ]
    result = _analyze(selected)
    _assert_workflow(result, repository)
    assert result["analysis_summary"]["total_files"] == 2


def _assert_repository_ci_parse_failure(result, malformed, valid):
    errors = result.get("analysis_errors", [])
    assert len(errors) == 1
    assert errors[0]["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    assert errors[0]["kind"] == "config_parse_error"
    assert errors[0]["component"] == "github_actions"
    assert errors[0]["file"] == str(malformed)
    assert errors[0]["line"] == 1
    assert errors[0]["severity"] == "HIGH"
    records = [item for item in result.get("danger", []) if Path(item["file"]) == valid]
    assert len(records) == len(_RECORD_SIGNATURES)
    assert Counter(item["rule_id"] for item in records) == _RULE_COUNTS
    assert {
        (item["rule_id"], item["severity"], item["line"]) for item in records
    } == _RECORD_SIGNATURES


@pytest.mark.parametrize("target", [".", "src", "empty-src"])
def test_repository_ci_parse_error_reaches_analyzer_and_gate(
    repository, target, monkeypatch, capsys
):
    selected = repository / target
    if target == "empty-src":
        (repository / "empty-src").mkdir()
    malformed = _write(repository / ".github" / "workflows" / "ci.yml", "name: [\n")
    valid = _write(repository / ".github" / "workflows" / "still-valid.yml", _WORKFLOW)

    result = _analyze(selected)
    _assert_repository_ci_parse_failure(result, malformed, valid)
    assert result["analysis_summary"]["total_files"] == (0 if target == "empty-src" else 1)

    # Disconnect optional Cloud only; run the real parser, detectors and gate.
    monkeypatch.setattr("skylos.cloud.sync.get_token", lambda: None)
    monkeypatch.setattr(sys, "argv", [
        "skylos", target, "--danger", "--gate", "--format", "json",
        "--no-upload", "--no-provenance", "--no-grep-verify",
    ])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    result = json.loads(capsys.readouterr().out)
    _assert_repository_ci_parse_failure(result, malformed, valid)


@pytest.mark.parametrize("selection", ["empty", "source-only"])
def test_explicit_change_scope_omits_unchanged_root_ci_parse_error(repository, selection):
    malformed = _write(repository / ".github" / "workflows" / "ci.yml", "name: [\n")
    valid = _write(repository / ".github" / "workflows" / "still-valid.yml", _WORKFLOW)
    changed = set() if selection == "empty" else {str(repository / "src" / "app.py")}
    result = _analyze(repository / "src", changed_files=changed)
    assert result.get("analysis_errors", []) == []
    assert not any(
        Path(item["file"]) in {malformed, valid} for item in result.get("danger", [])
    )
