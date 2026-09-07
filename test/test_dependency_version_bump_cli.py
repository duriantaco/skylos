"""CLI and staged metadata regressions; packaging fixtures are never executed."""

import contextlib
import io
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink


_GIT_ENV = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_PREFIX",
    "GIT_INTERNAL_SUPER_PREFIX",
    "SKYLOS_DIFF_BASE",
    "GITHUB_BASE_REF",
    "SKYLOS_TOKEN",
)


def _manifest(version, dependency_version=None, config=""):
    dependency_version = dependency_version or version
    return (
        '[project]\nname = "local-app"\n'
        f'version = "{version}"\n'
        f'dependencies = ["local-library>={dependency_version}"]\n' + config
    )


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, content)


def _git(repo, *args):
    return subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Skylos Test",
            "-c",
            "user.email=skylos-test@example.invalid",
            *args,
        ],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    for name in _GIT_ENV:
        monkeypatch.delenv(name, raising=False)
    root = tmp_path / "metadata repo"
    root.mkdir()
    _git(root, "init", "-q")
    _write(root / "pyproject.toml", _manifest("1.2.3"))
    _git(root, "add", "pyproject.toml")
    _git(root, "commit", "-qm", "initial metadata")
    monkeypatch.chdir(root)
    return root


def _cli(monkeypatch, *args):
    import skylos.cli as cli
    import skylos.cloud.sync as cloud

    def no_network(*args, **kwargs):
        raise OSError("network disabled in metadata-only integration tests")

    original = cli.run_analyze

    def local_analysis(*args, **kwargs):
        # A106 itself is unmocked; unrelated package-registry checks stay off.
        kwargs["enable_dependency_hallucinations"] = False
        return original(*args, **kwargs)

    output = io.StringIO()
    with monkeypatch.context() as patch:
        patch.setattr(cli, "run_analyze", local_analysis)
        patch.setattr(cloud, "get_token", lambda *args, **kwargs: None)
        patch.setattr(socket.socket, "connect", no_network)
        patch.setattr(socket, "create_connection", no_network)
        patch.setattr(sys, "argv", ["skylos", *map(str, args)])
        with contextlib.redirect_stdout(output):
            try:
                cli.main()
            except SystemExit as exc:
                status = exc.code
            else:
                status = 0
    return status, output.getvalue()


def _bumps(payload):
    findings = payload if isinstance(payload, list) else payload.get("ai_defects", [])
    return [finding for finding in findings if finding.get("rule_id") == "SKY-A106"]


def _hook(monkeypatch, repo):
    status, output = _cli(monkeypatch, "agent", "pre-commit", repo, "--format", "json")
    findings = json.loads(output) if output.lstrip().startswith("[") else []
    return status, _bumps(findings), output


@pytest.mark.parametrize("with_source", [False, True])
@pytest.mark.parametrize("mode", ["--diff", "--diff-base", "auto"])
def test_committed_cli_bump_uses_requested_base(repo, monkeypatch, with_source, mode):
    if with_source:
        _write(repo / "app.py", '"""Inert source fixture."""\n')
        _git(repo, "add", "app.py")
        _git(repo, "commit", "-qm", "source fixture")
    base = _git(repo, "rev-parse", "HEAD")
    _write(repo / "pyproject.toml", _manifest("1.2.4"))
    _git(repo, "add", "pyproject.toml")
    _git(repo, "commit", "-qm", "version change")
    if mode == "auto":
        _git(repo, "update-ref", "refs/remotes/origin/main", base)
        flags = ["--diff"]
    else:
        flags = [mode, base]

    status, output = _cli(
        monkeypatch,
        repo,
        "--select",
        "SKY-A106",
        "--format",
        "json",
        "--no-upload",
        *flags,
    )

    assert status == 0
    findings = _bumps(json.loads(output))
    assert len(findings) == 1
    assert findings[0]["line"] == 4


@pytest.mark.parametrize("companion", [None, "app.py", "Dockerfile"])
@pytest.mark.parametrize("dirty", [False, True])
def test_precommit_scans_same_staged_metadata_in_all_contexts(
    repo, monkeypatch, companion, dirty
):
    contents = {
        "app.py": '"""Original source fixture."""\n',
        "Dockerfile": 'FROM scratch\nUSER 1000\nWORKDIR /app\nLABEL stage="one"\n',
    }
    if companion:
        _write(repo / companion, contents[companion])
        _git(repo, "add", companion)
        _git(repo, "commit", "-qm", "companion fixture")
        _write(
            repo / companion,
            contents[companion].replace("Original", "Updated").replace("one", "two"),
        )
        _git(repo, "add", companion)
    _write(repo / "pyproject.toml", _manifest("1.2.4"))
    _git(repo, "add", "pyproject.toml")
    if dirty:
        _write(repo / "pyproject.toml", "# Working-only comment\n" + _manifest("1.2.4"))

    status, findings, output = _hook(monkeypatch, repo)

    assert status == 1, output  # Existing AI-defect gate policy is unchanged.
    assert len(findings) == 1
    assert findings[0]["line"] == 4
    assert Path(findings[0]["file"]).name == "pyproject.toml"


@pytest.mark.parametrize("filename", ["requirements.txt", "uv.lock"])
def test_precommit_accepts_supported_dependency_metadata(repo, monkeypatch, filename):
    def dependency(version):
        if filename.endswith(".txt"):
            return f"another-library=={version}\n"
        return (
            f'version = 1\n[[package]]\nname = "another-library"\nversion = "{version}"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
        )

    _write(repo / filename, dependency("1.2.3"))
    _git(repo, "add", filename)
    _git(repo, "commit", "-qm", "dependency metadata")
    _write(repo / "pyproject.toml", _manifest("1.2.4", "1.2.3"))
    _write(repo / filename, dependency("1.2.4"))
    _git(repo, "add", "pyproject.toml", filename)

    status, findings, output = _hook(monkeypatch, repo)

    assert status == 1, output
    assert len(findings) == 1
    assert Path(findings[0]["file"]).name == filename


def test_precommit_does_not_mix_unstaged_dependency_edit(repo, monkeypatch):
    _write(repo / "pyproject.toml", _manifest("1.2.4", "1.2.3"))
    _git(repo, "add", "pyproject.toml")
    _write(repo / "pyproject.toml", _manifest("1.2.4"))

    status, findings, output = _hook(monkeypatch, repo)

    assert status == 0, output
    assert findings == []


@pytest.mark.parametrize(
    "setting", ['ignore = ["SKY-A106"]', 'exclude = ["pyproject.toml"]']
)
@pytest.mark.parametrize("staged_setting", [False, True])
def test_precommit_uses_staged_config_context(
    repo, monkeypatch, setting, staged_setting
):
    config = "\n[tool.skylos]\n" + setting + "\n"
    _write(
        repo / "pyproject.toml",
        _manifest("1.2.4", config=config if staged_setting else ""),
    )
    _git(repo, "add", "pyproject.toml")
    _write(
        repo / "pyproject.toml",
        _manifest("1.2.4", config="" if staged_setting else config),
    )

    status, findings, output = _hook(monkeypatch, repo)

    assert status == (0 if staged_setting else 1), output
    assert len(findings) == (0 if staged_setting else 1)


def test_precommit_keeps_changed_adjacent_setup_literal(repo, monkeypatch):
    source = (
        "from setuptools import setup\n"
        "setup(\n"
        '    name="component",\n'
        '    version="1.2.3",\n'
        "    install_requires=[\n"
        '        "another-library>="\n'
        '        "1.2.3",\n'
        "    ],\n"
        ")\n"
    )
    _write(repo / "component/setup.py", source)
    _git(repo, "add", "component/setup.py")
    _git(repo, "commit", "-qm", "literal metadata fixture")
    _write(repo / "component/setup.py", source.replace("1.2.3", "1.2.4"))
    _git(repo, "add", "component/setup.py")

    status, findings, output = _hook(monkeypatch, repo)

    assert status == 1, output
    assert len(findings) == 1
    assert Path(findings[0]["file"]).name == "setup.py"


def test_diff_comparison_base_does_not_change_other_detectors_environment(
    repo, monkeypatch
):
    import os

    base = _git(repo, "rev-parse", "HEAD")
    _write(repo / "pyproject.toml", _manifest("1.2.4"))
    _git(repo, "add", "pyproject.toml")
    _git(repo, "commit", "-qm", "version change")
    monkeypatch.setenv("SKYLOS_DIFF_BASE", "HEAD")

    status, output = _cli(
        monkeypatch,
        repo,
        "--select",
        "SKY-A106",
        "--diff",
        base,
        "--format",
        "json",
        "--no-upload",
    )

    assert status == 0
    assert len(_bumps(json.loads(output))) == 1
    assert os.environ["SKYLOS_DIFF_BASE"] == "HEAD"
