"""Exercise the checked-in PostgreSQL workflow steps without GitHub or a package index."""

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ACTION = yaml.safe_load((ROOT / "action.yml").read_text())
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/postgres-policy.yml").read_text())
JOB = WORKFLOW["jobs"]["migration-policy"]
POLICY = (
    '[tool.skylos.sql.production]\ndirectories=["db/prod"]\nforbid_public_writes=true\n'
)


def git(repo, *args):
    return subprocess.check_output(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgSign=false",
            *args,
        ],
        cwd=repo,
        text=True,
    ).strip()


def commit(repo):
    git(repo, "add", "-A")
    git(repo, "commit", "--allow-empty", "-qm", "fixture")
    return git(repo, "rev-parse", "HEAD")


def shell(script, cwd, env):
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
        env={**os.environ, **env},
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )


def step_with_id(steps, name):
    return next(step for step in steps if step.get("id") == name)


@pytest.fixture
def repo(tmp_path):
    repo = tmp_path / "checkout"
    repo.mkdir()
    git(repo, "init", "-q")
    # A checkout that contains an ordinary local package with the same name.
    # Loading it accidentally would make the installed Skylos CLI unavailable.
    (repo / "skylos").mkdir()
    (repo / "skylos" / "__init__.py").touch()
    return repo


@pytest.mark.parametrize(
    ("before", "head", "expected"),
    [
        (None, POLICY, "configured=false"),
        ("[project]\nname='example'\n", POLICY, "configured=false"),
        (POLICY, "[project]\nname='example'\n", "configured=true"),
        ("[bad\n", POLICY, None),
        ("[tool.skylos]\nsql = 'invalid table'\n", POLICY, None),
        ("symlink", POLICY, None),
    ],
)
def test_self_workflow_reads_the_base_config(repo, tmp_path, before, head, expected):
    config = repo / "pyproject.toml"
    if before == "symlink":
        (repo / "other.toml").write_text(POLICY)
        config.symlink_to("other.toml")
    elif before is not None:
        config.write_text(before)
    base = commit(repo)
    if config.is_symlink():
        config.unlink()
    config.write_text(head)
    output = tmp_path / "output"
    result = shell(
        step_with_id(JOB["steps"], "policy")["run"],
        repo,
        {
            "BASE_SHA": base,
            "HEAD_SHA": commit(repo),
            "GITHUB_OUTPUT": str(output),
            "PATH": os.pathsep.join(
                (str(Path(sys.executable).parent), os.environ["PATH"])
            ),
        },
    )
    if expected is None:
        assert result.returncode != 0
    else:
        assert result.returncode == 0, result.stderr
        assert output.read_text().splitlines() == [expected]


@pytest.fixture(scope="module")
def installed_python(tmp_path_factory):
    """Expose the tested scanner and its local dependencies to an isolated interpreter."""
    venv = tmp_path_factory.mktemp("installed-scanner")
    subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True
    )
    python = next(
        p for p in (venv / "bin/python", venv / "Scripts/python.exe") if p.is_file()
    )
    site = subprocess.check_output(
        [
            str(python),
            "-I",
            "-c",
            "import sysconfig; print(sysconfig.get_path('purelib'))",
        ],
        text=True,
    ).strip()
    paths = dict.fromkeys([str(ROOT), *(p for p in sys.path if p and os.path.isabs(p))])
    (Path(site) / "trusted-scanner.pth").write_text("\n".join(paths) + "\n")
    return python


@pytest.mark.parametrize("surface", ["repository", "composite"])
@pytest.mark.parametrize(
    ("sql", "exit_code"),
    [
        ("SELECT 1;", 0),
        ("GRANT UPDATE ON app.t TO PUBLIC;", 1),
    ],
)
def test_workflow_invokes_isolated_scanner_on_committed_change(
    repo, tmp_path, installed_python, surface, sql, exit_code
):
    pytest.importorskip("pglast")
    (repo / "pyproject.toml").write_text(POLICY)
    base = commit(repo)
    migration = repo / "db/prod/001.sql"
    migration.parent.mkdir(parents=True)
    migration.write_text(sql)
    (repo / "pyproject.toml").write_text("")
    head = commit(repo)
    migration.write_text("SELECT 1;")

    # Replace environment provisioning and package download. The policy process
    # itself runs the real scanner with the exact workflow arguments and cwd.
    wrapper = tmp_path / "python"
    wrapper.write_text("""#!/usr/bin/env bash
set -eu
if [[ "${1:-} ${2:-} ${3:-}" == '-I -m venv' ]]; then
    mkdir -p "$4/bin"
    cp "$0" "$4/bin/python"
elif [[ "${1:-} ${2:-} ${3:-} ${4:-}" == '-I -m pip install' ]]; then
    printf '%s\\n' "${@:5}" > "$INSTALLED_FROM"
else
    exec "$SCANNER_PYTHON" "$@"
fi
""")
    wrapper.chmod(0o755)
    installed_from = tmp_path / "source"
    env = {
        "BASE_SHA": base,
        "HEAD_SHA": head,
        "RUNNER_TEMP": str(tmp_path),
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "SCANNER_PYTHON": str(installed_python),
        "INSTALLED_FROM": str(installed_from),
        "SKYLOS_ACTION_PATH": str(ROOT),
    }
    if surface == "repository":
        step = next(
            step for step in JOB["steps"] if "postgres-check" in step.get("run", "")
        )
        assert step["if"] == "steps.policy.outputs.configured == 'true'"
        result = shell(step["run"], repo, env)
        assert installed_from.read_text().splitlines() == [
            f"skylos[postgres] @ git+https://github.com/duriantaco/skylos.git@{base}"
        ]
    else:
        steps = ACTION["runs"]["steps"]
        install = next(step for step in steps if step["name"] == "Install Skylos")
        assert install["env"]["SKYLOS_ACTION_PATH"] == "${{ github.action_path }}"
        assert shell(install["run"], repo, env).returncode == 0
        assert installed_from.read_text().strip().startswith(str(ROOT) + "[")
        assert "postgres" in installed_from.read_text()
        result = shell(step_with_id(steps, "postgres_policy")["run"], repo, env)
    assert result.returncode == exit_code, result.stdout + result.stderr
    assert "1 files checked" in result.stdout
    assert ("SKY-D420" in result.stdout) is bool(exit_code)


def test_workflow_permission_and_action_gate_contract():
    assert WORKFLOW["permissions"] == {"contents": "read"}
    checkout = next(
        step
        for step in JOB["steps"]
        if step.get("uses", "").startswith("actions/checkout@")
    )
    assert checkout["with"] == {"fetch-depth": 0, "persist-credentials": False}
    assert "merge_group.base_sha" in JOB["env"]["BASE_SHA"]
    assert "pull_request.base.sha" in JOB["env"]["BASE_SHA"]
    assert JOB["env"]["HEAD_SHA"] == "${{ github.sha }}"
    steps = ACTION["runs"]["steps"]
    policy = step_with_id(steps, "postgres_policy")
    assert ACTION["inputs"]["postgres-policy"]["default"] == "false"
    assert policy["if"] == (
        "inputs.image == '' && inputs.postgres-policy == 'true' && "
        "(github.event_name == 'pull_request' || github.event_name == 'merge_group') && "
        "(inputs.mode == 'gate' || inputs.mode == 'review')"
    )
    assert policy["env"]["BASE_SHA"] == JOB["env"]["BASE_SHA"]
    assert policy["env"]["HEAD_SHA"] == "${{ github.sha }}"
    assert not policy.get("continue-on-error")
    assert ACTION["outputs"]["gate-passed"]["value"] == (
        "${{ steps.postgres_policy.outcome == 'failure' && 'false' || "
        "steps.gate.outputs.passed || steps.image_scan.outputs.passed }}"
    )
    for step in steps:
        for flags in re.findall(
            r"\bpython((?:[ \t]+-[A-Za-z]+)*)[ \t]+-m[ \t]+skylos\b",
            step.get("run", ""),
        ):
            assert "-I" in flags.split(), step["name"]


def test_composite_scan_before_policy_uses_installed_scanner(
    repo, tmp_path, installed_python
):
    commit(repo)
    output = tmp_path / "output"
    summary = tmp_path / "summary"
    result = shell(
        step_with_id(ACTION["runs"]["steps"], "scan")["run"],
        repo,
        {
            "PATH": str(installed_python.parent) + os.pathsep + os.environ["PATH"],
            "SKYLOS_PATH": ".",
            "SKYLOS_ANALYSIS": "dead-code",
            "SKYLOS_CONFIDENCE": "60",
            "SKYLOS_UPLOAD_SARIF": "false",
            "SKYLOS_DIFF_MODE": "false",
            "SKYLOS_TOKEN": "",
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(summary),
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "report=skylos-report.json" in output.read_text()
    assert "findings_count=" in output.read_text()
    assert (repo / "skylos-report.json").is_file()
