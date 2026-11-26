"""Exercise the self-scan PR summary command without making GitHub writes."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import venv

import pytest
import yaml

from test.fixture_paths import write_fixture


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/skylos.yaml"


def _workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def _step(name):
    return next(
        step for step in _workflow()["jobs"]["summary"]["steps"]
        if step.get("name") == name
    )


def test_summary_runs_after_failed_scans_with_scoped_comment_permission():
    workflow = _workflow()
    assert workflow["permissions"] == {"contents": "read"}
    assert "permissions" not in workflow["jobs"]["scan"]
    job = workflow["jobs"]["summary"]
    assert job["needs"] == "scan"
    assert "always()" in job["if"] and "!cancelled()" in job["if"]
    assert "github.event_name == 'pull_request'" in job["if"]
    assert "github.event.pull_request.head.repo.full_name == github.repository" in job["if"]
    assert job["permissions"] == {"contents": "read", "pull-requests": "write"}
    assert workflow["concurrency"]["cancel-in-progress"] is True

    steps = job["steps"]
    checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"] == {"fetch-depth": 0, "persist-credentials": False}
    for step in steps:
        if "uses" in step:
            assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", step["uses"])
        if step.get("name") != "Update the PR summary":
            assert "GH_TOKEN" not in step.get("env", {})


def test_summary_uses_the_same_pinned_renderer_and_exact_scan_artifact():
    workflow = _workflow()
    scan_install = next(
        step for step in workflow["jobs"]["scan"]["steps"]
        if step.get("name") == "Install trusted Skylos for pull requests"
    )
    install = _step("Install trusted PR renderer")
    for step in (install, scan_install):
        assert step["env"] == {"TRUSTED_BASE_SHA": "${{ github.event.pull_request.base.sha }}"}
        assert '[[ ! "$TRUSTED_BASE_SHA" =~ ^[0-9a-f]{40}$ ]]' in step["run"]
        assert "skylos.git@$TRUSTED_BASE_SHA" in step["run"]
    assert 'python -I -m venv "$RUNNER_TEMP/skylos-review-venv"' in install["run"]
    assert '"$RUNNER_TEMP/skylos-review-venv/bin/python" -I -m pip install' in install["run"]
    assert "-e ." not in install["run"] and "${{" not in install["run"]

    download = _step("Download the saved scan report")
    assert download["with"] == {
        "name": "${{ env.REPORT }}",
        "path": "${{ runner.temp }}/skylos-review",
    }
    assert download["continue-on-error"] is True
    scan = next(step for step in workflow["jobs"]["scan"]["steps"] if step.get("name") == "Run Skylos")
    assert workflow["jobs"]["summary"]["env"]["REPORT"] == scan["env"]["REPORT"]
    post = _step("Update the PR summary")
    verdict = post["env"]["SKYLOS_GATE_RESULT"]
    assert "needs.scan.result == 'success' && (needs.scan.outputs.policy_result || 'unavailable')" in verdict
    assert "needs.scan.result == 'failure'" in verdict and "'job-failed'" in verdict
    scan_job = workflow["jobs"]["scan"]
    policy = next(step for step in scan_job["steps"] if step.get("id") == "policy")
    assert scan_job["outputs"]["policy_result"] == "${{ steps.policy.outputs.policy_result }}"
    assert 'SKYLOS_GATE_OUTPUT="$GITHUB_OUTPUT"' in policy["run"]
    assert "${{" not in post["run"]


@pytest.fixture(scope="module")
def installed_renderer(tmp_path_factory):
    root = tmp_path_factory.mktemp("trusted-pr-renderer")
    environment = root / "environment"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(environment)
    python = environment / "bin/python"
    purelib = Path(subprocess.check_output(
        [str(python), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        text=True,
    ).strip())
    write_fixture(purelib, "skylos/__init__.py", "")
    write_fixture(purelib, "skylos/cli.py", """import json
import os
from pathlib import Path
import sys

Path(os.environ["REVIEW_INVOCATION"]).write_text(json.dumps({
    "args": sys.argv[1:], "isolated": sys.flags.isolated, "provider": __file__,
}))
raise SystemExit(int(os.environ["REVIEW_STATUS"]))
""")
    return environment, purelib


def _run_summary(tmp_path, installed_renderer, *, gate="success", status=0, overrides=None):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("workflow execution requires bash")
    environment, _ = installed_renderer
    runner_temp = tmp_path / "runner files"
    runner_temp.mkdir()
    (runner_temp / "skylos-review-venv").symlink_to(environment, target_is_directory=True)
    write_fixture(tmp_path, "skylos/__init__.py", """from pathlib import Path
Path('checkout-imported').write_text('untrusted checkout imported')
raise RuntimeError('the renderer must be installed outside the checkout')
""")
    env = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("GH_", "GITHUB_", "SKYLOS_"))
    }
    env.update(
        RUNNER_TEMP=str(runner_temp),
        REPORT="scan report.json",
        PR_BASE_SHA="a" * 40,
        PR_NUMBER="19",
        GITHUB_REPOSITORY="acme/example",
        SKYLOS_GATE_RESULT=gate,
        REVIEW_STATUS=str(status),
        REVIEW_INVOCATION=str(tmp_path / "invocation.json"),
    )
    env.update(overrides or {})
    result = subprocess.run(
        [bash, "-e", "-o", "pipefail", "-c", _step("Update the PR summary")["run"]],
        cwd=tmp_path, env=env, text=True, capture_output=True, timeout=10, check=False,
    )
    return result, runner_temp


@pytest.mark.parametrize("gate", ["success", "failure"])
@pytest.mark.parametrize("status", [0, 2])
def test_actual_summary_command_reuses_report_in_isolated_python(
    tmp_path, installed_renderer, gate, status
):
    result, runner_temp = _run_summary(tmp_path, installed_renderer, gate=gate, status=status)
    assert result.returncode == status, result.stderr
    invocation = json.loads((tmp_path / "invocation.json").read_text())
    assert invocation["args"] == [
        "cicd", "review", ".",
        "--input", str(runner_temp / "skylos-review/scan report.json"),
        "--diff-base", "a" * 40,
        "--pr", "19", "--repo", "acme/example",
        "--summary-only", "--gate-result", gate,
    ]
    assert invocation["isolated"] == 1
    assert Path(invocation["provider"]).samefile(installed_renderer[1] / "skylos/cli.py")
    assert not (tmp_path / "checkout-imported").exists()


@pytest.mark.parametrize("overrides", [
    {"PR_BASE_SHA": ""}, {"PR_BASE_SHA": "not-a-sha"}, {"PR_NUMBER": "not-a-number"},
])
def test_invalid_pr_context_stops_before_the_renderer(tmp_path, installed_renderer, overrides):
    result, _ = _run_summary(tmp_path, installed_renderer, overrides=overrides)
    assert result.returncode == 1
    assert "Invalid pull request identity" in result.stderr
    assert not (tmp_path / "invocation.json").exists()
