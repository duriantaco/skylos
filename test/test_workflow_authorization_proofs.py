"""Naming an environment or permission check does not enforce authorization."""

import pytest
import yaml

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.config.cicd.github_actions import scan_github_actions_file


def _scan(
    tmp_path,
    *,
    environment=None,
    condition=None,
    runner="ubuntu-latest",
    trigger="pull_request_target",
    pr_code=True,
    timeout=None,
    guard=None,
):
    folder = tmp_path / ".github" / "workflows"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "ci.yml"
    checkout = {"uses": "actions/checkout@v4"}
    if pr_code:
        checkout["with"] = {"ref": "${{ github.event.pull_request.head.sha }}"}
    job = {
        "runs-on": runner,
        "steps": [
            checkout,
            {
                "run": 'claude -p "Review ${{ github.event.pull_request.body }}" --dangerously-skip-permissions',
                "env": {"ANTHROPIC_API_KEY": "${{ secrets.AGENT_KEY }}"},
            },
        ],
    }
    if environment is not None:
        job["environment"] = environment
    if condition is not None:
        job["if"] = condition
    if timeout is not None:
        job["timeout-minutes"] = timeout
    jobs = {"review": job}
    if guard is not None:
        jobs["authorize"] = guard
        job["needs"] = "authorize"
    workflow = {
        "name": "Review",
        "on": trigger,
        "permissions": {"contents": "write"},
        "jobs": jobs,
    }
    assert write_text_no_symlink(path, yaml.safe_dump(workflow), encoding="utf-8")
    return scan_github_actions_file(path, root=tmp_path)


def _ids(findings):
    return {finding["rule_id"] for finding in findings}


@pytest.mark.parametrize(
    "environment",
    [
        "preview",
        "${{ 'preview' }}",
        "${{ inputs.environment }}",
        "${{ matrix.environment }}",
        "${{ github.actor }}",
        "${{ github.event.pull_request.head.ref }}",
        "${{ github.event.pull_request.head.repo.fork && 'approval' || 'preview' }}",
        "${{ github.event.pull_request.author_association == 'OWNER' && 'trusted' || 'approval' }}",
        {"name": "${{ 'preview' }}"},
    ],
)
def test_environment_selection_does_not_prove_approval(tmp_path, environment):
    ids = _ids(_scan(tmp_path, environment=environment))
    assert {"SKY-D293", "SKY-D313", "SKY-D350"} <= ids


def test_actual_job_actor_guard_blocks_outsider_reachability(tmp_path):
    findings = _scan(
        tmp_path, condition="github.event.pull_request.author_association == 'OWNER'"
    )
    assert not ({"SKY-D293", "SKY-D313", "SKY-D350"} & _ids(findings))


def test_actual_dependency_guard_blocks_outsider_reachability(tmp_path):
    guard = {
        "if": "github.event.pull_request.author_association == 'OWNER'",
        "runs-on": "ubuntu-latest",
        "steps": [{"run": "echo approved"}],
    }
    assert not (
        {"SKY-D293", "SKY-D313", "SKY-D350"} & _ids(_scan(tmp_path, guard=guard))
    )
    # A status override intentionally bypasses the skipped dependency.
    assert {"SKY-D293", "SKY-D313", "SKY-D350"} <= _ids(
        _scan(tmp_path, guard=guard, condition="always()")
    )


def test_dependency_environment_does_not_prove_approval(tmp_path):
    guard = {
        "environment": "${{ 'approval' }}",
        "steps": [{"run": "echo approved"}],
        "runs-on": "ubuntu-latest",
    }
    assert {"SKY-D293", "SKY-D313", "SKY-D350"} <= _ids(_scan(tmp_path, guard=guard))


@pytest.mark.parametrize("runner", ["ubuntu-latest", ["self-hosted", "linux"]])
def test_timeout_requires_the_outsider_pr_code_path(tmp_path, runner):
    assert "SKY-D313" not in _ids(_scan(tmp_path, runner=runner, trigger="push"))
    assert "SKY-D313" not in _ids(_scan(tmp_path, runner=runner, pr_code=False))
    assert "SKY-D313" not in _ids(_scan(tmp_path, runner=runner, timeout=15))
    assert "SKY-D313" in _ids(_scan(tmp_path, runner=runner))
