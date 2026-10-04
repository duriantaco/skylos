import ast
from pathlib import Path
import shlex

import pytest
import yaml

from skylos.cli_core.main_parser import build_main_parser
from skylos.cloud.sync_setup import cloud_workflow_content, write_cloud_workflow
from skylos.rules.config.cicd.github_actions import scan_github_actions


EXAMPLE = (
    Path(__file__).resolve().parents[1]
    / ".github/workflows/examples/skylos-tokenless-ci.yml"
)


@pytest.fixture(params=["generated", "example"])
def workflow(request):
    text = (
        cloud_workflow_content()
        if request.param == "generated"
        else EXAMPLE.read_text(encoding="utf-8")
    )
    return yaml.safe_load(text)


def _evaluate_condition(expression, context):
    """Evaluate only the Actions operations used by these job guards."""

    def value(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Attribute):
            return value(node.value)[node.attr]
        if isinstance(node, ast.Name):
            return context[node.id]
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
            return all(value(item) for item in node.values)
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            assert isinstance(node.ops[0], ast.Eq)
            return value(node.left) == value(node.comparators[0])
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id == "format" and not node.keywords
            template, *arguments = [value(item) for item in node.args]
            return template.format(*arguments)
        raise AssertionError(f"Unsupported workflow condition: {ast.dump(node)}")

    tree = ast.parse(expression.replace("&&", "and"), mode="eval")
    return value(tree.body)


@pytest.mark.parametrize(
    "default_branch",
    ["main", "master", "trunk", "release/2026", "team's-trunk", "release/$(id)"],
)
@pytest.mark.parametrize(
    ("event", "ref_template", "expected"),
    [
        ("push", "refs/heads/{branch}", True),
        ("push", "refs/heads/feature", False),
        ("push", "refs/tags/{branch}", False),
        ("pull_request", "refs/pull/1/merge", False),
        ("pull_request_target", "refs/heads/{branch}", False),
        ("workflow_dispatch", "refs/heads/{branch}", False),
    ],
)
def test_upload_job_accepts_only_default_branch_push(
    workflow, default_branch, event, ref_template, expected
):
    ref = ref_template.format(branch=default_branch)
    context = {
        "github": {
            "event_name": event,
            "ref": ref,
            "event": {"repository": {"default_branch": default_branch}},
        }
    }
    assert (
        _evaluate_condition(workflow["jobs"]["cloud-upload"]["if"], context) is expected
    )


def test_pr_scan_has_no_upload_authority(workflow):
    assert workflow["permissions"] == {}
    assert set(workflow["on"]) == {"push", "pull_request"}
    assert workflow["on"]["push"] is None
    assert workflow["on"]["pull_request"] is None
    job = workflow["jobs"]["pull-request"]
    assert job["permissions"] == {"contents": "read"}
    assert "environment" not in job
    context = {"github": {"event_name": "pull_request"}}
    assert _evaluate_condition(job["if"], context)
    context["github"]["event_name"] = "pull_request_target"
    assert not _evaluate_condition(job["if"], context)
    runs = [step["run"] for step in job["steps"] if "run" in step]
    assert all(
        "sync pull" not in run and "--upload" not in shlex.split(run) for run in runs
    )
    scan = next(run for run in runs if run.startswith("skylos ."))
    args = build_main_parser(version="test").parse_args(shlex.split(scan)[1:])
    assert args.no_upload and not args.upload
    assert not args.trace and not args.allow_coverage_execution
    assert not args.pytest_fixtures


def test_upload_commands_parse_and_preserve_cloud_policy_errors(workflow):
    job = workflow["jobs"]["cloud-upload"]
    assert job["permissions"] == {"contents": "read", "id-token": "write"}
    assert "environment" not in job
    steps = job["steps"]
    sync_index = next(
        i for i, step in enumerate(steps) if step.get("run") == "skylos sync pull"
    )
    scan_index = next(
        i for i, step in enumerate(steps) if step.get("run", "").startswith("skylos .")
    )
    assert sync_index < scan_index
    assert steps[sync_index].get("continue-on-error", False) is False
    scan = steps[scan_index]
    args = build_main_parser(version="test").parse_args(shlex.split(scan["run"])[1:])
    assert args.upload and not args.no_upload and not args.force
    assert scan["env"] == {
        "SKYLOS_COMMIT": "${{ github.sha }}",
        "SKYLOS_BRANCH": "${{ github.ref_name }}",
    }
    for current in workflow["jobs"].values():
        for step in current["steps"]:
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False
            if step.get("name") == "Install Skylos":
                assert shlex.split(step["run"])[:4] == ["python", "-I", "-m", "pip"]
            assert "SKYLOS_TOKEN" not in step.get("env", {})


def test_installer_writes_the_cloud_pinned_workflow_path(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    write_cloud_workflow()
    path = tmp_path / ".github/workflows/skylos.yml"
    assert path.read_text(encoding="utf-8") == cloud_workflow_content()
    assert scan_github_actions(tmp_path) == []


def test_example_passes_actions_security_audit(tmp_path):
    path = tmp_path / ".github/workflows/skylos.yml"
    path.parent.mkdir(parents=True)
    path.write_text(EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    assert scan_github_actions(tmp_path) == []
