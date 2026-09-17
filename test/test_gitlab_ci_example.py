from pathlib import Path
import shlex

import yaml


EXAMPLE = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "examples"
    / "gitlab-code-quality.yml"
)


def _job():
    return yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))["skylos-code-quality"]


def test_gitlab_example_uses_operator_supplied_scanner_image():
    job = _job()
    assert job["image"] == {
        "name": "$SKYLOS_SCANNER_IMAGE",
        "entrypoint": [""],
    }
    assert "SKYLOS_SCANNER_IMAGE" not in job["variables"]
    assert "latest" not in EXAMPLE.read_text(encoding="utf-8")


def test_gitlab_example_isolates_installed_scanner_from_checkout():
    job = _job()
    assert job["script"][0] == "cd /opt/skylos-ci"
    command = shlex.split(job["script"][1])
    assert command[:4] == [
        "/opt/skylos/bin/python",
        "-I",
        "/opt/skylos/bin/skylos",
        "$CI_PROJECT_DIR",
    ]
    assert command[command.index("--config-file") + 1] == (
        "/opt/skylos-ci/pyproject.toml"
    )
    assert "--no-upload" in command
    assert "--no-provenance" in command
    assert "--no-grep-verify" in command


def test_gitlab_example_does_not_inherit_project_execution_steps():
    job = _job()
    assert job["inherit"] == {"default": False, "variables": False}
    for key in ("before_script", "after_script", "services", "cache", "dependencies"):
        assert job[key] == []
    assert job["variables"]["GIT_SUBMODULE_STRATEGY"] == "none"
    script = "\n".join(job["script"])
    for forbidden in ("pip install", "npm ", "pnpm ", "pytest", "--trace", "eval "):
        assert forbidden not in script


def test_gitlab_example_scans_merge_requests_and_default_branch():
    assert _job()["rules"] == [
        {"if": '$CI_PIPELINE_SOURCE == "merge_request_event"'},
        {
            "if": '$CI_PIPELINE_SOURCE == "push" '
            "&& $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH"
        },
        {"when": "never"},
    ]


def test_gitlab_example_retains_full_report_and_gate_failure():
    job = _job()
    command = shlex.split(job["script"][1])
    assert command[command.index("--format") + 1] == "gitlab"
    assert command[command.index("-o") + 1] == (
        "$CI_PROJECT_DIR/gl-code-quality-report.json"
    )
    assert "--gate" in command
    assert job["allow_failure"] is False
    for option in ("--force", "--diff", "--diff-base", "--baseline", "--limit"):
        assert option not in command
    assert "||" not in job["script"][1]
    assert job["artifacts"] == {
        "when": "always",
        "expire_in": "1 week",
        "reports": {"codequality": "gl-code-quality-report.json"},
        "paths": ["gl-code-quality-report.json"],
    }


def test_gitlab_example_enables_static_checks_without_dependency_network():
    job = _job()
    command = shlex.split(job["script"][1])
    for option in ("--danger", "--secrets", "--quality", "--ai-defects"):
        assert option in command
    assert "--sca" not in command
    assert "--all" not in command
    assert "-a" not in command
    assert job["timeout"] == "15m"
    assert job["interruptible"] is True
