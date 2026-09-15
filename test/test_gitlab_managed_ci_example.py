"""Static validation of the documented job; no GitLab pipeline execution."""

from pathlib import Path
import shlex

import yaml


EXAMPLE = (
    Path(__file__).resolve().parents[1] / "docs/examples/gitlab-managed-upload.yml"
)


def _job():
    return yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))["skylos-managed-upload"]


def test_managed_job_uses_short_lived_audience_bound_id_token():
    job = _job()
    assert job["id_tokens"] == {"SKYLOS_GITLAB_ID_TOKEN": {"aud": "skylos"}}
    assert "SKYLOS_TOKEN" not in job["variables"]
    assert job["variables"]["SKYLOS_PROJECT_ROOT"] == ""


def test_managed_job_uses_trusted_installed_scanner_outside_checkout():
    job = _job()
    assert job["image"] == {"name": "$SKYLOS_SCANNER_IMAGE", "entrypoint": [""]}
    assert "SKYLOS_SCANNER_IMAGE" not in job["variables"]
    assert job["script"][0] == "cd /opt/skylos-ci"
    command = shlex.split(job["script"][1])
    assert command[:4] == [
        "/opt/skylos/bin/python",
        "-I",
        "/opt/skylos/bin/skylos",
        "$CI_PROJECT_DIR",
    ]
    assert (
        command[command.index("--config-file") + 1] == "/opt/skylos-ci/pyproject.toml"
    )
    assert "--all" in command
    assert "--upload" in command
    assert command[command.index("--format") + 1] == "json"
    assert "--no-provenance" in command
    assert "--no-grep-verify" in command


def test_managed_job_does_not_inherit_or_run_target_code():
    job = _job()
    assert job["inherit"] == {"default": False, "variables": False}
    for key in ("before_script", "after_script", "services", "cache", "dependencies"):
        assert job[key] == []
    assert job["variables"]["GIT_SUBMODULE_STRATEGY"] == "none"
    for forbidden in (
        "pip install",
        "npm ",
        "pytest",
        "--trace",
        "--coverage",
        "eval ",
        "echo ",
    ):
        assert forbidden not in "\n".join(job["script"])


def test_managed_job_allows_only_same_project_mrs_and_protected_default_pushes():
    rules = _job()["rules"]
    assert len(rules) == 3
    assert rules[-1] == {"when": "never"}
    for rule in rules[:2]:
        assert '$CI_SERVER_URL == "https://gitlab.com"' in rule["if"]
    assert '$CI_PIPELINE_SOURCE == "merge_request_event"' in rules[0]["if"]
    assert "$CI_MERGE_REQUEST_SOURCE_PROJECT_ID == $CI_PROJECT_ID" in rules[0]["if"]
    assert "$CI_MERGE_REQUEST_TARGET_PROJECT_ID == $CI_PROJECT_ID" in rules[0]["if"]
    assert '$CI_PIPELINE_SOURCE == "push"' in rules[1]["if"]
    assert "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH" in rules[1]["if"]
    assert '$CI_COMMIT_REF_PROTECTED == "true"' in rules[1]["if"]


def test_managed_job_preserves_artifact_and_gate_exit_status():
    job = _job()
    command = shlex.split(job["script"][1])
    assert "--gate" in command
    assert job["allow_failure"] is False
    assert job["artifacts"]["when"] == "always"
    assert "reports" not in job["artifacts"]
    assert job["artifacts"]["paths"] == ["skylos-report.json"]
    assert "||" not in job["script"][1]
    for option in (
        "--force",
        "--diff",
        "--diff-base",
        "--baseline",
        "--select",
        "--limit",
    ):
        assert option not in command
