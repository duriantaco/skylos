"""Real static CLI/analyzer uploads to mocked Cloud HTTP, never a live project."""

import json
from types import SimpleNamespace

import pytest

import skylos.api as api
import skylos.cli as cli
from test.test_cli_gitlab import _invoke
from test.test_cli_sca_baseline import _git
from test.test_cli_sca_sarif import (
    _write_lockfile,
    osv as osv,
    project as project,
)


@pytest.fixture
def managed(project, monkeypatch):
    _git(project, "init", "-q")
    for name in ("SKYLOS_TOKEN", "GITHUB_ACTIONS", "SKYLOS_CONFIG_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GITLAB_CI", "true")
    monkeypatch.setenv("CI_SERVER_URL", "https://gitlab.com")
    monkeypatch.setenv("CI_PROJECT_DIR", str(project))
    monkeypatch.setenv("CI_PROJECT_ID", "104")
    monkeypatch.setenv("CI_PROJECT_PATH", "group/subgroup/app")
    monkeypatch.setenv("CI_COMMIT_SHA", "a" * 40)
    monkeypatch.setenv("CI_COMMIT_BRANCH", "main")
    monkeypatch.setenv("SKYLOS_PROJECT_ROOT", "")
    monkeypatch.setenv("SKYLOS_GITLAB_ID_TOKEN", "fixture.job.id-token")
    monkeypatch.setattr(cli, "upload_report", api.upload_report)
    monkeypatch.setattr(api, "_try_github_oidc_token", lambda: None)
    monkeypatch.setattr(api, "_load_repo_link", lambda root: {})
    monkeypatch.setattr(api, "detect_ai_code", lambda root: {})
    # Simulate the example's trusted working directory outside the checkout.
    monkeypatch.setattr(api, "get_git_root", lambda: None)
    calls = []
    response = {
        "success": True,
        "scan_id": "fixture-saved-scan",
        "gitlab_delivery": {
            "status": "noop",
            "reason": "complete",
            "created": 0,
            "updated": 0,
            "resolved": 0,
            "eligible": 0,
        },
    }
    monkeypatch.setattr(api, "_gitlab_test_response", response, raising=False)

    def post(url, *, headers, json, **kwargs):
        assert url == api.REPORT_URL
        calls.append((headers, json))
        return SimpleNamespace(
            status_code=200, json=lambda: response, text="ok", headers={}
        )

    def get(*args, **kwargs):
        pytest.fail("managed machine output must not make unmocked HTTP requests")

    monkeypatch.setattr(api.requests, "post", post)
    monkeypatch.setattr(api.requests, "get", get)
    return calls


def test_full_cli_upload_keeps_native_artifact_and_managed_receipt(
    project, osv, managed, monkeypatch, capsys
):
    _write_lockfile(project, "npm")
    code, stdout, stderr = _invoke(project, monkeypatch, capsys, "--all", "--upload")
    assert code == 0
    assert json.loads(stdout)
    assert len(managed) == 1
    headers, body = managed[0]
    assert headers == {
        "Authorization": "Bearer fixture.job.id-token",
        "X-Skylos-Auth": "gitlab_oidc",
        "X-Skylos-Project-Root": "",
    }
    assert body["gitlab_scan_receipt"] == {"complete": True, "full_scan": True}
    assert body["project_root"] == ""
    assert body["ci"]["project_path"] == "group/subgroup/app"
    assert body["runs"][0]["results"]
    assert "fixture.job.id-token" not in json.dumps(body) + stdout + stderr
    assert "Scan saved. GitLab comments:" in stderr


@pytest.mark.parametrize(
    "options",
    [
        ["--baseline"],
        ["--select", "SKY-D201"],
        ["--severity", "HIGH"],
        ["--confidence", "80"],
        ["--exclude", "generated"],
    ],
)
def test_narrowed_cli_upload_cannot_resolve_old_comments(
    project, osv, managed, monkeypatch, capsys, options
):
    _write_lockfile(project, "npm")
    code, stdout, _stderr = _invoke(
        project, monkeypatch, capsys, "--all", "--upload", "--force", *options
    )
    assert code == 0
    assert isinstance(json.loads(stdout), list)
    assert len(managed) == 1
    assert managed[0][1]["gitlab_scan_receipt"] == {
        "complete": True,
        "full_scan": False,
    }


def test_incomplete_cli_scan_retains_native_findings_without_upload_even_with_force(
    project, osv, managed, monkeypatch, capsys
):
    _write_lockfile(project, "npm")
    osv.fail_details = True
    code, stdout, stderr = _invoke(
        project, monkeypatch, capsys, "--all", "--upload", "--force"
    )
    assert code == 2
    assert json.loads(stdout)
    assert "incomplete" in stderr.lower()
    assert managed == []


def test_monorepo_upload_paths_and_binding_survive_isolated_working_directory(
    project, osv, managed, monkeypatch, capsys
):
    subproject = project / "apps" / "api"
    subproject.mkdir(parents=True)
    _write_lockfile(subproject, "npm")
    monkeypatch.setenv("SKYLOS_PROJECT_ROOT", "apps/api")
    code, stdout, _stderr = _invoke(
        project, monkeypatch, capsys, "--all", "--upload", target=subproject
    )
    assert code == 0
    assert json.loads(stdout)
    assert len(managed) == 1
    headers, body = managed[0]
    assert headers["X-Skylos-Project-Root"] == body["project_root"] == "apps/api"
    assert body["gitlab_scan_receipt"] == {"complete": True, "full_scan": True}
    locations = [
        item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for item in body["runs"][0]["results"]
    ]
    assert locations
    assert all(not path.startswith("/") and "apps/api/" in path for path in locations)


@pytest.mark.parametrize(
    "status,reason,expected",
    [
        ("published", "complete", 0),
        ("noop", "complete", 0),
        ("skipped", "not_merge_request", 0),
        ("skipped", "plan_required", 2),
        ("skipped", "stale_diff", 2),
        ("skipped", "lease_busy_or_stale", 2),
        ("skipped", "disconnected", 2),
        ("partial", "comment_limit", 2),
        ("failed", "gitlab_transport_error", 2),
    ],
)
def test_cli_delivery_status_is_visible_and_never_reuploads_saved_scan(
    project, osv, managed, monkeypatch, capsys, status, reason, expected
):
    _write_lockfile(project, "npm")
    api._gitlab_test_response["gitlab_delivery"].update(
        status=status,
        reason=reason,
        created=1 if status in ("published", "partial") else 0,
    )
    code, stdout, stderr = _invoke(
        project, monkeypatch, capsys, "--all", "--upload", "--force"
    )
    assert code == expected
    assert json.loads(stdout)
    assert "Scan saved." in stderr
    assert len(managed) == 1
    if reason == "plan_required":
        assert "upgrade" in stderr and "setup" in stderr
    elif expected == 2:
        assert reason in stderr


def test_cli_missing_delivery_receipt_fails_closed_but_keeps_native_report(
    project, osv, managed, monkeypatch, capsys
):
    _write_lockfile(project, "npm")
    api._gitlab_test_response.pop("gitlab_delivery")
    code, stdout, stderr = _invoke(
        project, monkeypatch, capsys, "--all", "--upload", "--force"
    )
    assert code == 2
    assert json.loads(stdout)
    assert "Scan saved." in stderr and "delivery receipt" in stderr
    assert len(managed) == 1


@pytest.mark.parametrize(
    "delivery_fails,force,expected",
    [(False, False, 1), (False, True, 0), (True, False, 2), (True, True, 2)],
)
def test_cli_delivery_failure_takes_priority_without_losing_cloud_gate_result(
    project, osv, managed, monkeypatch, capsys, delivery_fails, force, expected
):
    _write_lockfile(project, "npm")
    api._gitlab_test_response["quality_gate"] = {"passed": False}
    if delivery_fails:
        api._gitlab_test_response["gitlab_delivery"].update(
            status="failed", reason="gitlab_transport_error"
        )
    options = ["--force"] if force else []
    code, stdout, stderr = _invoke(
        project, monkeypatch, capsys, "--all", "--upload", "--strict", *options
    )
    assert code == expected
    assert json.loads(stdout)
    assert "Scan saved." in stderr
    assert len(managed) == 1


def test_real_cli_multiple_unused_parameters_retain_distinct_messages(
    project, osv, managed, monkeypatch, capsys
):
    source = project / "app.py"
    source.write_text(  # skylos: ignore[SKY-D324] fixed file in fresh pytest project directory
        "def calculate(first, second):\n    return 1\n\nprint(calculate(1, 2))\n",
        encoding="utf-8",
    )
    config_path = project / "pyproject.toml"
    config_path.write_text(  # skylos: ignore[SKY-D324] fixed file in fresh pytest project directory
        "[tool.mypy]\n[tool.ruff]\n[tool.skylos.gate]\n",
        encoding="utf-8",
    )
    precommit_path = project / ".pre-commit-config.yaml"
    precommit_path.write_text(  # skylos: ignore[SKY-D324] fixed file in fresh pytest project directory
        "repos: []\n",
        encoding="utf-8",
    )
    code, _stdout, _stderr = _invoke(project, monkeypatch, capsys, "--all", "--upload")
    assert code == 0, _stderr
    findings = managed[0][1]["runs"][0]["results"]
    parameters = [item for item in findings if item["ruleId"] == "SKY-U006"]
    assert len(parameters) == 2
    assert parameters[0]["message"]["text"] != parameters[1]["message"]["text"]
    first = parameters[0]["locations"][0]["physicalLocation"]
    second = parameters[1]["locations"][0]["physicalLocation"]
    assert first["artifactLocation"] == second["artifactLocation"]
    assert first["region"]["startLine"] == second["region"]["startLine"]


def test_repo_level_policy_findings_without_file_locations_remain_incomplete(
    project, osv, managed, monkeypatch, capsys
):
    source = project / "app.py"
    source.write_text(  # skylos: ignore[SKY-D324] fixed file in fresh pytest project directory
        "def calculate(first, second):\n    return 1\n\nprint(calculate(1, 2))\n",
        encoding="utf-8",
    )
    code, stdout, stderr = _invoke(
        project, monkeypatch, capsys, "--all", "--upload", "--force"
    )
    assert code == 2
    assert json.loads(stdout)
    assert "Unrepresentable finding in quality" in stderr
    assert not managed


def test_minimal_repository_managed_json_upload_retains_repository_policy_findings(
    project, osv, managed, monkeypatch, capsys
):
    source = project / "app.py"
    source.write_text(  # skylos: ignore[SKY-D324] fixed file in fresh pytest project directory
        "def calculate(first, second):\n    return 1\n\nprint(calculate(1, 2))\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(project.parent)
    code, stdout, stderr = _invoke(
        project, monkeypatch, capsys, "--all", "--upload", format_option="json"
    )
    assert code == 0
    local = json.loads(stdout)
    assert local["quality"]
    assert "Scan saved." in stderr
    assert len(managed) == 1
    body = managed[0][1]
    parameters = [
        item for item in body["runs"][0]["results"] if item["ruleId"] == "SKY-U006"
    ]
    assert len(parameters) == 2
    assert all(
        item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
        for item in parameters
    )
    policies = [
        item
        for item in body["runs"][0]["results"]
        if item.get("properties", {}).get("kind") == "repo_policy"
    ]
    assert {item["ruleId"] for item in policies} >= {
        "SKY-R101",
        "SKY-R102",
        "SKY-R103",
        "SKY-R104",
    }
    assert all(
        item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "."
        for item in policies
    )
    assert all(
        item["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
        for item in policies
    )
    assert body["gitlab_scan_receipt"] == {"complete": True, "full_scan": True}


@pytest.mark.parametrize("failure", ["timeout", 500])
def test_cli_unknown_delivery_after_http_failure_is_exit_two_without_retry(
    project, osv, managed, monkeypatch, capsys, failure
):
    _write_lockfile(project, "npm")
    calls = []

    def post(url, **kwargs):
        calls.append(url)
        if failure == "timeout":
            raise api.requests.exceptions.Timeout("private fixture detail")
        return SimpleNamespace(status_code=500, text="private fixture detail")

    monkeypatch.setattr(api.requests, "post", post)
    code, stdout, stderr = _invoke(
        project, monkeypatch, capsys, "--all", "--upload", "--force"
    )
    assert code == 2
    assert json.loads(stdout)
    assert calls == [api.REPORT_URL]
    assert "outcome unknown" in stderr and "Check Cloud" in stderr
    assert "private fixture detail" not in stderr
