import gzip
import json
import os
import re
import shlex
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

from skylos import api
from skylos.cicd import pr_upload
from skylos.cicd.workflow import (
    PINNED_ACTIONS_CHECKOUT_PR_HEAD,
    generate_workflow,
    upload_project_root,
)
from skylos.cloud import sync
from skylos.config import ConfigError, load_config
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.config.cicd.github_actions import scan_github_actions

PR_JOBS = ("pr-policy", "pr-scan", "pr-publish")
HEAD_SHA = "a" * 40
CHECKOUT_PR_REF = "refs/pull/${{ github.event.pull_request.number }}/head"


def _parsed(**kwargs):
    kwargs.setdefault("skylos_version", "5.1.1")
    kwargs.setdefault("default_branch", "main")
    return yaml.safe_load(generate_workflow(**kwargs))


def _on(parsed):
    return parsed.get("on") or parsed.get(True)


def _step(job, name):
    return next(step for step in job["steps"] if step.get("name") == name)


def _cicd(argv, console=None):
    from skylos.commands import cicd_cmd

    console = console or Mock()
    code = cicd_cmd.run_cicd_command(
        argv,
        console_factory=lambda: console,
        load_config_func=lambda path: {},
        run_gate_interaction_func=Mock(),
        emit_github_annotations_func=Mock(),
    )
    printed = "\n".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    return code, printed


def test_pull_requests_to_the_default_branch_trigger_pull_request_target():
    on = _on(_parsed())
    assert on["pull_request"] is None
    assert on["pull_request_target"] == {
        "types": ["opened", "synchronize", "reopened"],
        "branches": ["main"],
    }
    assert on["push"] == {"branches": ["main"]}
    fallback = _on(_parsed(default_branch=None))
    assert fallback["pull_request_target"]["branches"] == ["main", "master"]


def test_pr_upload_jobs_match_the_cloud_contract():
    jobs = _parsed()["jobs"]
    condition = "github.event_name == 'pull_request_target'"

    policy = jobs["pr-policy"]
    assert policy["if"] == condition
    assert policy["permissions"] == {"id-token": "write"}
    assert "needs" not in policy
    assert [step.get("name") for step in policy["steps"]] == [
        "Setup Python",
        "Install Skylos",
        "Read the Skylos Cloud policy without pull request files",
        "Save the policy for the scan job",
    ]
    assert policy["steps"][1]["run"] == "python -I -m pip install skylos==5.1.1"
    assert policy["steps"][2]["run"] == (
        'skylos cicd pr-policy --output "$RUNNER_TEMP/skylos-pr-policy"'
    )

    scan = jobs["pr-scan"]
    assert scan["if"] == condition
    assert scan["needs"] == "pr-policy"
    assert scan["permissions"] == {"contents": "read"}
    assert scan["env"] == {
        "SKYLOS_COMMIT": "${{ github.event.pull_request.head.sha }}",
        "SKYLOS_BRANCH": "${{ github.event.pull_request.head.ref }}",
        "SKYLOS_PR_NUMBER": "${{ github.event.pull_request.number }}",
        "SKYLOS_PR_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
    }
    names = [step.get("name") for step in scan["steps"]]
    assert names == [
        "Setup Python",
        "Install Skylos before reading pull request files",
        "Checkout the pull request head without credentials",
        "Verify the fetched pull request head",
        "Download the Skylos Cloud policy",
        "Scan the pull request as untrusted data",
        "Save the scan for the upload job",
    ]
    assert "cache" not in scan["steps"][0].get("with", {})
    assert scan["steps"][1]["run"] == "python -I -m pip install 'skylos[dart]==5.1.1'"
    checkout = scan["steps"][2]
    assert checkout["uses"] == PINNED_ACTIONS_CHECKOUT_PR_HEAD
    assert checkout["with"] == {
        "ref": CHECKOUT_PR_REF,
        "path": "pr-source",
        "fetch-depth": 0,
        "persist-credentials": False,
        "allow-unsafe-pr-checkout": True,
    }
    verify = scan["steps"][3]
    assert verify["working-directory"] == "pr-source"
    assert verify["run"] == 'test "$(git rev-parse HEAD)" = "$SKYLOS_COMMIT"'
    scan_step = scan["steps"][5]
    assert scan_step["working-directory"] == "pr-source"
    assert scan_step["run"] == (
        "skylos cicd pr-scan . --danger --quality --ai-defects --secrets --sca "
        '--policy "$RUNNER_TEMP/skylos-pr-policy" '
        '--output "$RUNNER_TEMP/skylos-pr-report/report.json.gz"'
    )

    publish = jobs["pr-publish"]
    assert publish["if"] == condition
    assert publish["needs"] == "pr-scan"
    assert publish["permissions"] == {"id-token": "write"}
    assert publish["env"] == {
        "SKYLOS_COMMIT": "${{ github.event.pull_request.head.sha }}",
        "SKYLOS_PR_NUMBER": "${{ github.event.pull_request.number }}",
    }
    assert publish["steps"][-1]["run"] == (
        'skylos cicd pr-publish --input "$RUNNER_TEMP/skylos-pr-report/report.json.gz"'
    )


def _may_run_on_pull_request_target(job):
    condition = str(job.get("if", ""))
    if "!= 'pull_request_target'" in condition:
        return False
    events = re.findall(r"github\.event_name == '(\w+)'", condition)
    if events and "!=" not in condition and "&&" not in condition:
        return "pull_request_target" in events
    return True


def _uses_checkout(job):
    return any(
        str(step.get("uses", "")).startswith("actions/checkout@")
        for step in job.get("steps", [])
    )


@pytest.mark.parametrize(
    "options",
    [
        {},
        {"use_risk_review": True},
        {
            "use_llm": True,
            "use_defend": True,
            "use_claude_security": True,
            "model": "gpt-4.1",
        },
        {"scan_path": "apps/api", "analysis_types": ["dead-code"]},
    ],
)
def test_no_job_that_can_run_on_pull_request_target_reads_pr_code_with_credentials(
    options,
):
    jobs = _parsed(**options)["jobs"]
    assert {
        job_id for job_id, job in jobs.items() if _may_run_on_pull_request_target(job)
    } >= set(PR_JOBS)
    for job_id, job in jobs.items():
        if not _may_run_on_pull_request_target(job):
            continue
        text = json.dumps(job)
        permissions = job.get("permissions", {})
        reads_pr_code = "refs/pull/" in text or "pull_request.head" in json.dumps(
            [step.get("with", {}) for step in job.get("steps", [])]
        )
        if job_id in PR_JOBS:
            assert "secrets." not in text and "github.token" not in text, job_id
            assert "GITHUB_TOKEN" not in text, job_id
        if reads_pr_code:
            assert job_id == "pr-scan"
            assert permissions == {"contents": "read"}
        if permissions.get("id-token") == "write" and job_id in PR_JOBS:
            assert not _uses_checkout(job), job_id


def test_existing_jobs_stay_off_pull_request_target():
    jobs = _parsed(use_risk_review=True, use_claude_security=True)["jobs"]
    assert "github.event_name != 'pull_request_target'" in jobs["skylos"]["if"]
    assert "github.event_name != 'pull_request_target'" in jobs["claude-security"]["if"]
    assert (
        "github.event_name != 'pull_request_target'"
        in jobs["upload-claude-findings"]["if"]
    )
    for job_id in ("done", "risk-review"):
        assert "pull_request_target" not in jobs[job_id]["if"]
    assert jobs["risk-review-recheck"]["if"] == (
        "github.event_name == 'pull_request_review'"
    )
    assert jobs["cloud-upload"]["if"].startswith("github.event_name == 'push'")


@pytest.mark.parametrize(
    "options",
    [
        {},
        {"use_risk_review": True},
        {
            "use_llm": True,
            "use_defend": True,
            "use_claude_security": True,
            "model": "gpt-4.1",
        },
        {"scan_path": "apps/api"},
    ],
)
def test_generated_pr_upload_workflow_passes_skylos_actions_audit(tmp_path, options):
    workflow = tmp_path / ".github" / "workflows" / "skylos.yml"
    workflow.parent.mkdir(parents=True)
    assert write_text_no_symlink(workflow, generate_workflow(**options))
    assert scan_github_actions(tmp_path) == []


@pytest.mark.parametrize(
    ("label", "old", "new"),
    [
        (
            "oidc on the job that reads PR code",
            "    permissions:\n      contents: read\n    env:\n      SKYLOS_COMMIT",
            "    permissions:\n      contents: read\n      id-token: write\n    env:\n      SKYLOS_COMMIT",
        ),
        (
            "persisted checkout credentials",
            "          persist-credentials: false\n          allow-unsafe-pr-checkout: true",
            "          allow-unsafe-pr-checkout: true",
        ),
        (
            "secret next to PR code",
            "      SKYLOS_PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}",
            (
                "      SKYLOS_PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}\n"
                "      TOKEN: ${{ secrets.DEPLOY_TOKEN }}"
            ),
        ),
    ],
)
def test_weakened_pr_scan_job_is_flagged_by_skylos(tmp_path, label, old, new):
    content = generate_workflow(default_branch="main")
    assert content.count(old) == 1, label
    workflow = tmp_path / ".github" / "workflows" / "skylos.yml"
    workflow.parent.mkdir(parents=True)
    assert write_text_no_symlink(workflow, content.replace(old, new))
    assert "SKY-D290" in {
        finding["rule_id"] for finding in scan_github_actions(tmp_path)
    }


def test_monorepo_scan_path_names_the_cloud_project_root_in_every_job():
    jobs = _parsed(scan_path="apps/api")["jobs"]
    assert jobs["pr-policy"]["steps"][2]["run"].endswith(" --project-root apps/api")
    assert jobs["pr-scan"]["steps"][5]["run"].startswith(
        "skylos cicd pr-scan apps/api "
    )
    assert jobs["pr-scan"]["steps"][5]["run"].endswith(" --project-root apps/api")
    assert jobs["pr-publish"]["steps"][-1]["run"].endswith(" --project-root apps/api")
    assert upload_project_root("./apps/api/") == "apps/api"
    assert upload_project_root(".") == ""
    assert upload_project_root("-svc") == "-svc"


@pytest.mark.parametrize("scan_path", ["/abs/app", "../other", "a/../b"])
def test_pr_uploads_refuse_scan_paths_outside_the_repository(scan_path):
    with pytest.raises(ValueError, match="scan_path"):
        generate_workflow(scan_path=scan_path)
    assert "pull_request_target" not in generate_workflow(
        scan_path=scan_path, use_upload=False
    )


def test_dead_code_only_pr_scan_passes_no_category_flags():
    run = _parsed(analysis_types=["dead-code"])["jobs"]["pr-scan"]["steps"][5]["run"]
    assert run.startswith("skylos cicd pr-scan . --policy ")


@pytest.mark.parametrize(
    "options",
    [
        {"use_upload": False},
        {"use_pr_upload": False},
        {"triggers": ["pull_request"]},
        {"triggers": ["push"]},
        {"triggers": ["schedule"]},
    ],
)
def test_no_pr_upload_without_upload_pull_requests_and_pushes(options):
    content = generate_workflow(**options)
    assert "pull_request_target" not in content
    jobs = yaml.safe_load(content)["jobs"]
    assert not set(PR_JOBS) & set(jobs)
    assert "skylos cicd pr-" not in content


def test_generated_pr_commands_parse_with_the_cicd_parser(monkeypatch):
    calls = []

    def fake(args, console=None):
        calls.append(args)
        return 0

    monkeypatch.setattr(pr_upload, "run_pr_upload_command", fake)
    jobs = _parsed(scan_path="apps/api")["jobs"]
    runs = [
        jobs["pr-policy"]["steps"][2]["run"],
        jobs["pr-scan"]["steps"][5]["run"],
        jobs["pr-publish"]["steps"][-1]["run"],
    ]
    for run in runs:
        argv = shlex.split(run.replace("$RUNNER_TEMP", "/runner"))
        assert argv[:2] == ["skylos", "cicd"]
        assert _cicd(argv[2:])[0] == 0
    policy, scan, publish = calls
    assert policy.output == "/runner/skylos-pr-policy"
    assert scan.path == "apps/api"
    assert (scan.danger, scan.quality, scan.ai_defects, scan.secrets, scan.sca) == (
        True,
        True,
        True,
        True,
        True,
    )
    assert scan.policy == "/runner/skylos-pr-policy"
    assert publish.input == "/runner/skylos-pr-report/report.json.gz"
    assert {policy.project_root, scan.project_root, publish.project_root} == {
        "apps/api"
    }


def _run_init(tmp_path, monkeypatch, output, *argv):
    from skylos.commands import cicd_cmd

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cicd_cmd, "_git_output", lambda *args: "")
    code, printed = _cicd(["init", "--output", str(output), "--no-done", *argv])
    return code, yaml.safe_load(output.read_text()), printed


def test_cicd_init_adds_pr_uploads_only_to_skylos_yml(tmp_path, monkeypatch):
    default = tmp_path / ".github" / "workflows" / "skylos.yml"
    code, workflow, printed = _run_init(tmp_path, monkeypatch, default)
    assert code == 0
    assert set(PR_JOBS) <= set(workflow["jobs"])
    assert "Pull requests to main or master" in printed
    assert "Skylos Cloud PR upload" in printed

    other = tmp_path / ".github" / "workflows" / "quality.yml"
    code, workflow, printed = _run_init(tmp_path, monkeypatch, other)
    assert code == 0
    assert not set(PR_JOBS) & set(workflow["jobs"])
    assert "pull_request_target" not in _on(workflow)
    assert "cloud-upload" in workflow["jobs"]
    assert "only from .github/workflows/skylos.yml" in printed

    nested = tmp_path / "ci" / "skylos.yml"
    code, workflow, _ = _run_init(tmp_path, monkeypatch, nested)
    assert not set(PR_JOBS) & set(workflow["jobs"])

    code, workflow, printed = _run_init(
        tmp_path, monkeypatch, default, "--no-upload", "--force"
    )
    assert not set(PR_JOBS) & set(workflow["jobs"])
    assert "only from .github/workflows/skylos.yml" not in printed


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name in (
        "SKYLOS_TOKEN",
        "SKYLOS_CONFIG_FILE",
        "SKYLOS_POLICY_BASE",
        "SKYLOS_SYNCED_POLICY_FILE",
        "SKYLOS_CUSTOM_RULES",
        "SKYLOS_DIFF_BASE",
        "SKYLOS_COMMIT",
        "SKYLOS_BRANCH",
        "SKYLOS_PR_NUMBER",
        "SKYLOS_PR_BASE_SHA",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "GITHUB_ACTIONS",
        "GITHUB_BASE_REF",
        "GITHUB_HEAD_REF",
        "GITHUB_REF",
        "GITHUB_SHA",
        "GITHUB_EVENT_NAME",
        "GITHUB_EVENT_PATH",
        "GITHUB_STEP_SUMMARY",
        "GITLAB_CI",
        "CI",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(sync, "get_token", lambda: None)
    return tmp_path


def _no_network(*args, **kwargs):
    pytest.fail("this step must not touch the network")


def test_pr_policy_needs_github_oidc_and_writes_nothing_without_it(
    isolated, monkeypatch
):
    monkeypatch.setattr(sync, "api_get", _no_network)
    out = isolated / "policy"
    code, printed = _cicd(["pr-policy", "--output", str(out)])
    assert code == 1
    assert "id-token: write" in printed
    assert not out.exists()


def _policy_config(**overrides):
    config = {
        "project_id": "p1",
        "project_name": "demo",
        "security_enabled": True,
        "secrets_enabled": True,
        "quality_enabled": True,
        "exclude_paths": ["vendor"],
        "gate": {"enabled": True},
    }
    config.update(overrides)
    return config


def _fake_api(config, rules):
    calls = []

    def api_get(endpoint, token, *, extra_headers=None):
        calls.append((endpoint, token, extra_headers))
        if endpoint == "/api/sync/config":
            return config
        if isinstance(rules, Exception):
            raise rules
        return {"rules": rules}

    return api_get, calls


def test_pr_policy_saves_the_cloud_policy_and_rules(isolated, monkeypatch):
    config = _policy_config()
    fake, calls = _fake_api(config, [{"id": "r1", "pattern": "x"}])
    monkeypatch.setattr(sync, "api_get", fake)
    monkeypatch.setattr(api, "_try_github_oidc_token", lambda: "oidc:jwt")
    out = isolated / "policy"
    code, printed = _cicd(
        ["pr-policy", "--output", str(out), "--project-root", "apps/api"]
    )
    assert code == 0
    assert yaml.safe_load((out / "config.yaml").read_text()) == config
    assert (out / "config.yaml").read_text() == yaml.safe_dump(
        config, default_flow_style=False
    )
    assert json.loads((out / "rules.json").read_text()) == [
        {"id": "r1", "pattern": "x"}
    ]
    assert calls == [
        ("/api/sync/config", "oidc:jwt", {"X-Skylos-Project-Root": "apps/api"}),
        ("/api/sync/rules", "oidc:jwt", {"X-Skylos-Project-Root": "apps/api"}),
    ]
    assert "Saved the Skylos Cloud policy for demo (1 custom rules)" in printed


def test_pr_policy_rules_are_optional_unless_coverage_requires_them(
    isolated, monkeypatch
):
    monkeypatch.setattr(api, "_try_github_oidc_token", lambda: "oidc:jwt")
    refused = sync.AuthError("Invalid OIDC token")
    fake, _ = _fake_api(_policy_config(), refused)
    monkeypatch.setattr(sync, "api_get", fake)
    out = isolated / "optional"
    code, printed = _cicd(["pr-policy", "--output", str(out)])
    assert code == 0
    assert (out / "config.yaml").is_file() and not (out / "rules.json").exists()
    assert "not checked" in printed

    required = _policy_config(gate={"coverage": {"required": ["custom_rules"]}})
    fake, _ = _fake_api(required, refused)
    monkeypatch.setattr(sync, "api_get", fake)
    code, printed = _cicd(["pr-policy", "--output", str(isolated / "required")])
    assert code == 1
    assert "Required Skylos custom rules could not be read" in printed


@pytest.mark.parametrize(
    "config",
    [
        _policy_config(project_id=None),
        _policy_config(security_enabled="yes"),
        {k: v for k, v in _policy_config().items() if k != "quality_enabled"},
    ],
)
def test_pr_policy_refuses_an_unverified_policy(isolated, monkeypatch, config):
    monkeypatch.setattr(api, "_try_github_oidc_token", lambda: "oidc:jwt")
    fake, _ = _fake_api(config, [])
    monkeypatch.setattr(sync, "api_get", fake)
    out = isolated / "policy"
    code, _ = _cicd(["pr-policy", "--output", str(out)])
    assert code == 1
    assert not (out / "config.yaml").exists()


def test_pr_policy_reports_cloud_refusal(isolated, monkeypatch):
    monkeypatch.setattr(api, "_try_github_oidc_token", lambda: "oidc:jwt")

    def refuse(endpoint, token, *, extra_headers=None):
        raise sync.AuthError("Skylos Cloud rejected this GitHub Actions identity")

    monkeypatch.setattr(sync, "api_get", refuse)
    code, printed = _cicd(["pr-policy", "--output", str(isolated / "p")])
    assert code == 1
    assert "Skylos Cloud policy unavailable" in printed
    assert "skylos cicd init --no-upload" in printed


GIT_ENV = {
    "GIT_AUTHOR_NAME": "dev",
    "GIT_AUTHOR_EMAIL": "dev@example.com",
    "GIT_COMMITTER_NAME": "dev",
    "GIT_COMMITTER_EMAIL": "dev@example.com",
    "GIT_CONFIG_NOSYSTEM": "1",
}


def _git(repo, *args):
    env = {**os.environ, **GIT_ENV, "HOME": str(repo.parent)}
    completed = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


VULN = """import subprocess


def run(cmd):
    subprocess.call(cmd, shell=True)


def run_hidden(cmd):
    subprocess.call(cmd, shell=True)  # skylos: ignore


def unused_helper():  # skylos: ignore
    return 1


def classify(value):
    if value > 10:
        return "big"
    if value > 5:
        return "medium"
    if value > 1:
        return "small"
    return "tiny"
"""


@pytest.fixture
def pr_checkout(isolated, monkeypatch):
    repo = isolated / "pr-source"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "app.py").write_text("def greet(name):\n    return 'hi ' + name\n")
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\n\n[tool.skylos]\ncomplexity = 2\n'
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-qb", "feature")
    (repo / "vuln.py").write_text(VULN)
    (repo / ".skylos.toml").write_text(
        'ignore = ["SKY-D212", "SKY-D209", "SKY-Q301"]\nexclude = ["vuln.py"]\n'
    )
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\n\n[tool.skylos]\n'
        'complexity = 100\nexclude = ["*"]\nignore = ["SKY-D212", "SKY-D209"]\n'
    )
    (repo / ".skylos").mkdir()
    (repo / ".skylos" / "config.yaml").write_text(
        "security_enabled: false\nquality_enabled: false\nignore: [SKY-D212]\n"
    )
    (repo / ".skylos" / "baseline.json").write_text("{}\n")
    (repo / "pkg" / ".skylos").mkdir(parents=True)
    (repo / "pkg" / "__init__.py").write_text("")
    (repo / "pkg" / ".skylos" / "cache.json").write_text("{}\n")
    outside = isolated / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep\n")
    (repo / "sub").mkdir()
    os.symlink(outside, repo / "sub" / ".skylos")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "pr")
    head = _git(repo, "rev-parse", "HEAD")

    policy = isolated / "runner" / "skylos-pr-policy"
    policy.mkdir(parents=True)
    (policy / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "project_id": "p1",
                "security_enabled": True,
                "secrets_enabled": True,
                "quality_enabled": True,
            }
        )
    )
    monkeypatch.chdir(repo)
    monkeypatch.setenv("SKYLOS_COMMIT", head)
    monkeypatch.setenv("SKYLOS_BRANCH", "feature")
    monkeypatch.setenv("SKYLOS_PR_NUMBER", "7")
    monkeypatch.setenv("SKYLOS_PR_BASE_SHA", base)
    return {
        "repo": repo,
        "head": head,
        "base": base,
        "policy": policy,
        "outside": outside,
        "report": isolated / "runner" / "skylos-pr-report" / "report.json.gz",
    }


def _scan(pr, *extra):
    return _cicd(
        [
            "pr-scan",
            ".",
            "--danger",
            "--secrets",
            "--quality",
            "--policy",
            str(pr["policy"]),
            "--output",
            str(pr["report"]),
            *extra,
        ]
    )


def _findings(report):
    payload = json.loads(gzip.decompress(report.read_bytes()))
    rows = {
        (row["rule_id"], row["file_path"], row["line_number"])
        for row in payload["compatibility_payload"]["findings"]
    }
    return payload, rows


def test_pr_scan_reports_what_pr_owned_settings_and_ignores_try_to_hide(pr_checkout):
    code, printed = _scan(pr_checkout)
    assert code == 0, printed

    payload, rows = _findings(pr_checkout["report"])
    assert ("SKY-D212", "vuln.py", 5) in rows
    assert ("SKY-D209", "vuln.py", 5) in rows
    assert ("SKY-D212", "vuln.py", 9) in rows
    assert ("SKY-D209", "vuln.py", 9) in rows
    assert ("SKY-Q301", "vuln.py", 16) in rows
    assert not [row for row in rows if row[1] == "vuln.py" and row[2] == 12]
    assert ("SKY-U001", "app.py", 1) in rows
    assert "Restored 2 inline-ignored findings" in printed
    assert "1 dead-code items stay ignored inline" in printed

    metadata = payload["metadata"]
    assert metadata["commit_hash"] == pr_checkout["head"]
    assert metadata["branch"] == "feature"
    assert metadata["project_root"] == ""
    assert metadata["ci"]["pr_number"] == 7
    assert not metadata["is_forced"]
    assert metadata.get("project_id") is None
    assert payload["definitions_payload"] is None

    repo = pr_checkout["repo"]
    assert not os.path.lexists(repo / "sub" / ".skylos")
    assert not (repo / "pkg" / ".skylos").exists()
    assert not (repo / ".skylos" / "baseline.json").exists()
    assert (pr_checkout["outside"] / "keep.txt").read_text() == "keep\n"
    assert "Removed 3 .skylos folder(s)" in printed
    for name in ("SKYLOS_POLICY_BASE", "SKYLOS_SYNCED_POLICY_FILE"):
        assert name not in os.environ


def test_pr_scan_refuses_a_checkout_that_is_not_the_pr_head(pr_checkout, monkeypatch):
    monkeypatch.setenv("SKYLOS_COMMIT", pr_checkout["base"])
    code, printed = _scan(pr_checkout)
    assert code == 1
    assert "not the pull request head" in printed
    assert (pr_checkout["repo"] / ".skylos" / "config.yaml").is_file()
    assert not pr_checkout["report"].exists()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("SKYLOS_COMMIT", "main"),
        ("SKYLOS_PR_NUMBER", "0"),
        ("SKYLOS_PR_NUMBER", "7; rm -rf /"),
        ("SKYLOS_PR_BASE_SHA", ""),
    ],
)
def test_pr_scan_needs_the_pull_request_identity(pr_checkout, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    code, printed = _scan(pr_checkout)
    assert code == 1
    assert f"{name} is missing or invalid" in printed
    assert not pr_checkout["report"].exists()


def test_pr_scan_refuses_a_policy_inside_the_checkout(pr_checkout):
    inside = pr_checkout["repo"] / "policy"
    inside.mkdir()
    (inside / "config.yaml").write_text("project_id: p1\n")
    code, printed = _cicd(
        [
            "pr-scan",
            ".",
            "--policy",
            str(inside),
            "--output",
            str(pr_checkout["report"]),
        ]
    )
    assert code == 1
    assert "--policy must be outside the pull request checkout" in printed


def test_pr_scan_refuses_a_missing_or_linked_policy(pr_checkout):
    config = pr_checkout["policy"] / "config.yaml"
    real = pr_checkout["policy"].parent / "real.yaml"
    config.rename(real)
    code, printed = _scan(pr_checkout)
    assert code == 1 and "trusted Skylos policy is missing" in printed
    os.symlink(real, config)
    code, printed = _scan(pr_checkout)
    assert code == 1 and "Unsafe Skylos policy file" in printed
    assert (pr_checkout["repo"] / ".skylos" / "config.yaml").is_file()


def test_pr_scan_refuses_a_different_project_root(pr_checkout):
    code, printed = _scan(pr_checkout, "--project-root", "apps/api")
    assert code == 1
    assert "not the Skylos Cloud project folder apps/api" in printed


def test_restore_inline_ignored_findings_fails_closed():
    result = {
        "danger": [],
        "suppressed": [
            {
                "category": "security",
                "rule_id": "SKY-D212",
                "file": "a.py",
                "line": 3,
                "severity": "CRITICAL",
                "reason": "inline ignore comment",
            },
            {
                "category": "dependency",
                "rule_id": "SKY-SCA-LIC001",
                "file": "requirements.txt",
                "severity": "HIGH",
                "reason": "inline ignore comment",
            },
            {"category": "dead_code", "reason": "inline ignore comment"},
        ],
    }
    assert pr_upload.restore_inline_ignored_findings(result) == (2, 1)
    assert result["danger"][0]["rule_id"] == "SKY-D212"
    assert result["dependency_vulnerabilities"][0]["rule_id"] == "SKY-SCA-LIC001"

    for broken in (
        {
            "category": "security",
            "rule_id": "X",
            "file": "a.py",
            "severity": "LOW",
            "reason": "baseline",
        },
        {
            "category": "security",
            "rule_id": "X",
            "file": "a.py",
            "reason": "inline ignore comment",
        },
        {
            "category": "weird",
            "rule_id": "X",
            "file": "a.py",
            "severity": "LOW",
            "reason": "inline ignore comment",
        },
        "not a finding",
    ):
        with pytest.raises(pr_upload.PrUploadError):
            pr_upload.restore_inline_ignored_findings({"suppressed": [broken]})


def _artifact(path, *, commit=HEAD_SHA, pr_number=7, root="", forced=False):
    metadata = {
        "commit_hash": commit,
        "project_root": root,
        "is_forced": forced,
        "ci": {"pr_number": pr_number},
    }
    payload = {
        "legacy_payload": {"findings": []},
        "core_payload": {"runs": [], **metadata},
        "compatibility_payload": {"findings": []},
        "definitions_payload": {"definitions": [{"name": "f"}]},
        "metadata": metadata,
        "scan_summary": {"finding_count": 0},
        "grade_data": None,
        "legacy_payload_size_bytes": 1,
        "compatibility_payload_size_bytes": 1,
        "preflight": None,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gzip.compress(json.dumps(payload).encode()))
    return path


@pytest.fixture
def publish_env(isolated, monkeypatch):
    monkeypatch.chdir(isolated)
    monkeypatch.setenv("SKYLOS_COMMIT", HEAD_SHA)
    monkeypatch.setenv("SKYLOS_PR_NUMBER", "7")
    sent = []
    tokens = []

    def token():
        tokens.append(True)
        return "oidc:secret-jwt"

    def send(token, prepared, **kwargs):
        sent.append((token, prepared, kwargs))
        return {
            "success": True,
            "scan_id": "scan-1",
            "quality_gate_passed": False,
            "quality_gate": {"passed": False, "message": "1 critical"},
        }

    monkeypatch.setattr(api, "_try_github_oidc_token", token)
    monkeypatch.setattr(api, "_send_prepared_upload", send)
    return {"dir": isolated, "sent": sent, "tokens": tokens}


def test_pr_publish_uploads_with_oidc_and_keeps_the_gate_in_cloud(publish_env):
    report = _artifact(publish_env["dir"] / "r" / "report.json.gz")
    code, printed = _cicd(["pr-publish", "--input", str(report)])
    assert code == 0, printed
    [(token, prepared, kwargs)] = publish_env["sent"]
    assert token == "oidc:secret-jwt"
    assert prepared.definitions_payload is None
    assert prepared.preflight is None
    assert prepared.metadata["ci"]["pr_number"] == 7
    assert prepared.legacy_payload_size_bytes == len(b'{"findings":[]}')
    assert kwargs == {
        "kind": "report",
        "quiet": False,
        "strict": False,
        "is_forced": False,
    }
    assert "FAILED" in printed or "failed" in printed.lower()


@pytest.mark.parametrize(
    "change",
    [
        {"commit": "b" * 40},
        {"pr_number": 8},
        {"root": "apps/api"},
        {"forced": True},
    ],
)
def test_pr_publish_refuses_an_artifact_for_another_pr_before_minting_a_token(
    publish_env, change
):
    report = _artifact(publish_env["dir"] / "r" / "report.json.gz", **change)
    code, printed = _cicd(["pr-publish", "--input", str(report)])
    assert code == 1
    assert "does not match this pull request" in printed
    assert publish_env["sent"] == [] and publish_env["tokens"] == []


def test_pr_publish_refuses_linked_missing_or_oversized_artifacts(
    publish_env, monkeypatch
):
    real = _artifact(publish_env["dir"] / "real.json.gz")
    linked = publish_env["dir"] / "linked.json.gz"
    os.symlink(real, linked)
    assert _cicd(["pr-publish", "--input", str(linked)])[0] == 1
    assert _cicd(["pr-publish", "--input", str(publish_env["dir"] / "none.gz")])[0] == 1
    monkeypatch.setattr(pr_upload, "MAX_DECODED_ARTIFACT_BYTES", 10)
    code, printed = _cicd(["pr-publish", "--input", str(real)])
    assert code == 1 and "exceeds the upload limit" in printed
    assert publish_env["sent"] == []


def test_pr_publish_needs_oidc(publish_env, monkeypatch):
    monkeypatch.setattr(api, "_try_github_oidc_token", lambda: None)
    report = _artifact(publish_env["dir"] / "r" / "report.json.gz")
    code, printed = _cicd(["pr-publish", "--input", str(report)])
    assert code == 1
    assert "id-token: write" in printed
    assert publish_env["sent"] == []


def test_pr_publish_fails_when_cloud_refuses_and_hides_the_token(
    publish_env, monkeypatch
):
    def refuse(token, prepared, **kwargs):
        return {
            "success": False,
            "code": "UNVERIFIED_GITHUB_SCAN",
            "status": 403,
            "error": "Bad token secret-jwt",
        }

    monkeypatch.setattr(api, "_send_prepared_upload", refuse)
    report = _artifact(publish_env["dir"] / "r" / "report.json.gz")
    code, printed = _cicd(["pr-publish", "--input", str(report)])
    assert code == 1
    assert "UNVERIFIED_GITHUB_SCAN" in printed
    assert "secret-jwt" not in printed


def test_operator_synced_policy_replaces_checkout_policy(isolated, monkeypatch):
    project = isolated / "project"
    (project / ".skylos").mkdir(parents=True)
    (project / ".skylos" / "config.yaml").write_text("security_enabled: false\n")
    operator = isolated / "operator" / "config.yaml"
    operator.parent.mkdir()
    operator.write_text("security_enabled: true\nexclude_paths: [vendor]\n")

    assert load_config(project)["security_enabled"] is False
    monkeypatch.setenv("SKYLOS_SYNCED_POLICY_FILE", str(operator))
    config = load_config(project)
    assert config["security_enabled"] is True
    assert config["exclude"] == ["vendor"]


def test_operator_synced_policy_overrides_the_policy_base_and_pr_files(
    pr_checkout, monkeypatch
):
    repo = pr_checkout["repo"]
    monkeypatch.setenv("SKYLOS_POLICY_BASE", pr_checkout["base"])
    monkeypatch.setenv(
        "SKYLOS_SYNCED_POLICY_FILE", str(pr_checkout["policy"] / "config.yaml")
    )
    config = load_config(repo)
    assert config["complexity"] == 2
    assert config["security_enabled"] is True
    assert config["quality_enabled"] is True
    assert config["exclude"] == []
    assert config["ignore"] == []


@pytest.mark.parametrize(
    "setup",
    ["relative", "missing", "symlink", "list", "invalid", "wrong-name"],
)
def test_unreadable_operator_synced_policy_stops_the_scan(isolated, monkeypatch, setup):
    folder = isolated / "operator"
    folder.mkdir()
    target = folder / "config.yaml"
    value = str(target)
    if setup == "relative":
        target.write_text("security_enabled: true\n")
        monkeypatch.chdir(folder)
        value = "config.yaml"
    elif setup == "symlink":
        real = folder / "real.yaml"
        real.write_text("security_enabled: true\n")
        os.symlink(real, target)
    elif setup == "list":
        target.write_text("- a\n")
    elif setup == "invalid":
        target.write_text("a: [\n")
    elif setup == "wrong-name":
        other = folder / "policy.yaml"
        other.write_text("security_enabled: true\n")
        value = str(other)
    monkeypatch.setenv("SKYLOS_SYNCED_POLICY_FILE", value)
    with pytest.raises(ConfigError, match="SKYLOS_SYNCED_POLICY_FILE"):
        load_config(isolated)


def test_review_decision_environment_hash_follows_operator_synced_policy(
    isolated, monkeypatch
):
    from skylos.core.review_decisions import _environment_dependency_hash

    project = isolated / "project"
    project.mkdir()
    (project / "app.py").write_text("x = 1\n")
    plain = _environment_dependency_hash(project, "python", dependency_cache=None)
    operator = isolated / "operator" / "config.yaml"
    operator.parent.mkdir()
    operator.write_text("security_enabled: true\n")
    monkeypatch.setenv("SKYLOS_SYNCED_POLICY_FILE", str(operator))
    first = _environment_dependency_hash(project, "python", dependency_cache=None)
    operator.write_text("security_enabled: false\n")
    second = _environment_dependency_hash(project, "python", dependency_cache=None)
    assert len({plain, first, second}) == 3
    monkeypatch.setenv("SKYLOS_SYNCED_POLICY_FILE", str(isolated / "gone.yaml"))
    assert (
        _environment_dependency_hash(project, "python", dependency_cache=None) is None
    )
    assert Path(operator).is_file()


def test_sync_api_get_sends_extra_headers_without_replacing_auth(monkeypatch):
    captured = {}

    class Response:
        status_code = 200

        def json(self):
            return {"project_id": "p1"}

        def raise_for_status(self):
            return None

    def get(url, headers, timeout):
        captured.update(headers)
        return Response()

    monkeypatch.setattr(sync.requests, "get", get)
    sync.api_get(
        "/api/sync/config",
        "oidc:jwt",
        extra_headers={"X-Skylos-Project-Root": "apps/api", "Authorization": "x"},
    )
    assert captured == {
        "X-Skylos-Project-Root": "apps/api",
        "Authorization": "Bearer jwt",
        "X-Skylos-Auth": "oidc",
    }
