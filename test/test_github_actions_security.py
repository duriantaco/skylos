import json
from pathlib import Path

import yaml

from skylos.analyzer import analyze
from skylos.rules.config import scan_config_files
from skylos.rules.config.cicd.github_actions import scan_github_actions


def _rule_ids(findings):
    return {finding["rule_id"] for finding in findings}


def _publish_workflow():
    return yaml.safe_load(Path(".github/workflows/publish.yml").read_text())


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
        "SKY-D299",
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
        "SKY-D313",
    }.issubset(_rule_ids(findings))


def test_publish_workflow_keeps_pypi_token_out_of_tool_install():
    workflow = _publish_workflow()
    publish_steps = workflow["jobs"]["publish"]["steps"]
    install_step = next(s for s in publish_steps if s.get("name") == "Install publish tools")
    upload_step = next(s for s in publish_steps if s.get("name") == "Publish to PyPI")

    assert "TWINE_PASSWORD" not in install_step.get("env", {})
    assert "pip install" in install_step["run"]
    assert upload_step["env"]["TWINE_PASSWORD"] == "${{ secrets.PYPI_TOKEN }}"
    assert "pip install" not in upload_step["run"]
    assert "twine upload" in upload_step["run"]


def test_publish_workflow_validates_strict_semver_release_tags():
    workflow = _publish_workflow()
    build_steps = workflow["jobs"]["build"]["steps"]
    resolve_step = next(s for s in build_steps if s.get("name") == "Resolve release tag input")

    assert "semver_re=" in resolve_step["run"]
    assert "(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)" in resolve_step["run"]


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
""".lstrip(),
        encoding="utf-8",
    )

    result = json.loads(analyze(str(tmp_path), enable_danger=True))

    assert "danger" in result
    assert {"SKY-D290", "SKY-D291", "SKY-D292", "SKY-D293"}.issubset(
        _rule_ids(result["danger"])
    )
    assert result["analysis_summary"]["danger_count"] == len(result["danger"])
