import json

from skylos.analyzer import analyze
from skylos.rules.config import scan_config_files
from skylos.rules.config.cicd.gitlab_ci import scan_gitlab_ci


def _rule_ids(findings):
    return {finding["rule_id"] for finding in findings}


def _write_risky_gitlab_ci(path):
    path.write_text(
        """
include:
  - project: group/security/pipelines
    file: template.yml
  - remote: https://example.com/ci.yml

image: python:latest

variables:
  DEPLOY_TOKEN: plaintext-token-123
  DOCKER_TLS_CERTDIR: ""

stages: [test, deploy]

test:
  script:
    - eval "$CI_MERGE_REQUEST_TITLE"

deploy:
  stage: deploy
  image: docker:latest
  services:
    - docker:dind
  tags:
    - "$RUNNER_TAG"
  id_tokens:
    VAULT_TOKEN:
      aud: https://vault.example.com
  cache:
    paths:
      - node_modules/
  script:
    - ./scripts/release.sh
    - docker push registry.example.com/app:latest
""".lstrip(),
        encoding="utf-8",
    )


def test_gitlab_ci_scanner_detects_workflow_supply_chain_risks(tmp_path):
    gitlab_ci = tmp_path / ".gitlab-ci.yml"
    _write_risky_gitlab_ci(gitlab_ci)

    findings = scan_gitlab_ci(tmp_path)

    assert {
        "SKY-D314",
        "SKY-D315",
        "SKY-D316",
        "SKY-D317",
        "SKY-D318",
        "SKY-D319",
        "SKY-D320",
        "SKY-D321",
        "SKY-D322",
    }.issubset(_rule_ids(findings))
    assert {
        "kind": "config",
        "domain": "cicd",
        "provider": "gitlab_ci",
        "type": "workflow",
    }.items() <= findings[0].items()


def test_gitlab_ci_scanner_accepts_pinned_minimal_workflow(tmp_path):
    full_sha = "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
    gitlab_ci = tmp_path / ".gitlab-ci.yml"
    gitlab_ci.write_text(
        f"""
include:
  - project: group/security/pipelines
    file: template.yml
    ref: {full_sha}
  - remote: https://example.com/ci.yml
    integrity: sha256-abc123

image: python@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b

variables:
  SAFE_MODE: "true"

test:
  stage: test
  services:
    - postgres@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b
  script:
    - echo "$CI_COMMIT_REF_NAME"

deploy:
  stage: deploy
  timeout: 15 minutes
  id_tokens:
    VAULT_TOKEN:
      aud: https://vault.example.com
  secrets:
    PROD_PASSWORD:
      vault: production/password@ops
      token: $VAULT_TOKEN
  script:
    - echo "publish prebuilt artifact"
""".lstrip(),
        encoding="utf-8",
    )

    assert scan_gitlab_ci(tmp_path) == []


def test_gitlab_ci_changed_files_stay_under_scan_root(tmp_path):
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    outside_workflow = outside / ".gitlab-ci.yml"
    _write_risky_gitlab_ci(outside_workflow)

    findings = scan_config_files(
        repo,
        changed_files={str(outside_workflow), "../outside/.gitlab-ci.yml"},
    )

    assert findings == []


def test_gitlab_ci_scanner_rejects_symlinked_workflow(tmp_path):
    target = tmp_path / "outside-gitlab-ci.yml"
    target.write_text("image: python:latest\n", encoding="utf-8")
    link = tmp_path / ".gitlab-ci.yml"
    try:
        link.symlink_to(target)
    except OSError:
        return

    assert scan_gitlab_ci(tmp_path) == []


def test_config_scanner_routes_single_gitlab_ci_file(tmp_path):
    gitlab_ci = tmp_path / ".gitlab-ci.yml"
    _write_risky_gitlab_ci(gitlab_ci)

    findings = scan_config_files(gitlab_ci)

    assert {"SKY-D314", "SKY-D315", "SKY-D317"}.issubset(_rule_ids(findings))


def test_config_scanner_ignores_unowned_config_files_for_gitlab_ci(tmp_path):
    for relative in (
        "app.py",
        "config.yml",
        ".gitlab-ci.yaml",
        "Jenkinsfile",
        "Dockerfile",
        "main.tf",
    ):
        path = tmp_path / relative
        path.write_text(
            """
include:
  - project: group/security/pipelines
image: python:latest
deploy:
  stage: deploy
  script:
    - eval "$CI_MERGE_REQUEST_TITLE"
""".lstrip(),
            encoding="utf-8",
        )

    assert scan_config_files(tmp_path) == []
    assert scan_config_files(tmp_path / "app.py") == []
    assert scan_config_files(tmp_path / "config.yml") == []
    assert scan_config_files(tmp_path / ".gitlab-ci.yaml") == []
    assert scan_config_files(tmp_path / "Jenkinsfile") == []
    assert scan_config_files(tmp_path / "Dockerfile") == []
    assert scan_config_files(tmp_path / "main.tf") == []


def test_gitlab_ci_scanner_rejects_recursive_yaml_alias(tmp_path):
    gitlab_ci = tmp_path / ".gitlab-ci.yml"
    gitlab_ci.write_text(
        """
deploy: &deploy
  stage: deploy
  script:
    - echo ok
  self: *deploy
""".lstrip(),
        encoding="utf-8",
    )

    assert scan_gitlab_ci(tmp_path) == []


def test_gitlab_ci_scanner_handles_shared_yaml_alias_once(tmp_path):
    gitlab_ci = tmp_path / ".gitlab-ci.yml"
    gitlab_ci.write_text(
        """
.secret-script: &secret-script
  - echo "$DEPLOY_TOKEN"

variables:
  DEPLOY_TOKEN: plaintext-token-123

deploy:
  stage: deploy
  script: *secret-script
  after_script: *secret-script
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_gitlab_ci(tmp_path)

    assert "SKY-D316" in _rule_ids(findings)


def test_gitlab_ci_scanner_detects_ambiguous_secret_token(tmp_path):
    gitlab_ci = tmp_path / ".gitlab-ci.yml"
    gitlab_ci.write_text(
        """
deploy:
  stage: deploy
  timeout: 10 minutes
  id_tokens:
    VAULT_A:
      aud: https://vault-a.example.com
    VAULT_B:
      aud: https://vault-b.example.com
  secrets:
    PROD_PASSWORD:
      vault: production/password@ops
  script:
    - echo "deploy"
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_gitlab_ci(tmp_path)

    assert "SKY-D323" in _rule_ids(findings)


def test_analyzer_reports_gitlab_ci_dangers_without_source_files(tmp_path):
    gitlab_ci = tmp_path / ".gitlab-ci.yml"
    gitlab_ci.write_text(
        """
include:
  - project: group/security/pipelines
image: python:latest
deploy:
  stage: deploy
  script:
    - docker push registry.example.com/app:latest
""".lstrip(),
        encoding="utf-8",
    )

    result = json.loads(analyze(str(tmp_path), enable_danger=True))

    assert "danger" in result
    assert {"SKY-D314", "SKY-D315", "SKY-D321"}.issubset(_rule_ids(result["danger"]))
    assert result["analysis_summary"]["danger_count"] == len(result["danger"])
