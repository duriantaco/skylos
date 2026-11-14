from pathlib import Path

from skylos.rules.config.cicd.github_actions import scan_github_actions

_SHA = "de0fac2e4500dabe0009e67214ff5f5447ce83dd"


def _scan(root: Path, text: str):
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "call.yml").write_text(text, encoding="utf-8")
    return sorted(
        (finding["line"], finding["value"])
        for finding in scan_github_actions(root)
        if finding["rule_id"] == "SKY-D297"
    )


def test_each_job_is_reported_on_its_own_secrets_inherit_line(tmp_path):
    workflow = (
        "# Callers hand secrets to the shared workflows below.\n"
        "name: Call\n"
        "on: push\n"
        "permissions: {}\n"
        "jobs:\n"
        "  lint:\n"
        "    runs-on: ubuntu-latest\n"
        "    env:\n"
        "      LINT_TOKEN: ${{ secrets.LINT_TOKEN }}\n"
        "    steps:\n"
        "      - run: make lint\n"
        "  build:\n"
        f"    uses: org/repo/.github/workflows/build.yml@{_SHA}\n"
        "    secrets: inherit\n"
        "  deploy:\n"
        "    uses: ./.github/workflows/deploy.yml\n"
        "    with:\n"
        "      environment: prod\n"
        "    secrets: inherit\n"
    )

    assert _scan(tmp_path, workflow) == [(14, "build:inherit"), (19, "deploy:inherit")]


def test_marker_above_secrets_inherit_suppresses_it(tmp_path):
    workflow = (
        "# Shared secrets are reviewed per job.\n"
        "name: Call\n"
        "on: push\n"
        "permissions: {}\n"
        "jobs:\n"
        "  deploy:\n"
        "    uses: ./.github/workflows/deploy.yml\n"
        "    # skylos: ignore[SKY-D297] same-repo workflow, reviewed\n"
        "    secrets: inherit\n"
        "  release:\n"
        "    uses: ./.github/workflows/release.yml\n"
        "    secrets: inherit\n"
    )

    assert _scan(tmp_path, workflow) == [(12, "release:inherit")]


def test_named_secrets_and_step_text_are_not_reported(tmp_path):
    workflow = (
        "name: Call\n"
        "on: push\n"
        "permissions: {}\n"
        "jobs:\n"
        "  deploy:\n"
        "    uses: ./.github/workflows/deploy.yml\n"
        "    secrets:\n"
        "      DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n"
        "  notes:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo 'secrets: inherit'\n"
    )

    assert _scan(tmp_path, workflow) == []


def test_flow_style_job_reports_the_secrets_key_line(tmp_path):
    workflow = (
        "name: Call\n"
        "on: push\n"
        "permissions: {}\n"
        "jobs:\n"
        "  deploy: {uses: ./.github/workflows/deploy.yml,\n"
        "    secrets: inherit}\n"
    )

    assert _scan(tmp_path, workflow) == [(6, "deploy:inherit")]
