"""SKY-D350 to SKY-D354: AI coding agents running in GitHub Actions."""

import textwrap

import pytest

from skylos.rules.config.cicd.ai_agent_expressions import (
    EvalContext,
    evaluate,
    parse_condition,
)
from skylos.rules.config.cicd.github_actions import scan_github_actions

AGENT_RULES = {"SKY-D350", "SKY-D351", "SKY-D352", "SKY-D353", "SKY-D354"}


def _write(tmp_path, text, name="agent.yml"):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    path = workflows / name
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    return path


def _agent_findings(tmp_path, **kwargs):
    return [
        finding
        for finding in scan_github_actions(tmp_path, **kwargs)
        if finding["rule_id"] in AGENT_RULES
    ]


def _by_rule(findings):
    result = {}
    for finding in findings:
        result.setdefault(finding["rule_id"], []).append(finding)
    return result


CLINEJECTION = """
name: Issue triage
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          github_token: ${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: "*"
          claude_args: --allowedTools "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch"
          prompt: |
            Triage this issue: ${{ github.event.issue.title }}
"""


def test_clinejection_configuration_is_reported_on_each_axis(tmp_path):
    _write(tmp_path, CLINEJECTION)

    found = _by_rule(_agent_findings(tmp_path))

    assert set(found) == {"SKY-D351", "SKY-D352", "SKY-D353"}
    widened = found["SKY-D351"][0]
    assert widened["severity"] == "CRITICAL"
    assert widened["line"] == 14
    assert "issues (anyone who can open an issue) → claude-code-action" in widened["message"]
    assert 'allowed_non_write_users: "*"' in widened["message"]
    assert "Bash in --allowedTools" in widened["message"]
    assert "ANTHROPIC_API_KEY" in widened["message"]
    assert found["SKY-D352"][0]["severity"] == "HIGH"
    assert found["SKY-D353"][0]["severity"] == "HIGH"
    assert "github.event.issue.title" in found["SKY-D353"][0]["message"]


def test_allowed_non_write_users_without_github_token_keeps_the_check(tmp_path):
    # The action only honours allowed_non_write_users when github_token is passed.
    _write(tmp_path, CLINEJECTION.replace(
        "          github_token: ${{ secrets.GITHUB_TOKEN }}\n", ""
    ))

    found = _by_rule(_agent_findings(tmp_path))

    assert "SKY-D350" not in found
    assert "SKY-D351" not in found


def test_claude_code_action_defaults_are_not_reported(tmp_path):
    _write(
        tmp_path,
        """
        name: Claude
        on:
          issue_comment:
            types: [created]
          pull_request_review_comment:
            types: [created]
          issues:
            types: [opened, assigned]
        jobs:
          claude:
            if: contains(github.event.comment.body, '@claude')
            runs-on: ubuntu-latest
            permissions:
              contents: write
              pull-requests: write
              issues: write
              id-token: write
            steps:
              - uses: actions/checkout@v4
              - uses: anthropics/claude-code-action@v1
                with:
                  anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
        """,
    )

    assert _agent_findings(tmp_path) == []


def test_allowed_bots_wildcard_is_capped_at_high(tmp_path):
    _write(
        tmp_path,
        """
        name: Claude
        on: issue_comment
        jobs:
          claude:
            runs-on: ubuntu-latest
            steps:
              - uses: anthropics/claude-code-action@v1
                with:
                  anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
                  allowed_bots: "*"
                  claude_args: --dangerously-skip-permissions
        """,
    )

    found = _by_rule(_agent_findings(tmp_path))

    assert found["SKY-D351"][0]["severity"] == "HIGH"
    assert "any GitHub App" in found["SKY-D351"][0]["message"]
    assert found["SKY-D352"][0]["severity"] == "HIGH"


def test_gemini_on_comments_without_gate_is_critical(tmp_path):
    _write(
        tmp_path,
        """
        name: Gemini
        on:
          issue_comment:
        jobs:
          gemini:
            if: startsWith(github.event.comment.body, '@gemini-cli')
            runs-on: ubuntu-latest
            steps:
              - uses: google-github-actions/run-gemini-cli@v0
                env:
                  GEMINI_CLI_TRUST_WORKSPACE: 'true'
                with:
                  gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
                  prompt: "Answer: ${{ github.event.comment.body }}"
        """,
    )

    found = _by_rule(_agent_findings(tmp_path))

    no_gate = found["SKY-D350"][0]
    assert no_gate["severity"] == "CRITICAL"
    assert no_gate["message"].startswith(
        "issue_comment (anyone who can comment) → run-gemini-cli (the prompt "
        "interpolates github.event.comment.body) with shell commands"
    )
    assert "GEMINI_API_KEY" in no_gate["message"]
    assert found["SKY-D353"][0]["severity"] == "HIGH"


def test_gemini_without_workspace_trust_is_not_claimed_as_shell(tmp_path):
    # From Gemini CLI 0.39.1, an untrusted workspace ignores project settings
    # and turns off tool auto-approval, so YOLO shell access is not proven.
    _write(
        tmp_path,
        """
        name: Gemini
        on: issue_comment
        jobs:
          gemini:
            runs-on: ubuntu-latest
            steps:
              - uses: google-github-actions/run-gemini-cli@v0
                with:
                  gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
                  prompt: "Answer: ${{ github.event.comment.body }}"
        """,
    )

    found = _by_rule(_agent_findings(tmp_path))

    assert found["SKY-D350"][0]["severity"] == "MEDIUM"
    assert "no GEMINI_CLI_TRUST_WORKSPACE" in found["SKY-D350"][0]["message"]
    assert "SKY-D352" not in found


@pytest.mark.parametrize(
    "condition",
    [
        "contains(fromJSON('[\"OWNER\", \"MEMBER\", \"COLLABORATOR\"]'), github.event.comment.author_association)",
        "github.event.comment.author_association == 'OWNER' || github.event.comment.author_association == 'MEMBER'",
        "github.actor == 'octocat'",
        "contains('OWNER,MEMBER,COLLABORATOR', github.event.comment.author_association)",
        "${{ github.event.sender.login == github.repository_owner }}",
    ],
)
def test_actor_gate_on_job_stops_the_no_gate_finding(tmp_path, condition):
    _write(
        tmp_path,
        f"""
        name: Gemini
        on: issue_comment
        jobs:
          gemini:
            if: {condition!r}
            runs-on: ubuntu-latest
            steps:
              - uses: google-github-actions/run-gemini-cli@v0
                with:
                  gemini_api_key: ${{{{ secrets.GEMINI_API_KEY }}}}
                  settings: '{{"tools": {{"core": ["read_file", "glob"]}}}}'
        """,
    )

    assert _agent_findings(tmp_path) == []


@pytest.mark.parametrize(
    "condition",
    [
        # The issue author's association says nothing about the commenter.
        "github.event.comment.author_association == 'OWNER' || github.event.issue.author_association == 'OWNER'",
        "github.event.comment.author_association != 'NONE'",
        "contains('NONE,OWNER', github.event.comment.author_association)",
        "${{ github.event.comment.author_association == 'OWNER' }} && ${{ true }}",
    ],
)
def test_conditions_that_do_not_gate_the_commenter_still_report(tmp_path, condition):
    _write(
        tmp_path,
        f"""
        name: Gemini
        on: issue_comment
        jobs:
          gemini:
            if: {condition!r}
            runs-on: ubuntu-latest
            env:
              GEMINI_CLI_TRUST_WORKSPACE: 'true'
            steps:
              - uses: google-github-actions/run-gemini-cli@v0
                with:
                  gemini_api_key: ${{{{ secrets.GEMINI_API_KEY }}}}
                  prompt: "Answer the question in issue #${{{{ github.event.issue.number }}}}"
        """,
    )

    assert "SKY-D350" in _by_rule(_agent_findings(tmp_path))


def test_gemini_dispatch_gate_covers_comments_but_not_opened_issues(tmp_path):
    condition = """|-
              (
                github.event_name == 'issues' &&
                contains(fromJSON('["opened", "reopened"]'), github.event.action)
              ) || (
                github.event.sender.type == 'User' &&
                startsWith(github.event.comment.body || github.event.issue.body, '@gemini-cli') &&
                contains(fromJSON('["OWNER", "MEMBER", "COLLABORATOR"]'), github.event.comment.author_association || github.event.issue.author_association)
              )"""
    _write(
        tmp_path,
        f"""
        name: Gemini
        on:
          issues:
            types: [opened, reopened]
          issue_comment:
            types: [created]
        jobs:
          gemini:
            if: {condition}
            runs-on: ubuntu-latest
            env:
              GEMINI_CLI_TRUST_WORKSPACE: 'true'
            steps:
              - uses: google-github-actions/run-gemini-cli@v0
                with:
                  gemini_api_key: ${{{{ secrets.GEMINI_API_KEY }}}}
                  prompt: "/gemini-invoke"
        """,
    )

    no_gate = _by_rule(_agent_findings(tmp_path))["SKY-D350"]

    assert len(no_gate) == 1
    assert no_gate[0]["message"].startswith("issues (anyone who can open an issue) →")
    assert "issue_comment" not in no_gate[0]["message"]


def test_gemini_triage_without_tools_is_not_reported(tmp_path):
    # run-gemini-cli's own triage example: untrusted issues, but no tools at all.
    _write(
        tmp_path,
        """
        name: Triage
        on:
          issues:
            types: [opened]
        jobs:
          triage:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              id-token: write
              issues: read
            steps:
              - uses: google-github-actions/run-gemini-cli@v0
                env:
                  GEMINI_CLI_TRUST_WORKSPACE: 'true'
                  GITHUB_TOKEN: ''
                with:
                  gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
                  prompt: "Label: ${{ github.event.issue.title }}"
                  settings: |-
                    {"tools": {"core": []}}
        """,
    )

    assert _agent_findings(tmp_path) == []


def test_gemini_restricted_shell_is_high_and_old_cli_makes_it_critical(tmp_path):
    workflow = """
        name: Triage
        on:
          issues:
            types: [opened]
        jobs:
          triage:
            runs-on: ubuntu-latest
            permissions:
              issues: write
            env:
              GEMINI_CLI_TRUST_WORKSPACE: 'true'
            steps:
              - uses: google-github-actions/run-gemini-cli@v0
                with:
                  gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
                  gemini_cli_version: VERSION
                  prompt: "Label issue ${{ github.event.issue.number }} with gh issue edit"
                  settings: '{"tools": {"core": ["run_shell_command(gh issue edit)"]}}'
        """
    _write(tmp_path, workflow.replace("VERSION", "latest"))
    latest = _by_rule(_agent_findings(tmp_path))
    assert latest["SKY-D350"][0]["severity"] == "HIGH"
    assert "SKY-D352" not in latest
    assert "SKY-D354" not in latest

    _write(tmp_path, workflow.replace("VERSION", "0.30.0"))
    old = _by_rule(_agent_findings(tmp_path))
    assert old["SKY-D350"][0]["severity"] == "CRITICAL"
    assert "ignored under --yolo" in old["SKY-D350"][0]["message"]
    assert old["SKY-D354"][0]["severity"] == "HIGH"
    assert "gemini_cli_version 0.30.0" in old["SKY-D354"][0]["message"]


def test_read_only_permissions_and_no_secrets_are_not_reported(tmp_path):
    _write(
        tmp_path,
        """
        name: Gemini
        on: issue_comment
        permissions:
          contents: read
        jobs:
          gemini:
            runs-on: ubuntu-latest
            steps:
              - uses: google-github-actions/run-gemini-cli@v0
                with:
                  gemini_api_key: ${{ vars.KEY_IS_NOT_A_SECRET }}
                  settings: '{"tools": {"core": ["read_file"]}}'
        """,
    )

    assert _agent_findings(tmp_path) == []


@pytest.mark.parametrize(
    "trigger",
    [
        "pull_request",
        "workflow_dispatch",
        "push",
        "schedule:\n  - cron: '0 0 * * *'",
        "issues:\n  types: [labeled, assigned]",
        "pull_request_target:\n  types: [labeled]",
    ],
)
def test_trusted_triggers_are_not_reported(tmp_path, trigger):
    on_block = textwrap.indent(trigger, "  ")
    _write(
        tmp_path,
        "name: Agent\non:\n"
        + on_block
        + """
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
        with:
          gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
      - run: npx -y @anthropic-ai/claude-code -p "review" --dangerously-skip-permissions
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
""",
    )

    assert _agent_findings(tmp_path) == []


def test_pull_request_target_same_repository_check_is_a_gate(tmp_path):
    _write(
        tmp_path,
        """
        name: Review
        on: pull_request_target
        jobs:
          review:
            if: github.event.pull_request.head.repo.full_name == github.repository
            runs-on: ubuntu-latest
            steps:
              - run: claude -p "review this PR" --dangerously-skip-permissions
                env:
                  ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        """,
    )

    assert _agent_findings(tmp_path) == []


def test_cli_agent_in_run_block_on_pull_request_target(tmp_path):
    _write(
        tmp_path,
        """
        name: Review
        on: pull_request_target
        permissions:
          contents: read
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  npx -y @anthropic-ai/claude-code -p "Review this pull request" \\
                    --dangerously-skip-permissions
                env:
                  ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        """,
    )

    found = _by_rule(_agent_findings(tmp_path))

    assert found["SKY-D350"][0]["severity"] == "CRITICAL"
    assert found["SKY-D350"][0]["message"].startswith(
        "pull_request_target (fork pull requests) → Claude Code CLI (it can read the "
        "issue or pull request (shell commands)) with shell commands"
    )
    assert found["SKY-D352"][0]["severity"] == "HIGH"


@pytest.mark.parametrize(
    "command",
    [
        "copilot deploy --env prod",  # AWS Copilot
        "copilot svc deploy --name api -p",
        "echo claude -p --dangerously-skip-permissions",
        "gemini-lint --yolo",
    ],
)
def test_non_agent_commands_are_not_agents(tmp_path, command):
    _write(
        tmp_path,
        f"""
        name: Deploy
        on: issue_comment
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: {command}
                env:
                  TOKEN: ${{{{ secrets.TOKEN }}}}
        """,
    )

    assert _agent_findings(tmp_path) == []


def test_codex_action_check_and_widening(tmp_path):
    workflow = """
        name: Codex
        on: issue_comment
        jobs:
          codex:
            runs-on: ubuntu-latest
            steps:
              - uses: openai/codex-action@v1
                with:
                  openai-api-key: ${{ secrets.OPENAI_API_KEY }}
                  prompt: "Fix: ${{ github.event.comment.body }}"
                  EXTRA
        """
    _write(tmp_path, workflow.replace("EXTRA", "sandbox: workspace-write"))
    # Built-in write-access check, and the commenter's own text: nothing to report.
    assert _agent_findings(tmp_path) == []

    _write(
        tmp_path,
        workflow.replace(
            "EXTRA", 'allow-users: "*"\n' + " " * 18 + "sandbox: danger-full-access"
        ),
    )
    found = _by_rule(_agent_findings(tmp_path))
    assert found["SKY-D351"][0]["severity"] == "CRITICAL"
    assert 'allow-users: "*"' in found["SKY-D351"][0]["message"]
    assert found["SKY-D352"][0]["severity"] == "HIGH"
    assert found["SKY-D353"][0]["severity"] == "HIGH"


def test_maintainer_triggered_shell_agent_reading_others_text_is_medium(tmp_path):
    _write(
        tmp_path,
        """
        name: Claude
        on: issue_comment
        jobs:
          claude:
            runs-on: ubuntu-latest
            steps:
              - uses: anthropics/claude-code-action@v1
                with:
                  anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
                  claude_args: '--allowedTools "Bash"'
                  prompt: "Summarise ${{ github.event.issue.body }} for ${{ github.event.comment.body }}"
        """,
    )

    found = _by_rule(_agent_findings(tmp_path))

    assert "SKY-D350" not in found and "SKY-D351" not in found
    assert found["SKY-D352"][0]["severity"] == "MEDIUM"
    prompt = found["SKY-D353"]
    assert len(prompt) == 1
    assert "github.event.issue.body" in prompt[0]["message"]
    assert prompt[0]["severity"] == "MEDIUM"


def test_restricted_bash_rules_are_not_arbitrary_shell(tmp_path):
    _write(
        tmp_path,
        """
        name: Claude
        on: issue_comment
        jobs:
          claude:
            runs-on: ubuntu-latest
            steps:
              - uses: anthropics/claude-code-action@v1
                with:
                  anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
                  claude_args: '--allowedTools "Bash(gh issue view:*),Bash(git log *),Bash(npm test)"'
        """,
    )

    assert _agent_findings(tmp_path) == []


def test_legacy_allowed_tools_input_only_counts_on_v0(tmp_path):
    workflow = """
        name: Claude
        on: issue_comment
        jobs:
          claude:
            runs-on: ubuntu-latest
            steps:
              - uses: anthropics/claude-code-action@REF
                with:
                  anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
                  allowed_tools: "Bash"
        """
    _write(tmp_path, workflow.replace("REF", "beta"))
    assert "SKY-D352" in _by_rule(_agent_findings(tmp_path))

    _write(tmp_path, workflow.replace("REF", "v1"))
    assert _agent_findings(tmp_path) == []


def test_ai_inference_needs_tools_to_be_reported(tmp_path):
    workflow = """
        name: Triage
        on:
          issues:
            types: [opened]
        permissions:
          issues: write
          models: read
        jobs:
          triage:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/ai-inference@v1
                with:
                  prompt: "Classify: ${{ github.event.issue.body }}"
                  EXTRA
        """
    _write(tmp_path, workflow.replace("EXTRA", "model: openai/gpt-4.1"))
    assert _agent_findings(tmp_path) == []

    _write(tmp_path, workflow.replace("EXTRA", "enable-github-mcp: true"))
    found = _by_rule(_agent_findings(tmp_path))
    assert found["SKY-D350"][0]["severity"] == "HIGH"
    assert "GitHub MCP tools" in found["SKY-D350"][0]["message"]
    assert "issues: write" in found["SKY-D350"][0]["message"]
    assert found["SKY-D353"][0]["severity"] == "HIGH"


def test_needs_job_with_gate_or_environment_blocks_untrusted_accounts(tmp_path):
    for gate_job in (
        """
          authorize:
            if: github.event.comment.author_association == 'MEMBER'
            runs-on: ubuntu-latest
            steps:
              - run: echo ok
        """,
        """
          authorize:
            environment: external-contributors
            runs-on: ubuntu-latest
            steps:
              - run: echo ok
        """,
        """
          authorize:
            runs-on: ubuntu-latest
            steps:
              - uses: prince-chrismc/check-actor-permissions-action@v3
                with:
                  permission: write
        """,
    ):
        _write(
            tmp_path,
            """
            name: Gemini
            on: issue_comment
            jobs:
            """
            + textwrap.indent(textwrap.dedent(gate_job), "  ")
            + """
              gemini:
                needs: authorize
                runs-on: ubuntu-latest
                steps:
                  - uses: google-github-actions/run-gemini-cli@v0
                    with:
                      gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
                      settings: '{"tools": {"core": ["read_file"]}}'
            """,
        )
        assert _agent_findings(tmp_path) == [], gate_job


def test_always_ignores_a_gated_needs_job(tmp_path):
    _write(
        tmp_path,
        """
        name: Gemini
        on: issue_comment
        jobs:
          authorize:
            if: github.event.comment.author_association == 'MEMBER'
            runs-on: ubuntu-latest
            steps:
              - run: echo ok
          gemini:
            needs: authorize
            if: always()
            runs-on: ubuntu-latest
            steps:
              - uses: google-github-actions/run-gemini-cli@v0
                with:
                  gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
                  prompt: "Answer ${{ github.event.comment.body }}"
        """,
    )

    assert "SKY-D350" in _by_rule(_agent_findings(tmp_path))


def test_prior_permission_check_step_is_a_gate(tmp_path):
    _write(
        tmp_path,
        """
        name: Gemini
        on: issue_comment
        jobs:
          gemini:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@v7
                with:
                  script: |
                    const { data } = await github.rest.repos.getCollaboratorPermissionLevel({
                      owner: context.repo.owner, repo: context.repo.repo, username: context.actor });
                    if (!['admin', 'write'].includes(data.permission)) core.setFailed('no');
              - uses: google-github-actions/run-gemini-cli@v0
                with:
                  gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
                  settings: '{"tools": {"core": ["read_file"]}}'
        """,
    )

    assert _agent_findings(tmp_path) == []


def test_reusable_workflow_inherits_the_callers_untrusted_event(tmp_path):
    _write(
        tmp_path,
        """
        name: Dispatch
        on: issue_comment
        jobs:
          invoke:
            uses: ./.github/workflows/gemini-invoke.yml
            secrets: inherit
        """,
        name="dispatch.yml",
    )
    called = """
        name: Gemini invoke
        on: workflow_call
        env:
          GEMINI_CLI_TRUST_WORKSPACE: 'true'
        jobs:
          invoke:
            runs-on: ubuntu-latest
            steps:
              - uses: google-github-actions/run-gemini-cli@v0
                with:
                  gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
                  prompt: "/gemini-invoke"
        """
    _write(tmp_path, called, name="gemini-invoke.yml")

    no_gate = _by_rule(_agent_findings(tmp_path))["SKY-D350"]

    assert len(no_gate) == 1
    assert no_gate[0]["file"].endswith("gemini-invoke.yml")
    assert "issue_comment (anyone who can comment) via dispatch.yml" in no_gate[0]["message"]
    assert "GEMINI_API_KEY" in no_gate[0]["message"]

    _write(
        tmp_path,
        """
        name: Dispatch
        on: issue_comment
        jobs:
          invoke:
            if: contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)
            uses: ./.github/workflows/gemini-invoke.yml
            secrets: inherit
        """,
        name="dispatch.yml",
    )
    assert "SKY-D350" not in _by_rule(_agent_findings(tmp_path))


def test_dispatcher_output_routing_is_not_assumed_for_every_event(tmp_path):
    # run-gemini-cli's dispatch example: issues events only ever produce
    # command=triage; invoke runs for gated comments.
    _write(
        tmp_path,
        """
        name: Dispatch
        on:
          issues:
            types: [opened]
          issue_comment:
        jobs:
          dispatch:
            if: >-
              github.event_name == 'issues' ||
              contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)
            runs-on: ubuntu-latest
            outputs:
              command: ${{ steps.route.outputs.command }}
            steps:
              - id: route
                uses: actions/github-script@v7
                env:
                  EVENT_TYPE: '${{ github.event_name }}.${{ github.event.action }}'
                with:
                  script: |
                    core.setOutput('command', process.env.EVENT_TYPE === 'issues.opened' ? 'triage' : 'invoke');
          invoke:
            needs: dispatch
            if: needs.dispatch.outputs.command == 'invoke'
            uses: ./.github/workflows/gemini-invoke.yml
            secrets: inherit
        """,
        name="dispatch.yml",
    )
    _write(
        tmp_path,
        """
        name: Gemini invoke
        on: workflow_call
        jobs:
          invoke:
            runs-on: ubuntu-latest
            env:
              GEMINI_CLI_TRUST_WORKSPACE: 'true'
            steps:
              - uses: google-github-actions/run-gemini-cli@v0
                with:
                  gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
                  prompt: "/gemini-invoke"
        """,
        name="gemini-invoke.yml",
    )

    assert "SKY-D350" not in _by_rule(_agent_findings(tmp_path))


def test_workflow_run_upstream_triggers_decide_trust(tmp_path):
    _write(
        tmp_path,
        """
        name: CI
        on: UPSTREAM
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: make test
        """.replace("UPSTREAM", "push"),
        name="ci.yml",
    )
    _write(
        tmp_path,
        """
        name: Fix CI
        on:
          workflow_run:
            workflows: ["CI"]
            types: [completed]
        jobs:
          fix:
            runs-on: ubuntu-latest
            steps:
              - uses: anthropics/claude-code-action@v1.0.100
                with:
                  anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
                  claude_args: --dangerously-skip-permissions
                  prompt: "Fix the failing checks on the pull request for run ${{ github.event.workflow_run.id }}"
        """,
        name="fix.yml",
    )
    assert _agent_findings(tmp_path) == []

    _write(
        tmp_path,
        """
        name: CI
        on: pull_request
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: make test
        """,
        name="ci.yml",
    )
    found = _by_rule(_agent_findings(tmp_path))
    # Before v1.0.185 claude-code-action did not check workflow_run actors.
    assert found["SKY-D350"][0]["severity"] == "CRITICAL"
    assert "workflow_run" in found["SKY-D350"][0]["message"]


def test_workflow_run_actor_check_in_current_claude_code_action(tmp_path):
    _write(
        tmp_path,
        """
        name: Fix CI
        on:
          workflow_run:
            workflows: ["Unknown CI"]
        jobs:
          fix:
            runs-on: ubuntu-latest
            steps:
              - uses: anthropics/claude-code-action@v1
                with:
                  anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
                  claude_args: --dangerously-skip-permissions
                  prompt: "Fix the failing checks on the pull request"
        """,
    )

    assert _agent_findings(tmp_path) == []


@pytest.mark.parametrize(
    ("uses", "expected"),
    [
        ("anthropics/claude-code-action@v1.0.50", "LOW"),
        # Release v1.0.73 pinned by commit.
        ("anthropics/claude-code-action@1b422b3517b51140e4484faab676c5e68b914866", "LOW"),
        ("anthropics/claude-code-action@v1.0.74", None),
        ("anthropics/claude-code-action@v1", None),
        ("anthropics/claude-code-action@beta", None),
        ("google-github-actions/run-gemini-cli@v0.1.21", "MEDIUM"),
        ("google-github-actions/run-gemini-cli@9dbec29a20fab3f35017a40ad0eb798a257d4d51", "MEDIUM"),
        ("google-github-actions/run-gemini-cli@v0.1.22", None),
        ("google-github-actions/run-gemini-cli@v0", None),
    ],
)
def test_known_advisory_versions(tmp_path, uses, expected):
    _write(
        tmp_path,
        f"""
        name: Agent
        on: workflow_dispatch
        jobs:
          agent:
            runs-on: ubuntu-latest
            steps:
              - uses: {uses}
                with:
                  prompt: hello
        """,
    )

    advisories = _by_rule(_agent_findings(tmp_path)).get("SKY-D354", [])

    if expected is None:
        assert advisories == []
    else:
        assert len(advisories) == 1
        assert advisories[0]["severity"] == expected
        assert "GHSA-" in advisories[0]["message"]


def test_inline_and_configured_ignores(tmp_path):
    _write(tmp_path, CLINEJECTION.replace(
        '          allowed_non_write_users: "*"',
        '          # skylos: ignore[SKY-D351] reviewed: label-only workflow\n'
        '          allowed_non_write_users: "*"',
    ))
    found = _by_rule(_agent_findings(tmp_path))
    assert "SKY-D351" not in found
    assert "SKY-D352" in found

    _write(tmp_path, CLINEJECTION)
    ignored = _agent_findings(tmp_path, ignore={"SKY-D351", "SKY-D352", "SKY-D353"})
    assert ignored == []


def test_agent_that_never_sees_event_text_is_not_reported(tmp_path):
    # Anyone can start it, but the prompt is fixed, the checkout is the base
    # branch, and its tools cannot fetch the comment (Dragon-Git/uvm_bridge shape).
    _write(
        tmp_path,
        """
        name: Claude
        on:
          issue_comment:
            types: [created]
        jobs:
          review:
            runs-on: ubuntu-latest
            permissions:
              issues: write
              pull-requests: write
            steps:
              - uses: actions/checkout@v4
              - id: mention
                env:
                  COMMENT: ${{ github.event.comment.body }}
                run: |
                  if echo "$COMMENT" | grep -q "@claude"; then
                    echo "trigger=true" >> "$GITHUB_OUTPUT"
                  fi
              - if: steps.mention.outputs.trigger == 'true'
                uses: anthropics/claude-code-base-action@beta
                with:
                  anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
                  allowed_tools: "Bash(git:*),View,GlobTool"
                  prompt: "Review the code in this repository."
        """,
    )

    assert _agent_findings(tmp_path) == []


def test_event_text_written_to_a_file_by_an_earlier_step_reaches_the_agent(tmp_path):
    _write(
        tmp_path,
        """
        name: Claude
        on:
          issues:
            types: [opened]
        jobs:
          triage:
            runs-on: ubuntu-latest
            permissions:
              issues: write
            steps:
              - name: Save issue
                env:
                  BODY: ${{ github.event.issue.body }}
                run: printf '%s' "$BODY" > /tmp/issue.md
              - uses: anthropics/claude-code-base-action@beta
                with:
                  anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
                  prompt_file: /tmp/issue.md
                  allowed_tools: "Edit,Write"
        """,
    )

    no_gate = _by_rule(_agent_findings(tmp_path))["SKY-D350"][0]

    assert no_gate["severity"] == "HIGH"
    assert "Save issue writes github.event.issue.body to a file first" in no_gate["message"]


def test_widened_agent_mode_with_static_prompt_and_no_github_tools(tmp_path):
    _write(
        tmp_path,
        """
        name: Claude
        on:
          issues:
            types: [opened]
        jobs:
          triage:
            runs-on: ubuntu-latest
            steps:
              - uses: anthropics/claude-code-action@v1
                with:
                  anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
                  github_token: ${{ secrets.GITHUB_TOKEN }}
                  allowed_non_write_users: "*"
                  prompt: "Summarise the README."
        """,
    )

    assert _agent_findings(tmp_path) == []


def test_widened_agent_mode_with_read_only_gh_tools_is_medium(tmp_path):
    # The hardened triage shape that claude-code-action's docs recommend.
    _write(
        tmp_path,
        """
        name: Triage
        on:
          issues:
            types: [opened]
        jobs:
          classify:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              issues: read
              id-token: write
            steps:
              - uses: anthropics/claude-code-action@v1
                with:
                  github_token: ${{ secrets.GITHUB_TOKEN }}
                  allowed_non_write_users: "*"
                  claude_args: --allowed-tools "Bash(gh issue view:*)"
                  prompt: |
                    Read issue ${{ github.event.issue.number }} with gh issue view and classify it.
        """,
    )

    found = _by_rule(_agent_findings(tmp_path))

    assert set(found) == {"SKY-D351"}
    assert found["SKY-D351"][0]["severity"] == "MEDIUM"
    assert "read-only tools (Bash(gh issue view:*))" in found["SKY-D351"][0]["message"]


def test_slash_command_allowed_tools_come_from_the_command_file(tmp_path):
    commands = tmp_path / ".claude" / "commands"
    commands.mkdir(parents=True)
    (commands / "dedupe.md").write_text(
        "---\nallowed-tools: Bash(gh issue view:*), Bash(gh issue comment:*)\n"
        "description: Find duplicate issues\n---\nFind duplicates of $ARGUMENTS\n",
        encoding="utf-8",
    )
    _write(
        tmp_path,
        """
        name: Dedupe
        on:
          issues:
            types: [opened]
        jobs:
          dedupe:
            runs-on: ubuntu-latest
            permissions:
              issues: write
            steps:
              - uses: anthropics/claude-code-base-action@beta
                with:
                  prompt: "/dedupe ${{ github.repository }}/issues/${{ github.event.issue.number }}"
                  anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
        """,
    )

    no_gate = _by_rule(_agent_findings(tmp_path))["SKY-D350"][0]

    assert no_gate["severity"] == "HIGH"
    assert "Bash(gh issue comment:*)" in no_gate["message"]


@pytest.mark.parametrize(
    ("condition", "event", "untrusted", "expected"),
    [
        ("github.event_name == 'issues'", "issues", True, (True, False)),
        ("github.event_name == 'issues'", "issue_comment", True, (False, True)),
        ("github.event.comment.author_association == 'OWNER'", "issue_comment", True, (False, True)),
        ("github.event.comment.author_association == 'OWNER'", "issue_comment", False, (True, True)),
        # Null on an issues event.
        ("github.event.comment.author_association == 'OWNER'", "issues", False, (False, True)),
        ("!github.event.pull_request.head.repo.fork", "pull_request_target", True, (False, True)),
        ("github.event.workflow_run.event == 'push'", "workflow_run", True, (False, True)),
        ("contains(github.event.comment.body, '@claude')", "issue_comment", True, (True, True)),
        ("this is not an expression (", "issues", True, (True, True)),
    ],
)
def test_expression_evaluator(condition, event, untrusted, expected):
    context = EvalContext(event, untrusted, lambda _job: False)

    assert evaluate(parse_condition(condition), context) == expected


def test_gemini_read_only_command_allowlist_is_read_tier(tmp_path):
    _write(
        tmp_path,
        """
        name: Triage
        on:
          issues:
            types: [opened]
        permissions:
          issues: write
        jobs:
          triage:
            runs-on: ubuntu-latest
            env:
              GEMINI_CLI_TRUST_WORKSPACE: 'true'
            steps:
              - uses: google-github-actions/run-gemini-cli@v0
                with:
                  gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
                  prompt: "Triage ${{ github.event.issue.title }}"
                  settings: '{"coreTools": ["run_shell_command(echo)", "run_shell_command(gh issue view)", "read_file"]}'
        """,
    )

    found = _by_rule(_agent_findings(tmp_path))

    assert found["SKY-D350"][0]["severity"] == "MEDIUM"
    assert "read-only allowlisted commands" in found["SKY-D350"][0]["message"]


def test_script_that_fetches_the_issue_into_a_file_reaches_the_agent(tmp_path):
    _write(
        tmp_path,
        """
        name: Triage
        on:
          issues:
            types: [opened]
        permissions:
          issues: write
        jobs:
          triage:
            runs-on: ubuntu-latest
            steps:
              - name: Collect issue
                uses: actions/github-script@v7
                with:
                  script: |
                    const fs = require('fs');
                    fs.writeFileSync('issue.json', JSON.stringify(context.payload.issue));
              - uses: openai/codex-action@v1
                with:
                  openai-api-key: ${{ secrets.OPENAI_API_KEY }}
                  allow-users: "*"
                  prompt: "Label the issue described in issue.json"
        """,
    )

    widened = _by_rule(_agent_findings(tmp_path))["SKY-D351"][0]

    # codex-action's default sandbox has no network and keeps the key in a proxy.
    assert widened["severity"] == "MEDIUM"
    assert "sandboxed commands without network access" in widened["message"]
    assert "Collect issue writes the issue or pull request text it fetches" in widened["message"]


def test_private_repository_condition_counts_as_a_gate(tmp_path):
    # run-gemini-cli's gemini-cli.yml example: members of a public repository,
    # or anyone with access to a private one.
    _write(
        tmp_path,
        """
        name: Gemini
        on: issue_comment
        jobs:
          gemini:
            if: >-
              contains(github.event.comment.body, '@gemini-cli') &&
              (github.event.repository.private == true ||
               contains(fromJSON('["OWNER", "MEMBER", "COLLABORATOR"]'), github.event.comment.author_association))
            runs-on: ubuntu-latest
            steps:
              - uses: google-github-actions/run-gemini-cli@v0
                with:
                  gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
                  prompt: "Answer: ${{ github.event.comment.body }}"
        """,
    )

    assert "SKY-D350" not in _by_rule(_agent_findings(tmp_path))


def test_script_spotting_outsiders_is_not_a_permission_gate(tmp_path):
    _write(
        tmp_path,
        """
        name: Claude
        on:
          issues:
            types: [opened]
        jobs:
          route:
            runs-on: ubuntu-latest
            outputs:
              should_run: ${{ steps.check.outputs.should_run }}
            steps:
              - id: check
                run: |
                  if [[ "${{ github.event.issue.author_association }}" == "NONE" ]]; then
                    echo "should_run=true" >> "$GITHUB_OUTPUT"
                  fi
          triage:
            needs: route
            if: needs.route.outputs.should_run == 'true'
            runs-on: ubuntu-latest
            steps:
              - uses: anthropics/claude-code-action@v1
                with:
                  anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
                  github_token: ${{ secrets.GITHUB_TOKEN }}
                  allowed_non_write_users: "*"
                  claude_args: --allowedTools "Read,Bash(*)"
                  prompt: "Triage issue ${{ github.event.issue.number }}"
        """,
    )

    assert _by_rule(_agent_findings(tmp_path))["SKY-D351"][0]["severity"] == "CRITICAL"


def test_fixed_environment_is_noted_but_not_treated_as_approval(tmp_path):
    workflow = """
        name: Claude
        on:
          issues:
            types: [opened]
        jobs:
          triage:
            environment: ENV
            runs-on: ubuntu-latest
            steps:
              - run: claude -p "Fix issue ${{ github.event.issue.number }}" --dangerously-skip-permissions
                env:
                  ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        """
    _write(tmp_path, workflow.replace("ENV", "ai-bots"))
    no_gate = _by_rule(_agent_findings(tmp_path))["SKY-D350"][0]
    assert no_gate["severity"] == "HIGH"
    assert "uses environment ai-bots; required reviewers there would gate it" in no_gate["message"]

    _write(
        tmp_path,
        workflow.replace(
            "ENV", "${{ github.event.issue.author_association == 'OWNER' && 'trusted' || 'needs-approval' }}"
        ),
    )
    assert "SKY-D350" not in _by_rule(_agent_findings(tmp_path))


def test_codex_sandbox_with_network_access_is_tools(tmp_path):
    _write(
        tmp_path,
        """
        name: Dedupe
        on:
          issues:
            types: [opened]
        jobs:
          classify:
            runs-on: ubuntu-latest
            steps:
              - uses: openai/codex-action@v1
                with:
                  openai-api-key: ${{ secrets.OPENAI_API_KEY }}
                  allow-users: "*"
                  codex-args: '["-c", "sandbox_workspace_write.network_access=true"]'
                  prompt: "Is issue ${{ github.event.issue.number }} a duplicate?"
        """,
    )

    widened = _by_rule(_agent_findings(tmp_path))["SKY-D351"][0]

    assert widened["severity"] == "HIGH"
    assert "network access" in widened["message"]


def test_pull_request_checkout_on_comment_event_reaches_the_agent(tmp_path):
    _write(
        tmp_path,
        """
        name: Fix
        on: issue_comment
        jobs:
          fix:
            runs-on: ubuntu-latest
            steps:
              - run: gh pr checkout ${{ github.event.issue.number }}
              - run: claude -p "Make the tests pass" --dangerously-skip-permissions
                env:
                  ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        """,
    )

    no_gate = _by_rule(_agent_findings(tmp_path))["SKY-D350"][0]

    assert no_gate["severity"] == "CRITICAL"
    assert "the job checks out the pull request's code" in no_gate["message"]


def test_prompt_from_another_jobs_output_reaches_the_agent(tmp_path):
    _write(
        tmp_path,
        """
        name: Triage
        on:
          issues:
            types: [opened]
        jobs:
          context:
            runs-on: ubuntu-latest
            outputs:
              issue: ${{ steps.issue.outputs.context }}
            steps:
              - id: issue
                run: gh issue view "$N" --json title,body > issue.json && echo "context=$(cat issue.json)" >> "$GITHUB_OUTPUT"
                env:
                  N: ${{ github.event.issue.number }}
          triage:
            needs: context
            runs-on: ubuntu-latest
            steps:
              - uses: anthropics/claude-code-base-action@v1
                with:
                  anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
                  prompt: "Label this issue: ${{ needs.context.outputs.issue }}"
                  claude_args: --allowedTools "Bash(gh issue edit:*)"
        """,
    )

    no_gate = _by_rule(_agent_findings(tmp_path))["SKY-D350"][0]

    assert no_gate["severity"] == "HIGH"
    assert "the prompt uses job context's output" in no_gate["message"]


def test_agent_with_every_tool_denied_is_not_reported(tmp_path):
    _write(
        tmp_path,
        """
        name: Reopen
        on:
          issue_comment:
            types: [created]
        jobs:
          classify:
            runs-on: ubuntu-latest
            steps:
              - uses: anthropics/claude-code-action@v1
                with:
                  claude_code_oauth_token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
                  github_token: ${{ github.token }}
                  allowed_non_write_users: "*"
                  settings: |
                    {"permissions": {"allow": [], "deny": ["Bash", "Edit", "Write", "Read", "WebFetch"]}}
                  prompt: "Should this reopen? ${{ github.event.comment.body }}"
        """,
    )

    assert _agent_findings(tmp_path) == []


def test_exact_command_rule_is_not_any_shell_command(tmp_path):
    # claude-code-action's own claude.yml allows `Bash(bun install)`.
    _write(
        tmp_path,
        """
        name: Claude
        on: issue_comment
        jobs:
          claude:
            runs-on: ubuntu-latest
            steps:
              - uses: anthropics/claude-code-action@v1
                with:
                  anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
                  claude_args: --allowedTools "Bash(bun install),Bash(bun test:*),Bash(python3 scripts/check.py)"
        """,
    )

    assert _agent_findings(tmp_path) == []


def test_workflow_run_pull_requests_check_excludes_forks(tmp_path):
    _write(
        tmp_path,
        """
        name: CI
        on: pull_request
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: make test
        """,
        name="ci.yml",
    )
    _write(
        tmp_path,
        """
        name: Autofix
        on:
          workflow_run:
            workflows: ["CI"]
            types: [completed]
        jobs:
          fix:
            if: github.event.workflow_run.conclusion == 'failure' && github.event.workflow_run.pull_requests[0]
            runs-on: ubuntu-latest
            steps:
              - run: gemini --approval-mode yolo --prompt "Fix the failing pull request"
                env:
                  GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
                  GEMINI_CLI_TRUST_WORKSPACE: "true"
        """,
        name="autofix.yml",
    )

    assert _agent_findings(tmp_path) == []


def test_chained_workflow_run_resolves_to_trusted_upstreams(tmp_path):
    _write(
        tmp_path,
        """
        name: Create PR
        on: create
        jobs:
          open:
            runs-on: ubuntu-latest
            steps:
              - run: echo created
        """,
        name="create.yml",
    )
    _write(
        tmp_path,
        """
        name: CI Fix
        on:
          workflow_run:
            workflows:
            types: [completed]
        jobs:
          noop:
            runs-on: ubuntu-latest
            steps:
              - run: echo never
        """,
        name="fix.yml",
    )
    _write(
        tmp_path,
        """
        name: Review
        on:
          workflow_run:
            workflows: ["Create PR", "CI Fix"]
            types: [completed]
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - uses: anthropics/claude-code-action@v1
                with:
                  claude_code_oauth_token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
                  allowed_bots: "*"
                  claude_args: --dangerously-skip-permissions
                  prompt: "Review the pull request"
        """,
        name="review.yml",
    )

    assert _agent_findings(tmp_path) == []


def test_base_action_allowed_tools_count_for_a_pinned_commit(tmp_path):
    _write(
        tmp_path,
        """
        name: Respond
        on:
          issues:
            types: [opened]
        jobs:
          respond:
            runs-on: ubuntu-latest
            permissions:
              issues: write
            steps:
              - uses: anthropics/claude-code-base-action@e8132bc5e637a42c27763fc757faa37e1ee43b34
                with:
                  anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
                  prompt: "Answer issue ${{ github.event.issue.number }}: ${{ github.event.issue.body }}"
                  allowed_tools: "Read,Write,Bash(gh issue comment:*)"
        """,
    )

    no_gate = _by_rule(_agent_findings(tmp_path))["SKY-D350"][0]

    assert no_gate["severity"] == "HIGH"
    assert "Bash(gh issue comment:*)" in no_gate["message"]


def test_advisory_on_ungated_untrusted_event_is_high_without_prompt_text(tmp_path):
    _write(
        tmp_path,
        """
        name: Gemini old
        on:
          issues:
            types: [opened]
        jobs:
          label:
            runs-on: ubuntu-latest
            steps:
              - uses: google-github-actions/run-gemini-cli@v0.1.21
                env:
                  GEMINI_CLI_TRUST_WORKSPACE: 'true'
                with:
                  gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
                  prompt: "Label the issue"
                  settings: '{"tools": {"core": []}}'
        """,
    )

    found = _by_rule(_agent_findings(tmp_path))

    assert set(found) == {"SKY-D354"}
    assert found["SKY-D354"][0]["severity"] == "HIGH"
