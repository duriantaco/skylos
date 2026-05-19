from __future__ import annotations
from pathlib import Path
import re
import shlex
from typing import Optional

from rich.console import Console

console = Console()

ANALYSIS_FLAG_MAP: dict[str, str] = {
    "dead-code": "",
    "security": "--danger",
    "quality": "--quality",
    "secrets": "--secrets",
}

SKYLOS_RESULTS_SHELL_PATH = '"$RUNNER_TEMP/skylos-results.json"'
SKYLOS_LLM_RESULTS_SHELL_PATH = '"$RUNNER_TEMP/skylos-llm-results.json"'
SKYLOS_DEFENSE_RESULTS_SHELL_PATH = '"$RUNNER_TEMP/defense-results.json"'
SKYLOS_RESULTS_ARTIFACT_PATH = "${{ runner.temp }}/skylos-results.json"
CLAUDE_RESULTS_ARTIFACT_PATH = "${{ runner.temp }}/claude-security-results.json"


def _installed_skylos_version() -> str | None:
    try:
        from skylos import __version__

        version = str(__version__).strip()
    except Exception:
        return None
    return version or None


def _skylos_install_command(version: str | None = None) -> str:
    resolved = version if version is not None else _installed_skylos_version()
    if resolved and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.!+~-]*", resolved):
        return f"python -m pip install {shlex.quote(f'skylos=={resolved}')}"
    return "python -m pip install skylos"


def _shell_path(path: str | Path | None) -> str:
    raw = str(path or ".")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise ValueError("scan_path must not contain control characters")
    raw = raw.strip() or "."
    if raw.startswith("-"):
        raw = f"./{raw}"
    return shlex.quote(raw)


def _upload_env_block() -> str:
    return """        env:
          SKYLOS_COMMIT: ${{ github.event.pull_request.head.sha || github.sha }}
          SKYLOS_BRANCH: ${{ github.event.pull_request.head.ref || github.ref_name }}"""


def generate_workflow(
    *,
    triggers: Optional[list[str]] = None,
    analysis_types: Optional[list[str]] = None,
    python_version: str = "3.12",
    use_baseline: bool = True,
    use_llm: bool = False,
    model: Optional[str] = None,
    use_claude_security: bool = False,
    use_upload: bool = False,
    use_defend: bool = False,
    scan_path: str = ".",
    skylos_version: str | None = None,
) -> str:
    triggers = triggers or ["pull_request", "push"]
    analysis_types = analysis_types or ["dead-code", "security", "quality", "secrets"]

    trigger_block = _build_trigger_block(triggers)
    install_command = _skylos_install_command(skylos_version)
    scan_target = _shell_path(scan_path)
    analysis_flags = " ".join(
        ANALYSIS_FLAG_MAP[t]
        for t in analysis_types
        if t in ANALYSIS_FLAG_MAP and ANALYSIS_FLAG_MAP[t]
    )
    if analysis_flags:
        analysis_flags = " " + analysis_flags
    baseline_flag = " --baseline" if use_baseline else ""
    upload_flag = ""
    if use_upload:
        upload_flag = " --upload"
    analysis_run = "\n".join(
        [
            '          if [ "${{ github.event_name }}" = "pull_request" ]; then',
            '            pr_base_ref="origin/${GITHUB_BASE_REF:-main}"',
            (
                f"            skylos {scan_target}{analysis_flags}{baseline_flag}{upload_flag} "
                '--diff-base "$pr_base_ref" --diff "$pr_base_ref" '
                f"--json -o {SKYLOS_RESULTS_SHELL_PATH}"
            ),
            "          else",
            f"            skylos {scan_target}{analysis_flags}{baseline_flag}{upload_flag} --json -o {SKYLOS_RESULTS_SHELL_PATH}",
            "          fi",
        ]
    )
    analysis_upload_env = f"\n{_upload_env_block()}" if use_upload else ""

    llm_step = ""
    if use_llm:
        model_str = model or "gpt-4.1"
        api_key_env = ""
        if model_str and "claude" in model_str.lower():
            api_key_env = (
                "\n          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}"
            )
        llm_step = "\n".join(
            [
                "",
                "      - name: Skylos Agent Review (LLM)",
                "        if: github.event_name == 'pull_request'",
                (
                    f"        run: skylos agent scan {scan_target} "
                    f"--model {shlex.quote(model_str)} --changed --format json "
                    f"-o {SKYLOS_LLM_RESULTS_SHELL_PATH}"
                ),
                "        env:",
                "          SKYLOS_API_KEY: ${{ secrets.SKYLOS_API_KEY }}" + api_key_env,
            ]
        )
    defend_step = ""
    if use_defend:
        defend_parts = [
            "",
            "      - name: AI Defense Check",
            f"        run: skylos defend {scan_target} --fail-on critical --min-score 70 --json -o {SKYLOS_DEFENSE_RESULTS_SHELL_PATH}{' --upload' if use_upload else ''}",
        ]
        if use_upload:
            defend_parts.append(_upload_env_block())
        defend_step = "\n".join(defend_parts)

    review_args = [f"--input {SKYLOS_RESULTS_SHELL_PATH}"]
    if use_llm:
        review_args.append(f"--llm-input {SKYLOS_LLM_RESULTS_SHELL_PATH}")
    if use_defend:
        review_args.append(f"--defense-input {SKYLOS_DEFENSE_RESULTS_SHELL_PATH}")
    review_args.extend(['--diff-base "$pr_base_ref"', "--evidence-cards"])
    review_command = "skylos cicd review " + " ".join(review_args)
    review_run = "\n".join(
        [
            '          pr_base_ref="origin/${GITHUB_BASE_REF:-main}"',
            f"          {review_command}",
        ]
    )

    permissions_block = """permissions:
  contents: read
  pull-requests: write
  checks: write
  id-token: write"""
    if use_claude_security:
        permissions_block += "\n  security-events: write"

    sync_step = """
      - name: Pull Skylos Cloud Policy
        run: |
          skylos sync pull || echo "No Skylos Cloud policy available through GitHub OIDC; continuing with local config."
"""
    skylos_results_upload_step = ""
    if use_claude_security:
        skylos_results_upload_step = f"""
      - name: Upload Skylos Results for Cross-Reference
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: skylos-results
          path: {SKYLOS_RESULTS_ARTIFACT_PATH}
"""

    workflow = f"""name: Skylos Analysis

{trigger_block}

{permissions_block}

jobs:
  skylos:
    name: Skylos Quality Gate
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '{python_version}'

      - name: Install Skylos
        run: {install_command}
{sync_step}

      - name: Run Skylos Analysis
        run: |
{analysis_run}{analysis_upload_env}
{llm_step}{defend_step}
      - name: Quality Gate
        if: always()
        run: skylos cicd gate --input {SKYLOS_RESULTS_SHELL_PATH} --summary --advisory

      - name: GitHub Annotations
        if: always()
        run: skylos cicd annotate --input {SKYLOS_RESULTS_SHELL_PATH}

      - name: PR Review Comments
        if: github.event_name == 'pull_request' && always()
        run: |
{review_run}
        env:
          GH_TOKEN: ${{{{ github.token }}}}
{skylos_results_upload_step}"""

    if use_claude_security:
        workflow += _build_claude_security_jobs(python_version, install_command)

    return workflow


def _build_claude_security_jobs(python_version: str, install_command: str) -> str:
    return f"""
  claude-security:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Claude Code Security Review
        uses: anthropics/claude-code-action@main
        with:
          anthropic_api_key: ${{{{ secrets.ANTHROPIC_API_KEY }}}}
          direct_prompt: "/review --output-file {CLAUDE_RESULTS_ARTIFACT_PATH}"

      - name: Upload Claude Security Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: claude-security-results
          path: {CLAUDE_RESULTS_ARTIFACT_PATH}

  upload-claude-findings:
    if: always()
    runs-on: ubuntu-latest
    needs: [skylos, claude-security]
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '{python_version}'

      - name: Install Skylos
        run: {install_command}

      - name: Download Claude Security Results
        uses: actions/download-artifact@v4
        with:
          name: claude-security-results
          path: ${{{{ runner.temp }}}}/claude-security

      - name: Download Skylos Results
        uses: actions/download-artifact@v4
        with:
          name: skylos-results
          path: ${{{{ runner.temp }}}}/skylos-results

      - name: Ingest Claude Security Findings
        run: skylos ingest claude-security --input "$RUNNER_TEMP/claude-security/claude-security-results.json" --cross-reference "$RUNNER_TEMP/skylos-results/skylos-results.json"
"""


def _build_trigger_block(triggers: list[str]) -> str:
    lines = ['"on":']
    for trigger in triggers:
        if trigger == "pull_request":
            lines.append("  pull_request:")
            lines.append("    branches: [main]")
        elif trigger == "push":
            lines.append("  push:")
            lines.append("    branches: [main]")
        elif trigger == "schedule":
            lines.append("  schedule:")
            lines.append("    - cron: '0 6 * * 1'  # Weekly Monday 6am")
        elif trigger == "workflow_dispatch":
            lines.append("  workflow_dispatch:")
        else:
            lines.append(f"  {trigger}:")
    return "\n".join(lines)


def write_workflow(content: str, output_path: str):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        console.print(f"[yellow]Overwriting existing workflow: {path}[/yellow]")

    path.write_text(content)
    console.print(f"[bold green]Workflow written to {path}[/bold green]")
    console.print(f"[dim]Commit and push to activate: git add {path} && git push[/dim]")
