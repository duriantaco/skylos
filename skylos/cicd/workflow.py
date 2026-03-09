from __future__ import annotations
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()

ANALYSIS_FLAG_MAP: dict[str, str] = {
    "dead-code": "",
    "security": "--danger",
    "quality": "--quality",
    "secrets": "--secrets",
}


def generate_workflow(
    *,
    triggers: Optional[list[str]] = None,
    analysis_types: Optional[list[str]] = None,
    python_version: str = "3.12",
    # use_baseline: bool = True,
    use_llm: bool = False,
    model: Optional[str] = None,
    use_claude_security: bool = False,
    use_upload: bool = False,
) -> str:
    triggers = triggers or ["pull_request", "push"]
    analysis_types = analysis_types or ["dead-code", "security", "quality", "secrets"]

    trigger_block = _build_trigger_block(triggers)
    analysis_flags = " ".join(
        ANALYSIS_FLAG_MAP[t]
        for t in analysis_types
        if t in ANALYSIS_FLAG_MAP and ANALYSIS_FLAG_MAP[t]
    )
    if analysis_flags:
        analysis_flags = " " + analysis_flags

    upload_flag = ""
    upload_env_block = ""
    if use_upload:
        upload_flag = " --upload"
        upload_env_block = (
            "\n        env:\n          SKYLOS_TOKEN: ${{ secrets.SKYLOS_TOKEN }}"
        )

    # llm_env = ""
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
                f"        run: skylos agent review . --model {model_str} --format json -o skylos-llm-results.json",
                "        env:",
                "          SKYLOS_API_KEY: ${{ secrets.SKYLOS_API_KEY }}" + api_key_env,
            ]
        )
        llm_env = """
          SKYLOS_API_KEY: ${{ secrets.SKYLOS_API_KEY }}"""

    permissions_block = """permissions:
  contents: read
  pull-requests: write
  checks: write"""
    if use_claude_security:
        permissions_block += "\n  security-events: write"

    workflow = f"""name: Skylos Analysis

{trigger_block}

{permissions_block}

jobs:
  skylos:
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
        run: pip install skylos

      - name: Run Skylos Analysis
        run: skylos .{analysis_flags}{upload_flag} --json -o skylos-results.json{
        upload_env_block
    }
{llm_step}
      - name: Quality Gate
        run: skylos cicd gate --input skylos-results.json --summary

      - name: GitHub Annotations
        if: always()
        run: skylos cicd annotate --input skylos-results.json

      - name: PR Review Comments
        if: github.event_name == 'pull_request' && always()
        run: skylos cicd review --input skylos-results.json{
        " --llm-input skylos-llm-results.json" if use_llm else ""
    } --diff-base origin/${{{{ github.base_ref || 'main' }}}}
        env:
          GH_TOKEN: ${{{{ github.token }}}}
{
        ""
        if not use_claude_security
        else '''
      - name: Upload Skylos Results for Cross-Reference
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: skylos-results
          path: skylos-results.json
'''
    }"""

    if use_claude_security:
        workflow += _build_claude_security_jobs(python_version)

    return workflow


def _build_claude_security_jobs(python_version: str) -> str:
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
          direct_prompt: "/review --output-file claude-security-results.json"

      - name: Upload Claude Security Results
        uses: actions/upload-artifact@v4
        with:
          name: claude-security-results
          path: claude-security-results.json

  upload-claude-findings:
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
        run: pip install skylos

      - name: Download Claude Security Results
        uses: actions/download-artifact@v4
        with:
          name: claude-security-results

      - name: Download Skylos Results
        uses: actions/download-artifact@v4
        with:
          name: skylos-results

      - name: Ingest Claude Security Findings
        run: skylos ingest claude-security --input claude-security-results.json --cross-reference skylos-results.json
        env:
          SKYLOS_TOKEN: ${{{{ secrets.SKYLOS_TOKEN }}}}
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
