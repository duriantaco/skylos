import os
import subprocess
import sys

from rich.console import Console
from rich.prompt import Confirm, Prompt

try:
    import inquirer

    INTERACTIVE = True
except ImportError:
    INTERACTIVE = False

console = Console()
DEAD_CODE_RESULT_KEYS = (
    "unused_functions",
    "unused_imports",
    "unused_variables",
    "unused_classes",
    "unused_parameters",
)
AGENT_GATE_PREFIX = "Agent gate: "
ADVISORY_QUALITY_RULE_IDS = {"SKY-Q802", "SKY-Q803"}


def run_cmd(cmd_list, error_msg="Git command failed"):
    try:
        result = subprocess.run(cmd_list, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Error:[/bold red] {error_msg}\n[dim]{e.stderr}[/dim]")
        return None


def get_git_status():
    out = run_cmd(
        ["git", "status", "--porcelain"], "Could not get git status. Is this a repo?"
    )
    if not out:
        return []

    files = []
    for line in out.splitlines():
        if len(line) > 3:
            files.append(line[3:])
    return files


def run_push():
    console.print("[dim]Pushing to remote...[/dim]")
    try:
        subprocess.run(["git", "push"], check=True)
        console.print("[bold green] Deployment Complete. Code is live.[/bold green]")
    except subprocess.CalledProcessError:
        console.print(
            "[bold red] Push failed. Check your git remote settings.[/bold red]"
        )


def start_deployment_wizard():
    if not INTERACTIVE:
        console.print(
            "[yellow]Install 'inquirer' (pip install inquirer) to use interactive deployment.[/yellow]"
        )
        return

    console.print("\n[bold cyan] Skylos Deployment Wizard[/bold cyan]")

    files = get_git_status()
    if not files:
        console.print("[green]Working tree is clean.[/green]")
        if Confirm.ask("Push existing commits?"):
            run_push()
        return

    q_scope = [
        inquirer.List(
            "scope",
            message="What do you want to stage?",
            choices=[
                "All changed files",
                "Select files manually",
                "Skip commit (Push only)",
            ],
        ),
    ]
    ans_scope = inquirer.prompt(q_scope)
    if not ans_scope:
        return

    if ans_scope["scope"] == "Select files manually":
        q_files = [inquirer.Checkbox("files", message="Select files", choices=files)]
        ans_files = inquirer.prompt(q_files)
        if not ans_files or not ans_files["files"]:
            console.print("[red]No files selected.[/red]")
            return
        run_cmd(["git", "add"] + ans_files["files"])
        console.print(f"[green]Staged {len(ans_files['files'])} files.[/green]")

    elif ans_scope["scope"] == "All changed files":
        run_cmd(["git", "add", "."])
        console.print("[green]Staged all files.[/green]")

    if ans_scope["scope"] != "Skip commit (Push only)":
        msg = Prompt.ask("[bold green]Enter commit message[/bold green]")
        if not msg:
            console.print("[red]Commit message required.[/red]")
            return
        if run_cmd(["git", "commit", "-m", msg]):
            console.print("[green]✓ Committed.[/green]")

    if Confirm.ask("Ready to git push?"):
        run_push()


def _get_finding_file(finding):
    return finding.get("file", finding.get("file_path", ""))


def _collect_dead_code_items(results):
    items = []
    for key in DEAD_CODE_RESULT_KEYS:
        items.extend(results.get(key, []) or [])
    return items


def _count_dead_code_findings(results):
    return sum(len(results.get(key, []) or []) for key in DEAD_CODE_RESULT_KEYS)


def _split_danger_by_severity(danger):
    critical_issues = []
    high_issues = []
    for issue in danger:
        sev = str(issue.get("severity", "")).lower()
        if sev == "critical":
            critical_issues.append(issue)
        elif sev == "high":
            high_issues.append(issue)
    return critical_issues, high_issues


def _is_advisory_quality_finding(finding):
    return (
        isinstance(finding, dict)
        and bool(finding.get("advisory"))
        and str(finding.get("rule_id", "")) in ADVISORY_QUALITY_RULE_IDS
    )


def _gate_quality_findings(quality):
    return [finding for finding in quality if not _is_advisory_quality_finding(finding)]


def _append_threshold_reason(reasons, *, count, limit, message_template):
    if isinstance(limit, int) and count > limit:
        reasons.append(message_template.format(count=count, limit=limit))
        return False
    return True


def _agent_gate_reason(message):
    return f"{AGENT_GATE_PREFIX}{message}"


def _collect_agent_findings(findings_lists, agent_file_set):
    agent_danger = []
    agent_quality = []
    agent_secrets = []
    agent_dead_code = 0
    buckets = {
        "danger": agent_danger,
        "quality": agent_quality,
        "secrets": agent_secrets,
    }

    for category, items in findings_lists.items():
        for finding in items:
            fpath = _get_finding_file(finding)
            if fpath not in agent_file_set:
                continue
            bucket = buckets.get(category)
            if bucket is not None:
                bucket.append(finding)
            elif category == "dead_code":
                agent_dead_code += 1

    return agent_danger, agent_quality, agent_secrets, agent_dead_code


def _apply_agent_thresholds(
    reasons,
    agent_cfg,
    *,
    critical_count,
    high_count,
    security_count,
    quality_count,
    secrets_count,
    dead_code_count,
):
    agent_passed = True

    if not _append_threshold_reason(
        reasons,
        count=critical_count,
        limit=agent_cfg.get("max_critical"),
        message_template=_agent_gate_reason(
            "{count} critical issue(s) in AI-authored files (max: {limit})"
        ),
    ):
        agent_passed = False

    if not _append_threshold_reason(
        reasons,
        count=high_count,
        limit=agent_cfg.get("max_high"),
        message_template=_agent_gate_reason(
            "{count} high severity issue(s) in AI-authored files (max: {limit})"
        ),
    ):
        agent_passed = False

    if not _append_threshold_reason(
        reasons,
        count=security_count,
        limit=agent_cfg.get("max_security"),
        message_template=_agent_gate_reason(
            "{count} security issue(s) in AI-authored files (max: {limit})"
        ),
    ):
        agent_passed = False

    if not _append_threshold_reason(
        reasons,
        count=quality_count,
        limit=agent_cfg.get("max_quality"),
        message_template=_agent_gate_reason(
            "{count} quality issue(s) in AI-authored files (max: {limit})"
        ),
    ):
        agent_passed = False

    if not _append_threshold_reason(
        reasons,
        count=secrets_count,
        limit=agent_cfg.get("max_secrets"),
        message_template=_agent_gate_reason(
            "{count} secret(s) in AI-authored files (max: {limit})"
        ),
    ):
        agent_passed = False

    if not _append_threshold_reason(
        reasons,
        count=dead_code_count,
        limit=agent_cfg.get("max_dead_code"),
        message_template=_agent_gate_reason(
            "{count} dead code issue(s) in AI-authored files (max: {limit})"
        ),
    ):
        agent_passed = False

    return agent_passed


def _check_agent_gate(findings_lists, agent_file_set, agent_cfg, reasons):
    """Evaluate agent-specific thresholds against findings in AI-authored files.

    Returns False if any agent threshold is exceeded.
    """
    agent_danger, agent_quality, agent_secrets, agent_dead_code = (
        _collect_agent_findings(findings_lists, agent_file_set)
    )
    agent_critical, agent_high = _split_danger_by_severity(agent_danger)
    agent_passed = _apply_agent_thresholds(
        reasons,
        agent_cfg,
        critical_count=len(agent_critical),
        high_count=len(agent_high),
        security_count=len(agent_danger),
        quality_count=len(agent_quality),
        secrets_count=len(agent_secrets),
        dead_code_count=agent_dead_code,
    )

    min_defend = agent_cfg.get("min_defend_score")
    require_defend = agent_cfg.get("require_defend", False)
    if require_defend or isinstance(min_defend, (int, float)):
        reasons.append(
            _agent_gate_reason(
                "require_defend/min_defend_score set but no defense data available (run skylos defend)"
            )
        )
        agent_passed = False

    return agent_passed


def _check_strict_gate(*, total_findings, danger, quality, secrets):
    gate_quality = _gate_quality_findings(quality)
    total_issues = total_findings + len(danger) + len(gate_quality) + len(secrets)
    if total_issues > 0:
        return False, [f"Strict mode: {total_issues} issue(s) found"]
    return True, []


def _apply_gate_thresholds(
    reasons,
    *,
    fail_on_critical,
    critical_count,
    max_critical,
    high_count,
    max_high,
    security_count,
    max_security,
    quality_count,
    max_quality,
    secrets_count,
    max_secrets,
    dead_code_count,
    max_dead_code,
):
    passed = True

    if fail_on_critical and critical_count > 0:
        passed = False
        reasons.append(f"{critical_count} critical security issue(s)")
    elif not _append_threshold_reason(
        reasons,
        count=critical_count,
        limit=max_critical,
        message_template="{count} critical issues (max: {limit})",
    ):
        passed = False

    if not _append_threshold_reason(
        reasons,
        count=high_count,
        limit=max_high,
        message_template="{count} high severity issues (max: {limit})",
    ):
        passed = False

    if not _append_threshold_reason(
        reasons,
        count=security_count,
        limit=max_security,
        message_template="{count} total security issues (max: {limit})",
    ):
        passed = False

    if not _append_threshold_reason(
        reasons,
        count=quality_count,
        limit=max_quality,
        message_template="{count} quality issues (max: {limit})",
    ):
        passed = False

    if not _append_threshold_reason(
        reasons,
        count=secrets_count,
        limit=max_secrets,
        message_template="{count} secrets issues (max: {limit})",
    ):
        passed = False

    if not _append_threshold_reason(
        reasons,
        count=dead_code_count,
        limit=max_dead_code,
        message_template="{count} dead code issue(s) (max: {limit})",
    ):
        passed = False

    return passed


def _build_findings_lists(results, danger, quality, secrets):
    return {
        "danger": danger,
        "quality": quality,
        "secrets": secrets,
        "dead_code": _collect_dead_code_items(results),
    }


def check_gate(results, config, strict=False, provenance=None):
    """
    Evaluate scan results against gate thresholds.

    Calls: skylos/core/gatekeeper.py _check_strict_gate;
        skylos/core/gatekeeper.py _apply_gate_thresholds;
        skylos/core/gatekeeper.py _check_agent_gate.

    Called from: skylos/core/gatekeeper.py _resolve_gate_check;
        skylos/cli.py _formatted_output_gate_exit_code;
        skylos/cli.py _concise_scan_exit_code;
        skylos/cli.py _strict_scan_exit_code.
    """
    results = results or {}
    config = config or {}

    reasons = []
    total_findings = _count_dead_code_findings(results)
    danger = results.get("danger", []) or []
    quality = results.get("quality", []) or []
    gate_quality = _gate_quality_findings(quality)
    secrets = results.get("secrets", []) or []
    gate_config = config.get("gate", {}) if config else {}

    if strict:
        return _check_strict_gate(
            total_findings=total_findings,
            danger=danger,
            quality=gate_quality,
            secrets=secrets,
        )

    critical_issues, high_issues = _split_danger_by_severity(danger)
    passed = _apply_gate_thresholds(
        reasons,
        fail_on_critical=gate_config.get("fail_on_critical", True),
        critical_count=len(critical_issues),
        max_critical=gate_config.get("max_critical", 0),
        high_count=len(high_issues),
        max_high=gate_config.get("max_high", 5),
        security_count=len(danger),
        max_security=gate_config.get("max_security", 10),
        quality_count=len(gate_quality),
        max_quality=gate_config.get("max_quality", 10),
        secrets_count=len(secrets),
        max_secrets=gate_config.get("max_secrets", None),
        dead_code_count=total_findings,
        max_dead_code=gate_config.get("max_dead_code", None),
    )

    # Agent-aware gating: apply stricter thresholds to AI-authored files
    agent_cfg = gate_config.get("agent")
    if provenance and agent_cfg and provenance.agent_files:
        agent_file_set = set(provenance.agent_files)
        agent_passed = _check_agent_gate(
            _build_findings_lists(results, danger, gate_quality, secrets),
            agent_file_set,
            agent_cfg,
            reasons,
        )
        if not agent_passed:
            passed = False

    return passed, reasons


def _build_summary_rows(
    *,
    critical_count,
    high_count,
    security_count,
    quality_count,
    secrets_count,
    dead_code_count,
):
    return [
        f"| Security (critical) | {critical_count} | {'✅' if critical_count == 0 else '❌'} |",
        f"| Security (high) | {high_count} | {'✅' if high_count <= 5 else '⚠️'} |",
        f"| Security (total) | {security_count} | {'✅' if security_count <= 10 else '⚠️'} |",
        f"| Quality | {quality_count} | {'✅' if quality_count <= 10 else '⚠️'} |",
        f"| Secrets | {secrets_count} | {'✅' if secrets_count == 0 else '❌'} |",
        f"| Dead Code | {dead_code_count} | ℹ️ |",
    ]


def _append_failure_reasons(lines, reasons, *, heading="Failure Reasons"):
    if reasons:
        lines.append("")
        lines.append(f"### {heading}")
        for reason in reasons:
            lines.append(f"- {reason}")


def build_summary_markdown(results, passed, reasons, *, advisory=False):
    results = results or {}

    danger = results.get("danger", []) or []
    quality = results.get("quality", []) or []
    secrets = results.get("secrets", []) or []
    critical_issues, high_issues = _split_danger_by_severity(danger)
    critical_count = len(critical_issues)
    high_count = len(high_issues)
    dead_code_count = _count_dead_code_findings(results)

    if advisory and not passed:
        status = "ADVISORY - WOULD FAIL"
        icon = "⚠️"
    else:
        status = "PASSED" if passed else "FAILED"
        icon = "✅" if passed else "❌"

    lines = [
        "## Skylos Analysis Results",
        "",
        "| Category | Count | Status |",
        "|----------|-------|--------|",
        *_build_summary_rows(
            critical_count=critical_count,
            high_count=high_count,
            security_count=len(danger),
            quality_count=len(quality),
            secrets_count=len(secrets),
            dead_code_count=dead_code_count,
        ),
        "",
        f"**Result: {icon} {status}**",
    ]
    _append_failure_reasons(
        lines,
        reasons,
        heading="Advisory Reasons" if advisory and not passed else "Failure Reasons",
    )

    return "\n".join(lines)


def write_github_summary(markdown):
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a") as f:
                f.write(markdown + "\n")
        except OSError as e:
            console.print(
                f"[yellow]Could not write to GITHUB_STEP_SUMMARY: {e}[/yellow]"
            )
    else:
        console.print(markdown)


def _resolve_gate_check(results, config, strict, provenance):
    try:
        return check_gate(results, config, strict=strict, provenance=provenance)
    except TypeError:
        return check_gate(results, config)


def _handle_passed_gate(console, command_to_run):
    console.print("\n[bold green]✅ Quality Gate: PASSED[/bold green]")

    if command_to_run:
        proc = subprocess.run(command_to_run)
        return getattr(proc, "returncode", 0)

    return 0


def _handle_failed_gate(console, reasons, *, force, strict):
    console.print("\n[bold red] Quality Gate: FAILED[/bold red]")
    for reason in reasons or []:
        console.print(f"   • {reason}")

    if force:
        console.print("[yellow] Forced pass (local only)[/yellow]")
        return 0

    if strict:
        return 1

    try:
        if sys.stdout.isatty():
            if Confirm.ask("Quality gate failed. Continue anyway?"):
                start_deployment_wizard()
                return 0
            return 1
    except Exception:
        pass

    return 1


def _handle_advisory_gate(console, reasons):
    console.print("\n[bold yellow]Quality Gate: ADVISORY[/bold yellow]")
    for reason in reasons or []:
        console.print(f"   • {reason}")
    console.print("[yellow]Advisory mode enabled; CI is allowed to pass.[/yellow]")
    return 0


def run_gate_interaction(
    *,
    results=None,
    result=None,
    config=None,
    strict=False,
    force=False,
    command_to_run=None,
    summary=False,
    provenance=None,
    advisory=False,
):
    """
    Runs the interactive or CI quality gate flow.

    Calls: skylos/core/gatekeeper.py _resolve_gate_check;
        skylos/core/gatekeeper.py build_summary_markdown;
        skylos/core/gatekeeper.py write_github_summary.

    Called from: skylos/commands/scan_cmd.py run_scan_command;
        skylos/cli.py run_gate_interaction.
    """
    console = Console()

    if results is None:
        results = result or {}

    config = config or {}
    gate_cfg = config.get("gate") or {}

    strict = bool(strict or gate_cfg.get("strict", False))
    passed, reasons = _resolve_gate_check(results, config, strict, provenance)

    if summary:
        md = build_summary_markdown(results, passed, reasons, advisory=advisory)
        write_github_summary(md)

    if passed:
        return _handle_passed_gate(console, command_to_run)

    if advisory:
        return _handle_advisory_gate(console, reasons)

    return _handle_failed_gate(console, reasons, force=force, strict=strict)
