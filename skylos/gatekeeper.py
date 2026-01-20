import subprocess
from rich.console import Console
from rich.prompt import Confirm, Prompt
import sys

try:
    import inquirer

    INTERACTIVE = True
except ImportError:
    INTERACTIVE = False

console = Console()


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


def check_gate(results, config, strict=False):
    results = results or {}
    config = config or {}

    reasons = []
    passed = True

    total_findings = sum(
        len(results.get(k, []))
        for k in (
            "unused_functions",
            "unused_imports",
            "unused_variables",
            "unused_classes",
            "unused_parameters",
        )
    )

    danger = results.get("danger", []) or []
    quality = results.get("quality", []) or []
    secrets = results.get("secrets", []) or []

    critical_issues = []
    high_issues = []

    for issue in danger:
        sev = str(issue.get("severity", "")).lower()
        if sev == "critical":
            critical_issues.append(issue)
        elif sev == "high":
            high_issues.append(issue)

    gate_config = config.get("gate", {}) if config else {}

    if strict:
        total_issues = total_findings + len(danger) + len(quality) + len(secrets)
        if total_issues > 0:
            return False, [f"Strict mode: {total_issues} issue(s) found"]
        return True, []

    fail_on_critical = gate_config.get("fail_on_critical", True)
    max_critical = gate_config.get("max_critical", 0)
    max_high = gate_config.get("max_high", 5)
    max_security = gate_config.get("max_security", 10)
    max_quality = gate_config.get("max_quality", 10)
    max_secrets = gate_config.get("max_secrets", None)
    max_dead_code = gate_config.get("max_dead_code", None)

    if fail_on_critical and len(critical_issues) > 0:
        passed = False
        reasons.append(f"{len(critical_issues)} critical security issue(s)")

    elif isinstance(max_critical, int) and len(critical_issues) > max_critical:
        passed = False
        reasons.append(f"{len(critical_issues)} critical issues (max: {max_critical})")

    if isinstance(max_high, int) and len(high_issues) > max_high:
        passed = False
        reasons.append(f"{len(high_issues)} high severity issues (max: {max_high})")

    if isinstance(max_security, int) and len(danger) > max_security:
        passed = False
        reasons.append(f"{len(danger)} total security issues (max: {max_security})")

    if isinstance(max_quality, int) and len(quality) > max_quality:
        passed = False
        reasons.append(f"{len(quality)} quality issues (max: {max_quality})")

    if isinstance(max_secrets, int) and len(secrets) > max_secrets:
        passed = False
        reasons.append(f"{len(secrets)} secrets issues (max: {max_secrets})")

    if isinstance(max_dead_code, int) and total_findings > max_dead_code:
        passed = False
        reasons.append(f"{total_findings} dead code issue(s) (max: {max_dead_code})")

    return passed, reasons


def run_gate_interaction(
    *,
    results=None,
    result=None,
    config=None,
    strict=False,
    force=False,
    command_to_run=None,
):
    console = Console()

    if results is None:
        results = result or {}

    config = config or {}
    gate_cfg = config.get("gate") or {}

    strict = bool(strict or gate_cfg.get("strict", False))

    try:
        passed, reasons = check_gate(results, config, strict=strict)
    except TypeError:
        passed, reasons = check_gate(results, config)

    if passed:
        console.print("\n[bold green]✅ Quality Gate: PASSED[/bold green]")

        if command_to_run:
            proc = subprocess.run(command_to_run)
            return getattr(proc, "returncode", 0)

        return 0

    console.print("\n[bold red] Quality Gate: FAILED[/bold red]")
    for r in reasons or []:
        console.print(f"   • {r}")

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
