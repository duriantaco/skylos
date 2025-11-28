import sys
import subprocess
from rich.console import Console
from rich.prompt import Confirm, Prompt

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


def check_gate(results, config):
    gate_cfg = config.get("gate", {})

    danger = results.get("danger", [])
    secrets = results.get("secrets", [])
    quality = results.get("quality", [])

    reasons = []

    criticals = []
    for f in danger:
        if f.get("severity") == "CRITICAL":
            criticals.append(f)

    if gate_cfg.get("fail_on_critical") and (criticals or secrets):
        if criticals:
            reasons.append(f"Found {len(criticals)} CRITICAL security issues")
        if secrets:
            reasons.append(f"Found {len(secrets)} Secrets")

    total_sec = len(danger)
    limit_sec = gate_cfg.get("max_security", 0)
    if total_sec > limit_sec:
        reasons.append(f"Security issues ({total_sec}) exceed limit ({limit_sec})")

    total_qual = len(quality)
    limit_qual = gate_cfg.get("max_quality", 10)
    if total_qual > limit_qual:
        reasons.append(f"Quality issues ({total_qual}) exceed limit ({limit_qual})")

    return (len(reasons) == 0), reasons


def run_gate_interaction(results, config, command_to_run):
    passed, reasons = check_gate(results, config)

    if passed:
        console.print("\n[bold green] Skylos Gate Passed.[/bold green]")
        if command_to_run:
            console.print(f"[dim]Running: {' '.join(command_to_run)}[/dim]")
            subprocess.run(command_to_run)
        else:
            start_deployment_wizard()
        return 0

    console.print("\n[bold red] Skylos Gate Failed![/bold red]")
    for reason in reasons:
        console.print(f" - {reason}")

    if config.get("gate", {}).get("strict"):
        console.print("[bold red]Strict mode enabled. Cannot bypass.[/bold red]")
        return 1

    if sys.stdout.isatty():
        if Confirm.ask(
            "\n[bold yellow]Do you want to bypass checks and proceed anyway?[/bold yellow]"
        ):
            console.print("[yellow]⚠ Bypassing Gate...[/yellow]")
            if command_to_run:
                subprocess.run(command_to_run)
            else:
                start_deployment_wizard()
            return 0

    return 1
