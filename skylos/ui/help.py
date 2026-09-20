import skylos
from rich.markup import escape

COMMANDS = [
    {
        "name": "skylos suite [directory]",
        "desc": "Build one static, debt, defense, and provenance report",
        "details": [
            "DIRECTORY defaults to the current directory; files are rejected",
            "Dependency checks may query OSV.dev and public package registries",
            "Findings are report-only; operational, upload, or uploaded gate failures are nonzero",
        ],
        "group": "Core Analysis",
    },
    {
        "name": "skylos PATH [PATH ...]",
        "desc": "Scan source code; dead code by default, main analyzers with -a",
        "group": "Core Analysis",
    },
    {
        "name": "skylos lint [RUFF_ARGS ...]",
        "desc": "Run Ruff Python linting through Skylos",
        "details": [
            "Arguments are forwarded to `ruff check`; the default path is `.`",
            'Install support with: pip install "skylos[lint]"',
            "Ruff configuration is read from pyproject.toml, ruff.toml, or .ruff.toml",
            "Exit codes are preserved: 0 clean, 1 findings, 2 error",
        ],
        "group": "Core Analysis",
    },
    {
        "name": "skylos debt [path]",
        "desc": "Rank technical-debt hotspots and trends",
        "details": [
            "PATH defaults to the current directory",
            "This is a debt score and hotspot report, separate from normal scan findings",
        ],
        "group": "Core Analysis",
    },
    {
        "name": "skylos verify [path]",
        "desc": "Check source code and Python working changes for AI-code mistakes",
        "details": [
            "PATH defaults to the current directory",
            "Scans PATH as a source target; separately compares affected Python functions with Git HEAD",
            "Path targets may query public package registries; disable with --no-dependency-hallucinations",
            "It does not inspect a built release artifact",
            "Use --file and --range L1:L2 to narrow the check; "
            "--project-context keeps repo context",
            "Use --output FILE for JSON or --no-fail to preserve status while exiting 0",
            "Terminal output is human-readable; redirected, stdin, and saved output use JSON",
        ],
        "group": "AI Agent",
    },
    {
        "name": "skylos preflight [ARTIFACT]",
        "desc": "Check a local built GPU artifact against its declared hardware fleet",
        "details": [
            "ARTIFACT: local file/directory or digest-pinned OCI image; "
            "omit it to read .skylos/release.json",
            "Requires .skylos/gpu-targets.yml (.yaml also accepted) and reports "
            "PASS, FAIL, or UNKNOWN per target",
            "Checks artifact identity, Linux ELF platform, selected CUDA code "
            "architectures, a static packaged CUDA runtime route, and documented "
            "driver-family compatibility",
            "Does not review source changes or scan container CVEs",
            "Local inspection v1 supports Linux ELF/CUDA bundles and a trusted NVIDIA cuobjdump",
            "Digest-pinned OCI references are never pulled or started and return "
            "UNKNOWN in this CLI",
            "There are no mode flags: the artifact and .skylos/gpu-targets.yml define the check",
            "Valid reports are concise in a terminal and JSON when redirected; input errors are text",
            "Exit codes: 0 PASS, 1 FAIL, 2 UNKNOWN or invalid input",
        ],
        "group": "Release",
    },
    {
        "name": "skylos review [path]",
        "desc": "Review a finding and remember the local decision",
        "details": [
            "Interactive: scan, select a finding, then mark it false positive or "
            "accept risk temporarily",
            "list [path]: show local decisions and their expiry",
            "restore <decision-id> [path]: revoke a decision and show the finding again",
            "Local decisions are operator-owned and ignored in CI",
        ],
        "group": "Core Analysis",
    },
    {
        "name": "skylos discover [path]",
        "desc": "Inventory Python and TypeScript/JavaScript LLM integrations",
        "group": "Core Analysis",
    },
    {
        "name": "skylos sbom [path] [--output sbom.cdx.json]",
        "desc": "Export supported dependency inventory as offline CycloneDX 1.6 JSON",
        "details": [
            "--output, -o  Write a file; default '-' writes JSON to stdout",
            "--format cyclonedx-json  CycloneDX JSON output (default)",
            "No installs, project scripts, or network requests",
            "Exit 2 on unreadable, unsupported, or incomplete inputs; keeps partial output",
            "Includes all recorded environments, not an installed or licence inventory",
        ],
        "group": "Core Analysis",
    },
    {
        "name": "skylos defend [directory]",
        "desc": "Report static guardrails for Python and TypeScript/JavaScript LLM integrations",
        "details": [
            "DIRECTORY defaults to the current directory; files are rejected",
            "Findings are report-only unless --fail-on, --min-score, or policy requests a gate",
        ],
        "group": "Core Analysis",
    },
    {
        "name": "skylos agent scan [path]",
        "desc": "Hybrid static + LLM analysis",
        "group": "AI Agent",
    },
    {
        "name": "skylos agent audit [path]",
        "desc": "Manage the persistent Deep Mode security audit workflow",
        "group": "AI Agent",
    },
    {
        "name": "skylos agent security-quick [path]",
        "desc": "Run a one-shot LLM security audit",
        "group": "AI Agent",
    },
    {
        "name": "skylos agent security-deep [path]",
        "desc": "Start the staged Deep Mode security workflow",
        "group": "AI Agent",
    },
    {
        "name": "skylos agent verify <path>",
        "desc": "Use an LLM to review dead-code findings",
        "group": "AI Agent",
    },
    {
        "name": "skylos agent remediate [path]",
        "desc": "Scan and fix issues; optionally test or create a PR",
        "group": "AI Agent",
    },
    {
        "name": "skylos agent replay RUN_DIR",
        "desc": "Validate and inspect a saved agent harness run",
        "group": "AI Agent",
    },
    {
        "name": "skylos agent init [--path CONTRACT]",
        "desc": "Create a runtime agent behavior contract",
        "group": "AI Agent",
    },
    {
        "name": "skylos agent test [CONTRACT]",
        "desc": "Test runtime agent behavior against its contract",
        "group": "AI Agent",
    },
    {
        "name": "skylos agent watch [path]",
        "desc": "Continuous repo monitoring",
        "group": "AI Agent",
    },
    {
        "name": "skylos agent pre-commit [path]",
        "desc": "Staged local hook for security, secrets, and quality",
        "group": "AI Agent",
    },
    {
        "name": "skylos agent triage <command>",
        "desc": "Suggest, dismiss, snooze, or restore ranked actions",
        "group": "AI Agent",
    },
    {
        "name": "skylos agent status [path]",
        "desc": "Show the latest active-agent summary",
        "group": "AI Agent",
    },
    {
        "name": "skylos agent serve [path]",
        "desc": "Serve the active-agent state through a local HTTP API",
        "group": "AI Agent",
    },
    {
        "name": "skylos cicd init",
        "desc": "Generate GitHub Actions workflow",
        "group": "CI/CD",
    },
    {
        "name": "skylos cicd gate [path]",
        "desc": "Quality gate (CI exit code)",
        "group": "CI/CD",
    },
    {
        "name": "skylos cicd annotate [path]",
        "desc": "Emit GitHub Actions annotations",
        "group": "CI/CD",
    },
    {
        "name": "skylos cicd review [path]",
        "desc": "Post inline PR review comments",
        "group": "CI/CD",
    },
    {
        "name": "skylos login",
        "desc": "Connect or switch Skylos Cloud project",
        "group": "Account",
    },
    {
        "name": "skylos whoami",
        "desc": "Show connected account info",
        "group": "Account",
    },
    {
        "name": "skylos project <command>",
        "desc": "Manage the active project for this repo",
        "group": "Account",
    },
    {
        "name": "skylos key [list|add|remove]",
        "desc": "Manage local model-provider API keys",
        "group": "Account",
    },
    {"name": "skylos credits", "desc": "Check credit balance", "group": "Account"},
    {
        "name": "skylos init",
        "desc": "Initialize config in pyproject.toml",
        "group": "Utility",
    },
    {
        "name": "skylos baseline [path]",
        "desc": "Save current findings as baseline",
        "group": "Utility",
    },
    {
        "name": "skylos whitelist [pattern|--show]",
        "desc": "Manage whitelisted symbols",
        "group": "Utility",
    },
    {
        "name": "skylos badge",
        "desc": "Get badge markdown for README",
        "group": "Utility",
    },
    {
        "name": "skylos rules <command>",
        "desc": "Install/manage community rule packs",
        "group": "Utility",
    },
    {
        "name": "skylos contract <command>",
        "desc": "Create and validate AI hallucination contracts",
        "details": [
            "init: create .skylos/ai-contract.yml",
            "validate [path]: validate a contract without scanning code",
            "inspect [path]: print the normalized contract (explain is an alias)",
        ],
        "group": "Utility",
    },
    {
        "name": "skylos doctor [--format text|json]",
        "desc": "Check installation health and language-engine availability",
        "details": [
            "--format text|json  Print human-readable or machine-readable health"
        ],
        "group": "Utility",
    },
    {
        "name": "skylos clean [path] [--dry-run|--apply]",
        "desc": "Preview or apply Python import/function cleanup",
        "details": [
            "No mode flag: interactive selection and confirmation; confirmed edits write files",
            "--dry-run: show import/function cleanup edits without writing files",
            "--apply: apply matching cleanup edits without prompting",
            "--confidence N: minimum confidence, default 80 in noninteractive mode",
            "--types import,function: comma-separated cleanup types",
            "--exclude FOLDER: exclude a folder from analysis",
            "--comment-out: comment out findings instead of removing them",
        ],
        "group": "Utility",
    },
    {
        "name": "skylos cache clear [path]",
        "desc": "Clear cached run data",
        "group": "Utility",
    },
    {
        "name": "skylos cache stats [path]",
        "desc": "Show cached run data size",
        "group": "Utility",
    },
    {
        "name": "skylos sync",
        "desc": "Sync config with Skylos Cloud",
        "group": "Utility",
    },
    {
        "name": "skylos sonar import [properties_file]",
        "desc": "Create a Skylos migration plan from Sonar properties",
        "details": [
            "properties_file defaults to sonar-project.properties",
            "Use --write-config to write mapped settings to .skylos/config.yaml",
        ],
        "group": "Utility",
    },
    {
        "name": "skylos image scan IMAGE@sha256:<digest> --platform os/arch",
        "desc": "Find vulnerabilities in a pinned container image with installed Trivy",
        "details": [
            "Requires a trusted Trivy executable on PATH plus registry network access and credentials",
            "Checks container vulnerabilities; it does not check CUDA architecture "
            "or driver compatibility",
            "--platform linux/amd64: select and verify the image platform",
            "--fail-on high: fail for reported high or critical vulnerabilities",
            "Without --fail-on, vulnerability findings are report-only and exit 0",
            "--output result.json / --sarif result.sarif: save normalized reports",
            "--timeout-seconds 300: bound scanner execution time",
        ],
        "group": "Release",
    },
    {
        "name": "skylos ingest <trivy|claude-security>",
        "desc": "Ingest findings from external tools",
        "details": [
            "trivy --input report.json: import container vulnerability results offline",
            "--fail-on high --expect-image repository@sha256:digest: check a pinned image report",
            "--output report.json / --sarif image.sarif: export imported image findings",
            "claude-security --input report.json: ingest Claude Code Security findings",
        ],
        "group": "Utility",
    },
    {
        "name": "skylos compare [path] --against <report>",
        "desc": "Measure Skylos beside an incumbent scanner without replacing it",
        "details": [
            "--against: SARIF, Sonar issues JSON, or normalized findings JSON",
            "--skylos-results: reuse an existing Skylos JSON report instead of scanning",
            "--confidence/--exclude: tune the local Skylos scan profile",
            "--sca: add bounded exact-pin OSV signals (category-limited)",
            "default profile: no secret-file traversal, registry lookup, or SCA network calls",
            "--external-revision/--skylos-revision: bind reports that lack provenance",
            "--format text|json: print a concise scorecard or machine-readable report",
            "-o/--output: write the full comparison report as JSON",
            "--upload: opt in to a project-bound Cloud receipt and scorecard",
        ],
        "group": "Utility",
    },
    {
        "name": "skylos provenance [path]",
        "desc": "Detect AI-authored code in PR changes",
        "group": "Utility",
    },
    {
        "name": "skylos commands",
        "desc": "List command families and canonical subcommands",
        "group": "Utility",
    },
    {"name": "skylos tour", "desc": "Guided tour of capabilities", "group": "Utility"},
]

# NOTE: MUST UPDATE this list when adding new commands to cli.py


def print_command_overview(console):
    from rich.table import Table

    console.print(
        f"\n[bold cyan]Skylos[/bold cyan] [dim]v{skylos.__version__}[/dim]"
    )
    console.print("[bold]Choose by what you need to check[/bold]\n")

    table = Table(show_header=True, box=None, padding=(0, 2), pad_edge=False)
    table.add_column("Command", style="bold", no_wrap=True)
    table.add_column("Use it for")
    workflows = (
        (
            "skylos PATH",
            "Scan source code; dead code is the default, and -a enables the main analyzers.",
        ),
        (
            "skylos verify [PATH]",
            "Scan for AI-code mistakes and model Python working changes.",
        ),
        (
            "skylos preflight [ARTIFACT]",
            "Check a local built GPU artifact against the declared fleet; OCI is UNKNOWN.",
        ),
        (
            "skylos image scan IMAGE…",
            "Find container vulnerabilities in a pinned remote image.",
        ),
        (
            "skylos suite [DIRECTORY]",
            "Build a combined repo report; dependency checks can use the network.",
        ),
        (
            "skylos defend [DIRECTORY]",
            "Report supported LLM integration guardrails; gating is opt-in.",
        ),
        (
            "skylos clean [PATH]",
            "Preview or interactively apply Python import/function cleanup.",
        ),
    )
    for command, purpose in workflows:
        table.add_row(command, purpose)
    console.print(table)
    console.print(
        "\n[bold]Keep these three separate:[/bold] "
        "[cyan]verify[/cyan] scans source and models Python changes; "
        "[cyan]preflight[/cyan] statically reads a local GPU artifact; "
        "[cyan]image scan[/cyan] asks installed Trivy to scan a remote image."
    )
    console.print(
        "\n[dim]Optional paths and directories default to the current directory. "
        "Preflight may omit ARTIFACT only when .skylos/release.json declares it.[/dim]"
    )
    console.print("[dim]Command details:[/dim] [bold]skylos <command> --help[/bold]")
    console.print("[dim]Source-scan flags:[/dim] [bold]skylos PATH --help[/bold]")
    console.print("[dim]Command-family map:[/dim] [bold]skylos commands[/bold]\n")


def print_flat_commands(console):
    from rich.table import Table

    table = Table(
        title="[bold cyan]Skylos Command Map[/bold cyan]",
        show_header=True,
        header_style="bold",
        border_style="dim",
        pad_edge=True,
    )
    table.add_column("Command", style="bold")
    table.add_column("Description", style="dim")
    table.add_column("Group", style="yellow")

    for cmd in sorted(COMMANDS, key=lambda c: c["name"]):
        table.add_row(
            escape(cmd["name"]),
            escape(cmd["desc"]),
            escape(cmd["group"]),
        )

    console.print()
    console.print(table)
    console.print(
        "\n[dim]Family details:[/dim] [bold]skylos <family> --help[/bold]"
        "  [dim]Removed:[/dim] [bold]skylos run[/bold], [bold]skylos city[/bold]"
    )
    console.print()
