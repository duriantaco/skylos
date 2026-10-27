import argparse
import json
import os
import platform
from pathlib import Path

import skylos
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

from skylos.cloud.plan_names import plan_display_name
from skylos.config import load_config
from skylos.constants import RIPGREP_INSTALL_URL


RUST_ACCELERATION_BUILD_URL = (
    "https://github.com/duriantaco/skylos/blob/main/rust/README.md"
)


def _rust_available() -> bool:
    from skylos.core.fast import FAST_AVAILABLE

    return FAST_AVAILABLE


def _llm_available() -> bool:
    from skylos.llm.runtime import llm_extra_installed

    return llm_extra_installed()


def _interactive_available() -> bool:
    try:
        import inquirer  # noqa: F401

        return True
    except ImportError:
        return False


def _dart_available() -> bool:
    """Whether the optional `skylos[dart]` grammar is installed."""
    from skylos.visitors.languages.dart.core import DART_LANG

    return DART_LANG is not None


def _ripgrep_available() -> bool:
    """Whether scans here would use ripgrep (else the slower in-process search)."""
    from skylos.core.grep_verify_common import grep_backend_name

    return grep_backend_name(str(Path.cwd())) == "ripgrep"


def _go_engine_status() -> dict[str, str]:
    from skylos.engines.go_runner import get_go_engine_status

    return get_go_engine_status()


def _agent_hooks_report() -> dict:
    """Installed agent hooks per client, with a pre-bash self-test."""
    from skylos.commands.doctor_hooks import check_agent_hooks

    return check_agent_hooks()


def _doctor_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos doctor",
        description="Check installation health and language-engine availability",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Print human-readable (default) or machine-readable health",
    )
    return parser


def _doctor_json_report(py_ver: str, py_ok: bool, go_status: dict) -> dict:
    rust_available = _rust_available()
    llm_available = _llm_available()
    interactive_available = _interactive_available()
    agent_hooks = _agent_hooks_report()
    degraded = (
        go_status.get("status") != "available"
        or agent_hooks.get("status") == "degraded"
    )
    return {
        "schema_version": 1,
        "tool": "doctor",
        "status": "fail" if not py_ok else ("degraded" if degraded else "ok"),
        "checks": {
            "python": {
                "status": "ok" if py_ok else "fail",
                "version": py_ver,
                "minimum_version": "3.10",
            },
            "skylos": {"status": "ok", "version": str(skylos.__version__)},
            "go_engine": _go_engine_json(go_status),
            "rust_acceleration": {
                "status": "available" if rust_available else "unavailable",
                "module": "skylos_fast",
                "optional": True,
                "build_url": RUST_ACCELERATION_BUILD_URL,
            },
            "llm_support": (
                {"status": "available"}
                if llm_available
                else {"status": "unavailable", "install": 'pip install "skylos[llm]"'}
            ),
            "dart_support": (
                {"status": "available"}
                if _dart_available()
                else {"status": "unavailable", "install": 'pip install "skylos[dart]"'}
            ),
            "interactive": {
                "status": "available" if interactive_available else "unavailable"
            },
            "ripgrep": (
                {"status": "available"}
                if _ripgrep_available()
                else {"status": "unavailable", "install_url": RIPGREP_INSTALL_URL}
            ),
            "agent_hooks": agent_hooks,
            "config": _config_sources_report(Path.cwd()),
            "ci": _ci_report(Path.cwd()),
        },
    }


def _config_sources_report(cwd: Path) -> dict:
    """The config files that apply here (nearest first) and the ones ignored."""
    from skylos.config import describe_config_sources

    try:
        sources = describe_config_sources(cwd)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "sources": []}
    return {
        "status": "ok" if any(s["used"] for s in sources) else "defaults",
        "sources": [
            {
                "path": str(s["path"]),
                "kind": s["kind"],
                "used": s["used"],
                **({"reason": s["reason"]} if s.get("reason") else {}),
            }
            for s in sources
        ],
    }


def _go_engine_json(go_status: dict) -> dict:
    report = dict(go_status)
    if report.get("status") != "available":
        from skylos.engines.go_runner import (
            GO_ENGINE_IMAGE,
            go_engine_install_hint,
            go_engine_install_steps,
        )

        report.setdefault("install", go_engine_install_hint())
        report["install_steps"] = go_engine_install_steps()
        report["container_image"] = f"{GO_ENGINE_IMAGE}:{skylos.__version__}"
    return report


def _print_availability(
    console: Console,
    available: bool,
    available_message: str,
    unavailable_message: str,
) -> None:
    console.print(available_message if available else unavailable_message)


def _print_runtime_status(
    console: Console,
    py_ver: str,
    py_ok: bool,
    go_status: dict[str, str],
) -> None:
    console.print(
        f"  {'[green]OK[/green]' if py_ok else '[red]FAIL[/red]'}  Python {py_ver}"
        + ("" if py_ok else " [red](requires 3.10+)[/red]")
    )
    console.print(f"  [green]OK[/green]  Skylos {skylos.__version__}")
    _print_availability(
        console,
        go_status.get("status") == "available",
        "  [green]OK[/green]  Go engine available"
        + (
            " [dim](bundled with this install)[/dim]"
            if go_status.get("configured_by") == "bundled"
            else ""
        ),
        "  [yellow]--[/yellow]  Go engine unavailable "
        "[dim](Go dead-code and security checks will be incomplete)[/dim]",
    )
    if go_status.get("status") != "available":
        _print_go_engine_steps(console)


def _print_go_engine_steps(console: Console) -> None:
    from rich.markup import escape

    from skylos.engines.go_runner import (
        GO_ENGINE_IMAGE,
        GO_ENGINE_MIN_GO,
        go_engine_install_steps,
    )

    version = str(skylos.__version__)
    console.print(
        f"      [dim]Get it (needs Go {GO_ENGINE_MIN_GO}+), matching this Skylos:[/dim]"
    )
    for step in go_engine_install_steps(version):
        console.print(f"        {escape(step)}", soft_wrap=True, highlight=False)
    console.print(
        "      [dim]Keep $HOME/.local/bin on PATH, or set SKYLOS_GO_BIN to the "
        "binary (skylos-go.exe on Windows).[/dim]",
        soft_wrap=True,
    )
    console.print(
        f"      [dim]No Go toolchain? The container image {GO_ENGINE_IMAGE}:{version} "
        "includes the engine, and the Skylos GitHub Action builds it.[/dim]",
        soft_wrap=True,
    )


def _print_optional_status(console: Console) -> None:
    rust_available = _rust_available()
    _print_availability(
        console,
        rust_available,
        "  [green]OK[/green]  skylos_fast available (optional Rust acceleration)",
        "  [yellow]--[/yellow]  Rust acceleration unavailable "
        "[dim](optional; using Python fallbacks)[/dim]",
    )
    if not rust_available:
        console.print(
            f"      [dim]Build from source: {RUST_ACCELERATION_BUILD_URL}[/dim]"
        )
    _print_availability(
        console,
        _llm_available(),
        "  [green]OK[/green]  LLM support installed",
        "  [yellow]--[/yellow]  LLM support not installed "
        '[dim](optional, for skylos agent: pip install "skylos\\[llm]")[/dim]',
    )
    _print_availability(
        console,
        _dart_available(),
        "  [green]OK[/green]  Dart support installed",
        "  [yellow]--[/yellow]  Dart support not installed "
        '[dim](optional, needs a C compiler: pip install "skylos\\[dart]")[/dim]',
    )
    _print_availability(
        console,
        _interactive_available(),
        "  [green]OK[/green]  Interactive mode available",
        "  [yellow]--[/yellow]  Interactive mode not available "
        "[dim](optional: pip install inquirer)[/dim]",
    )
    _print_availability(
        console,
        _ripgrep_available(),
        "  [green]OK[/green]  ripgrep available (fast dead-code verification)",
        "  [yellow]--[/yellow]  ripgrep (rg) unavailable to Skylos "
        "[dim](optional, faster on large repos: brew install ripgrep / "
        f"apt install ripgrep; ensure rg is on PATH; {RIPGREP_INSTALL_URL})[/dim]",
    )


def _print_credit_status(console: Console, token: str) -> None:
    try:
        from skylos.api import get_credit_balance

        balance_data = get_credit_balance(token)
    except Exception:
        console.print("  [yellow]--[/yellow]  Cloud credit balance unavailable")
        return
    if not balance_data:
        return
    plan = balance_data.get("plan", "free")
    balance = balance_data.get("balance", 0)
    plan_name = plan_display_name(plan)
    color = "green" if balance > 0 else "red"
    console.print(f"  [{color}]OK[/{color}]  Plan: {plan_name} | Credits: {balance:,}")


def _print_cloud_status(console: Console) -> None:
    from skylos.api import get_project_token

    token = get_project_token()
    if not token:
        console.print(
            "  [yellow]--[/yellow]  Cloud not connected [dim](optional: skylos login)[/dim]"
        )
        return
    source = "saved login"
    if os.environ.get("SKYLOS_TOKEN"):
        source = "SKYLOS_TOKEN set"
    console.print(f"  [green]OK[/green]  Cloud connected ({source})")
    _print_credit_status(console, token)


def _config_label(source: dict, cwd: Path) -> str:
    path = source["path"]
    try:
        shown = path.relative_to(cwd).as_posix()
    except ValueError:
        shown = str(path)
    if source["kind"] == "pyproject.toml":
        return (
            f"pyproject.toml {escape('[tool.skylos]')} config found ({escape(shown)})"
        )
    if source["kind"] == "synced":
        return f"Synced Cloud policy found ({escape(shown)})"
    return f"{escape(source['kind'])} config found ({escape(shown)})"


def _print_project_config(console: Console, cwd: Path) -> None:
    """Which config files apply here, nearest first, and which are ignored."""
    from skylos.config import describe_config_sources

    try:
        load_config(cwd)
        sources = describe_config_sources(cwd)
    except Exception as exc:
        console.print(
            f"  [yellow]--[/yellow]  Skylos config could not be read: {escape(str(exc))}"
        )
        return
    used = [s for s in sources if s["used"] and s["kind"] != "synced"]
    if not used:
        console.print(
            "  [yellow]--[/yellow]  No Skylos config (defaults) [dim](add skylos.toml, "
            "or \\[tool.skylos] in pyproject.toml)[/dim]"
        )
    for index, source in enumerate(used):
        note = ""
        if len(used) > 1:
            note = (
                " [dim](nearest, wins per key)[/dim]"
                if index == 0
                else (" [dim](inherited)[/dim]")
            )
        console.print(f"  [green]OK[/green]  {_config_label(source, cwd)}{note}")
    for source in sources:
        if source["kind"] == "synced":
            console.print(f"  [green]OK[/green]  {_config_label(source, cwd)}")
        elif not source["used"]:
            console.print(
                f"  [yellow]--[/yellow]  Not read: {escape(str(source['path']))} "
                f"[dim]({escape(source.get('reason', ''))})[/dim]"
            )


def _print_workflow_status(console: Console, cwd: Path) -> None:
    from skylos.cicd.platforms import detect_repo_platforms

    workflow = cwd / ".github" / "workflows" / "skylos.yml"
    found = []
    if not workflow.exists():
        found = detect_repo_platforms(cwd)
    if workflow.exists() or not found:
        _print_availability(
            console,
            workflow.exists(),
            "  [green]OK[/green]  GitHub Actions workflow found",
            "  [yellow]--[/yellow]  No CI/CD workflow [dim](run: skylos cicd init)[/dim]",
        )
    for item in found:
        name = escape(item.platform.name)
        if item.runs_skylos:
            shown = escape(_relative_label(item.runs_skylos, cwd))
            console.print(f"  [green]OK[/green]  {name} runs Skylos ({shown})")
            continue
        key = item.platform.key
        if not item.platform.config:
            key = "other"
        shown = escape(_relative_label(item.path, cwd))
        console.print(
            f"  [yellow]--[/yellow]  {name} ({shown}) does not run Skylos "
            f"[dim](run: skylos cicd init --ci {key})[/dim]"
        )
    _print_ci_runtime(console, cwd)


def _relative_label(path: Path, cwd: Path) -> str:
    try:
        return str(path.relative_to(cwd))
    except ValueError:
        return str(path)


def _ci_runtime_report(cwd: Path) -> dict | None:
    """What `--diff` compares with in the CI running this, or None outside CI."""
    from skylos.cicd.platforms import missing_base_hint
    from skylos.core.ci_env import auto_diff_base_ref, ci_name, github_or_ci_base_ref

    name = ci_name()
    if not name:
        return None
    base = auto_diff_base_ref()
    try:
        fetch = missing_base_hint(base, cwd)
    except Exception:
        fetch = None
    report = {
        "name": name,
        "pull_request": bool(github_or_ci_base_ref()),
        "diff_base": base,
    }
    if fetch:
        report["fetch"] = fetch
    return report


def _print_ci_runtime(console: Console, cwd: Path) -> None:
    runtime = _ci_runtime_report(cwd)
    if runtime is None:
        return
    name = escape(runtime["name"])
    base = escape(runtime["diff_base"] or "")
    if runtime["pull_request"]:
        console.print(f"  [green]OK[/green]  {name} pull request: --diff compares with {base}")
    else:
        console.print(
            f"  [dim]--[/dim]  {name} build, not a pull request: --diff compares with {base}"
        )
    if runtime.get("fetch"):
        console.print(
            f"  [yellow]--[/yellow]  {base} is not usable here. "
            f"{escape(runtime['fetch'])}",
            soft_wrap=True,
        )


def _ci_report(cwd: Path) -> dict:
    from skylos.cicd.platforms import detect_repo_platforms

    platforms = [
        {
            "key": item.platform.key,
            "name": item.platform.name,
            "path": _relative_label(item.path, cwd),
            "runs_skylos": item.runs_skylos is not None,
        }
        for item in detect_repo_platforms(cwd)
    ]
    status = "missing"
    if any(p["runs_skylos"] for p in platforms):
        status = "ok"
    return {"status": status, "platforms": platforms, "runtime": _ci_runtime_report(cwd)}


def _print_rule_status(console: Console) -> None:
    rules_dir = Path.home() / ".skylos" / "rules"
    rule_files = list(rules_dir.glob("*.yml")) if rules_dir.exists() else []
    if rule_files:
        console.print(
            f"  [green]OK[/green]  {len(rule_files)} community rule pack(s) installed"
        )
        return
    console.print(
        "  [yellow]--[/yellow]  No community rules "
        "[dim](optional: skylos rules install <pack>)[/dim]"
    )


def _print_local_status(console: Console) -> None:
    cwd = Path.cwd()
    _print_project_config(console, cwd)
    _print_workflow_status(console, cwd)
    _print_rule_status(console)


def _print_agent_hooks(console: Console) -> None:
    from skylos.commands.doctor_hooks import print_agent_hooks

    console.print()
    print_agent_hooks(console, _agent_hooks_report())


def run_doctor_command(argv: list[str] | None = None) -> int:
    args = _doctor_parser().parse_args(argv or [])
    py_ver = platform.python_version()
    py_ok = tuple(int(x) for x in py_ver.split(".")[:2]) >= (3, 10)
    go_status = _go_engine_status()
    if args.format == "json":
        print(json.dumps(_doctor_json_report(py_ver, py_ok, go_status), indent=2))
        return 0

    console = Console()
    console.print()
    console.print(Panel.fit("[bold]Skylos Doctor[/bold]", border_style="cyan"))
    console.print()
    _print_runtime_status(console, py_ver, py_ok, go_status)
    _print_optional_status(console)
    _print_cloud_status(console)
    _print_local_status(console)
    _print_agent_hooks(console)
    console.print()
    return 0
