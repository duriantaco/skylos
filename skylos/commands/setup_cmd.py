"""``skylos setup``: connect a repository's coding agents and pull request check to Skylos."""

from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.markup import escape

MARK_START = "<!-- skylos:start -->"
MARK_END = "<!-- skylos:end -->"
AGENT_FILES = ("CLAUDE.md", "AGENTS.md")
MCP_FILE = ".mcp.json"
MCP_ENTRY = {"command": "skylos", "args": ["mcp"]}
WORKFLOW = Path(".github") / "workflows" / "skylos.yml"
GRAPH_DIR = ".skylos/graph"
EXIT_OK = 0
EXIT_ERROR = 1

AGENT_BLOCK = """## Skylos

Before changing code, use the Skylos tools: graph_relevant for the files you
will touch, then graph_show and graph_impact for each function you change.

When you are done:
1. Run `skylos done --base {base}` and fix anything it blocks.
2. Explain the change for reviewers: call graph_pending with changes=true and
   base {base}, then save each explanation (before, after, same_behaviour,
   why, and impact on the callers it lists) with graph_describe.
3. Describe new or changed code: call graph_pending and save a one-sentence
   plain-English description for each item with graph_describe.
4. Put the "Read first" list from `skylos done map --base {base}` in your
   final message.

When asked to describe the code, call graph_pending and save descriptions with
graph_describe until it lists nothing.

Without the Skylos tools, use the same steps from the shell:
`skylos graph pending --changes --base {base}` and `skylos graph import FILE`."""


@dataclass
class Step:
    label: str
    text: str
    ok: bool = True


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos setup",
        description=(
            "Set up Skylos in this repository once: adds the Skylos steps to CLAUDE.md and AGENTS.md, "
            "connects Claude Code (.mcp.json) and Codex to the Skylos tools, writes the pull request "
            "check and maps the code. Run it again at any time; it only changes what is missing or out of date. "
            "Then run: skylos open"
        ),
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository (default: .)")
    parser.add_argument("--base", metavar="REF", help="Branch pull requests merge into, e.g. origin/main (default: detected)")
    parser.add_argument("--ci", help="CI to set up when the repository has several (github, gitlab, jenkins, bitbucket, azure, circleci)")
    parser.add_argument("--no-ci", action="store_true", help="Do not write the pull request check")
    parser.add_argument("--no-codex", action="store_true", help="Do not add the Skylos tools to Codex")
    parser.add_argument("--yes", action="store_true", help="Replace an existing Skylos workflow without asking")
    return parser


def _git(root: Path, *args: str, strip: bool = True) -> str:
    try:
        result = subprocess.run(
            ["git", *args], cwd=root, capture_output=True, text=True, timeout=20, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode:
        return ""
    if strip:
        return result.stdout.strip()
    return result.stdout


def repo_root(path: str) -> Path | None:
    start = Path(path).resolve()
    if not start.is_dir():
        return None
    top = _git(start, "rev-parse", "--show-toplevel")
    if not top:
        return None
    return Path(top)


def default_base(root: Path) -> str | None:
    head = _git(root, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD")
    if head.startswith("origin/"):
        return head
    for ref in ("origin/main", "origin/master"):
        if _git(root, "rev-parse", "--verify", "--quiet", f"refs/remotes/{ref}"):
            return ref
    for branch in ("main", "master"):
        if _git(root, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"):
            return branch
    return None


def current_branch(root: Path) -> str:
    return _git(root, "branch", "--show-current")


def agent_block(base: str) -> str:
    return f"{MARK_START}\n{AGENT_BLOCK.format(base=base)}\n{MARK_END}\n"


def merge_block(existing: str | None, block: str) -> str:
    if not existing:
        return block
    start = existing.find(MARK_START)
    end = existing.find(MARK_END, max(start, 0))
    if start >= 0 and end > start:
        tail = existing[end + len(MARK_END):]
        if tail.startswith("\n"):
            tail = tail[1:]
        return existing[:start] + block + tail
    separator = "\n\n"
    if existing.endswith("\n\n"):
        separator = ""
    elif existing.endswith("\n"):
        separator = "\n"
    return existing + separator + block


def _imports_agents_file(text: str) -> bool:
    return any(line.strip() == "@AGENTS.md" for line in text.splitlines())


def _inside(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def write_agent_files(root: Path, base: str) -> Step:
    block = agent_block(base)
    written = []
    refreshed = []
    current = []
    skipped = []
    seen = set()
    for name in AGENT_FILES:
        path = root / name
        if path.is_symlink() and not _inside(root, path):
            skipped.append(f"{name} (links outside the repository)")
            continue
        target = path.resolve()
        if target in seen:
            continue
        seen.add(target)
        existing = None
        if path.exists():
            try:
                existing = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                skipped.append(f"{name} (could not be read)")
                continue
        if name == "CLAUDE.md" and existing and _imports_agents_file(existing) and MARK_START not in existing:
            continue
        updated = merge_block(existing, block)
        if updated == existing:
            current.append(name)
            continue
        try:
            path.write_text(updated, encoding="utf-8")
        except OSError:
            skipped.append(f"{name} (could not be written)")
            continue
        if existing and MARK_START in existing:
            refreshed.append(name)
        else:
            written.append(name)
    parts = []
    if written:
        parts.append(f"{', '.join(written)}: Skylos steps added")
    if refreshed:
        parts.append(f"{', '.join(refreshed)}: Skylos steps updated")
    if current:
        parts.append(f"{', '.join(current)}: up to date")
    if skipped:
        parts.append(f"skipped {', '.join(skipped)}")
    return Step("Coding agents", "; ".join(parts), not skipped)


def _path_mismatch() -> str:
    running = skylos_command()
    found = shutil.which("skylos")
    if running == "skylos" or not found:
        return ""
    try:
        same = Path(found).resolve() == Path(running).resolve()
    except OSError:
        same = False
    if same:
        return ""
    return found


def write_mcp_config(root: Path) -> Step:
    path = root / MCP_FILE
    config = {}
    if path.exists():
        try:
            config = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return Step("Claude Code", f"{MCP_FILE} is not valid JSON; add \"skylos\": {json.dumps(MCP_ENTRY)} under mcpServers", False)
        if not isinstance(config, dict):
            return Step("Claude Code", f"{MCP_FILE} is not a JSON object; left unchanged", False)
    servers = config.get("mcpServers")
    if servers is None:
        servers = {}
    if not isinstance(servers, dict):
        return Step("Claude Code", f"mcpServers in {MCP_FILE} is not an object; left unchanged", False)
    if "skylos" in servers:
        return Step("Claude Code", f"{MCP_FILE}: Skylos tools already connected")
    servers["skylos"] = dict(MCP_ENTRY)
    config["mcpServers"] = servers
    try:
        path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        return Step("Claude Code", f"could not write {MCP_FILE}: {exc}", False)
    return Step("Claude Code", f"{MCP_FILE}: Skylos tools connected (Claude Code asks you to approve them once)")


def skylos_command() -> str:
    launched = Path(sys.argv[0])
    if launched.name == "skylos" and launched.is_file():
        return str(launched.resolve())
    found = shutil.which("skylos")
    if found:
        return found
    return "skylos"


def _run_quiet(args: list[str]) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        return None


def _codex_command(text: str) -> str:
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return ""
    if not isinstance(data, dict):
        return ""
    transport = data.get("transport")
    if not isinstance(transport, dict):
        return ""
    command = transport.get("command")
    if not isinstance(command, str):
        return ""
    return command


def connect_codex() -> Step:
    codex = shutil.which("codex")
    command = skylos_command()
    manual = f"codex mcp add skylos -- {command} mcp"
    if not codex:
        return Step("Codex", f"not installed; when you install it run: {manual}")
    found = _run_quiet([codex, "mcp", "get", "skylos", "--json"])
    if found is not None and found.returncode == 0:
        current = _codex_command(found.stdout)
        if current and current != command and command != "skylos":
            return Step(
                "Codex",
                f"connected to a different Skylos ({current}); to use this one run: "
                f"codex mcp remove skylos && {manual}",
                False,
            )
        return Step("Codex", "Skylos tools already connected")
    added = _run_quiet([codex, "mcp", "add", "skylos", "--", command, "mcp"])
    if added is None or added.returncode:
        return Step("Codex", f"could not add the Skylos tools; run: {manual}", False)
    return Step("Codex", "Skylos tools connected (in your Codex settings)")


def _cicd_argv(args) -> list[str]:
    argv = ["init"]
    if args.ci:
        argv += ["--ci", args.ci]
    if args.yes:
        argv.append("--force")
    return argv


def _ci_summary(output: str) -> str | None:
    for line in output.splitlines():
        text = line.strip()
        if text.startswith("Workflow written to "):
            return f"{text.removeprefix('Workflow written to ')}: scans changed lines and runs your tests on every pull request"
        if text.startswith("Workflow already up to date: "):
            return f"{text.removeprefix('Workflow already up to date: ')}: up to date"
    return None


def write_ci(root: Path, args, out: Console) -> Step:
    previous = Path.cwd()
    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    live = interactive and not args.yes and (root / WORKFLOW).exists()
    buffer = io.StringIO()

    def recording_console():
        return Console(file=buffer, width=100, highlight=False, soft_wrap=True)

    def live_console():
        return out

    factory = recording_console
    if live:
        factory = live_console
    try:
        os.chdir(root)
        from skylos.commands.cicd_cmd import run_cicd_command as run_cicd_impl
        from skylos import cli as cli_module

        code = run_cicd_impl(
            _cicd_argv(args),
            console_factory=factory,
            load_config_func=cli_module.load_config,
            run_gate_interaction_func=cli_module.run_gate_interaction,
            emit_github_annotations_func=cli_module._emit_github_annotations,
        )
    except SystemExit as exc:
        code = exc.code
        if not isinstance(code, int):
            code = EXIT_ERROR
    finally:
        os.chdir(previous)
    output = buffer.getvalue()
    summary = _ci_summary(output)
    if live:
        summary = summary or "see above"
    if code == 0 and summary:
        return Step("PR check", summary)
    if output.strip():
        out.print(escape(output.rstrip()), soft_wrap=True)
    if code == 0:
        return Step("PR check", "add the steps printed above to your CI")
    return Step("PR check", "not written (see above); run skylos setup again or skylos cicd init", False)


def map_code(root: Path) -> tuple[Step, bool]:
    from skylos.graph import build_graph
    from skylos.graph.query import GraphIndex
    from skylos.graph.store import load_notes

    try:
        graph = build_graph(str(root))
    except Exception as exc:
        return Step("Code map", f"could not build: {exc}", False), True
    info = GraphIndex(root, graph, load_notes(root)).overview()
    total = info["functions"] + info["methods"] + info["classes"]
    text = f"{total} functions and classes in {info['files']} files"
    if info.get("areas"):
        text += f", {info['areas']} areas"
    if total:
        text += f"; {info['described']} described in plain English"
    return Step("Code map", text), info["described"] > 0 or total == 0


def _print_steps(out: Console, root: Path, steps: list[Step]) -> None:
    out.print(f"[bold]Skylos is set up in {escape(root.name)}[/bold]")
    out.print("")
    width = max(len(step.label) for step in steps)
    for step in steps:
        mark = "[green]✓[/green]"
        if not step.ok:
            mark = "[yellow]![/yellow]"
        out.print(f"  {mark} {escape(step.label.ljust(width))}  {escape(step.text)}", soft_wrap=True)


def _changed_files(root: Path) -> list[str]:
    candidates = [*AGENT_FILES, MCP_FILE, str(WORKFLOW), GRAPH_DIR]
    status = _git(root, "status", "--porcelain", "--untracked-files=all", "--", *candidates, strip=False)
    files = []
    for line in status.splitlines():
        name = line[3:].strip()
        if name:
            files.append(name)
    return files


def _print_next(out: Console, root: Path, described: bool) -> None:
    out.print("")
    out.print("[bold]Next[/bold]")
    out.print("  [bold]skylos open[/bold]   the map of your code, what changed and every check, in one page", soft_wrap=True)
    files = _changed_files(root)
    if files:
        out.print(f"  Commit {escape(', '.join(files))} so your team and CI get them.", soft_wrap=True)
    if not described:
        out.print("  [dim]For plain-English descriptions, ask your coding agent: \"describe the code with Skylos\".[/dim]", soft_wrap=True)


def _with_path_check(step: Step) -> Step:
    other = _path_mismatch()
    if not other:
        return step
    return Step(
        step.label,
        f"{step.text}. But your PATH starts {other}, not this Skylos: start Claude Code from a shell "
        f"where `which skylos` shows {skylos_command()}",
        False,
    )


def run_setup_command(argv: list[str], *, console: Console | None = None) -> int:
    out = console or Console(highlight=False)
    args = build_parser().parse_args(list(argv))
    root = repo_root(args.path)
    if root is None:
        out.print("[red]skylos setup:[/red] run it inside a git repository.")
        return EXIT_ERROR
    base = args.base or default_base(root)
    base_note = None
    if not base:
        base = "origin/main"
        base_note = "No main branch found; agents compare with origin/main. Use --base to change it."
    steps = [write_agent_files(root, base), _with_path_check(write_mcp_config(root))]
    if not args.no_codex:
        steps.append(connect_codex())
    if not args.no_ci:
        steps.append(write_ci(root, args, out))
    mapped, described = map_code(root)
    steps.append(mapped)
    _print_steps(out, root, steps)
    if base_note:
        out.print(f"  [dim]{escape(base_note)}[/dim]", soft_wrap=True)
    _print_next(out, root, described)
    if all(step.ok for step in steps):
        return EXIT_OK
    return EXIT_ERROR
