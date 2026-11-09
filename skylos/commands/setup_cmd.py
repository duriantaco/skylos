"""``skylos setup``: connect a repository's coding agents and pull request check to Skylos."""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from skylos.cicd.init_setup import detect_done_setup, js_runner_settings
from skylos.cicd.platforms import platform_from_remote
from skylos.cicd.workflow import DONE_JOB_NAME, GATE_JOB_NAME, RISK_REVIEW_JOB_NAME, UPLOAD_JOB_NAME
from skylos.commands import install_hooks_cmd
from skylos.done.config import CONFIG_FILE_NAMES, parse_done_config, working_tree_config_file

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

MARK_START = "<!-- skylos:start -->"
MARK_END = "<!-- skylos:end -->"
AGENT_FILES = ("CLAUDE.md", "AGENTS.md")
MCP_FILE = ".mcp.json"
MCP_ENTRY = {"command": "skylos", "args": ["mcp"]}
WORKFLOW = Path(".github") / "workflows" / "skylos.yml"
GRAPH_DIR = ".skylos/graph"
HOOK_FILES = (("claude", ".claude/settings.json"), ("codex", ".codex/hooks.json"))
HOOK_STATE_IGNORE = ".skylos/.gitignore"
DONE_TABLE_COMMENT = "# written by skylos setup; Done reads this table from the base branch"
PYTEST_DONE_LINES = ("test_budget_seconds = 300",)
RULESET_NAME = "Skylos"
CLOUD_LABEL = "Skylos Cloud"
CLOUD_CONNECTED = (
    "connected; the workflow uploads to Skylos Cloud with GitHub OIDC; see this branch with skylos cloud"
)
CLOUD_CONNECTED_NO_UPLOAD = "connected; see this branch with skylos cloud"
CLOUD_WORKFLOW_WITHOUT_UPLOAD = " (the workflow has no Cloud upload jobs: skylos setup --yes rewrites it)"
CLOUD_NOT_CONNECTED = (
    "not connected (optional): skylos login once, then skylos setup again adds the Cloud upload jobs"
)
GH_REPO = "repos/{owner}/{repo}"
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

hook_probe = install_hooks_cmd.probe_hook_support


@dataclass
class Step:
    label: str
    text: str
    ok: bool = True
    pending: bool = False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos setup",
        description=(
            "Set up Skylos in this repository once: adds the Skylos steps to CLAUDE.md and AGENTS.md, "
            "connects Claude Code (.mcp.json) and Codex to the Skylos tools, installs the agent hooks "
            "(.claude/settings.json, .codex/hooks.json), lets Done run your tests ([tool.skylos.done]), "
            "writes the pull request check (with the Skylos Cloud upload when this machine is logged in), "
            "makes its checks required on GitHub once the workflow is merged, "
            "and maps the code. Run it again at any time; it only changes what is missing or out of date. "
            "Then run: skylos open"
        ),
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository (default: .)")
    parser.add_argument("--base", metavar="REF", help="Branch pull requests merge into, e.g. origin/main (default: detected)")
    parser.add_argument("--ci", help="CI to set up when the repository has several (github, gitlab, jenkins, bitbucket, azure, circleci)")
    parser.add_argument("--no-ci", action="store_true", help="Do not write the pull request check")
    parser.add_argument("--no-codex", action="store_true", help="Do not add the Skylos tools or hooks to Codex")
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


def _append(existing: str | None, block: str) -> str:
    if not existing:
        return block
    separator = "\n\n"
    if existing.endswith("\n\n"):
        separator = ""
    elif existing.endswith("\n"):
        separator = "\n"
    return existing + separator + block


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
    return _append(existing, block)


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


def install_agent_hooks(root: Path, *, codex: bool) -> tuple[Step, bool]:
    if hook_probe(["skylos"]) is None:
        return Step(
            "Agent hooks",
            "not installed: the `skylos` on PATH does not support `skylos hook` (missing or older "
            f"than this one); put {skylos_command()} first on PATH, then run skylos setup again",
            False,
        ), False
    installed = []
    current = []
    problems = []
    for agent, shown in HOOK_FILES:
        if agent == "codex" and not codex:
            continue
        lines: list[str] = []
        args = argparse.Namespace(
            agent=agent,
            scope="project",
            path=str(root),
            skylos_bin="skylos",
            check_bin=False,
            uninstall=False,
            dry_run=False,
        )
        code = install_hooks_cmd.run_install_hooks_command(args, print_func=lines.append)
        first = ""
        if lines:
            first = lines[0]
        if code:
            problems.append(f"{shown}: {first}")
        elif first.startswith("Installed"):
            installed.append(shown)
        else:
            current.append(shown)
    parts = []
    if installed:
        parts.append(f"{', '.join(installed)}: Skylos checks every edit and the finished change")
    if current:
        parts.append(f"{', '.join(current)}: up to date")
    parts.extend(problems)
    return Step("Agent hooks", "; ".join(parts), not problems), bool(installed)


def _done_header(path: Path, data: dict) -> str:
    if path.name == "pyproject.toml":
        return "[tool.skylos.done]"
    tool = data.get("tool")
    if isinstance(tool, dict) and "skylos" in tool:
        return "[tool.skylos.done]"
    if isinstance(data.get("skylos"), dict):
        return "[skylos.done]"
    return "[done]"


def done_settings(root: Path) -> tuple[tuple[str, ...], str, str]:
    detected = detect_done_setup(root)
    if detected.enabled:
        return PYTEST_DONE_LINES, "pytest", ""
    runner = js_runner_settings(root)
    if runner is None:
        return (), "", ""
    name, lines, install = runner
    if install:
        return (), name, install
    return lines, name, ""


def write_done_table(root: Path) -> Step:
    path = working_tree_config_file(root)
    shown = path.name
    existing = None
    data: dict = {}
    if path.exists():
        if path.is_symlink() and not _inside(root, path):
            return Step("Tests", f"{shown} links outside the repository; left unchanged", False)
        try:
            existing = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return Step("Tests", f"{shown} could not be read; left unchanged", False)
        try:
            data = tomllib.loads(existing)
        except tomllib.TOMLDecodeError:
            return Step("Tests", f"{shown} is not valid TOML; left unchanged", False)
    header = _done_header(path, data)
    if parse_done_config(existing).configured:
        return Step("Tests", f"{shown}: {header} already set")
    lines, runner, install = done_settings(root)
    if install:
        return Step("Tests", f"{runner} found: run {install}, then skylos setup again", pending=True)
    if not lines:
        return Step(
            "Tests",
            f"no pytest, Vitest or Jest tests found; set test_command in {header} when you have some",
            pending=True,
        )
    block = "\n".join([header, DONE_TABLE_COMMENT, *lines]) + "\n"
    try:
        path.write_text(_append(existing, block), encoding="utf-8")
    except OSError as exc:
        return Step("Tests", f"could not write {shown}: {exc}", False)
    return Step("Tests", f"{shown}: {header} added; Done runs {runner} once it is committed")


def _cicd_argv(args, connected: bool) -> list[str]:
    argv = ["init"]
    if args.ci:
        argv += ["--ci", args.ci]
    if args.yes:
        argv.append("--force")
    if connected:
        argv.append("--upload")
    else:
        argv.append("--no-upload")
    return argv


def cloud_login_found(root: Path) -> bool:
    from skylos.commands.cicd_cmd import _cloud_login_found

    return _cloud_login_found(root)


def _workflow_uploads(root: Path) -> bool | None:
    try:
        text = (root / WORKFLOW).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    return f"name: {UPLOAD_JOB_NAME}" in text


def cloud_status(root: Path, connected: bool) -> Step:
    if not connected:
        return Step(CLOUD_LABEL, CLOUD_NOT_CONNECTED, pending=True)
    uploads = _workflow_uploads(root)
    if uploads:
        return Step(CLOUD_LABEL, CLOUD_CONNECTED)
    if uploads is None:
        return Step(CLOUD_LABEL, CLOUD_CONNECTED_NO_UPLOAD)
    return Step(CLOUD_LABEL, CLOUD_CONNECTED_NO_UPLOAD + CLOUD_WORKFLOW_WITHOUT_UPLOAD)


def _ci_summary(output: str) -> str | None:
    for line in output.splitlines():
        text = line.strip()
        if text.startswith("Workflow written to "):
            return f"{text.removeprefix('Workflow written to ')}: scans changed lines and runs your tests on every pull request"
        if text.startswith("Workflow already up to date: "):
            return f"{text.removeprefix('Workflow already up to date: ')}: up to date"
    return None


def write_ci(root: Path, args, out: Console, connected: bool) -> Step:
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
            _cicd_argv(args, connected),
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


def _gh(root: Path, args: list[str], input: str | None = None) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(
            ["gh", *args], cwd=root, input=input, capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _gh_json(root: Path, args: list[str]):
    result = _gh(root, args)
    if result is None or result.returncode:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def workflow_checks(text: str) -> list[str]:
    checks = [GATE_JOB_NAME]
    for name in (DONE_JOB_NAME, RISK_REVIEW_JOB_NAME):
        if re.search(rf"^\s*name: {re.escape(name)}\s*$", text, re.MULTILINE):
            checks.append(name)
    return checks


def ruleset_body(checks: list[str]) -> dict:
    return {
        "name": RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "rules": [
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": False,
                    "required_status_checks": [{"context": check} for check in checks],
                },
            }
        ],
    }


def _ruleset_checks(ruleset: dict) -> list[str]:
    found = []
    for rule in ruleset.get("rules") or []:
        if not isinstance(rule, dict) or rule.get("type") != "required_status_checks":
            continue
        parameters = rule.get("parameters")
        if not isinstance(parameters, dict):
            continue
        for entry in parameters.get("required_status_checks") or []:
            if isinstance(entry, dict) and isinstance(entry.get("context"), str):
                found.append(entry["context"])
    return found


def require_checks(root: Path, base: str) -> tuple[Step, bool]:
    label = "Required checks"
    branch = base.removeprefix("origin/")
    workflow = root / WORKFLOW
    if not workflow.is_file():
        return Step(label, f"no {WORKFLOW.as_posix()}; other CIs: require the Skylos check in the CI's own settings", pending=True), False
    remote = _git(root, "remote", "get-url", "origin")
    if not remote:
        return Step(label, "no origin remote yet; push to GitHub and merge the workflow first", pending=True), True
    platform = platform_from_remote(remote)
    if platform is None or platform.key != "github":
        return Step(label, "origin is not on GitHub; require the Skylos checks in your code host's branch settings", pending=True), False
    if not shutil.which("gh"):
        return Step(label, "needs the GitHub CLI: install gh (https://cli.github.com), then run skylos setup again", pending=True), True
    auth = _gh(root, ["auth", "status"])
    if auth is None or auth.returncode:
        return Step(label, "run gh auth login, then skylos setup again", pending=True), True
    try:
        text = workflow.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return Step(label, f"could not read {WORKFLOW.as_posix()}", False), False
    at_origin = _gh_json(root, ["api", f"{GH_REPO}/contents/{WORKFLOW.as_posix()}"])
    local_sha = _git(root, "hash-object", WORKFLOW.as_posix())
    if not isinstance(at_origin, dict) or not local_sha or at_origin.get("sha") != local_sha:
        return Step(label, f"waits for {WORKFLOW.as_posix()} to be merged into {branch}", pending=True), True
    checks = workflow_checks(text)
    listed = _gh_json(root, ["api", f"{GH_REPO}/rulesets?per_page=100"])
    if not isinstance(listed, list):
        return Step(label, f"could not list the rulesets (gh api {GH_REPO}/rulesets)", False), False
    existing = None
    for ruleset in listed:
        if isinstance(ruleset, dict) and ruleset.get("name") == RULESET_NAME:
            existing = ruleset
    if existing is not None:
        ruleset = _gh_json(root, ["api", f"{GH_REPO}/rulesets/{existing.get('id')}"])
        if not isinstance(ruleset, dict):
            return Step(label, f"could not read the {RULESET_NAME} ruleset", False), False
        found = _ruleset_checks(ruleset)
        if ruleset.get("enforcement") == "active" and sorted(found) == sorted(checks):
            return Step(label, f"ruleset {RULESET_NAME} already requires {', '.join(checks)} on {branch}"), False
        return Step(
            label,
            f"ruleset {RULESET_NAME} requires {', '.join(found) or 'nothing'} ({ruleset.get('enforcement')}); "
            f"the workflow has {', '.join(checks)}: fix it under Settings → Rules → Rulesets",
            pending=True,
        ), False
    created = _gh(
        root,
        ["api", "--method", "POST", f"{GH_REPO}/rulesets", "--input", "-"],
        input=json.dumps(ruleset_body(checks)),
    )
    if created is None or created.returncode:
        reason = "gh could not run"
        if created is not None and created.stderr.strip():
            reason = created.stderr.strip().splitlines()[0]
        return Step(
            label,
            f"could not create the ruleset ({reason}); needs admin access and a public repository or a paid plan",
            pending=True,
        ), False
    return Step(label, f"ruleset {RULESET_NAME} created: {', '.join(checks)} must pass to merge into {branch}"), False


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
        if step.pending:
            mark = "[dim]-[/dim]"
        elif not step.ok:
            mark = "[yellow]![/yellow]"
        out.print(f"  {mark} {escape(step.label.ljust(width))}  {escape(step.text)}", soft_wrap=True)


def _changed_files(root: Path) -> list[str]:
    candidates = [
        *AGENT_FILES,
        MCP_FILE,
        str(WORKFLOW),
        GRAPH_DIR,
        *(shown for _agent, shown in HOOK_FILES),
        HOOK_STATE_IGNORE,
        ".gitignore",
        *CONFIG_FILE_NAMES,
    ]
    status = _git(root, "status", "--porcelain", "--untracked-files=all", "--", *candidates, strip=False)
    files = []
    for line in status.splitlines():
        name = line[3:].strip()
        if name:
            files.append(name)
    return files


def _print_next(out: Console, root: Path, described: bool, *, merge_first: bool, hooks_added: bool) -> None:
    out.print("")
    out.print("[bold]Next[/bold]")
    out.print("  [bold]skylos open[/bold]   the map of your code, what changed and every check, in one page", soft_wrap=True)
    files = _changed_files(root)
    if files:
        out.print(f"  Commit {escape(', '.join(files))} so your team and CI get them.", soft_wrap=True)
    if merge_first:
        out.print(f"  Merge {WORKFLOW.as_posix()}, then run skylos setup again: it makes the checks required.", soft_wrap=True)
    if hooks_added:
        out.print("  Hooks start with the next Claude Code session; in Codex, trust them once with /hooks.", soft_wrap=True)
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
    hooks, hooks_added = install_agent_hooks(root, codex=not args.no_codex)
    steps.append(hooks)
    steps.append(write_done_table(root))
    merge_first = False
    connected = cloud_login_found(root)
    if not args.no_ci:
        steps.append(write_ci(root, args, out, connected))
    steps.append(cloud_status(root, connected))
    if not args.no_ci:
        required, merge_first = require_checks(root, base)
        steps.append(required)
    mapped, described = map_code(root)
    steps.append(mapped)
    _print_steps(out, root, steps)
    if base_note:
        out.print(f"  [dim]{escape(base_note)}[/dim]", soft_wrap=True)
    _print_next(out, root, described, merge_first=merge_first, hooks_added=hooks_added)
    if all(step.ok for step in steps):
        return EXIT_OK
    return EXIT_ERROR
