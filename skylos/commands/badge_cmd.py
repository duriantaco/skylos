"""``skylos badge``: README badge markdown that shows real state.

In order of preference:
1. The repo is linked to a Skylos Cloud project (``.skylos/link.json``): the
   Cloud badge, which shows whether the latest trusted scan passes the gate.
2. A GitHub repo with the Skylos workflow (``skylos cicd init``): the GitHub
   Actions status badge for that workflow.
3. Otherwise a plain "Checked with Skylos" badge, and how to get a live one.

No network request is made.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

from rich.console import Console

STATIC_BADGE = (
    "[![Checked with Skylos](https://img.shields.io/badge/checked%20with-Skylos-17627a)]"
    "(https://skylos.dev)"
)
# Kept for callers that imported the old name.
BADGE_MARKDOWN = STATIC_BADGE
WORKFLOW_NAMES = ("skylos.yml", "skylos.yaml")
_GITHUB_REMOTE_RE = re.compile(
    r"^(?:https?://(?:[^@/]+@)?github\.com/|ssh://git@github\.com/|git@github\.com:)"
    r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")


def github_slug(remote_url: str | None) -> str | None:
    if not remote_url:
        return None
    match = _GITHUB_REMOTE_RE.match(remote_url.strip())
    if not match:
        return None
    return f"{match.group('owner')}/{match.group('repo')}"


def _git_root(start: Path) -> Path | None:
    for parent in (start, *start.parents):
        if (parent / ".git").exists():
            return parent
    return None


def _origin_url(root: Path) -> str | None:
    from skylos.core.git_safety import read_only_git_command, read_only_git_environment

    try:
        out = subprocess.check_output(
            read_only_git_command(["-C", str(root), "config", "--get", "remote.origin.url"]),
            env=read_only_git_environment(),
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return out.decode("utf-8", "replace").strip() or None


def _linked_project_id(root: Path) -> str | None:
    from skylos.api import _linked_project_id_for_current_path, _load_repo_link

    project_id = _linked_project_id_for_current_path(_load_repo_link(str(root)), str(root))
    return project_id if project_id and _SAFE_ID_RE.match(project_id) else None


def choose_badge(root: Path | None, *, api_url: str, origin: str | None = None) -> dict:
    """Pick the most useful badge for ``root``; returns markdown, kind and a note."""
    if root is not None:
        project_id = _linked_project_id(root)
        if project_id:
            base = api_url.rstrip("/")
            return {
                "kind": "cloud",
                "markdown": f"[![Skylos quality gate]({base}/api/badge/{project_id})]"
                f"({base}/dashboard/projects/{project_id})",
                "note": "Live: shows whether the latest trusted scan passes your Skylos quality gate.",
            }
        slug = github_slug(origin if origin is not None else _origin_url(root))
        workflow = next(
            (n for n in WORKFLOW_NAMES if (root / ".github" / "workflows" / n).is_file()), None
        )
        if slug and workflow:
            url = f"https://github.com/{slug}/actions/workflows/{workflow}"
            return {
                "kind": "github-actions",
                "markdown": f"[![Skylos gate]({url}/badge.svg)]({url})",
                "note": "Live: shows whether the Skylos workflow passes on your default branch.",
            }
    return {
        "kind": "static",
        "markdown": STATIC_BADGE,
        "note": "For a badge that shows pass or fail, add the PR gate: skylos cicd init",
    }


def _badge_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos badge",
        description=(
            "Print README badge Markdown for this repository. It picks the "
            "Skylos Cloud gate badge when the repository is linked to a Cloud "
            "project, else the GitHub Actions badge for the Skylos workflow, "
            "else a static 'Checked with Skylos' badge. No network request is made."
        ),
        allow_abbrev=False,
    )
    parser.add_argument(
        "--plain",
        action="store_true",
        help="Print only the Markdown line, for scripts (no clipboard copy)",
    )
    return parser


def run_badge_command(argv: list[str] | None = None) -> int:
    from skylos.api import BASE_URL

    options, _unused = _badge_parser().parse_known_args(list(argv or []))
    plain = options.plain
    root = _git_root(Path.cwd().resolve())
    badge = choose_badge(root, api_url=BASE_URL)

    if plain:
        print(badge["markdown"])
        return 0

    from rich.markup import escape

    console = Console()
    console.print()
    console.print("[bold cyan]Add this badge to your README.md:[/bold cyan]")
    console.print()
    # Plain print: Rich would wrap the long line, and a wrapped or boxed line
    # doesn't paste back as working Markdown.
    print(badge["markdown"])
    console.print()
    console.print(f"[dim]{escape(badge['note'])}[/dim]")

    from skylos.ui.clipboard import copy_to_clipboard

    status = copy_to_clipboard(badge["markdown"], console)
    if status == "copied":
        console.print("[good]Badge markdown copied to clipboard.[/good]")
    elif status == "missing":
        console.print(
            "[muted]Install pyperclip for auto-copy: pip install pyperclip[/muted]"
        )
    console.print("[dim]Markdown only, for scripts: skylos badge --plain[/dim]")
    return 0
