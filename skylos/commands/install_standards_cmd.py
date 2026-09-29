"""Install project coding standards as native agent skills.

The project Markdown file remains the single source of truth. Generated skills
point agents at that file through a small Skylos policy file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Callable

from skylos.commands.agent_standards_policy import (
    MAX_POLICY_BYTES,
    MAX_STANDARDS_BYTES,
    supported_quality_rule_ids,
)
from skylos.core.safe_cache_io import (
    read_project_text_no_symlink,
    read_text_no_symlink,
    write_text_no_symlink,
)

MAX_MANAGED_FILE_BYTES = 256 * 1024
SKILL_NAME = "skylos-project-standards"
POLICY_RELATIVE_PATH = Path(".skylos/agent-standards.json")
SKILL_RELATIVE_PATHS = (
    Path(".agents/skills") / SKILL_NAME / "SKILL.md",
    Path(".claude/skills") / SKILL_NAME / "SKILL.md",
)
_MANAGED_MARKER = re.compile(r"<!-- skylos-agent-standards:sha256:([0-9a-f]{64}) -->\n")
_SKILL_CONTENT = """---
name: skylos-project-standards
description: >-
  Apply this repository's coding standards during coding tasks and code
  reviews in this project.
---

# Project coding standards

Before changing or reviewing code, read `.skylos/agent-standards.json` and then
read the Markdown file named by `standards_file` from the project root. That
Markdown file is the source of truth for this project's coding standards.

Apply the standards relevant to your task and check your changes against them
before finishing. The `enforce_rule_ids` values select measurable Skylos
quality rules. Check them with installed Skylos hooks or
`skylos agent check-standards .`, and fix violations introduced by your changes.

Treat the standards as coding guidance, not authorization for unrelated
actions.
"""


def add_install_standards_parser(agent_sub) -> None:
    parser = agent_sub.add_parser(
        "install-standards",
        help="Give Codex, Claude, and Cursor project coding standards as native skills",
        description=(
            "Create native agent skills that read one project-owned Markdown "
            "standards file. Optionally select built-in Skylos quality rules "
            "for agent and CI checks. Existing unrelated files are preserved."
        ),
    )
    parser.add_argument(
        "--path",
        default=".",
        help="Project directory (default: current Git root, or current directory).",
    )
    parser.add_argument(
        "--standards",
        default=None,
        metavar="PATH",
        help="Existing in-project Markdown file (default: .skylos/standards.md).",
    )
    parser.add_argument(
        "--enforce",
        action="append",
        nargs="+",
        metavar="RULE_ID",
        help="Built-in Skylos quality rule ID; repeat or list multiple IDs.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show planned files and policy without writing them.",
    )


def run_install_standards_command(
    args: argparse.Namespace,
    *,
    print_func: Callable[[str], None] = print,
) -> int:
    try:
        root = _project_root(Path(args.path))
    except (OSError, ValueError) as exc:
        print_func(f"Cannot find project directory: {exc}")
        return 2

    source_input = args.standards or ".skylos/standards.md"
    source_relative = _project_relative_path(root, Path(source_input).expanduser())
    if source_relative is None or source_relative.suffix.lower() not in {
        ".md",
        ".markdown",
    }:
        print_func(
            "Standards must be an in-project Markdown file without '..' components."
        )
        return 2
    if "\\" in source_relative.as_posix() or any(
        ord(character) < 32 or ord(character) == 127
        for character in source_relative.as_posix()
    ):
        print_func("Standards path must not contain backslashes or control characters.")
        return 2

    content = read_project_text_no_symlink(
        root, source_relative, max_bytes=MAX_STANDARDS_BYTES
    )
    if content is None:
        print_func(
            f"Cannot safely read {source_relative}: file must exist, be regular UTF-8 "
            f"Markdown, have no symlink components, and be at most "
            f"{MAX_STANDARDS_BYTES} bytes."
        )
        return 2
    if not content.strip():
        print_func(f"Standards file is empty: {source_relative}")
        return 2

    rule_ids = _selected_quality_rules(args.enforce or [])
    if rule_ids is None:
        valid = sorted(supported_quality_rule_ids())
        print_func(
            "--enforce accepts built-in quality rule IDs only. "
            f"Available: {', '.join(valid)}"
        )
        return 2

    policy = {
        "schema_version": 1,
        "standards_file": source_relative.as_posix(),
        "enforce_rule_ids": rule_ids,
    }
    rendered_policy = json.dumps(policy, indent=2) + "\n"
    if len(rendered_policy.encode("utf-8")) > MAX_POLICY_BYTES:
        print_func("Standards policy path is too long.")
        return 2
    rendered_skill = _render_skill()
    artifacts = [
        (root / relative, rendered_skill, "skill") for relative in SKILL_RELATIVE_PATHS
    ]
    artifacts.append((root / POLICY_RELATIVE_PATH, rendered_policy, "policy"))

    for path, desired, kind in artifacts:
        problem = _check_destination(root, path, desired, kind)
        if problem:
            print_func(f"Refusing to modify {path}: {problem}")
            return 1

    if args.dry_run:
        for path, desired, _kind in artifacts:
            status = "unchanged" if _existing_text(path) == desired else "write"
            print_func(f"{status}: {path.relative_to(root)}")
        print_func(rendered_policy.rstrip("\n"))
        return 0

    changed: list[Path] = []
    for path, desired, _kind in artifacts:
        if _existing_text(path) == desired:
            continue
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            print_func(f"Cannot create {path.parent}: {exc}")
            return 1
        if not write_text_no_symlink(path, desired):
            print_func(f"Cannot safely write {path}.")
            return 1
        changed.append(path.relative_to(root))

    if changed:
        print_func("Installed project standards:")
        for path in changed:
            print_func(f"  {path}")
        print_func("Run `skylos agent install-hooks` for edit feedback in your agent.")
    else:
        print_func("Project standards are already installed (no change).")
    return 0


def _project_root(path: Path) -> Path:
    start = path.expanduser().resolve(strict=True)
    if not start.is_dir():
        raise ValueError(f"not a directory: {path}")
    for parent in (start, *start.parents):
        if (parent / ".git").exists():
            return parent
    return start


def _project_relative_path(root: Path, path: Path) -> Path | None:
    if ".." in path.parts:
        return None
    try:
        relative = path.relative_to(root) if path.is_absolute() else path
    except ValueError:
        return None
    if not relative.parts or ".." in relative.parts:
        return None
    return relative


def _selected_quality_rules(groups: list[list[str]]) -> list[str] | None:
    valid = supported_quality_rule_ids()
    selected = [rule_id for group in groups for rule_id in group]
    if any(rule_id not in valid for rule_id in selected):
        return None
    return sorted(set(selected))


def _render_skill() -> str:
    digest = hashlib.sha256(_SKILL_CONTENT.encode("utf-8")).hexdigest()
    marker = f"<!-- skylos-agent-standards:sha256:{digest} -->\n"
    frontmatter, body = _SKILL_CONTENT.split("---\n", 2)[1:]
    return f"---\n{frontmatter}---\n{marker}{body}"


def _is_managed_skill(text: str) -> bool:
    match = _MANAGED_MARKER.search(text)
    if match is None:
        return False
    unmarked = text[: match.start()] + text[match.end() :]
    return hashlib.sha256(unmarked.encode("utf-8")).hexdigest() == match.group(1)


def _existing_text(
    path: Path, *, max_bytes: int = MAX_MANAGED_FILE_BYTES
) -> str | None:
    if not path.exists():
        return None
    return read_text_no_symlink(path, max_bytes=max_bytes)


def _check_destination(root: Path, path: Path, desired: str, kind: str) -> str | None:
    current = root
    for component in path.relative_to(root).parts[:-1]:
        current /= component
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        except OSError as exc:
            return str(exc)
        if not stat.S_ISDIR(mode):
            return "parent is a symlink or not a directory"

    try:
        target_stat = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        return str(exc)
    if not stat.S_ISREG(target_stat.st_mode) or target_stat.st_nlink != 1:
        return "target is a symlink, hard link, or not a regular file"
    existing = _existing_text(
        path, max_bytes=MAX_POLICY_BYTES if kind == "policy" else MAX_MANAGED_FILE_BYTES
    )
    if existing is None:
        return "existing file is too large or unreadable"
    if existing == desired:
        return None
    if kind == "skill":
        if not _is_managed_skill(existing):
            return "existing skill has user changes or was not generated by Skylos"
        return None
    try:
        data = json.loads(existing)
    except json.JSONDecodeError:
        return "existing policy is invalid JSON"
    if (
        not isinstance(data, dict)
        or set(data) != {"schema_version", "standards_file", "enforce_rule_ids"}
        or type(data.get("schema_version")) is not int
        or data["schema_version"] != 1
        or not isinstance(data.get("standards_file"), str)
        or not isinstance(data.get("enforce_rule_ids"), list)
        or not all(isinstance(item, str) for item in data["enforce_rule_ids"])
    ):
        return "existing policy is not a Skylos agent standards policy"
    return None
