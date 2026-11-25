from __future__ import annotations

import json
import re
from pathlib import Path

from skylos.core.safe_cache_io import read_text_no_symlink

from .analysis import _esbuild_glob_matches, _node_text

_VITE_DEV_COMMAND = re.compile(r"vite(?:\s+((?:\./)?[\w-]+(?:/[\w.-]+)*|\.))?")
_GLOB_PATTERN = re.compile(r"!?(/|\./)([\w.*-]+(?:/[\w.*-]+)*)")
_VITE_CONFIG_SUFFIXES = (".js", ".ts", ".mjs", ".mts", ".cjs", ".cts")
_VITE_SUBCOMMANDS = {"build", "dev", "optimize", "preview", "serve"}


def is_vite_index(path: Path, scan_root: Path) -> bool:
    """Prove this index is at the root of a package's literal Vite dev command."""
    return path.name == "index.html" and path.parent in _literal_vite_roots(
        path, scan_root
    )


def vite_root_for_script(path: Path, scan_root: Path) -> Path | None:
    """Find a single contained, literal Vite root for this source file."""
    roots = [
        root
        for root in _literal_vite_roots(path, scan_root)
        if path.is_relative_to(root)
        and root.resolve() == root
        and (root / "index.html").is_file()
        and not (root / "index.html").is_symlink()
    ]
    return roots[0] if len(roots) == 1 else None


def _literal_vite_roots(path: Path, scan_root: Path) -> set[Path]:
    for directory in path.parents:
        if not directory.is_relative_to(scan_root):
            break
        manifest = directory / "package.json"
        if not manifest.exists():
            continue
        contents = read_text_no_symlink(manifest, max_bytes=1_000_000, encoding="utf-8")
        try:
            package = json.loads(contents) if contents is not None else None
        except (ValueError, RecursionError):
            return set()
        scripts = package.get("scripts") if isinstance(package, dict) else None
        if not isinstance(scripts, dict):
            return set()
        roots = set()
        for command in scripts.values():
            match = (
                _VITE_DEV_COMMAND.fullmatch(command.strip())
                if isinstance(command, str)
                else None
            )
            if not match:
                continue
            argument = match.group(1)
            if argument in _VITE_SUBCOMMANDS:
                continue
            if argument is None and any(
                (directory / f"vite.config{suffix}").exists()
                for suffix in _VITE_CONFIG_SUFFIXES
            ):
                # A config can relocate the default root. A literal positional
                # root takes priority over that setting.
                continue
            roots.add(directory / (argument or "."))
        return roots
    return set()


def _eager_patterns(call, source: bytes) -> list[tuple[bool, str]]:
    if call is None or call.type != "call_expression":
        return []
    function = call.child_by_field_name("function")
    arguments = call.child_by_field_name("arguments")
    if (
        function is None
        or arguments is None
        or _node_text(source, function) != "import.meta.glob"
    ):
        return []
    args = [child for child in arguments.named_children if child.type != "comment"]
    if len(args) != 2 or args[1].type != "object":
        return []
    options = {}
    for child in args[1].named_children:
        if child.type == "comment":
            continue
        key = child.child_by_field_name("key")
        value = child.child_by_field_name("value")
        if child.type != "pair" or key is None or value is None:
            return []
        option = _node_text(source, key)
        if option in options or option not in {"eager", "import"}:
            return []
        if option == "import" and value.type != "string":
            return []
        options[option] = _node_text(source, value)
    if options.get("eager") != "true":
        return []

    patterns = args[0].named_children if args[0].type == "array" else [args[0]]
    result = []
    for node in patterns:
        if node.type == "comment":
            continue
        if node.type != "string":
            return []
        literal = _node_text(source, node)[1:-1]
        match = _GLOB_PATTERN.fullmatch(literal)
        if match is None:
            return []
        pattern = match.group(2)
        if any(part.startswith(".") for part in pattern.split("/")):
            return []
        # A trailing globstar includes files at every directory depth.
        if pattern.endswith("/**") or pattern == "**":
            pattern += "/*"
        result.append((literal.startswith("!"), pattern))
    return result


def eager_inline_glob_entries(
    source: bytes, parsed, directory: Path, files: set[Path]
) -> set[Path]:
    """Resolve bounded, eager top-level globs in an admitted Vite HTML entry."""
    calls = []
    for statement in parsed.named_children:
        if statement.type == "expression_statement":
            calls.extend(statement.named_children)
        elif statement.type in {"lexical_declaration", "variable_declaration"}:
            calls.extend(
                declaration.child_by_field_name("value")
                for declaration in statement.named_children
                if declaration.type == "variable_declarator"
            )

    entries = set()
    for call in calls:
        patterns = _eager_patterns(call, source)
        if not patterns:
            continue
        select = [pattern for negated, pattern in patterns if not negated]
        exclude = [pattern for negated, pattern in patterns if negated]
        for path in files:
            if not path.is_relative_to(directory):
                continue
            parts = path.relative_to(directory).parts
            if any(part.startswith(".") or part == "node_modules" for part in parts):
                continue
            relative = "/".join(parts)
            if any(
                _esbuild_glob_matches(pattern, relative) for pattern in select
            ) and not any(
                _esbuild_glob_matches(pattern, relative) for pattern in exclude
            ):
                entries.add(path)
    return entries
