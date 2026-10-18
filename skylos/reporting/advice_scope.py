"""Positive source context for human advice views, never for analysis or gates.

An unknown context keeps advice visible. Repository metadata may explain why a
maintainability check concerns sample or copied code; it cannot establish that
the code is safe, unused, or exempt from a configured quality gate.
"""

from __future__ import annotations

import ast
import builtins
import re
import stat
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.core.test_paths import _is_test_parts, _uses_test_framework
from skylos.reporting.finding_types import get_finding_type
from skylos.rules.quality._pytest_collection import is_collected_pytest_file

_MAX_BYTES = 2_000_000
_MAX_METADATA_BYTES = 128_000
_MAX_DEPTH = 64
_SAMPLE_DIRS = frozenset({"example", "examples", "docs_src", "doc_src"})
_BENCHMARK_DIRS = frozenset({"bench", "benchmark", "benchmarks"})
_READMES = ("README", "README.md", "README.rst", "README.txt")
_LICENSES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.txt")
_CONTEXT_MARKERS = (
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "pytest.toml",
    ".pytest.toml",
    "pytest.ini",
    ".pytest.ini",
    "tox.ini",
    "package.json",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "pubspec.yaml",
)
_BUILTIN_NAMES = frozenset(vars(builtins)) | {"__builtins__"}
_COPY_PROVENANCE = re.compile(
    r"\b(?:copied|taken|derived|vendored)\s+from\s+\S+"
    r"|\bvendored\s+(?:copy|version|code|dependency)\b",
    re.IGNORECASE,
)
_WHOLE_TREE_PROVENANCE = re.compile(
    r"\A\s*(?:"
    r"a\s+subset(?:\s+of\s+[\w.+/-]+)?\s+(?:taken|copied|derived)\s+from\s+"
    r"|(?:this|the)\s+(?:directory|package|folder|subtree)\s+is\s+"
    r"(?:a\s+vendored\s+(?:copy|version)\s+of\s+|(?:copied|taken|derived|vendored)\s+from\s+)"
    r"|vendored\s+(?:copy|version)\s+of\s+)",
    re.IGNORECASE,
)
_UPSTREAM = re.compile(
    r"https?://\S+|\b(?:cpython|python\s+\d)|\bcommit\s+(?:hash\s*:)?\s*[0-9a-f]{7,40}\b",
    re.IGNORECASE,
)


def _guarded_file(filename, project_root):
    if not isinstance(filename, (str, Path)) or not filename or project_root is None:
        return None
    try:
        root = Path(project_root).resolve(strict=True)
        path = Path(filename)
        if not path.is_absolute():
            path = root / path
        relative = path.relative_to(root)
        if (
            not relative.parts
            or ".." in relative.parts
            or len(relative.parts) > _MAX_DEPTH
        ):
            return None
        current = root
        for part in relative.parts:
            current /= part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode):
                return None
        if not stat.S_ISREG(info.st_mode):
            return None
        return root, path, relative, info
    except (OSError, RuntimeError, TypeError, ValueError):
        return None


def _context_root(scan_root):
    """Anchor folder conventions to the checkout, even for a package scan.

    A real Git boundary wins over nested project manifests. Source archives
    can use the nearest project/config marker; without one, retain the
    caller's explicit root. Markers are only inspected, never followed or run.
    """
    closest_project = None
    current = scan_root
    for _ in range(_MAX_DEPTH):
        try:
            git = (current / ".git").lstat()
        except FileNotFoundError:
            pass
        except OSError:
            return None
        else:
            if stat.S_ISDIR(git.st_mode) or stat.S_ISREG(git.st_mode):
                return current
            return None
        if closest_project is None:
            for marker in _CONTEXT_MARKERS:
                try:
                    info = (current / marker).lstat()
                except FileNotFoundError:
                    continue
                except OSError:
                    return None
                if stat.S_ISREG(info.st_mode):
                    closest_project = current
                    break
                return None
        if current.parent == current:
            return closest_project or scan_root
        current = current.parent
    return None


@lru_cache(maxsize=128)
def _read(root, path, size, mtime_ns, ctime_ns, inode, limit):
    return read_project_text_no_symlink(root, path, max_bytes=limit, errors="strict")


def _text(root, path, *, limit=_MAX_METADATA_BYTES):
    guarded = _guarded_file(path, root)
    if guarded is None:
        return None
    _, path, _, info = guarded
    if info.st_size > limit:
        return None
    return _read(
        str(root),
        str(path),
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_ino,
        limit,
    )


@lru_cache(maxsize=128)
def _parse(root, path, size, mtime_ns, ctime_ns, inode):
    source = _read(root, path, size, mtime_ns, ctime_ns, inode, _MAX_BYTES)
    if source is None:
        return None
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return None


def _tree(root, path, info):
    if info.st_size > _MAX_BYTES:
        return None
    return _parse(
        str(root),
        str(path),
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_ino,
    )


def _sample_path(parts):
    """Conventional checkout and package sample folders, not arbitrary ancestors."""
    dirs = [part.lower() for part in parts[:-1]]
    candidates = dirs[:1]
    if len(dirs) > 1:
        candidates.append(dirs[1])
    if len(dirs) > 2 and dirs[0] == "src":
        candidates.append(dirs[2])
    if any(part in _SAMPLE_DIRS for part in candidates):
        return "example"
    if any(part in _BENCHMARK_DIRS for part in candidates):
        return "profiling"
    return None


def _declared_vendor(root, path):
    # A root README describes the project itself, not a vendored subtree.
    for directory in list(path.parents)[:8]:
        if directory == root:
            break
        for name in _READMES:
            source = _text(root, directory / name)
            if source is None:
                continue
            if re.search(r"\bnot\s+(?:vendored|copied|taken|derived)\b", source, re.I):
                continue
            paragraph = re.split(r"\n\s*\n", source.strip(), maxsplit=1)[0]
            # A copied-file mention does not describe its first-party
            # siblings. The README must introduce the enclosing tree itself
            # as copied, with its upstream identified in that declaration.
            if not (
                _WHOLE_TREE_PROVENANCE.search(paragraph)
                and _COPY_PROVENANCE.search(paragraph)
                and _UPSTREAM.search(paragraph)
            ):
                continue
            if re.search(
                r"\b(?:only|except|excluding)\b[^\n.]*\.(?:py|pyi|js|ts)\b"
                r"|\bfirst.party\b",
                source,
                re.I,
            ):
                continue
            for license_name in _LICENSES:
                license_text = _text(root, directory / license_name)
                if license_text and re.search(
                    r"\b(?:copyright|permission|licen[cs]e)\b", license_text, re.I
                ):
                    return True
    return False


def _literal_directory(value):
    if not isinstance(value, str) or any(char in value for char in "*?[]\\"):
        return None
    path = Path(value.lstrip("/"))
    if not path.parts or any(part in {".", ".."} for part in path.parts):
        return None
    return path


@lru_cache(maxsize=128)
def _distribution_paths(root, size, mtime_ns, ctime_ns, inode):
    source = _read(
        root,
        str(Path(root) / "pyproject.toml"),
        size,
        mtime_ns,
        ctime_ns,
        inode,
        _MAX_METADATA_BYTES,
    )
    if source is None:
        return None
    try:
        targets = tomllib.loads(source)["tool"]["hatch"]["build"]["targets"]
        excluded = targets["sdist"]["exclude"]
        included = targets["wheel"]["only-include"]
        if (
            not isinstance(excluded, list)
            or not isinstance(included, list)
            or not included
        ):
            return None
        excluded = tuple(_literal_directory(item) for item in excluded)
        included = tuple(_literal_directory(item) for item in included)
        if any(item is None for item in (*excluded, *included)):
            return None
        return excluded, included
    except (KeyError, TypeError, ValueError, RecursionError):
        return None


def _excluded_from_distributions(root, relative):
    guarded = _guarded_file(root / "pyproject.toml", root)
    if guarded is None:
        return False
    info = guarded[-1]
    if info.st_size > _MAX_METADATA_BYTES:
        return False
    paths = _distribution_paths(
        str(root), info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino
    )
    return bool(
        paths
        and any(relative.is_relative_to(part) for part in paths[0])
        and not any(relative.is_relative_to(part) for part in paths[1])
    )


def _data_expression(node, assigned):
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_data_expression(item, assigned) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            key is not None
            and _data_expression(key, assigned)
            and _data_expression(value, assigned)
            for key, value in zip(node.keys, node.values)
        )
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        return isinstance(node.operand, ast.Constant) and isinstance(
            node.operand.value, (int, float, complex)
        )
    if not isinstance(node, ast.Call) or any(
        keyword.arg is None for keyword in node.keywords
    ):
        return False
    function = node.func
    if isinstance(function, ast.Name):
        if function.id not in {"set", "frozenset", "list", "tuple", "dict"}:
            return False
        if function.id in assigned:
            return False
    elif isinstance(function, ast.Attribute):
        # Formatter inputs often wrap their literals in an intentionally
        # unresolved sample constructor, e.g. some.Structure(...).
        while isinstance(function, ast.Attribute):
            function = function.value
        if (
            not isinstance(function, ast.Name)
            or function.id in assigned
            or function.id in _BUILTIN_NAMES
        ):
            return False
    else:
        return False
    return all(_data_expression(item, assigned) for item in node.args) and all(
        _data_expression(keyword.value, assigned) for keyword in node.keywords
    )


def _profile_data(tree):
    if tree is None:
        return False
    body = tree.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
    ):
        if not isinstance(body[0].value.value, str):
            return False
        body = body[1:]
    if not body or any(
        not isinstance(node, ast.Assign)
        or any(not isinstance(target, ast.Name) for target in node.targets)
        for node in body
    ):
        return False
    assigned = {target.id for node in body for target in node.targets}
    return (
        all(_data_expression(node.value, assigned) for node in body)
        and sum(isinstance(node, ast.Constant) for node in ast.walk(tree)) >= 128
        and any(
            isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict))
            for node in ast.walk(tree)
        )
    )


def _file_context(filename, project_root):
    guarded = _guarded_file(filename, project_root)
    if guarded is None:
        return None
    root, path, relative, info = guarded
    context_root = _context_root(root)
    if context_root is None:
        return None
    if context_root != root:
        guarded = _guarded_file(path, context_root)
        if guarded is None:
            return None
        root, path, relative, info = guarded
    if _is_test_parts(relative.parts):
        return "test"
    if is_collected_pytest_file(path, root):
        return "test"
    if path.suffix.lower() in {".py", ".pyi", ".pyw"} and (
        path.name.startswith("test_") or path.stem.endswith("_test")
    ):
        tree = _tree(root, path, info)
        if tree is not None and _uses_test_framework(tree):
            return "test"
    sample = _sample_path(relative.parts)
    if sample is not None:
        return sample
    if _declared_vendor(root, path):
        return "vendored"
    if (
        len(relative.parts) > 1
        and relative.parts[0] == "profiling"
        and path.suffix == ".py"
        and _excluded_from_distributions(root, relative)
        and _profile_data(_tree(root, path, info))
    ):
        return "profiling"
    return None


def _clone_context(finding, project_root):
    # Legacy clone exports include at most four members in their message.
    # Parse only the complete, unambiguous scanner format; a representative
    # file or a truncated preview cannot establish the group's context.
    message = finding.get("message")
    if not isinstance(message, str) or len(message) > 16_000:
        return None
    group = re.fullmatch(
        r"Clone group detected \(type[123], sim=(?:0\.\d+|1(?:\.0+)?), "
        r"members=([2-4])\) examples: ([^\r\n]+)",
        message,
    )
    if group is None:
        return None
    members = group[2].split(", ")
    if len(members) != int(group[1]):
        return None
    contexts = set()
    representative = _guarded_file(
        finding.get("file") or finding.get("file_path"), project_root
    )
    if representative is None:
        return None
    locations = set()
    for index, member in enumerate(members):
        match = re.fullmatch(
            r"([^(),\r\n]+):(\d+)-(\d+) \((?:function|class) ([^()]+)\)", member
        )
        if match is None or not (0 < int(match[2]) <= int(match[3])):
            return None
        guarded = _guarded_file(match[1], project_root)
        if guarded is None:
            return None
        location = (str(guarded[1]), int(match[2]), int(match[3]))
        if location in locations:
            return None
        locations.add(location)
        if index == 0 and (
            guarded[1] != representative[1] or finding.get("line") != int(match[2])
        ):
            return None
        context = _file_context(match[1], project_root)
        if context is None:
            return None
        contexts.add(context)
    return next(iter(contexts)) if len(contexts) == 1 else None


def advice_source_context(finding, project_root=None) -> str | None:
    """Explain a proven local context for a built-in advice finding.

    No root, missing evidence, malformed metadata, and symlinked or escaping
    paths all preserve the advice in the ordinary view. Source and metadata
    reads are bounded and cached by file stat, so edits invalidate evidence.
    """
    if not isinstance(finding, Mapping) or get_finding_type(finding) != "advice":
        return None
    if str(finding.get("rule_id") or finding.get("id")).upper() == "SKY-C401":
        return _clone_context(finding, project_root)
    return _file_context(finding.get("file") or finding.get("file_path"), project_root)
