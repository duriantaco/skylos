"""Bounded source comparisons that preserve a renamed control's base path."""

from dataclasses import dataclass
import difflib
import os
from pathlib import Path, PurePosixPath

from skylos.cicd.policy import _base_text
from skylos.config import ConfigError
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.quality.regression import detect_security_regressions


SOURCE_SUFFIXES = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".mts",
    ".cts",
    ".go",
    ".java",
    ".php",
    ".rs",
    ".dart",
}


@dataclass(frozen=True)
class SourceChange:
    path: str
    base_path: str | None
    deleted: bool = False


def _lexical_repository_path(root, path):
    """Resolve a repository alias without following paths inside that repository."""
    root = Path(root).resolve()
    candidate = Path(path).expanduser()
    candidate = Path(os.path.abspath(
        candidate if candidate.is_absolute() else root / candidate
    ))
    if candidate.is_relative_to(root):
        return candidate
    for ancestor in (*reversed(candidate.parents), candidate):
        try:
            if ancestor.resolve() == root:
                return root / candidate.relative_to(ancestor)
        except (OSError, RuntimeError):
            continue
    return candidate


def _valid_path(path):
    candidate = PurePosixPath(path)
    if not path or candidate.is_absolute() or ".." in candidate.parts:
        raise ConfigError("Compared security path must stay inside the repository")
    return path


def _parse_changes(output):
    tokens = iter(output.rstrip("\0").split("\0")) if output else iter(())
    changed = {}
    try:
        for status in tokens:
            kind = status[:1]
            first = _valid_path(next(tokens))
            if kind in {"R", "C"}:
                current = _valid_path(next(tokens))
                old = first if kind == "R" else None
            else:
                current = first
                old = None if kind == "A" else first
            if kind not in {"A", "D", "M", "T", "U", "R", "C"}:
                raise ConfigError("Unknown compared security path status")
            changed[current] = SourceChange(current, old, kind == "D")
    except StopIteration as exc:
        raise ConfigError("Incomplete compared security paths") from exc
    return changed


def changed_sources(context, base):
    result = context.run(
        "diff",
        "--name-status",
        "--no-relative",
        "--no-ext-diff",
        "--no-textconv",
        "-z",
        "--find-renames",
        base,
        "--",
    )
    if result.returncode:
        raise ConfigError("Could not inspect compared security controls")
    return _parse_changes(result.stdout)


def compare_source_controls(context, base, change):
    """Classify at the old path; report at the surviving implementation's path."""
    if change.deleted:
        # Git can mark a tracked child deleted after its directory becomes a
        # symlink. Reject that surviving path before accepting genuine removal.
        current = context.root
        for component in PurePosixPath(_valid_path(change.path)).parts:
            current = current / component
            if current.is_symlink():
                raise ConfigError(
                    "Compared security source must be readable, bounded and symlink-free"
                )
        return []
    if change.base_path is None:
        return []
    before = _base_text(context, base, change.base_path)
    current = read_project_text_no_symlink(
        context.root, change.path, max_bytes=2 * 1024 * 1024
    )
    if before is None or current is None:
        raise ConfigError(
            "Compared security source must be readable, bounded and symlink-free"
        )
    # Build the text comparison ourselves: repository attributes can otherwise
    # label source as binary or hide text through a custom diff driver.
    diff = "".join(
        difflib.unified_diff(
            before.splitlines(True),
            current.splitlines(True),
            fromfile=f"a/{change.base_path}",
            tofile=f"b/{change.path}",
        )
    )
    findings = detect_security_regressions(
        diff,
        str(context.root / change.base_path),
        old_source=before,
        new_source=current,
        project_root=context.root,
    )
    current_path = str(context.root / change.path)
    return [
        {**finding, "file": current_path, "basename": Path(current_path).name}
        for finding in findings
    ]
