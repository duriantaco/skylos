"""Compare actual checker diagnostics without implementing a type system."""

from __future__ import annotations

import configparser
import difflib
import hashlib
import math
import os
import re
import subprocess
import tempfile
import time
import unicodedata
from collections import Counter
from pathlib import Path, PurePosixPath

from skylos.core.git_safety import read_only_git_command, read_only_git_environment
from skylos.typecheck.adapters import discover_checker, run_project_checker

_MAX_FILES = 20_000
_MAX_TREE_BYTES = 128 * 1024 * 1024
_MAX_FILE_BYTES = 8 * 1024 * 1024
_MARKERS = (
    "pyproject.toml",
    "mypy.ini",
    ".mypy.ini",
    "setup.cfg",
    "pyrightconfig.json",
    "pyrefly.toml",
    "tsconfig.json",
    "package.json",
)


def _project_root(path: Path) -> Path:
    path = path.resolve()
    current = path.parent if path.is_file() else path
    for candidate in (current, *current.parents):
        if any((candidate / name).is_file() for name in _MARKERS):
            return candidate
        if (candidate / ".git").exists():
            return candidate
    return current


def _git(
    root: Path, args: list[str], *, input_bytes=None, output=None, timeout_seconds=60
):
    result = subprocess.run(
        read_only_git_command(args),
        cwd=root,
        env=read_only_git_environment(),
        input=input_bytes,
        stdout=output if output is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=max(0.01, min(60, timeout_seconds)),
        check=False,
    )
    if result.returncode:
        raise ValueError("The baseline Git objects could not be read")
    return result.stdout


def _snapshot(comparison, destination: Path, *, timeout_seconds=120) -> None:
    """Materialize blobs without checkout, hooks, filters or index writes.

    Unlike git archive, this preserves files marked export-ignore. All paths,
    object sizes and modes are checked before the batch of blobs is requested.
    Symlinks and submodules require a richer environment than this comparison.
    """
    deadline = time.monotonic() + timeout_seconds
    with tempfile.TemporaryFile() as inventory:
        _git(
            comparison.root,
            ["ls-tree", "-rlz", "--full-tree", comparison.base_sha],
            output=inventory,
            timeout_seconds=deadline - time.monotonic(),
        )
        if inventory.tell() > 8 * 1024 * 1024:
            raise ValueError("Baseline file inventory exceeds its limit")
        inventory.seek(0)
        entries = []
        total = 0
        for record in inventory.read().split(b"\0"):
            if not record:
                continue
            header, raw_path = record.split(b"\t", 1)
            mode, kind, oid, raw_size = header.split()
            relative = PurePosixPath(raw_path.decode("utf-8", "strict"))
            if relative.is_absolute() or any(
                part.casefold() in {"..", ".git"} or "\\" in part or ":" in part
                for part in relative.parts
            ):
                raise ValueError("Baseline contains an unsafe file path")
            if kind != b"blob" or mode not in {b"100644", b"100755"}:
                raise ValueError(
                    "Baseline contains a symlink or submodule; comparison is unavailable"
                )
            size = int(raw_size)
            total += size
            if (
                size > _MAX_FILE_BYTES
                or total > _MAX_TREE_BYTES
                or len(entries) >= _MAX_FILES
            ):
                raise ValueError("Baseline source snapshot exceeds its limit")
            entries.append((oid, relative, size, mode))
    with tempfile.TemporaryFile() as objects:
        _git(
            comparison.root,
            ["cat-file", "--batch"],
            input_bytes=b"".join(oid + b"\n" for oid, _, _, _ in entries),
            output=objects,
            timeout_seconds=deadline - time.monotonic(),
        )
        if objects.tell() > total + len(entries) * 100:
            raise ValueError("Baseline object output exceeds its limit")
        objects.seek(0)
        for oid, relative, size, mode in entries:
            if time.monotonic() >= deadline:
                raise ValueError(
                    "Type-check baseline snapshot exceeded its time budget"
                )
            header = objects.readline().split()
            if header != [oid, b"blob", str(size).encode()]:
                raise ValueError("Baseline object identity changed")
            data = objects.read(size)
            if len(data) != size or objects.read(1) != b"\n":
                raise ValueError("Baseline object is truncated")
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                raise ValueError("Baseline file paths collide on this filesystem")
            target.write_bytes(data)
            target.chmod(0o755 if mode == b"100755" else 0o644)


def _config_problem(plan: dict, comparison, root: Path) -> str | None:
    from skylos.done.preexisting import environment_blocker

    if plan.get("comparison_supported") is False:
        return (
            plan.get("comparison_reason")
            or "Checker configuration inheritance cannot be compared"
        )
    blocker = environment_blocker(comparison)
    if blocker:
        return blocker
    for variable in ("PYTHONPATH", "MYPYPATH", "NODE_PATH"):
        if os.environ.get(variable):
            return f"Baseline source isolation is unavailable with {variable} set"
    prefix = root.relative_to(comparison.root)
    for name, expected in plan.get("config_fingerprints", {}).items():
        source = comparison.base_text((prefix / name).as_posix())
        if source is None or hashlib.sha256(source.encode()).hexdigest() != expected:
            return f"Checker configuration differs from the baseline: {name}"
        if str(comparison.root) in source:
            return f"Checker configuration refers to the live working tree: {name}"
        if _has_external_source_paths(name, source, plan.get("checker")):
            return f"Checker configuration has absolute or environment-dependent paths that cannot be isolated: {name}"
    # Added/removed configs must not silently change discovery or precedence.
    for name in _MARKERS:
        if name == "package.json":
            continue
        relative = (prefix / name).as_posix()
        was_present = comparison.base_text(relative) is not None
        if was_present != (root / name).is_file():
            return f"Checker configuration availability differs: {name}"
    return None


def _has_external_source_paths(name: str, source: str, checker: str) -> bool:
    """Absolute paths (including aliases) cannot be rebound by a source snapshot.

    Inspect decoded checker settings, rather than searching raw JSON or unrelated
    pyproject metadata. Relative paths and compiler-owned config-directory
    substitutions retain the snapshot's source context.
    """
    from skylos.typecheck.adapters import _json_config, _toml

    if checker == "pyrefly" and name.endswith(".json"):
        # Pyrefly's suppression baseline is opaque data, fingerprinted above;
        # its schema is validated by the real checker rather than interpreted.
        return False
    if name.endswith(".json"):
        settings = _json_config(source)
    elif name.endswith(".toml"):
        settings = _toml(source)
        if name == "pyproject.toml":
            settings = settings.get("tool", {}).get(checker, {})
    elif name in {"mypy.ini", ".mypy.ini", "setup.cfg"}:
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        parser.read_string(source)
        settings = {
            section: dict(parser[section])
            for section in parser.sections()
            if section == "mypy" or section.startswith("mypy-")
        }
    else:
        return False

    def unsafe(value):
        if isinstance(value, dict):
            return any(unsafe(v) for v in value.values())
        if isinstance(value, list):
            return any(unsafe(v) for v in value)
        if not isinstance(value, str):
            return False
        # mypy accepts comma-separated and platform-separated path lists.
        # Reject absolute paths even if they resolve through a symlink alias.
        if re.search(r"(?:^|[\s,;=:])(?:/|[A-Za-z]:[\\/]|~[/\\])", value):
            return True
        for variable in re.findall(r"\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))", value):
            if (variable[0] or variable[1]) != "MYPY_CONFIG_FILE_DIR":
                return True
        return False

    return unsafe(settings)


def _source_inventory(root: Path) -> dict:
    """Detect ordinary concurrent source edits while the compiler runs."""
    ignored = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".skylos",
        ".mypy_cache",
        ".pytest_cache",
        ".pyright",
    }
    suffixes = {
        ".py",
        ".pyi",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".json",
        ".toml",
        ".ini",
        ".cfg",
    }
    inventory = {}
    visited = 0
    for directory, folders, files in os.walk(root, followlinks=False):
        folders[:] = [
            name
            for name in folders
            if name not in ignored and not (Path(directory) / name).is_symlink()
        ]
        for name in files:
            visited += 1
            if visited > 100_000:
                raise ValueError("Source inventory exceeds its limit")
            path = Path(directory) / name
            if path.suffix not in suffixes or path.is_symlink():
                continue
            stat = path.stat()
            inventory[path.relative_to(root).as_posix()] = (
                stat.st_dev,
                stat.st_ino,
                stat.st_size,
                stat.st_mtime_ns,
                stat.st_ctime_ns,
            )
    return inventory


def _identity(diagnostic: dict) -> tuple:
    return tuple(diagnostic.get(key) for key in ("file", "code", "message", "severity"))


def _attribute(head: list[dict], base: list[dict], comparison, root: Path) -> None:
    prefix = root.relative_to(comparison.root)
    renames = {c.path: c.base_path for c in comparison.changed if c.base_path}
    base_counts = Counter((*_identity(d), d.get("line"), d.get("column")) for d in base)
    identities = Counter(_identity(d) for d in base)
    maps = {}
    for diagnostic in head:
        name = diagnostic["file"]
        if name not in maps:
            relative = (prefix / name).as_posix()
            old_relative = renames.get(relative, relative)
            old = comparison.base_text(old_relative)
            new = comparison.head_text(relative)
            try:
                old_name = Path(old_relative).relative_to(prefix).as_posix()
            except ValueError:
                old_name = name
            line_map = {}
            if old is not None and new is not None:
                before, after = old.splitlines(), new.splitlines()
                old_counts, new_counts = Counter(before), Counter(after)
                for block in difflib.SequenceMatcher(
                    None, before, after, autojunk=False
                ).get_matching_blocks():
                    for offset in range(block.size):
                        a, b = block.a + offset, block.b + offset
                        # A repeated line may have moved to a different function.
                        # Leave that attribution uncertain instead of forgiving it.
                        if old == new or (
                            old_counts[before[a]] == 1 and new_counts[after[b]] == 1
                        ):
                            line_map[b + 1] = a + 1
            maps[name] = (old_name, line_map)
        old_name, line_map = maps[name]
        old_diagnostic = dict(diagnostic, file=old_name)
        identity = _identity(old_diagnostic)
        old_line = line_map.get(diagnostic.get("line"))
        key = (*identity, old_line, diagnostic.get("column"))
        if old_line is not None and base_counts[key]:
            diagnostic["origin"] = "preexisting"
            base_counts[key] -= 1
        elif identities[identity]:
            diagnostic["origin"] = "unclassified"
        else:
            diagnostic["origin"] = "introduced"


def _scope_spelling(root: Path, relative: Path) -> str:
    """Recover directory-entry spelling for aliases on case-insensitive disks."""
    cursor = root
    parts = []
    for part in relative.parts:
        names = os.listdir(cursor)
        if part not in names:
            folded = unicodedata.normalize("NFC", part).casefold()
            candidates = [
                name
                for name in names
                if unicodedata.normalize("NFC", name).casefold() == folded
                and (cursor / part).samefile(cursor / name)
            ]
            if len(candidates) != 1:
                raise ValueError(
                    "Selected source path has ambiguous filesystem spelling"
                )
            part = candidates[0]
        parts.append(part)
        cursor /= part
    return Path(*parts).as_posix()


def _finish(report: dict, target_files, root: Path) -> dict:
    diagnostics = report.setdefault("diagnostics", [])
    selected = None
    scope_problem = None
    if target_files:
        selected = set()
        for value in target_files:
            path = Path(value)
            path = path if path.is_absolute() else root / path
            try:
                resolved = path.resolve()
                relative = resolved.relative_to(root)
                if not resolved.is_file():
                    scope_problem = (
                        "The selected type-check scope must be an existing source file"
                    )
                    break
                selected.add(_scope_spelling(root, relative))
            except (OSError, RuntimeError, ValueError):
                scope_problem = (
                    "The selected type-check file is outside the checker project"
                )
                break
    if scope_problem:
        selected = None
        report.update(
            status="incomplete",
            complete=False,
            reason="invalid_file_scope",
            summary=scope_problem,
        )
    all_errors = [d for d in diagnostics if d.get("severity") == "error"]
    # A real comparison can reveal a new error in an unchanged caller. Retain
    # these explicitly as dependency impact, outside the ordinary file scope.
    comparable = report["comparison"]["status"] == "complete"
    visible = []
    for diagnostic in diagnostics:
        name = diagnostic["file"]
        if selected is not None:
            try:
                name = _scope_spelling(root, Path(name))
            except (OSError, RuntimeError, ValueError):
                pass
        if selected is None or name in selected:
            diagnostic["scope"] = "selected"
            visible.append(diagnostic)
        elif comparable and diagnostic["origin"] in {"introduced", "unclassified"}:
            diagnostic["scope"] = "dependency_impact"
            visible.append(diagnostic)
    report["project_error_count"] = len(all_errors)
    report["out_of_scope_count"] = len(diagnostics) - len(visible)
    report["diagnostics"] = visible
    errors = [d for d in visible if d.get("severity") == "error"]
    report["counts"] = {
        name: sum(d.get("origin") == name for d in errors)
        for name in ("introduced", "preexisting", "unclassified")
    }
    report["error_count"] = len(errors)
    report["warning_count"] = sum(
        d.get("severity") in {"warning", "warn"} for d in visible
    )
    if report.get("complete"):
        blocking = any(d.get("origin") != "preexisting" for d in errors)
        report["status"] = "fail" if blocking else "pass"
        report["summary"] = (
            f"{report.get('checker')}: {len(errors)} error(s); "
            f"{report['counts']['introduced']} introduced, "
            f"{report['counts']['preexisting']} preexisting, "
            f"{report['counts']['unclassified']} without confirmed origin"
        )
    return report


def run_type_check(
    path,
    *,
    checker="auto",
    base_ref=None,
    timeout_seconds=120,
    comparison=None,
    target_files=None,
) -> dict:
    """Run an installed checker; classify origins only against comparable code.

    Without a baseline every current error blocks. A baseline uses Git object
    reads and a temporary source snapshot, never a checkout in the user's repo.
    """
    started = time.monotonic()
    root = _project_root(Path(path))
    if (
        type(timeout_seconds) not in {int, float}
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= 3600
    ):
        return _finish(
            {
                "status": "incomplete",
                "complete": False,
                "checker": checker,
                "summary": "Type-check timeout must be greater than 0 and at most 3600 seconds",
                "reason": "invalid_timeout",
                "diagnostics": [],
                "seconds": 0.0,
                "comparison": {
                    "status": "not_requested",
                    "base": base_ref,
                    "base_run": False,
                },
            },
            target_files,
            root,
        )
    deadline = started + timeout_seconds
    comparison_problem = None
    if comparison is None and base_ref is not None:
        from skylos.done.base import DoneError, open_comparison

        try:
            comparison = open_comparison(root, base_ref)
        except DoneError as exc:
            comparison_problem = str(exc)
    inventory_root = comparison.root if comparison is not None else root
    plan = discover_checker(root, checker)
    inventory_problem = None
    sources_before = None
    if comparison is not None or base_ref is not None:
        try:
            sources_before = _source_inventory(inventory_root)
        except (OSError, ValueError) as exc:
            inventory_problem = str(exc)
    report = run_project_checker(
        root,
        checker=checker,
        timeout_seconds=max(0.01, deadline - time.monotonic()),
    )
    report["comparison"] = {
        "status": "not_requested",
        "base": base_ref,
        "base_run": False,
        "reason": "No baseline requested; current errors have unclassified origin",
    }
    for diagnostic in report.get("diagnostics", []):
        diagnostic["origin"] = "unclassified"
    if comparison_problem:
        report["comparison"].update(status="incomplete", reason=comparison_problem)
    if comparison is not None:
        state = report["comparison"]
        state.update(
            status="incomplete",
            base=comparison.base_sha,
            reason="Baseline comparison has not completed",
        )
        try:
            if inventory_problem:
                raise ValueError(inventory_problem)
            if sources_before != _source_inventory(inventory_root):
                raise ValueError("Project sources changed during type checking")
            current_plan = discover_checker(root, checker)
            if any(
                plan.get(key) != report.get(key)
                or plan.get(key) != current_plan.get(key)
                for key in ("checker", "config_fingerprints", "executable_fingerprint")
            ):
                raise ValueError(
                    "Checker configuration or executable changed during type checking"
                )
            problem = _config_problem(plan, comparison, root)
            if problem:
                raise ValueError(problem)
            if not report.get("complete"):
                raise ValueError("The current project check did not complete")
            if not report.get("diagnostics"):
                state.update(
                    status="complete",
                    reason="No current diagnostics; checker configuration and dependencies match",
                )
            else:
                from skylos.done.preexisting import link_node_modules

                with tempfile.TemporaryDirectory(
                    prefix="skylos-type-baseline-"
                ) as directory:
                    tree = Path(directory) / comparison.root.name
                    tree.mkdir()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError("Type checking exceeded its time budget")
                    _snapshot(comparison, tree, timeout_seconds=remaining)
                    linked = link_node_modules(comparison.root, tree)
                    if linked.workspace_missing:
                        raise ValueError(
                            "Installed workspace dependencies are unavailable in the baseline"
                        )
                    baseline_root = tree / root.relative_to(comparison.root)
                    baseline_plan = discover_checker(
                        baseline_root, report.get("checker")
                    )
                    if baseline_plan.get("config_fingerprints") != plan.get(
                        "config_fingerprints"
                    ):
                        raise ValueError(
                            "Baseline checker configuration could not be reproduced"
                        )
                    state["base_run"] = True
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError("Type checking exceeded its time budget")
                    baseline = run_project_checker(
                        baseline_root,
                        checker=report["checker"],
                        timeout_seconds=remaining,
                        executable_override=report.get("executable"),
                    )
                    if not baseline.get("complete"):
                        raise ValueError(
                            "Baseline checker did not complete: "
                            + baseline.get("summary", "unknown result")
                        )
                    if baseline.get("executable_fingerprint") != report.get(
                        "executable_fingerprint"
                    ):
                        raise ValueError(
                            "The installed checker changed during comparison"
                        )
                    if sources_before != _source_inventory(inventory_root):
                        raise ValueError(
                            "Project sources changed during baseline comparison"
                        )
                    after_plan = discover_checker(root, checker)
                    if any(
                        plan.get(key) != after_plan.get(key)
                        for key in ("config_fingerprints", "executable_fingerprint")
                    ):
                        raise ValueError(
                            "Checker configuration or executable changed during baseline comparison"
                        )
                    _attribute(
                        report["diagnostics"],
                        baseline.get("diagnostics", []),
                        comparison,
                        root,
                    )
                    state.update(
                        status="complete",
                        reason="Compared using the same checker, configuration and installed dependencies",
                    )
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            state.update(status="incomplete", reason=str(exc))
    report["escape_guard"] = {
        "status": "not_assessed" if comparison is not None else "not_requested",
        "added": 0,
    }
    if report.get("complete") and report["comparison"]["status"] == "complete":
        from skylos.typecheck.escapes import new_type_escapes

        try:
            escapes = new_type_escapes(comparison, root=root, checker=report["checker"])
            if sources_before != _source_inventory(inventory_root):
                raise ValueError(
                    "Project sources changed during compiler escape analysis"
                )
            if time.monotonic() > deadline:
                raise ValueError("Type checking exceeded its time budget")
            report["diagnostics"].extend(escapes)
            report["escape_guard"] = {"status": "complete", "added": len(escapes)}
        except (OSError, ValueError, RuntimeError, SyntaxError) as exc:
            report["escape_guard"]["status"] = "incomplete"
            report["comparison"].update(
                status="incomplete",
                reason="Compiler escape analysis incomplete: " + str(exc),
            )
    if report["comparison"]["status"] == "incomplete":
        report.update(
            status="incomplete",
            complete=False,
            reason="comparison_incomplete",
            summary="Type check incomplete: " + report["comparison"]["reason"],
        )
    report["seconds"] = round(time.monotonic() - started, 6)
    return _finish(report, target_files, root)
