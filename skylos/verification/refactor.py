"""Compare Git source snapshots without importing or executing target code."""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tempfile
import tokenize
from typing import Any

from skylos.verification.behavior import compare_python_behavior
from skylos.verification.comparison import is_environment_file as _environment_file

_MAX_FILES = 4096
_MAX_FILE_BYTES = 1024 * 1024
_MAX_SOURCE_BYTES = 16 * 1024 * 1024
_MAX_LIST_BYTES = 8 * 1024 * 1024


def _snapshot_input(name: str) -> bool:
    return name.endswith(".py") or _environment_file(name)


def _git(
    root: Path, *args: str, data: bytes | None = None, limit: int = _MAX_LIST_BYTES
) -> bytes:
    # Ambient Git variables must not redirect the caller's requested repository.
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_NO_LAZY_FETCH"] = "1"
    command = [
        "git",
        "--no-pager",
        "--no-replace-objects",
        "-c",
        "core.fsmonitor=false",
        "-C",
        str(root),
        *args,
    ]
    try:
        # A file bounds memory even when a repository produces excessive output.
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            proc = subprocess.run(
                command,
                input=data,
                stdout=output,
                stderr=errors,
                env=env,
                timeout=30,
                check=False,
            )
            if proc.returncode:
                raise ValueError(
                    f"Cannot read Git snapshot ({args[0]}). Check repository and base ref."
                )
            if output.tell() > limit:
                raise ValueError("Git snapshot exceeds the verification size limit")
            output.seek(0)
            return output.read(limit + 1)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"Cannot read Git snapshot: {type(exc).__name__}") from exc


def _safe_relative(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts


def _selected_file(path: str | Path, file: str | Path | None) -> tuple[Path, str]:
    target = Path(path).expanduser().absolute()
    if target.is_symlink():
        raise ValueError("Verification path must not be a symlink")
    if target.is_dir():
        if file is None:
            raise ValueError("--file is required when verifying a project directory")
        requested = Path(file)
        if requested.is_absolute() or ".." in requested.parts:
            raise ValueError(
                "--file must be a relative path within the selected directory"
            )
        selected = target / requested
        anchor = target
    else:
        if file is not None:
            raise ValueError("--file cannot be combined with a file path target")
        selected = target
        anchor = target.parent
    if not anchor.is_dir():
        raise ValueError("Verification path does not exist")
    root = Path(
        os.fsdecode(_git(anchor, "rev-parse", "--show-toplevel")).removesuffix("\n")
    ).resolve()
    # Resolve the anchor for platform aliases such as /tmp, but check every
    # repository-relative component before allowing resolution of the target.
    ancestor = selected
    while ancestor != ancestor.parent:
        if ancestor.is_symlink() and ancestor.resolve().is_relative_to(root):
            raise ValueError("Verification file or directory must not be a symlink")
        if ancestor.resolve() == root:
            break
        ancestor = ancestor.parent
    if selected.is_symlink():
        raise ValueError("Verification file must not be a symlink")
    resolved = selected.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError("Verification file must be within the Git repository")
    if resolved.suffix != ".py":
        raise ValueError(
            "Behavior preservation currently supports Python .py files only"
        )
    if resolved.exists() and not resolved.is_file():
        raise ValueError("Verification target must be a regular Python file")
    return root, resolved.relative_to(root).as_posix()


def _decode_source(raw: bytes, name: str) -> str:
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        return raw.decode(encoding)
    except (SyntaxError, UnicodeError, LookupError) as exc:
        raise ValueError(f"Cannot decode Python source: {name}") from exc


def _base_sources(
    root: Path, commit: str, *, allow_submodules: bool = False
) -> tuple[dict[str, str], dict[str, str]]:
    listing = _git(root, "ls-tree", "-r", "-l", "-z", commit)
    entries = []
    total = 0
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        metadata, raw_name = entry.split(b"\t", 1)
        name = os.fsdecode(raw_name)
        if metadata.split()[1] == b"commit":
            if allow_submodules:
                continue
            raise ValueError(f"Git submodule dependencies are unsupported: {name}")
        if not _snapshot_input(name):
            continue
        mode, kind, oid, size = metadata.split()
        if (
            not _safe_relative(name)
            or mode not in (b"100644", b"100755")
            or kind != b"blob"
        ):
            raise ValueError(
                f"Unsupported Python source entry in base snapshot: {name}"
            )
        count = int(size)
        total += count
        if (
            count > _MAX_FILE_BYTES
            or total > _MAX_SOURCE_BYTES
            or len(entries) >= _MAX_FILES
        ):
            raise ValueError("Base source snapshot exceeds the verification size limit")
        entries.append((name, oid, count))
    if not entries:
        return {}, {}
    batch = _git(
        root,
        "cat-file",
        "--batch",
        data=b"\n".join(e[1] for e in entries) + b"\n",
        limit=_MAX_SOURCE_BYTES + _MAX_FILES * 128,
    )
    stream = io.BytesIO(batch)
    sources, hashes = {}, {}
    for name, oid, count in entries:
        header = stream.readline().split()
        if header != [oid, b"blob", str(count).encode()]:
            raise ValueError("Invalid Git blob response")
        raw = stream.read(count)
        if len(raw) != count or stream.read(1) != b"\n":
            raise ValueError("Truncated Git blob response")
        if name.endswith(".py"):
            sources[name] = _decode_source(raw, name)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    return sources, hashes


def _current_sources(
    root: Path, selected: str | None = None, *, allow_submodules: bool = False
) -> tuple[dict[str, str], dict[str, str]]:
    index = _git(root, "ls-files", "--stage", "-z")
    if not allow_submodules and any(
        entry.startswith(b"160000 ") for entry in index.split(b"\0")
    ):
        raise ValueError("Git submodule dependencies are unsupported")
    listing = _git(
        root, "ls-files", "--cached", "--others", "--exclude-standard", "-z"
    ).split(b"\0")
    if any(name.endswith(b"/") for name in listing):
        raise ValueError("Untracked nested repository dependencies are unsupported")
    names = {
        os.fsdecode(name)
        for name in listing
        if name and _snapshot_input(os.fsdecode(name))
    }
    # An explicitly selected ignored file is still part of the obligation.
    if selected is not None:
        names.add(selected)
    if len(names) > _MAX_FILES:
        raise ValueError("Working source snapshot exceeds the verification file limit")
    sources, hashes = {}, {}
    total = 0
    for name in sorted(names):
        if not _safe_relative(name):
            raise ValueError("Unsafe path in working source snapshot")
        source = root / name
        for parent in (source, *source.parents):
            if parent == root:
                break
            if parent.is_symlink():
                raise ValueError(f"Symlink source is unsupported: {name}")
        try:
            descriptor = os.open(
                source,
                os.O_RDONLY
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError:
            continue  # Deleted files must be absent from the current snapshot.
        except OSError as exc:
            raise ValueError(f"Cannot read working source: {name}") from exc
        with os.fdopen(descriptor, "rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError(f"Working source is not a regular file: {name}")
            if before.st_size > _MAX_FILE_BYTES:
                raise ValueError(
                    f"Working source exceeds the verification size limit: {name}"
                )
            raw = handle.read(_MAX_FILE_BYTES + 1)
            after = os.fstat(handle.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError(f"Working source changed while being read: {name}")
        total += len(raw)
        if len(raw) > _MAX_FILE_BYTES or total > _MAX_SOURCE_BYTES:
            raise ValueError(
                "Working source snapshot exceeds the verification size limit"
            )
        if name.endswith(".py"):
            sources[name] = _decode_source(raw, name)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    return sources, hashes


def verify_refactor(
    path: str | Path,
    *,
    base: str,
    file: str | Path | None = None,
    symbol: str,
    max_paths: int = 64,
    max_depth: int = 8,
) -> dict[str, Any]:
    """Verify a selected function's explicit preserve-behavior obligation.

    A pass is conditional on the engine's stated model and snapshot assumptions.
    It is not a claim of equivalence for arbitrary Python programs.
    """
    if (
        not isinstance(base, str)
        or not base.strip()
        or len(base) > 1024
        or base.startswith("-")
        or "\0" in base
    ):
        raise ValueError("--base must be a valid Git commit reference")
    if not isinstance(symbol, str) or not symbol.isidentifier():
        raise ValueError("--symbol must name one module-level Python function")
    if type(max_paths) is not int or not 1 <= max_paths <= 1024:
        raise ValueError("max_paths must be between 1 and 1024")
    if type(max_depth) is not int or not 1 <= max_depth <= 64:
        raise ValueError("max_depth must be between 1 and 64")
    root, relative = _selected_file(path, file)
    commit = (
        _git(root, "rev-parse", "--verify", "--end-of-options", f"{base}^{{commit}}")
        .decode()
        .strip()
    )
    before_hashes, after_hashes = {}, {}
    try:
        before, before_hashes = _base_sources(root, commit)
        after, after_hashes = _current_sources(root, relative)
        environment_changes = sorted(
            name
            for name in before_hashes.keys() | after_hashes.keys()
            if _environment_file(name)
            and before_hashes.get(name) != after_hashes.get(name)
        )
        if environment_changes:
            raise ValueError(
                "Dependency or Python environment files changed: "
                + ", ".join(environment_changes)
            )
        comparison = compare_python_behavior(
            before,
            after,
            file=relative,
            symbol=symbol,
            max_paths=max_paths,
            max_depth=max_depth,
        )
    except ValueError as exc:
        comparison = {
            "status": "unknown",
            "model_version": 1,
            "file": relative,
            "symbol": symbol,
            "before_range": None,
            "after_range": None,
            "differences": [],
            "reasons": [str(exc)],
            "assumptions": [],
        }
    comparison["assumptions"] = list(comparison.get("assumptions", [])) + [
        "Snapshots include tracked and unignored Python files; ignored dependencies and the external environment are assumed stable.",
        "The current snapshot identifies the bytes read, not an atomic filesystem transaction.",
    ]
    status = {"equivalent": "pass", "different": "fail", "unknown": "incomplete"}[
        comparison["status"]
    ]
    findings = (
        [
            {
                "check_id": "python_behavior_preservation",
                "file": relative,
                "symbol": symbol,
                **difference,
                "evidence_kind": "modeled_difference",
                "runtime_witness": False,
            }
            for difference in comparison.get("differences", [])
        ]
        if status == "fail"
        else []
    )
    return {
        "schema_version": 1,
        "tool": "verify_behavior",
        "status": status,
        "obligation": "preserve_behavior",
        "target": {"path": str(root), "file": relative, "symbol": symbol},
        "base": {
            "ref": base,
            "commit": commit,
            "source_hashes": {
                name: digest
                for name, digest in before_hashes.items()
                if name.endswith(".py")
            },
            "environment_hashes": {
                name: digest
                for name, digest in before_hashes.items()
                if _environment_file(name)
            },
        },
        "current": {
            "source_hashes": {
                name: digest
                for name, digest in after_hashes.items()
                if name.endswith(".py")
            },
            "environment_hashes": {
                name: digest
                for name, digest in after_hashes.items()
                if _environment_file(name)
            },
        },
        "comparison": comparison,
        "findings": findings,
        "summary": {
            "pass": "Selected function preserves observable behavior within the supported model and stated assumptions.",
            "fail": "A modeled behavior difference violates the requested preservation obligation.",
            "incomplete": "Behavior preservation could not be established; inspect comparison.reasons.",
        }[status],
        "coverage": {
            "state": "incomplete" if status == "incomplete" else "complete",
            "check": "python_behavior_preservation",
            "scope": "selected_function_and_resolved_helpers",
            "max_paths": max_paths,
            "max_depth": max_depth,
            "reasons": comparison.get("reasons", []),
        },
    }
