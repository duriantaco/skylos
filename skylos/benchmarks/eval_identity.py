"""Local input identities for deterministic evaluation receipts.

These identify actual checkout bytes, including local edits. They do not cache a
test result or assert that a recorded evaluation passed.
"""

from __future__ import annotations

import gzip
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import stat
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any


_EXCLUDED_PARTS = {
    ".git",
    ".skylos",
    ".agents",
    ".codex",
    ".claude",
    ".aws",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
}
_CREDENTIAL_WORDS = {"KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH"}


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def _excluded(relative: Path) -> bool:
    # Root marketing/editor media does not execute or configure these scanner
    # evals. Fixture assets, including native metadata samples, remain inputs.
    media = relative.parts[:1] == ("assets",) or relative.parts[:3] == (
        "editors",
        "vscode",
        "media",
    )
    return (
        media
        or bool(set(relative.parts) & _EXCLUDED_PARTS)
        or relative.suffix
        in {
            ".pyc",
            ".pyo",
        }
    )


def _checked_path(repo: Path, relative: str) -> Path:
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts or _excluded(rel):
        raise ValueError(f"unsupported evaluation source path: {relative}")
    path = repo / rel
    if not path.resolve(strict=False).is_relative_to(repo):
        raise ValueError(f"source symlink escapes checkout: {relative}")
    for parent in path.parents:
        if parent == repo:
            break
        if parent.is_symlink():
            raise ValueError(f"source directory symlinks are unsupported: {relative}")
    return path


def _walk_error(error: OSError) -> None:
    raise error


def _effective_names(repo: Path) -> set[str]:
    names = {
        name
        for name in _git(
            repo, "ls-files", "--cached", "--others", "--exclude-standard", "-z"
        ).split("\0")
        if name and not _excluded(Path(name))
    }
    package = repo / "skylos"
    if package.is_symlink():
        raise ValueError("source directory symlinks are unsupported: skylos")
    if package.is_dir():
        # Native engines and extensions may be ignored by Git but still execute.
        for current, directories, files in os.walk(package, onerror=_walk_error):
            parent = Path(current)
            kept = []
            for name in directories:
                path = parent / name
                relative = path.relative_to(repo)
                if _excluded(relative):
                    continue
                if path.is_symlink():
                    _checked_path(repo, relative.as_posix())
                    raise ValueError(
                        f"source directory symlinks are unsupported: {relative}"
                    )
                kept.append(name)
            directories[:] = kept
            for name in files:
                relative = (parent / name).relative_to(repo)
                if not _excluded(relative):
                    names.add(relative.as_posix())
    return names


def _gitlinks(repo: Path) -> dict[str, str]:
    links = {}
    for record in _git(repo, "ls-files", "--stage", "-z").split("\0"):
        if not record:
            continue
        metadata, relative = record.split("\t", 1)
        mode, revision, _stage = metadata.split(" ", 2)
        if mode == "160000" and not _excluded(Path(relative)):
            links[relative] = revision
    return links


def _entry(repo: Path, relative: str) -> dict[str, Any]:
    path = _checked_path(repo, relative)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"sha256": None, "mode": None, "missing": True}
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(path)
        if Path(target).is_absolute() or not path.is_file():
            raise ValueError(f"unsupported source symlink: {relative}")
        resolved = path.resolve(strict=True)
        if _excluded(resolved.relative_to(repo)):
            raise ValueError(f"source symlink targets excluded input: {relative}")
        return {"sha256": _file_digest(path), "mode": mode, "symlink": target}
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"source path is not a regular file: {relative}")
    return {"sha256": _file_digest(path), "mode": mode}


def source_identity(repo: Path) -> dict[str, Any]:
    """Hash the effective checkout, preserving dirty and deleted-file identity.

    Local credentials/instructions, generated evaluation output, bytecode and
    root marketing/editor media are excluded. Fixture assets and ignored regular
    files inside ``skylos/`` remain inputs. Unsupported
    paths fail closed instead of creating a partial identity.
    """
    repo = Path(repo).resolve(strict=True)
    root = Path(_git(repo, "rev-parse", "--show-toplevel").strip()).resolve()
    if root != repo:
        raise ValueError("evaluation source must be a Git checkout root")
    revision = _git(repo, "rev-parse", "HEAD").strip()
    names = _effective_names(repo)
    links = _gitlinks(repo)
    names.difference_update(links)
    for relative in links:
        path = _checked_path(repo, relative)
        if path.is_symlink():
            raise ValueError(f"source directory symlinks are unsupported: {relative}")
        if path.exists() and not path.is_dir():
            raise ValueError(f"submodule source is not a directory: {relative}")
        if relative == "skylos-demo":
            # The demo application is not an analyzer input. Keep its pinned
            # Git link below without snapshotting its generated example repos.
            continue
        if path.is_dir():
            # Preserve checked-out submodule bytes as well as its pinned Git link.
            for current, directories, children in os.walk(path, onerror=_walk_error):
                parent = Path(current)
                kept = []
                for name in directories:
                    child = parent / name
                    if _excluded(child.relative_to(repo)):
                        continue
                    if child.is_symlink():
                        _checked_path(repo, child.relative_to(repo).as_posix())
                        raise ValueError(
                            f"source directory symlinks are unsupported: {child}"
                        )
                    kept.append(name)
                directories[:] = kept
                names.update(
                    child.relative_to(repo).as_posix()
                    for name in children
                    if not _excluded((child := parent / name).relative_to(repo))
                )
    files: dict[str, dict[str, Any]] = {}
    pending = list(names)
    while pending:
        relative = pending.pop()
        entry = _entry(repo, relative)
        files[relative] = entry
        if "symlink" in entry:
            target = (repo / relative).resolve(strict=True).relative_to(repo).as_posix()
            if target not in names:
                names.add(target)
                pending.append(target)
    for relative, gitlink in links.items():
        files[relative] = {
            "sha256": _digest({"gitlink": gitlink}),
            "mode": 0o160000,
            "gitlink": gitlink,
        }
    files = dict(sorted(files.items()))
    dirty = {
        path
        for path in (
            _git(repo, "diff", "--name-only", "--no-renames", "-z", "HEAD")
            + _git(repo, "ls-files", "--others", "--exclude-standard", "-z")
        ).split("\0")
        if path and not _excluded(Path(path))
    }
    return {
        "revision": revision,
        "snapshot_sha256": _digest(files),
        "files": files,
        "dirty_paths": sorted(dirty),
    }


def write_source_snapshot(
    repo: Path, destination: Path, identity: dict[str, Any]
) -> None:
    """Save inventoried source bytes without Git metadata or private artifacts.

    The destination must be new and outside the source inventory. A failed or
    concurrently changed snapshot is removed rather than retained as evidence.
    """
    repo = Path(repo).resolve(strict=True)
    destination = Path(destination).absolute()
    if destination.exists():
        raise FileExistsError(destination)
    if destination.resolve(strict=False).is_relative_to(repo) and not _excluded(
        destination.resolve(strict=False).relative_to(repo)
    ):
        raise ValueError(
            "source snapshot destination must be outside the source inventory"
        )
    if source_identity(repo) != identity:
        raise ValueError("source changed before snapshot capture")
    destination.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with destination.open("xb") as output:
            created = True
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=output, mtime=0, compresslevel=1
            ) as zipped:
                with tarfile.open(mode="w", fileobj=zipped) as archive:
                    for relative, entry in sorted(identity["files"].items()):
                        if entry.get("missing"):
                            continue
                        path = _checked_path(repo, relative)
                        if "gitlink" not in entry and _entry(repo, relative) != entry:
                            raise ValueError(
                                f"source changed during capture: {relative}"
                            )
                        member = tarfile.TarInfo(relative)
                        member.mode = entry["mode"]
                        if "gitlink" in entry:
                            member.mode = 0o755
                            member.type = tarfile.DIRTYPE
                            archive.addfile(member)
                        elif "symlink" in entry:
                            member.type = tarfile.SYMTYPE
                            member.linkname = entry["symlink"]
                            archive.addfile(member)
                        else:
                            data = path.read_bytes()
                            if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                                raise ValueError(
                                    f"source changed during capture: {relative}"
                                )
                            member.size = len(data)
                            archive.addfile(member, io.BytesIO(data))
        if source_identity(repo) != identity:
            raise ValueError("source changed during snapshot capture")
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


def environment_identity() -> dict[str, Any]:
    """Return runtime/dependency facts and a hash of noncredential Skylos options.

    Configuration values are represented only by a combined digest. API keys and
    similar credentials are omitted entirely from the identity and output.
    """
    executable = Path(sys.executable).resolve(strict=True)
    distributions = sorted(
        {
            (distribution.metadata.get("Name", ""), distribution.version)
            for distribution in importlib.metadata.distributions()
        }
    )
    configuration = {
        name: value
        for name, value in os.environ.items()
        if name.startswith("SKYLOS_")
        and not (set(name.upper().split("_")) & _CREDENTIAL_WORDS)
    }
    facts = {
        "python_executable": str(executable),
        "python_executable_sha256": _file_digest(executable),
        "python_version": sys.version,
        "platform": platform.platform(),
        "distributions": [list(item) for item in distributions],
        "skylos_configuration_sha256": _digest(configuration),
    }
    return {"sha256": _digest(facts), "facts": facts}
