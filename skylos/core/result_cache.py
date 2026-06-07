from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import skylos
from skylos.core.safe_cache_io import load_project_json_cache, save_project_json_cache

SCHEMA_VERSION = 1
CACHE_KIND_TRACE = "trace"
RUN_CACHE_DIR = Path(".skylos") / "cache" / "runs"
TRACE_CACHE_DIR = RUN_CACHE_DIR / "v1" / "trace"
MAX_CACHE_STAT_ENTRIES = 100_000
MAX_TRACE_PAYLOAD_BYTES = 10_000_000

TRACE_ENV_VARS = (
    "PYTHONPATH",
    "PYTEST_ADDOPTS",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
    "SKYLOS_ADDOPTS",
    "SKYLOS_CUSTOM_RULES",
    "TOX_ENV_NAME",
    "CI",
    "GITHUB_ACTIONS",
)

TRACE_EXCLUDE_PATTERNS = (
    "site-packages",
    "venv",
    ".venv",
    "pytest",
    "_pytest",
)

SOURCE_EXTENSIONS = {
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".mjs",
    ".cjs",
    ".go",
    ".java",
    ".php",
    ".rs",
    ".dart",
    ".kt",
    ".kts",
}

RELEVANT_FILENAMES = {
    ".pre-commit-config.yaml",
    ".pre-commit-config.yml",
    "Cargo.lock",
    "Cargo.toml",
    "Pipfile",
    "Pipfile.lock",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "composer.lock",
    "constraints.txt",
    "go.mod",
    "go.sum",
    "gradle.lockfile",
    "package-lock.json",
    "package.json",
    "pdm.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pom.xml",
    "pubspec.lock",
    "pubspec.yaml",
    "pyproject.toml",
    "pytest.ini",
    "requirements.txt",
    "setup.cfg",
    "setup.py",
    "tox.ini",
    "uv.lock",
    "yarn.lock",
}

RELEVANT_GLOBS = (
    "requirements*.txt",
    "constraints*.txt",
)

SKYLOS_CONFIG_PATHS = {
    ".skylos/config.yaml",
    ".skylos/config.yml",
}

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    "target",
}


def build_trace_cache_key(
    project_root: str | Path,
    scan_paths: str | Path | list[str | Path] | tuple[str | Path, ...],
    *,
    pytest_args: list[str] | tuple[str, ...] | None = None,
    pytest_fixtures: bool = False,
    env: dict[str, str] | None = None,
    return_fingerprint: bool = False,
) -> str | tuple[str, dict[str, Any]]:
    """Build a correctness-first cache key for the pytest call-trace phase."""
    root = _normalize_root(project_root)
    env_map = env if env is not None else os.environ
    normalized_pytest_args = list(pytest_args or ["-q"])

    files = _fingerprinted_files(root)
    fingerprint = {
        "schema_version": SCHEMA_VERSION,
        "cache_kind": CACHE_KIND_TRACE,
        "skylos_version": skylos.__version__,
        "python": _python_fingerprint(),
        "trace_options": {
            "pytest_args": normalized_pytest_args,
            "pytest_fixtures": bool(pytest_fixtures),
            "tracer_exclude_patterns": list(TRACE_EXCLUDE_PATTERNS),
            "sys_executable": sys.executable,
        },
        "scan_paths": _normalize_scan_paths(root, scan_paths),
        "env": _hash_selected_env(env_map),
        "files": files,
    }
    key = _sha256_json(fingerprint)
    if return_fingerprint:
        return key, _fingerprint_summary(fingerprint, key)
    return key


def load_trace_cache(project_root: str | Path, key: str) -> dict[str, Any] | None:
    root = _normalize_root(project_root)
    path = _trace_cache_path(root, key)
    entry = load_project_json_cache(
        root,
        path,
        max_bytes=MAX_TRACE_PAYLOAD_BYTES,
    )
    if not entry:
        return None

    if not isinstance(entry, dict):
        return None
    if entry.get("schema_version") != SCHEMA_VERSION:
        return None
    if entry.get("cache_kind") != CACHE_KIND_TRACE:
        return None
    if entry.get("key") != key:
        return None
    if not isinstance(entry.get("trace"), dict):
        return None
    if not isinstance(entry["trace"].get("calls", []), list):
        return None
    if not isinstance(entry.get("pytest_returncode"), int):
        return None
    return entry


def save_trace_cache(
    project_root: str | Path,
    key: str,
    trace_payload: dict[str, Any],
    *,
    pytest_returncode: int,
    fingerprint_summary: dict[str, Any] | None = None,
) -> Path | None:
    if pytest_returncode != 0 or not _is_valid_trace_payload(trace_payload):
        return None

    root = _normalize_root(project_root)
    path = _trace_cache_path(root, key)
    entry = {
        "schema_version": SCHEMA_VERSION,
        "cache_kind": CACHE_KIND_TRACE,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "key": key,
        "skylos_version": skylos.__version__,
        "python": _python_fingerprint(),
        "fingerprint": fingerprint_summary or {},
        "pytest_returncode": int(pytest_returncode),
        "trace": trace_payload,
    }
    if not save_project_json_cache(root, path, entry):
        return None
    return path


def clear_run_cache(project_root: str | Path) -> bool:
    root = _normalize_root(project_root)
    path = root / RUN_CACHE_DIR
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        return False
    if path.is_symlink():
        return False
    if not path.exists():
        return False
    shutil.rmtree(path)  # skylos: ignore[SKY-D215] guarded project-local cache directory
    return True


def run_cache_stats(project_root: str | Path) -> dict[str, Any]:
    root = _normalize_root(project_root)
    path = root / RUN_CACHE_DIR
    stats = {
        "path": str(path),
        "exists": False,
        "files": 0,
        "directories": 0,
        "symlinks": 0,
        "other_entries": 0,
        "bytes": 0,
        "errors": 0,
        "skipped": 0,
        "truncated": False,
        "max_entries": MAX_CACHE_STAT_ENTRIES,
    }

    try:
        root_resolved = root.resolve(strict=True)
        path.resolve(strict=False).relative_to(root_resolved)
    except (OSError, ValueError):
        stats["error"] = "cache path is outside the project root"
        return stats

    try:
        root_stat = path.lstat()
    except FileNotFoundError:
        return stats
    except OSError as exc:
        stats["errors"] += 1
        stats["error"] = str(exc)
        return stats

    stats["exists"] = True
    if stat.S_ISLNK(root_stat.st_mode):
        stats["symlinks"] += 1
        stats["skipped"] += 1
        stats["error"] = "cache path is a symlink"
        return stats
    if not stat.S_ISDIR(root_stat.st_mode):
        if stat.S_ISREG(root_stat.st_mode):
            stats["files"] += 1
            stats["bytes"] += root_stat.st_size
        else:
            stats["other_entries"] += 1
            stats["skipped"] += 1
        return stats

    seen_entries = 0

    def visit(directory: Path) -> None:
        nonlocal seen_entries
        if stats["truncated"]:
            return

        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if seen_entries >= MAX_CACHE_STAT_ENTRIES:
                        stats["truncated"] = True
                        return
                    seen_entries += 1

                    try:
                        entry_stat = entry.stat(follow_symlinks=False)
                    except OSError:
                        stats["errors"] += 1
                        stats["skipped"] += 1
                        continue

                    mode = entry_stat.st_mode
                    if stat.S_ISLNK(mode):
                        stats["symlinks"] += 1
                        stats["skipped"] += 1
                        continue
                    if stat.S_ISDIR(mode):
                        stats["directories"] += 1
                        visit(Path(entry.path))
                        continue
                    if stat.S_ISREG(mode):
                        stats["files"] += 1
                        stats["bytes"] += entry_stat.st_size
                        continue

                    stats["other_entries"] += 1
                    stats["skipped"] += 1
        except OSError:
            stats["errors"] += 1
            stats["skipped"] += 1

    visit(path)
    return stats


def read_trace_payload(trace_file: str | Path) -> dict[str, Any] | None:
    path = Path(trace_file)
    payload = load_project_json_cache(
        path.parent,
        path,
        max_bytes=MAX_TRACE_PAYLOAD_BYTES,
    )
    if not payload:
        return None
    if not _is_valid_trace_payload(payload):
        return None
    return payload


def write_trace_payload(trace_file: str | Path, trace_payload: dict[str, Any]) -> None:
    if not _is_valid_trace_payload(trace_payload):
        raise ValueError("invalid trace payload")
    _write_json_atomic(Path(trace_file), trace_payload)


def _trace_cache_path(project_root: str | Path, key: str) -> Path:
    return _normalize_root(project_root) / TRACE_CACHE_DIR / f"{key}.json"


def _normalize_root(project_root: str | Path) -> Path:
    root = Path(project_root).resolve()
    if root.is_file():
        root = root.parent
    return root


def _python_fingerprint() -> dict[str, str]:
    return {
        "version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": sys.platform,
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
    }


def _normalize_scan_paths(
    project_root: Path,
    scan_paths: str | Path | list[str | Path] | tuple[str | Path, ...],
) -> list[str]:
    if isinstance(scan_paths, (str, Path)):
        raw_paths = [scan_paths]
    else:
        raw_paths = list(scan_paths)

    normalized = []
    for raw in raw_paths:
        path = Path(raw)
        if not path.is_absolute():
            path = (Path.cwd() / path).resolve()
        else:
            path = path.resolve()
        try:
            normalized.append(path.relative_to(project_root).as_posix() or ".")
        except ValueError:
            normalized.append(str(path))
    return sorted(normalized)


def _hash_selected_env(env: dict[str, str]) -> dict[str, str | None]:
    values: dict[str, str | None] = {}
    for name in TRACE_ENV_VARS:
        if name not in env:
            values[name] = None
            continue
        value = str(env.get(name, ""))
        values[name] = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return values


def _fingerprinted_files(project_root: Path) -> list[dict[str, Any]]:
    files = _git_visible_files(project_root)
    if files is None:
        files = _walk_visible_files(project_root)

    fingerprinted = []
    seen = set()
    for path in files:
        abs_path = path if path.is_absolute() else project_root / path
        try:
            rel = abs_path.relative_to(project_root)
        except ValueError:
            continue
        rel_posix = rel.as_posix()
        if rel_posix in seen:
            continue
        seen.add(rel_posix)
        if _is_excluded_rel(rel) or not _is_relevant_rel(rel):
            continue
        digest = _content_digest(abs_path)
        if digest is None:
            continue
        fingerprinted.append(
            {
                "path": rel_posix,
                "sha256": digest["sha256"],
                "size": digest["size"],
                "kind": digest["kind"],
            }
        )

    fingerprinted.sort(key=lambda item: item["path"])
    return fingerprinted


def _git_visible_files(project_root: Path) -> list[Path] | None:
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=project_root,
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, ValueError):
        return None

    if result.returncode != 0:
        return None

    files = []
    for line in result.stdout.splitlines():
        rel = line.strip()
        if not rel:
            continue
        files.append(project_root / rel)
    return files


def _walk_visible_files(project_root: Path) -> list[Path]:
    files = []
    for dirpath, dirnames, filenames in os.walk(project_root):
        base = Path(dirpath)
        keep_dirs = []
        for dirname in dirnames:
            try:
                rel = (base / dirname).resolve().relative_to(project_root)
            except (OSError, ValueError):
                continue
            if not _is_excluded_rel(rel):
                keep_dirs.append(dirname)
        dirnames[:] = keep_dirs

        for filename in filenames:
            files.append(base / filename)
    return files


def _is_excluded_rel(rel: Path) -> bool:
    parts = rel.parts
    if any(part in EXCLUDED_DIRS for part in parts):
        return True
    if len(parts) >= 2 and parts[0] == ".skylos" and parts[1] == "cache":
        return True
    return False


def _is_relevant_rel(rel: Path) -> bool:
    rel_posix = rel.as_posix()
    if rel_posix in SKYLOS_CONFIG_PATHS:
        return True
    if rel.suffix.lower() in SOURCE_EXTENSIONS:
        return True
    if rel.name in RELEVANT_FILENAMES:
        return True
    return any(fnmatchcase(rel.name, pattern) for pattern in RELEVANT_GLOBS)


def _content_digest(path: Path) -> dict[str, Any] | None:
    try:
        stat = path.lstat()
    except OSError:
        return None

    if path.is_symlink():
        try:
            target = os.readlink(path)
        except OSError:
            return None
        return {
            "sha256": hashlib.sha256(f"symlink:{target}".encode("utf-8")).hexdigest(),
            "size": len(target),
            "kind": "symlink",
        }

    if not path.is_file():
        return None

    h = hashlib.sha256()
    try:
        with (
            path.open("rb") as handle
        ):  # skylos: ignore[SKY-D215] hashing project files for trace cache key
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return None

    return {"sha256": h.hexdigest(), "size": stat.st_size, "kind": "file"}


def _fingerprint_summary(
    fingerprint: dict[str, Any],
    key: str,
) -> dict[str, Any]:
    files = fingerprint.get("files", [])
    return {
        "key": key,
        "file_count": len(files),
        "files_digest": _sha256_json(files),
        "scan_paths": fingerprint.get("scan_paths", []),
        "trace_options": fingerprint.get("trace_options", {}),
        "env": fingerprint.get("env", {}),
    }


def _sha256_json(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _is_valid_trace_payload(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    calls = payload.get("calls")
    if not isinstance(calls, list):
        return False
    return True


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            tmp_name = handle.name
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_name, path)
    finally:
        if tmp_name:
            try:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
            except OSError:
                pass
