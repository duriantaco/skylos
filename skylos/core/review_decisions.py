from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
import subprocess
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from skylos import __version__ as skylos_version
from skylos.core.git_safety import (
    read_only_git_command,
    read_only_git_environment,
)
from skylos.core.review_context import (
    review_context_hash_for_category,
    review_context_is_valid,
)
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.core.safe_cache_io import (
    load_project_json_cache,
    project_cache_lock,
    read_text_no_symlink,
    save_project_json_cache,
    write_text_no_symlink,
)


REVIEW_SCHEMA = "skylos.reviewed-findings"
REVIEW_SCHEMA_VERSION = 2
FINGERPRINT_VERSION = "skylos-finding-v2"
DEFAULT_RULE_REVISION = f"skylos:{skylos_version}"

MAX_BUNDLE_BYTES = 1_000_000
MAX_DECISIONS = 10_000
MAX_STRING_LENGTH = 4_000
MAX_SOURCE_BYTES = 2_000_000
MAX_DEPENDENCY_FILES = 128
MAX_DEPENDENCY_SOURCE_BYTES = 16_000_000
MAX_PYTHON_INDEX_FILES = 20_000
MAX_ENVIRONMENT_FILES = 512
MAX_REPOSITORY_SOURCE_BYTES = 128_000_000
DEFAULT_CLOUD_ORIGIN = "https://skylos.dev"
TRUSTED_CLOUD_CACHE_TTL = timedelta(hours=24)

SUPPRESSING_DISPOSITIONS = frozenset({"false_positive", "risk_accepted"})
KNOWN_DISPOSITIONS = SUPPRESSING_DISPOSITIONS | {"fixed"}

FINDING_SECTIONS: tuple[tuple[str, str, str], ...] = (
    ("danger", "SECURITY", "SKY-D000"),
    ("reliability", "RELIABILITY", "SKY-R000"),
    ("ai_defects", "AI_DEFECT", "SKY-AI000"),
    ("quality", "QUALITY", "SKY-Q000"),
    ("secrets", "SECRET", "SKY-S000"),
    ("custom_rules", "CUSTOM", "CUSTOM"),
    ("unused_functions", "DEAD_CODE", "SKY-U001"),
    ("unused_imports", "DEAD_CODE", "SKY-U002"),
    ("unused_variables", "DEAD_CODE", "SKY-U003"),
    ("unused_classes", "DEAD_CODE", "SKY-U004"),
    ("unused_parameters", "DEAD_CODE", "SKY-U006"),
    ("unused_files", "DEAD_CODE", "SKY-E002"),
    ("unused_fixtures", "DEAD_CODE", "SKY-U000"),
    ("unused_exports", "DEAD_CODE", "SKY-U000"),
    ("forgotten", "DEAD_CODE", "SKY-U001"),
    ("circular_dependencies", "QUALITY", "SKY-CIRC"),
    ("dependency_vulnerabilities", "DEPENDENCY", "SKY-SCA-000"),
)
_DEAD_CODE_SECTIONS = frozenset(
    section
    for section, category, _rule_id in FINDING_SECTIONS
    if category == "DEAD_CODE"
)
_DEAD_CODE_RULE_IDS = frozenset(
    rule_id
    for _section, category, rule_id in FINDING_SECTIONS
    if category == "DEAD_CODE"
)

_SUMMARY_COUNT_KEYS = {
    "danger": "danger_count",
    "reliability": "reliability_count",
    "ai_defects": "ai_defects_count",
    "quality": "quality_count",
    "secrets": "secrets_count",
    "custom_rules": "custom_rules_count",
    "unused_functions": "unused_functions_count",
    "unused_imports": "unused_imports_count",
    "unused_variables": "unused_variables_count",
    "unused_classes": "unused_classes_count",
    "unused_parameters": "unused_parameters_count",
    "unused_files": "unused_files_count",
    "unused_fixtures": "unused_fixtures_count",
    "unused_exports": "unused_exports_count",
    "circular_dependencies": "circular_dependencies_count",
    "dependency_vulnerabilities": "sca_count",
}

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RULE_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,119}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$"
)
_RESERVED_REVIEW_KEYS = frozenset(
    {
        "fingerprint_version",
        "stable_fingerprint",
        "context_hash",
        "rule_revision",
        "review_decision",
        "_skylos_trusted_review",
    }
)
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_IDENTIFIER_TOKEN_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]{0,499}")
_LANGUAGES = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".php": "php",
    ".rs": "rust",
    ".dart": "dart",
    ".cs": "csharp",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ksh": "shell",
    ".bats": "shell",
}

_TS_JS_SOURCE_SUFFIXES = frozenset(
    {".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"}
)
_JS_ENVIRONMENT_FILES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        "bun.lock",
        "bun.lockb",
        "deno.json",
        "deno.jsonc",
        "deno.lock",
    }
)
_POLYGLOT_ENVIRONMENT_FILES = frozenset(
    {
        ".gitmodules",
        ".tool-versions",
        "Dockerfile",
        "go.mod",
        "go.sum",
        "go.work",
        "go.work.sum",
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain",
        "rust-toolchain.toml",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "gradle.properties",
        "composer.json",
        "composer.lock",
        "pubspec.yaml",
        "pubspec.lock",
        "global.json",
        "Directory.Packages.props",
        "packages.lock.json",
        "NuGet.Config",
    }
)

_CI_RUN_KEYS = (
    ("github", "GITHUB_RUN_ID"),
    ("gitlab", "CI_PIPELINE_ID"),
    ("azure", "BUILD_BUILDID"),
    ("circle", "CIRCLE_WORKFLOW_ID"),
    ("jenkins", "BUILD_TAG"),
)


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        # Repository paths can contain undecodable bytes represented by
        # surrogate escapes.  Escaping non-ASCII text keeps canonicalization
        # deterministic without trying to encode those surrogates as UTF-8.
        ensure_ascii=True,
    )


def sha256_value(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _normalize_repository_identity(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or "\x00" in raw:
        return None
    scp_match = re.fullmatch(r"[^/@\s]+@([^:\s]+):(.+)", raw)
    if scp_match:
        host, repo_path = scp_match.groups()
    else:
        from urllib.parse import unquote, urlparse

        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        if parsed.scheme.lower() not in {"http", "https", "ssh", "git"}:
            return None
        if not parsed.hostname or parsed.username and parsed.scheme != "ssh":
            return None
        try:
            port = parsed.port
        except ValueError:
            return None
        default_port = {"http": 80, "https": 443, "ssh": 22, "git": 9418}.get(
            parsed.scheme.lower()
        )
        host = parsed.hostname
        if port and port != default_port:
            host = f"{host}:{port}"
        repo_path = unquote(parsed.path)
    host = host.strip().lower()
    repo_path = repo_path.replace("\\", "/").strip("/")
    if repo_path.lower().endswith(".git"):
        repo_path = repo_path[:-4]
    parts = repo_path.split("/") if repo_path else []
    if not host or not parts or any(part in {"", ".", ".."} for part in parts):
        return None
    if host == "github.com":
        repo_path = repo_path.lower()
    return f"{host}/{repo_path}"


def _identity_project_root(project_root: str | Path) -> Path | None:
    try:
        requested = Path(project_root).expanduser().resolve(strict=True)
        if requested.is_file():
            requested = requested.parent
        from skylos.core.file_discovery import find_git_root

        git_root = find_git_root(requested)
        if git_root is None:
            return None
        requested.relative_to(git_root)
        return git_root
    except (OSError, RuntimeError, ValueError):
        return None


def _review_scope_candidates(
    project_root: str | Path, *, git_root: Path | None = None
) -> list[Path]:
    git_root = git_root or _identity_project_root(project_root)
    if git_root is None:
        return []
    try:
        current = Path(project_root).expanduser().resolve(strict=True)
        if current.is_file():
            current = current.parent
    except OSError:
        return []
    candidates: list[Path] = []
    while True:
        candidates.append(current)
        if current == git_root:
            return candidates
        if current.parent == current:
            return []
        current = current.parent


def _git_remote_identity(git_root: Path) -> str | None:
    try:
        completed = subprocess.run(
            read_only_git_command(["-C", str(git_root), "remote", "get-url", "origin"]),
            capture_output=True,
            check=False,
            env=read_only_git_environment(),
            timeout=5,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    remote = completed.stdout.strip()
    return _normalize_repository_identity(remote)


def _scope_for_project(
    project_root: str | Path,
    git_root: Path,
    repository_identity: str,
) -> dict[str, str] | None:
    try:
        requested = Path(project_root).expanduser().resolve(strict=True)
        if requested.is_file():
            requested = requested.parent
        subpath = requested.relative_to(git_root).as_posix()
    except (OSError, ValueError):
        return None
    return {
        "repository_identity": repository_identity,
        "repo_subpath": "" if subpath == "." else subpath,
    }


def _linked_project_id(identity_root: Path, scan_root: str | Path) -> str | None:
    raw = read_project_text_no_symlink(
        identity_root,
        Path(".skylos") / "link.json",
        max_bytes=200_000,
        encoding="utf-8",
    )
    if raw is None:
        return None
    try:
        link = json.loads(raw)
        requested = Path(scan_root).expanduser().resolve(strict=True)
        if requested.is_file():
            requested = requested.parent
        requested_subpath = requested.relative_to(identity_root).as_posix()
    except (json.JSONDecodeError, OSError, RecursionError, ValueError):
        return None
    if requested_subpath == ".":
        requested_subpath = ""
    if not isinstance(link, dict):
        return None
    projects = link.get("projects")
    matches: list[tuple[int, str]] = []
    if isinstance(projects, dict):
        for raw_subpath, entry in projects.items():
            if not isinstance(raw_subpath, str) or not isinstance(entry, dict):
                continue
            subpath = (
                normalize_repo_path(raw_subpath, identity_root) if raw_subpath else ""
            )
            if subpath is None:
                continue
            if (
                requested_subpath == subpath
                or (subpath and requested_subpath.startswith(f"{subpath}/"))
                or not subpath
            ):
                project_id = _bounded_string(
                    entry.get("project_id") or entry.get("projectId"), maximum=200
                )
                if project_id:
                    matches.append((len(subpath), project_id))
    if matches:
        return max(matches, key=lambda item: item[0])[1]
    return _bounded_string(link.get("project_id") or link.get("projectId"), maximum=200)


def repository_scope(project_root: str | Path) -> dict[str, str] | None:
    git_root = _identity_project_root(project_root)
    if git_root is None:
        return None
    identity = _git_remote_identity(git_root)
    if identity is None:
        return None
    return _scope_for_project(project_root, git_root, identity)


def current_ci_run_identity(environ: dict[str, str] | None = None) -> str | None:
    env = environ if environ is not None else os.environ
    for provider, key in _CI_RUN_KEYS:
        value = str(env.get(key) or "").strip()
        if value:
            identity = f"{provider}:{value[:300]}"
            if provider == "github":
                attempt = str(env.get("GITHUB_RUN_ATTEMPT") or "").strip()
                job = str(env.get("GITHUB_JOB") or "").strip()
                if attempt:
                    identity += f":attempt:{attempt[:40]}"
                if job:
                    identity += f":job:{job[:120]}"
            return identity
    return None


def is_ci_environment(environ: dict[str, str] | None = None) -> bool:
    env = environ if environ is not None else os.environ
    marker = str(env.get("CI") or "").strip().lower()
    return marker in {"1", "true", "yes"} or current_ci_run_identity(env) is not None


def _cloud_service_origin(
    value: str | None = None, environ: dict[str, str] | None = None
) -> str | None:
    from urllib.parse import urlparse

    env = environ if environ is not None else os.environ
    raw = (
        str(value or env.get("SKYLOS_API_URL") or DEFAULT_CLOUD_ORIGIN)
        .strip()
        .rstrip("/")
    )
    parsed = urlparse(raw)
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    host = parsed.hostname.lower()
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    authority = host if port in (None, default_port) else f"{host}:{port}"
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme.lower()}://{authority}{path}"


def _cache_root(value: str | Path | None = None) -> Path:
    if value is not None:
        return Path(value).expanduser()
    return Path.home() / ".skylos" / "reviewed-findings"


def _trusted_cache_path(
    project_root: str | Path, *, cache_root: str | Path | None = None
) -> Path | None:
    scope = repository_scope(project_root)
    if scope is None:
        return None
    return _trusted_cache_path_for_scope(scope, cache_root=cache_root)


def _trusted_cache_path_for_scope(
    scope: dict[str, str], *, cache_root: str | Path | None = None
) -> Path:
    digest = hashlib.sha256(canonical_json(scope).encode("utf-8")).hexdigest()
    return _cache_root(cache_root) / f"{digest}.json"


def _local_cache_root(value: str | Path | None = None) -> Path:
    if value is not None:
        return Path(value).expanduser()
    return Path.home() / ".skylos" / "local-review-decisions"


def _local_repository_scope(project_root: str | Path) -> dict[str, str] | None:
    git_root = _identity_project_root(project_root)
    if git_root is None:
        return None
    remote_scope = repository_scope(git_root)
    if remote_scope is not None:
        return remote_scope
    return {
        "repository_identity": "local:"
        + hashlib.sha256(str(git_root).encode("utf-8")).hexdigest(),
        "repo_subpath": "",
    }


def _local_cache_path(
    project_root: str | Path, *, cache_root: str | Path | None = None
) -> tuple[Path, Path, dict[str, str]] | None:
    scope = _local_repository_scope(project_root)
    if scope is None:
        return None
    return _local_cache_path_for_scope(scope, cache_root=cache_root)


def _local_cache_path_for_scope(
    scope: dict[str, str], *, cache_root: str | Path | None = None
) -> tuple[Path, Path, dict[str, str]]:
    root = _local_cache_root(cache_root)
    digest = hashlib.sha256(canonical_json(scope).encode("utf-8")).hexdigest()
    return root, root / f"{digest}.json", scope


def _ensure_private_cache_root(path: Path) -> bool:
    try:
        path = Path(os.path.abspath(path))
        missing: list[Path] = []
        current = path
        while not current.exists():
            missing.append(current)
            if current.parent == current:
                return False
            current = current.parent
        if current.is_symlink() or not current.is_dir():
            return False
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
        if path.is_symlink() or not path.is_dir():
            return False
        os.chmod(path, 0o700)
        return True
    except OSError:
        return False


def write_trusted_bundle(
    project_root: str | Path,
    bundle: dict[str, Any],
    *,
    cache_root: str | Path | None = None,
    fetched_at: datetime | None = None,
    environ: dict[str, str] | None = None,
    service_origin: str | None = None,
) -> Path | None:
    if not isinstance(bundle, dict):
        return None
    if bundle.get("schema") not in (None, REVIEW_SCHEMA):
        return None
    if bundle.get("version") not in (None, 1, REVIEW_SCHEMA_VERSION):
        return None
    scope = repository_scope(project_root)
    if scope is None:
        return None
    path = _trusted_cache_path_for_scope(scope, cache_root=cache_root)
    if not _ensure_private_cache_root(path.parent):
        return None
    current = _now_utc(fetched_at)
    payload = deepcopy(bundle)
    origin = _cloud_service_origin(service_origin, environ)
    project_id = _bounded_string(payload.get("project_id"), maximum=200)
    if origin is None:
        return None
    if _bundle_decision_records(payload) and project_id is None:
        return None
    payload["_local_trust"] = {
        **scope,
        "project_id": project_id,
        "service_origin": origin,
        "fetched_at": current.isoformat().replace("+00:00", "Z"),
        "ci_run": current_ci_run_identity(environ),
    }
    try:
        serialized = json.dumps(payload, sort_keys=True, indent=2) + "\n"
    except (MemoryError, RecursionError, TypeError, ValueError):
        return None
    if len(serialized.encode("utf-8")) > MAX_BUNDLE_BYTES:
        return None
    if not write_text_no_symlink(path, serialized):
        return None
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def invalidate_trusted_bundle(
    project_root: str | Path, *, cache_root: str | Path | None = None
) -> bool:
    scope = repository_scope(project_root)
    if scope is None:
        return False
    path = _trusted_cache_path_for_scope(scope, cache_root=cache_root)
    try:
        file_stat = path.lstat()
        if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
            return False
        path.unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False


def load_trusted_bundle(
    project_root: str | Path,
    *,
    cache_root: str | Path | None = None,
    environ: dict[str, str] | None = None,
    service_origin: str | None = None,
    expected_project_id: str | None = None,
    now: datetime | None = None,
    _scope: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    env = environ if environ is not None else os.environ
    # Cloud cache files are locally writable and therefore cannot authorize a
    # CI suppression. CI uploads raw findings and lets the authenticated Cloud
    # response make the gate decision.
    if is_ci_environment(env):
        return None
    scope = _scope or repository_scope(project_root)
    if scope is None:
        return None
    path = _trusted_cache_path_for_scope(scope, cache_root=cache_root)
    raw = read_text_no_symlink(path, max_bytes=MAX_BUNDLE_BYTES, encoding="utf-8")
    if raw is None:
        return None
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, MemoryError, RecursionError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    trust = payload.get("_local_trust")
    if not isinstance(trust, dict):
        return None
    if trust.get("repository_identity") != scope["repository_identity"]:
        return None
    if trust.get("repo_subpath") != scope["repo_subpath"]:
        return None
    expected_origin = _cloud_service_origin(service_origin, environ)
    if expected_origin is None or trust.get("service_origin") != expected_origin:
        return None
    project_id = _bounded_string(payload.get("project_id"), maximum=200)
    if trust.get("project_id") != project_id:
        return None
    if expected_project_id is not None and project_id != expected_project_id:
        return None
    if _bundle_decision_records(payload) and project_id is None:
        return None
    fetched_at = _parse_timestamp(trust.get("fetched_at"))
    current = _now_utc(now)
    if (
        fetched_at is None
        or fetched_at > current
        or current - fetched_at >= TRUSTED_CLOUD_CACHE_TTL
    ):
        return None
    payload.pop("_local_trust", None)
    return payload


def _load_local_bundle(
    project_root: str | Path,
    *,
    cache_root: str | Path | None = None,
    environ: dict[str, str] | None = None,
    _scope: dict[str, str] | None = None,
    _identity_root: Path | None = None,
) -> dict[str, Any] | None:
    if is_ci_environment(environ):
        return None
    resolved = (
        _local_cache_path_for_scope(_scope, cache_root=cache_root)
        if _scope is not None
        else _local_cache_path(project_root, cache_root=cache_root)
    )
    if resolved is None:
        return None
    root, path, scope = resolved
    try:
        payload = load_project_json_cache(root, path, max_bytes=MAX_BUNDLE_BYTES)
    except (MemoryError, RecursionError):
        return None
    if not payload:
        return None
    if (
        payload.get("schema") != REVIEW_SCHEMA
        or payload.get("version") != REVIEW_SCHEMA_VERSION
    ):
        return None
    if payload.get("source") != "local_cli":
        return None
    if payload.get("repository_scope") != scope:
        return None
    decisions = payload.get("decisions")
    if not isinstance(decisions, list) or len(decisions) > MAX_DECISIONS:
        return None
    identity_root = _identity_root or _identity_project_root(project_root)
    if identity_root is None or any(
        not _valid_stored_local_record(record, identity_root) for record in decisions
    ):
        return None
    return payload


def list_local_decisions(
    project_root: str | Path,
    *,
    include_revoked: bool = False,
    environ: dict[str, str] | None = None,
    cache_root: str | Path | None = None,
) -> list[dict[str, Any]]:
    if is_ci_environment(environ):
        return []
    resolved = _local_cache_path(project_root, cache_root=cache_root)
    if resolved is None:
        raise ValueError("local review decisions require a Git repository")
    identity_root = _identity_project_root(project_root)
    if identity_root is None:
        raise ValueError("local review decisions require a Git repository")
    _root, path, _scope = resolved
    payload = _load_local_bundle(
        project_root,
        cache_root=cache_root,
        environ=environ,
    )
    if payload is None:
        try:
            if path.exists() or path.is_symlink():
                raise ValueError("local review decision store is invalid or unsafe")
        except OSError as exc:
            raise OSError("could not inspect local review decision store") from exc
        return []
    records = payload["decisions"]
    if include_revoked:
        return [deepcopy(record) for record in records if isinstance(record, dict)]
    return [
        {
            key: deepcopy(value)
            for key, value in record.items()
            if not key.startswith("_")
        }
        for record in active_decisions(payload, identity_root)
    ]


def _validated_local_decision(
    decision: Any,
    project_root: str | Path,
    *,
    now: datetime,
) -> dict[str, Any]:
    if not isinstance(decision, dict):
        raise ValueError("review decision must be an object")
    try:
        decision_size = len(canonical_json(decision).encode("utf-8"))
    except (MemoryError, RecursionError, TypeError, ValueError) as exc:
        raise ValueError("review decision is not valid JSON") from exc
    if decision_size > 20_000:
        raise ValueError("review decision is too large")

    decision_id = _decision_id(decision.get("decision_id"))
    reason = _bounded_string(decision.get("reason"), maximum=2_000)
    disposition = decision.get("disposition")
    created_at = _parse_timestamp(decision.get("created_at"))
    file_path = normalize_repo_path(decision.get("file_path"), project_root)
    line_number = _strict_positive_line(
        decision.get("line_number") or decision.get("line")
    )
    if decision_id is None:
        raise ValueError("review decision requires a decision_id")
    if reason is None:
        raise ValueError("review decision requires a reason")
    if disposition not in SUPPRESSING_DISPOSITIONS:
        raise ValueError("unsupported local review disposition")
    if created_at is None:
        raise ValueError("review decision requires a timezone-aware created_at")
    if file_path is None or line_number is None:
        raise ValueError("review decision has an invalid repository location")
    if _v2_key(decision) is None:
        raise ValueError("review decision requires a complete v2 finding identity")
    if _active_disposition(decision, now) is None:
        raise ValueError("review decision is expired or missing a required expiry")

    normalized: dict[str, Any] = {
        "decision_id": decision_id,
        "fingerprint_version": decision["fingerprint_version"],
        "stable_fingerprint": decision["stable_fingerprint"],
        "context_hash": decision["context_hash"],
        "rule_revision": str(decision["rule_revision"]).strip(),
        "rule_id": str(decision["rule_id"]).strip(),
        "file_path": file_path,
        "line_number": line_number,
        "disposition": disposition,
        "reason": reason,
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
        "source": "local_cli",
    }
    expires_raw = decision.get("expires_at")
    if expires_raw not in (None, ""):
        expires_at = _parse_timestamp(expires_raw)
        if expires_at is None:
            raise ValueError("review decision has an invalid expiry")
        normalized["expires_at"] = expires_at.isoformat().replace("+00:00", "Z")
    for key, maximum in (
        ("language", 40),
        ("symbol", 500),
        ("section", 80),
        ("category", 80),
    ):
        value = _bounded_string(decision.get(key), maximum=maximum)
        if value is not None:
            normalized[key] = value
    return normalized


def _new_local_bundle(scope: dict[str, str]) -> dict[str, Any]:
    return {
        "schema": REVIEW_SCHEMA,
        "version": REVIEW_SCHEMA_VERSION,
        "source": "local_cli",
        "repository_scope": scope,
        "decisions": [],
    }


def record_local_decision(
    project_root: str | Path,
    decision: dict[str, Any],
    *,
    environ: dict[str, str] | None = None,
    cache_root: str | Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    if is_ci_environment(environ):
        raise RuntimeError("local review decisions cannot be created in CI")
    current = _now_utc(now)
    identity_root = _identity_project_root(project_root)
    if identity_root is None:
        raise ValueError("local review decisions require a Git repository")
    normalized = _validated_local_decision(decision, identity_root, now=current)
    resolved = _local_cache_path(project_root, cache_root=cache_root)
    if resolved is None:
        raise ValueError("local review decisions require a Git repository")
    root, path, scope = resolved
    if not _ensure_private_cache_root(root):
        raise OSError("could not create a private local review store")

    lock_path = path.with_suffix(path.suffix + ".lock")
    with project_cache_lock(root, lock_path) as acquired:
        if not acquired:
            raise OSError("local review decision store is busy or unsafe")
        payload = _load_local_bundle(
            project_root,
            cache_root=cache_root,
            environ=environ,
        )
        if payload is None:
            try:
                if path.exists() or path.is_symlink():
                    raise ValueError("local review decision store is invalid or unsafe")
            except OSError as exc:
                raise OSError("could not inspect local review decision store") from exc
            payload = _new_local_bundle(scope)
        records = payload["decisions"]
        if any(
            isinstance(record, dict)
            and (record.get("decision_id") or record.get("id"))
            == normalized["decision_id"]
            for record in records
        ):
            raise ValueError("review decision_id already exists")
        if len(records) >= MAX_DECISIONS:
            raise ValueError("local review decision store is full")

        new_key = _v2_key(normalized)
        revoked_at = current.isoformat().replace("+00:00", "Z")
        for record in records:
            if (
                isinstance(record, dict)
                and record.get("revoked_at") in (None, "")
                and _v2_key(record) == new_key
            ):
                record["revoked_at"] = revoked_at
                record["revoked_reason"] = "superseded by a newer local decision"
        records.append(normalized)
        if not save_project_json_cache(root, path, payload):
            raise OSError("could not save local review decision securely")
    return deepcopy(normalized)


def revoke_local_decision(
    project_root: str | Path,
    decision_id: str,
    *,
    environ: dict[str, str] | None = None,
    cache_root: str | Path | None = None,
    now: datetime | None = None,
) -> bool:
    if is_ci_environment(environ):
        raise RuntimeError("local review decisions cannot be changed in CI")
    normalized_id = _bounded_string(decision_id, maximum=200)
    if normalized_id is None:
        raise ValueError("decision_id is required")
    resolved = _local_cache_path(project_root, cache_root=cache_root)
    if resolved is None:
        raise ValueError("local review decisions require a Git repository")
    root, path, _scope = resolved
    if not _ensure_private_cache_root(root):
        raise OSError("could not access the private local review store")

    lock_path = path.with_suffix(path.suffix + ".lock")
    with project_cache_lock(root, lock_path) as acquired:
        if not acquired:
            raise OSError("local review decision store is busy or unsafe")
        payload = _load_local_bundle(
            project_root,
            cache_root=cache_root,
            environ=environ,
        )
        if payload is None:
            try:
                if path.exists() or path.is_symlink():
                    raise ValueError("local review decision store is invalid or unsafe")
            except OSError as exc:
                raise OSError("could not inspect local review decision store") from exc
            return False
        target = None
        for record in payload["decisions"]:
            if (
                isinstance(record, dict)
                and record.get("decision_id") == normalized_id
                and record.get("revoked_at") in (None, "")
            ):
                target = record
        if target is None:
            return False
        target["revoked_at"] = _now_utc(now).isoformat().replace("+00:00", "Z")
        target["revoked_reason"] = "restored from local CLI"
        if not save_project_json_cache(root, path, payload):
            raise OSError("could not update local review decision securely")
    return True


def normalize_repo_path(
    value: Any,
    project_root: str | Path,
    *,
    allow_absolute: bool = False,
) -> str | None:
    if not isinstance(value, (str, Path)):
        return None
    original = str(value)
    if any(ord(char) < 32 or ord(char) == 127 for char in original):
        return None
    raw = original.strip().replace("\\", "/")
    if not raw or raw.startswith("//") or _DRIVE_RE.match(raw):
        return None

    root = Path(project_root).expanduser()
    try:
        root = root.resolve(strict=True)
    except OSError:
        return None

    candidate = Path(raw).expanduser()
    if candidate.is_absolute():
        if not allow_absolute:
            return None
        try:
            relative = Path(os.path.abspath(candidate)).relative_to(root)
        except (OSError, ValueError):
            return None
    else:
        posix = PurePosixPath(raw)
        if not posix.parts or any(part in {"", ".", ".."} for part in posix.parts):
            return None
        relative = Path(*posix.parts)

    normalized = relative.as_posix()
    if (
        not normalized
        or len(normalized) > 500
        or normalized == "."
        or normalized.startswith("../")
    ):
        return None

    try:
        resolved = (root / relative).resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    return normalized


def _positive_line(value: Any) -> int | None:
    try:
        line = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return line if line > 0 else None


def _strict_positive_line(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 < value <= 9_007_199_254_740_991 else None


def _bounded_string(value: Any, *, maximum: int = MAX_STRING_LENGTH) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or "\x00" in normalized:
        return None
    return normalized


def _decision_id(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 200:
        return None
    if value != value.strip() or any(
        ord(char) < 32 or ord(char) == 127 for char in value
    ):
        return None
    return value


def _valid_stored_local_record(record: Any, project_root: str | Path) -> bool:
    if not isinstance(record, dict) or record.get("source") != "local_cli":
        return False
    allowed_keys = {
        "decision_id",
        "fingerprint_version",
        "stable_fingerprint",
        "context_hash",
        "rule_revision",
        "rule_id",
        "file_path",
        "line_number",
        "disposition",
        "reason",
        "created_at",
        "source",
        "expires_at",
        "language",
        "symbol",
        "section",
        "category",
        "revoked_at",
        "revoked_reason",
        "status",
    }
    if not set(record).issubset(allowed_keys):
        return False
    if _v2_key(record) is None:
        return False
    if _decision_id(record.get("decision_id")) is None:
        return False
    if _strict_positive_line(record.get("line_number")) is None:
        return False
    if normalize_repo_path(record.get("file_path"), project_root) is None:
        return False
    if record.get("disposition") not in SUPPRESSING_DISPOSITIONS or "type" in record:
        return False
    if _bounded_string(record.get("reason"), maximum=2_000) is None:
        return False
    if _parse_timestamp(record.get("created_at")) is None:
        return False
    if (
        record.get("expires_at") is not None
        and _parse_timestamp(record.get("expires_at")) is None
    ):
        return False
    if (
        record.get("disposition") == "risk_accepted"
        and record.get("expires_at") is None
    ):
        return False
    if (
        record.get("revoked_at") is not None
        and _parse_timestamp(record.get("revoked_at")) is None
    ):
        return False
    status = record.get("status")
    return status is None or status == "active"


def _valid_rule_id(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 120:
        return None
    if value != value.strip() or any(
        ord(char) < 32 or ord(char) == 127 for char in value
    ):
        return None
    return value


def _rule_id(finding: dict[str, Any], fallback: str) -> str | None:
    value = (
        finding.get("rule_id")
        or finding.get("rule")
        or finding.get("code")
        or finding.get("id")
        or fallback
    )
    return _valid_rule_id(value)


def _symbol(finding: dict[str, Any]) -> str:
    value = (
        finding.get("qualified_name")
        or finding.get("qualname")
        or finding.get("symbol")
        or finding.get("function")
        or finding.get("name")
        or "<file>"
    )
    return str(value).strip()[:500] or "<file>"


def _language(finding: dict[str, Any], file_path: str) -> str:
    explicit = finding.get("language")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip().lower()[:40]
    return _LANGUAGES.get(Path(file_path).suffix.lower(), "unknown")


def _strip_untrusted_review_fields(result: dict[str, Any]) -> dict[str, Any]:
    sanitized = dict(result)
    sanitized.pop("reviewed_findings", None)
    sanitized.pop("reviewed_findings_summary", None)
    for section, _category, _default_rule_id in FINDING_SECTIONS:
        findings = result.get(section)
        if not isinstance(findings, list):
            continue
        cleaned_items: list[Any] = []
        changed = False
        for item in findings:
            if not isinstance(item, dict):
                cleaned_items.append(item)
                continue
            metadata = item.get("metadata")
            has_reserved_metadata = isinstance(metadata, dict) and any(
                key in metadata for key in _RESERVED_REVIEW_KEYS
            )
            if (
                not any(key in item for key in _RESERVED_REVIEW_KEYS)
                and not has_reserved_metadata
            ):
                cleaned_items.append(item)
                continue
            cleaned = {
                key: value
                for key, value in item.items()
                if key not in _RESERVED_REVIEW_KEYS
            }
            if isinstance(metadata, dict):
                cleaned_metadata = {
                    key: value
                    for key, value in metadata.items()
                    if key not in _RESERVED_REVIEW_KEYS
                }
                if cleaned_metadata:
                    cleaned["metadata"] = cleaned_metadata
                else:
                    cleaned.pop("metadata", None)
            cleaned_items.append(cleaned)
            changed = True
        if changed:
            sanitized[section] = cleaned_items
    return sanitized


def _normalize_source_line(value: str) -> str:
    # Whitespace can change program semantics (Python indentation and string
    # literals in every supported language), so it is part of the identity.
    return value


def _bounded_evidence(value: Any, *, depth: int = 0) -> Any:
    if depth > 6:
        return None
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:2_000]
    if isinstance(value, list):
        return [_bounded_evidence(item, depth=depth + 1) for item in value[:64]]
    if isinstance(value, dict):
        bounded: dict[str, Any] = {}
        for key in sorted(value, key=lambda item: str(item))[:64]:
            safe_key = str(key)[:120]
            bounded[safe_key] = _bounded_evidence(value[key], depth=depth + 1)
        return bounded
    return str(value)[:500]


def _bounded_result_copy(
    value: Any,
    *,
    depth: int = 0,
    ancestors: frozenset[int] = frozenset(),
) -> Any:
    """Copy analyzer output without trusting its nesting depth or acyclicity."""
    if depth > 32:
        return None
    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        return value
    value_id = id(value)
    if value_id in ancestors:
        return None
    nested_ancestors = ancestors | {value_id}
    if isinstance(value, dict):
        return {
            key: _bounded_result_copy(
                item,
                depth=depth + 1,
                ancestors=nested_ancestors,
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _bounded_result_copy(
                item,
                depth=depth + 1,
                ancestors=nested_ancestors,
            )
            for item in value
        ]
    if isinstance(value, tuple):
        return tuple(
            _bounded_result_copy(
                item,
                depth=depth + 1,
                ancestors=nested_ancestors,
            )
            for item in value
        )
    try:
        return deepcopy(value)
    except (MemoryError, RecursionError, TypeError, ValueError):
        return str(value)[:500]


def _security_evidence(finding: dict[str, Any]) -> Any:
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    # These are analyzer proof inputs, not presentation fields.  A decision
    # made for an unverified candidate must not silently carry over after a
    # verifier, data-flow path, or related location changes.
    evidence = {
        "security_evidence": (
            finding.get("security_evidence")
            or finding.get("_security_evidence")
            or finding.get("security_details")
            or metadata.get("security_evidence")
        ),
        "evidence_contract": finding.get("evidence_contract")
        or metadata.get("evidence_contract"),
        "verification": finding.get("verification") or metadata.get("verification"),
        "related_locations": finding.get("related_locations")
        or metadata.get("related_locations"),
        "verdict": finding.get("verdict")
        or finding.get("_review_verdict")
        or finding.get("_llm_verdict")
        or metadata.get("review_verdict"),
        "proof": finding.get("proof")
        or finding.get("_review_safety_proof")
        or metadata.get("review_safety_proof"),
        "proof_kind": finding.get("proof_kind")
        or finding.get("_review_proof_kind")
        or metadata.get("review_proof_kind"),
        "proof_lines": finding.get("proof_lines")
        or finding.get("_review_proof_lines")
        or metadata.get("review_proof_lines"),
    }
    bounded = _bounded_evidence(evidence)
    if isinstance(bounded, dict):
        return {
            key: value for key, value in bounded.items() if value not in (None, [], {})
        }
    return bounded


def _finding_assurance_context(finding: dict[str, Any]) -> dict[str, Any]:
    """Return state that changes how strongly Skylos stands behind a finding."""
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    raw_source = _bounded_string(
        finding.get("_source") or metadata.get("source"), maximum=120
    )
    normalized_source = None
    if raw_source:
        lowered_source = raw_source.lower()
        if lowered_source in {"analyzer", "skylos", "static"}:
            # The native analyzer normally emits no source label. Agent views
            # add ``static`` while flattening the same finding, so treating it
            # as evidence would make one analyzer finding acquire two
            # incompatible review identities.
            normalized_source = None
        else:
            normalized_source = "llm" if "llm" in lowered_source else lowered_source
    confidence = finding.get("confidence", finding.get("_confidence"))
    if isinstance(confidence, str):
        confidence = confidence.strip().lower()[:120]
    return {
        "severity": str(finding.get("severity") or "UNKNOWN").strip().upper(),
        "confidence": _bounded_evidence(confidence),
        "source": normalized_source,
        "model": _bounded_string(
            finding.get("model") or metadata.get("model"), maximum=300
        ),
        "provider": _bounded_string(
            finding.get("provider") or metadata.get("provider"), maximum=120
        ),
        "prompt_revision": _bounded_string(
            finding.get("prompt_revision") or metadata.get("prompt_revision"),
            maximum=200,
        ),
        "evidence_contract": _bounded_evidence(
            finding.get("evidence_contract") or metadata.get("evidence_contract")
        ),
        "verification": _bounded_evidence(
            finding.get("verification") or metadata.get("verification")
        ),
        "verdict": _bounded_string(
            finding.get("verdict")
            or finding.get("_review_verdict")
            or finding.get("_llm_verdict")
            or metadata.get("review_verdict"),
            maximum=120,
        ),
    }


def _tree_sitter_language(language: str, suffix: str):
    from tree_sitter import Language

    if language in {"typescript", "javascript"}:
        import tree_sitter_typescript as grammar

        factory = (
            grammar.language_tsx
            if suffix in {".tsx", ".jsx"}
            else grammar.language_typescript
        )
    elif language == "java":
        import tree_sitter_java as grammar

        factory = grammar.language
    elif language == "go":
        import tree_sitter_go as grammar

        factory = grammar.language
    elif language == "php":
        import tree_sitter_php as grammar

        factory = grammar.language_php
    elif language == "rust":
        import tree_sitter_rust as grammar

        factory = grammar.language
    elif language == "dart":
        import tree_sitter_dart_orchard as grammar

        factory = grammar.language
    else:
        return None
    return Language(factory())


def _semantic_source_hash(source: str, language: str, suffix: str) -> str:
    if language == "python":
        try:
            tree = ast.parse(source, type_comments=True)
            return sha256_value(
                {
                    "parser": "python-ast-v1",
                    "tree": ast.dump(tree, include_attributes=False),
                }
            )
        except Exception:
            return sha256_value({"parser": "raw-v1", "source": source})

    try:
        from tree_sitter import Parser

        grammar = _tree_sitter_language(language, suffix)
        if grammar is None:
            raise ValueError("unsupported semantic parser")
        source_bytes = source.encode("utf-8")
        root = Parser(grammar).parse(source_bytes).root_node
        digest = hashlib.sha256(f"tree-sitter-{language}-v1\0".encode("ascii"))
        stack: list[tuple[Any, bool]] = [(root, False)]
        while stack:
            node, closing = stack.pop()
            if closing:
                digest.update(b")")
                continue
            node_type = node.type.encode("utf-8")
            digest.update(b"(")
            digest.update(len(node_type).to_bytes(4, "big"))
            digest.update(node_type)
            children = [child for child in node.children if not child.is_extra]
            if children:
                stack.append((node, True))
                stack.extend((child, False) for child in reversed(children))
                continue
            token_text = source_bytes[node.start_byte : node.end_byte]
            digest.update(len(token_text).to_bytes(8, "big"))
            digest.update(token_text)
            digest.update(b")")
        return "sha256:" + digest.hexdigest()
    except Exception:
        return sha256_value({"parser": "raw-v1", "source": source})


def _python_import_candidates(
    project_root: Path,
    importer_path: str,
    node: ast.Import | ast.ImportFrom,
    module_index: dict[str, tuple[str, ...]],
) -> list[str] | None:
    importer_parent = Path(importer_path).parent
    modules: list[tuple[Path | None, tuple[str, ...]]] = []
    if isinstance(node, ast.Import):
        modules.extend((None, tuple(alias.name.split("."))) for alias in node.names)
    else:
        module_parts = tuple((node.module or "").split(".")) if node.module else ()
        if node.level:
            base = importer_parent
            for _ in range(max(0, node.level - 1)):
                base = base.parent
            modules.append((base, module_parts))
        elif module_parts:
            modules.append((None, module_parts))
        for alias in node.names:
            if alias.name != "*":
                modules.append(
                    (
                        modules[-1][0] if modules else None,
                        module_parts + tuple(alias.name.split(".")),
                    )
                )

    candidates: list[str] = []
    seen: set[str] = set()
    for relative_base, parts in modules:
        if not parts:
            continue
        if relative_base is None:
            indexed_paths = module_index.get(".".join(parts), ())
            direct_stem = Path(*parts)
            resolved_paths = tuple(
                dict.fromkeys(
                    (
                        *indexed_paths,
                        direct_stem.with_suffix(".py").as_posix(),
                        (direct_stem / "__init__.py").as_posix(),
                    )
                )
            )
        else:
            stem = relative_base.joinpath(*parts)
            resolved_paths = tuple(
                candidate.as_posix()
                for candidate in (stem.with_suffix(".py"), stem / "__init__.py")
            )
        for candidate in resolved_paths:
            normalized = normalize_repo_path(candidate, project_root)
            if normalized is None:
                try:
                    if (project_root / candidate).exists() or (
                        project_root / candidate
                    ).is_symlink():
                        return None
                except OSError:
                    return None
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            try:
                candidate_stat = (project_root / normalized).lstat()
            except FileNotFoundError:
                continue
            except OSError:
                candidates.append(normalized)
                continue
            if stat.S_ISREG(candidate_stat.st_mode) or stat.S_ISLNK(
                candidate_stat.st_mode
            ):
                candidates.append(normalized)
    return candidates


def _python_module_index(project_root: Path) -> dict[str, tuple[str, ...]] | None:
    from collections import defaultdict as _defaultdict

    modules: dict[str, set[str]] = _defaultdict(set)
    file_count = 0
    walk_failed = False

    def onerror(_error: OSError) -> None:
        nonlocal walk_failed
        walk_failed = True

    excluded = {".git", ".hg", ".svn", ".venv", "node_modules", "__pycache__"}
    for current, directories, files in os.walk(
        project_root,
        topdown=True,
        followlinks=False,
        onerror=onerror,
    ):
        safe_directories: list[str] = []
        for name in directories:
            directory = Path(current) / name
            try:
                if directory.is_symlink():
                    walk_failed = True
                    continue
            except OSError:
                walk_failed = True
                continue
            if name in excluded:
                continue
            safe_directories.append(name)
        directories[:] = safe_directories
        for name in files:
            if not name.endswith((".py", ".pyi")):
                continue
            file_count += 1
            if file_count > MAX_PYTHON_INDEX_FILES:
                return None
            absolute = Path(current) / name
            try:
                relative = absolute.relative_to(project_root)
                file_stat = absolute.lstat()
            except (OSError, ValueError):
                walk_failed = True
                continue
            if not stat.S_ISREG(file_stat.st_mode):
                walk_failed = True
                continue
            parts = list(relative.with_suffix("").parts)
            if parts and parts[-1] == "__init__":
                parts.pop()
            if not parts:
                continue
            relative_path = relative.as_posix()
            for start in range(len(parts)):
                modules[".".join(parts[start:])].add(relative_path)
    if walk_failed:
        return None

    package_directories = _python_package_directories(project_root)
    if package_directories is None:
        return None
    for package_name, directory in package_directories.items():
        base = project_root / directory
        try:
            base_stat = base.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return None
        if not stat.S_ISDIR(base_stat.st_mode):
            return None
        for absolute in base.rglob("*"):
            if not absolute.name.endswith((".py", ".pyi")):
                continue
            try:
                file_stat = absolute.lstat()
                relative_to_base = absolute.relative_to(base).with_suffix("")
                relative_to_root = absolute.relative_to(project_root).as_posix()
            except (OSError, ValueError):
                return None
            if not stat.S_ISREG(file_stat.st_mode):
                return None
            parts = list(relative_to_base.parts)
            if parts and parts[-1] == "__init__":
                parts.pop()
            mapped_parts = [*package_name.split("."), *parts]
            if mapped_parts:
                modules[".".join(mapped_parts)].add(relative_to_root)
    return {key: tuple(sorted(paths)) for key, paths in modules.items()}


def _python_package_directories(project_root: Path) -> dict[str, Path] | None:
    """Read static package-name-to-directory mappings without executing setup code."""
    mappings: dict[str, Path] = {}

    def add_mapping(raw_package: Any, raw_directory: Any) -> bool:
        if not isinstance(raw_package, str) or not isinstance(raw_directory, str):
            return False
        package = raw_package.strip()
        directory_text = raw_directory.strip().replace("\\", "/")
        if not package:
            # Default source roots are already represented by suffix indexing.
            return True
        if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", package):
            return False
        directory = PurePosixPath(directory_text)
        if (
            not directory_text
            or directory.is_absolute()
            or any(part in {"", ".", ".."} for part in directory.parts)
        ):
            return False
        mappings[package] = Path(*directory.parts)
        return True

    pyproject = read_project_text_no_symlink(
        project_root,
        "pyproject.toml",
        max_bytes=MAX_SOURCE_BYTES,
        encoding="utf-8",
    )
    if pyproject is not None:
        try:
            import tomllib

            parsed = tomllib.loads(pyproject)
            package_dir = (
                parsed.get("tool", {}).get("setuptools", {}).get("package-dir", {})
            )
        except (MemoryError, RecursionError, TypeError, ValueError):
            return None
        if not isinstance(package_dir, dict):
            return None
        if any(not add_mapping(key, value) for key, value in package_dir.items()):
            return None

    setup_cfg = read_project_text_no_symlink(
        project_root,
        "setup.cfg",
        max_bytes=MAX_SOURCE_BYTES,
        encoding="utf-8",
    )
    if setup_cfg is not None:
        try:
            import configparser

            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(setup_cfg)
            raw = parser.get("options", "package_dir", fallback="")
            for line in raw.splitlines():
                if not line.strip():
                    continue
                if "=" not in line:
                    return None
                package, directory = line.split("=", 1)
                if not add_mapping(package, directory):
                    return None
        except (configparser.Error, MemoryError, RecursionError, ValueError):
            return None

    setup_py = read_project_text_no_symlink(
        project_root,
        "setup.py",
        max_bytes=MAX_SOURCE_BYTES,
        encoding="utf-8",
    )
    if setup_py is not None and re.search(r"\bpackage_dir\s*=", setup_py):
        # setup.py is executable Python; guessing its computed mapping would
        # let a reviewed security finding outlive a dependency change.
        return None
    return mappings


def _python_parent_initializers(
    project_root: Path,
    file_path: str,
) -> list[str] | None:
    parents: list[str] = []
    current = Path(file_path).parent
    while current != Path(".") and current.parts:
        candidate = current / "__init__.py"
        absolute = project_root / candidate
        try:
            candidate_stat = absolute.lstat()
        except FileNotFoundError:
            current = current.parent
            continue
        except OSError:
            return None
        if not stat.S_ISREG(candidate_stat.st_mode):
            return None
        parents.append(candidate.as_posix())
        current = current.parent
    return parents


def _environment_dependency_hash(
    project_root: Path,
    language: str,
    *,
    dependency_cache: dict[str, Any] | None,
) -> str | None:
    """Hash dependency-resolution inputs that can change a security proof."""
    cache_key = f"environment:{language}"
    if dependency_cache is not None and cache_key in dependency_cache:
        return dependency_cache[cache_key]

    try:
        from skylos.verification.comparison import is_environment_file
    except ImportError:
        return None

    records: list[dict[str, str]] = []
    environment: dict[str, str] = {}
    for name in ("SKYLOS_ADDOPTS", "SKYLOS_CUSTOM_RULES"):
        if name not in os.environ:
            continue
        raw_value = str(os.environ.get(name) or "")
        if len(raw_value.encode("utf-8")) > MAX_DEPENDENCY_SOURCE_BYTES:
            if dependency_cache is not None:
                dependency_cache[cache_key] = None
            return None
        environment[name] = (
            "sha256:" + hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
        )

    explicit_config = str(os.environ.get("SKYLOS_CONFIG_FILE") or "").strip()
    if explicit_config:
        candidate = Path(explicit_config).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        try:
            resolved_config = candidate.resolve(strict=True)
        except OSError:
            if dependency_cache is not None:
                dependency_cache[cache_key] = None
            return None
        config_text = read_text_no_symlink(
            resolved_config,
            max_bytes=MAX_SOURCE_BYTES,
            encoding="utf-8",
            errors="surrogateescape",
        )
        if config_text is None:
            if dependency_cache is not None:
                dependency_cache[cache_key] = None
            return None
        config_bytes = config_text.encode("utf-8", "surrogateescape")
        environment["SKYLOS_CONFIG_FILE"] = sha256_value(
            {
                "content": "sha256:" + hashlib.sha256(config_bytes).hexdigest(),
            }
        )
    total_bytes = 0
    matched_files = 0
    walk_failed = False

    def onerror(_error: OSError) -> None:
        nonlocal walk_failed
        walk_failed = True

    excluded = {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "node_modules",
        "__pycache__",
    }
    for current, directories, files in os.walk(
        project_root,
        topdown=True,
        followlinks=False,
        onerror=onerror,
    ):
        directories[:] = [name for name in directories if name not in excluded]
        for name in files:
            try:
                relative = (Path(current) / name).relative_to(project_root)
            except ValueError:
                walk_failed = True
                continue
            relative_path = relative.as_posix()
            relevant = is_environment_file(relative_path) or relative_path in {
                ".skylos/config.yaml",
                ".skylos/config.yml",
            }
            if language in {"javascript", "typescript", "all"}:
                relevant = (
                    relevant
                    or name in _JS_ENVIRONMENT_FILES
                    or (
                        name.startswith(("tsconfig", "jsconfig"))
                        and name.endswith(".json")
                    )
                )
            if language == "all":
                relevant = (
                    relevant
                    or name in _POLYGLOT_ENVIRONMENT_FILES
                    or Path(name).suffix.lower()
                    in {".csproj", ".fsproj", ".vbproj", ".sln", ".props", ".targets"}
                )
            if not relevant:
                continue
            matched_files += 1
            if matched_files > MAX_ENVIRONMENT_FILES:
                walk_failed = True
                break
            try:
                file_stat = (project_root / relative).lstat()
            except OSError:
                walk_failed = True
                continue
            if not stat.S_ISREG(file_stat.st_mode):
                walk_failed = True
                continue
            remaining = MAX_DEPENDENCY_SOURCE_BYTES - total_bytes
            if remaining <= 0:
                walk_failed = True
                break
            content = read_project_text_no_symlink(
                project_root,
                relative_path,
                max_bytes=remaining,
                encoding="utf-8",
                errors="surrogateescape",
            )
            if content is None:
                walk_failed = True
                continue
            raw = content.encode("utf-8", "surrogateescape")
            total_bytes += len(raw)
            records.append(
                {
                    "file_path": relative_path,
                    "content_hash": "sha256:" + hashlib.sha256(raw).hexdigest(),
                }
            )
        if walk_failed:
            break

    if walk_failed:
        if dependency_cache is not None:
            dependency_cache[cache_key] = None
        return None
    digest = sha256_value(
        {
            "scope": f"{language}-environment-v1",
            "environment": environment,
            "files": sorted(records, key=lambda item: item["file_path"]),
        }
    )
    if dependency_cache is not None:
        dependency_cache[cache_key] = digest
    return digest


def _repository_semantic_hash(
    project_root: str | Path,
    *,
    source_cache: dict[str, str | None] | None,
    semantic_cache: dict[str, str] | None,
    dependency_cache: dict[str, Any] | None,
) -> str | None:
    """Bind a high-risk review to inputs the analyzer can actually consume.

    Repository checkouts routinely contain large images, archives, generated
    output, and worktree metadata.  Those files cannot change a Skylos proof,
    so reading them made review identities both slow and needlessly fragile.
    The inventory below follows Skylos' source/config/dependency inputs.  The
    finding's proven dependency closure uses syntax hashes; reverse runtime
    setup uses a fast conservative content hash.
    """
    if dependency_cache is None:
        dependency_cache = {}
    records_cache_key = "repository-input-records-v3"
    try:
        root = Path(project_root).resolve(strict=True)
    except OSError:
        return None

    try:
        from skylos.core.result_cache import _is_relevant_rel
        from skylos.rules.secrets import ALLOWED_FILE_SUFFIXES
    except ImportError:
        return None

    cached_records = (
        dependency_cache.get(records_cache_key)
        if dependency_cache is not None
        else None
    )
    if isinstance(cached_records, list):
        environment_hash = _environment_dependency_hash(
            root,
            "all",
            dependency_cache=dependency_cache,
        )
        if environment_hash is None:
            return None
        overrides = {
            item["file_path"]: semantic_cache[item["file_path"]]
            for item in cached_records
            if semantic_cache is not None and item.get("file_path") in semantic_cache
        }
        digest_cache_key = "repository-input-envelope-v3:" + sha256_value(overrides)
        if dependency_cache is not None and digest_cache_key in dependency_cache:
            return dependency_cache[digest_cache_key]
        effective_records = [
            {
                "file_path": item["file_path"],
                "semantic_hash": overrides.get(
                    item["file_path"], item["semantic_hash"]
                ),
            }
            for item in cached_records
        ]
        digest = sha256_value(
            {
                "scope": "repository-input-envelope-v3",
                "environment_hash": environment_hash,
                "files": effective_records,
            }
        )
        if dependency_cache is not None:
            dependency_cache[digest_cache_key] = digest
        return digest

    records: list[dict[str, str]] = []
    total_bytes = 0
    file_count = 0
    failed = False

    def onerror(_error: OSError) -> None:
        nonlocal failed
        failed = True

    excluded = {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        "node_modules",
        "__pycache__",
        "dist",
        "build",
        "target",
    }

    def is_input(relative: Path) -> bool:
        relative_text = relative.as_posix()
        name = relative.name.lower()
        suffix = relative.suffix.lower()
        return bool(
            _is_relevant_rel(relative)
            or suffix in ALLOWED_FILE_SUFFIXES
            or name == ".env"
            or name.startswith(".env.")
            or relative_text in {".skylos/config.yaml", ".skylos/config.yml"}
        )

    candidates: list[Path] | None = None
    try:
        completed = subprocess.run(
            read_only_git_command(
                [
                    "-C",
                    str(root),
                    "ls-files",
                    "-z",
                    "--cached",
                    "--others",
                    "--exclude-standard",
                    "--",
                    ".",
                ],
                literal_pathspecs=True,
            ),
            capture_output=True,
            check=False,
            env=read_only_git_environment(),
            timeout=10,
        )
        if completed.returncode == 0:
            candidates = [
                root / os.fsdecode(raw) for raw in completed.stdout.split(b"\0") if raw
            ]
    except (OSError, subprocess.SubprocessError, ValueError):
        candidates = None

    if candidates is None:
        candidates = []
        for current, directories, files in os.walk(
            root,
            topdown=True,
            followlinks=False,
            onerror=onerror,
        ):
            safe_directories: list[str] = []
            for name in directories:
                directory = Path(current) / name
                try:
                    if directory.is_symlink():
                        failed = True
                        continue
                except OSError:
                    failed = True
                    continue
                relative_dir = directory.relative_to(root)
                if name in excluded or (
                    len(relative_dir.parts) >= 2
                    and relative_dir.parts[:2] == (".skylos", "cache")
                ):
                    continue
                safe_directories.append(name)
            directories[:] = safe_directories
            candidates.extend(Path(current) / name for name in files)

    seen_paths: set[str] = set()
    for absolute in sorted(candidates, key=lambda item: os.fsencode(str(item))):
        try:
            relative_path = absolute.relative_to(root)
        except ValueError:
            failed = True
            break
        if not is_input(relative_path):
            continue
        relative = relative_path.as_posix()
        if relative in seen_paths:
            continue
        seen_paths.add(relative)
        file_count += 1
        if file_count > MAX_PYTHON_INDEX_FILES:
            failed = True
            break
        try:
            file_stat = absolute.lstat()
        except FileNotFoundError:
            # A tracked deletion changes the analyzer input just as a content
            # edit does.  Retain a marker instead of abandoning every review.
            records.append({"file_path": relative, "semantic_hash": "missing"})
            continue
        except OSError:
            failed = True
            break
        if not stat.S_ISREG(file_stat.st_mode):
            failed = True
            break
        suffix = relative_path.suffix.lower()
        language = _LANGUAGES.get(suffix)
        if (
            language is not None
            and source_cache is not None
            and relative in source_cache
        ):
            source = source_cache[relative]
        else:
            source = read_project_text_no_symlink(
                root,
                relative,
                max_bytes=MAX_SOURCE_BYTES,
                encoding="utf-8",
                errors=None if language is not None else "surrogateescape",
            )
            if language is not None and source_cache is not None:
                source_cache[relative] = source
        if source is None:
            failed = True
            break
        encoded_source = source.encode(
            "utf-8", "strict" if language is not None else "surrogateescape"
        )
        total_bytes += len(encoded_source)
        if total_bytes > MAX_REPOSITORY_SOURCE_BYTES:
            failed = True
            break
        raw_hash = "sha256:" + hashlib.sha256(encoded_source).hexdigest()
        records.append({"file_path": relative, "semantic_hash": raw_hash})

    environment_hash = None
    if not failed:
        environment_hash = _environment_dependency_hash(
            root,
            "all",
            dependency_cache=dependency_cache,
        )
        failed = environment_hash is None
    if failed:
        return None

    records = sorted(records, key=lambda item: item["file_path"])
    if dependency_cache is not None:
        dependency_cache[records_cache_key] = records
    # Re-enter through the cached-record branch so semantic overrides are
    # applied consistently on the first and subsequent findings.
    return _repository_semantic_hash(
        root,
        source_cache=source_cache,
        semantic_cache=semantic_cache,
        dependency_cache=dependency_cache,
    )


def _dead_code_proof_digest(finding: dict[str, Any]) -> str | None:
    proof = finding.get("dead_code_review_proof")
    if not isinstance(proof, dict):
        return None
    if proof.get("schema") != "skylos.dead-code-review-proof-v1":
        return None
    if proof.get("complete") is not True:
        return None
    digest = proof.get("digest")
    return digest if isinstance(digest, str) and _HASH_RE.fullmatch(digest) else None


def _dead_code_leaf(symbol: str) -> str | None:
    leaf = re.split(r"[.:/#]", symbol)[-1]
    return leaf if _IDENTIFIER_TOKEN_RE.fullmatch(leaf) else None


def _prepare_dead_code_symbol_support(
    project_root: str | Path,
    symbols: set[str],
    *,
    source_cache: dict[str, str | None] | None,
    semantic_cache: dict[str, str] | None,
    dependency_cache: dict[str, Any],
) -> bool:
    """Index files mentioning requested symbols in one repository pass."""
    requested = {
        leaf for symbol in symbols if (leaf := _dead_code_leaf(symbol)) is not None
    }
    cache_key = "dead-code-symbol-support-v2"
    cached = dependency_cache.get(cache_key)
    if isinstance(cached, dict) and requested.issubset(cached.get("symbols", set())):
        return cached.get("support") is not None
    if cache_key in dependency_cache:
        # A partially-built or failed index must never be treated as proof.
        dependency_cache[cache_key] = None
        return False
    if not requested:
        dependency_cache[cache_key] = None
        return False
    if (
        _repository_semantic_hash(
            project_root,
            source_cache=source_cache,
            semantic_cache=semantic_cache,
            dependency_cache=dependency_cache,
        )
        is None
    ):
        dependency_cache[cache_key] = None
        return False
    records = dependency_cache.get("repository-input-records-v3")
    if not isinstance(records, list):
        dependency_cache[cache_key] = None
        return False

    support: dict[str, list[dict[str, str]]] = {symbol: [] for symbol in requested}
    records_by_path: dict[str, dict[str, str]] = {}
    for record in records:
        relative = record.get("file_path") if isinstance(record, dict) else None
        if not isinstance(relative, str):
            dependency_cache[cache_key] = None
            return False
        records_by_path[relative] = record
        suffix = Path(relative).suffix.lower()
        language = _LANGUAGES.get(suffix)
        source = source_cache.get(relative) if source_cache is not None else None
        if source is None:
            source = read_project_text_no_symlink(
                project_root,
                relative,
                max_bytes=MAX_SOURCE_BYTES,
                encoding="utf-8",
                errors=None if language is not None else "surrogateescape",
            )
            if source_cache is not None and language is not None:
                source_cache[relative] = source
        if source is None:
            dependency_cache[cache_key] = None
            return False
        matches = {
            match.group(0)
            for match in _IDENTIFIER_TOKEN_RE.finditer(source)
            if match.group(0) in requested
        }
        if not matches:
            continue
        if language is None:
            semantic_hash = str(record.get("semantic_hash") or "")
            if not _HASH_RE.fullmatch(semantic_hash):
                dependency_cache[cache_key] = None
                return False
        elif semantic_cache is not None and relative in semantic_cache:
            semantic_hash = semantic_cache[relative]
        else:
            semantic_hash = _semantic_source_hash(source, language, suffix)
            if semantic_cache is not None:
                semantic_cache[relative] = semantic_hash
        support_record = {"file_path": relative, "semantic_hash": semantic_hash}
        for match in matches:
            support[match].append(support_record)

    environment_hash = _environment_dependency_hash(
        Path(project_root),
        "all",
        dependency_cache=dependency_cache,
    )
    if environment_hash is None:
        dependency_cache[cache_key] = None
        return False
    dependency_cache[cache_key] = {
        "symbols": requested,
        "support": support,
        "records_by_path": records_by_path,
        "environment_hash": environment_hash,
    }
    return True


def _dead_code_symbol_context_hash(
    project_root: str | Path,
    file_path: str,
    symbol: str,
    *,
    source_cache: dict[str, str | None] | None,
    semantic_cache: dict[str, str] | None,
    dependency_cache: dict[str, Any] | None,
) -> str | None:
    """Hash source files that can carry external evidence for one symbol."""
    if dependency_cache is None:
        dependency_cache = {}
    leaf = _dead_code_leaf(symbol)
    if leaf is None or not _prepare_dead_code_symbol_support(
        project_root,
        {leaf},
        source_cache=source_cache,
        semantic_cache=semantic_cache,
        dependency_cache=dependency_cache,
    ):
        return None
    index = dependency_cache.get("dead-code-symbol-support-v2")
    if not isinstance(index, dict):
        return None
    indexed_support = index.get("support")
    records_by_path = index.get("records_by_path")
    environment_hash = index.get("environment_hash")
    if (
        not isinstance(indexed_support, dict)
        or not isinstance(records_by_path, dict)
        or not isinstance(environment_hash, str)
        or not _HASH_RE.fullmatch(environment_hash)
    ):
        return None
    support = list(indexed_support.get(leaf, ()))
    if not any(item.get("file_path") == file_path for item in support):
        primary_record = records_by_path.get(file_path)
        if not isinstance(primary_record, dict):
            return None
        suffix = Path(file_path).suffix.lower()
        language = _LANGUAGES.get(suffix)
        source = source_cache.get(file_path) if source_cache is not None else None
        if source is None:
            source = read_project_text_no_symlink(
                project_root,
                file_path,
                max_bytes=MAX_SOURCE_BYTES,
                encoding="utf-8",
                errors=None if language is not None else "surrogateescape",
            )
        if source is None:
            return None
        if language is None:
            semantic_hash = str(primary_record.get("semantic_hash") or "")
        else:
            semantic_hash = _semantic_source_hash(source, language, suffix)
        if not _HASH_RE.fullmatch(semantic_hash):
            return None
        support.append({"file_path": file_path, "semantic_hash": semantic_hash})

    if any(
        not isinstance(item, dict)
        or not isinstance(item.get("file_path"), str)
        or not isinstance(item.get("semantic_hash"), str)
        or not _HASH_RE.fullmatch(item["semantic_hash"])
        for item in support
    ):
        return None
    return sha256_value(
        {
            "scope": "dead-code-symbol-context-v2",
            "symbol": leaf,
            "environment_hash": environment_hash,
            "files": sorted(support, key=lambda item: item["file_path"]),
        }
    )


def _python_dynamic_imports(tree: ast.AST) -> list[str] | None:
    """Return literal dynamic imports, or abstain when loader behavior escapes."""
    module_aliases: dict[str, str] = {"__builtins__": "builtins"}
    function_aliases = {"__import__"}
    unsafe_module_aliases: set[str] = set()
    unsafe_symbol_aliases: set[str] = set()
    sys_aliases: set[str] = set()
    site_aliases: set[str] = set()
    unsafe_modules = {
        "importlib.machinery",
        "importlib.util",
        "runpy",
        "pkgutil",
        "zipimport",
    }
    unsafe_symbols = {
        "SourceFileLoader",
        "SourcelessFileLoader",
        "ExtensionFileLoader",
        "spec_from_file_location",
        "module_from_spec",
        "run_module",
        "run_path",
        "resolve_name",
        "zipimporter",
    }
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib" or alias.name.startswith("importlib."):
                    module_aliases[alias.asname or alias.name] = "importlib"
                elif alias.name == "builtins":
                    module_aliases[alias.asname or alias.name] = "builtins"
                if alias.name == "sys":
                    sys_aliases.add(alias.asname or alias.name)
                if alias.name == "site":
                    site_aliases.add(alias.asname or alias.name)
                if alias.name in unsafe_modules and alias.asname:
                    unsafe_module_aliases.add(alias.asname)
                elif alias.name in {"runpy", "pkgutil", "zipimport"}:
                    unsafe_module_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "importlib":
                for alias in node.names:
                    if alias.name == "import_module":
                        function_aliases.add(alias.asname or alias.name)
                    elif alias.name in {"machinery", "util"}:
                        unsafe_module_aliases.add(alias.asname or alias.name)
            elif node.module == "builtins":
                for alias in node.names:
                    if alias.name == "__import__":
                        function_aliases.add(alias.asname or alias.name)
            if node.module in unsafe_modules:
                for alias in node.names:
                    if alias.name in unsafe_symbols or alias.name == "*":
                        unsafe_symbol_aliases.add(alias.asname or alias.name)
            if node.module == "site":
                for alias in node.names:
                    if alias.name == "addsitedir":
                        unsafe_symbol_aliases.add(alias.asname or alias.name)

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id in unsafe_module_aliases or node.id in unsafe_symbol_aliases:
                return None
            if node.id in sys_aliases:
                parent = parents.get(id(node))
                if (
                    isinstance(parent, ast.Attribute)
                    and parent.value is node
                    and parent.attr == "path"
                ):
                    return None
            if node.id in site_aliases:
                parent = parents.get(id(node))
                if (
                    isinstance(parent, ast.Attribute)
                    and parent.value is node
                    and parent.attr == "addsitedir"
                ):
                    return None
        if isinstance(node, ast.Constant) and node.value == "PYTHONPATH":
            return None

    def is_loader(expression: ast.AST) -> bool:
        if isinstance(expression, ast.Name):
            return expression.id in function_aliases
        return (
            isinstance(expression, ast.Attribute)
            and isinstance(expression.value, ast.Name)
            and (
                (
                    module_aliases.get(expression.value.id) == "importlib"
                    and expression.attr == "import_module"
                )
                or (
                    module_aliases.get(expression.value.id) == "builtins"
                    and expression.attr == "__import__"
                )
            )
        )

    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            value: ast.AST | None = None
            targets: list[ast.AST] = []
            if isinstance(node, ast.Assign):
                value = node.value
                targets = list(node.targets)
            elif isinstance(node, ast.NamedExpr):
                value = node.value
                targets = [node.target]
            if value is None or not is_loader(value):
                continue
            for target in targets:
                if not isinstance(target, ast.Name):
                    return None
                if target.id not in function_aliases:
                    function_aliases.add(target.id)
                    changed = True

    dynamic_modules: list[str] = []
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        dotted_call = ""
        if isinstance(call.func, ast.Name):
            dotted_call = call.func.id
        elif isinstance(call.func, ast.Attribute):
            parts: list[str] = []
            current: ast.AST = call.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
                dotted_call = ".".join(reversed(parts))
        if dotted_call in {"eval", "exec", "compile"} or dotted_call.endswith(
            (
                ".run_module",
                ".run_path",
                ".resolve_name",
                ".spec_from_file_location",
                ".module_from_spec",
                ".SourceFileLoader",
            )
        ):
            return None
        if not is_loader(call.func):
            continue
        if (
            not call.args
            or not isinstance(call.args[0], ast.Constant)
            or not isinstance(call.args[0].value, str)
        ):
            return None
        dynamic_name = call.args[0].value.strip()
        if not dynamic_name or dynamic_name.startswith("."):
            return None
        dynamic_modules.append(dynamic_name)

    # Reflection or passing a loader as a value can load a module that the
    # closure above cannot prove. In that case the review must not be reused.
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in function_aliases:
            parent = parents.get(id(node))
            if isinstance(parent, ast.Call) and parent.func is node:
                continue
            if isinstance(parent, (ast.Assign, ast.NamedExpr)) and parent.value is node:
                continue
            if isinstance(parent, (ast.Import, ast.ImportFrom, ast.alias)):
                continue
            # ast.Name nodes are not emitted for import aliases, so every other
            # load is an escape. Store-context assignment targets are harmless.
            if isinstance(node.ctx, ast.Store):
                continue
            return None
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and is_loader(node)
        ):
            parent = parents.get(id(node))
            if isinstance(parent, ast.Call) and parent.func is node:
                continue
            if isinstance(parent, (ast.Assign, ast.NamedExpr)) and parent.value is node:
                continue
            return None
        if isinstance(node, ast.Name) and node.id in module_aliases:
            parent = parents.get(id(node))
            if (
                isinstance(parent, ast.Attribute)
                and parent.value is node
                and is_loader(parent)
            ):
                continue
            if isinstance(node.ctx, ast.Store):
                continue
            # getattr(), __dict__, passing the module around, and other
            # reflection can recover a loader without an analyzable edge.
            return None
    return dynamic_modules


def _python_dependency_hash(
    project_root: str | Path,
    file_path: str,
    source: str,
    *,
    source_cache: dict[str, str | None] | None,
    semantic_cache: dict[str, str] | None,
    dependency_cache: dict[str, Any] | None,
) -> str | None:
    cache_key = f"python-dependencies:{file_path}"
    if dependency_cache is not None and cache_key in dependency_cache:
        return dependency_cache[cache_key]
    try:
        root = Path(project_root).resolve(strict=True)
    except OSError:
        return None
    index_cache_key = "python-module-index"
    module_index = (
        dependency_cache.get(index_cache_key) if dependency_cache is not None else None
    )
    if not isinstance(module_index, dict):
        module_index = _python_module_index(root)
        if module_index is None:
            if dependency_cache is not None:
                dependency_cache[cache_key] = None
            return None
        if dependency_cache is not None:
            dependency_cache[index_cache_key] = module_index
    pending: list[tuple[str, str]] = [(file_path, source)]
    visited = {file_path}
    dependencies: list[dict[str, str]] = []
    total_bytes = 0

    while pending:
        importer_path, importer_source = pending.pop()
        try:
            tree = ast.parse(importer_source, type_comments=True)
        except (MemoryError, RecursionError, SyntaxError, ValueError):
            if dependency_cache is not None:
                dependency_cache[cache_key] = None
            return None
        dynamic_modules = _python_dynamic_imports(tree)
        if dynamic_modules is None:
            if dependency_cache is not None:
                dependency_cache[cache_key] = None
            return None
        candidates_from_dynamic: list[str] = []
        for dynamic_module in dynamic_modules:
            candidates_from_dynamic.extend(module_index.get(dynamic_module, ()))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            candidates = _python_import_candidates(
                root,
                importer_path,
                node,
                module_index,
            )
            if candidates is None:
                if dependency_cache is not None:
                    dependency_cache[cache_key] = None
                return None
            if isinstance(node, ast.ImportFrom) and node.level and not candidates:
                if dependency_cache is not None:
                    dependency_cache[cache_key] = None
                return None
            candidates_from_dynamic.extend(candidates)
        parent_initializers = _python_parent_initializers(root, importer_path)
        if parent_initializers is None:
            if dependency_cache is not None:
                dependency_cache[cache_key] = None
            return None
        candidates_from_dynamic.extend(parent_initializers)
        for dependency_path in candidates_from_dynamic:
            if dependency_path in visited:
                continue
            visited.add(dependency_path)
            if len(visited) > MAX_DEPENDENCY_FILES:
                if dependency_cache is not None:
                    dependency_cache[cache_key] = None
                return None
            if source_cache is not None and dependency_path in source_cache:
                dependency_source = source_cache[dependency_path]
            else:
                dependency_source = read_project_text_no_symlink(
                    root,
                    dependency_path,
                    max_bytes=MAX_SOURCE_BYTES,
                    encoding="utf-8",
                )
                if source_cache is not None:
                    source_cache[dependency_path] = dependency_source
            if dependency_source is None:
                if dependency_cache is not None:
                    dependency_cache[cache_key] = None
                return None
            total_bytes += len(dependency_source.encode("utf-8"))
            if total_bytes > MAX_DEPENDENCY_SOURCE_BYTES:
                if dependency_cache is not None:
                    dependency_cache[cache_key] = None
                return None
            if semantic_cache is not None and dependency_path in semantic_cache:
                semantic_hash = semantic_cache[dependency_path]
            else:
                semantic_hash = _semantic_source_hash(
                    dependency_source, "python", ".py"
                )
                if semantic_cache is not None:
                    semantic_cache[dependency_path] = semantic_hash
            dependencies.append(
                {"file_path": dependency_path, "semantic_hash": semantic_hash}
            )
            pending.append((dependency_path, dependency_source))

    environment_hash = _environment_dependency_hash(
        root,
        "python",
        dependency_cache=dependency_cache,
    )
    if environment_hash is None:
        if dependency_cache is not None:
            dependency_cache[cache_key] = None
        return None
    digest = sha256_value(
        {
            "scope": "python-local-import-closure-v2",
            "environment_hash": environment_hash,
            "files": sorted(dependencies, key=lambda item: item["file_path"]),
        }
    )
    if dependency_cache is not None:
        dependency_cache[cache_key] = digest
    return digest


def _typescript_dependency_hash(
    project_root: str | Path,
    file_path: str,
    source: str,
    *,
    source_cache: dict[str, str | None] | None,
    semantic_cache: dict[str, str] | None,
    dependency_cache: dict[str, Any] | None,
) -> str | None:
    cache_key = f"typescript-dependencies:{file_path}"
    if dependency_cache is not None and cache_key in dependency_cache:
        return dependency_cache[cache_key]
    try:
        root = Path(project_root).resolve(strict=True)
        from skylos.visitors.languages.typescript.analysis import resolve_ts_module
        from skylos.visitors.languages.typescript.core import TypeScriptCore
        from skylos.visitors.languages.typescript.resolve import MonorepoResolver
    except (ImportError, OSError):
        return None

    resolver = MonorepoResolver(str(root))
    source_suffixes = {
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mts",
        ".cts",
        ".mjs",
        ".cjs",
    }
    pending: list[tuple[str, str]] = [(file_path, source)]
    visited = {file_path}
    dependencies: list[dict[str, str]] = []
    total_bytes = 0
    while pending:
        importer_path, importer_source = pending.pop()
        try:
            core = TypeScriptCore(
                str(root / importer_path), importer_source.encode("utf-8")
            )
            if core.root_node is None or core.root_node.has_error:
                raise ValueError("incomplete TypeScript parse")
            core.scan()
        except (MemoryError, RecursionError, UnicodeError, ValueError):
            if dependency_cache is not None:
                dependency_cache[cache_key] = None
            return None
        for node in core._iter_nodes(core.root_node):
            if node.type == "identifier" and core._get_text(node) == "require":
                parent = node.parent
                direct_call = (
                    parent is not None
                    and parent.type == "call_expression"
                    and parent.child_by_field_name("function") == node
                )
                resolve_member = (
                    parent is not None
                    and parent.type == "member_expression"
                    and parent.child_by_field_name("object") == node
                    and core._get_text(parent) == "require.resolve"
                )
                if not direct_call and not resolve_member:
                    if dependency_cache is not None:
                        dependency_cache[cache_key] = None
                    return None
            if node.type == "member_expression":
                member_text = core._get_text(node)
                if member_text.endswith(
                    (".require", ".require.resolve")
                ) and not member_text.startswith("require."):
                    if dependency_cache is not None:
                        dependency_cache[cache_key] = None
                    return None
            if node.type != "call_expression":
                continue
            function_node = node.child_by_field_name("function")
            arguments_node = node.child_by_field_name("arguments")
            if function_node is None or arguments_node is None:
                continue
            function_text = core._get_text(function_node)
            if function_text not in {
                "import",
                "require",
                "require.resolve",
                "import.meta.glob",
                "import.meta.globEager",
            }:
                continue
            arguments = arguments_node.named_children
            literal_types = (
                {"string", "array"}
                if function_text.startswith("import.meta.glob")
                else {"string"}
            )
            if not arguments or arguments[0].type not in literal_types:
                if dependency_cache is not None:
                    dependency_cache[cache_key] = None
                return None
            if arguments[0].type == "array" and any(
                child.type != "string" for child in arguments[0].named_children
            ):
                if dependency_cache is not None:
                    dependency_cache[cache_key] = None
                return None
        for raw_import in core.raw_imports:
            source_path = raw_import.get("source")
            if not isinstance(source_path, str) or not source_path:
                continue
            resolved = resolve_ts_module(
                source_path,
                str(root / importer_path),
                resolver,
            )
            if resolved is None:
                if source_path.startswith((".", "#")):
                    if dependency_cache is not None:
                        dependency_cache[cache_key] = None
                    return None
                continue
            dependency_path = normalize_repo_path(
                resolved,
                root,
                allow_absolute=True,
            )
            if dependency_path is None:
                if dependency_cache is not None:
                    dependency_cache[cache_key] = None
                return None
            if dependency_path in visited:
                continue
            visited.add(dependency_path)
            if len(visited) > MAX_DEPENDENCY_FILES:
                if dependency_cache is not None:
                    dependency_cache[cache_key] = None
                return None
            if source_cache is not None and dependency_path in source_cache:
                dependency_source = source_cache[dependency_path]
            else:
                dependency_source = read_project_text_no_symlink(
                    root,
                    dependency_path,
                    max_bytes=MAX_SOURCE_BYTES,
                    encoding="utf-8",
                )
                if source_cache is not None:
                    source_cache[dependency_path] = dependency_source
            if dependency_source is None:
                if dependency_cache is not None:
                    dependency_cache[cache_key] = None
                return None
            total_bytes += len(dependency_source.encode("utf-8"))
            if total_bytes > MAX_DEPENDENCY_SOURCE_BYTES:
                if dependency_cache is not None:
                    dependency_cache[cache_key] = None
                return None
            dependency_suffix = Path(dependency_path).suffix.lower()
            dependency_language = _LANGUAGES.get(dependency_suffix)
            if semantic_cache is not None and dependency_path in semantic_cache:
                semantic_hash = semantic_cache[dependency_path]
            elif dependency_language is None:
                semantic_hash = sha256_value(
                    {"parser": "raw-dependency-v1", "source": dependency_source}
                )
            else:
                semantic_hash = _semantic_source_hash(
                    dependency_source,
                    dependency_language,
                    dependency_suffix,
                )
                if semantic_cache is not None:
                    semantic_cache[dependency_path] = semantic_hash
            dependencies.append(
                {"file_path": dependency_path, "semantic_hash": semantic_hash}
            )
            if dependency_suffix in source_suffixes:
                pending.append((dependency_path, dependency_source))

    environment_hash = _environment_dependency_hash(
        root,
        "typescript",
        dependency_cache=dependency_cache,
    )
    if environment_hash is None:
        if dependency_cache is not None:
            dependency_cache[cache_key] = None
        return None
    digest = sha256_value(
        {
            "scope": "typescript-local-import-closure-v2",
            "environment_hash": environment_hash,
            "files": sorted(dependencies, key=lambda item: item["file_path"]),
        }
    )
    if dependency_cache is not None:
        dependency_cache[cache_key] = digest
    return digest


def finding_identity(
    finding: dict[str, Any],
    *,
    section: str,
    category: str,
    default_rule_id: str,
    project_root: str | Path,
    source_cache: dict[str, str | None] | None = None,
    semantic_cache: dict[str, str] | None = None,
    dependency_cache: dict[str, Any] | None = None,
) -> dict[str, str] | None:
    if finding.get("_review_identity_incomplete") is True:
        return None
    llm_analysis_context_hash = finding.get("_llm_analysis_context_hash")
    if llm_analysis_context_hash is not None and (
        not isinstance(llm_analysis_context_hash, str)
        or not _HASH_RE.fullmatch(llm_analysis_context_hash)
    ):
        return None
    if dependency_cache is not None and dependency_cache.get(
        "analysis-review-context-invalid"
    ):
        return None
    raw_path = finding.get("file_path") or finding.get("file")
    file_path = normalize_repo_path(raw_path, project_root, allow_absolute=True)
    line = _strict_positive_line(finding.get("line_number") or finding.get("line"))
    if file_path is None or line is None:
        return None

    if source_cache is not None and file_path in source_cache:
        source = source_cache[file_path]
    else:
        source = read_project_text_no_symlink(
            project_root,
            file_path,
            max_bytes=MAX_SOURCE_BYTES,
            encoding="utf-8",
        )
        if source_cache is not None:
            source_cache[file_path] = source
    if source is None:
        return None
    lines = source.splitlines()
    empty_file_finding = section == "unused_files" and line == 1 and not lines
    if line > len(lines) and not empty_file_finding:
        return None

    end_line = _strict_positive_line(finding.get("end_line")) or line
    end_line = min(max(end_line, line), min(len(lines), line + 20))
    primary_lines = [
        _normalize_source_line(raw) for raw in lines[line - 1 : end_line] if raw.strip()
    ]
    if not primary_lines and not empty_file_finding:
        return None

    context_start = max(0, line - 3)
    context_end = min(len(lines), end_line + 2)
    context_lines = [
        _normalize_source_line(raw) for raw in lines[context_start:context_end]
    ]

    rule_id = _rule_id(finding, default_rule_id)
    if rule_id is None:
        return None
    raw_rule_revision = finding.get("rule_revision")
    # A user/cloud supplied rule can change without the Skylos package version
    # changing.  Such findings are reusable only when the rule implementation
    # supplied its own content-derived revision.
    if section == "custom_rules" and not raw_rule_revision:
        return None
    if raw_rule_revision is not None and (
        not isinstance(raw_rule_revision, str)
        or raw_rule_revision != raw_rule_revision.strip()
    ):
        return None
    rule_revision = raw_rule_revision or DEFAULT_RULE_REVISION
    if not _RULE_REVISION_RE.fullmatch(rule_revision):
        return None
    language = _language(finding, file_path)
    symbol = _symbol(finding)
    severity = str(finding.get("severity") or "").strip().upper()
    high_risk = category in {"SECURITY", "SECRET", "DEPENDENCY"} or severity in {
        "HIGH",
        "CRITICAL",
    }
    evidence = _security_evidence(finding) if high_risk else None
    semantic_source_hash = None
    semantic_dependency_hash = None
    dead_code_proof = None
    dead_code_support_hash = None
    if category == "DEAD_CODE":
        dead_code_proof = _dead_code_proof_digest(finding)
        if dead_code_proof is not None:
            dead_code_support_hash = _dead_code_symbol_context_hash(
                project_root,
                file_path,
                symbol,
                source_cache=source_cache,
                semantic_cache=semantic_cache,
                dependency_cache=dependency_cache,
            )
            if dead_code_support_hash is None:
                return None
        else:
            # Results from older/non-Python analyzers lack a complete proof
            # slice.  Keep them reviewable, but bind the decision to the full
            # bounded analyzer-input snapshot.
            semantic_source_hash = _semantic_source_hash(
                source, language, Path(file_path).suffix.lower()
            )
            if semantic_cache is not None:
                semantic_cache[file_path] = semantic_source_hash
            dead_code_support_hash = _repository_semantic_hash(
                project_root,
                source_cache=source_cache,
                semantic_cache=semantic_cache,
                dependency_cache=dependency_cache,
            )
            if dead_code_support_hash is None:
                return None
    if high_risk:
        if semantic_cache is not None and file_path in semantic_cache:
            semantic_source_hash = semantic_cache[file_path]
        else:
            semantic_source_hash = _semantic_source_hash(
                source, language, Path(file_path).suffix.lower()
            )
            if semantic_cache is not None:
                semantic_cache[file_path] = semantic_source_hash
        local_dependency_hash = None
        if language == "python":
            try:
                primary_tree = ast.parse(source, type_comments=True)
            except (MemoryError, RecursionError, SyntaxError, ValueError):
                return None
            # A loader recovered from runtime state in the finding's own file
            # can change without any repository input changing.  Do not mint a
            # reusable identity for that case.
            if _python_dynamic_imports(primary_tree) is None:
                return None
            local_dependency_hash = _python_dependency_hash(
                project_root,
                file_path,
                source,
                source_cache=source_cache,
                semantic_cache=semantic_cache,
                dependency_cache=dependency_cache,
            )
            if local_dependency_hash is None:
                # A transitive module may contain an unrelated loader or an
                # import form our closure cannot prove.  The repository input
                # envelope below still gives a safe, useful exact snapshot.
                local_dependency_hash = "dependency-closure-incomplete"
        elif language in {"javascript", "typescript"}:
            local_dependency_hash = _typescript_dependency_hash(
                project_root,
                file_path,
                source,
                source_cache=source_cache,
                semantic_cache=semantic_cache,
                dependency_cache=dependency_cache,
            )
            if local_dependency_hash is None:
                return None
        # A forward import closure cannot see startup monkeypatches, reverse
        # importers, or framework registries.  Retain a fast, bounded envelope
        # of other analyzer inputs until each language exposes those proof
        # edges directly.
        repository_hash = _repository_semantic_hash(
            project_root,
            source_cache=source_cache,
            semantic_cache=semantic_cache,
            dependency_cache=dependency_cache,
        )
        if repository_hash is None:
            return None
        semantic_dependency_hash = sha256_value(
            {
                "scope": "high-risk-proof-envelope-v2",
                "local_dependency_hash": local_dependency_hash,
                "repository_hash": repository_hash,
            }
        )
    assurance = _finding_assurance_context(finding)
    effective_config_hash = finding.get("_analysis_config_hash")
    if effective_config_hash is not None and (
        not isinstance(effective_config_hash, str)
        or not _HASH_RE.fullmatch(effective_config_hash)
    ):
        return None
    analysis_context_hash = None
    if (
        dependency_cache is not None
        and (review_context := dependency_cache.get("analysis-review-context"))
        is not None
    ):
        analysis_context_hash = review_context_hash_for_category(
            review_context,
            category,
            effective_config_hash=effective_config_hash,
        )
        if analysis_context_hash is None:
            return None
    anchor_hash = sha256_value(
        {
            "primary_lines": primary_lines,
            "empty_file": empty_file_finding,
            "security_evidence": evidence,
            "assurance": assurance,
        }
    )
    stable_fingerprint = sha256_value(
        {
            "fingerprint_version": FINGERPRINT_VERSION,
            "rule_id": rule_id,
            "rule_revision": rule_revision,
            "file_path": file_path,
            "language": language,
            "category": category,
            "symbol": symbol,
            "anchor_hash": anchor_hash,
        }
    )
    context_hash = sha256_value(
        {
            "primary_lines": primary_lines,
            "empty_file": empty_file_finding,
            "context_lines": None
            if high_risk or dead_code_proof is not None
            else context_lines,
            "security_evidence": evidence,
            "assurance": assurance,
            "semantic_source_hash": semantic_source_hash,
            "semantic_dependency_hash": semantic_dependency_hash,
            "dead_code_proof": dead_code_proof,
            "dead_code_support_hash": dead_code_support_hash,
            "analysis_context_hash": analysis_context_hash,
            "llm_analysis_context_hash": llm_analysis_context_hash,
        }
    )
    return {
        "fingerprint_version": FINGERPRINT_VERSION,
        "stable_fingerprint": stable_fingerprint,
        "context_hash": context_hash,
        "rule_revision": rule_revision,
        "rule_id": rule_id,
        "file_path": file_path,
        "language": language,
        "symbol": symbol,
        "section": section,
    }


def annotate_result_identities(
    result: dict[str, Any],
    project_root: str | Path,
    *,
    candidate_keys: set[tuple[str, str | None]] | None = None,
) -> dict[str, Any]:
    sanitized = _strip_untrusted_review_fields(result)
    try:
        annotated = deepcopy(sanitized)
    except (MemoryError, RecursionError, TypeError, ValueError):
        annotated = _bounded_result_copy(sanitized)
        if not isinstance(annotated, dict):
            return {}
    source_cache: dict[str, str | None] = {}
    semantic_cache: dict[str, str] = {}
    dependency_cache: dict[str, Any] = {}
    summary = annotated.get("analysis_summary")
    review_context = (
        summary.get("review_context") if isinstance(summary, dict) else None
    )
    if isinstance(summary, dict) and "review_context" in summary:
        if review_context_is_valid(review_context):
            dependency_cache["analysis-review-context"] = review_context
        else:
            dependency_cache["analysis-review-context-invalid"] = True

    def is_candidate(finding: dict[str, Any], default_rule_id: str) -> bool:
        if candidate_keys is None:
            return True
        rule_id = _rule_id(finding, default_rule_id)
        file_path = normalize_repo_path(
            finding.get("file_path") or finding.get("file"),
            project_root,
            allow_absolute=True,
        )
        return (rule_id, file_path) in candidate_keys or (
            rule_id,
            None,
        ) in candidate_keys

    dead_code_symbols: set[str] = set()
    for section, category, default_rule_id in FINDING_SECTIONS:
        if category != "DEAD_CODE":
            continue
        for finding in annotated.get(section, []) or []:
            if isinstance(finding, dict) and is_candidate(finding, default_rule_id):
                dead_code_symbols.add(_symbol(finding))
    if dead_code_symbols:
        _prepare_dead_code_symbol_support(
            project_root,
            dead_code_symbols,
            source_cache=source_cache,
            semantic_cache=semantic_cache,
            dependency_cache=dependency_cache,
        )

    for section, category, default_rule_id in FINDING_SECTIONS:
        findings = annotated.get(section)
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if not is_candidate(finding, default_rule_id):
                finding.pop("_analysis_config_hash", None)
                finding.pop("_analysis_worker_config", None)
                finding.pop("_llm_analysis_context_hash", None)
                continue
            identity = finding_identity(
                finding,
                section=section,
                category=category,
                default_rule_id=default_rule_id,
                project_root=project_root,
                source_cache=source_cache,
                semantic_cache=semantic_cache,
                dependency_cache=dependency_cache,
            )
            finding.pop("_analysis_config_hash", None)
            finding.pop("_analysis_worker_config", None)
            finding.pop("_llm_analysis_context_hash", None)
            if identity:
                finding.update(identity)
    return annotated


def _bundle_decision_records(bundle: Any) -> list[Any]:
    if isinstance(bundle, list):
        return list(bundle)
    if not isinstance(bundle, dict):
        return []
    if bundle.get("schema") not in (None, REVIEW_SCHEMA):
        return []
    if bundle.get("version") not in (None, 1, REVIEW_SCHEMA_VERSION):
        return []
    records = bundle.get("decisions")
    if records is None:
        records = bundle.get("suppressions")
    return list(records) if isinstance(records, list) else []


def _records_for_repository_scope(
    bundle: Any,
    project_root: str | Path,
    repo_subpath: str,
) -> list[Any]:
    records = _bundle_decision_records(bundle)
    if not repo_subpath:
        return records
    scoped: list[Any] = []
    for raw in records:
        if not isinstance(raw, dict):
            scoped.append(raw)
            continue
        file_path = normalize_repo_path(raw.get("file_path"), project_root)
        if file_path is None:
            scoped.append(raw)
            continue
        record = dict(raw)
        if file_path != repo_subpath and not file_path.startswith(f"{repo_subpath}/"):
            record["file_path"] = f"{repo_subpath}/{file_path}"
        scoped.append(record)
    return scoped


def _active_decision_targets_dead_code(
    bundle: Any,
    project_root: str | Path,
    *,
    now: datetime | None,
) -> bool:
    """Return whether an active v2 decision needs a dead-code proof identity."""
    for decision in active_decisions(bundle, project_root, now=now):
        # Legacy decisions match by location and do not consume the proof digest.
        if decision.get("_v2_key") is None:
            continue
        category = _bounded_string(decision.get("category"), maximum=80)
        if category is not None:
            if category.upper().replace("-", "_") == "DEAD_CODE":
                return True
            continue
        section = _bounded_string(decision.get("section"), maximum=80)
        if section is not None:
            if section.lower() in _DEAD_CODE_SECTIONS:
                return True
            continue
        rule_id = _bounded_string(decision.get("rule_id"), maximum=120)
        if rule_id in _DEAD_CODE_RULE_IDS:
            return True
    return False


def review_scan_requirements(
    project_root: str | Path,
    *,
    environ: dict[str, str] | None = None,
    now: datetime | None = None,
) -> tuple[bool, bool]:
    """Return ``(context, dead-code proof)`` needs for active v2 reviews."""
    env = environ if environ is not None else os.environ
    if is_ci_environment(env):
        return False, False
    identity_root = _identity_project_root(project_root)
    if identity_root is None:
        return False, False
    repository_identity = _git_remote_identity(identity_root)
    local_scope = {
        "repository_identity": repository_identity
        or "local:" + hashlib.sha256(str(identity_root).encode("utf-8")).hexdigest(),
        "repo_subpath": "",
    }
    local_bundle = _load_local_bundle(
        identity_root,
        environ=env,
        _scope=local_scope,
        _identity_root=identity_root,
    )
    bundles = [local_bundle]

    expected_project_id = _linked_project_id(identity_root, project_root)
    if repository_identity is not None and expected_project_id is not None:
        for candidate in _review_scope_candidates(project_root, git_root=identity_root):
            candidate_scope = _scope_for_project(
                candidate, identity_root, repository_identity
            )
            if candidate_scope is None:
                continue
            bundles.append(
                load_trusted_bundle(
                    candidate,
                    environ=env,
                    expected_project_id=expected_project_id,
                    now=now,
                    _scope=candidate_scope,
                )
            )

    context_required = False
    proofs_required = False
    for bundle in bundles:
        decisions = active_decisions(bundle, identity_root, now=now)
        context_required = context_required or any(
            decision.get("_v2_key") is not None for decision in decisions
        )
        proofs_required = proofs_required or _active_decision_targets_dead_code(
            decisions,
            identity_root,
            now=now,
        )
    return context_required, proofs_required


def review_context_required(
    project_root: str | Path,
    *,
    environ: dict[str, str] | None = None,
    now: datetime | None = None,
) -> bool:
    """Return whether an active v2 decision needs analyzer review context."""
    required, _proofs_required = review_scan_requirements(
        project_root,
        environ=environ,
        now=now,
    )
    return required


def review_proofs_required(
    project_root: str | Path,
    *,
    environ: dict[str, str] | None = None,
    now: datetime | None = None,
) -> bool:
    """Return whether an active v2 dead-code review needs graph proofs."""
    _context_required, required = review_scan_requirements(
        project_root,
        environ=environ,
        now=now,
    )
    return required


def review_state_revision(
    project_root: str | Path,
    *,
    cache_root: str | Path | None = None,
    local_cache_root: str | Path | None = None,
    environ: dict[str, str] | None = None,
    now: datetime | None = None,
) -> str | None:
    """Return a semantic digest of active decisions for cached projections.

    Agent state may be reused while source files are unchanged.  This digest
    makes review authoring, revocation, Cloud sync, and expiry part of that
    reuse decision without treating review files as analyzer input.
    """
    env = environ if environ is not None else os.environ
    if is_ci_environment(env):
        return None
    identity_root = _identity_project_root(project_root)
    if identity_root is None:
        return None

    repository_identity = _git_remote_identity(identity_root)
    expected_project_id = _linked_project_id(identity_root, project_root)
    trusted_bundle = None
    trusted_scope: dict[str, str] | None = None
    if repository_identity is not None and expected_project_id is not None:
        for candidate in _review_scope_candidates(project_root, git_root=identity_root):
            candidate_scope = _scope_for_project(
                candidate, identity_root, repository_identity
            )
            if candidate_scope is None:
                continue
            trusted_bundle = load_trusted_bundle(
                candidate,
                cache_root=cache_root,
                environ=env,
                expected_project_id=expected_project_id,
                now=now,
                _scope=candidate_scope,
            )
            if trusted_bundle is not None:
                trusted_scope = candidate_scope
                break

    local_scope = {
        "repository_identity": repository_identity
        or "local:" + hashlib.sha256(str(identity_root).encode("utf-8")).hexdigest(),
        "repo_subpath": "",
    }
    local_bundle = _load_local_bundle(
        identity_root,
        cache_root=local_cache_root,
        environ=env,
        _scope=local_scope,
        _identity_root=identity_root,
    )
    combined = {
        "schema": REVIEW_SCHEMA,
        "version": REVIEW_SCHEMA_VERSION,
        "decisions": [
            *_records_for_repository_scope(
                trusted_bundle,
                identity_root,
                (trusted_scope or {}).get("repo_subpath", ""),
            ),
            *_bundle_decision_records(local_bundle),
        ],
    }

    revision_items: list[dict[str, Any]] = []
    for decision in active_decisions(combined, identity_root, now=now):
        expires_at = _parse_timestamp(decision.get("expires_at"))
        revision_items.append(
            {
                # Keep every physical decision in the digest. Duplicate active
                # identities deliberately change matching from exact to
                # ambiguous, even if their other semantic fields agree.
                "decision_id": str(
                    decision.get("decision_id") or decision.get("id") or ""
                ),
                "v2_key": list(decision["_v2_key"])
                if decision.get("_v2_key") is not None
                else None,
                "legacy_key": list(decision["_legacy_key"])
                if decision.get("_legacy_key") is not None
                else None,
                "disposition": decision["disposition"],
                "expires_at": expires_at.isoformat()
                if expires_at is not None
                else None,
                # These fields decide whether the analyzer must emit a
                # dead-code proof before applying the same decision set.
                "category": _bounded_string(decision.get("category"), maximum=80),
                "section": _bounded_string(decision.get("section"), maximum=80),
            }
        )
    if not revision_items:
        return None
    revision_items.sort(key=canonical_json)
    return sha256_value(
        {
            "revision": "skylos-review-state-v1",
            "decisions": revision_items,
        }
    )


def apply_trusted_review_decisions(
    result: dict[str, Any],
    project_root: str | Path,
    *,
    analysis_root: str | Path | None = None,
    cache_root: str | Path | None = None,
    local_cache_root: str | Path | None = None,
    environ: dict[str, str] | None = None,
    now: datetime | None = None,
    include_identities: bool = False,
) -> dict[str, Any]:
    result = _strip_untrusted_review_fields(result)
    summary = result.get("analysis_summary")
    has_review_context = isinstance(summary, dict) and review_context_is_valid(
        summary.get("review_context")
    )
    can_emit_identities = include_identities and has_review_context
    if (
        not include_identities
        and not _cache_root(cache_root).is_dir()
        and not _local_cache_root(local_cache_root).is_dir()
    ):
        return result
    identity_root = _identity_project_root(project_root)
    identity_analysis_root = identity_root
    if analysis_root is not None:
        try:
            candidate = Path(analysis_root).expanduser()
            candidate_stat = candidate.lstat()
            if stat.S_ISLNK(candidate_stat.st_mode) or not stat.S_ISDIR(
                candidate_stat.st_mode
            ):
                return result
            identity_analysis_root = candidate.resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            return result
    if identity_root is None:
        return (
            annotate_result_identities(
                result,
                identity_analysis_root or project_root,
            )
            if can_emit_identities
            else result
        )
    trusted_bundle = None
    trusted_scope: dict[str, str] | None = None
    expected_project_id = _linked_project_id(identity_root, project_root)
    repository_identity = _git_remote_identity(identity_root)
    # A Cloud cache is only authoritative while the repository is explicitly
    # linked to the same Cloud project.  The cache itself lives outside the
    # repository, but a missing link must still behave like an unlink rather
    # than leaving old policy active indefinitely.
    if repository_identity is not None and expected_project_id is not None:
        for candidate in _review_scope_candidates(project_root, git_root=identity_root):
            candidate_scope = _scope_for_project(
                candidate, identity_root, repository_identity
            )
            if candidate_scope is None:
                continue
            trusted_bundle = load_trusted_bundle(
                candidate,
                cache_root=cache_root,
                environ=environ,
                expected_project_id=expected_project_id,
                now=now,
                _scope=candidate_scope,
            )
            if trusted_bundle is not None:
                trusted_scope = candidate_scope
                break
    local_scope = {
        "repository_identity": repository_identity
        or "local:" + hashlib.sha256(str(identity_root).encode("utf-8")).hexdigest(),
        "repo_subpath": "",
    }
    local_bundle = _load_local_bundle(
        identity_root,
        cache_root=local_cache_root,
        environ=environ,
        _scope=local_scope,
        _identity_root=identity_root,
    )
    if trusted_bundle is None and local_bundle is None:
        return (
            annotate_result_identities(
                result,
                identity_analysis_root or identity_root,
            )
            if can_emit_identities
            else result
        )
    combined = {
        "schema": REVIEW_SCHEMA,
        "version": REVIEW_SCHEMA_VERSION,
        "decisions": [
            *_records_for_repository_scope(
                trusted_bundle,
                identity_root,
                (trusted_scope or {}).get("repo_subpath", ""),
            ),
            *_bundle_decision_records(local_bundle),
        ],
    }
    if not active_decisions(combined, identity_root, now=now):
        return (
            annotate_result_identities(
                result,
                identity_analysis_root or identity_root,
            )
            if can_emit_identities
            else result
        )
    return apply_review_decisions(
        result,
        combined,
        identity_analysis_root or identity_root,
        now=now,
        include_identities=can_emit_identities,
        require_review_context=True,
    )


def _parse_timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if (
        not isinstance(value, str)
        or len(value) > 80
        or not _RFC3339_RE.fullmatch(value)
    ):
        return None
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _now_utc(now: datetime | None) -> datetime:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        return current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)


def _active_disposition(record: dict[str, Any], now: datetime) -> str | None:
    if record.get("revoked_at") is not None:
        return None
    status = record.get("status")
    if status is not None and status != "active":
        return None
    disposition = record.get("disposition")
    if not _has_v2_fields(record) and disposition is None:
        disposition = record.get("type")
    if not isinstance(disposition, str) or disposition not in KNOWN_DISPOSITIONS:
        return None
    if disposition not in SUPPRESSING_DISPOSITIONS:
        return None
    expires_raw = record.get("expires_at")
    expires_at = _parse_timestamp(expires_raw)
    if expires_raw is not None and expires_at is None:
        return None
    if disposition == "risk_accepted" and expires_at is None:
        return None
    if expires_at is not None and expires_at <= now:
        return None
    return disposition


def _v2_key(record: dict[str, Any]) -> tuple[str, str, str, str, str] | None:
    fields = (
        record.get("fingerprint_version"),
        record.get("stable_fingerprint"),
        record.get("context_hash"),
        record.get("rule_revision"),
        record.get("rule_id"),
    )
    if not all(isinstance(value, str) and value.strip() for value in fields):
        return None
    version, stable, context, revision, rule_id = (
        str(value).strip() for value in fields
    )
    if version != FINGERPRINT_VERSION:
        return None
    if not _HASH_RE.fullmatch(stable) or not _HASH_RE.fullmatch(context):
        return None
    raw_rule_id = record.get("rule_id")
    raw_revision = record.get("rule_revision")
    if (
        not _RULE_REVISION_RE.fullmatch(revision)
        or not isinstance(raw_revision, str)
        or raw_revision != revision
        or not isinstance(raw_rule_id, str)
        or _valid_rule_id(raw_rule_id) != rule_id
    ):
        return None
    return version, stable, context, revision, rule_id


def _has_v2_fields(record: dict[str, Any]) -> bool:
    return any(
        record.get(key) is not None
        for key in (
            "fingerprint_version",
            "stable_fingerprint",
            "context_hash",
            "rule_revision",
        )
    )


def _legacy_key(
    record: dict[str, Any], project_root: str | Path
) -> tuple[str, str, int] | None:
    if _has_v2_fields(record):
        return None
    rule_id = _valid_rule_id(record.get("rule_id"))
    file_path = normalize_repo_path(record.get("file_path"), project_root)
    line = _positive_line(record.get("line_number") or record.get("line"))
    if rule_id is None or file_path is None or line is None:
        return None
    return rule_id, file_path, line


def active_decisions(
    bundle: Any,
    project_root: str | Path,
    *,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    if isinstance(bundle, list):
        records = bundle
    elif isinstance(bundle, dict):
        if bundle.get("schema") not in (None, REVIEW_SCHEMA):
            return []
        if bundle.get("version") not in (None, 1, REVIEW_SCHEMA_VERSION):
            return []
        records = bundle.get("decisions")
        if records is None:
            records = bundle.get("suppressions")
    else:
        return []
    if not isinstance(records, list) or len(records) > MAX_DECISIONS:
        return []

    current = _now_utc(now)
    valid: list[dict[str, Any]] = []
    for raw in records:
        if not isinstance(raw, dict):
            continue
        try:
            if len(canonical_json(raw).encode("utf-8")) > 20_000:
                continue
        except (MemoryError, RecursionError, TypeError, ValueError):
            continue
        disposition = _active_disposition(raw, current)
        if disposition is None:
            continue
        v2_key = _v2_key(raw)
        legacy_key = _legacy_key(raw, project_root)
        if v2_key is not None and (
            _decision_id(raw.get("decision_id") or raw.get("id")) is None
            or _strict_positive_line(raw.get("line_number") or raw.get("line")) is None
            or normalize_repo_path(raw.get("file_path"), project_root) is None
        ):
            continue
        if v2_key is None and legacy_key is None:
            continue
        record = dict(raw)
        record["disposition"] = disposition
        record["_v2_key"] = v2_key
        record["_legacy_key"] = legacy_key
        valid.append(record)
    return valid


def _finding_legacy_key(
    finding: dict[str, Any], project_root: str | Path, default_rule_id: str
) -> tuple[str, str, int] | None:
    path = normalize_repo_path(
        finding.get("file_path") or finding.get("file"),
        project_root,
        allow_absolute=True,
    )
    line = _positive_line(finding.get("line_number") or finding.get("line"))
    if path is None or line is None:
        return None
    rule_id = _rule_id(finding, default_rule_id)
    if rule_id is None:
        return None
    return rule_id, path, line


def _decision_audit(record: dict[str, Any], match_mode: str) -> dict[str, Any]:
    audit = {
        "decision_id": str(record.get("decision_id") or record.get("id") or "")[:200],
        "disposition": record["disposition"],
        "reason": str(record.get("reason") or "")[:2_000],
        "created_at": record.get("created_at"),
        "created_by": str(record.get("created_by") or "")[:200],
        "expires_at": record.get("expires_at"),
        "match_mode": match_mode,
    }
    return {key: value for key, value in audit.items() if value not in (None, "")}


def apply_review_decisions(
    result: dict[str, Any],
    bundle: Any,
    project_root: str | Path,
    *,
    now: datetime | None = None,
    include_identities: bool = True,
    require_review_context: bool = False,
) -> dict[str, Any]:
    decisions = active_decisions(bundle, project_root, now=now)
    if require_review_context:
        summary = result.get("analysis_summary")
        has_review_context = isinstance(summary, dict) and review_context_is_valid(
            summary.get("review_context")
        )
        if not has_review_context:
            decisions = [
                decision for decision in decisions if decision.get("_v2_key") is None
            ]
    candidate_keys: set[tuple[str, str | None]] | None = None
    if not include_identities:
        candidate_keys = set()
        for decision in decisions:
            rule_id = str(decision.get("rule_id") or "")
            file_path = normalize_repo_path(decision.get("file_path"), project_root)
            candidate_keys.add((rule_id, file_path))
    projected = annotate_result_identities(
        result,
        project_root,
        candidate_keys=candidate_keys,
    )

    current_v2_counts: Counter[tuple[str, str, str, str, str]] = Counter()
    current_legacy_counts: Counter[tuple[str, str, int]] = Counter()
    for section, _category, default_rule_id in FINDING_SECTIONS:
        for finding in projected.get(section, []) or []:
            if not isinstance(finding, dict):
                continue
            if (key := _v2_key(finding)) is not None:
                current_v2_counts[key] += 1
            legacy_key = _finding_legacy_key(finding, project_root, default_rule_id)
            if legacy_key is not None:
                current_legacy_counts[legacy_key] += 1

    v2_records: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = (
        defaultdict(list)
    )
    legacy_records: dict[tuple[str, str, int], list[dict[str, Any]]] = defaultdict(list)
    for decision in decisions:
        if decision["_v2_key"] is not None:
            v2_records[decision["_v2_key"]].append(decision)
        elif decision["_legacy_key"] is not None:
            legacy_records[decision["_legacy_key"]].append(decision)

    reviewed: list[dict[str, Any]] = []
    ambiguous = 0
    for section, category, default_rule_id in FINDING_SECTIONS:
        findings = projected.get(section)
        if not isinstance(findings, list):
            continue
        active: list[Any] = []
        for item in findings:
            if not isinstance(item, dict):
                active.append(item)
                continue
            decision = None
            match_mode = ""
            v2_ambiguous = False
            v2_key = _v2_key(item)
            if v2_key is not None and current_v2_counts[v2_key] == 1:
                matches = v2_records.get(v2_key, [])
                if len(matches) == 1:
                    decision = matches[0]
                    match_mode = "v2_exact_context"
                elif len(matches) > 1:
                    ambiguous += 1
                    v2_ambiguous = True
            elif v2_key is not None and current_v2_counts[v2_key] > 1:
                ambiguous += 1
                v2_ambiguous = True

            severity = str(item.get("severity") or "").strip().upper()
            legacy_can_suppress = category not in {
                "SECURITY",
                "SECRET",
                "DEPENDENCY",
            } and severity not in {"HIGH", "CRITICAL"}
            if decision is None and not v2_ambiguous and legacy_can_suppress:
                legacy_key = _finding_legacy_key(item, project_root, default_rule_id)
                matches = legacy_records.get(legacy_key, []) if legacy_key else []
                if legacy_key is not None and current_legacy_counts[legacy_key] > 1:
                    ambiguous += 1
                elif len(matches) == 1:
                    decision = matches[0]
                    match_mode = "legacy_exact_location"
                elif len(matches) > 1:
                    ambiguous += 1

            if decision is None:
                active.append(item)
                continue

            suppressed = dict(item)
            suppressed["category"] = category
            suppressed["review_decision"] = _decision_audit(decision, match_mode)
            suppressed["_skylos_trusted_review"] = True
            reviewed.append(suppressed)
        projected[section] = active

    projected["reviewed_findings"] = reviewed
    projected["reviewed_findings_summary"] = {
        "suppressed_count": len(reviewed),
        "active_decision_count": len(decisions),
        "ambiguous_match_count": ambiguous,
    }
    summary = projected.get("analysis_summary")
    if isinstance(summary, dict):
        for section, count_key in _SUMMARY_COUNT_KEYS.items():
            if section in projected:
                summary[count_key] = len(projected.get(section) or [])
        summary["reviewed_findings"] = dict(projected["reviewed_findings_summary"])
        if reviewed:
            summary.pop("by_directory", None)
            summary.pop("dead_code_evidence", None)
    if reviewed:
        # These aggregates describe the unprojected finding set. Omitting them
        # is safer than presenting a score or provenance count that no longer
        # agrees with the visible results.
        projected.pop("grade", None)
        projected.pop("ai_security_stats", None)
        projected.pop("provenance_summary", None)
    return projected
