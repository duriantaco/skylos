"""Hallucinated / look-alike package checks for a single shell install command.

The install-surface scanner in ``manifest_dependency_hallucination`` only
checks pinned specs found in files. An agent typing ``pip install foo`` is the
opposite case: one command, usually unpinned, checked *before* it runs. This
module reuses that scanner's tokenizer, private-registry detection, registry
URL guards and look-alike heuristic, and adds package-only existence checks.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any, Callable

from skylos.rules.ai_defect.dependency_truth import (
    DependencyTruthState,
    dependency_truth_cache_key,
    normalize_dependency_truth_state,
)
from skylos.rules.ai_defect.manifest_dependency_hallucination import (
    AUTHORITATIVE_CACHE_STATES,
    GO_PROXY_ORIGIN,
    NPM_PRIVATE_REGISTRY_ENV_PREFIXES,
    NPM_PRIVATE_REGISTRY_FLAGS,
    NPM_REGISTRY_ORIGIN,
    NPM_VALUE_FLAGS,
    PIP_PRIVATE_REGISTRY_ENV_PREFIXES,
    PIP_VALUE_FLAGS,
    PYPI_JSON_ORIGIN,
    STATUS_MISSING_PACKAGE,
    STATUS_PRESENT,
    STATUS_UNKNOWN,
    _check_registry_package_url,
    _command_prefix_tokens,
    _go_install_args_start,
    _load_version_cache,
    _npm_install_args_start,
    _package_specs,
    _pip_install_args_start,
    _registry_http_status,
    _safe_go_path_part,
    _safe_npm_package_path,
    _safe_pypi_package_path,
    _save_version_cache,
    _space_shell_command_separators,
    _suspicious_existing_dependency_reason,
    _tokens_have_private_pip_index,
    _tokens_have_private_registry_env,
    _tokens_have_private_registry_option,
    check_dependency_version_status,
)
from skylos.rules.sca.vulnerability_scanner import (
    ECOSYSTEM_GO,
    ECOSYSTEM_NPM,
    ECOSYSTEM_PYPI,
    _classify_npm_registry_spec,
)

PACKAGE_ONLY_VERSION = "<package-only>"
MAX_COMMAND_CHARS = 20_000
MAX_PACKAGES_PER_COMMAND = 25

# Cheap pre-filter so unrelated commands never pay for tokenizing.
INSTALL_COMMAND_HINT_RE = re.compile(
    r"\b(?:pip3?|pipx|uv|poetry|npm|pnpm|yarn|bun|go)\b[^\n]*?\b(?:install|add|get|i)\b"
)
_PIP_SPEC_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?"
    r"(?:\s*(?P<op>===|==|~=|>=|<=|!=|>|<)\s*(?P<version>\S+))?$"
)
_EXACT_PIP_VERSION_RE = re.compile(r"^[0-9][A-Za-z0-9._+-]*$")
_ARCHIVE_SUFFIXES = (".whl", ".tar.gz", ".tgz", ".zip", ".tar.bz2", ".egg")
_GO_MIN_MODULE_PARTS = 2

StatusChecker = Callable[[str, str, str, dict[str, Any]], str]

# Widely used packages that sit one edit away from a name in the popular
# list used for look-alike detection (``preact`` vs ``react``, ``pyaml`` vs
# ``pyyaml``). They are never reported as typosquats. A package that is itself
# in that popular list is never flagged either.
KNOWN_LEGITIMATE_PACKAGES = {
    ECOSYSTEM_PYPI: frozenset(
        {
            "pyaml", "numba", "pandera", "pandas-stubs", "flake8", "flask-cors",
            "flask-login", "django-environ", "djangorestframework", "pytest-cov",
            "pytest-mock", "pytest-xdist", "requests-mock", "requests-oauthlib",
            "boto", "botocore", "sqlmodel", "fastapi-users", "celery-types",
            "pillow-heif", "cryptography-vectors", "urllib3-secure-extra",
        }
    ),
    ECOSYSTEM_NPM: frozenset(
        {
            "preact", "react-dom", "react-is", "react-router", "react-native",
            "reactflow", "redux", "vuex", "vite", "vitest", "nuxt", "next-auth",
            "axios-retry", "express-session", "lodash-es", "webpack-cli",
            "ts-node", "typescript-eslint", "jest-cli",
        }
    ),
}  # fmt: skip
CONFIG_ALLOW_KEY = "hooks_allow_packages"


def looks_like_install_command(command: str) -> bool:
    return bool(command) and bool(INSTALL_COMMAND_HINT_RE.search(command))


def install_command_packages(command: str) -> list[dict[str, Any]]:
    """Return registry packages named by install commands in ``command``.

    Each entry: ``ecosystem``, ``name``, ``version`` ("" when unpinned or a
    range), ``private`` (alternate index/registry in use, so the public
    registry is not authoritative).
    """
    if not isinstance(command, str) or len(command) > MAX_COMMAND_CHARS:
        return []
    if not looks_like_install_command(command):
        return []
    spaced = _space_shell_command_separators(command)
    try:
        tokens = shlex.split(spaced, comments=True, posix=True)
    except ValueError:
        tokens = spaced.split()

    packages: list[dict[str, Any]] = []
    for idx in range(len(tokens)):
        prefix = _command_prefix_tokens(tokens, idx)
        pip_start = _pip_install_args_start(tokens, idx)
        if pip_start is not None:
            packages.extend(_pip_packages(tokens[pip_start:], prefix))
            continue
        npm_start = _npm_install_args_start(tokens, idx)
        if npm_start is not None:
            packages.extend(_npm_packages(tokens[npm_start:], prefix))
            continue
        go_start = _go_install_args_start(tokens, idx)
        if go_start is not None:
            packages.extend(_go_packages(tokens[go_start:]))
    return _dedupe(packages)[:MAX_PACKAGES_PER_COMMAND]


def check_install_command(
    command: str,
    repo_root: str | Path | None = None,
    *,
    status_checker: StatusChecker | None = None,
    cache_root: str | Path | None = None,
) -> dict[str, Any]:
    """Check packages in ``command`` against their public registries.

    ``repo_root`` supplies the project config (allowlist); registry answers
    are cached under ``cache_root`` (default: ``repo_root``).

    Returns ``{"packages": [...], "findings": [...], "unverified": [...]}``.
    A finding means the package does not exist, the pinned version does not
    exist, or the name is a one-edit look-alike of a popular package.
    ``unverified`` lists packages that could not be checked (private
    registry, network failure); callers must treat them as allowed.
    """
    packages = install_command_packages(command)
    result: dict[str, Any] = {"packages": packages, "findings": [], "unverified": []}
    if not packages:
        return result

    checker = status_checker or check_install_package_status
    root = _existing_dir(repo_root)
    allowed = _user_allowed_packages(root)
    kept = []
    for package in packages:
        if _allowed(package, allowed):
            result["unverified"].append({**package, "reason": "allowlisted"})
        else:
            kept.append(package)
    packages = kept
    store = _existing_dir(cache_root) if cache_root is not None else root
    cache = _load_version_cache(store) if store is not None else {"statuses": {}}
    cache_changed = False

    public = [package for package in packages if not package["private"]]
    for package in packages:
        if package["private"]:
            result["unverified"].append({**package, "reason": "private registry"})
    statuses = _lookup_statuses(public, cache, checker)

    for package, (status, fresh) in zip(public, statuses):
        if fresh and _record_status(package, cache, status):
            cache_changed = True
        state = normalize_dependency_truth_state(status)
        finding = _finding(package, state)
        if finding is not None:
            result["findings"].append(finding)
        elif state == DependencyTruthState.UNKNOWN:
            result["unverified"].append({**package, "reason": "registry unreachable"})

    if cache_changed and store is not None:
        _save_version_cache(store, cache)
    return result


def _lookup_statuses(
    packages: list[dict[str, Any]],
    cache: dict[str, Any],
    checker: StatusChecker,
) -> list[tuple[str, bool]]:
    """Cached status or a registry lookup per package; lookups run in parallel."""
    results: list[tuple[str, bool] | None] = []
    pending: list[int] = []
    for idx, package in enumerate(packages):
        cached = _cached_status(package, cache)
        results.append((cached, False) if cached is not None else None)
        if cached is None:
            pending.append(idx)
    if pending:
        from concurrent.futures import ThreadPoolExecutor

        def _check(idx: int) -> str:
            package = packages[idx]
            try:
                return checker(
                    package["ecosystem"], package["name"], package["version"], cache
                )
            except Exception:
                return STATUS_UNKNOWN

        with ThreadPoolExecutor(max_workers=min(8, len(pending))) as pool:
            for idx, status in zip(pending, pool.map(_check, pending)):
                results[idx] = (status, True)
    return [item if item is not None else (STATUS_UNKNOWN, False) for item in results]


def check_install_package_status(
    ecosystem: str, name: str, version: str, cache: dict[str, Any]
) -> str:
    if ecosystem == ECOSYSTEM_GO:
        return _check_go_module_exists(name)
    if version:
        return check_dependency_version_status(ecosystem, name, version, cache)
    if ecosystem == ECOSYSTEM_PYPI:
        path = _safe_pypi_package_path(name)
        if path is None:
            return STATUS_UNKNOWN
        return _check_registry_package_url(
            f"{PYPI_JSON_ORIGIN}/{path}/json",
            user_agent="skylos-pypi-dep-scanner/1.0",
        )
    if ecosystem == ECOSYSTEM_NPM:
        path = _safe_npm_package_path(name)
        if path is None:
            return STATUS_UNKNOWN
        return _check_registry_package_url(
            f"{NPM_REGISTRY_ORIGIN}/{path}",
            user_agent="skylos-npm-dep-scanner/1.0",
        )
    return STATUS_UNKNOWN


def _pip_packages(args: list[str], prefix: list[str]) -> list[dict[str, Any]]:
    private = _tokens_have_private_pip_index(args) or _tokens_have_private_registry_env(
        prefix, PIP_PRIVATE_REGISTRY_ENV_PREFIXES
    )
    packages = []
    for spec in _package_specs(args, value_flags=PIP_VALUE_FLAGS):
        parsed = _parse_pip_spec(spec)
        if parsed is None:
            continue
        name, version = parsed
        packages.append(_package(ECOSYSTEM_PYPI, name, version, private))
    return packages


def _parse_pip_spec(spec: str) -> tuple[str, str] | None:
    raw = spec.strip()
    if not raw or "/" in raw or "\\" in raw or ":" in raw:
        return None
    if raw.lower().endswith(_ARCHIVE_SUFFIXES):
        return None
    if "@" in raw:
        # poetry/uv ``name@^1.2`` constraint; only the name is checkable.
        raw = raw.split("@", 1)[0].strip()
    match = _PIP_SPEC_RE.match(raw)
    if not match:
        return None
    version = ""
    if match.group("op") in {"==", "==="}:
        candidate = match.group("version") or ""
        if _EXACT_PIP_VERSION_RE.match(candidate) and "*" not in candidate:
            version = candidate
    return match.group("name"), version


def _npm_packages(args: list[str], prefix: list[str]) -> list[dict[str, Any]]:
    private = _tokens_have_private_registry_option(
        args, NPM_PRIVATE_REGISTRY_FLAGS
    ) or _tokens_have_private_registry_env(prefix, NPM_PRIVATE_REGISTRY_ENV_PREFIXES)
    packages = []
    for spec in _package_specs(args, value_flags=NPM_VALUE_FLAGS):
        parsed = _parse_npm_spec(spec)
        if parsed is None:
            continue
        name, version = parsed
        packages.append(_package(ECOSYSTEM_NPM, name, version, private))
    return packages


def _parse_npm_spec(spec: str) -> tuple[str, str] | None:
    raw = spec.strip()
    if not raw or ":" in raw:
        return None
    split_at = raw.rfind("@")
    if split_at > 0:
        name, version_spec = raw[:split_at], raw[split_at + 1 :]
    else:
        name, version_spec = raw, ""
    if _safe_npm_package_path(name) is None:
        return None
    version = ""
    if version_spec:
        classified = _classify_npm_registry_spec(version_spec)
        if classified is None:
            return None
        lookup, exact = classified
        version = lookup if exact else ""
    return name, version


def _go_packages(args: list[str]) -> list[dict[str, Any]]:
    packages = []
    for spec in _package_specs(args, value_flags=set()):
        name = spec.strip().split("@", 1)[0]
        parts = name.split("/")
        if len(parts) < _GO_MIN_MODULE_PARTS or "." not in parts[0]:
            continue  # local package pattern such as ./... or a stdlib path
        if not all(_safe_go_path_part(part) for part in parts):
            continue
        packages.append(_package(ECOSYSTEM_GO, name, "", False))
    return packages


def _check_go_module_exists(name: str) -> str:
    """A Go import path exists if it or any parent path is a proxied module."""
    parts = name.split("/")
    saw_unknown = False
    for end in range(len(parts), _GO_MIN_MODULE_PARTS - 1, -1):
        module = "/".join(_go_escape(part) for part in parts[:end])
        status = _registry_http_status(
            f"{GO_PROXY_ORIGIN}/{module}/@v/list",
            user_agent="skylos-go-dep-scanner/1.0",
        )
        if status == 200:
            return STATUS_PRESENT
        if status != 404 and status != 410:
            saw_unknown = True
    return STATUS_UNKNOWN if saw_unknown else STATUS_MISSING_PACKAGE


def _go_escape(part: str) -> str:
    # Module proxy case-encoding: uppercase letters become "!" + lowercase.
    return "".join(f"!{ch.lower()}" if ch.isupper() else ch for ch in part)


def _package(ecosystem: str, name: str, version: str, private: bool) -> dict[str, Any]:
    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "private": bool(private),
    }


def _dedupe(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    unique = []
    for package in packages:
        key = (package["ecosystem"], package["name"].lower(), package["version"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(package)
    return unique


def _cache_key(package: dict[str, Any]) -> str:
    return dependency_truth_cache_key(
        package["ecosystem"],
        package["name"],
        package["version"] or PACKAGE_ONLY_VERSION,
    )


def _cached_status(package: dict[str, Any], cache: dict[str, Any]) -> str | None:
    statuses = cache.get("statuses")
    if not isinstance(statuses, dict):
        return None
    value = statuses.get(_cache_key(package))
    if not isinstance(value, str):
        return None
    state = normalize_dependency_truth_state(value)
    return state.value if state in AUTHORITATIVE_CACHE_STATES else None


def _record_status(package: dict[str, Any], cache: dict[str, Any], status: str) -> bool:
    state = normalize_dependency_truth_state(status)
    if state not in AUTHORITATIVE_CACHE_STATES:
        return False
    statuses = cache.setdefault("statuses", {})
    if not isinstance(statuses, dict):
        return False
    key = _cache_key(package)
    if statuses.get(key) == state.value:
        return False
    statuses[key] = state.value
    return True


def _finding(
    package: dict[str, Any], state: DependencyTruthState
) -> dict[str, Any] | None:
    ecosystem = package["ecosystem"]
    name = package["name"]
    registry = _REGISTRY_LABELS.get(ecosystem, "its registry")
    if state == DependencyTruthState.MISSING_PACKAGE:
        return {
            **package,
            "state": state.value,
            "rule_id": "SKY-D222",
            "message": f"{ecosystem} package '{name}' does not exist on {registry} "
            "(likely hallucinated; an attacker can register it).",
        }
    if state == DependencyTruthState.MISSING_VERSION:
        return {
            **package,
            "state": state.value,
            "rule_id": "SKY-D225",
            "message": f"{ecosystem} package '{name}' has no version "
            f"'{package['version']}' on {registry}.",
        }
    if state == DependencyTruthState.PRESENT:
        if _normalized(name) in _KNOWN_LEGITIMATE_NORMALIZED.get(ecosystem, set()):
            return None
        reason = _suspicious_existing_dependency_reason(
            {"ecosystem": ecosystem, "name": name}, []
        )
        if reason:
            return {
                **package,
                "state": DependencyTruthState.SUSPICIOUS_EXISTING.value,
                "rule_id": "SKY-D222",
                "message": f"{ecosystem} package '{name}' exists but is a possible "
                f"typosquat: {reason}.",
            }
    return None


_REGISTRY_LABELS = {
    ECOSYSTEM_PYPI: "PyPI",
    ECOSYSTEM_NPM: "the npm registry",
    ECOSYSTEM_GO: "the Go module proxy",
}


def _normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


_KNOWN_LEGITIMATE_NORMALIZED = {
    ecosystem: {_normalized(name) for name in names}
    for ecosystem, names in KNOWN_LEGITIMATE_PACKAGES.items()
}
_ECOSYSTEM_PREFIXES = {
    "pypi": ECOSYSTEM_PYPI,
    "pip": ECOSYSTEM_PYPI,
    "npm": ECOSYSTEM_NPM,
    "go": ECOSYSTEM_GO,
}


def _user_allowed_packages(root: Path | None) -> set[tuple[str, str]]:
    """``[tool.skylos] hooks_allow_packages`` from the project's pyproject.toml.

    Entries are package names (any ecosystem) or ``npm:name`` / ``pypi:name``
    / ``go:module``. Allowed packages skip every registry check (use it for
    internal packages and deliberate look-alikes).
    """
    if root is None:
        return set()
    pyproject = root / "pyproject.toml"
    try:
        if not pyproject.is_file() or pyproject.stat().st_size > 2_000_000:
            return set()
        try:
            import tomllib
        except ModuleNotFoundError:  # Python < 3.11
            import tomli as tomllib  # type: ignore[no-redef]
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except Exception:
        return set()
    raw = data.get("tool", {}).get("skylos", {}).get(CONFIG_ALLOW_KEY)
    if not isinstance(raw, list):
        return set()
    allowed: set[tuple[str, str]] = set()
    for entry in raw:
        if not isinstance(entry, str) or not entry.strip():
            continue
        prefix, sep, rest = entry.strip().partition(":")
        ecosystem = _ECOSYSTEM_PREFIXES.get(prefix.lower()) if sep else None
        if ecosystem is not None:
            allowed.add((ecosystem, _normalized(rest)))
        else:
            allowed.add(("*", _normalized(entry)))
    return allowed


def _allowed(package: dict[str, Any], allowed: set[tuple[str, str]]) -> bool:
    name = _normalized(package["name"])
    return (package["ecosystem"], name) in allowed or ("*", name) in allowed


def _existing_dir(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    try:
        path = Path(value).resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    return path if path.is_dir() else None


__all__ = [
    "check_install_command",
    "check_install_package_status",
    "install_command_packages",
    "looks_like_install_command",
]
