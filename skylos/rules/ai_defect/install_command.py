"""Hallucinated / look-alike package checks for a single shell install command.

The install-surface scanner in ``manifest_dependency_hallucination`` only
checks pinned specs found in files. An agent typing ``pip install foo`` is the
opposite case: one command, usually unpinned, checked *before* it runs.
:mod:`skylos.commands.hook_install_parse` reads the command (install
commands, one-shot runners such as ``npx``/``uvx``/``pnpm dlx``, direct git
and URL sources, registry overrides); this module checks the registry
packages and sorts everything into explicit outcomes. Nothing it cannot
check is reported as checked.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from skylos.commands.hook_install_parse import (
    JSR,
    OUTCOME_DYNAMIC,
    REGISTRY,
    InstallTarget,
    install_targets,
    looks_like_install,
    split_targets,
)
from skylos.commands.hook_registry_context import (
    RegistryContext,
    is_trusted,
    registry_context,
)
from skylos.rules.ai_defect.dependency_truth import (
    DependencyTruthState,
    dependency_truth_cache_key,
    normalize_dependency_truth_state,
)
from skylos.rules.ai_defect.manifest_dependency_hallucination import (
    AUTHORITATIVE_CACHE_STATES,
    GO_PROXY_ORIGIN,
    NPM_REGISTRY_ORIGIN,
    PYPI_JSON_ORIGIN,
    STATUS_MISSING_PACKAGE,
    STATUS_MISSING_VERSION,
    STATUS_PRESENT,
    STATUS_UNKNOWN,
    _check_registry_package_url,
    _load_version_cache,
    _registry_http_status,
    _safe_npm_package_path,
    _safe_pypi_package_path,
    _save_version_cache,
    _suspicious_existing_dependency_reason,
    check_dependency_version_status,
)
from skylos.rules.sca.vulnerability_scanner import (
    ECOSYSTEM_GO,
    ECOSYSTEM_NPM,
    ECOSYSTEM_PYPI,
)

PACKAGE_ONLY_VERSION = "<package-only>"
MAX_COMMAND_CHARS = 20_000
MAX_PACKAGES_PER_COMMAND = 25
JSR_ORIGIN = "https://jsr.io"

# Outcomes of entries in ``unverified``. The hook allows "allowlisted" and
# "private" (the user configured them); every other outcome goes through the
# project's hook policy, which by default asks the user.
OUTCOME_ALLOWLISTED = "allowlisted"
OUTCOME_PRIVATE = "private"
OUTCOME_REGISTRY_OVERRIDE = "registry_override"
OUTCOME_NOT_PUBLIC = "not_public"
OUTCOME_UNREACHABLE = "unreachable"
OUTCOME_TOO_MANY = "too_many"

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
    return looks_like_install(command)


def install_command_packages(
    command: str, cwd: str | Path | None = None
) -> list[dict[str, Any]]:
    """Return registry packages named by install commands in ``command``.

    Each entry: ``ecosystem``, ``name``, ``version`` ("" when unpinned or a
    range), ``private`` (alternate index/registry in use, so the public
    registry is not authoritative).
    """
    targets = _parse(command, Path(cwd) if cwd is not None else Path.cwd(), None)
    packages = [
        _package_from_target(target) for target in targets if target.kind == REGISTRY
    ]
    return _dedupe(packages)[:MAX_PACKAGES_PER_COMMAND]


def check_install_command(
    command: str,
    repo_root: str | Path | None = None,
    *,
    status_checker: StatusChecker | None = None,
    cache_root: str | Path | None = None,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    trusted_registries: tuple[str, ...] | None = None,
    context: RegistryContext | None = None,
    home: str | Path | None = None,
    targets: list[InstallTarget] | None = None,
) -> dict[str, Any]:
    """Check what ``command`` installs and sort it into explicit outcomes.

    ``repo_root`` supplies the project config (allowlist, trusted
    registries); registry answers are cached under ``cache_root`` (default:
    ``repo_root``).

    Returns a dict with:

    * ``packages``: registry packages the command names;
    * ``findings``: packages that do not exist, pinned versions that do not
      exist, and one-edit look-alikes of popular packages (block);
    * ``unverified``: packages not checked or not checkable, each with a
      ``reason`` and an ``outcome`` (see the ``OUTCOME_*`` constants);
    * ``direct``: code fetched from outside a registry (git, URL, tarball,
      archive outside the project);
    * ``local`` / ``manifest``: counts of local and manifest installs.

    ``targets`` skips parsing when the caller already parsed ``command``.
    """
    root = _existing_dir(repo_root)
    base = Path(cwd) if cwd is not None else (root or Path.cwd())
    if targets is None:
        targets = _parse(command, base, root)
    registry_targets, result = split_targets(targets)
    if not registry_targets:
        return result

    if trusted_registries is None:
        from skylos.commands.hook_install_policy import load_install_policy

        trusted_registries = load_install_policy(root).trusted_registries
    trusted = tuple(trusted_registries or ())

    packages = _dedupe([_package_from_target(t) for t in registry_targets])
    result["packages"] = packages[:MAX_PACKAGES_PER_COMMAND]
    for package in packages[MAX_PACKAGES_PER_COMMAND:]:
        result["unverified"].append(
            {
                **package,
                "reason": "too many packages in one command",
                "outcome": OUTCOME_TOO_MANY,
            }
        )
    packages = packages[:MAX_PACKAGES_PER_COMMAND]
    if not packages:
        return result

    allowed = _user_allowed_packages(root)
    if context is None:
        context = registry_context(
            root, base, env or {}, Path(home) if home is not None else None
        )
    to_check: list[dict[str, Any]] = []
    for package in packages:
        entry = _route(package, allowed, trusted, context)
        if entry is None:
            to_check.append(package)
        else:
            result["unverified"].append(entry)
    if not to_check:
        return result

    checker = status_checker or check_install_package_status
    store = _existing_dir(cache_root) if cache_root is not None else root
    cache = _load_version_cache(store) if store is not None else {"statuses": {}}
    cache_changed = False
    statuses = _lookup_statuses(to_check, cache, checker)
    for package, (status, fresh) in zip(to_check, statuses):
        if fresh and _record_status(package, cache, status):
            cache_changed = True
        state = normalize_dependency_truth_state(status)
        alternates = package.get("alternate") or []
        if (
            state
            in {
                DependencyTruthState.MISSING_PACKAGE,
                DependencyTruthState.MISSING_VERSION,
            }
            and alternates
        ):
            registry = alternates[0]
            outcome = (
                OUTCOME_PRIVATE if is_trusted(registry, trusted) else OUTCOME_NOT_PUBLIC
            )
            result["unverified"].append(
                {
                    **package,
                    "outcome": outcome,
                    "registry": registry,
                    "reason": f"not on {_REGISTRY_LABELS.get(package['ecosystem'], 'the public registry')}; "
                    f"may be on {_registry_label(registry)}",
                }
            )
            continue
        finding = _finding(package, state)
        if finding is not None:
            result["findings"].append(finding)
        elif state == DependencyTruthState.UNKNOWN:
            result["unverified"].append(
                {
                    **package,
                    "reason": "registry unreachable",
                    "outcome": OUTCOME_UNREACHABLE,
                }
            )

    if cache_changed and store is not None:
        _save_version_cache(store, cache)
    return result


def _parse(command: str, cwd: Path, root: Path | None) -> list[InstallTarget]:
    if not isinstance(command, str) or len(command) > MAX_COMMAND_CHARS:
        return []
    if not looks_like_install(command):
        return []
    return install_targets(command, cwd, root=root)


def _route(
    package: dict[str, Any],
    allowed: set[tuple[str, str]],
    trusted: tuple[str, ...],
    context: RegistryContext,
) -> dict[str, Any] | None:
    """An ``unverified`` entry for a package that skips the public check,
    or None when the public registry should be asked."""
    if _allowed(package, allowed):
        return {**package, "reason": "allowlisted", "outcome": OUTCOME_ALLOWLISTED}
    registries = package.get("registries") or []
    if registries:
        if all(is_trusted(r, trusted) for r in registries):
            return {**package, "reason": "trusted registry", "outcome": OUTCOME_PRIVATE,
                    "registry": registries[0]}  # fmt: skip
        if any(r.startswith("configured:") for r in registries):
            package["alternate"] = [r for r in registries]
            return None
        untrusted = next(r for r in registries if not is_trusted(r, trusted))
        return {**package, "reason": "private registry",
                "outcome": OUTCOME_REGISTRY_OVERRIDE, "registry": untrusted}  # fmt: skip
    ecosystem, name = package["ecosystem"], package["name"]
    if ecosystem == ECOSYSTEM_GO and context.go_is_private(name):
        return {**package, "reason": "GOPRIVATE module", "outcome": OUTCOME_PRIVATE}
    scoped = context.scoped(ecosystem, name)
    if scoped is not None:
        outcome = OUTCOME_PRIVATE if is_trusted(scoped, trusted) else OUTCOME_NOT_PUBLIC
        return {**package, "registry": scoped, "outcome": outcome,
                "reason": f"scope registry {scoped}"}  # fmt: skip
    alternates = context.alternate(ecosystem, name)
    if alternates:
        package["alternate"] = alternates
    return None


def _registry_label(registry: str) -> str:
    if registry.startswith("configured:"):
        return registry.split(":", 1)[1]
    return f"the configured registry {registry}"


def _package_from_target(target: InstallTarget) -> dict[str, Any]:
    package = {
        "ecosystem": target.ecosystem,
        "name": target.name,
        "version": target.version,
        "private": bool(target.registries),
        "tool": target.tool,
        "runs": target.runs,
    }
    if target.registries:
        package["registries"] = list(target.registries)
    return package


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
    if ecosystem == JSR:
        return _check_jsr_package(name, version)
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


_JSR_NAME_RE = re.compile(r"^@[a-z0-9-]+/[a-z0-9-]+$")
_JSR_VERSION_RE = re.compile(r"^[0-9][A-Za-z0-9.+-]*$")


def _check_jsr_package(name: str, version: str) -> str:
    if not _JSR_NAME_RE.match(name):
        return STATUS_UNKNOWN
    package_url = f"{JSR_ORIGIN}/{name}/meta.json"
    if version and _JSR_VERSION_RE.match(version):
        status = _registry_http_status(
            f"{JSR_ORIGIN}/{name}/{version}_meta.json", user_agent="skylos-jsr/1.0"
        )
        if status == 200:
            return STATUS_PRESENT
        if status not in {404, 410}:
            return STATUS_UNKNOWN
        package = _registry_http_status(package_url, user_agent="skylos-jsr/1.0")
        if package == 200:
            return STATUS_MISSING_VERSION
        return STATUS_MISSING_PACKAGE if package in {404, 410} else STATUS_UNKNOWN
    status = _registry_http_status(package_url, user_agent="skylos-jsr/1.0")
    if status == 200:
        return STATUS_PRESENT
    return STATUS_MISSING_PACKAGE if status in {404, 410} else STATUS_UNKNOWN


_GO_MIN_MODULE_PARTS = 2


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


def _dedupe(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, tuple[str, ...]]] = set()
    unique = []
    for package in packages:
        key = (
            package["ecosystem"],
            package["name"].lower(),
            package["version"],
            tuple(package.get("registries") or ()),
        )
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
    JSR: "JSR",
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
    "jsr": JSR,
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
    "OUTCOME_ALLOWLISTED",
    "OUTCOME_DYNAMIC",
    "OUTCOME_NOT_PUBLIC",
    "OUTCOME_PRIVATE",
    "OUTCOME_REGISTRY_OVERRIDE",
    "OUTCOME_TOO_MANY",
    "OUTCOME_UNREACHABLE",
    "check_install_command",
    "check_install_package_status",
    "install_command_packages",
    "looks_like_install_command",
]
