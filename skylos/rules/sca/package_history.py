"""Declared dependencies whose name is new or barely used on its registry.

A package name an AI model invented and someone then registered
(slopsquatting) exists, so the existence checks pass. ca9
(``ca9.api.package_history``) reads what the uploader cannot backdate: when
the project was first published and how many releases it has. Skylos reports
``SKY-SCA-NEW001`` for a direct dependency that is

- ``new``: first published less than 30 days ago, or
- ``thin_history``: less than 180 days old with at most 2 releases.

Measured on 2,521 declared dependencies of 184 popular Python projects, 0.6%
match; they are mostly a project's own brand-new packages. The finding asks
for a check, it does not say the package is malicious: the message links the
registry page and names the two ways out, removing the dependency or listing
it in ``approved_packages`` under ``[tool.skylos.supply_chain]``.

Pinned dependencies come from the dependency inventory. PyPI names declared
without a version (``fitz``, ``flask>=3``) are read from the manifests too,
because that is how an invented name is usually added.

Never looked up: transitive dependencies, packages matching
``internal_packages``, packages resolved from a registry other than the
public one (their names must not reach a public registry), and approved
packages. When the policy lists private registries but no
``internal_packages`` patterns, names declared without a version are not
looked up either: nothing says which of them are private. A registry that cannot be read is counted in the receipt as
``unknown`` and reported as nothing.
"""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from skylos.rules.sca.package_sources import PUBLIC_REGISTRY_URLS

logger = logging.getLogger(__name__)

RULE_UNPROVEN_PACKAGE = "SKY-SCA-NEW001"
NOTE_HISTORY_UNAVAILABLE = "ca9_package_history_unavailable"
NOTE_HISTORY_CAPPED = "package_history_lookup_cap_reached"
NOTE_NAMES_NOT_CHECKED = (
    "declared_names_not_checked_private_registries_without_internal_packages"
)
MAX_MANIFEST_BYTES = 2_000_000
_PYPI_MANIFESTS = ("pyproject.toml", "setup.cfg", "setup.py")
MAX_HISTORY_LOOKUPS = 300
HISTORY_WORKERS = 8
UNPROVEN_STATUSES = frozenset({"new", "thin_history"})
_CA9_ECOSYSTEMS = {"npm": "npm", "PyPI": "pypi"}
_REGISTRY_LABELS = {"pypi": "PyPI", "npm": "npm"}
_PUBLIC_REGISTRIES = frozenset(PUBLIC_REGISTRY_URLS) | frozenset(
    PUBLIC_REGISTRY_URLS.values()
)


def history_function(api: Any):
    function = getattr(api, "package_history", None) if api is not None else None
    return function if callable(function) else None


def describe_history(history: dict) -> str:
    """One sentence of facts for a ``new`` or ``thin_history`` result."""
    label = _REGISTRY_LABELS.get(str(history.get("ecosystem")), "the registry")
    age = history.get("age_days")
    count = history.get("release_count")
    parts = []
    if isinstance(age, int):
        parts.append(f"first published on {label} {_days(age)} ago")
    if isinstance(count, int):
        parts.append(f"{count} release{'s' if count != 1 else ''}")
    owners = [str(owner) for owner in history.get("owners") or [] if owner][:3]
    if owners:
        parts.append("published by " + ", ".join(owners))
    return ", ".join(parts) or f"new on {label}"


def _days(age: int) -> str:
    return "less than a day" if age < 1 else f"{age} day{'s' if age != 1 else ''}"


def history_metadata(history: dict) -> dict:
    """The facts and links a reviewer needs, bounded for reports and uploads."""
    return {
        "history_status": str(history.get("status") or ""),
        "first_published_at": history.get("first_published_at"),
        "latest_published_at": history.get("latest_published_at"),
        "age_days": history.get("age_days"),
        "release_count": history.get("release_count"),
        "owners": [str(owner)[:100] for owner in (history.get("owners") or [])[:10]],
        "source_url": _link(history.get("source_url")),
        "registry_url": _link(history.get("registry_url")),
        "report_url": _link(history.get("report_url")),
    }


def _link(value: object) -> str | None:
    if isinstance(value, str) and value.startswith("https://") and len(value) <= 300:
        return value
    return None


def _candidates(inventory, policy) -> tuple[list[dict], dict[str, int]]:
    from skylos.commands.hook_locked_packages import is_internal

    skipped = {"transitive": 0, "internal": 0, "private_registry": 0, "approved": 0}
    seen: dict[tuple[str, str], dict] = {}
    for dependency in getattr(inventory, "occurrences", None) or list(inventory):
        ecosystem = _CA9_ECOSYSTEMS.get(dependency.get("ecosystem"))
        name = str(dependency.get("name") or "").strip()
        if ecosystem is None or not name:
            continue
        lockfile = "lockfile_version" in dependency
        if lockfile and dependency.get("dependency_kind") != "direct":
            skipped["transitive"] += 1
            continue
        key = (ecosystem, name.lower())
        if key in seen:
            continue
        registry = dependency.get("registry")
        if registry and registry not in _PUBLIC_REGISTRIES:
            skipped["private_registry"] += 1
            continue
        if is_internal(ecosystem, name, tuple(policy.internal_packages)):
            skipped["internal"] += 1
            continue
        if policy.is_approved(ecosystem, name):
            skipped["approved"] += 1
            continue
        seen[key] = {
            "ecosystem": ecosystem,
            "skylos_ecosystem": dependency.get("ecosystem"),
            "name": name,
            "version": str(dependency.get("version") or ""),
            "dev": dependency.get("dependency_dev") is True,
            "file": str(dependency.get("file") or ""),
            "line": dependency.get("line") or 1,
            "snippet": dependency.get("snippet") or "",
        }
    return list(seen.values()), skipped


def _declared_pypi_names(root: Path) -> set[str]:
    from skylos.rules.ai_defect import dependency_hallucination as declared

    return set(declared._collect_declared_deps(root)) - set(
        declared._collect_project_names(root)
    )


def _manifest_texts(root: Path) -> list[tuple[str, list[str]]]:
    from skylos.core.safe_cache_io import read_project_text_no_symlink

    names = list(_PYPI_MANIFESTS)
    try:
        names += sorted(
            entry.name
            for entry in root.iterdir()
            if entry.name.startswith("requirements") and entry.name.endswith(".txt")
        )[:20]
    except OSError:
        pass
    texts = []
    for name in names:
        try:
            text = read_project_text_no_symlink(
                root, name, max_bytes=MAX_MANIFEST_BYTES
            )
        except (OSError, ValueError):
            text = None
        if text:
            texts.append((str(root / name), text.splitlines()))
    return texts


def _locate(name: str, texts: list[tuple[str, list[str]]]) -> tuple[str, int, str]:
    parts = [re.escape(part) for part in re.split(r"[-_.]+", name) if part]
    pattern = re.compile(
        r"(?<![\w.-])" + "[-_.]+".join(parts) + r"(?![\w.-])", re.IGNORECASE
    )
    for path, lines in texts:
        for number, line in enumerate(lines, start=1):
            if pattern.search(line.split("#", 1)[0]):
                return path, number, line.strip()[:200]
    return (texts[0][0] if texts else ""), 1, ""


def _named_candidates(
    root: Path | None, policy, seen: set[tuple[str, str]], skipped: dict
) -> tuple[list[dict], bool]:
    """PyPI names the manifests declare without a pinned version."""
    from skylos.commands.hook_locked_packages import is_internal

    if root is None:
        return [], False
    if policy.private_registries and not policy.internal_packages:
        return [], True
    try:
        names = sorted(_declared_pypi_names(root))
    except Exception as exc:  # noqa: BLE001 - a manifest that cannot be read adds nothing
        logger.debug("declared dependency names unavailable: %s", type(exc).__name__)
        return [], False
    texts = _manifest_texts(root)
    records = []
    for name in names:
        key = ("pypi", re.sub(r"[-_.]+", "-", name).lower())
        if key in seen:
            continue
        if is_internal("pypi", name, tuple(policy.internal_packages)):
            skipped["internal"] += 1
            continue
        if policy.is_approved("pypi", name):
            skipped["approved"] += 1
            continue
        file, line, snippet = _locate(name, texts)
        if not file:
            continue
        seen.add(key)
        records.append(
            {
                "ecosystem": "pypi",
                "skylos_ecosystem": "PyPI",
                "name": name,
                "version": "",
                "dev": False,
                "file": file,
                "line": line,
                "snippet": snippet,
            }
        )
    return records, False


def unproven_message(label: str, name: str, history: dict) -> str:
    registry_url = _link(history.get("registry_url"))
    where = f" ({registry_url})" if registry_url else ""
    return (
        f"{label} package '{name}' has little history: {describe_history(history)}. "
        f"Check it is the package you meant{where}. If it is, add it to "
        "approved_packages under [tool.skylos.supply_chain]; if not, remove it."
    )


def _finding(record: dict, history: dict, mode: str) -> dict:
    label = _REGISTRY_LABELS[record["ecosystem"]]
    return {
        "rule_id": RULE_UNPROVEN_PACKAGE,
        "category": "DEPENDENCY",
        "severity": "HIGH" if mode == "block" else "MEDIUM",
        "message": unproven_message(label, record["name"], history),
        "file": record["file"],
        "file_path": record["file"],
        "line": record["line"],
        "line_number": record["line"],
        "snippet": record["snippet"],
        "symbol": record["name"],
        "metadata": {
            "ecosystem": record["skylos_ecosystem"],
            "package_name": record["name"],
            "package_version": record["version"] or None,
            "supply_chain_signal": "unproven_package",
            "engine": "ca9",
            "action": mode,
            "dependency_kind": "direct",
            "dependency_dev": record["dev"],
            "approve_with": f"{record['ecosystem']}:{record['name']}",
            **history_metadata(history),
        },
    }


def evaluate_package_history(
    inventory, policy, *, api=None, root: Path | None = None
) -> tuple[list[dict], dict]:
    """``SKY-SCA-NEW001`` findings for ``inventory`` and a receipt."""
    mode = getattr(policy, "unproven_packages", "warn")
    receipt: dict[str, Any] = {"engine": "ca9", "mode": mode, "notes": []}
    if mode == "off":
        receipt["status"] = "off"
        return [], receipt
    lookup = history_function(api)
    if lookup is None:
        receipt["status"] = "unavailable"
        receipt["notes"].append(NOTE_HISTORY_UNAVAILABLE)
        return [], receipt
    records, skipped = _candidates(inventory, policy)
    seen = {
        (record["ecosystem"], re.sub(r"[-_.]+", "-", record["name"]).lower())
        if record["ecosystem"] == "pypi"
        else (record["ecosystem"], record["name"].lower())
        for record in records
    }
    named, names_withheld = _named_candidates(root, policy, seen, skipped)
    records += named
    if names_withheld:
        receipt["notes"].append(NOTE_NAMES_NOT_CHECKED)
    receipt["skipped"] = {key: count for key, count in skipped.items() if count}
    if len(records) > MAX_HISTORY_LOOKUPS:
        receipt["notes"].append(NOTE_HISTORY_CAPPED)
        receipt["not_checked"] = len(records) - MAX_HISTORY_LOOKUPS
        records = records[:MAX_HISTORY_LOOKUPS]
    receipt["packages"] = len(records)

    def check(record: dict) -> dict:
        try:
            result = lookup(record["ecosystem"], record["name"])
        except Exception as exc:  # noqa: BLE001 - one lookup never fails the scan
            logger.debug("package history lookup failed: %s", type(exc).__name__)
            return {"status": "unknown"}
        return result if isinstance(result, dict) else {"status": "unknown"}

    if records:
        with ThreadPoolExecutor(max_workers=HISTORY_WORKERS) as pool:
            results = list(pool.map(check, records))
    else:
        results = []
    findings: list[dict] = []
    counts: dict[str, int] = {}
    for record, history in zip(records, results):
        status = str(history.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
        if status in UNPROVEN_STATUSES:
            findings.append(_finding(record, history, mode))
    receipt["results"] = counts
    receipt["status"] = (
        "incomplete"
        if counts.get("unknown") or NOTE_HISTORY_CAPPED in receipt["notes"]
        else "complete"
    )
    return findings, receipt
