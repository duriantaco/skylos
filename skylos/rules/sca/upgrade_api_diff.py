"""``SKY-SCA-API001``: your lines that use API a locked upgrade removed.

For a Python package whose locked version changed base to head, both releases
are fetched and unpacked by ``ca9.artifacts`` and read with ``ast``; nothing is
installed, imported or run. Each public name, method and keyword your code uses
is compared across the two surfaces. Advice only: anything that could not be
read is listed under ``could_not_check`` in the receipt, never an analysis
error, and the rule does not count toward the gate.
"""

from __future__ import annotations

import re
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.ai_defect.api_signature_hallucination import (
    _MANIFEST_SKIP_DIRS,
    _source_mentions_allowed_root,
    _top_level_python_modules,
)
from skylos.rules.sca.python_api_references import Reference, references_in_source
from skylos.rules.sca.python_package_surface import (
    PackageSurface,
    SurfaceUnreadable,
    build_surface,
)
from skylos.rules.sca.supply_chain_diff import (
    _SKIP_PARTS,
    RULE_UPGRADE_API,
    GitSides,
    _finding,
    _review_options,
    _text,
)
from skylos.rules.sca.upgrade_api_compare import (
    Verdict,
    compare_reference,
    reference_symbol,
)
from skylos.rules.sca.upgrade_api_pairs import api_pairs

MAX_API_PAIRS = 25
MAX_SECONDS = 180
REQUEST_TIMEOUT = 20
MAX_ARTIFACT_BYTES = 50 * 1024 * 1024
MAX_EXTRACTED_FILES = 20_000
MAX_USER_FILES = 20_000
MAX_USER_FILE_BYTES = 32_000_000
MAX_USER_PARSE_CHARS = 2_000_000
MAX_SHOWN = 200
MAX_REASONS = 50
_VALID_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
_VALID_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_!-]*\Z")
_USER_SKIP_PARTS = frozenset(_SKIP_PARTS) | _MANIFEST_SKIP_DIRS


class CouldNotCheck(ValueError):
    """This release pair cannot be compared; the message says why."""


@dataclass
class _UserCode:
    references: dict[str, set[Reference]] = field(default_factory=dict)
    unreadable: list[tuple[str, str, str | None]] = field(default_factory=list)
    local_roots: set[str] = field(default_factory=set)
    files: int = 0
    limit_reason: str = ""


@dataclass
class _Run:
    sides: GitSides
    receipt: dict
    rows: list[dict]
    deadline: float
    ca9: Any = None
    internal: tuple[str, ...] = ()
    code: _UserCode | None = None
    findings: list[dict] = field(default_factory=list)
    sites: list[dict] = field(default_factory=list)


def _load_ca9() -> SimpleNamespace | None:
    try:
        from ca9.analyzers.supply_chain import internal_pattern_for
        from ca9.artifacts import ArtifactScanConfig, collect_artifact_snapshots
        from ca9.artifacts.releases import (
            pypi_release_entries,
            release_file,
            select_pypi_pair,
        )
        from ca9.core.models import Artifact, Inventory, Package
    except ImportError:
        return None
    return SimpleNamespace(
        Artifact=Artifact,
        ArtifactScanConfig=ArtifactScanConfig,
        Inventory=Inventory,
        Package=Package,
        collect_artifact_snapshots=collect_artifact_snapshots,
        internal_pattern_for=internal_pattern_for,
        pypi_release_entries=pypi_release_entries,
        release_file=release_file,
        select_pypi_pair=select_pypi_pair,
    )


def _snapshot(ca9, name: str, version: str, release, config) -> Any:
    package = ca9.Package(
        name=name,
        version=version,
        ecosystem="pypi",
        dependency_kind="unknown",
        artifacts=(
            ca9.Artifact(
                kind=release.kind,
                url=release.url,
                hash=release.hash,
                size=release.size,
            ),
        ),
    )
    collection = ca9.collect_artifact_snapshots(
        ca9.Inventory(repo_path=".", packages=(package,)), config
    )
    for finding in collection.findings:
        if finding.signal_type != "artifact_weak_integrity":
            reason = _text(finding.metadata.get("reason"), 160) or finding.signal_type
            raise CouldNotCheck(f"{release.filename} could not be read: {reason}")
    if len(collection.snapshots) != 1:
        raise CouldNotCheck(f"{release.filename} was not collected")
    return collection.snapshots[0]


def _release_surface(ca9, name, version, entry, basis, config, deadline):
    release = ca9.release_file(entry, basis)
    try:
        snapshot = _snapshot(ca9, name, version, release, config)
        return build_surface(snapshot.files, kind=release.kind, deadline=deadline)
    except SurfaceUnreadable as exc:
        raise CouldNotCheck(f"{name} {version}: {exc}") from None
    except CouldNotCheck:
        raise
    except Exception as exc:  # noqa: BLE001 - advice only: a failed download is a could-not-check row
        raise CouldNotCheck(f"the download failed: {_text(exc, 160)}") from None


def _release_surfaces(
    ca9, pair: dict, work: Path, deadline: float
) -> tuple[PackageSurface, PackageSurface, str]:
    name = pair["name"]
    config = ca9.ArtifactScanConfig(
        cache_dir=work,
        max_artifact_bytes=MAX_ARTIFACT_BYTES,
        max_extracted_files=MAX_EXTRACTED_FILES,
        allowed_local_roots=(),
        request_timeout=REQUEST_TIMEOUT,
        deadline=deadline,
    )
    try:
        old_entries = ca9.pypi_release_entries(name, pair["old"], None, config)
        new_entries = ca9.pypi_release_entries(name, pair["new"], None, config)
    except Exception as exc:  # noqa: BLE001 - advice only: a failed lookup is a could-not-check row
        raise CouldNotCheck(f"the release lookup failed: {_text(exc, 160)}") from None
    chosen = ca9.select_pypi_pair(old_entries, new_entries)
    if chosen is None:
        raise CouldNotCheck("the two releases share no wheel or sdist to compare")
    old_entry, new_entry, basis = chosen
    old = _release_surface(ca9, name, pair["old"], old_entry, basis, config, deadline)
    new = _release_surface(ca9, name, pair["new"], new_entry, basis, config, deadline)
    return old, new, basis


def _is_user_python(path: str) -> bool:
    if not path.endswith(".py"):
        return False
    return not any(part in _USER_SKIP_PARTS for part in path.split("/")[:-1])


def read_user_code(sides: GitSides, deadline: float) -> _UserCode:
    code = _UserCode()
    root = Path(sides.root)
    code.local_roots = _top_level_python_modules(root) | _top_level_python_modules(
        root / "src"
    )
    paths = sorted(path for path in sides.head_paths if _is_user_python(path))
    if len(paths) > MAX_USER_FILES:
        code.limit_reason = f"the repository has more than {MAX_USER_FILES:,} Python files"
        return code
    for path in paths:
        if time.monotonic() >= deadline:
            code.limit_reason = "the time limit was reached while reading your code"
            return code
        _read_user_file(code, root, path)
    return code


def _read_user_file(code: _UserCode, root: Path, path: str) -> None:
    target = root / path
    if target.is_symlink():
        return
    text = read_project_text_no_symlink(
        root, path, max_bytes=MAX_USER_FILE_BYTES, encoding="utf-8", errors="replace"
    )
    if text is None:
        if target.exists():
            code.unreadable.append((path, "it could not be read", None))
        return
    code.files += 1
    if len(text) > MAX_USER_PARSE_CHARS:
        code.unreadable.append((path, "it is too large to parse", text))
        return
    try:
        found = references_in_source(path, text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        code.unreadable.append((path, "it does not parse", text))
        return
    ignored, ignored_rules = _inline_ignores(text)
    for root_name, references in found.items():
        kept = code.references.setdefault(root_name, set())
        for reference in references:
            if reference.line in ignored or RULE_UPGRADE_API in ignored_rules.get(
                reference.line, ()
            ):
                reference = replace(reference, guarded=True)
            kept.add(reference)


def _inline_ignores(text: str) -> tuple[set[int], dict[int, set[str]]]:
    if "skylos" not in text:
        return set(), {}
    from skylos.config import get_skylos_ignore_lines, get_skylos_ignore_rules_by_line

    return get_skylos_ignore_lines(text), get_skylos_ignore_rules_by_line(text)


def _label(pair: dict) -> str:
    return f"{pair['name']} {pair['old']} to {pair['new']}"


def _message(verdict: Verdict, pair: dict) -> str:
    return (
        f"{verdict.change.capitalize()} `{verdict.symbol}` exists in {pair['name']} "
        f"{pair['old']} and was removed in {pair['new']}. This line uses it; "
        "update it before merging this upgrade, or keep the old version."
    )


def _site_finding(sides: GitSides, reference: Reference, verdict: Verdict, pair: dict):
    metadata = {
        "ecosystem": pair["ecosystem"],
        "package_name": pair["name"],
        "old_version": pair["old"],
        "package_version": pair["new"],
        "basis": "api_diff",
        "change": verdict.change,
        "symbol": verdict.symbol,
        "engine": "skylos",
        "base_commit": sides.commit,
    }
    return _finding(
        RULE_UPGRADE_API,
        "MEDIUM",
        _message(verdict, pair),
        Path(sides.root) / reference.file,
        reference.line,
        metadata,
        category="DEPENDENCY",
        snippet=reference.snippet,
    )


def _record_removed(run: _Run, reference: Reference, verdict: Verdict, pair: dict) -> None:
    run.findings.append(_site_finding(run.sides, reference, verdict, pair))
    run.sites.append(
        {
            "file": reference.file,
            "line": reference.line,
            "symbol": verdict.symbol,
            "package": pair["name"],
            "old": pair["old"],
            "new": pair["new"],
            "change": verdict.change,
        }
    )


def _tally_reference(run, reference, verdict, pair, tally, unknown) -> None:
    if verdict.status == "unknown":
        unknown.setdefault(verdict.reason, []).append(reference)
    elif verdict.status == "removed":
        tally["call_sites"] += 1
        if reference.guarded:
            tally["guarded"] += 1
        else:
            tally["review_sites"] += 1
            _record_removed(run, reference, verdict, pair)
    elif verdict.status == "ok":
        tally["call_sites"] += 1
        if verdict.change:
            tally["keywords_not_followed"] += 1
    else:
        tally[verdict.status] += 1


def _unknown_rows(run: _Run, pair: dict, unknown: dict) -> None:
    for reason, items in sorted(unknown.items()):
        first = items[0]
        run.rows.append(
            {
                "subject": _label(pair),
                "reason": _text(reason, 200),
                "symbol": reference_symbol(first),
                "file": first.file,
                "line": first.line,
                "count": len(items),
            }
        )


def _unreadable_rows(run: _Run, roots: set[str], pair: dict, entry: dict) -> None:
    for path, reason, text in run.code.unreadable:
        if text is not None and not _source_mentions_allowed_root(text, set(roots)):
            continue
        if entry["status"] == "not_used":
            entry["status"] = "partial"
        run.rows.append(
            {
                "subject": _label(pair),
                "reason": f"your file {path} was not read: {reason}",
                "file": path,
            }
        )


def _compare_pair(run: _Run, pair: dict, surfaces, entry: dict) -> None:
    old, new = surfaces
    roots = (old.roots | new.roots) - run.code.local_roots
    references: set[Reference] = set()
    for root in roots:
        references |= run.code.references.get(root, set())
    tally: Counter = Counter()
    unknown: dict[str, list[Reference]] = {}
    for reference in sorted(references, key=_reference_key):
        verdict = compare_reference(reference, old, new)
        _tally_reference(run, reference, verdict, pair, tally, unknown)
    entry["call_sites"] = tally["call_sites"]
    entry["review_sites"] = tally["review_sites"]
    for key in ("private", "keywords_not_followed", "guarded"):
        if tally[key]:
            entry[key] = tally[key]
    entry["status"] = "compared"
    if not tally["call_sites"] and not tally["private"]:
        entry["status"] = "not_used"
    if unknown:
        entry["status"] = "partial"
    _unknown_rows(run, pair, unknown)
    _unreadable_rows(run, roots, pair, entry)


def _reference_key(reference: Reference) -> tuple:
    return (reference.file, reference.line, reference.module, reference.path)


def _skip_reason(pair: dict, ca9, internal: tuple[str, ...]) -> str:
    if ca9 is None:
        return "ca9.artifacts is not installed or too old"
    valid = _VALID_NAME.fullmatch(str(pair["name"])) and all(
        _VALID_VERSION.fullmatch(str(pair[key])) for key in ("old", "new")
    )
    if not valid:
        return "the lockfile entry has an invalid name or version"
    if ca9.internal_pattern_for(pair["name"], internal) is not None:
        return "internal package names are never looked up on a public registry"
    return ""


def _add_row(run: _Run, pair: dict, reason: str, **extra: Any) -> None:
    run.rows.append({"subject": _label(pair), "reason": reason, **extra})


def _check_pair(run: _Run, pair: dict) -> None:
    entry = {
        "name": pair["name"],
        "ecosystem": pair["ecosystem"],
        "old": pair["old"],
        "new": pair["new"],
        "call_sites": 0,
        "review_sites": 0,
        "status": "could_not_check",
    }
    run.receipt["packages"].append(entry)
    if pair["ecosystem"] != "pypi":
        _add_row(
            run,
            pair,
            "only Python package APIs are compared so far",
            unsupported=True,
        )
        return
    reason = _skip_reason(pair, run.ca9, run.internal)
    if reason:
        _add_row(run, pair, reason)
        return
    if run.code is None:
        run.code = read_user_code(run.sides, run.deadline)
        run.receipt["files_read"] = run.code.files
    if run.code.limit_reason:
        _add_row(run, pair, run.code.limit_reason)
        return
    if time.monotonic() >= run.deadline:
        _add_row(run, pair, "the time limit was reached")
        return
    try:
        with tempfile.TemporaryDirectory(prefix="skylos-api-") as temp:
            old, new, basis = _release_surfaces(
                run.ca9, pair, Path(temp), run.deadline
            )
    except CouldNotCheck as exc:
        _add_row(run, pair, _text(exc, 240))
        return
    entry["basis"] = basis
    _compare_pair(run, pair, (old, new), entry)


def _finish(run: _Run) -> None:
    receipt = run.receipt
    rows = run.rows
    receipt["call_sites"] = sum(entry["call_sites"] for entry in receipt["packages"])
    receipt["review_sites"] = len(run.findings)
    receipt["sites"] = run.sites[:MAX_SHOWN]
    receipt["could_not_check"] = rows[:MAX_REASONS]
    if len(rows) > MAX_REASONS:
        receipt["could_not_check_omitted"] = len(rows) - MAX_REASONS
    receipt["status"] = "complete"
    if rows:
        receipt["status"] = "partial"


def _check(sides: GitSides, receipt: dict) -> list[dict]:
    pairs, rows, added = api_pairs(sides)
    receipt.update(
        {
            "status": "nothing_to_review",
            "call_sites": 0,
            "review_sites": 0,
            "packages": [],
            "sites": [],
            "could_not_check": rows,
        }
    )
    if added:
        receipt["new_packages"] = added
    if not pairs and not rows:
        return []
    run = _Run(
        sides,
        receipt,
        rows,
        time.monotonic() + MAX_SECONDS,
        ca9=_load_ca9(),
        internal=tuple(_review_options(sides.root).get("internal_packages") or ()),
    )
    if len(pairs) > MAX_API_PAIRS:
        rows.append(
            {
                "subject": f"{len(pairs) - MAX_API_PAIRS} more packages",
                "reason": f"over the limit of {MAX_API_PAIRS} packages",
            }
        )
    for pair in pairs[:MAX_API_PAIRS]:
        _check_pair(run, pair)
    _finish(run)
    return run.findings


def upgrade_api_findings(
    sides: GitSides, _api, receipt: dict, _errors: list
) -> list[dict]:
    """SKY-SCA-API001 findings. Advice only, so ``_errors`` is never touched:
    every failure becomes a could-not-check row in the receipt."""
    try:
        return _check(sides, receipt)
    except Exception as exc:  # noqa: BLE001 - advice must not stop the gate as incomplete
        receipt["status"] = "failed"
        receipt.setdefault("call_sites", 0)
        receipt.setdefault("review_sites", 0)
        receipt.setdefault("packages", [])
        receipt.setdefault("sites", [])
        receipt["could_not_check"] = [
            *receipt.get("could_not_check", []),
            {
                "subject": "dependency upgrades",
                "reason": f"the API comparison failed ({type(exc).__name__})",
            },
        ]
        return []


__all__ = [
    "Reference",
    "Verdict",
    "compare_reference",
    "read_user_code",
    "references_in_source",
    "upgrade_api_findings",
]
