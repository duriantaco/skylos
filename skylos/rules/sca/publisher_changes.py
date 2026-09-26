"""Optional, review-only npm publisher history checks backed by ca9.

Only validated direct dependencies from bounded package-lock snapshots are
submitted to ca9. This result is separate from OSV vulnerability findings.
"""

from __future__ import annotations

import io
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.sca.lockfile_types import LockfileParseError
from skylos.rules.sca.npm_lockfile import parse_package_lock

RULE_ID = "SKY-SCA-NPM-PUB001"
MAX_LOCKFILE_BYTES = 10_000_000
MAX_TOTAL_LOCKFILE_BYTES = 50_000_000
MAX_LOCKFILES = 1_000
MAX_PACKAGES = 5_000
MAX_PUBLISHER_CANDIDATES = 25
MAX_WALK_DIRECTORIES = 10_000
SKIP_DIRECTORIES = frozenset(
    {"node_modules", ".git", "__pycache__", ".venv", "venv", ".tox", "dist", "build"}
)


@dataclass
class PublisherScanResult:
    findings: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    receipt: dict = field(default_factory=dict)


@dataclass(frozen=True)
class _LockfileSnapshot:
    """Give ca9's reader the checked bytes without reopening target source.

    ca9's ``load_package_lock`` uses ``open``, ``parent`` and ``str`` on its path.
    The snapshot preserves the original path for evidence and artifact context.
    """

    path: Path
    text: str

    @property
    def parent(self) -> Path:
        return self.path.parent

    def open(self):
        return io.StringIO(self.text)

    def __str__(self) -> str:
        return str(self.path)


def _eligible_inventory_package(package) -> bool:
    """Keep location evidence only for packages ca9 can actually review."""
    metadata = package.metadata
    names = metadata.get("installed_names")
    specifiers = metadata.get("requested_specifiers")
    return (
        package.dependency_kind == "direct"
        and package.source_registry == "https://registry.npmjs.org"
        and metadata.get("source_kind") == "registry"
        and not any(
            metadata.get(key)
            for key in (
                "identity_ambiguous",
                "identity_unverified",
                "local_workspace",
                "self_name",
                "link",
            )
        )
        and isinstance(names, list)
        and len(names) == 1
        and isinstance(names[0], str)
        and names[0].lower() == package.name.lower()
        and isinstance(specifiers, list)
        and bool(specifiers)
        and all(
            isinstance(specifier, str) and not specifier.lower().startswith("npm:")
            for specifier in specifiers
        )
    )


def scan_publisher_changes(
    root: str | Path, *, enabled: bool = False, now: datetime | None = None
) -> PublisherScanResult:
    """Review public npm publisher handovers in v2/v3 package-lock files.

    Disabled scans do no filesystem or network work. Enabled scans use only
    bounded, regular, non-symlink lockfiles and ca9's public npm registry check.
    Every omitted input or registry problem remains visible in the receipt.
    """
    receipt = {
        "status": "disabled",
        "complete": False,
        "selected_lockfiles": 0,
        "parsed_lockfiles": 0,
        "candidate_packages": 0,
        "submitted_packages": 0,
        "finding_count": 0,
        "limit_reasons": [],
    }
    result = PublisherScanResult(receipt=receipt)
    if not enabled:
        return result

    try:
        from ca9.npm_publisher import scan_npm_publisher_changes
        from ca9.readers.package_lock import load_package_lock
    except ImportError:
        result.warnings.append("npm publisher check requires ca9 0.6.0 or newer")
        receipt["status"] = "unavailable"
        return result

    scan_root = Path(root)
    if scan_root.is_symlink() or not scan_root.is_dir():
        result.warnings.append("npm publisher check requires a readable directory")
        receipt["status"] = "unavailable"
        return result
    scan_root = scan_root.resolve()

    packages = {}
    occurrences: dict[str, list[dict]] = {}
    total_bytes = 0
    walked_directories = 0
    unsupported_shrinkwraps = 0
    partial = False

    for directory, dirnames, filenames in os.walk(scan_root, followlinks=False):
        walked_directories += 1
        if walked_directories > MAX_WALK_DIRECTORIES:
            receipt["limit_reasons"].append("directory_limit_exceeded")
            partial = True
            break

        selected = set(filenames)
        present = selected | set(dirnames)
        if "npm-shrinkwrap.json" in present:
            unsupported_shrinkwraps += 1
            # npm gives shrinkwrap precedence even when that path is invalid.
            selected.discard("package-lock.json")
            if "package-lock.json" in present:
                receipt.setdefault("ignored_package_locks", 0)
                receipt["ignored_package_locks"] += 1
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in SKIP_DIRECTORIES
            and name not in {"package-lock.json", "npm-shrinkwrap.json"}
        )
        if "package-lock.json" not in selected and "package-lock.json" not in present:
            continue
        if "npm-shrinkwrap.json" in present:
            continue

        receipt["selected_lockfiles"] += 1
        if receipt["selected_lockfiles"] > MAX_LOCKFILES:
            receipt["limit_reasons"].append("lockfile_count_limit_exceeded")
            partial = True
            break
        path = Path(directory) / "package-lock.json"
        source = read_project_text_no_symlink(
            scan_root, path, max_bytes=MAX_LOCKFILE_BYTES, encoding="utf-8"
        )
        if source is None:
            result.warnings.append(
                f"npm publisher check skipped {path}: unreadable, symlinked, or over 10 MB"
            )
            partial = True
            continue
        source_bytes = len(source.encode("utf-8"))
        if total_bytes + source_bytes > MAX_TOTAL_LOCKFILE_BYTES:
            receipt["limit_reasons"].append("total_lockfile_bytes_limit_exceeded")
            partial = True
            break
        total_bytes += source_bytes

        try:
            validated = parse_package_lock(path, text=source, max_packages=MAX_PACKAGES)
        except LockfileParseError as exc:
            result.warnings.append(f"npm publisher check skipped {path}: {exc}")
            partial = True
            continue
        if validated.format_version not in (2, 3):
            result.warnings.append(
                f"npm publisher check skipped {path}: requires npm lockfile v2/v3"
            )
            partial = True
            continue
        receipt["parsed_lockfiles"] += 1

        # The strict Skylos parser proves each identity and source. ca9's
        # inventory reader supplies the additional publisher-check metadata.
        allowed = {
            (dep["package_path"], dep["name"].lower(), dep["version"]): dep
            for dep in validated.dependencies
            if dep["dependency_kind"] == "direct"
            and dep["source_type"] == "npm_registry"
            and "node_modules/" in dep["package_path"]
            and dep["name"].lower()
            == dep["package_path"].rsplit("node_modules/", 1)[-1].lower()
        }
        if not allowed:
            continue
        try:
            inventory = load_package_lock(
                _LockfileSnapshot(path, source), repo_path=path.parent
            )
        except (ValueError, TypeError, RecursionError, OverflowError) as exc:
            result.warnings.append(
                f"npm publisher check skipped {path}: ca9 inventory error ({exc})"
            )
            partial = True
            continue
        result.warnings.extend(inventory.warnings)

        for package in inventory.packages:
            lock_path = package.metadata.get("lock_path")
            validated_dep = allowed.get(
                (lock_path, package.name.lower(), package.version)
            )
            if validated_dep is None or not _eligible_inventory_package(package):
                continue
            receipt["candidate_packages"] += 1
            if (
                package.key not in packages
                and len(packages) >= MAX_PUBLISHER_CANDIDATES
            ):
                if "publisher_candidate_limit_exceeded" not in receipt["limit_reasons"]:
                    receipt["limit_reasons"].append(
                        "publisher_candidate_limit_exceeded"
                    )
                    result.warnings.append(
                        "npm publisher check reached its 25-package limit; remaining direct npm "
                        "dependencies were not checked"
                    )
                partial = True
                continue
            packages.setdefault(package.key, package)
            location = {
                "file": str(path),
                "line": validated_dep["line"],
                "package_path": lock_path,
            }
            matches = occurrences.setdefault(package.key, [])
            if location not in matches:
                matches.append(location)

    if unsupported_shrinkwraps:
        receipt["unsupported_shrinkwraps"] = unsupported_shrinkwraps
        result.warnings.append(
            "npm publisher check does not support npm-shrinkwrap.json; "
            f"{unsupported_shrinkwraps} selected lockfile(s) were not checked"
        )
        partial = True

    receipt["submitted_packages"] = len(packages)
    if packages:
        try:
            ca9_findings, ca9_warnings = scan_npm_publisher_changes(
                packages.values(), now=now
            )
        except (ValueError, TypeError, OSError) as exc:
            result.warnings.append(f"npm publisher check failed: {exc}")
            partial = True
        else:
            result.warnings.extend(ca9_warnings)
            for finding in ca9_findings:
                locations = occurrences.get(finding.package_key)
                if not locations:
                    continue
                detail = finding.to_dict()
                metadata = {
                    **finding.metadata,
                    "package_name": finding.metadata.get("package"),
                    "package_version": finding.metadata.get("locked_version"),
                    "dormancy_days": finding.metadata.get("release_gap_days"),
                    "ca9_severity": finding.severity,
                    "ca9_fingerprint": finding.fingerprint,
                    "occurrences": locations,
                    "publisher_evidence": detail["evidence"],
                }
                message = (
                    f"Review npm publisher change for "
                    f"{metadata['package_name']}@{metadata['package_version']}: "
                    f"{metadata['previous_publisher']} to {metadata['new_publisher']} "
                    f"after {metadata['dormancy_days']} days without a release"
                )
                result.findings.append(
                    {
                        "rule_id": RULE_ID,
                        "severity": "WARN",
                        "message": message,
                        "file": locations[0]["file"],
                        "line": locations[0]["line"],
                        "metadata": metadata,
                    }
                )

    result.warnings = list(dict.fromkeys(result.warnings))
    receipt["finding_count"] = len(result.findings)
    if receipt["selected_lockfiles"] == 0 and not partial:
        receipt["status"] = "no_inputs"
    elif partial or result.warnings:
        receipt["status"] = "partial"
    else:
        receipt["status"] = "complete"
    receipt["complete"] = receipt["status"] in {"complete", "no_inputs"}
    return result
