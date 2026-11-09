"""Dependency advisories rolled up per package for terminal output.

A lockfile with old packages can carry hundreds of advisories (one repo gave
294 over 69 packages, 1,770 terminal lines). People act per package: which
version to install. Terminal output shows one row per installed package; JSON
and SARIF keep one finding per advisory, unchanged.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_VERSION_TOKEN = re.compile(r"\d+|[A-Za-z]+")
_END = (0, 1, "~")
MAX_IDS_SHOWN = 3
_TIER_RANK = {"used": 0, "imported": 1, "unknown": 2, "not_imported": 3, "unreachable": 4}
_NOT_ANALYZED_RANK = 2
_TIER_LABELS = {
    "used": "called",
    "imported": "imported",
    "unknown": "unknown",
    "not_imported": "no import found",
    "unreachable": "not reached",
}
_LOWER_PRIORITY_TIERS = frozenset({"not_imported", "unreachable"})
LICENSE_POLICY_RULE_ID = "SKY-SCA-LIC001"


def _version_key(version: str):
    """Tolerant ordering for PyPI, npm and Go versions (pre-releases first)."""
    key = []
    for token in _VERSION_TOKEN.findall(version.lstrip("vV")):
        key.append((1, int(token), "") if token.isdigit() else (0, 0, token.lower()))
    key.append(_END)
    return key


def _lowest_fix_above(installed: str, metadata) -> str | None:
    """This advisory's lowest reported fix above the installed version.

    ``fixed_version`` is set only when one upgrade is unambiguous; with fixes
    on several release lines (``fixed_versions``: 15.5.24 and 16.3.3 for an
    installed 14.0.0) the next release line's fix is the lowest that applies.
    """
    candidates = set()
    single = metadata.get("fixed_version")
    if isinstance(single, str) and single.strip():
        candidates.add(single.strip())
    many = metadata.get("fixed_versions")
    if isinstance(many, list):
        candidates.update(v.strip() for v in many if isinstance(v, str) and v.strip())
    installed_key = _version_key(installed)
    above = [v for v in candidates if _version_key(v) > installed_key]
    return min(above, key=_version_key) if above else None


def is_advisory(finding) -> bool:
    """A known-vulnerability finding (not a licence or other SCA record)."""
    if not isinstance(finding, Mapping):
        return False
    metadata = finding.get("metadata")
    return (
        isinstance(metadata, Mapping)
        and bool(metadata.get("vuln_id"))
        and bool(metadata.get("package_name"))
    )


def is_license_finding(finding) -> bool:
    """A dependency license-policy finding (SKY-SCA-LIC001)."""
    if not isinstance(finding, Mapping):
        return False
    rule_id = str(finding.get("rule_id") or "").strip().upper()
    return rule_id == LICENSE_POLICY_RULE_ID


@dataclass
class PackageAdvisories:
    ecosystem: str
    name: str
    version: str
    file: str
    line: int
    findings: list = field(default_factory=list)
    fixed_versions: set = field(default_factory=set)
    without_fix: int = 0
    ids: list = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def worst_severity(self) -> str:
        severities = [str(f.get("severity") or "MEDIUM").upper() for f in self.findings]
        return min(severities, key=lambda s: _SEVERITY_RANK.get(s, 9))

    @property
    def fix_version(self) -> str | None:
        """The highest of each advisory's lowest fix above the installed
        version: the first version that clears every advisory with a fix."""
        if not self.fixed_versions:
            return None
        return max(self.fixed_versions, key=_version_key)

    @property
    def malicious(self) -> bool:
        return any(
            (finding.get("metadata") or {}).get("malicious") is True
            for finding in self.findings
        )

    @property
    def tier(self) -> str | None:
        """The strongest use any advisory shows. A finding with no tier
        counts as not analyzed, so it can never lower the package's priority."""
        best = None
        best_rank = len(_TIER_RANK)
        for finding in self.findings:
            value = (finding.get("metadata") or {}).get("reachability_tier")
            rank = _TIER_RANK.get(value, _NOT_ANALYZED_RANK)
            if rank < best_rank:
                best_rank = rank
                best = None
                if value in _TIER_RANK:
                    best = value
        return best

    @property
    def lower_priority(self) -> bool:
        return self.tier in _LOWER_PRIORITY_TIERS

    def use_text(self) -> str:
        tier = self.tier
        if tier is None:
            return "not analyzed"
        if tier == "used":
            for finding in self.findings:
                sites = (finding.get("metadata") or {}).get("reachability_call_sites")
                if sites:
                    return f"called at {sites[0]['file']}:{sites[0]['line']}"
        return _TIER_LABELS[tier]

    def fix_text(self) -> str:
        if self.malicious:
            return "remove (malicious package)"
        fix = self.fix_version
        if fix is None:
            return "no fix released"
        if self.without_fix:
            return f"{fix} ({self.without_fix} without a fix)"
        return fix

    def ids_text(self) -> str:
        shown = ", ".join(self.ids[:MAX_IDS_SHOWN])
        more = self.count - min(self.count, MAX_IDS_SHOWN)
        return f"{shown} +{more} more" if more > 0 else shown


def group_advisories(findings: Iterable) -> list[PackageAdvisories]:
    """One group per installed package: malware, then by severity with what
    the code uses first. Packages with no sign of use sort last and stay listed."""
    groups: dict[tuple, PackageAdvisories] = {}
    for finding in findings or ():
        if not is_advisory(finding):
            continue
        meta = finding["metadata"]
        name = str(meta.get("package_name"))
        version = str(meta.get("package_version") or "?")
        ecosystem = str(meta.get("ecosystem") or "")
        key = (ecosystem, name, version)
        group = groups.get(key)
        if group is None:
            line = finding.get("line") or finding.get("line_number") or 1
            group = groups[key] = PackageAdvisories(
                ecosystem,
                name,
                version,
                str(finding.get("file") or finding.get("file_path") or "?"),
                line if isinstance(line, int) and line > 0 else 1,
            )
        group.findings.append(finding)
        fix = _lowest_fix_above(version, meta)
        if fix is None:
            group.without_fix += 1
        else:
            group.fixed_versions.add(fix)
        advisory_id = meta.get("display_id") or meta.get("vuln_id")
        if advisory_id and str(advisory_id) not in group.ids:
            group.ids.append(str(advisory_id))
    return sorted(
        groups.values(),
        key=lambda g: (
            not g.malicious,
            g.lower_priority,
            _SEVERITY_RANK.get(g.worst_severity, 9),
            _TIER_RANK.get(g.tier, _NOT_ANALYZED_RANK),
            -g.count,
            g.name.lower(),
            g.version,
        ),
    )


def summary_footer(groups: list[PackageAdvisories]) -> str:
    total = sum(group.count for group in groups)
    packages = len(groups)
    footer = (
        f"{total} advisor{'y' if total == 1 else 'ies'} in {packages} "
        f"package{'' if packages == 1 else 's'}. Every advisory, with its "
        "range and references: --format json (dependency_vulnerabilities)."
    )
    tally = use_tally(groups)
    if tally:
        return f"{footer} Use: {tally}. The gate counts all of them."
    return footer


def has_use_data(groups: list[PackageAdvisories]) -> bool:
    return any(group.tier is not None for group in groups)


def use_tally(groups: list[PackageAdvisories]) -> str:
    if not has_use_data(groups):
        return ""
    counts: dict[str, int] = {}
    for group in groups:
        label = "not analyzed"
        if group.tier is not None:
            label = _TIER_LABELS[group.tier]
        counts[label] = counts.get(label, 0) + 1
    order = [*_TIER_LABELS.values(), "not analyzed"]
    return ", ".join(f"{counts[label]} {label}" for label in order if label in counts)
