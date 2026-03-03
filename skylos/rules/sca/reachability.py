"""Bridge between Skylos SCA findings and ca9 reachability analysis."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ca9.engine import analyze as ca9_analyze
from ca9.models import Verdict, VersionRange, Vulnerability

logger = logging.getLogger(__name__)


def finding_to_vulnerability(finding: dict) -> Vulnerability | None:
    """Convert a Skylos SCA finding dict to a ca9 Vulnerability."""
    meta = finding.get("metadata") or {}
    vuln_id = meta.get("vuln_id")
    pkg_name = meta.get("package_name")
    pkg_version = meta.get("package_version")
    if not (vuln_id and pkg_name and pkg_version):
        return None

    affected_ranges = _parse_affected_range(meta.get("affected_range", ""))
    refs = tuple(meta.get("references") or ())

    return Vulnerability(
        id=vuln_id,
        package_name=pkg_name,
        package_version=pkg_version,
        severity=(finding.get("severity") or "MEDIUM").upper(),
        title=finding.get("message") or f"Known vulnerability ({vuln_id})",
        affected_ranges=affected_ranges,
        references=refs,
    )


def _parse_affected_range(range_str: str) -> tuple[VersionRange, ...]:
    """Parse '>=1.0, <1.5; >=2.0' into ca9 VersionRange objects."""
    if not range_str or range_str == "unknown":
        return ()

    ranges = []
    for segment in range_str.split(";"):
        segment = segment.strip()
        if not segment:
            continue

        introduced = ""
        fixed = ""
        for part in segment.split(","):
            part = part.strip()
            m = re.match(r">=\s*(.+)", part)
            if m:
                introduced = m.group(1).strip()
                continue
            m = re.match(r"<\s*(.+)", part)
            if m:
                fixed = m.group(1).strip()

        if introduced or fixed:
            ranges.append(VersionRange(introduced=introduced, fixed=fixed))

    return tuple(ranges)


def _discover_coverage(root: Path) -> Path | None:
    """Auto-discover coverage.json in common locations."""
    candidates = [
        root / "coverage.json",
        root / ".coverage" / "coverage.json",
        root / "htmlcov" / "coverage.json",
    ]
    for p in candidates:
        if p.is_file():
            return p
    return None


def enrich_with_reachability(
    findings: list[dict], repo_path: Path
) -> list[dict]:
    """Enrich SCA findings with ca9 reachability verdicts.

    Only PyPI findings are analyzed. Non-PyPI findings pass through unchanged.
    """
    if not findings:
        return findings

    pypi_findings = []
    other_findings = []
    for f in findings:
        eco = (f.get("metadata") or {}).get("ecosystem", "")
        if eco == "PyPI":
            pypi_findings.append(f)
        else:
            other_findings.append(f)

    if not pypi_findings:
        return findings

    vulns = []
    vuln_id_to_indices: dict[str, list[int]] = {}
    for idx, f in enumerate(pypi_findings):
        v = finding_to_vulnerability(f)
        if v is not None:
            vulns.append(v)
            vuln_id_to_indices.setdefault(v.id, []).append(idx)

    if not vulns:
        return findings

    coverage_path = _discover_coverage(repo_path)
    report = ca9_analyze(vulns, repo_path, coverage_path)

    verdict_map = {
        Verdict.REACHABLE: "reachable",
        Verdict.UNREACHABLE_STATIC: "unreachable_static",
        Verdict.UNREACHABLE_DYNAMIC: "unreachable_dynamic",
        Verdict.INCONCLUSIVE: "inconclusive",
    }

    for vr in report.results:
        indices = vuln_id_to_indices.get(vr.vulnerability.id, [])
        for idx in indices:
            meta = pypi_findings[idx].setdefault("metadata", {})
            meta["reachability_verdict"] = verdict_map.get(
                vr.verdict, "inconclusive"
            )
            meta["reachability_reason"] = vr.reason
            if vr.imported_as:
                meta["reachability_imported_as"] = vr.imported_as
            if vr.executed_files:
                meta["reachability_executed_files"] = vr.executed_files

    return pypi_findings + other_findings
