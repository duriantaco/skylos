"""Conservative display metadata from OSV advisories, without version solving.

OSV severity scores may be vectors, not numbers. We preserve those vectors and
use explicit database labels without inventing a numeric CVSS score. Upgrade
hints require a single provably newer stable release; all reported release fixes
remain available when branches or version syntax make that inference unsafe.
"""

from __future__ import annotations

import math
import re

_SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_CVSS_TYPES = {"CVSS_V2", "CVSS_V3", "CVSS_V4"}


def _objects(value):
    return (
        [item for item in value if isinstance(item, dict)]
        if isinstance(value, list)
        else []
    )


def _strings(value):
    return (
        list(dict.fromkeys(item for item in value if isinstance(item, str) and item))
        if isinstance(value, list)
        else []
    )


def _matching_affected(vuln: dict, dep: dict) -> list[dict]:
    ecosystem = dep.get("ecosystem")
    name = dep.get("name")
    if not isinstance(ecosystem, str) or not isinstance(name, str) or not name:
        return []
    if ecosystem == "PyPI":
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif ecosystem == "NuGet":
        name = name.casefold()
    matching = []
    for affected in _objects(vuln.get("affected")):
        package = affected.get("package")
        if not isinstance(package, dict) or package.get("ecosystem") != ecosystem:
            continue
        candidate = package.get("name")
        if ecosystem == "PyPI" and isinstance(candidate, str):
            candidate = re.sub(r"[-_.]+", "-", candidate).lower()
        elif ecosystem == "NuGet" and isinstance(candidate, str):
            candidate = candidate.casefold()
        if candidate == name:
            matching.append(affected)
    return matching


def advisory_matches_dependency(vuln: dict, dep: dict) -> bool:
    """Require package identity evidence, not just another package's ecosystem."""
    return bool(_matching_affected(vuln, dep))


def _numeric_score(value) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        score = float(value)
    except (ValueError, TypeError, OverflowError):
        return None
    return score if math.isfinite(score) and 0 <= score <= 10 else None


def _severity_label(value) -> str | None:
    if not isinstance(value, str):
        return None
    label = value.upper()
    label = "MEDIUM" if label == "MODERATE" else label
    return label if label in _SEVERITY_ORDER else None


def _severity_metadata(vuln: dict, matching: list[dict]) -> dict:
    # Package-specific severity replaces the top-level severity in the schema.
    package_ratings = [item for item in matching if _objects(item.get("severity"))]
    rating_sources = package_ratings or [vuln]
    scores, vectors, labels = [], [], []
    for source in rating_sources:
        for entry in _objects(source.get("severity")):
            if entry.get("type") not in _CVSS_TYPES:
                continue
            score = _numeric_score(entry.get("score"))
            if score is not None:
                scores.append(score)
            elif isinstance(entry.get("score"), str) and "/" in entry["score"]:
                vector = {"type": entry["type"], "score": entry["score"]}
                if isinstance(entry.get("source"), str):
                    vector["source"] = entry["source"]
                if vector not in vectors:
                    vectors.append(vector)
    for source in matching if package_ratings else [vuln, *matching]:
        database = source.get("database_specific")
        if not isinstance(database, dict):
            continue
        # Arbitrary database-specific "score" fields need not be CVSS scores.
        for key in ("cvss_score", "cvss"):
            value = database.get(key)
            if isinstance(value, dict):
                value = value.get("score")
            score = _numeric_score(value)
            if score is not None:
                scores.append(score)
        label = _severity_label(database.get("severity"))
        if label is not None:
            labels.append(label)
    # Some OSV publishers put package severity labels in ecosystem_specific.
    # Only the queried package's entries supply these labels, never other
    # affected packages or a guessed numeric interpretation of the label.
    for source in matching:
        ecosystem = source.get("ecosystem_specific")
        if isinstance(ecosystem, dict):
            label = _severity_label(ecosystem.get("severity"))
            if label is not None:
                labels.append(label)
    score = max(scores, default=None)
    if score is not None:
        label = (
            "CRITICAL"
            if score >= 9
            else "HIGH"
            if score >= 7
            else "MEDIUM"
            if score >= 4
            else "LOW"
        )
    else:
        label = max(labels, key=_SEVERITY_ORDER.get, default="UNKNOWN")
    return {"cvss_score": score, "severity": label, "severity_vectors": vectors}


def _release_version(value, ecosystem: str) -> tuple[int, ...] | None:
    """Compare only stable numeric releases; no implicit prerelease semantics."""
    if not isinstance(value, str) or len(value) > 100:
        return None
    if ecosystem == "Go" and value.startswith("v"):
        value = value[1:]
    pattern = (
        r"[0-9]+(?:\.[0-9]+)*"
        if ecosystem == "PyPI"
        else r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,3}"
        if ecosystem == "NuGet"
        else r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    )
    if ecosystem not in {"PyPI", "npm", "Go", "NuGet"} or not re.fullmatch(
        pattern, value
    ):
        return None
    parts = tuple(int(part) for part in value.split("."))
    # PEP 440 pads stable release segments with zero during comparison.
    if ecosystem == "PyPI":
        while len(parts) > 1 and parts[-1] == 0:
            parts = parts[:-1]
    elif ecosystem == "NuGet":
        parts += (0,) * (4 - len(parts))
    return parts


def _range_intervals(value: dict):
    events = value.get("events")
    if not isinstance(events, list) or not events:
        return None
    intervals, start = [], None
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return None
        key, version = next(iter(event.items()))
        if not isinstance(version, str) or not version:
            return None
        if key == "introduced" and start is None:
            start = version
        elif key in {"fixed", "last_affected", "limit"} and start is not None:
            intervals.append((start, version, key))
            start = None
        else:
            return None
    if start is not None:
        intervals.append((start, "*", "limit"))
    return intervals


def _fix_metadata(matching: list[dict], dep: dict) -> dict:
    fixes, display, intervals, explicit_versions = [], [], [], []
    understood = bool(matching)
    ecosystem = dep.get("ecosystem", "")
    expected_type = "ECOSYSTEM" if ecosystem in {"PyPI", "NuGet"} else "SEMVER"
    for affected in matching:
        versions = affected.get("versions", [])
        if not isinstance(versions, list) or any(
            not isinstance(version, str) or not version for version in versions
        ):
            understood = False
        explicit_versions.extend(_strings(affected.get("versions")))
        ranges = affected.get("ranges")
        if not isinstance(ranges, list) or not ranges:
            understood = False
        for value in _objects(ranges):
            if value.get("type") not in {"SEMVER", "ECOSYSTEM"}:
                understood = False
                continue
            fixes.extend(
                event["fixed"]
                for event in _objects(value.get("events"))
                if isinstance(event.get("fixed"), str) and event["fixed"]
            )
            parsed = _range_intervals(value)
            if parsed is None or value.get("type") != expected_type:
                understood = False
                continue
            for start, end, kind in parsed:
                parts = [] if start == "0" else [f">={start}"]
                if end != "*":
                    parts.append(f"{'<=' if kind == 'last_affected' else '<'}{end}")
                display.append(", ".join(parts) or "all versions")
                lower = () if start == "0" else _release_version(start, ecosystem)
                upper = None if end == "*" else _release_version(end, ecosystem)
                if (
                    lower is None
                    or (end != "*" and upper is None)
                    or (upper is not None and lower >= upper)
                ):
                    understood = False
                intervals.append((lower, upper, kind))
        if isinstance(ranges, list) and len(_objects(ranges)) != len(ranges):
            understood = False
    fixes = list(dict.fromkeys(fixes))
    current = _release_version(dep.get("version"), ecosystem)
    candidate = _release_version(fixes[0], ecosystem) if len(fixes) == 1 else None
    fixed = None
    if (
        understood
        and current is not None
        and candidate is not None
        and candidate > current
    ):

        def includes(version, interval):
            lower, upper, kind = interval
            if version < lower:
                return False
            if upper is None:
                return True
            return version <= upper if kind == "last_affected" else version < upper

        current_has_fix = any(
            kind == "fixed"
            and upper == candidate
            and includes(current, (lower, upper, kind))
            for lower, upper, kind in intervals
        )
        candidate_is_affected = any(
            includes(candidate, interval) for interval in intervals
        )
        explicit = [
            _release_version(version, ecosystem) for version in explicit_versions
        ]
        if (
            current_has_fix
            and not candidate_is_affected
            and candidate not in explicit
            and None not in explicit
        ):
            fixed = fixes[0]
    return {
        "fixed_version": fixed,
        "fixed_versions": fixes,
        "affected_range": "; ".join(dict.fromkeys(display)) or "unknown",
    }


def extract_advisory_metadata(vuln: dict, dep: dict) -> dict:
    """Extract report data without implying that omitted details are known."""
    matching = _matching_affected(vuln, dep)
    aliases = _strings(vuln.get("aliases"))
    vuln_id = vuln.get("id") if isinstance(vuln.get("id"), str) else "UNKNOWN"
    summary = next(
        (
            vuln[key]
            for key in ("summary", "details")
            if isinstance(vuln.get(key), str) and vuln[key]
        ),
        None,
    )
    summary = summary or ", ".join(aliases) or f"Known vulnerability ({vuln_id})"
    references = list(
        dict.fromkeys(
            entry["url"]
            for entry in _objects(vuln.get("references"))
            if isinstance(entry.get("url"), str)
            and entry["url"].startswith(("https://", "http://"))
        )
    )[:5]
    return {
        "vuln_id": vuln_id,
        "summary": summary[:300],
        "aliases": aliases,
        "references": references,
        "withdrawn": vuln.get("withdrawn")
        if isinstance(vuln.get("withdrawn"), str)
        else None,
        **_severity_metadata(vuln, matching),
        **_fix_metadata(matching, dep),
    }
