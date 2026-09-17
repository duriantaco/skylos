"""Versioned dependency identities for explicit, complete-scan baselines.

Line numbers and checkout locations are not identity. Package versions,
advisory IDs, manifest/workspace scope and usage context are. An ambiguous
identity is never evidence that a finding was previously accepted.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

IDENTITY_VERSION = 1
MAX_FINGERPRINTS = 20_000
MAX_OCCURRENCES = 5_000
_CONTEXT_FIELDS = (
    "dependency_section",
    "dependency_sections",
    "dependency_dev",
    "dependency_optional",
    "dependency_groups",
    "dependency_extras",
    "dependency_markers",
    "source_type",
    "requires_python",
    "lockfile_resolution_markers",
    "lockfile_supported_markers",
    "lockfile_required_markers",
    "environment_scope",
)
# Optional additions preserve fingerprints for older uv/npm/pnpm occurrences.
_EXTENDED_CONTEXT_FIELDS = (
    "lockfile_requires_python",
    "dependency_extra_requirements",
)
_ADVISORY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z")
_FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")


def dependency_scan_complete(result: dict) -> bool:
    summary = result.get("analysis_summary")
    receipt = summary.get("sca_coverage") if isinstance(summary, dict) else None
    return (
        isinstance(receipt, dict)
        and receipt.get("complete") is True
        and isinstance(receipt.get("status"), str)
        and receipt.get("status") in {"complete", "complete_with_unresolved_versions"}
    )


def _text(value, *, maximum=512):
    if not isinstance(value, str) or not value or len(value) > maximum:
        return None
    if value != value.strip() or any(ord(char) < 32 for char in value):
        return None
    return value


def _relative_file(value, project_root):
    value = _text(value, maximum=4096)
    if value is None or "\\" in value and os.name != "nt":
        return None
    path = Path(value)
    if ".." in path.parts:
        return None
    if path.is_absolute():
        if project_root is None:
            return None
        try:
            path = path.relative_to(Path(os.path.abspath(project_root)))
        except (TypeError, ValueError, OSError):
            return None
    if not path.parts or path.as_posix() == ".":
        return None
    return path.as_posix()


def _context(value, depth=0):
    if depth > 4:
        raise ValueError("dependency context too deep")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str) and len(value) <= 512:
        return value
    if isinstance(value, list) and len(value) <= 256:
        items = [_context(item, depth + 1) for item in value]
        # Lists here describe sets of groups/markers, not ordered execution.
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, dict) and len(value) <= 32:
        if not all(_text(key) for key in value):
            raise ValueError("invalid dependency context key")
        return {key: _context(item, depth + 1) for key, item in value.items()}
    raise ValueError("invalid dependency context")


def dependency_fingerprints(finding, project_root=None) -> set[str] | None:
    if not isinstance(finding, dict):
        return None
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("advisory_status") != "complete":
        return None
    fields = [
        metadata.get(key)
        for key in ("ecosystem", "package_name", "package_version", "vuln_id")
    ]
    if not all(_text(value) for value in fields):
        return None
    ecosystem, name, version, advisory = fields
    if (
        not _ADVISORY_ID.fullmatch(advisory)
        or finding.get("rule_id") != f"SKY-SCA-{advisory}"
    ):
        return None
    if ecosystem == "PyPI":
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif ecosystem not in {"npm", "Go"}:
        return None
    severity = finding.get("severity", "UNKNOWN")
    if not isinstance(severity, str) or severity not in {
        "UNKNOWN",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }:
        return None
    primary_file = _relative_file(finding.get("file"), project_root)
    if primary_file is None:
        return None
    occurrences = metadata.get(
        "dependency_occurrences", [{**metadata, "file": finding.get("file")}]
    )
    if not isinstance(occurrences, list) or not 0 < len(occurrences) <= MAX_OCCURRENCES:
        return None
    fingerprints = set()
    files = set()
    for occurrence in occurrences:
        if not isinstance(occurrence, dict):
            return None
        file = _relative_file(occurrence.get("file"), project_root)
        if file is None:
            return None
        files.add(file)
        roots = occurrence.get("dependency_roots", [])
        if not isinstance(roots, list) or len(roots) > 256:
            return None
        if not all(root == "" or _text(root) for root in roots):
            return None
        try:
            context = _context({key: occurrence.get(key) for key in _CONTEXT_FIELDS})
            context.update(
                {
                    key: _context(occurrence[key])
                    for key in _EXTENDED_CONTEXT_FIELDS
                    if key in occurrence
                }
            )
            if ecosystem == "npm":
                # npm install paths distinguish identical transitive versions
                # under different consumers. uv's package_path is an unstable
                # TOML array index and must not participate in identity.
                context["package_path"] = _context(occurrence.get("package_path"))
            for root in roots or [None]:
                payload = [
                    IDENTITY_VERSION,
                    ecosystem,
                    name,
                    version,
                    advisory,
                    severity,
                    file,
                    root,
                    context,
                ]
                encoded = json.dumps(
                    payload, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
                fingerprints.add(hashlib.sha256(encoded).hexdigest())
        except (TypeError, ValueError, RecursionError):
            return None
        if len(fingerprints) > MAX_FINGERPRINTS:
            return None
    return fingerprints if primary_file in files else None


def dependency_snapshot(result: dict, project_root) -> dict | None:
    if not dependency_scan_complete(result):
        return None
    findings = result.get("dependency_vulnerabilities", [])
    if not isinstance(findings, list) or len(findings) > MAX_FINGERPRINTS:
        raise ValueError("dependency baseline exceeds finding limit")
    fingerprints = set()
    captured = 0
    for finding in findings:
        identity = dependency_fingerprints(finding, project_root)
        if identity:
            fingerprints.update(identity)
            captured += 1
        if len(fingerprints) > MAX_FINGERPRINTS:
            raise ValueError("dependency baseline exceeds identity limit")
    return {
        "version": IDENTITY_VERSION,
        "fingerprints": sorted(fingerprints),
        "captured_count": captured,
        "unmatched_count": len(findings) - captured,
    }


def _known_fingerprints(baseline):
    if not isinstance(baseline, dict):
        return None
    section = baseline.get("dependency_baseline")
    if (
        not isinstance(section, dict)
        or type(section.get("version")) is not int
        or section["version"] != IDENTITY_VERSION
    ):
        return None
    fingerprints = section.get("fingerprints")
    if not isinstance(fingerprints, list) or len(fingerprints) > MAX_FINGERPRINTS:
        return None
    if not all(
        isinstance(item, str) and _FINGERPRINT.fullmatch(item) for item in fingerprints
    ):
        return None
    return set(fingerprints)


def filter_dependency_findings(
    result, baseline, *, project_root=None, disabled_reason=None, source=None
):
    filtered = dict(result)
    findings = result.get("dependency_vulnerabilities", [])
    if not isinstance(findings, list):
        return filtered
    known = _known_fingerprints(baseline)
    status = disabled_reason or (
        "applied" if known is not None else "no_dependency_baseline"
    )
    if not dependency_scan_complete(result):
        status = "scan_incomplete"
    existing = []
    new = []
    for finding in findings:
        identity = (
            dependency_fingerprints(finding, project_root)
            if status == "applied"
            else None
        )
        if identity and identity <= known:
            existing.append(finding)
        else:
            new.append(finding)
    if "dependency_vulnerabilities" in result:
        filtered["dependency_vulnerabilities"] = new
    # Keep baseline-matched evidence available in JSON without treating it as new.
    filtered["baseline_dependency_vulnerabilities"] = existing
    summary = dict(result.get("analysis_summary") or {})
    if "dependency_vulnerabilities" in result:
        summary["dependency_vulnerabilities_count"] = len(new)
    summary["dependency_baseline"] = {
        "status": status,
        "existing_count": len(existing),
        "new_count": len(new),
        "identity_version": IDENTITY_VERSION,
        **({"source": source} if source is not None else {}),
    }
    filtered["analysis_summary"] = summary
    return filtered
