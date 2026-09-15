"""Data-only, bounded GitLab Code Quality report conversion.

The artifact is a JSON array; completion diagnostics belong on stderr, not in
that array. Paths are checked lexically, without opening source files or
following symlinks. Fingerprint v1 ignores checkout roots and line movement;
otherwise indistinguishable occurrences are numbered in source order.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import unicodedata

from skylos.cicd.evidence import sanitize_untrusted_text


MAX_FINDINGS = 10_000
MAX_INPUT_FINDINGS = 20_000
MAX_DESCRIPTION_LENGTH = 2_000
MAX_FIELD_LENGTH = 4_096
MAX_IDENTITY_NODES = 4_096
MAX_IDENTITY_TEXT = 32_768
MAX_OCCURRENCES = 5_000
MAX_REPORT_BYTES = 16 * 1024 * 1024
FINGERPRINT_VERSION = "skylos-gitlab-v1"

_SECTIONS = (
    ("danger", "SKY-D000", "Security issue", "HIGH"),
    ("reliability", "SKY-R000", "Reliability issue", "MEDIUM"),
    ("ai_defects", "SKY-AI000", "AI-code issue", "MEDIUM"),
    ("quality", "SKY-Q000", "Quality issue", "MEDIUM"),
    ("secrets", "SKY-S000", "Potential secret detected (value omitted)", "HIGH"),
    ("custom_rules", "CUSTOM", "Custom rule finding", "MEDIUM"),
    ("unused_functions", "SKY-U001", "Unused function", "LOW"),
    ("unused_imports", "SKY-U002", "Unused import", "LOW"),
    ("unused_variables", "SKY-U003", "Unused variable", "LOW"),
    ("unused_classes", "SKY-U004", "Unused class", "LOW"),
    ("unused_parameters", "SKY-U006", "Unused parameter", "LOW"),
    ("unused_files", "SKY-E002", "Unused file", "LOW"),
    ("unused_fixtures", "SKY-U000", "Unused fixture", "LOW"),
    ("unused_exports", "SKY-U000", "Unused export", "LOW"),
    ("forgotten", "SKY-U001", "Unused function", "LOW"),
    ("circular_dependencies", "SKY-CIRC", "Circular dependency", "MEDIUM"),
    ("dependency_vulnerabilities", "SKY-SCA-000", "Dependency vulnerability", "HIGH"),
)
_SEVERITIES = {
    "CRITICAL": "blocker",
    "HIGH": "critical",
    "MEDIUM": "major",
    "LOW": "minor",
    "INFO": "info",
    "INFORMATIONAL": "info",
    # GitLab has no unknown severity. Preserve the uncertainty in the description.
    "UNKNOWN": "major",
}
_SEVERITY_RANK = {
    "blocker": 0,
    "critical": 1,
    "major": 2,
    "minor": 3,
    "info": 4,
}
# All native SCA receipts carry both fields. "no_supported_manifests" describes
# an inventory limitation, not an interrupted scan; it is the sole non-complete
# state that does not by itself make the report operationally incomplete.
_SCA_COMPLETION_STATES = {
    "complete": True,
    "complete_with_unresolved_versions": True,
    "incomplete": False,
    "unavailable": False,
    "unknown": False,
    "no_supported_manifests": False,
}
_SCA_CONTEXT_FIELDS = (
    "dependency_section",
    "dependency_sections",
    "dependency_kind",
    "dependency_kinds",
    "dependency_dev",
    "dependency_optional",
    "dependency_groups",
    "dependency_extras",
    "dependency_markers",
    "dependency_roots",
    "source_type",
    "requires_python",
    "lockfile_resolution_markers",
    "lockfile_supported_markers",
    "lockfile_required_markers",
    "environment_scope",
)
_URI_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_URL_CREDENTIALS = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://)[^\s/]+@")


@dataclass(frozen=True)
class GitLabReport:
    findings: list[dict]
    diagnostics: list[str]
    complete: bool


def _text(value: object, *, maximum: int = MAX_FIELD_LENGTH) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError("invalid or oversized text field")
    if any(unicodedata.category(char) == "Cs" for char in value):
        raise ValueError("invalid Unicode text field")
    return value


def _root_path(project_root: Path) -> str:
    root = _text(os.fspath(project_root))
    if any(unicodedata.category(char) in {"Cc", "Cf"} for char in root):
        raise ValueError("invalid project root")
    return os.path.abspath(root).replace("\\", "/").rstrip("/") or "/"


def _relative_path(value: object, root: str) -> str:
    raw = _text(value)
    if raw != raw.strip() or any(
        unicodedata.category(char) in {"Cc", "Cf"} for char in raw
    ):
        raise ValueError("invalid location path")
    if "\\" in raw:
        if os.name != "nt":
            raise ValueError("ambiguous location path")
        raw = raw.replace("\\", "/")
    if raw.startswith("//"):
        raise ValueError("network location path")
    root_prefix = root.rstrip("/") + "/"
    if raw.startswith(root_prefix):
        raw = raw[len(root_prefix) :]
    elif raw.startswith("/") or _URI_SCHEME.match(raw):
        raise ValueError("location outside project")
    parts = raw.split("/")
    if ".." in parts or raw.endswith("/"):
        raise ValueError("invalid location path")
    path = PurePosixPath(raw)
    if not path.parts or path.as_posix() == ".":
        raise ValueError("missing location path")
    relative = path.as_posix()
    if _URI_SCHEME.match(relative):
        raise ValueError("URI location path")
    return relative


def _line(item: dict, section: str) -> int:
    value = next(
        (item[key] for key in ("line", "line_number", "lineno") if key in item),
        None,
    )
    # File-level findings legitimately have no line; an explicitly bad line is
    # different and must not be silently moved to line one.
    if (
        section == "unused_files"
        and value is None
        and not any(key in item for key in ("line", "line_number", "lineno"))
    ):
        return 1
    if type(value) is int and 1 <= value <= 2_147_483_647:
        return value
    if isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,9}", value):
        number = int(value)
        if number <= 2_147_483_647:
            return number
    raise ValueError("invalid location line")


def _first_text(item: dict, keys: tuple[str, ...], default: str = "") -> str:
    for key in keys:
        value = item.get(key)
        if value is not None and value != "":
            return _text(value)
    return default


def _safe_text(value: str, *, maximum: int) -> str:
    value = _URL_CREDENTIALS.sub(r"\1[redacted]@", value)
    return sanitize_untrusted_text(value, max_length=maximum, markdown=True)


def _semantic_text(value: str, root: str) -> str:
    return value.replace(root.rstrip("/") + "/", "")


def _canonical_context(value: object, budget: list[int], depth: int = 0):
    budget[0] -= 1
    if budget[0] < 0 or depth > 6:
        raise ValueError("dependency identity exceeds limit")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        budget[1] -= len(value)
        if budget[1] < 0:
            raise ValueError("dependency identity text exceeds limit")
        return _text(value) if value else ""
    if type(value) is int and abs(value) <= 2_147_483_647:
        return value
    if isinstance(value, list) and len(value) <= 256:
        return sorted(
            (_canonical_context(item, budget, depth + 1) for item in value),
            key=_encoded,
        )
    if isinstance(value, dict) and len(value) <= 64:
        if not all(isinstance(key, str) and 0 < len(key) <= 512 for key in value):
            raise ValueError("invalid dependency identity key")
        budget[1] -= sum(len(key) for key in value)
        if budget[1] < 0:
            raise ValueError("dependency identity text exceeds limit")
        return {
            key: _canonical_context(item, budget, depth + 1)
            for key, item in value.items()
        }
    raise ValueError("invalid dependency identity")


def _dependency_identity(item: dict, root: str, path: str):
    metadata = item.get("metadata")
    if not isinstance(metadata, dict):
        return None
    fields = ("ecosystem", "package_name", "package_version", "vuln_id")
    if not all(metadata.get(key) for key in fields):
        return None
    identity = [_text(metadata[key], maximum=512) for key in fields]
    if identity[0] == "PyPI":
        identity[1] = re.sub(r"[-_.]+", "-", identity[1]).lower()
    occurrences = metadata.get("dependency_occurrences")
    if occurrences is None:
        occurrences = [{**metadata, "file": path}]
    if not isinstance(occurrences, list) or not 0 < len(occurrences) <= MAX_OCCURRENCES:
        raise ValueError("invalid dependency occurrences")
    contexts = set()
    budget = [MAX_IDENTITY_NODES, MAX_IDENTITY_TEXT]
    for occurrence in occurrences:
        if not isinstance(occurrence, dict):
            raise ValueError("invalid dependency occurrence")
        occurrence_path = _relative_path(occurrence.get("file", path), root)
        context = {
            key: occurrence[key] for key in _SCA_CONTEXT_FIELDS if key in occurrence
        }
        if identity[0] == "npm" and "package_path" in occurrence:
            context["package_path"] = occurrence["package_path"]
        contexts.add(
            _encoded(
                [
                    occurrence_path,
                    _canonical_context(context, budget),
                ]
            )
        )
    return [*identity, sorted(contexts)]


def _description(item: dict, section: str, fallback: str, identity) -> str:
    if section == "secrets":
        # Never trust a secret finding's message, preview, name, or snippet to
        # already be masked: an arbitrary high-entropy value may not match a
        # provider-specific redaction pattern.
        return fallback
    if section == "dependency_vulnerabilities" and identity:
        ecosystem, package, version, advisory = identity[:4]
        return f"Vulnerable dependency: {package}@{version} ({advisory}, {ecosystem})"
    if section.startswith("unused_") or section == "forgotten":
        symbol = _first_text(item, ("name", "qualified_name", "symbol", "simple_name"))
        return f"{fallback}: {symbol}" if symbol else fallback
    return _first_text(
        item,
        ("message", "msg", "detail", "description", "reason"),
        fallback,
    )


def _encoded(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _candidate(item: dict, spec: tuple, root: str):
    section, default_rule, fallback, default_severity = spec
    path = _relative_path(item.get("file") or item.get("file_path"), root)
    line = _line(item, section)
    rule = _first_text(item, ("rule_id", "rule", "code", "id"), default_rule)
    if len(rule) > 200:
        raise ValueError("rule identifier exceeds limit")
    severity = _first_text(item, ("severity",), default_severity).strip().upper()
    if severity not in _SEVERITIES:
        raise ValueError("invalid severity")
    dependency = (
        _dependency_identity(item, root, path)
        if section == "dependency_vulnerabilities"
        else None
    )
    description = _description(item, section, fallback, dependency)
    if severity == "UNKNOWN":
        description += " [severity unknown]"
    semantic = [FINGERPRINT_VERSION, section, path, rule]
    if dependency:
        semantic.append(dependency)
    else:
        semantic.append(_semantic_text(description, root))
        if section == "secrets":
            semantic.append(_first_text(item, ("provider",)))
        else:
            semantic.extend(
                _semantic_text(_first_text(item, (key,)), root)
                for key in ("qualified_name", "symbol", "name", "kind")
            )
    column = item.get("col", item.get("column", item.get("col_number", 0)))
    column = column if type(column) is int and 0 <= column <= 2_147_483_647 else 0
    row = {
        "description": _safe_text(description, maximum=MAX_DESCRIPTION_LENGTH),
        "check_name": _safe_text(rule, maximum=200),
        "severity": _SEVERITIES[severity],
        "location": {"path": path, "lines": {"begin": line}},
    }
    if not row["description"].strip() or not row["check_name"].strip():
        raise ValueError("empty sanitized finding text")
    semantic_hash = hashlib.sha256(_encoded(semantic).encode("utf-8")).hexdigest()
    return (
        semantic_hash,
        (line, column),
        row,
        len(description) > MAX_DESCRIPTION_LENGTH,
    )


def _sca_completion_diagnostic(coverage: object) -> str | None:
    invalid = "Invalid dependency analysis completion receipt."
    if not isinstance(coverage, dict):
        return invalid
    status = coverage.get("status")
    if not isinstance(status, str) or status not in _SCA_COMPLETION_STATES:
        return invalid
    if coverage.get("complete") is not _SCA_COMPLETION_STATES[status]:
        return invalid
    if not coverage["complete"] and status != "no_supported_manifests":
        return "Dependency vulnerability analysis is incomplete."
    return None


def _scan_diagnostics(result: dict) -> set[str]:
    diagnostics = set()
    if result.get("analysis_errors"):
        diagnostics.add("Scan analysis errors are present; the report is incomplete.")
    summary = result.get("analysis_summary")
    if summary is not None and not isinstance(summary, dict):
        diagnostics.add("Invalid analysis summary.")
    if isinstance(summary, dict):
        if summary.get("incomplete_languages"):
            diagnostics.add("Language analysis is incomplete.")
        if "sca_coverage" in summary:
            diagnostic = _sca_completion_diagnostic(summary["sca_coverage"])
            if diagnostic:
                diagnostics.add(diagnostic)
    return diagnostics


def build_gitlab_report(result: dict, *, project_root: Path) -> GitLabReport:
    """Convert selected findings without scanning, executing, or writing files.

    Exact duplicates collapse; different source locations retain distinct
    ordinal fingerprints. Adding/removing otherwise identical occurrences can
    change their ordinals. Malformed findings never produce a clean receipt.
    """
    if not isinstance(result, dict):
        return GitLabReport([], ["Invalid scan result."], False)
    try:
        root = _root_path(project_root)
    except (TypeError, ValueError, OSError):
        return GitLabReport([], ["Invalid project root."], False)
    diagnostics = _scan_diagnostics(result)
    groups: dict[str, dict[tuple[int, int], dict]] = {}
    remaining = MAX_INPUT_FINDINGS
    for spec in _SECTIONS:
        section = spec[0]
        items = result.get(section, [])
        if items is None:
            continue
        if not isinstance(items, list):
            diagnostics.add(f"Invalid finding collection: {section}.")
            continue
        count = min(len(items), remaining)
        if count < len(items):
            diagnostics.add("Finding input limit exceeded; some findings are omitted.")
        remaining -= count
        for item in items[:count]:
            if not isinstance(item, dict):
                diagnostics.add(f"Unrepresentable finding in {section}.")
                continue
            try:
                semantic, location, row, truncated = _candidate(item, spec, root)
            except (TypeError, ValueError, RecursionError, OverflowError):
                diagnostics.add(f"Unrepresentable finding in {section}.")
                continue
            if truncated:
                diagnostics.add(
                    "Description limit exceeded; some descriptions are truncated."
                )
            group = groups.setdefault(semantic, {})
            previous = group.get(location)
            if previous is None or (_SEVERITY_RANK[row["severity"]], _encoded(row)) < (
                _SEVERITY_RANK[previous["severity"]],
                _encoded(previous),
            ):
                group[location] = row
    findings = []
    for semantic, group in sorted(groups.items()):
        for ordinal, (_location, row) in enumerate(sorted(group.items())):
            payload = _encoded([semantic, ordinal]).encode("utf-8")
            findings.append(
                {
                    **row,
                    "fingerprint": hashlib.sha256(payload).hexdigest(),
                }
            )
    findings.sort(
        key=lambda row: (
            row["location"]["path"],
            row["location"]["lines"]["begin"],
            row["check_name"],
            row["fingerprint"],
        )
    )
    if len(findings) > MAX_FINDINGS:
        diagnostics.add("Report finding limit exceeded; some findings are omitted.")
        findings = findings[:MAX_FINDINGS]
    report_bytes = 2
    for index, row in enumerate(findings):
        report_bytes += len(_encoded(row)) + 1
        if report_bytes > MAX_REPORT_BYTES:
            diagnostics.add("Report byte limit exceeded; some findings are omitted.")
            findings = findings[:index]
            break
    return GitLabReport(findings, sorted(diagnostics), not diagnostics)
