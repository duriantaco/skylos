"""Read recorded static traces; never import or execute the scanned project."""

import hashlib
import json

from skylos.cicd.evidence import sanitize_untrusted_text
from skylos.core.safe_cache_io import (
    read_project_text_no_symlink,
    read_text_no_symlink,
)
from skylos.reporting.finding_types import iter_result_findings

MAX_REPORT_BYTES = 256_000_000
MAX_SOURCE_BYTES = 2_000_000
MAX_FINDINGS = 100_000
MAX_VIEW_STEPS = 256


def load_security_findings(report_path):
    text = read_text_no_symlink(report_path, max_bytes=MAX_REPORT_BYTES)
    if text is None:
        raise ValueError("Report must be a regular UTF-8 JSON file, at most 256 MB.")
    try:
        report = json.loads(text)
    except (ValueError, RecursionError) as error:
        raise ValueError("Report is not valid JSON.") from error
    if not isinstance(report, dict):
        raise ValueError("Expected a Skylos JSON report object.")
    findings = []
    for category, finding in iter_result_findings(report):
        if category == "security":
            findings.append(finding)
        if len(findings) > MAX_FINDINGS:
            raise ValueError(
                "Report exceeds the 100,000-security-finding viewer limit."
            )
    findings.sort(key=_finding_key)
    return findings


def _finding_key(finding):
    return (
        str(finding.get("file", "")),
        _integer(finding.get("line")),
        _integer(finding.get("col")),
        str(finding.get("rule_id", "")),
        str(finding.get("message", "")),
    )


def _integer(value):
    try:
        return int(value or 0)
    except (ValueError, TypeError):
        return 0


def select_findings(findings, *, rule=None, file=None, line=None):
    matches = []
    for finding in findings:
        if rule and str(finding.get("rule_id", "")).upper() != rule.upper():
            continue
        if line is not None and _integer(finding.get("line")) != line:
            continue
        if file:
            actual = str(finding.get("file", "")).replace("\\", "/")
            requested = file.replace("\\", "/")
            if actual != requested and not actual.endswith("/" + requested):
                continue
        matches.append(finding)
    return matches


def recorded_trace(finding):
    metadata = finding.get("metadata")
    if isinstance(metadata, dict):
        trace = metadata.get("security_trace")
        if isinstance(trace, dict) and isinstance(trace.get("steps"), list):
            valid_steps = []
            for step in trace["steps"][:MAX_VIEW_STEPS]:
                if isinstance(step, dict):
                    valid_steps.append(step)
            if len(valid_steps) == len(trace["steps"]):
                return trace
            bounded = dict(trace)
            bounded["steps"] = valid_steps
            bounded["status"] = "partial"
            bounded["limitations"] = []
            if isinstance(trace.get("limitations"), list):
                bounded["limitations"] = list(trace["limitations"])
            bounded["limitations"].append(
                "Viewer limited to 256 valid recorded steps; the saved report retains the rest."
            )
            return bounded
    return {
        "version": 1,
        "status": "unknown",
        "steps": [],
        "receiver": {"status": "unknown"},
        "limitations": [
            "This finding has no recorded located trace. Rescan with a trace-capable version; no call chain was inferred by this viewer."
        ],
    }


def trace_coverage(findings):
    """Describe explanation availability separately from detector coverage."""
    statuses = {"source_to_sink": 0, "partial": 0, "unknown": 0, "unavailable": 0}
    failures = 0
    for finding in findings:
        metadata = finding.get("metadata")
        trace = None
        if isinstance(metadata, dict):
            trace = metadata.get("security_trace")
        if not isinstance(trace, dict):
            statuses["unavailable"] += 1
            continue
        status = trace.get("status")
        if status not in statuses:
            status = "unknown"
        statuses[status] += 1
        if trace.get("error"):
            failures += 1
    return {
        "static_only": True,
        "findings": sum(statuses.values()),
        "by_status": statuses,
        "explanation_failures": failures,
        "scope": "Recorded explanation coverage; not proof of runtime exploitation or complete external callers.",
    }


def source_context(trace, step, root):
    if root is None:
        raise ValueError("Source viewing requires an explicit --root directory.")
    filename = step.get("file")
    line = _integer(step.get("line"))
    if not isinstance(filename, str) or not filename or line < 1:
        raise ValueError("This recorded step has no source location.")
    expected = step.get("source_sha256")
    if not expected:
        digests = trace.get("file_digests")
        if isinstance(digests, dict):
            expected = digests.get(filename)
    if not isinstance(expected, str) or len(expected) != 64:
        raise ValueError("This step has no source digest; source cannot be verified.")
    source = read_project_text_no_symlink(
        root, filename, max_bytes=MAX_SOURCE_BYTES, newline=""
    )
    if source is None:
        raise ValueError(
            "Source is unavailable, outside --root, a symlink, or too large."
        )
    actual = hashlib.sha256(source.encode("utf-8")).hexdigest()
    if actual != expected:
        raise ValueError("Source changed since the scan; rescan before following it.")
    lines = source.splitlines()
    if line > len(lines):
        raise ValueError("Recorded source line is outside the verified file.")
    context = []
    for index in range(max(0, line - 3), min(len(lines), line + 2)):
        label = " "
        if index + 1 == line:
            label = ">"
        original = lines[index]
        indentation = original[: len(original) - len(original.lstrip(" \t"))]
        text = indentation.expandtabs(4)[:80] + sanitize_untrusted_text(
            original.lstrip(" \t"), max_length=400, neutralize_mentions=False
        )
        context.append(f"{label} {index + 1}: {text}")
    return context
