# skylos: ignore[SKY-Q502] Bounded scanner-comparison evidence engine.
from __future__ import annotations

import json
import hashlib
import re
from bisect import bisect_left, bisect_right
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urljoin, urlparse


SCHEMA_VERSION = 1
MAX_EXTERNAL_REPORT_BYTES = 50 * 1024 * 1024
MAX_NORMALIZED_FINDINGS = 100_000
MAX_CORRELATION_PATH_BYTES = 4_096
MAX_CORRELATION_PATH_COMPONENTS = 256
MAX_INDEXED_SUFFIX_COMPONENTS = 32
MAX_NORMALIZED_DEFINITIONS = 500_000

_SKYLOS_BUCKETS = {
    "danger": "SECURITY",
    "reliability": "RELIABILITY",
    "ai_defects": "AI_DEFECT",
    "quality": "QUALITY",
    "custom_rules": "QUALITY",
    "secrets": "SECRET",
    "dependency_vulnerabilities": "DEPENDENCY",
    "unused_functions": "DEAD_CODE",
    "unused_imports": "DEAD_CODE",
    "unused_variables": "DEAD_CODE",
    "unused_classes": "DEAD_CODE",
    "unused_parameters": "DEAD_CODE",
    "unused_files": "DEAD_CODE",
    "unused_exports": "DEAD_CODE",
    "unused_fixtures": "DEAD_CODE",
}

_REPORTABLE_DEAD_STATES = {"dead", "likely_dead", "validated_dead"}

_LEVEL_SEVERITY = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "LOW",
}

_SONAR_SEVERITY = {
    "BLOCKER": "CRITICAL",
    "CRITICAL": "HIGH",
    "MAJOR": "MEDIUM",
    "MINOR": "LOW",
    "INFO": "LOW",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

_SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

_BENEFIT_ELIGIBLE_CATEGORIES = {"SECURITY", "RELIABILITY", "QUALITY", "AI_DEFECT"}

_INACTIVE_STATUSES = {
    "ACCEPTED",
    "CLOSED",
    "FALSE-POSITIVE",
    "FALSE_POSITIVE",
    "FIXED",
    "NOT_APPLICABLE",
    "REMOVED",
    "RESOLVED",
    "SAFE",
    "SUPPRESSED",
    "WONTFIX",
    "WONT_FIX",
}


class UnsupportedShadowReport(ValueError):
    """Raised when an incumbent report is not a supported JSON shape."""


def load_json_report(path: str | Path) -> Any:
    report_path = Path(path)
    from skylos.core.safe_cache_io import read_text_no_symlink

    text = read_text_no_symlink(
        report_path,
        max_bytes=MAX_EXTERNAL_REPORT_BYTES,
        encoding="utf-8",
    )
    if text is None:
        raise ValueError(
            f"Report must be a regular, non-symlink UTF-8 file no larger than "
            f"{MAX_EXTERNAL_REPORT_BYTES // (1024 * 1024)} MiB: {report_path}"
        )
    try:
        return json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"Invalid JSON in {report_path}: {exc}") from exc


def normalize_external_report(data: Any) -> dict[str, Any]:
    """Normalize SARIF, Sonar issue-search JSON, or a generic findings array."""
    if not isinstance(data, dict):
        raise UnsupportedShadowReport("External report must be a JSON object")

    if isinstance(data.get("runs"), list):
        normalized = _normalize_sarif(data)
    elif isinstance(data.get("issues"), list):
        normalized = _normalize_sonar(data)
    elif isinstance(data.get("findings"), list):
        normalized = _normalize_generic(data)
    else:
        raise UnsupportedShadowReport(
            "Unsupported report shape; expected SARIF, Sonar issues JSON, or a findings array"
        )

    try:
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError) as exc:
        raise UnsupportedShadowReport(
            "External report cannot be canonicalized safely"
        ) from exc
    normalized["canonical_json_sha256"] = hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()
    return normalized


def _excluded_summary(excluded: Counter[str]) -> dict[str, Any]:
    return {
        "excluded_findings_count": sum(excluded.values()),
        "excluded_by_reason": dict(sorted(excluded.items())),
    }


def _enforce_finding_limit(count: int) -> None:
    if count > MAX_NORMALIZED_FINDINGS:
        raise UnsupportedShadowReport(
            f"Report exceeds the {MAX_NORMALIZED_FINDINGS:,}-finding safety limit"
        )


def _revision_values(data: dict[str, Any]) -> set[str]:
    revisions: set[str] = set()
    for key in ("revision", "revision_id", "commit", "commit_sha", "git_commit"):
        value = data.get(key)
        if value:
            revisions.add(str(value))
    return revisions


def _normalize_repository_identity(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    scp_match = re.fullmatch(r"[^@]+@([^:]+):(.+)", raw)
    if scp_match:
        host, path = scp_match.groups()
        raw = f"ssh://{host}/{path}"
    parsed = urlparse(raw)
    if parsed.scheme and parsed.hostname:
        try:
            port = parsed.port
        except ValueError:
            return None
        default_port = {"http": 80, "https": 443, "ssh": 22}.get(parsed.scheme.lower())
        host = parsed.hostname
        if port and port != default_port:
            host = f"{host}:{port}"
        identity = f"{host}{parsed.path}"
    else:
        identity = raw
    identity = identity.rstrip("/")
    if identity.lower().endswith(".git"):
        identity = identity[:-4]
    return identity


def _external_scope(
    data: dict[str, Any], *, repository_identities: set[str] | None = None
) -> dict[str, Any]:
    raw_scope = data.get("scope")
    scope = raw_scope if isinstance(raw_scope, dict) else {}
    identities = set(repository_identities or set())
    for value in (
        scope.get("repository_identity"),
        scope.get("repository_uri"),
        data.get("repository_identity"),
        data.get("repository_uri"),
    ):
        normalized = _normalize_repository_identity(value)
        if normalized:
            identities.add(normalized)
    raw_identities = scope.get("repository_identities", [])
    if isinstance(raw_identities, list):
        for value in raw_identities:
            normalized = _normalize_repository_identity(value)
            if normalized:
                identities.add(normalized)
    return {
        "complete_repository": scope.get("complete_repository")
        if isinstance(scope.get("complete_repository"), bool)
        else None,
        "repository_identities": sorted(identities),
        "source_root": scope.get("source_root")
        if isinstance(scope.get("source_root"), str) and scope.get("source_root")
        else None,
    }


def _generic_exclusion_reason(item: dict[str, Any]) -> str | None:
    if item.get("active") is False:
        return "inactive"
    if item.get("suppressed") is True:
        return "suppressed"
    status = str(item.get("issue_status") or item.get("status") or "").upper()
    if status in _INACTIVE_STATUSES:
        return "inactive_status"
    return None


def _sarif_exclusion_reason(result: dict[str, Any]) -> str | None:
    kind = str(result.get("kind") or "fail")
    if kind in {"pass", "notApplicable"}:
        return f"sarif_kind_{kind}"
    if str(result.get("baselineState") or "") == "absent":
        return "sarif_baseline_absent"
    suppressions = result.get("suppressions")
    if suppressions is not None and not isinstance(suppressions, list):
        raise UnsupportedShadowReport("SARIF result suppressions must be an array")
    if isinstance(suppressions, list):
        for suppression in suppressions:
            if not isinstance(suppression, dict):
                raise UnsupportedShadowReport(
                    "Each SARIF suppression must be a JSON object"
                )
            if str(suppression.get("status") or "") == "accepted":
                return "sarif_suppression_accepted"
    return None


def _sarif_rule_id(
    result: dict[str, Any],
    raw_rules: list[Any],
    rules_by_id: dict[str, dict[str, Any]],
) -> tuple[str, dict[str, Any]]:
    raw_rule_id = result.get("ruleId")
    if raw_rule_id:
        rule_id = str(raw_rule_id)
        return rule_id, rules_by_id.get(rule_id, {})

    rule_index = result.get("ruleIndex")
    if isinstance(rule_index, int) and not isinstance(rule_index, bool):
        if 0 <= rule_index < len(raw_rules) and isinstance(raw_rules[rule_index], dict):
            rule = raw_rules[rule_index]
            return str(rule.get("id") or "UNKNOWN"), rule
    return "UNKNOWN", {}


def _sarif_run_revisions(run: dict[str, Any]) -> set[str]:
    provenance = run.get("versionControlProvenance", [])
    if not isinstance(provenance, list):
        raise UnsupportedShadowReport("SARIF versionControlProvenance must be an array")
    revisions: set[str] = set()
    for item in provenance:
        if not isinstance(item, dict):
            raise UnsupportedShadowReport(
                "Each SARIF version-control provenance entry must be an object"
            )
        revision = item.get("revisionId")
        if revision:
            revisions.add(str(revision))
    return revisions


def _sarif_run_repository_identities(run: dict[str, Any]) -> set[str]:
    provenance = run.get("versionControlProvenance", [])
    if not isinstance(provenance, list):
        return set()
    identities: set[str] = set()
    for item in provenance:
        if not isinstance(item, dict):
            continue
        normalized = _normalize_repository_identity(item.get("repositoryUri"))
        if normalized:
            identities.add(normalized)
    return identities


def _sarif_execution_signal(run: dict[str, Any]) -> bool | None:
    invocations = run.get("invocations")
    if invocations is None:
        return None
    if not isinstance(invocations, list):
        raise UnsupportedShadowReport("SARIF invocations must be an array")
    signals: list[bool] = []
    for invocation in invocations:
        if not isinstance(invocation, dict):
            raise UnsupportedShadowReport("Each SARIF invocation must be a JSON object")
        successful = invocation.get("executionSuccessful")
        if isinstance(successful, bool):
            signals.append(successful)
    if not signals:
        return None
    return all(signals)


def _sarif_tool_version(driver: dict[str, Any]) -> str | None:
    value = driver.get("semanticVersion") or driver.get("version")
    return str(value) if value else None


def _sarif_fingerprints(result: dict[str, Any]) -> dict[str, Any]:
    combined: dict[str, Any] = {}
    for key in ("fingerprints", "partialFingerprints"):
        values = result.get(key)
        if values is not None and not isinstance(values, dict):
            raise UnsupportedShadowReport(f"SARIF result {key} must be an object")
        if isinstance(values, dict):
            combined.update(values)
    return combined


def _sarif_run_details(run: Any) -> dict[str, Any]:
    if not isinstance(run, dict):
        raise UnsupportedShadowReport("Each SARIF run must be a JSON object")
    tool = run.get("tool")
    if not isinstance(tool, dict):
        raise UnsupportedShadowReport("Each SARIF run must identify a tool")
    driver = tool.get("driver")
    if not isinstance(driver, dict):
        raise UnsupportedShadowReport("Each SARIF tool must contain a driver")
    raw_rules = driver.get("rules", [])
    if not isinstance(raw_rules, list):
        raise UnsupportedShadowReport("SARIF driver rules must be an array")
    if any(not isinstance(rule, dict) for rule in raw_rules):
        raise UnsupportedShadowReport("Each SARIF rule must be a JSON object")
    raw_results = run.get("results", [])
    if not isinstance(raw_results, list):
        raise UnsupportedShadowReport("SARIF run results must be an array")
    return {
        "run": run,
        "driver": driver,
        "tool_name": str(driver.get("name") or "SARIF"),
        "raw_rules": raw_rules,
        "raw_results": raw_results,
        "rules_by_id": {str(rule["id"]): rule for rule in raw_rules if rule.get("id")},
    }


def _normalize_sarif_result(
    result: Any,
    *,
    details: dict[str, Any],
) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(result, dict):
        raise UnsupportedShadowReport("Each SARIF result must be a JSON object")
    exclusion_reason = _sarif_exclusion_reason(result)
    if exclusion_reason:
        return None, exclusion_reason
    rule_id, rule = _sarif_rule_id(result, details["raw_rules"], details["rules_by_id"])
    location = _sarif_location(result, details["run"])
    message = result.get("message", {})
    message_text = (
        message.get("text") or message.get("markdown")
        if isinstance(message, dict)
        else message
    )
    fingerprints = _sarif_fingerprints(result)
    return {
        "source_tool": details["tool_name"],
        "rule_id": rule_id,
        "file_path": location["file_path"],
        "line_number": location["line_number"],
        "end_line": location["end_line"],
        "message": str(message_text or _rule_description(rule) or "Issue"),
        "severity": _sarif_severity(result, rule),
        "category": _sarif_category(result, rule),
        "external_fingerprint": _first_string_value(fingerprints),
        "external_fingerprints": fingerprints,
    }, None


def _normalize_sarif(data: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    tools: set[str] = set()
    tool_versions: dict[str, set[str]] = {}
    revisions = _revision_values(data)
    excluded: Counter[str] = Counter()
    execution_signals: list[bool] = []
    repository_identities: set[str] = set()
    runs = data.get("runs", [])
    if not runs:
        raise UnsupportedShadowReport("SARIF report must contain at least one run")

    raw_finding_count = 0
    for run in runs:
        details = _sarif_run_details(run)
        tool_name = details["tool_name"]
        tools.add(tool_name)
        tool_version = _sarif_tool_version(details["driver"])
        if tool_version:
            tool_versions.setdefault(tool_name, set()).add(tool_version)
        revisions.update(_sarif_run_revisions(run))
        repository_identities.update(_sarif_run_repository_identities(run))
        execution_signal = _sarif_execution_signal(run)
        if execution_signal is not None:
            execution_signals.append(execution_signal)
        raw_finding_count += len(details["raw_results"])
        _enforce_finding_limit(raw_finding_count)
        for result in details["raw_results"]:
            finding, exclusion_reason = _normalize_sarif_result(result, details=details)
            if exclusion_reason:
                excluded[exclusion_reason] += 1
            elif finding is not None:
                findings.append(finding)

    execution_successful = all(execution_signals) if execution_signals else None
    normalized = {
        "format": "sarif",
        "tools": sorted(tools),
        "tool_versions": {
            tool: sorted(versions) for tool, versions in sorted(tool_versions.items())
        },
        "revisions": sorted(revisions),
        "revision_source": "report" if revisions else None,
        "findings": findings,
        "input_complete": False if execution_successful is False else None,
        "execution_successful": execution_successful,
        "scope": _external_scope(data, repository_identities=repository_identities),
    }
    normalized.update(_excluded_summary(excluded))
    return normalized


def _sarif_location(  # skylos: ignore[SKY-Q301] defensive untrusted SARIF location parser
    result: dict[str, Any], run: dict[str, Any]
) -> dict[str, Any]:
    locations = result.get("locations")
    if locations is not None and not isinstance(locations, list):
        raise UnsupportedShadowReport("SARIF result locations must be an array")
    first = locations[0] if isinstance(locations, list) and locations else {}
    if first and not isinstance(first, dict):
        raise UnsupportedShadowReport("Each SARIF location must be a JSON object")
    physical = first.get("physicalLocation", {}) if isinstance(first, dict) else {}
    if physical and not isinstance(physical, dict):
        raise UnsupportedShadowReport("SARIF physicalLocation must be an object")
    artifact = physical.get("artifactLocation", {}) if physical else {}
    region = physical.get("region", {}) if physical else {}
    if artifact and not isinstance(artifact, dict):
        raise UnsupportedShadowReport("SARIF artifactLocation must be an object")
    if region and not isinstance(region, dict):
        raise UnsupportedShadowReport("SARIF region must be an object")
    artifact = artifact if isinstance(artifact, dict) else {}
    region = region if isinstance(region, dict) else {}
    artifact = _resolve_sarif_artifact_location(artifact, run)
    start = _positive_int(region.get("startLine"), default=0)
    end = _positive_int(region.get("endLine"), default=start)
    uri = str(artifact.get("uri") or "")
    base_id = artifact.get("uriBaseId")
    base_map = run.get("originalUriBaseIds")
    if base_id and base_map is not None and not isinstance(base_map, dict):
        raise UnsupportedShadowReport("SARIF originalUriBaseIds must be an object")
    if base_id and isinstance(base_map, dict):
        base = base_map.get(str(base_id))
        if isinstance(base, dict) and base.get("uri"):
            uri = urljoin(str(base["uri"]), uri)
    return {
        "file_path": _normalize_path(uri),
        "line_number": start,
        "end_line": max(start, end),
    }


def _resolve_sarif_artifact_location(
    artifact: dict[str, Any], run: dict[str, Any]
) -> dict[str, Any]:
    if artifact.get("uri"):
        return artifact
    index = artifact.get("index")
    if index is None:
        return artifact
    if not isinstance(index, int) or isinstance(index, bool):
        raise UnsupportedShadowReport("SARIF artifact index must be an integer")
    artifacts = run.get("artifacts")
    if not isinstance(artifacts, list) or not 0 <= index < len(artifacts):
        raise UnsupportedShadowReport("SARIF artifact index is out of range")
    entry = artifacts[index]
    if not isinstance(entry, dict):
        raise UnsupportedShadowReport("Each SARIF artifact must be a JSON object")
    location = entry.get("location")
    if not isinstance(location, dict):
        return artifact
    return {**location, **artifact}


def _rule_description(rule: dict[str, Any]) -> str | None:
    for key in ("shortDescription", "fullDescription"):
        value = rule.get(key)
        if isinstance(value, dict) and value.get("text"):
            return str(value["text"])
    return None


def _sarif_severity(result: dict[str, Any], rule: dict[str, Any]) -> str:
    property_sources = (result.get("properties"), rule.get("properties"))
    for properties in property_sources:
        if not isinstance(properties, dict):
            continue
        for key in ("security-severity", "securitySeverity"):
            raw = properties.get(key)
            try:
                score = float(raw)
            except (TypeError, ValueError):
                continue
            if score >= 9:
                return "CRITICAL"
            if score >= 7:
                return "HIGH"
            if score >= 4:
                return "MEDIUM"
            return "LOW"

    level = result.get("level")
    if not level:
        default_config = rule.get("defaultConfiguration")
        if isinstance(default_config, dict):
            level = default_config.get("level")
    return _LEVEL_SEVERITY.get(str(level or "warning").lower(), "MEDIUM")


def _sarif_category(  # skylos: ignore[SKY-Q301] ordered SARIF tag classifier
    result: dict[str, Any], rule: dict[str, Any]
) -> str:
    properties = result.get("properties")
    properties = properties if isinstance(properties, dict) else {}
    explicit = properties.get("category") or properties.get("softwareQuality")

    rule_properties = rule.get("properties")
    rule_properties = rule_properties if isinstance(rule_properties, dict) else {}
    raw_tags = rule_properties.get("tags")
    tags = [str(tag).lower() for tag in raw_tags] if isinstance(raw_tags, list) else []
    if any("secret" in tag or "credential" in tag for tag in tags):
        return "SECRET"
    if any(
        tag in {"dependency", "dependencies", "sca", "vulnerable-package"}
        for tag in tags
    ):
        return "DEPENDENCY"
    if explicit:
        return _normalize_category(explicit)
    if any(
        tag in {"security", "vulnerability", "cwe", "owasp"}
        or tag.startswith(("cwe-", "owasp-"))
        for tag in tags
    ):
        return "SECURITY"
    if any(tag in {"reliability", "bug", "correctness"} for tag in tags):
        return "RELIABILITY"
    if any(tag in {"dead-code", "unused"} for tag in tags):
        return "DEAD_CODE"
    return "UNKNOWN"


def _normalize_sonar_issue(  # skylos: ignore[SKY-Q301] bounded untrusted Sonar record normalizer
    issue: Any,
) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(issue, dict):
        raise UnsupportedShadowReport("Each Sonar issue must be a JSON object")
    impacts = issue.get("impacts")
    if impacts is not None and (
        not isinstance(impacts, list)
        or any(not isinstance(impact, dict) for impact in impacts)
    ):
        raise UnsupportedShadowReport("Sonar issue impacts must be an array of objects")
    exclusion_reason = _sonar_exclusion_reason(issue)
    if exclusion_reason:
        return None, exclusion_reason
    text_range = issue.get("textRange")
    if text_range is not None and not isinstance(text_range, dict):
        raise UnsupportedShadowReport("Sonar issue textRange must be an object")
    text_range = text_range if isinstance(text_range, dict) else {}
    line = _positive_int(text_range.get("startLine") or issue.get("line"), default=0)
    end_line = _positive_int(text_range.get("endLine"), default=line)
    return {
        "source_tool": "SonarQube",
        "rule_id": str(issue.get("rule") or "UNKNOWN"),
        "file_path": _sonar_component_path(issue),
        "line_number": line,
        "end_line": max(line, end_line),
        "message": str(issue.get("message") or "Issue"),
        "severity": _sonar_issue_severity(issue),
        "category": _sonar_issue_category(issue),
        "external_fingerprint": str(issue.get("key") or "") or None,
        "external_status": str(issue.get("issueStatus") or issue.get("status") or "")
        or None,
    }, None


def _normalize_sonar(data: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    excluded: Counter[str] = Counter()
    raw_issues = data.get("issues", [])
    _enforce_finding_limit(len(raw_issues))
    for issue in raw_issues:
        finding, exclusion_reason = _normalize_sonar_issue(issue)
        if exclusion_reason:
            excluded[exclusion_reason] += 1
        elif finding is not None:
            findings.append(finding)

    normalized = {
        "format": "sonar",
        "tools": ["SonarQube"],
        "tool_versions": {
            "SonarQube": [str(data["version"])] if data.get("version") else []
        },
        "revisions": sorted(_revision_values(data)),
        "revision_source": "report" if _revision_values(data) else None,
        "findings": findings,
        "input_complete": _sonar_input_complete(data, len(raw_issues)),
        "scope": _external_scope(data),
    }
    normalized.update(_excluded_summary(excluded))
    return normalized


def _sonar_exclusion_reason(issue: dict[str, Any]) -> str | None:
    status = str(issue.get("issueStatus") or issue.get("status") or "").upper()
    resolution = str(issue.get("resolution") or "").upper()
    if status in _INACTIVE_STATUSES or resolution in _INACTIVE_STATUSES:
        return "inactive_status"
    return None


def _sonar_input_complete(data: dict[str, Any], findings_count: int) -> bool | None:
    paging = data.get("paging")
    if paging is None:
        return None
    if not isinstance(paging, dict):
        raise UnsupportedShadowReport("Sonar paging must be an object")
    total = paging.get("total")
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        raise UnsupportedShadowReport(
            "Sonar paging total must be a non-negative integer"
        )
    return findings_count >= total


def _sonar_component_path(issue: dict[str, Any]) -> str:
    component = str(issue.get("component") or "")
    project = str(issue.get("project") or "")
    if project and component.startswith(f"{project}:"):
        component = component[len(project) + 1 :]
    elif ":" in component and not _looks_like_windows_path(component):
        component = component.split(":", 1)[1]
    return _normalize_path(component)


def _sonar_issue_severity(issue: dict[str, Any]) -> str:
    candidates: list[str] = []
    impacts = issue.get("impacts")
    if isinstance(impacts, list):
        candidates.extend(
            str(impact.get("severity") or "").upper()
            for impact in impacts
            if isinstance(impact, dict)
        )
    candidates.append(str(issue.get("severity") or "").upper())
    normalized = [_SONAR_SEVERITY.get(value) for value in candidates if value]
    normalized = [value for value in normalized if value]
    if not normalized:
        return "MEDIUM"
    return max(normalized, key=lambda value: _SEVERITY_ORDER[value])


def _sonar_issue_category(issue: dict[str, Any]) -> str:
    impacts = issue.get("impacts")
    if isinstance(impacts, list):
        qualities = [
            str(impact.get("softwareQuality") or "").upper()
            for impact in impacts
            if isinstance(impact, dict)
        ]
        for preferred in ("SECURITY", "RELIABILITY", "MAINTAINABILITY"):
            if preferred in qualities:
                return _normalize_category(preferred)

    issue_type = str(issue.get("type") or "").upper()
    return {
        "VULNERABILITY": "SECURITY",
        "SECURITY_HOTSPOT": "SECURITY",
        "BUG": "RELIABILITY",
        "CODE_SMELL": "QUALITY",
    }.get(issue_type, "UNKNOWN")


def _normalize_generic_finding(  # skylos: ignore[SKY-Q301] bounded untrusted generic record normalizer
    item: Any, *, tool_name: str
) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(item, dict):
        raise UnsupportedShadowReport("Each generic finding must be a JSON object")
    exclusion_reason = _generic_exclusion_reason(item)
    if exclusion_reason:
        return None, exclusion_reason
    location = item.get("location")
    if location is not None and not isinstance(location, dict):
        raise UnsupportedShadowReport("Generic finding location must be a JSON object")
    location = location if isinstance(location, dict) else {}
    line = _positive_int(
        item.get("line_number") or item.get("line") or location.get("line"),
        default=0,
    )
    return {
        "source_tool": str(item.get("source_tool") or tool_name),
        "rule_id": str(item.get("rule_id") or item.get("rule") or "UNKNOWN"),
        "file_path": _normalize_path(
            item.get("file_path") or item.get("file") or location.get("file")
        ),
        "line_number": line,
        "end_line": _positive_int(item.get("end_line"), default=line),
        "message": str(item.get("message") or item.get("title") or "Issue"),
        "severity": _normalize_severity(item.get("severity")),
        "category": _normalize_category(item.get("category")),
        "external_fingerprint": str(item.get("fingerprint") or "") or None,
        "external_status": str(item.get("issue_status") or item.get("status") or "")
        or None,
    }, None


def _normalize_generic(data: dict[str, Any]) -> dict[str, Any]:
    tool_name = str(data.get("tool") or data.get("scanner") or "External")
    findings: list[dict[str, Any]] = []
    excluded: Counter[str] = Counter()
    raw_findings = data.get("findings", [])
    _enforce_finding_limit(len(raw_findings))
    for item in raw_findings:
        finding, exclusion_reason = _normalize_generic_finding(
            item, tool_name=tool_name
        )
        if exclusion_reason:
            excluded[exclusion_reason] += 1
        elif finding is not None:
            findings.append(finding)
    supplied_complete = data.get("complete")
    normalized = {
        "format": "generic",
        "tools": [tool_name],
        "tool_versions": {
            tool_name: [str(data["version"])] if data.get("version") else []
        },
        "revisions": sorted(_revision_values(data)),
        "revision_source": "report" if _revision_values(data) else None,
        "findings": findings,
        "input_complete": supplied_complete
        if isinstance(supplied_complete, bool)
        else None,
        "scope": _external_scope(data),
    }
    normalized.update(_excluded_summary(excluded))
    return normalized


def _prepare_shadow_inputs(
    external_report: dict[str, Any], skylos_result: dict[str, Any]
) -> dict[str, Any]:
    raw_external_findings = external_report.get("findings")
    if not isinstance(raw_external_findings, list) or any(
        not isinstance(item, dict) for item in raw_external_findings
    ):
        raise UnsupportedShadowReport(
            "Normalized external findings must be an array of objects"
        )
    _enforce_finding_limit(len(raw_external_findings))
    external_findings = [dict(item) for item in raw_external_findings]
    raw_summary = skylos_result.get("analysis_summary")
    shape_valid = isinstance(raw_summary, dict) and _valid_skylos_result_shape(
        skylos_result, raw_summary
    )
    skylos_findings = _flatten_skylos_findings(skylos_result) if shape_valid else []
    definitions = _definition_spans(skylos_result) if shape_valid else []
    unused_files = _unused_file_paths(skylos_result) if shape_valid else set()
    skylos_metadata = _skylos_result_metadata(skylos_result, skylos_findings)
    incomplete_categories = set(skylos_metadata["incomplete_categories"])
    external_categories = {
        _normalize_category(finding.get("category")) for finding in external_findings
    }
    uncovered_categories = (
        external_categories - set(skylos_metadata["scanned_categories"]) - {"UNKNOWN"}
    )
    incomplete_categories.update(uncovered_categories)
    return {
        "external_findings": external_findings,
        "skylos_findings": skylos_findings,
        "skylos_metadata": skylos_metadata,
        "external_categories": external_categories,
        "uncovered_external_categories": uncovered_categories,
        "incomplete_categories": incomplete_categories,
        "coverage_limits_comparison": bool(external_categories & incomplete_categories),
        "location_lookup": _build_location_lookup(skylos_findings),
        "reachability_lookup": _build_reachability_lookup(definitions, unused_files),
    }


@dataclass
class _CorrelationStats:
    annotated_external: list[dict[str, Any]] = field(default_factory=list)
    overlapped_skylos: set[int] = field(default_factory=set)
    dead_symbols: set[tuple[str, int, str]] = field(default_factory=set)
    dead_files: set[str] = field(default_factory=set)
    eligible_dead_symbols: set[tuple[str, int, str]] = field(default_factory=set)
    eligible_dead_files: set[str] = field(default_factory=set)
    applied_overlap_locations: set[tuple[str, int]] = field(default_factory=set)
    external_overlap: int = 0
    external_dead: int = 0
    eligible_external_dead: int = 0
    ineligible_external_dead: int = 0
    external_live: int = 0
    external_unknown: int = 0


def _record_external_reachability(
    stats: _CorrelationStats,
    reachability: dict[str, Any],
    *,
    category_eligible: bool,
) -> bool:
    state = reachability["state"]
    dead_context = state in {
        "dead",
        "likely_dead",
        "validated_dead",
        "dead_file",
    }
    if not dead_context:
        if state == "live":
            stats.external_live += 1
        else:
            stats.external_unknown += 1
        return False

    stats.external_dead += 1
    symbol = reachability.get("symbol")
    symbol_key: tuple[str, int, str] | None = None
    if symbol:
        symbol_key = (
            str(reachability.get("file_path") or ""),
            int(reachability.get("start_line") or 0),
            str(symbol),
        )
        stats.dead_symbols.add(symbol_key)
    elif state == "dead_file":
        stats.dead_files.add(str(reachability.get("file_path") or ""))

    if not category_eligible:
        stats.ineligible_external_dead += 1
        return True
    stats.eligible_external_dead += 1
    if symbol_key:
        stats.eligible_dead_symbols.add(symbol_key)
    elif state == "dead_file":
        stats.eligible_dead_files.add(str(reachability.get("file_path") or ""))
    return True


def _deletion_category_exclusion(
    *,
    dead_context: bool,
    category_eligible: bool,
    base_category_eligible: bool,
    normalized_category: str,
) -> str | None:
    if not dead_context or category_eligible:
        return None
    prefix = "incomplete_category" if base_category_eligible else "category"
    return f"{prefix}_{normalized_category.lower()}"


def _correlate_external_findings(
    external_findings: list[dict[str, Any]],
    *,
    location_lookup: dict[str, Any],
    reachability_lookup: dict[str, Any],
    incomplete_categories: set[str],
) -> _CorrelationStats:
    stats = _CorrelationStats()
    for external in external_findings:
        matches, overlapping_rules, overlap_location = _location_correlation(
            external, location_lookup
        )
        if overlap_location is not None and (
            overlap_location not in stats.applied_overlap_locations
        ):
            stats.overlapped_skylos.update(matches)
            stats.applied_overlap_locations.add(overlap_location)
        if matches:
            stats.external_overlap += 1

        reachability = _reachability_for_finding(external, reachability_lookup)
        normalized_category = _normalize_category(external.get("category"))
        base_category_eligible = normalized_category in _BENEFIT_ELIGIBLE_CATEGORIES
        category_eligible = (
            base_category_eligible and normalized_category not in incomplete_categories
        )
        dead_context = _record_external_reachability(
            stats,
            reachability,
            category_eligible=category_eligible,
        )
        annotated = dict(external)
        annotated["shadow"] = {
            "location_overlap": bool(matches),
            "overlapping_skylos_rules": list(overlapping_rules),
            "reachability": reachability,
            "deletion_candidate_category_eligible": dead_context and category_eligible,
            "deletion_candidate_category_exclusion": _deletion_category_exclusion(
                dead_context=dead_context,
                category_eligible=category_eligible,
                base_category_eligible=base_category_eligible,
                normalized_category=normalized_category,
            ),
        }
        stats.annotated_external.append(annotated)
    return stats


def _scope_state(
    *,
    skylos_scope_complete: bool | None,
    external_input_complete: bool | None,
    external_scope_complete: bool | None,
    source_root_conflict: bool,
    multiple_external_identities: bool,
    has_skylos_identity: bool,
    has_external_identity: bool,
    explicit_identity_mismatch: bool,
) -> str:
    if skylos_scope_complete is False:
        return "partial_skylos_scope"
    if skylos_scope_complete is not True:
        return "skylos_scope_unverified"
    if external_input_complete is not True:
        return "incumbent_export_scope_unverified"
    if external_scope_complete is not True:
        return "incumbent_repository_scope_unattested"
    if source_root_conflict:
        return "incumbent_source_root_conflicts_with_repository_scope"
    if multiple_external_identities:
        return "multiple_incumbent_repository_identities"
    if not has_skylos_identity or not has_external_identity:
        return "repository_identity_unverified"
    if explicit_identity_mismatch:
        return "repository_identity_mismatch"
    return "repository_scope_and_identity_verified"


def _scope_assessment(
    external_report: dict[str, Any], skylos_metadata: dict[str, Any]
) -> dict[str, Any]:
    external_input_complete = external_report.get("input_complete")
    skylos_scope = skylos_metadata["comparison_scope"]
    skylos_scope_complete = skylos_scope.get("complete_repository")
    raw_external_scope = external_report.get("scope")
    external_scope = (
        raw_external_scope
        if isinstance(raw_external_scope, dict)
        else _external_scope({})
    )
    skylos_identities = set(skylos_scope.get("repository_identities") or [])
    external_identities = set(external_scope.get("repository_identities") or [])
    identity_match = len(skylos_identities) == 1 and (
        external_identities == skylos_identities
    )
    explicit_identity_mismatch = bool(
        skylos_identities and external_identities and not identity_match
    )
    multiple_external_identities = len(external_identities) > 1
    source_root = external_scope.get("source_root")
    source_root_conflict = bool(
        external_scope.get("complete_repository") is True
        and source_root is not None
        and str(source_root).strip().replace("\\", "/").rstrip("/") not in {"", "."}
    )
    binding_verified = all(
        (
            skylos_scope_complete is True,
            external_input_complete is True,
            external_scope.get("complete_repository") is True,
            identity_match,
            not source_root_conflict,
        )
    )
    state = _scope_state(
        skylos_scope_complete=skylos_scope_complete,
        external_input_complete=external_input_complete,
        external_scope_complete=external_scope.get("complete_repository"),
        source_root_conflict=source_root_conflict,
        multiple_external_identities=multiple_external_identities,
        has_skylos_identity=bool(skylos_identities),
        has_external_identity=bool(external_identities),
        explicit_identity_mismatch=explicit_identity_mismatch,
    )
    return {
        "external_input_complete": external_input_complete,
        "external_scope": external_scope,
        "repository_identity_match": identity_match,
        "explicit_repository_identity_mismatch": explicit_identity_mismatch,
        "multiple_external_repository_identities": multiple_external_identities,
        "external_source_root_conflict": source_root_conflict,
        "binding_verified": binding_verified,
        "state": state,
    }


def _comparison_completeness_state(
    *,
    usable: bool,
    coverage_limited: bool,
    external_input_complete: bool | None,
    same_revision_verified: bool,
    scope_binding_verified: bool,
) -> str:
    if not usable:
        return "incomplete"
    if coverage_limited:
        return "category_coverage_incomplete"
    if external_input_complete is None:
        return "external_completeness_unknown"
    if not same_revision_verified:
        return "revision_unverified"
    if not scope_binding_verified:
        return "scope_unverified"
    return "inputs_verified_same_revision"


def _comparison_completeness_reasons(
    *,
    skylos_core_complete: bool,
    skylos_complete: bool,
    external_input_complete: bool | None,
    revision_blocks_comparison: bool,
    revision_state: str,
    same_revision_verified: bool,
    coverage_limited: bool,
    scope_binding_verified: bool,
    scope_state: str,
) -> list[str]:
    reasons: list[str] = []
    if not skylos_core_complete:
        reasons.append("skylos_core_analysis_incomplete")
    if external_input_complete is False:
        reasons.append("incumbent_export_known_incomplete")
    elif external_input_complete is None:
        reasons.append("incumbent_export_completeness_unknown")
    if revision_blocks_comparison:
        reasons.append(f"revision_{revision_state}")
    elif not same_revision_verified:
        reasons.append("same_revision_unverified")
    if coverage_limited:
        reasons.append("observed_category_coverage_incomplete")
    if not scope_binding_verified:
        reasons.append(scope_state)
    if not skylos_complete:
        reasons.append("requested_profile_coverage_incomplete")
    return reasons or ["inputs_complete_same_revision"]


def _comparison_claim_scope(
    *,
    usable: bool,
    external_input_complete: bool | None,
    same_revision_verified: bool,
    coverage_limited: bool,
    scope_binding_verified: bool,
) -> str:
    if not usable:
        return "not_eligible"
    if external_input_complete is True and same_revision_verified:
        claim_scope = "complete_export_same_revision_verified"
    elif external_input_complete is True:
        claim_scope = "complete_export_revision_unverified"
    elif same_revision_verified:
        claim_scope = "imported_findings_same_revision_verified"
    else:
        claim_scope = "imported_findings_revision_unverified"
    if coverage_limited:
        claim_scope = f"limited_{claim_scope}"
    if not scope_binding_verified:
        claim_scope = f"limited_scope_{claim_scope}"
    return claim_scope


def _comparison_policy(
    external_report: dict[str, Any],
    skylos_result: dict[str, Any],
    skylos_metadata: dict[str, Any],
    *,
    coverage_limits_comparison: bool,
) -> dict[str, Any]:
    scope = _scope_assessment(external_report, skylos_metadata)
    revisions = _revision_comparison(external_report, skylos_result)
    revision_blocks = revisions["state"] in {
        "mismatch",
        "multiple_external_revisions",
        "multiple_skylos_revisions",
    }
    usable = all(
        (
            skylos_metadata["core_complete"],
            scope["external_input_complete"] is not False,
            not revision_blocks,
            not scope["explicit_repository_identity_mismatch"],
            not scope["multiple_external_repository_identities"],
            not scope["external_source_root_conflict"],
        )
    )
    complete = all(
        (
            usable,
            scope["external_input_complete"] is True,
            revisions["same_revision_verified"],
            not coverage_limits_comparison,
            scope["binding_verified"],
        )
    )
    state = _comparison_completeness_state(
        usable=usable,
        coverage_limited=coverage_limits_comparison,
        external_input_complete=scope["external_input_complete"],
        same_revision_verified=revisions["same_revision_verified"],
        scope_binding_verified=scope["binding_verified"],
    )
    reasons = _comparison_completeness_reasons(
        skylos_core_complete=skylos_metadata["core_complete"],
        skylos_complete=skylos_metadata["complete"],
        external_input_complete=scope["external_input_complete"],
        revision_blocks_comparison=revision_blocks,
        revision_state=revisions["state"],
        same_revision_verified=revisions["same_revision_verified"],
        coverage_limited=coverage_limits_comparison,
        scope_binding_verified=scope["binding_verified"],
        scope_state=scope["state"],
    )
    claim_scope = _comparison_claim_scope(
        usable=usable,
        external_input_complete=scope["external_input_complete"],
        same_revision_verified=revisions["same_revision_verified"],
        coverage_limited=coverage_limits_comparison,
        scope_binding_verified=scope["binding_verified"],
    )
    return {
        **scope,
        "revision": revisions,
        "revision_blocks_comparison": revision_blocks,
        "usable": usable,
        "complete": complete,
        "completeness_state": state,
        "completeness_reasons": reasons,
        "claim_scope": claim_scope,
    }


def _apply_benefit_eligibility(
    annotated_external: list[dict[str, Any]], *, report_usable: bool
) -> None:
    for annotated in annotated_external:
        shadow = annotated["shadow"]
        category_eligible = bool(shadow["deletion_candidate_category_eligible"])
        shadow["benefit_eligible"] = report_usable and category_eligible
        if category_eligible and not report_usable:
            shadow["benefit_exclusion_reason"] = "comparison_not_usable"
        else:
            shadow["benefit_exclusion_reason"] = shadow.pop(
                "deletion_candidate_category_exclusion"
            )


def _comparable_skylos_only_findings(
    skylos_findings: list[dict[str, Any]],
    skylos_only: list[dict[str, Any]],
    *,
    external_categories: set[str],
    incomplete_categories: set[str],
) -> tuple[set[str], list[dict[str, Any]]]:
    skylos_categories = {
        _normalize_category(finding.get("category")) for finding in skylos_findings
    }
    comparable_categories = (
        external_categories & skylos_categories
    ) - incomplete_categories
    comparable_findings = [
        finding
        for finding in skylos_only
        if _normalize_category(finding.get("category")) in comparable_categories
    ]
    return comparable_categories, comparable_findings


def _benefit_summary(
    correlation: _CorrelationStats,
    *,
    report_usable: bool,
    report_complete: bool,
    claim_scope: str,
) -> dict[str, Any]:
    if not report_usable:
        return {
            "claim_scope": claim_scope,
            "provisional": not report_complete,
            "review_or_deletion_candidates": None,
            "candidate_symbols": None,
            "candidate_files": None,
            "statement": (
                "No value claim is available because the comparison is "
                "incomplete or invalid."
            ),
        }
    return {
        "claim_scope": claim_scope,
        "provisional": not report_complete,
        "review_or_deletion_candidates": correlation.eligible_external_dead,
        "candidate_symbols": len(correlation.eligible_dead_symbols),
        "candidate_files": len(correlation.eligible_dead_files),
        "statement": (
            f"{'Provisional: ' if not report_complete else ''}review "
            f"{correlation.eligible_external_dead} imported incumbent finding(s) in "
            "evidence-backed unused code "
            f"({len(correlation.eligible_dead_symbols)} symbol(s), "
            f"{len(correlation.eligible_dead_files)} file(s)) as deletion candidates."
        ),
    }


def build_shadow_report(  # skylos: ignore[SKY-C304] explicit receipt schema after extracted policy and correlation
    external_report: dict[str, Any],
    skylos_result: dict[str, Any],
) -> dict[str, Any]:
    """Build a neutral side-by-side effectiveness report.

    Location overlap is deliberately not called validation, and findings in likely-dead
    symbols remain review/deletion candidates rather than automatic false positives.
    """
    prepared = _prepare_shadow_inputs(external_report, skylos_result)
    external_findings = prepared["external_findings"]
    skylos_findings = prepared["skylos_findings"]
    skylos_metadata = prepared["skylos_metadata"]
    external_categories = prepared["external_categories"]
    uncovered_external_categories = prepared["uncovered_external_categories"]
    incomplete_category_set = prepared["incomplete_categories"]
    coverage_limits_comparison = prepared["coverage_limits_comparison"]
    location_lookup = prepared["location_lookup"]
    reachability_lookup = prepared["reachability_lookup"]

    correlation = _correlate_external_findings(
        external_findings,
        location_lookup=location_lookup,
        reachability_lookup=reachability_lookup,
        incomplete_categories=incomplete_category_set,
    )
    overlapped_skylos = correlation.overlapped_skylos
    dead_symbols = correlation.dead_symbols
    dead_files = correlation.dead_files
    external_overlap = correlation.external_overlap
    external_dead = correlation.external_dead
    ineligible_external_dead = correlation.ineligible_external_dead
    external_live = correlation.external_live
    external_unknown = correlation.external_unknown
    annotated_external = correlation.annotated_external

    skylos_only = [
        finding
        for index, finding in enumerate(skylos_findings)
        if index not in overlapped_skylos
    ]
    policy = _comparison_policy(
        external_report,
        skylos_result,
        skylos_metadata,
        coverage_limits_comparison=coverage_limits_comparison,
    )
    external_input_complete = policy["external_input_complete"]
    external_scope = policy["external_scope"]
    repository_identity_match = policy["repository_identity_match"]
    scope_binding_verified = policy["binding_verified"]
    scope_state = policy["state"]
    revisions = policy["revision"]
    report_usable = policy["usable"]
    report_complete = policy["complete"]
    completeness_state = policy["completeness_state"]
    completeness_reasons = policy["completeness_reasons"]
    claim_scope = policy["claim_scope"]

    _apply_benefit_eligibility(
        annotated_external,
        report_usable=report_usable,
    )
    comparable_categories, skylos_only_comparable = _comparable_skylos_only_findings(
        skylos_findings,
        skylos_only,
        external_categories=external_categories,
        incomplete_categories=incomplete_category_set,
    )
    benefit = _benefit_summary(
        correlation,
        report_usable=report_usable,
        report_complete=report_complete,
        claim_scope=claim_scope,
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "shadow",
        "complete": report_complete,
        "usable": report_usable,
        "completeness_state": completeness_state,
        "completeness_reasons": completeness_reasons,
        "coverage_attested": False,
        "revision": revisions,
        "scope": {
            "state": scope_state,
            "binding_verified": scope_binding_verified,
            "skylos": skylos_metadata["comparison_scope"],
            "incumbent": external_scope,
            "incumbent_complete_export_attested": external_input_complete is True,
            "repository_identity_match": repository_identity_match,
        },
        "external": {
            "format": external_report.get("format") or "unknown",
            "tools": list(external_report.get("tools") or []),
            "tool_versions": dict(external_report.get("tool_versions") or {}),
            "revisions": list(external_report.get("revisions") or []),
            "revision_source": external_report.get("revision_source"),
            "canonical_json_sha256": external_report.get("canonical_json_sha256"),
            "execution_successful": external_report.get("execution_successful"),
            "total_findings": len(external_findings),
            "excluded_findings_count": int(
                external_report.get("excluded_findings_count") or 0
            ),
            "excluded_by_reason": dict(external_report.get("excluded_by_reason") or {}),
            "input_complete": external_input_complete,
            "by_severity": _counts(external_findings, "severity"),
            "by_category": _counts(external_findings, "category"),
        },
        "skylos": {
            "total_findings": len(skylos_findings),
            "by_severity": _counts(skylos_findings, "severity"),
            "by_category": _counts(skylos_findings, "category"),
            **skylos_metadata,
        },
        "coverage": {
            "observed_external_categories": sorted(external_categories),
            "skylos_scanned_categories": skylos_metadata["scanned_categories"],
            "observed_comparable_categories": sorted(comparable_categories),
            "incomplete_skylos_categories": skylos_metadata["incomplete_categories"],
            "uncovered_external_categories": sorted(uncovered_external_categories),
            "comparison_incomplete_categories": sorted(incomplete_category_set),
            "all_requested_categories_complete": skylos_metadata["complete"],
            "coverage_limits_comparison": coverage_limits_comparison,
            "raw_unique_counts_are_cross_category": True,
        },
        "comparison": {
            "location_overlap": external_overlap,
            "external_only": len(external_findings) - external_overlap,
            "skylos_only": len(skylos_only),
            "skylos_only_in_observed_comparable_categories": len(
                skylos_only_comparable
            ),
            "skylos_only_by_category": _counts(skylos_only, "category"),
            "external_in_likely_dead_code": external_dead,
            "external_dead_context_excluded_from_benefit": ineligible_external_dead,
            "external_in_live_code": external_live,
            "external_reachability_unknown": external_unknown,
            "affected_likely_dead_symbols": len(dead_symbols),
            "affected_unused_files": len(dead_files),
        },
        "benefit": benefit,
        "external_findings": annotated_external,
        "skylos_only_findings": skylos_only,
        "limitations": [
            "Location overlap is corroboration only; it does not prove rule equivalence.",
            "Likely-dead code is a review/deletion candidate, not an automatic false positive.",
            "Unknown reachability must not be treated as safe or suppressed automatically.",
            "Comparison quality depends on both reports describing the same commit and source tree.",
            "Unknown incumbent export completeness limits value claims to imported findings.",
            "Secrets and dependency findings are reachability context only, not deletion-benefit candidates.",
            "Raw unique counts can span different configured categories and must not be presented as scanner misses.",
            "Input completion and revision verification do not attest that every best-effort detector executed successfully.",
        ],
    }


def _normalized_analysis_errors(result: dict[str, Any]) -> list[dict[str, Any]]:
    raw_errors = result.get("analysis_errors")
    if not isinstance(raw_errors, list):
        return []
    return [dict(error) for error in raw_errors if isinstance(error, dict)]


def _normalized_incomplete_languages(summary: dict[str, Any]) -> list[str]:
    raw_languages = summary.get("incomplete_languages", [])
    if not isinstance(raw_languages, list):
        return ["invalid-completion-metadata"]
    return [str(language) for language in raw_languages]


def _comparison_surface_present(
    total_files: Any,
    skylos_findings: list[dict[str, Any]],
    sca_coverage: Any,
) -> bool:
    has_files = (
        isinstance(total_files, int)
        and not isinstance(total_files, bool)
        and total_files > 0
    )
    supported_manifests = (
        _positive_int(
            sca_coverage.get("supported_manifest_candidate_count")
            or sca_coverage.get("supported_manifest_count"),
            default=0,
        )
        if isinstance(sca_coverage, dict)
        else 0
    )
    return has_files or bool(skylos_findings) or supported_manifests > 0


def _normalized_scanned_categories(summary: dict[str, Any]) -> list[str]:
    raw_categories = summary.get("grade_categories", [])
    categories = (
        sorted({_normalize_category(item) for item in raw_categories})
        if isinstance(raw_categories, list)
        else []
    )
    if "SECURITY" in categories and "RELIABILITY" not in categories:
        categories.append("RELIABILITY")
        categories.sort()
    return categories


def _normalized_comparison_scope(summary: dict[str, Any]) -> dict[str, Any]:
    default = {
        "kind": "unknown",
        "scan_path": None,
        "repository_root": None,
        "complete_repository": None,
        "repository_identities": [],
    }
    raw_scope = summary.get("comparison_scope")
    if not isinstance(raw_scope, dict):
        return default
    raw_identities = raw_scope.get("repository_identities", [])
    identities = (
        sorted(
            {
                normalized
                for value in raw_identities
                if (normalized := _normalize_repository_identity(value))
            }
        )
        if isinstance(raw_identities, list)
        else []
    )
    return {
        "kind": str(raw_scope.get("kind") or "unknown"),
        "scan_path": raw_scope.get("scan_path")
        if isinstance(raw_scope.get("scan_path"), str)
        else None,
        "repository_root": raw_scope.get("repository_root")
        if isinstance(raw_scope.get("repository_root"), str)
        else None,
        "complete_repository": raw_scope.get("complete_repository")
        if isinstance(raw_scope.get("complete_repository"), bool)
        else None,
        "repository_identities": identities,
    }


def _normalized_disabled_checks(summary: dict[str, Any]) -> list[str]:
    raw_checks = summary.get("comparison_disabled_checks", [])
    if not isinstance(raw_checks, list) or not all(
        isinstance(item, str) for item in raw_checks
    ):
        return ["invalid-disabled-check-metadata"]
    return sorted(set(raw_checks))


def _normalized_requested_categories(summary: dict[str, Any]) -> list[str]:
    raw_categories = summary.get("comparison_requested_categories")
    if not isinstance(raw_categories, list) or not all(
        isinstance(item, str) for item in raw_categories
    ):
        return []
    return sorted({_normalize_category(item) for item in raw_categories})


def _incomplete_comparison_categories(
    summary: dict[str, Any],
    *,
    scanned_categories: list[str],
    requested_categories: list[str],
    disabled_checks: list[str],
    ai_verification: Any,
    sca_coverage: Any,
) -> set[str]:
    incomplete: set[str] = set()
    if summary.get("comparison_requested_categories") is not None:
        incomplete.update(
            set(requested_categories) - set(scanned_categories)
            if requested_categories
            else {"UNKNOWN"}
        )
    ai_requested = "AI_DEFECT" in (set(requested_categories) | set(scanned_categories))
    ai_complete = isinstance(ai_verification, dict) and (
        str(ai_verification.get("state") or "").lower() == "complete"
    )
    if ai_requested and not ai_complete:
        incomplete.add("AI_DEFECT")
    if "dependency_hallucinations" in disabled_checks:
        incomplete.add("AI_DEFECT")
    sca_requested = summary.get("comparison_sca_requested") is True
    sca_complete = isinstance(sca_coverage, dict) and all(
        (
            sca_coverage.get("complete") is True,
            sca_coverage.get("category_complete") is True,
        )
    )
    if (sca_requested or "DEPENDENCY" in scanned_categories) and not sca_complete:
        incomplete.add("DEPENDENCY")
    return incomplete


def _skylos_result_metadata(
    skylos_result: dict[str, Any], skylos_findings: list[dict[str, Any]]
) -> dict[str, Any]:
    analysis_errors = _normalized_analysis_errors(skylos_result)
    raw_summary = skylos_result.get("analysis_summary")
    summary = raw_summary if isinstance(raw_summary, dict) else {}
    incomplete_languages = _normalized_incomplete_languages(summary)
    total_files = summary.get("total_files")
    recognized = _valid_skylos_result_shape(skylos_result, summary)
    analysis_error_count = max(
        len(analysis_errors),
        _positive_int(summary.get("analysis_error_count"), default=0),
    )
    sca_coverage = summary.get("sca_coverage")
    comparison_surface_present = _comparison_surface_present(
        total_files,
        skylos_findings,
        sca_coverage,
    )
    core_complete = all(
        (
            recognized,
            analysis_error_count == 0,
            not incomplete_languages,
            comparison_surface_present,
        )
    )
    scanned_categories = _normalized_scanned_categories(summary)
    languages = summary.get("languages")
    excluded_folders = summary.get("excluded_folders")
    ai_verification = summary.get("ai_verification")
    comparison_scope = _normalized_comparison_scope(summary)
    disabled_checks = _normalized_disabled_checks(summary)
    requested_categories = _normalized_requested_categories(summary)
    incomplete_categories = _incomplete_comparison_categories(
        summary,
        scanned_categories=scanned_categories,
        requested_categories=requested_categories,
        disabled_checks=disabled_checks,
        ai_verification=ai_verification,
        sca_coverage=sca_coverage,
    )
    complete = core_complete and not incomplete_categories
    return {
        "complete": complete,
        "core_complete": core_complete,
        "recognized_result": recognized,
        "comparison_surface_present": comparison_surface_present,
        "analysis_error_count": analysis_error_count,
        "analysis_errors": analysis_errors,
        "incomplete_languages": incomplete_languages,
        "total_files": total_files if isinstance(total_files, int) else None,
        "languages": dict(languages) if isinstance(languages, dict) else {},
        "scanned_categories": scanned_categories,
        "requested_categories": requested_categories,
        "comparison_scope": comparison_scope,
        "incomplete_categories": sorted(incomplete_categories),
        "ai_verification": dict(ai_verification)
        if isinstance(ai_verification, dict)
        else None,
        "disabled_checks": disabled_checks,
        "sca_coverage": dict(sca_coverage) if isinstance(sca_coverage, dict) else None,
        "excluded_folders": list(excluded_folders)
        if isinstance(excluded_folders, list)
        else [],
        "version": summary.get("skylos_version") or skylos_result.get("skylos_version"),
        "revision_source": summary.get("revision_source")
        or skylos_result.get("revision_source"),
        "worktree_dirty": summary.get("worktree_dirty"),
        "snapshot_stable": summary.get("snapshot_stable"),
        "canonical_json_sha256": _canonical_json_digest(skylos_result),
    }


def _valid_skylos_result_shape(  # skylos: ignore[SKY-Q301] strict bounded result-shape validator
    result: dict[str, Any], summary: dict[str, Any]
) -> bool:
    total_files = summary.get("total_files")
    analysis_error_count = summary.get("analysis_error_count", 0)
    if (
        not isinstance(result.get("analysis_errors"), list)
        or any(not isinstance(item, dict) for item in result["analysis_errors"])
        or not isinstance(total_files, int)
        or isinstance(total_files, bool)
        or total_files < 0
        or not isinstance(analysis_error_count, int)
        or isinstance(analysis_error_count, bool)
        or analysis_error_count < 0
    ):
        return False

    definitions = result.get("definitions")
    if definitions is not None and not isinstance(definitions, dict):
        return False
    if isinstance(definitions, dict) and len(definitions) > MAX_NORMALIZED_DEFINITIONS:
        return False
    if total_files > 0 and not isinstance(definitions, dict):
        return False
    if isinstance(definitions, dict) and any(
        not _valid_skylos_definition(item) for item in definitions.values()
    ):
        return False

    required_dead_buckets = {
        "unused_functions",
        "unused_imports",
        "unused_variables",
        "unused_classes",
        "unused_parameters",
        "unused_files",
    }
    if not required_dead_buckets.issubset(result):
        return False
    for bucket in _SKYLOS_BUCKETS:
        if bucket not in result:
            continue
        items = result[bucket]
        if not isinstance(items, list) or any(
            not isinstance(item, dict) for item in items
        ):
            return False
    if any(
        not _valid_unused_file_finding(item) for item in result.get("unused_files", [])
    ):
        return False

    incomplete_languages = summary.get("incomplete_languages", [])
    grade_categories = summary.get("grade_categories", [])
    languages = summary.get("languages", {})
    excluded_folders = summary.get("excluded_folders", [])
    return (
        isinstance(incomplete_languages, list)
        and isinstance(grade_categories, list)
        and isinstance(languages, dict)
        and isinstance(excluded_folders, list)
    )


def _valid_skylos_definition(  # skylos: ignore[SKY-Q301] strict bounded definition validator
    value: Any,
) -> bool:
    if not isinstance(value, dict):
        return False
    dead = value.get("dead")
    classification = value.get("dead_code_classification")
    line = value.get("line")
    loc = value.get("loc")
    if (
        not isinstance(dead, bool)
        or classification
        not in {
            None,
            "",
            "alive",
            "dead",
            "likely_dead",
            "validated_dead",
            "uncertain",
        }
        or not isinstance(value.get("file"), str)
        or not value["file"]
        or not isinstance(line, int)
        or isinstance(line, bool)
        or line <= 0
        or not isinstance(loc, int)
        or isinstance(loc, bool)
        or loc <= 0
    ):
        return False
    if classification in _REPORTABLE_DEAD_STATES and dead is not True:
        return False
    if classification == "alive" and dead is not False:
        return False
    reason_tags = value.get("dead_code_reason_tags", [])
    return isinstance(reason_tags, list) and all(
        isinstance(tag, str) for tag in reason_tags
    )


def _valid_unused_file_finding(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    path = value.get("file_path") or value.get("file") or value.get("path")
    return (
        isinstance(path, str)
        and bool(path)
        and value.get("rule_id") in {"SKY-E002", "SKY-E003"}
    )


def _revision_comparison(
    external_report: dict[str, Any], skylos_result: dict[str, Any]
) -> dict[str, Any]:
    external_revisions = {
        str(value) for value in external_report.get("revisions", []) if value
    }
    summary = skylos_result.get("analysis_summary")
    summary = summary if isinstance(summary, dict) else {}
    skylos_revisions = _revision_values(skylos_result) | _revision_values(summary)
    external_source = external_report.get("revision_source")
    skylos_source = summary.get("revision_source") or skylos_result.get(
        "revision_source"
    )
    worktree_dirty = summary.get("worktree_dirty") is True

    if len(external_revisions) > 1:
        state = "multiple_external_revisions"
    elif len(skylos_revisions) > 1:
        state = "multiple_skylos_revisions"
    elif (
        external_revisions
        and skylos_revisions
        and external_revisions != skylos_revisions
    ):
        state = "mismatch"
    elif worktree_dirty:
        state = "skylos_worktree_dirty"
    elif external_revisions and skylos_revisions:
        state = (
            "asserted_match"
            if "cli" in {external_source, skylos_source}
            else "verified_match"
        )
    else:
        state = "unknown"
    return {
        "state": state,
        "same_revision_verified": state == "verified_match",
        "revision_ids_match": state in {"verified_match", "asserted_match"},
        "external_revisions": sorted(external_revisions),
        "skylos_revisions": sorted(skylos_revisions),
        "external_revision_source": external_source,
        "skylos_revision_source": skylos_source,
        "skylos_worktree_dirty": worktree_dirty,
    }


def _canonical_json_digest(data: dict[str, Any]) -> str | None:
    try:
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError):
        return None
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _flatten_skylos_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for bucket, category in _SKYLOS_BUCKETS.items():
        raw_items = result.get(bucket, [])
        if not isinstance(raw_items, list):
            continue
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            line = _positive_int(item.get("line_number") or item.get("line"), default=0)
            findings.append(
                {
                    "source_tool": "Skylos",
                    "source_bucket": bucket,
                    "rule_id": str(item.get("rule_id") or _dead_rule_id(bucket)),
                    "file_path": _normalize_path(
                        item.get("file_path") or item.get("file")
                    ),
                    "line_number": line,
                    "end_line": _positive_int(item.get("end_line"), default=line),
                    "message": str(item.get("message") or item.get("name") or "Issue"),
                    "severity": _normalize_severity(item.get("severity")),
                    "category": _normalize_category(item.get("category") or category),
                    "evidence_contract": item.get("evidence_contract"),
                }
            )
            _enforce_finding_limit(len(findings))
    return findings


def _dead_rule_id(bucket: str) -> str:
    return {
        "unused_functions": "SKY-U001",
        "unused_imports": "SKY-U002",
        "unused_variables": "SKY-U003",
        "unused_classes": "SKY-U004",
        "unused_parameters": "SKY-U006",
        "unused_files": "SKY-E002",
        "unused_exports": "SKY-U000",
        "unused_fixtures": "SKY-U000",
    }.get(bucket, "SKY-U000")


def _definition_spans(result: dict[str, Any]) -> list[dict[str, Any]]:
    spans: list[dict[str, Any]] = []
    definitions = result.get("definitions")
    if not isinstance(definitions, dict):
        return spans

    for key, definition in definitions.items():
        if not isinstance(definition, dict):
            continue
        start = _positive_int(definition.get("line"), default=0)
        if start <= 0:
            continue
        loc = _positive_int(definition.get("loc"), default=1)
        classification = str(definition.get("dead_code_classification") or "")
        is_dead = (
            bool(definition.get("dead")) and classification in _REPORTABLE_DEAD_STATES
        )
        state = (
            classification
            if is_dead
            else "live"
            if classification == "alive"
            else "unknown"
        )
        spans.append(
            {
                "symbol": str(definition.get("name") or key),
                "file_path": _normalize_path(definition.get("file")),
                "start_line": start,
                "end_line": start + max(1, loc) - 1,
                "state": state,
                "classification": classification or None,
                "reason": definition.get("dead_code_reason"),
                "reason_tags": list(definition.get("dead_code_reason_tags"))
                if isinstance(definition.get("dead_code_reason_tags"), list)
                else [],
            }
        )
    return spans


def _unused_file_paths(result: dict[str, Any]) -> set[str]:
    paths: set[str] = set()
    raw_unused_files = result.get("unused_files", [])
    if not isinstance(raw_unused_files, list):
        return paths
    for item in raw_unused_files:
        if isinstance(item, dict):
            path = item.get("file_path") or item.get("file") or item.get("path")
        else:
            path = item
        normalized = _normalize_path(path)
        if normalized:
            paths.add(normalized)
    return paths


def _reachability_for_finding(
    finding: dict[str, Any],
    lookup: dict[str, Any],
) -> dict[str, Any]:
    file_path = _normalize_path(finding.get("file_path"))
    line = _positive_int(finding.get("line_number"), default=0)
    cache_key = (file_path, line)
    cached = lookup["query_cache"].get(cache_key)
    if cached is not None:
        return dict(cached)
    if _invalid_correlation_path(file_path):
        result = {
            "state": "unknown",
            "file_path": file_path,
            "reason": "invalid_or_nonlocal_path",
        }
        lookup["query_cache"][cache_key] = result
        return dict(result)
    matching_paths, ambiguous, match_strength = _unambiguous_matching_paths(
        file_path, lookup["path_index"]
    )
    if ambiguous:
        result = {
            "state": "unknown",
            "file_path": file_path,
            "reason": "ambiguous_path",
        }
        lookup["query_cache"][cache_key] = result
        return dict(result)
    if not matching_paths:
        result = {"state": "unknown", "file_path": file_path}
        lookup["query_cache"][cache_key] = result
        return dict(result)
    if match_strength == "basename":
        result = {
            "state": "unknown",
            "file_path": file_path,
            "reason": "weak_basename_path_match",
        }
        lookup["query_cache"][cache_key] = result
        return dict(result)

    canonical_path = next(iter(matching_paths))
    if canonical_path in lookup["unused_files"]:
        result = {
            "state": "dead_file",
            "file_path": canonical_path,
            "reported_path": file_path,
        }
        lookup["query_cache"][cache_key] = result
        return dict(result)

    definition = _query_interval_tree(
        lookup["definition_intervals"].get(canonical_path), line
    )
    result = (
        dict(definition)
        if definition is not None
        else {"state": "unknown", "file_path": file_path}
    )
    lookup["query_cache"][cache_key] = result
    return dict(result)


def _location_correlation(
    external: dict[str, Any], lookup: dict[str, Any]
) -> tuple[tuple[int, ...], tuple[str, ...], tuple[str, int] | None]:
    external_line = _positive_int(external.get("line_number"), default=0)
    external_path = _normalize_path(external.get("file_path"))
    cache_key = (external_path, external_line)
    cached = lookup["query_cache"].get(cache_key)
    if cached is not None:
        return cached
    if external_line <= 0 or not external_path:
        result = ((), (), None)
        lookup["query_cache"][cache_key] = result
        return result

    matching_paths, ambiguous, match_strength = _unambiguous_matching_paths(
        external_path, lookup["path_index"]
    )
    if ambiguous or not matching_paths or match_strength == "basename":
        result = ((), (), None)
        lookup["query_cache"][cache_key] = result
        return result
    canonical_path = next(iter(matching_paths))
    canonical_location = (canonical_path, external_line)
    result = (
        lookup["by_path_line"].get(canonical_location, ()),
        lookup["rule_ids_by_path_line"].get(canonical_location, ()),
        canonical_location,
    )
    lookup["query_cache"][cache_key] = result
    return result


def _definition_rank(definition: dict[str, Any]) -> tuple[int, int, str]:
    return (
        int(definition["end_line"]) - int(definition["start_line"]),
        -int(definition["start_line"]),
        str(definition.get("symbol") or ""),
    )


def _better_definition(
    left: dict[str, Any] | None, right: dict[str, Any] | None
) -> dict[str, Any] | None:
    if left is None:
        return right
    if right is None:
        return left
    return min(left, right, key=_definition_rank)


def _build_interval_tree(
    definitions: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not definitions:
        return None
    midpoints = sorted(
        (int(item["start_line"]) + int(item["end_line"])) // 2 for item in definitions
    )
    center = midpoints[len(midpoints) // 2]
    left: list[dict[str, Any]] = []
    right: list[dict[str, Any]] = []
    overlapping: list[dict[str, Any]] = []
    for definition in definitions:
        if int(definition["end_line"]) < center:
            left.append(definition)
        elif int(definition["start_line"]) > center:
            right.append(definition)
        else:
            overlapping.append(definition)

    by_start = sorted(overlapping, key=lambda item: int(item["start_line"]))
    prefix_best: list[dict[str, Any]] = []
    best: dict[str, Any] | None = None
    for definition in by_start:
        best = _better_definition(best, definition)
        prefix_best.append(best)

    by_end = sorted(overlapping, key=lambda item: int(item["end_line"]))
    suffix_best: list[dict[str, Any]] = [by_end[-1]] * len(by_end)
    best = None
    for index in range(len(by_end) - 1, -1, -1):
        best = _better_definition(best, by_end[index])
        suffix_best[index] = best

    return {
        "center": center,
        "starts": [int(item["start_line"]) for item in by_start],
        "prefix_best": prefix_best,
        "ends": [int(item["end_line"]) for item in by_end],
        "suffix_best": suffix_best,
        "center_best": min(overlapping, key=_definition_rank),
        "left": _build_interval_tree(left),
        "right": _build_interval_tree(right),
    }


def _query_interval_tree(
    node: dict[str, Any] | None, line: int
) -> dict[str, Any] | None:
    if node is None or line <= 0:
        return None
    center = int(node["center"])
    candidate: dict[str, Any] | None = None
    if line < center:
        index = bisect_right(node["starts"], line) - 1
        if index >= 0:
            candidate = node["prefix_best"][index]
        child_candidate = _query_interval_tree(node["left"], line)
    elif line > center:
        index = bisect_left(node["ends"], line)
        if index < len(node["ends"]):
            candidate = node["suffix_best"][index]
        child_candidate = _query_interval_tree(node["right"], line)
    else:
        return node["center_best"]
    return _better_definition(candidate, child_candidate)


def _unambiguous_matching_paths(
    query: Any, path_index: dict[str, Any]
) -> tuple[set[str], bool, str | None]:
    query_path = _normalize_path(query)
    if _invalid_correlation_path(query_path):
        return set(), False, None
    if query_path in path_index["paths"]:
        return {query_path}, False, "exact"
    for suffix in _path_suffixes(query_path):
        matches = path_index["suffixes"].get(suffix, set())
        if matches:
            strength = "suffix" if "/" in suffix else "basename"
            return (
                (set(matches), False, strength)
                if len(matches) == 1
                else (set(), True, strength)
            )
    return set(), False, None


def _build_path_match_index(candidate_paths: set[str]) -> dict[str, Any]:
    paths = {
        _normalize_path(path)
        for path in candidate_paths
        if not _invalid_correlation_path(path)
    }
    paths.discard("")
    suffixes: dict[str, set[str]] = {}
    for path in paths:
        for suffix in _path_suffixes(path):
            suffixes.setdefault(suffix, set()).add(path)
    return {"paths": paths, "suffixes": suffixes}


def _path_suffixes(value: Any) -> list[str]:
    if _invalid_correlation_path(value):
        return []
    normalized = _normalize_path(value).lstrip("/")
    parts = [part for part in normalized.split("/") if part]
    parts = parts[-MAX_INDEXED_SUFFIX_COMPONENTS:]
    return ["/".join(parts[index:]) for index in range(len(parts))]


def _invalid_correlation_path(value: Any) -> bool:
    normalized = _normalize_path(value)
    if not normalized:
        return False
    if "://" in normalized:
        return True
    parts = normalized.replace("\\", "/").split("/")
    return (
        len(normalized.encode("utf-8")) > MAX_CORRELATION_PATH_BYTES
        or len(parts) > MAX_CORRELATION_PATH_COMPONENTS
        or ".." in parts
    )


def _build_location_lookup(findings: list[dict[str, Any]]) -> dict[str, Any]:
    paths: set[str] = set()
    by_path_line: dict[tuple[str, int], list[int]] = {}
    rule_ids_by_path_line: dict[tuple[str, int], set[str]] = {}
    for index, finding in enumerate(findings):
        path = _normalize_path(finding.get("file_path"))
        line = _positive_int(finding.get("line_number"), default=0)
        if not path or line <= 0:
            continue
        paths.add(path)
        by_path_line.setdefault((path, line), []).append(index)
        rule_ids_by_path_line.setdefault((path, line), set()).add(
            str(finding["rule_id"])
        )
    return {
        "path_index": _build_path_match_index(paths),
        "by_path_line": {key: tuple(value) for key, value in by_path_line.items()},
        "rule_ids_by_path_line": {
            key: tuple(sorted(value)) for key, value in rule_ids_by_path_line.items()
        },
        "query_cache": {},
    }


def _build_reachability_lookup(
    definitions: list[dict[str, Any]], unused_files: set[str]
) -> dict[str, Any]:
    definitions_by_path: dict[str, list[dict[str, Any]]] = {}
    for definition in definitions:
        path = _normalize_path(definition.get("file_path"))
        if path:
            definitions_by_path.setdefault(path, []).append(definition)
    inventory_paths = unused_files | set(definitions_by_path)
    return {
        "path_index": _build_path_match_index(inventory_paths),
        "definition_intervals": {
            path: _build_interval_tree(items)
            for path, items in definitions_by_path.items()
        },
        "unused_files": unused_files,
        "query_cache": {},
    }


def _same_path(left: Any, right: Any) -> bool:
    left_path = _normalize_path(left)
    right_path = _normalize_path(right)
    if not left_path or not right_path:
        return False
    if left_path == right_path:
        return True
    left_path = left_path.lstrip("/")
    right_path = right_path.lstrip("/")
    return left_path.endswith(f"/{right_path}") or right_path.endswith(f"/{left_path}")


def _normalize_path(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.lower().startswith("file:"):
        parsed = urlparse(raw)
        if parsed.netloc and parsed.netloc.lower() != "localhost":
            return f"file://{parsed.netloc}{unquote(parsed.path)}"
        raw = parsed.path
    raw = unquote(raw).replace("\\", "/")
    while raw.startswith("./"):
        raw = raw[2:]
    return raw.rstrip("/")


def _normalize_severity(value: Any) -> str:
    severity = str(value or "MEDIUM").upper()
    if severity in _SEVERITY_ORDER:
        return severity
    return _SONAR_SEVERITY.get(severity, "MEDIUM")


def _normalize_category(value: Any) -> str:
    category = str(value or "UNKNOWN").upper().replace("-", "_")
    return {
        "DANGER": "SECURITY",
        "VULNERABILITY": "SECURITY",
        "SECURITY_HOTSPOT": "SECURITY",
        "BUG": "RELIABILITY",
        "MAINTAINABILITY": "QUALITY",
        "CODE_SMELL": "QUALITY",
        "SECRETS": "SECRET",
        "SCA": "DEPENDENCY",
        "DEPENDENCIES": "DEPENDENCY",
        "AI_DEFECTS": "AI_DEFECT",
    }.get(category, category)


def _positive_int(value: Any, *, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _counts(findings: list[dict[str, Any]], key: str) -> dict[str, int]:
    return dict(
        sorted(Counter(str(item.get(key) or "UNKNOWN") for item in findings).items())
    )


def _first_string_value(values: dict[str, Any]) -> str | None:
    for value in values.values():
        if value is not None:
            return str(value)
    return None


def _looks_like_windows_path(value: str) -> bool:
    return len(value) >= 3 and value[1] == ":" and value[2] in {"/", "\\"}
