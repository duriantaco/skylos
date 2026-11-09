"""The quality gate Skylos Cloud syncs into ``.skylos/config.yaml``.

``skylos sync pull`` (and ``SKYLOS_SYNCED_POLICY_FILE`` in CI) hands the CLI
the gate Skylos Cloud evaluates: ``enabled``, ``mode`` (zero-new, category,
severity or both), ``by_category`` and ``by_severity`` limits, and the
``block_secrets`` switch. This module reads that gate the way Cloud reads a
saved policy (``readAnalysisPolicyConfig`` in ``src/lib/policy-config.ts``)
and builds the conditions Cloud checks (``evaluateScanGate`` in
``src/lib/scan-gate-core.ts``).

Cloud files each finding the CLI uploads under one of five categories and four
severities: the CLI sends native SARIF and Cloud's ``pickCategory`` and
``pickSeverity`` (``src/lib/sarif.ts``), then the upload contract
(``contracts/upload/v1.json``), decide them. ``cloud_category`` and
``cloud_severity`` follow those rules.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

CLOUD_GATE_MODES = ("zero-new", "category", "severity", "both")
DEFAULT_CLOUD_GATE_MODE = "zero-new"
CATEGORY_KEYS = ("SECURITY", "SECRET", "QUALITY", "DEAD_CODE", "DEPENDENCY")
SEVERITY_KEYS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
CLOUD_GATE_KEYS = ("mode", "by_category", "by_severity")
CATEGORY_MODES = ("zero-new", "category", "both")
SEVERITY_MODES = ("severity", "both")

CLOUD_GATE_SCOPE_NOTE = (
    "Skylos Cloud counts only new issues. Run skylos . -a --gate --diff "
    "origin/main to check what this branch changes."
)
CLOUD_GATE_OFF_NOTE = (
    "Skylos Cloud has the quality gate turned off, so the built-in limits apply."
)
UNUSED_CLOUD_GATE_NOTE = (
    "This --diff check reads policy from the base branch, which has no Skylos "
    "Cloud gate, so the gate in your .skylos/config.yaml is not used."
)
CLOUD_AI_DEFECT_HINT = (
    "Your Skylos Cloud policy fails the gate on AI-code issues at this "
    "severity (Fail on AI-code issues)."
)

_SECTION_CATEGORIES = {
    "danger": "SECURITY",
    "secrets": "SECRET",
    "quality": "QUALITY",
    "dependencies": "DEPENDENCY",
    "dead_code": "DEAD_CODE",
}
_RULE_PREFIX_CATEGORIES = (
    ("SKY-SCA", "DEPENDENCY"),
    ("SKY-SC", "SECURITY"),
    ("SKY-D", "SECURITY"),
    ("SKY-S", "SECRET"),
    ("SKY-U", "DEAD_CODE"),
    ("SKY-Q", "QUALITY"),
)
_SECRET_MESSAGE_WORDS = ("secret", "apikey", "api key", "token")
_DEAD_CODE_MESSAGE_WORDS = ("dead code", "unused")
_SEVERITY_ALIASES = {
    "WARN": "MEDIUM",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    "ERROR": "HIGH",
}
_GATE_SECTIONS = (
    "danger",
    "reliability",
    "ai_defects",
    "quality",
    "secrets",
    "dependencies",
    "dead_code",
)

_CATEGORY_WORDS = {
    "SECURITY": ("security", "security issue", None),
    "SECRET": ("secrets", "secret", None),
    "QUALITY": ("quality", "quality issue", None),
    "DEAD_CODE": ("dead code", "dead code issue", None),
    "DEPENDENCY": (
        "dependency vulnerabilities",
        "dependency vulnerability",
        "dependency vulnerabilities",
    ),
}
_CATEGORY_SCANNED = {
    "SECURITY": ("security", ("danger", "reliability")),
    "SECRET": ("secrets", ("secrets",)),
    "QUALITY": ("quality", ("quality",)),
    "DEAD_CODE": ("dead_code", ("unused_functions",)),
    "DEPENDENCY": ("dependencies", ("dependency_vulnerabilities",)),
}


@dataclass(frozen=True)
class CloudGateCondition:
    """One limit of the synced gate and the findings counted against it."""

    kind: str
    key: str
    label: str
    noun: str
    plural: str | None
    limit: int
    issues: tuple

    @property
    def failed(self):
        return len(self.issues) > self.limit


def _cloud_bool(value, default):
    if value is True or value is False:
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text == "true":
            return True
        if text == "false":
            return False
    return default


def _cloud_limit(value):
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(value, 0)
    if isinstance(value, float) and math.isfinite(value):
        return max(math.floor(value), 0)
    return 0


def _cloud_limits(value, keys):
    if not isinstance(value, dict):
        value = {}
    return {key: _cloud_limit(value.get(key)) for key in keys}


def cloud_gate_policy(raw):
    """The synced gate as Skylos Cloud reads it, or None for a CLI-style gate.

    Only a gate with Cloud's own keys (``mode``, ``by_category`` or
    ``by_severity``) counts. An unknown mode reads as zero-new and a missing
    or unusable limit as 0, as in Cloud, so a malformed gate is never looser.
    """
    if not isinstance(raw, dict):
        return None
    if not any(key in raw for key in CLOUD_GATE_KEYS):
        return None
    mode = raw.get("mode")
    if mode not in CLOUD_GATE_MODES:
        mode = DEFAULT_CLOUD_GATE_MODE
    return {
        "enabled": _cloud_bool(raw.get("enabled"), True),
        "mode": mode,
        "by_category": _cloud_limits(raw.get("by_category"), CATEGORY_KEYS),
        "by_severity": _cloud_limits(raw.get("by_severity"), SEVERITY_KEYS),
        "block_secrets": _cloud_bool(raw.get("block_secrets"), False),
        "ignore_unreachable_dependencies": raw.get("ignore_unreachable_dependencies")
        is True,
    }


_PLAIN_ADVISORY_ID = re.compile(
    r"(?:CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+)",
    re.IGNORECASE,
)
_MALWARE_CWE = re.compile(r"(?:CWE-)?506", re.IGNORECASE)
_CWE_KEYS = ("cwe", "cwes", "cwe_ids", "cweIds", "cwe_id")
_REACHABILITY_VERDICTS = frozenset(
    {"reachable", "unreachable_static", "unreachable_dynamic", "inconclusive"}
)


def _is_malware_cwe(value, depth=0):
    if depth > 3:
        return False
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value == 506
    if isinstance(value, str):
        return _MALWARE_CWE.fullmatch(value.strip()) is not None
    if isinstance(value, list):
        return any(_is_malware_cwe(entry, depth + 1) for entry in value[:100])
    if isinstance(value, dict):
        return any(
            _is_malware_cwe(value.get(key), depth + 1)
            for key in ("cweId", "cwe_id", "id", "cwe")
        )
    return False


def _advisory_ids(metadata):
    ids = [
        metadata[key]
        for key in ("vuln_id", "display_id")
        if isinstance(metadata.get(key), str)
    ]
    aliases = metadata.get("aliases")
    if isinstance(aliases, list):
        ids.extend(alias for alias in aliases if isinstance(alias, str))
    return ids


def _metadata_is_malicious(metadata):
    if metadata.get("malicious") is True:
        return True
    database_specific = metadata.get("database_specific")
    if not isinstance(database_specific, dict):
        database_specific = {}
    for source in (metadata, database_specific):
        if any(_is_malware_cwe(source.get(key)) for key in _CWE_KEYS):
            return True
    for origins in (
        metadata.get("malicious_packages_origins"),
        database_specific.get("malicious-packages-origins"),
    ):
        if isinstance(origins, list) and origins:
            return True
    return any(
        advisory.strip().upper().startswith("MAL-")
        for advisory in _advisory_ids(metadata)
    )


def _only_plain_advisory_ids(metadata):
    vuln_id = metadata.get("vuln_id")
    if not isinstance(vuln_id, str) or not _PLAIN_ADVISORY_ID.fullmatch(vuln_id.strip()):
        return False
    aliases = metadata.get("aliases")
    if aliases is not None and not isinstance(aliases, list):
        return False
    return all(
        _PLAIN_ADVISORY_ID.fullmatch(advisory.strip())
        for advisory in _advisory_ids(metadata)
    )


def _reachability_verdict(metadata):
    nested = metadata.get("reachability")
    candidates = [nested, metadata.get("reachability_verdict")]
    if isinstance(nested, dict):
        candidates = [nested.get("verdict"), metadata.get("reachability_verdict")]
    for value in candidates:
        if isinstance(value, str) and value.strip().lower() in _REACHABILITY_VERDICTS:
            return value.strip().lower()
    return None


def cloud_ignores_unreachable_dependency(finding):
    """Whether Cloud's "ignore statically unreachable dependency CVEs" skips it.

    Mirrors Skylos Cloud: only a plain CVE/GHSA/PYSEC advisory with a static
    unreachable verdict is skipped. Malware (a MAL id, CWE-506, OpenSSF
    malicious-packages origins or ``malicious``), any other advisory id and a
    missing verdict always count.
    """
    if not isinstance(finding, dict):
        return False
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        return False
    if _is_malware_cwe(finding.get("cwes")) or _metadata_is_malicious(metadata):
        return False
    if not _only_plain_advisory_ids(metadata):
        return False
    return _reachability_verdict(metadata) == "unreachable_static"


def _finding_text(finding, key):
    if not isinstance(finding, dict):
        return ""
    return str(finding.get(key) or "")


def cloud_category(section, finding):
    """The category Skylos Cloud files an uploaded finding under.

    Danger, secrets, quality, dependency and dead-code results keep their
    category. Cloud does not take the CLI's AI_DEFECT, RELIABILITY or CUSTOM
    labels, so those findings get a category from the rule ID prefix, then
    from their message, then QUALITY.
    """
    category = _SECTION_CATEGORIES.get(section)
    if category:
        return category
    rule_id = (
        _finding_text(finding, "rule_id") or _finding_text(finding, "id")
    ).upper()
    for prefix, prefix_category in _RULE_PREFIX_CATEGORIES:
        if rule_id.startswith(prefix):
            return prefix_category
    message = _finding_text(finding, "message").lower()
    if any(word in message for word in _SECRET_MESSAGE_WORDS):
        return "SECRET"
    if any(word in message for word in _DEAD_CODE_MESSAGE_WORDS):
        return "DEAD_CODE"
    return "QUALITY"


def cloud_severity(finding):
    """The severity Skylos Cloud gates an uploaded finding at.

    A missing, UNKNOWN or unrecognised severity is stored as MEDIUM.
    """
    severity = _finding_text(finding, "severity").strip().upper()
    severity = _SEVERITY_ALIASES.get(severity, severity)
    if severity in SEVERITY_KEYS:
        return severity
    return "MEDIUM"


def cloud_gate_rows(found, custom_rules=(), *, ignore_unreachable_dependencies=False):
    """Every gate finding with the category and severity Cloud gives it.

    With ``ignore_unreachable_dependencies`` the dependency findings Cloud
    would skip (see ``cloud_ignores_unreachable_dependency``) are left out.
    """
    custom_ids = {id(finding) for finding in custom_rules or ()}
    rows = []
    for section in _GATE_SECTIONS:
        for finding in found.get(section) or ():
            row_section = section
            if section == "quality" and id(finding) in custom_ids:
                row_section = "custom_rules"
            category = cloud_category(row_section, finding)
            if (
                ignore_unreachable_dependencies
                and category == "DEPENDENCY"
                and cloud_ignores_unreachable_dependency(finding)
            ):
                continue
            rows.append((finding, category, cloud_severity(finding)))
    return rows


def _issues(rows, *, category=None, severity=None):
    return tuple(
        finding
        for finding, row_category, row_severity in rows
        if (category is None or row_category == category)
        and (severity is None or row_severity == severity)
    )


def cloud_gate_conditions(policy, found, custom_rules=()):
    """The limits an enabled synced gate applies, in the order they are shown.

    Critical security issues always fail, as in Cloud. The mode adds limits
    per category (zero-new: every category at 0) and per severity. Secrets
    keep the local floor: never more than 0, whatever Cloud allows.
    """
    rows = cloud_gate_rows(
        found,
        custom_rules,
        ignore_unreachable_dependencies=policy.get("ignore_unreachable_dependencies")
        is True,
    )
    mode = policy["mode"]
    conditions = [
        CloudGateCondition(
            "critical",
            "CRITICAL_SECURITY",
            "critical security",
            "critical security issue",
            None,
            0,
            _issues(rows, category="SECURITY", severity="CRITICAL"),
        )
    ]
    if mode in CATEGORY_MODES:
        for category in CATEGORY_KEYS:
            limit = 0
            if mode != "zero-new" and category != "SECRET":
                limit = policy["by_category"][category]
            label, noun, plural = _CATEGORY_WORDS[category]
            conditions.append(
                CloudGateCondition(
                    "category",
                    category,
                    label,
                    noun,
                    plural,
                    limit,
                    _issues(rows, category=category),
                )
            )
    if mode in SEVERITY_MODES:
        for severity in SEVERITY_KEYS:
            conditions.append(
                CloudGateCondition(
                    "severity",
                    severity,
                    severity.lower(),
                    f"{severity.lower()} severity issue",
                    None,
                    policy["by_severity"][severity],
                    _issues(rows, severity=severity),
                )
            )
    if mode not in CATEGORY_MODES:
        secrets = tuple(found.get("secrets") or ())
        if policy["block_secrets"]:
            secrets = _issues(rows, category="SECRET")
        conditions.append(
            CloudGateCondition(
                "secrets", "SECRET", "secrets", "secret", None, 0, secrets
            )
        )
    return conditions


def category_label(category):
    """The word the gate lines use for one Cloud category."""
    return _CATEGORY_WORDS[category][0]


def cloud_category_scanned(category, results):
    """Whether the scan ran the checks behind one Cloud category."""
    grade_name, result_keys = _CATEGORY_SCANNED[category]
    if not isinstance(results, dict):
        return False
    summary = results.get("analysis_summary")
    if not isinstance(summary, dict):
        summary = {}
    scanned = summary.get("grade_categories")
    if isinstance(scanned, list):
        return grade_name in scanned
    return any(key in results for key in result_keys)
