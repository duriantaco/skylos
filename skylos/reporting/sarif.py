import copy
import hashlib
import os
import json
import re

from skylos.cicd.evidence import sanitize_bounded_payload, sanitize_untrusted_text
from skylos.core.evidence_contract import finding_evidence_contract
from skylos.deadcode.finding_evidence import dead_code_finding_evidence_payload


_MAX_SARIF_MESSAGE_LENGTH = 4_000
_MAX_SARIF_SNIPPET_LENGTH = 2_000
_MAX_SARIF_METADATA_TEXT_LENGTH = 500
_MAX_SARIF_METADATA_ITEMS = 32
_MAX_SARIF_DEPENDENCY_METADATA_ITEMS = 64
_MAX_SARIF_METADATA_NODES = 256


_MAX_SARIF_RELATED_LOCATIONS = 32
_MAX_SARIF_FLOW_STEPS = 32
_FINGERPRINT_KEY = "skylosFindingHash/v1"
_MAX_FINGERPRINT_SOURCE_BYTES = 5_000_000

# Categories whose rules GitHub code scanning should rank as security alerts.
_SECURITY_CATEGORIES = {"SECURITY", "SECRET", "DEPENDENCY"}

# GitHub maps security-severity to: >=9.0 critical, 7.0-8.9 high,
# 4.0-6.9 medium, 0.1-3.9 low.
_SECURITY_SEVERITY_SCORES = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "WARN": 5.5,
    "WARNING": 5.5,
    "LOW": 3.0,
    "INFO": 1.0,
}

_WS_RE = re.compile(r"\s+")
_DIGITS_RE = re.compile(r"\d+")


def _is_security_finding(finding):
    category = str(finding.get("category") or "").upper()
    return category in _SECURITY_CATEGORIES


def security_severity_score(finding):
    """Numeric 0.0-10.0 score used for SARIF ``security-severity``."""
    metadata = finding.get("metadata")
    if isinstance(metadata, dict):
        try:
            cvss = float(metadata.get("cvss_score"))
        except (TypeError, ValueError, OverflowError):
            cvss = None
        if cvss is not None and 0.0 < cvss <= 10.0:
            return round(cvss, 1)
    severity = str(finding.get("severity") or "").upper()
    return _SECURITY_SEVERITY_SCORES.get(severity, 5.5)


def _normalize_fingerprint_text(value):
    return _WS_RE.sub(" ", str(value or "")).strip()


def compute_partial_fingerprint(rule_id, file_path, anchor):
    """Line-independent fingerprint: rule id + normalized path + anchor text.

    ``anchor`` should be content that survives line shifts (symbol name,
    normalized snippet/source line, dependency identity) - never a line number.
    """
    payload = "\x1f".join(
        [
            str(rule_id or ""),
            normalize_file_path_for_sarif(file_path),
            _normalize_fingerprint_text(anchor),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()


def severity_to_sarif_level(severity):
    severity_text = str(severity or "").upper()
    if severity_text in {"CRITICAL", "HIGH"}:
        return "error"
    if severity_text == "MEDIUM":
        return "warning"
    return "note"


def _positive_sarif_integer(value, default=1):
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return number if number >= 1 else default


def normalize_file_path_for_sarif(file_path=None):
    raw_path = sanitize_untrusted_text(
        file_path or "",
        max_length=1_000,
        preserve_newlines=False,
        neutralize_mentions=False,
    )
    cleaned_path = raw_path.replace("\\", "/").strip()

    if cleaned_path.lower().startswith("file://"):
        cleaned_path = cleaned_path[7:]

    try:
        repo_root = os.getcwd().replace("\\", "/").rstrip("/") + "/"
        if cleaned_path.startswith(repo_root):
            cleaned_path = cleaned_path[len(repo_root) :]
    except Exception:
        pass

    cleaned_path = cleaned_path.lstrip("/")
    return cleaned_path or "unknown"


class SarifExporter:
    def __init__(
        self,
        findings,
        tool_name="Skylos",
        version="1.0.0",
        *,
        analyzer_owned=False,
    ):
        self.findings = findings
        self.tool_name = tool_name
        self.version = version
        self.analyzer_owned = analyzer_owned
        self._source_cache = {}

    def generate(self):
        from skylos.rules.quality.standards import get_cwe_taxa

        cwe_taxa = get_cwe_taxa()
        run = {
            "tool": {
                "driver": {
                    "name": self.tool_name,
                    "version": self.version,
                    "rules": self._get_unique_rules(),
                }
            },
            "results": self._get_results(),
        }

        if cwe_taxa:
            run["taxonomies"] = [
                {
                    "name": "CWE",
                    "version": "4.14",
                    "organization": "MITRE",
                    "shortDescription": {"text": "Common Weakness Enumeration"},
                    "taxa": cwe_taxa,
                }
            ]

        sarif_log = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [run],
        }
        return sarif_log

    def write(self, path):
        with open(
            path, "w", encoding="utf-8"
        ) as f:  # skylos: ignore[SKY-D215] user-selected SARIF output path
            json.dump(self.generate(), f, indent=2)

    def _get_unique_rules(self):
        rules = {}
        security_scores = {}
        for finding in self.findings:
            if not isinstance(finding, dict) or not _is_security_finding(finding):
                continue
            rid = sanitize_untrusted_text(
                finding.get("rule_id") or "UNKNOWN", max_length=120
            )
            score = security_severity_score(finding)
            security_scores[rid] = max(score, security_scores.get(rid, 0.0))

        for finding in self.findings:
            rule_id = sanitize_untrusted_text(
                finding.get("rule_id") or "UNKNOWN",
                max_length=120,
            )
            if rule_id in rules:
                continue

            msg_text = sanitize_untrusted_text(
                finding.get("message") or "",
                max_length=_MAX_SARIF_MESSAGE_LENGTH,
                markdown=True,
            )
            fallback_title = msg_text.splitlines()[0] if msg_text.strip() else rule_id

            title_raw = (
                finding.get("title") or finding.get("rule_name") or fallback_title
            )
            if str(
                finding.get("category") or ""
            ).upper() == "PUBLISHER_CHANGE" and not finding.get("title"):
                title_raw = "Review npm publisher change after release dormancy"
            title = sanitize_untrusted_text(
                title_raw,
                max_length=120,
                markdown=True,
            ).strip()

            level = severity_to_sarif_level(finding.get("severity"))

            cat = sanitize_untrusted_text(
                finding.get("category") or "",
                max_length=80,
            ).upper()
            tags = []
            if cat:
                tags.append(cat.lower())
            if cat == "SECURITY":
                tags.append("security")
            tags = list(dict.fromkeys(tags))

            rule_entry = {
                "id": rule_id,
                "shortDescription": {"text": title or rule_id},
                "defaultConfiguration": {"level": level},
                "properties": {"tags": tags},
                "helpUri": sanitize_untrusted_text(
                    finding.get("help_uri")
                    or f"https://docs.skylos.dev/rules/{rule_id}",
                    max_length=1_000,
                    markdown=False,
                    neutralize_mentions=False,
                ),
            }

            cwe_list = finding.get("cwe", [])
            if isinstance(cwe_list, list) and cwe_list:
                safe_cwe_ids = list(
                    dict.fromkeys(
                        sanitize_untrusted_text(cwe.get("id"), max_length=80)
                        for cwe in cwe_list[:_MAX_SARIF_METADATA_ITEMS]
                        if isinstance(cwe, dict) and cwe.get("id")
                    )
                )
                rule_entry["relationships"] = [
                    {
                        "target": {
                            "id": cwe_id,
                            "toolComponent": {"name": "CWE"},
                        },
                        "kinds": ["superset"],
                    }
                    for cwe_id in safe_cwe_ids
                ]
                tags.extend(safe_cwe_ids)
                tags.extend(
                    f"external/cwe/{cwe_id.lower()}"
                    for cwe_id in safe_cwe_ids
                    if cwe_id.upper().startswith("CWE-")
                )

            if rule_id in security_scores:
                if "security" not in tags:
                    tags.append("security")
                rule_entry["properties"]["security-severity"] = (
                    f"{security_scores[rule_id]:.1f}"
                )
            rule_entry["properties"]["tags"] = list(dict.fromkeys(tags))

            rules[rule_id] = rule_entry

        return list(rules.values())

    def _get_results(self):
        results = []
        fingerprint_counts = {}

        for finding in self.findings:
            rule_id = sanitize_untrusted_text(
                finding.get("rule_id") or "UNKNOWN",
                max_length=120,
            )
            level = severity_to_sarif_level(finding.get("severity"))

            message_text = sanitize_untrusted_text(
                finding.get("message") or "(no message)",
                max_length=_MAX_SARIF_MESSAGE_LENGTH,
                markdown=True,
            )

            file_path = normalize_file_path_for_sarif(
                finding.get("file_path") or finding.get("file")
            )

            line_number = _positive_sarif_integer(
                finding.get("line_number") or finding.get("line") or 1
            )
            column_number = _positive_sarif_integer(
                finding.get("col_number") or finding.get("col") or 1
            )

            snippet_text = finding.get("snippet")
            if snippet_text is not None:
                snippet_text = sanitize_untrusted_text(
                    snippet_text,
                    max_length=_MAX_SARIF_SNIPPET_LENGTH,
                    markdown=False,
                    preserve_newlines=True,
                    neutralize_mentions=False,
                )

            category = sanitize_untrusted_text(
                finding.get("category") or "QUALITY",
                max_length=80,
            ).upper()

            properties = {"category": category}
            if category == "PUBLISHER_CHANGE":
                properties["review_only"] = True

            review_decision = (
                finding.get("review_decision")
                if self.analyzer_owned and finding.get("_skylos_trusted_review") is True
                else None
            )
            if isinstance(review_decision, dict):
                safe_review = _sanitize_sarif_payload(review_decision)
                if safe_review:
                    properties["skylos_review_decision"] = safe_review

            kind = finding.get("kind")
            if kind:
                properties["kind"] = sanitize_untrusted_text(kind, max_length=120)

            control_type = finding.get("control_type")
            if control_type:
                properties["control_type"] = sanitize_untrusted_text(
                    control_type,
                    max_length=120,
                )

            metadata = finding.get("metadata")
            if isinstance(metadata, dict) and metadata:
                # Lockfile environment context plus full advisory details can
                # exceed 32 fields. Keep their locations without changing the
                # existing total-node, depth, text or redaction safeguards.
                metadata_items = (
                    _MAX_SARIF_DEPENDENCY_METADATA_ITEMS
                    if category in {"DEPENDENCY", "PUBLISHER_CHANGE"}
                    else _MAX_SARIF_METADATA_ITEMS
                )
                safe_metadata = _sanitize_sarif_payload(
                    metadata, max_items=metadata_items
                )
                if safe_metadata:
                    properties["skylos_metadata"] = safe_metadata

            safe_evidence_input = _sanitize_sarif_payload(finding)
            if not isinstance(safe_evidence_input, dict):
                safe_evidence_input = {}

            evidence_contract = finding_evidence_contract(
                safe_evidence_input,
                analyzer_owned=self.analyzer_owned,
            )
            if evidence_contract is not None:
                safe_contract = _sanitize_sarif_payload(evidence_contract)
                if safe_contract:
                    properties["skylos_evidence_contract"] = safe_contract

            dead_code_evidence = dead_code_finding_evidence_payload(safe_evidence_input)
            if dead_code_evidence is not None:
                safe_dead_code_evidence = _sanitize_sarif_payload(dead_code_evidence)
                if safe_dead_code_evidence:
                    properties["skylos_dead_code_evidence"] = safe_dead_code_evidence

            result_obj = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message_text},
                "properties": properties,
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": file_path},
                            "region": {
                                "startLine": line_number,
                                "startColumn": column_number,
                            },
                        }
                    }
                ],
            }

            if snippet_text:
                result_obj["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                    "text": snippet_text
                }

            base_fingerprint = compute_partial_fingerprint(
                rule_id,
                file_path,
                self._fingerprint_anchor(finding, line_number),
            )
            # Identical findings in the same file/anchor get an occurrence
            # suffix so they stay distinct but remain order-stable.
            occurrence = fingerprint_counts.get(base_fingerprint, 0) + 1
            fingerprint_counts[base_fingerprint] = occurrence
            result_obj["partialFingerprints"] = {
                _FINGERPRINT_KEY: f"{base_fingerprint}:{occurrence}"
            }

            related_locations = _sarif_related_locations(
                finding.get("related_locations")
            )
            if related_locations:
                result_obj["relatedLocations"] = related_locations

            code_flows = _sarif_code_flows(
                finding, result_obj["locations"][0]["physicalLocation"]
            )
            if code_flows:
                result_obj["codeFlows"] = code_flows

            if isinstance(review_decision, dict):
                justification = sanitize_untrusted_text(
                    review_decision.get("reason") or "Reviewed in Skylos",
                    max_length=_MAX_SARIF_METADATA_TEXT_LENGTH,
                    markdown=False,
                )
                result_obj["suppressions"] = [
                    {
                        "kind": "external",
                        "status": "accepted",
                        "justification": justification,
                    }
                ]

            results.append(result_obj)

        return results

    def _fingerprint_anchor(self, finding, line_number):
        parts = []
        metadata = finding.get("metadata")
        if isinstance(metadata, dict):
            for key in ("vuln_id", "package_name", "package_version"):
                if metadata.get(key):
                    parts.append(f"{key}={metadata[key]}")
        for key in ("symbol", "name", "full_name", "function"):
            value = finding.get(key)
            if isinstance(value, str) and value.strip():
                parts.append(f"symbol={value.strip()}")
                break
        snippet = finding.get("snippet")
        if not (isinstance(snippet, str) and snippet.strip()):
            snippet = self._source_line(finding, line_number)
        if isinstance(snippet, str) and snippet.strip():
            parts.append(f"code={_normalize_fingerprint_text(snippet)}")
        if not parts:
            # Last resort: message with numbers removed so embedded line
            # numbers do not break stability.
            parts.append(
                "message=" + _DIGITS_RE.sub("#", str(finding.get("message") or ""))
            )
        return "|".join(parts)

    def _source_line(self, finding, line_number):
        # Only read files for analyzer-produced findings; imported/untrusted
        # findings must not make the exporter open arbitrary paths.
        if not self.analyzer_owned:
            return None
        raw_path = finding.get("file_path") or finding.get("file")
        if not isinstance(raw_path, str) or not raw_path:
            return None
        if raw_path not in self._source_cache:
            lines = None
            try:
                if (
                    os.path.isfile(raw_path)
                    and os.path.getsize(raw_path) <= _MAX_FINGERPRINT_SOURCE_BYTES
                ):
                    with open(raw_path, encoding="utf-8", errors="replace") as fh:
                        lines = fh.read().splitlines()
            except OSError:
                lines = None
            self._source_cache[raw_path] = lines
        lines = self._source_cache[raw_path]
        if not lines or not (1 <= line_number <= len(lines)):
            return None
        return lines[line_number - 1]


def _sarif_region(start_line, end_line=None):
    start = _positive_sarif_integer(start_line)
    region = {"startLine": start}
    end = _positive_sarif_integer(end_line, default=start)
    if end > start:
        region["endLine"] = end
    return region


def _location_text(value, limit=_MAX_SARIF_METADATA_TEXT_LENGTH):
    return sanitize_untrusted_text(value, max_length=limit, markdown=True)


def _sarif_related_locations(raw_locations):
    if not isinstance(raw_locations, list):
        return []
    related = []
    for raw in raw_locations:
        if len(related) >= _MAX_SARIF_RELATED_LOCATIONS:
            break
        if not isinstance(raw, dict):
            continue
        raw_file = raw.get("file") or raw.get("file_path")
        if not raw_file:
            continue
        location = {
            "id": len(related) + 1,
            "physicalLocation": {
                "artifactLocation": {"uri": normalize_file_path_for_sarif(raw_file)},
                "region": _sarif_region(
                    raw.get("start_line") or raw.get("line"),
                    raw.get("end_line"),
                ),
            },
        }
        message = raw.get("message") or raw.get("label")
        if message:
            location["message"] = {"text": _location_text(message)}
        related.append(location)
    return related


def _security_evidence(finding):
    metadata = finding.get("metadata")
    evidence = metadata.get("security_evidence") if isinstance(metadata, dict) else None
    if not isinstance(evidence, dict):
        evidence = finding.get("security_evidence")
    return evidence if isinstance(evidence, dict) else None


def _sarif_code_flows(finding, primary_physical_location):
    """Build codeFlows only from analyzer-recorded source-to-sink steps.

    Steps come from ``security_evidence.path`` / ``trace`` / ``traces``.
    Steps that carry their own ``file``/``line`` get that physical location;
    textual steps are anchored at the finding's primary location (the sink
    expression they describe). Nothing is emitted when the finding has no
    recorded flow.
    """
    evidence = _security_evidence(finding)
    if evidence is None:
        return []
    steps = None
    for key in ("path", "trace", "traces", "flow"):
        value = evidence.get(key)
        if isinstance(value, list) and value:
            steps = value
            break
    if not steps:
        return []
    steps = [step for step in steps if isinstance(step, (str, dict)) and step]
    steps = steps[:_MAX_SARIF_FLOW_STEPS]
    if not steps:
        return []

    thread_locations = []
    for step in steps:
        location = {}
        if isinstance(step, dict):
            text = step.get("message") or step.get("label") or step.get("step")
            step_file = step.get("file") or step.get("file_path")
            if step_file and (step.get("line") or step.get("start_line")):
                location["physicalLocation"] = {
                    "artifactLocation": {
                        "uri": normalize_file_path_for_sarif(step_file)
                    },
                    "region": _sarif_region(
                        step.get("line") or step.get("start_line"),
                        step.get("end_line"),
                    ),
                }
        else:
            text = step
        if "physicalLocation" not in location:
            # Current producers record textual steps within the sink
            # expression; anchor them at the finding so GitHub can render
            # every step (it drops locationless thread-flow steps).
            location["physicalLocation"] = copy.deepcopy(primary_physical_location)
        if text:
            location["message"] = {"text": _location_text(text)}
        if not location:
            continue
        thread_locations.append({"location": location})

    if not thread_locations:
        return []
    flow = {"threadFlows": [{"locations": thread_locations}]}
    source = evidence.get("source")
    sink = evidence.get("sink")
    if isinstance(source, str) and isinstance(sink, str) and source and sink:
        flow["message"] = {"text": _location_text(f"Flow from {source} to {sink}")}
    return [flow]


def _sanitize_sarif_payload(value, *, max_items=_MAX_SARIF_METADATA_ITEMS):
    # SARIF properties are machine-readable JSON, not a Markdown sink. Keep
    # evidence symbols and trace arrows stable while still bounding content,
    # removing unsafe controls, and redacting credentials. Human-facing SARIF
    # messages and snippets are sanitized separately above.
    return sanitize_bounded_payload(
        value,
        max_depth=4,
        max_items=max_items,
        max_text_length=_MAX_SARIF_METADATA_TEXT_LENGTH,
        max_nodes=_MAX_SARIF_METADATA_NODES,
        markdown=False,
        neutralize_mentions=False,
    )
