import os
import json

from skylos.cicd.evidence import sanitize_bounded_payload, sanitize_untrusted_text
from skylos.core.evidence_contract import finding_evidence_contract
from skylos.deadcode.finding_evidence import dead_code_finding_evidence_payload


_MAX_SARIF_MESSAGE_LENGTH = 4_000
_MAX_SARIF_SNIPPET_LENGTH = 2_000
_MAX_SARIF_METADATA_TEXT_LENGTH = 500
_MAX_SARIF_METADATA_ITEMS = 32
_MAX_SARIF_METADATA_NODES = 256


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

            rules[rule_id] = rule_entry

        return list(rules.values())

    def _get_results(self):
        results = []

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
                safe_metadata = _sanitize_sarif_payload(metadata)
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

            results.append(result_obj)

        return results


def _sanitize_sarif_payload(value):
    # SARIF properties are machine-readable JSON, not a Markdown sink. Keep
    # evidence symbols and trace arrows stable while still bounding content,
    # removing unsafe controls, and redacting credentials. Human-facing SARIF
    # messages and snippets are sanitized separately above.
    return sanitize_bounded_payload(
        value,
        max_depth=4,
        max_items=_MAX_SARIF_METADATA_ITEMS,
        max_text_length=_MAX_SARIF_METADATA_TEXT_LENGTH,
        max_nodes=_MAX_SARIF_METADATA_NODES,
        markdown=False,
        neutralize_mentions=False,
    )
