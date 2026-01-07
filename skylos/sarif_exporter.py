import os
import json


def severity_to_sarif_level(severity):
    severity_text = (severity or "").upper()
    if severity_text in {"CRITICAL", "HIGH"}:
        return "error"
    if severity_text == "MEDIUM":
        return "warning"
    return "note"


def normalize_file_path_for_sarif(file_path=None):
    raw_path = str(file_path or "")
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
    def __init__(self, findings, tool_name="Skylos", version="1.0.0"):
        self.findings = findings
        self.tool_name = tool_name
        self.version = version

    def generate(self):
        sarif_log = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.version,
                            "rules": self._get_unique_rules(),
                        }
                    },
                    "results": self._get_results(),
                }
            ],
        }
        return sarif_log

    def write(self, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.generate(), f, indent=2)

    def _get_unique_rules(self):
        rules = {}

        for finding in self.findings:
            rule_id = str(finding.get("rule_id") or "UNKNOWN")
            if rule_id in rules:
                continue

            msg_text = str(finding.get("message") or "")
            fallback_title = msg_text.splitlines()[0] if msg_text.strip() else rule_id

            title_raw = (
                finding.get("title") or finding.get("rule_name") or fallback_title
            )
            title = str(title_raw).strip()
            if len(title) > 120:
                title = title[:117] + "..."

            level = severity_to_sarif_level(finding.get("severity"))

            cat = str(finding.get("category") or "").upper()
            tags = []
            if cat:
                tags.append(cat.lower())
            if cat == "SECURITY":
                tags.append("security")

            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": title or rule_id},
                "defaultConfiguration": {"level": level},
                "properties": {"tags": tags},
                "helpUri": f"https://docs.skylos.dev/rules/{rule_id}",
            }

        return list(rules.values())

    def _get_results(self):
        results = []

        for finding in self.findings:
            rule_id = str(finding.get("rule_id") or "UNKNOWN")
            level = severity_to_sarif_level(finding.get("severity"))

            message_text = str(finding.get("message") or "(no message)")

            file_path = normalize_file_path_for_sarif(
                finding.get("file_path") or finding.get("file")
            )

            line_number = int(finding.get("line_number") or finding.get("line") or 1)
            column_number = int(finding.get("col_number") or finding.get("col") or 1)
            if line_number < 1:
                line_number = 1
            if column_number < 1:
                column_number = 1

            snippet_text = finding.get("snippet")
            if snippet_text is not None:
                snippet_text = str(snippet_text)[:2000]

            category = str(finding.get("category") or "QUALITY").upper()

            result_obj = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message_text},
                "properties": {"category": category},
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
