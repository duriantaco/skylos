from enum import Enum
import json


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IssueType(str, Enum):
    SECURITY = "security"
    DEAD_CODE = "dead_code"
    QUALITY = "quality"
    BUG = "bug"
    PERFORMANCE = "performance"
    STYLE = "style"
    HALLUCINATION = "hallucination"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCERTAIN = "uncertain"


class CodeLocation:
    def __init__(self, file, line, end_line=None, column=None, end_column=None):
        self.file = file
        self.line = line
        self.end_line = end_line
        self.column = column
        self.end_column = end_column

    def to_dict(self):
        result = {"file": self.file, "line": self.line}
        if self.end_line:
            result["end_line"] = self.end_line
        if self.column:
            result["column"] = self.column
        if self.end_column:
            result["end_column"] = self.end_column
        return result


class Finding:
    def __init__(
        self,
        rule_id,
        issue_type,
        severity,
        message,
        location,
        confidence=None,
        explanation=None,
        suggestion=None,
        code_snippet=None,
        references=None,
    ):
        self.rule_id = rule_id
        self.issue_type = issue_type
        self.severity = severity
        self.message = message
        self.location = location
        self.confidence = confidence or Confidence.MEDIUM
        self.explanation = explanation
        self.suggestion = suggestion
        self.code_snippet = code_snippet
        self.references = references or []

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "issue_type": self.issue_type.value,
            "severity": self.severity.value,
            "message": self.message,
            "location": self.location.to_dict(),
            "confidence": self.confidence.value,
            "explanation": self.explanation,
            "suggestion": self.suggestion,
            "code_snippet": self.code_snippet,
            "references": self.references,
        }

    def to_sarif_result(self):
        return {
            "ruleId": self.rule_id,
            "level": self._severity_to_sarif_level(),
            "message": {"text": self.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.location.file},
                        "region": {
                            "startLine": self.location.line,
                            "endLine": self.location.end_line or self.location.line,
                        },
                    }
                }
            ],
            "properties": {
                "confidence": self.confidence.value,
                "issueType": self.issue_type.value,
            },
        }

    def _severity_to_sarif_level(self):
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }
        return mapping.get(self.severity, "warning")


class CodeFix:
    def __init__(
        self,
        finding,
        original_code,
        fixed_code,
        description,
        confidence=None,
        side_effects=None,
    ):
        self.finding = finding
        self.original_code = original_code
        self.fixed_code = fixed_code
        self.description = description
        self.confidence = confidence or Confidence.MEDIUM
        self.side_effects = side_effects or []

    def to_dict(self):
        return {
            "finding": self.finding.to_dict(),
            "original_code": self.original_code,
            "fixed_code": self.fixed_code,
            "description": self.description,
            "confidence": self.confidence.value,
            "side_effects": self.side_effects,
        }


class AnalysisResult:
    def __init__(
        self,
        findings=None,
        summary="",
        files_analyzed=0,
        total_lines=0,
        analysis_time_ms=0,
        model_used="",
        tokens_used=0,
    ):
        self.findings = findings or []
        self.summary = summary
        self.files_analyzed = files_analyzed
        self.total_lines = total_lines
        self.analysis_time_ms = analysis_time_ms
        self.model_used = model_used
        self.tokens_used = tokens_used

    def to_dict(self):
        out_findings = []
        for f in self.findings:
            out_findings.append(f.to_dict())

        return {
            "findings": out_findings,
            "summary": self.summary,
            "metadata": {
                "files_analyzed": self.files_analyzed,
                "total_lines": self.total_lines,
                "analysis_time_ms": self.analysis_time_ms,
                "model_used": self.model_used,
                "tokens_used": self.tokens_used,
            },
        }

    def to_sarif(self, tool_name="Skylos-LLM", version="1.0.0"):
        rules = {}
        for f in self.findings:
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.rule_id,
                    "shortDescription": {"text": f.message[:100]},
                    "defaultConfiguration": {"level": f._severity_to_sarif_level()},
                }

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "version": version,
                            "informationUri": "https://github.com/your-org/skylos",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": [f.to_sarif_result() for f in self.findings],
                }
            ],
        }

    def get_critical_count(self):
        count = 0
        for f in self.findings:
            if f.severity == Severity.CRITICAL:
                count += 1
        return count

    def get_high_count(self):
        count = 0
        for f in self.findings:
            if f.severity == Severity.HIGH:
                count += 1
        return count

    def has_blockers(self):
        if self.get_critical_count() > 0:
            return True
        if self.get_high_count() > 0:
            return True
        return False


ISSUE_TYPE_VALUES = []
for e in IssueType:
    ISSUE_TYPE_VALUES.append(e.value)

SEVERITY_VALUES = []
for e in Severity:
    SEVERITY_VALUES.append(e.value)

CONFIDENCE_VALUES = []
for e in Confidence:
    CONFIDENCE_VALUES.append(e.value)


FINDING_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "rule_id",
        "issue_type",
        "severity",
        "message",
        "line",
        "end_line",
        "explanation",
        "suggestion",
        "confidence",
    ],
    "properties": {
        "rule_id": {"type": "string", "pattern": "^SKY-[A-Z][0-9]{3}$"},
        "issue_type": {"type": "string", "enum": ISSUE_TYPE_VALUES},
        "severity": {"type": "string", "enum": SEVERITY_VALUES},
        "message": {"type": "string", "maxLength": 500},
        "line": {"type": "integer", "minimum": 1},
        "end_line": {
            "anyOf": [
                {"type": "integer", "minimum": 1},
                {"type": "null"},
            ]
        },
        "explanation": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "suggestion": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "confidence": {"type": "string", "enum": CONFIDENCE_VALUES},
    },
}


def parse_llm_finding(data, file_path):
    try:
        rule_id = data.get("rule_id", "SKY-L000")
        issue_type_raw = data.get("issue_type") or data.get("type") or "quality"
        issue_type = IssueType(str(issue_type_raw).lower())
        severity_raw = data.get("severity", "medium")
        severity = Severity(str(severity_raw).lower())
        message = data.get("message", "Issue detected")
        line = int(data.get("line", 1))

        end_line = data.get("end_line")
        confidence_raw = data.get("confidence", "medium")
        confidence = Confidence(str(confidence_raw).lower())
        explanation = data.get("explanation")
        suggestion = data.get("suggestion")

        location = CodeLocation(file=file_path, line=line, end_line=end_line)

        return Finding(
            rule_id=rule_id,
            issue_type=issue_type,
            severity=severity,
            message=message,
            location=location,
            confidence=confidence,
            explanation=explanation,
            suggestion=suggestion,
        )
    except (ValueError, KeyError):
        return None


def parse_llm_response(response_text, file_path):
    if not response_text:
        return []

    text = response_text.strip()
    if text.startswith("Error:"):
        raise RuntimeError(text)

    try:
        obj = json.loads(text)
    except Exception:
        return []

    if isinstance(obj, dict):
        obj = obj.get("findings", [])

    out = []
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                f = parse_llm_finding(item, file_path)
                if f:
                    out.append(f)

    return out
