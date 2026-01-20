import re

from .schemas import Finding, Severity, Confidence, IssueType, CodeLocation


class ValidationResult:
    def __init__(self, valid, adjusted_finding, reason):
        self.valid = valid
        self.adjusted_finding = adjusted_finding
        self.reason = reason


class CodeValidator:
    def __init__(self, strict=False):
        self.strict = strict

    def validate(self, finding, source, file_path):
        lines = source.splitlines()
        total_lines = len(lines)

        issues = []

        location = CodeLocation(
            file=finding.location.file,
            line=finding.location.line,
            end_line=finding.location.end_line,
            column=finding.location.column,
        )

        f = Finding(
            rule_id=finding.rule_id,
            issue_type=finding.issue_type,
            severity=finding.severity,
            confidence=finding.confidence,
            message=finding.message,
            location=location,
            suggestion=finding.suggestion,
            explanation=finding.explanation,
        )

        if f.location.line < 1 or f.location.line > total_lines:
            if self.strict:
                msg = (
                    "Line "
                    + str(f.location.line)
                    + " out of range (1-"
                    + str(total_lines)
                    + ")"
                )
                return ValidationResult(False, None, msg)

            if f.location.line < 1:
                f.location.line = 1
            if f.location.line > total_lines:
                f.location.line = total_lines

            f.confidence = Confidence.LOW
            issues.append("line_adjusted")

        line_content = ""
        if f.location.line >= 1 and f.location.line <= total_lines:
            line_content = lines[f.location.line - 1]

        if not self._is_line_relevant(f, line_content):
            if self.strict:
                return ValidationResult(
                    False, None, "Line content not relevant to finding"
                )

            f.confidence = Confidence.LOW
            issues.append("low_relevance")

        symbol = self._extract_symbol(f.message)
        if symbol is not None and symbol != "":
            if not self._symbol_exists(symbol, source):
                if self.strict:
                    return ValidationResult(
                        False, None, "Symbol '" + symbol + "' not found in code"
                    )

                f.confidence = Confidence.UNCERTAIN
                issues.append("symbol_not_found:" + symbol)

        if f.issue_type == IssueType.SECURITY:
            if not self._verify_security_pattern(f, lines):
                if self.strict:
                    return ValidationResult(
                        False, None, "Security pattern not found at location"
                    )

                f.confidence = Confidence.LOW
                issues.append("pattern_not_verified")

        if issues:
            note = "[Validation: " + ", ".join(issues) + "]"
            if f.explanation:
                f.explanation = str(f.explanation) + " " + note
            else:
                f.explanation = note

        return ValidationResult(True, f, "passed")

    def _is_line_relevant(self, finding, line_content):
        if line_content is None:
            return False

        line = line_content.strip().lower()

        if line == "":
            return False

        if line.startswith("#"):
            return False

        if finding.issue_type == IssueType.SECURITY:
            return True

        if finding.issue_type == IssueType.DEAD_CODE:
            keywords = ["def ", "class ", "import ", "from ", "="]
            for kw in keywords:
                if kw in line:
                    return True
            return False

        if finding.issue_type == IssueType.QUALITY:
            return True

        return True

    def _extract_symbol(self, message):
        if not message:
            return None

        patterns = [
            r"(?:function|method|class|import|variable)[\s:]+['\"`]?(\w+)['\"`]?",
            r"['\"`](\w+)['\"`]",
            r":\s+(\w+)\s*$",
            r"unused\s+(\w+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _symbol_exists(self, symbol, source):
        if not symbol:
            return False
        if not source:
            return False

        pattern = r"\b" + re.escape(symbol) + r"\b"
        return re.search(pattern, source) is not None

    def _verify_security_pattern(self, finding, lines):
        if finding.location.line > len(lines):
            return False

        start = finding.location.line - 3
        if start < 0:
            start = 0

        end = finding.location.line + 2
        if end > len(lines):
            end = len(lines)

        context = "\n".join(lines[start:end]).lower()
        msg = str(finding.message or "").lower()

        patterns = {
            "sql": [
                "execute",
                "query",
                "cursor",
                "select",
                "insert",
                "update",
                "delete",
                'f"',
                "f'",
                "%s",
                ".format",
            ],
            "injection": ["subprocess", "os.system", "shell", "popen", "eval", "exec"],
            "hardcoded": [
                "password",
                "secret",
                "key",
                "token",
                "api_key",
                "apikey",
                '= "',
                "= '",
            ],
            "xss": ["render", "html", "template", "innerhtml", "mark_safe"],
            "pickle": ["pickle", "loads", "load", "unpickle"],
            "yaml": ["yaml.load", "yaml.unsafe_load"],
            "path": ["../", "path", "file", "open(", "read("],
        }

        for keyword in patterns:
            if keyword in msg:
                indicators = patterns[keyword]
                found = False
                for ind in indicators:
                    if ind in context:
                        found = True
                        break
                if found:
                    return True
                return False

        return True


class ResultValidator:
    def __init__(self, strict=False, min_confidence=Confidence.LOW):
        self.code_validator = CodeValidator(strict=strict)
        self.min_confidence = min_confidence
        self.strict = strict

    def validate(self, findings, source, file_path):
        stats = {
            "original": len(findings),
            "accepted": 0,
            "rejected": 0,
            "adjusted": 0,
        }

        validated = []

        for finding in findings:
            result = self.code_validator.validate(finding, source, file_path)

            if result.valid and result.adjusted_finding is not None:
                if self._meets_confidence(result.adjusted_finding.confidence):
                    validated.append(result.adjusted_finding)
                    stats["accepted"] += 1

                    if result.adjusted_finding.confidence != finding.confidence:
                        stats["adjusted"] += 1
                else:
                    stats["rejected"] += 1
            else:
                stats["rejected"] += 1

        return validated, stats

    def _meets_confidence(self, conf):
        rank = {
            Confidence.HIGH: 0,
            Confidence.MEDIUM: 1,
            Confidence.LOW: 2,
            Confidence.UNCERTAIN: 3,
        }

        conf_rank = rank.get(conf, 999)
        min_rank = rank.get(self.min_confidence, 999)

        return conf_rank <= min_rank


def deduplicate_findings(findings):
    if not findings:
        return []

    seen = set()
    unique = []

    for f in findings:
        msg_key = ""
        if f.message:
            msg_key = f.message[:50].lower()

        is_dup = False

        # +-2 line tolerance
        offset = -2
        while offset <= 2:
            key = (f.location.file, f.location.line + offset, msg_key)
            if key in seen:
                is_dup = True
                break
            offset += 1

        if not is_dup:
            key = (f.location.file, f.location.line, msg_key)
            seen.add(key)
            unique.append(f)

    return unique


def merge_findings(llm_findings, static_findings, file_path):
    merged = []

    llm_by_line = {}
    for f in llm_findings:
        line = f.location.line
        if line not in llm_by_line:
            llm_by_line[line] = []
        llm_by_line[line].append(f)

    static_lines_covered = set()

    for f in llm_findings:
        static_match = False

        for static in static_findings:
            static_line = 0
            if "line" in static:
                static_line = static.get("line", 0)
            else:
                static_line = static.get("lineno", 0)

            if abs(f.location.line - static_line) <= 2:
                static_match = True
                static_lines_covered.add(static_line)
                break

        if static_match:
            if f.confidence == Confidence.MEDIUM or f.confidence == Confidence.LOW:
                f.confidence = Confidence.HIGH

            suffix = " [Corroborated by static analysis]"
            if f.explanation:
                f.explanation = str(f.explanation) + suffix
                f.explanation = f.explanation.strip()
            else:
                f.explanation = suffix.strip()

        merged.append(f)

    for static in static_findings:
        static_line = 0
        if "line" in static:
            static_line = static.get("line", 0)
        else:
            static_line = static.get("lineno", 0)

        if static_line in static_lines_covered:
            continue

        nearby = False

        for line in llm_by_line:
            if abs(line - static_line) <= 2:
                nearby = True
                break

        if nearby:
            continue

        rule_id = static.get("rule_id")
        if not rule_id:
            rule_id = static.get("code", "STATIC")

        msg = static.get("message")
        if not msg:
            msg = static.get("msg", "Issue detected")

        merged.append(
            Finding(
                rule_id=rule_id,
                issue_type=_infer_issue_type(static),
                severity=_parse_severity(static.get("severity", "medium")),
                confidence=Confidence.MEDIUM,
                message=msg,
                location=CodeLocation(file=file_path, line=static_line),
                explanation="[From static analysis only]",
            )
        )

    return merged


def _infer_issue_type(static):
    msg = str(static.get("message", "") + static.get("rule_id", "")).lower()

    sec_words = ["security", "injection", "xss", "sql", "secret"]
    for kw in sec_words:
        if kw in msg:
            return IssueType.SECURITY

    dead_words = ["unused", "dead", "unreachable"]
    for kw in dead_words:
        if kw in msg:
            return IssueType.DEAD_CODE

    return IssueType.QUALITY


def _parse_severity(sev):
    s = str(sev or "").lower()

    if s == "critical" or s == "blocker":
        return Severity.CRITICAL
    if s == "high" or s == "error":
        return Severity.HIGH
    if s == "medium" or s == "warning":
        return Severity.MEDIUM

    return Severity.LOW


Validator = CodeValidator
merge_with_static = merge_findings
