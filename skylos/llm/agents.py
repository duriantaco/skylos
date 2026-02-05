import json

from .schemas import (
    Finding,
    CodeFix,
    IssueType,
    Severity,
    Confidence,
    CodeLocation,
    parse_llm_response,
    FINDING_SCHEMA,
)
from .context import ContextBuilder
from .prompts import (
    build_security_prompt,
    build_quality_prompt,
    build_fix_prompt,
    build_security_audit_prompt,
)


FINDINGS_RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["findings"],
    "properties": {
        "findings": {
            "type": "array",
            "items": FINDING_SCHEMA,
        }
    },
}

FINDINGS_RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "skylos_findings",
        "schema": FINDINGS_RESPONSE_SCHEMA,
        "strict": True,
    },
}


FIX_RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["problem", "solution", "code_lines", "confidence"],
    "properties": {
        "problem": {"type": "string"},
        "solution": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "code_lines": {"type": "array", "items": {"type": "string"}},
    },
}


FIX_RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "skylos_fix",
        "schema": FIX_RESPONSE_SCHEMA,
        "strict": True,
    },
}

FP_FILTER_RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "reason"],
    "properties": {
        "verdict": {"type": "string", "enum": ["TRUE_POSITIVE", "FALSE_POSITIVE"]},
        "reason": {"type": "string"},
    },
}

FP_FILTER_RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "skylos_fp_filter",
        "schema": FP_FILTER_RESPONSE_SCHEMA,
        "strict": True,
    },
}


class AgentConfig:
    RATE_LIMITED_PREFIXES = [
        "groq/",
        "gemini/",
        "ollama/",
        "mistral/",
    ]

    def __init__(
        self,
        model="gpt-4.1",
        api_key=None,
        temperature=0.1,
        max_tokens=2048,
        timeout=240,
        stream=True,
        enable_cache=True,
    ):
        self.model = model
        self.api_key = api_key
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.stream = stream
        self.enable_cache = enable_cache

    def is_rate_limited_model(self):
        m = (self.model or "").strip().lower()

        for prefix in self.RATE_LIMITED_PREFIXES:
            if m.startswith(prefix):
                return True

        return False


def create_llm_adapter(config):
    from skylos.adapters.litellm_adapter import LiteLLMAdapter

    return LiteLLMAdapter(
        model=config.model, api_key=config.api_key, enable_cache=config.enable_cache
    )


class SecurityAgent:
    def __init__(self, config=None):
        if config is None:
            config = AgentConfig()
        self.config = config
        self.context_builder = ContextBuilder()
        self._adapter = None

    def get_adapter(self):
        if self._adapter is None:
            self._adapter = create_llm_adapter(self.config)
        return self._adapter

    def analyze(self, source, file_path, defs_map=None, context=None):
        if context is None:
            context = self.context_builder.build_analysis_context(
                source, file_path=file_path, defs_map=defs_map
            )

        include_examples = (
            not self.config.is_rate_limited_model() and len(context) < 10_000
        )
        system, user = build_security_prompt(context, include_examples=include_examples)

        if self.config.stream:
            full = ""
            for chunk in self.get_adapter().stream(system, user):
                full += chunk
            response = full
        else:
            response = self.get_adapter().complete(
                system, user, response_format=FINDINGS_RESPONSE_FORMAT
            )

        return parse_llm_response(response, file_path)


class QualityAgent:
    def __init__(self, config=None):
        if config is None:
            config = AgentConfig()
        self.config = config
        self.context_builder = ContextBuilder()
        self._adapter = None

    def get_adapter(self):
        if self._adapter is None:
            self._adapter = create_llm_adapter(self.config)
        return self._adapter

    def analyze(self, source, file_path, defs_map=None, context=None):
        if context is None:
            context = self.context_builder.build_analysis_context(
                source, file_path=file_path, defs_map=defs_map
            )

        include_examples = (
            not self.config.is_rate_limited_model() and len(context) < 10_000
        )
        system, user = build_quality_prompt(context, include_examples=include_examples)

        if self.config.stream:
            full = ""
            for chunk in self.get_adapter().stream(system, user):
                full += chunk
            response = full
        else:
            response = self.get_adapter().complete(
                system, user, response_format=FINDINGS_RESPONSE_FORMAT
            )

        return parse_llm_response(response, file_path)


class SecurityAuditAgent:
    def __init__(self, config=None):
        if config is None:
            config = AgentConfig()
        self.config = config
        self.context_builder = ContextBuilder()
        self._adapter = None

    def get_adapter(self):
        if self._adapter is None:
            self._adapter = create_llm_adapter(self.config)
        return self._adapter

    def analyze(self, source, file_path, defs_map=None, context=None):
        if context is None:
            context = self.context_builder.build_analysis_context(
                source, file_path=file_path, defs_map=defs_map
            )

        include_examples = (
            not self.config.is_rate_limited_model() and len(context) < 10_000
        )
        system, user = build_security_audit_prompt(
            context, include_examples=include_examples
        )

        response = self.get_adapter().complete(
            system,
            user,
            response_format=FINDINGS_RESPONSE_FORMAT,
        )

        return parse_llm_response(response, file_path)


class FixerAgent:
    def __init__(self, config=None):
        if config is None:
            config = AgentConfig()
        self.config = config
        self.context_builder = ContextBuilder()
        self._adapter = None

    def get_adapter(self):
        if self._adapter is None:
            self._adapter = create_llm_adapter(self.config)
        return self._adapter

    def analyze(self, source, file_path, defs_map=None, context=None):
        return []

    def fix(
        self, source, file_path, issue_line, issue_message, defs_map=None, context=None
    ):
        if context is None:
            context = self.context_builder.build_fix_context(
                source, file_path, issue_line, issue_message, defs_map
            )

        system, user = build_fix_prompt(context, issue_line, issue_message)
        response = self.get_adapter().complete(
            system, user, response_format=FIX_RESPONSE_FORMAT
        )

        try:
            data = json.loads(response)
            lines = source.splitlines()
            start = max(0, issue_line - 5)
            end = min(len(lines), issue_line + 5)
            original = "\n".join(lines[start:end])

            finding = Finding(
                rule_id="SKY-FIX",
                issue_type=IssueType.BUG,
                severity=Severity.MEDIUM,
                message=issue_message,
                location=CodeLocation(file=file_path, line=issue_line),
            )

            fixed_code = ""
            code_lines = data.get("code_lines")
            if isinstance(code_lines, list):
                fixed_code = "\n".join(str(x) for x in code_lines) + "\n"
            else:
                code = data.get("code")
                if isinstance(code, str):
                    fixed_code = code

            if not fixed_code.strip():
                return None

            problem = data.get("problem")
            if not problem:
                problem = issue_message

            solution = data.get("solution")
            if solution:
                description = f"{problem}\n\nSolution: {solution}"
            else:
                description = problem

            raw_confidence = data.get("confidence", "medium")
            confidence = Confidence(str(raw_confidence).lower())

            return CodeFix(
                finding=finding,
                original_code=original,
                fixed_code=fixed_code,
                description=description,
                confidence=confidence,
                side_effects=[],
            )

        except (json.JSONDecodeError, KeyError):
            return None


class FalsePositiveFilterAgent:
    def __init__(self, config=None):
        if config is None:
            config = AgentConfig()
        self.config = config
        self._adapter = None

    def get_adapter(self):
        if self._adapter is None:
            self._adapter = create_llm_adapter(self.config)
        return self._adapter

    def _extract_finding_info(self, finding):
        if isinstance(finding, dict):
            return {
                "line": finding.get("line") or finding.get("lineno") or 1,
                "rule_id": finding.get("rule_id", "unknown"),
                "severity": finding.get("severity", "medium"),
                "message": finding.get("message", ""),
            }
        else:
            return {
                "line": finding.location.line,
                "rule_id": finding.rule_id,
                "severity": finding.severity.value
                if hasattr(finding.severity, "value")
                else str(finding.severity),
                "message": finding.message,
            }

    def _mark_as_verified(self, finding):
        if isinstance(finding, dict):
            finding["_confidence"] = "high"
            finding["_verified_by_llm"] = True
        else:
            finding.confidence = Confidence.HIGH
            finding._verified_by_llm = True

    def filter(self, findings, source, file_path):
        if not findings:
            return []

        lines = source.splitlines()
        filtered = []

        for finding in findings:
            verdict = self._review_finding(finding, lines, file_path)
            if verdict == "TRUE_POSITIVE":
                self._mark_as_verified(finding)
                filtered.append(finding)

        return filtered

    def _review_finding(self, finding, lines, file_path):
        info = self._extract_finding_info(finding)
        line_num = info["line"]

        start = max(0, line_num - 10)
        end = min(len(lines), line_num + 10)

        context_lines = []
        for i in range(start, end):
            marker = " >>> " if i == line_num - 1 else "     "
            if i < len(lines):
                context_lines.append(f"{i + 1:4d}{marker}{lines[i]}")

        context = "\n".join(context_lines)

        system = """You are a security code reviewer. Your job is to verify if a static analysis finding is a TRUE vulnerability or a FALSE POSITIVE.

Be rigorous but fair:
- TRUE_POSITIVE: The vulnerability is real and exploitable
- FALSE_POSITIVE: The code is safe due to sanitization, validation, or the flagged pattern isn't actually dangerous

Respond with JSON only."""

        user = f"""## Static Analysis Finding
- Rule: {info["rule_id"]}
- Severity: {info["severity"]}
- Message: {info["message"]}
- Line: {line_num}

## Code Context (>>> marks the flagged line)
{context}

## Your Analysis
Analyze if this is a TRUE_POSITIVE (real vulnerability) or FALSE_POSITIVE (safe code).

Respond with JSON:
{{"verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE", "reason": "brief explanation"}}"""

        try:
            response = self.get_adapter().complete(
                system, user, response_format=FP_FILTER_RESPONSE_FORMAT
            )
            data = json.loads(response)
            return data.get("verdict", "TRUE_POSITIVE")
        except Exception:
            return "TRUE_POSITIVE"

    def filter_batch(self, findings, source, file_path, batch_size=5):
        if not findings:
            return []

        if len(findings) <= 1:
            return self.filter(findings, source, file_path)

        lines = source.splitlines()
        filtered = []

        for i in range(0, len(findings), batch_size):
            batch = findings[i : i + batch_size]
            batch_results = self._review_batch(batch, lines, file_path)

            for finding, verdict in zip(batch, batch_results):
                if verdict == "TRUE_POSITIVE":
                    self._mark_as_verified(finding)
                    filtered.append(finding)

        return filtered

    def _review_batch(self, findings, lines, file_path):
        findings_text = []

        for idx, finding in enumerate(findings):
            info = self._extract_finding_info(finding)
            line_num = info["line"]

            start = max(0, line_num - 5)
            end = min(len(lines), line_num + 5)

            context_parts = []
            for i in range(start, end):
                if i < len(lines):
                    context_parts.append(f"{i + 1:4d} | {lines[i]}")
            context = "\n".join(context_parts)

            findings_text.append(f"""
### Finding {idx + 1}
- Rule: {info["rule_id"]}
- Severity: {info["severity"]}
- Line: {line_num}
- Message: {info["message"]}

Context:
{context}
-------------------
""")

        system = """You are a security code reviewer verifying static analysis findings.
For each finding, determine if it's TRUE_POSITIVE (real vulnerability) or FALSE_POSITIVE (safe).

Respond with a JSON array containing one object per finding, in order.
Example: [{"id": 1, "verdict": "TRUE_POSITIVE"}, {"id": 2, "verdict": "FALSE_POSITIVE"}]"""

        user = f"""Review these {len(findings)} findings from {file_path}:

{"".join(findings_text)}

Respond with JSON array."""

        try:
            response = self.get_adapter().complete(system, user)

            response = response.strip()
            if response.startswith("```"):
                response = response.split("```")[1]
                if response.startswith("json"):
                    response = response[4:]

            data = json.loads(response)

            if isinstance(data, list):
                verdicts = []
                for i in range(len(findings)):
                    match = next((d for d in data if d.get("id") == i + 1), None)
                    if match:
                        verdicts.append(match.get("verdict", "TRUE_POSITIVE"))
                    elif i < len(data):
                        verdicts.append(data[i].get("verdict", "TRUE_POSITIVE"))
                    else:
                        verdicts.append("TRUE_POSITIVE")
                return verdicts

        except Exception:
            pass

        return ["TRUE_POSITIVE"] * len(findings)


AGENT_REGISTRY = {
    "security": SecurityAgent,
    "quality": QualityAgent,
    "security_audit": SecurityAuditAgent,
    "fixer": FixerAgent,
    "false_positive_filter": FalsePositiveFilterAgent,
}


def create_agent(agent_type, config=None):
    if agent_type not in AGENT_REGISTRY:
        valid_types = list(AGENT_REGISTRY.keys())
        raise ValueError(f"Unknown agent type: {agent_type}. Valid: {valid_types}")

    agent_class = AGENT_REGISTRY[agent_type]
    return agent_class(config)
