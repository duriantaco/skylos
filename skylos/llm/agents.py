import json
import time
import random

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
    build_dead_code_prompt,
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
    ):
        self.model = model
        self.api_key = api_key
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.stream = stream

    def is_rate_limited_model(self):
        m = (self.model or "").strip().lower()

        for prefix in self.RATE_LIMITED_PREFIXES:
            if m.startswith(prefix):
                return True

        return False


class OpenAILLM:
    def __init__(self, model, api_key, config):
        self.model = model
        self.api_key = api_key
        self.config = config
        self._client = None

    def get_client(self):
        if self._client is not None:
            return self._client

        try:
            import openai
        except ImportError:
            raise ImportError("OpenAI not installed. Run: pip install openai")

        self._client = openai.OpenAI(
            api_key=self.api_key,
            max_retries=0,
            timeout=self.config.timeout,
        )
        return self._client

    def complete(self, system, user, response_format=None):
        try:
            import openai
        except ImportError:
            return "Error: OpenAI not installed. Run: pip install openai"

        delay = 1.0
        max_delay = 12.0
        attempts = 8
        last_err = None

        for _ in range(attempts):
            try:
                kwargs = dict(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                )

                if response_format is not None:
                    kwargs["response_format"] = response_format

                response = self.get_client().chat.completions.create(**kwargs)

                content = response.choices[0].message.content
                return content or ""

            except openai.RateLimitError as e:
                last_err = e
                time.sleep(delay + random.random() * 0.5)
                delay = min(delay * 2, max_delay)
                continue

            except openai.APIStatusError as e:
                last_err = e
                status_code = getattr(e, "status_code", None)
                if status_code == 429:
                    time.sleep(delay + random.random() * 0.5)
                    delay = min(delay * 2, max_delay)
                    continue
                return f"Error: {e}"

            except Exception as e:
                return f"Error: {e}"

        return f"Error: 429 rate-limited after {attempts} retries: {last_err}"

    def stream(self, system, user):
        delay = 1.0
        max_delay = 12.0
        attempts = 6
        last_err = None

        for _ in range(attempts):
            try:
                response = self.get_client().chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                    stream=True,
                )

                for chunk in response:
                    delta = chunk.choices[0].delta
                    if delta and delta.content:
                        yield delta.content
                return

            except Exception as e:
                last_err = e
                msg = str(e)

                is_rate_limit = (
                    "429" in msg
                    or "Too Many Requests" in msg
                    or "Rate limit" in msg
                    or "rate_limit" in msg
                )

                if not is_rate_limit:
                    yield f"Error: {msg}"
                    return

                time.sleep(delay + random.random() * 0.5)
                delay = min(delay * 2, max_delay)

        yield f"Error: 429 rate-limited after {attempts} retries: {last_err}"


class AnthropicLLM:
    def __init__(self, model, api_key, config):
        self.model = model
        self.api_key = api_key
        self.config = config
        self._client = None

    def get_client(self):
        if self._client is not None:
            return self._client

        try:
            import anthropic
        except ImportError:
            raise ImportError("Anthropic not installed. Run: pip install anthropic")

        self._client = anthropic.Anthropic(api_key=self.api_key)
        return self._client

    def complete(self, system, user, response_format=None):
        try:
            response = self.get_client().messages.create(
                model=self.model,
                max_tokens=self.config.max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
                temperature=self.config.temperature,
            )
            return response.content[0].text
        except Exception as e:
            return f"Error: {str(e)}"

    def stream(self, system, user):
        try:
            with self.get_client().messages.stream(
                model=self.model,
                max_tokens=self.config.max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
                temperature=self.config.temperature,
            ) as stream:
                for text in stream.text_stream:
                    yield text
        except Exception as e:
            yield f"Error: {str(e)}"


def create_llm_adapter(config):
    from skylos.adapters.litellm_adapter import LiteLLMAdapter

    return LiteLLMAdapter(model=config.model, api_key=config.api_key)


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


class DeadCodeAgent:
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
        system, user = build_dead_code_prompt(
            context, include_examples=include_examples
        )

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


AGENT_REGISTRY = {
    "security": SecurityAgent,
    "dead_code": DeadCodeAgent,
    "quality": QualityAgent,
    "security_audit": SecurityAuditAgent,
    "fixer": FixerAgent,
}


def create_agent(agent_type, config=None):
    if agent_type not in AGENT_REGISTRY:
        valid_types = list(AGENT_REGISTRY.keys())
        raise ValueError(f"Unknown agent type: {agent_type}. Valid: {valid_types}")

    agent_class = AGENT_REGISTRY[agent_type]
    return agent_class(config)
