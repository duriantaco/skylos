from __future__ import annotations

import ast
from typing import Iterable


LLM_CLIENT_CONSTRUCTORS = frozenset(
    {
        "openai.OpenAI",
        "openai.AsyncOpenAI",
        "anthropic.Anthropic",
        "anthropic.AsyncAnthropic",
        "google.genai.Client",
        "genai.Client",
        "cohere.Client",
        "huggingface_hub.InferenceClient",
        "langchain_openai.ChatOpenAI",
        "langchain.chat_models.ChatOpenAI",
        "langchain.chains.LLMChain",
        "LLMChain",
        "ChatOpenAI",
        "OpenAI",
        "AsyncOpenAI",
        "Anthropic",
        "AsyncAnthropic",
        "InferenceClient",
    }
)

DIRECT_LLM_CALLS = frozenset(
    {
        "openai.chat.completions.create",
        "openai.responses.create",
        "openai.embeddings.create",
        "litellm.completion",
        "litellm.acompletion",
        "completion",
        "acompletion",
        "generateText",
        "streamText",
    }
)

LLM_CLIENT_CALL_SUFFIXES = (
    ".chat.completions.create",
    ".responses.create",
    ".embeddings.create",
    ".messages.create",
    ".invoke_model",
    ".invoke",
    ".predict",
    ".generate",
)

PROMPT_KEYWORDS = frozenset(
    {
        "prompt",
        "input",
        "inputs",
        "query",
        "question",
        "messages",
        "text",
        "texts",
    }
)

DANGEROUS_EXEC_CALLS = frozenset({"eval", "exec", "os.system"})
HTTP_SINKS = frozenset(
    {
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.request",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "httpx.request",
    }
)
SQL_SINK_SUFFIXES = (".execute", ".executemany", ".executescript")
SUBPROCESS_PREFIX = "subprocess."

SENSITIVE_FIELD_NAMES = frozenset(
    {
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "aws_secret_access_key",
        "credit_card",
        "credential",
        "credentials",
        "password",
        "private_key",
        "secret",
        "ssn",
        "token",
    }
)

SENSITIVE_ENV_FRAGMENTS = (
    "API_KEY",
    "AUTH",
    "AWS_SECRET_ACCESS_KEY",
    "CREDENTIAL",
    "KEY",
    "PASSWORD",
    "PRIVATE_KEY",
    "SECRET",
    "TOKEN",
)

REDACTION_CALLS = frozenset(
    {
        "redact",
        "mask",
        "sanitize_for_llm",
        "redact_secrets",
        "redact_pii",
    }
)


def qualified_name_from_expr(node: ast.AST, aliases: dict[str, str]) -> str | None:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        root = aliases.get(current.id, current.id)
        parts.append(root)
        parts.reverse()
        return ".".join(parts)
    return None


def qualified_name_from_call(node: ast.Call, aliases: dict[str, str]) -> str | None:
    return qualified_name_from_expr(node.func, aliases)


def root_name(node: ast.AST) -> str | None:
    current = node
    while isinstance(current, (ast.Attribute, ast.Subscript)):
        current = current.value
    if isinstance(current, ast.Call):
        return root_name(current.func)
    if isinstance(current, ast.Name):
        return current.id
    return None


def constant_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def dict_value(node: ast.Dict, key_name: str) -> ast.AST | None:
    for key, value in zip(node.keys, node.values):
        if constant_string(key) == key_name:
            return value
    return None


def iter_child_exprs(node: ast.AST) -> Iterable[ast.AST]:
    for child in ast.iter_child_nodes(node):
        yield child


def is_shell_true(node: ast.Call) -> bool:
    return any(
        kw.arg == "shell"
        and isinstance(kw.value, ast.Constant)
        and kw.value.value is True
        for kw in node.keywords
    )


def subscript_key_name(node: ast.Subscript) -> str | None:
    key = node.slice
    if isinstance(key, ast.Constant) and isinstance(key.value, str):
        return key.value
    return None


def is_sensitive_name(value: str | None) -> bool:
    if not value:
        return False
    lowered = value.lower()
    return any(part in lowered for part in SENSITIVE_FIELD_NAMES)
