from __future__ import annotations

import re
from typing import Any

REDACTION = "[REDACTED_SECRET]"

SECRET_KEYWORDS = {
    "access_token",
    "api_key",
    "auth",
    "authorization",
    "bearer",
    "credential",
    "key",
    "match",
    "password",
    "private_key",
    "raw",
    "secret",
    "token",
    "value",
}

SECRET_PATTERNS = (
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|gpat)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,48}\b"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA)[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
    re.compile(
        r"(?i)AWS_SECRET_ACCESS_KEY\s*[:=]\s*[A-Za-z0-9/+=]{40}"
    ),
    re.compile(
        r"(?i)\b(?:token|api[_-]?key|secret|password|passwd|pwd|auth[_-]?token)"
        r"\s*[:=]\s*['\"][^'\"]{12,}['\"]"
    ),
)


def redact_text(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(REDACTION, redacted)
    return redacted


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(token in lowered for token in SECRET_KEYWORDS)


def sanitize_for_audit(value: Any, *, key: str | None = None) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        if key and _is_sensitive_key(key) and "preview" not in key.lower():
            return REDACTION
        return redact_text(value)

    if isinstance(value, list):
        return [sanitize_for_audit(item) for item in value]

    if isinstance(value, tuple):
        return [sanitize_for_audit(item) for item in value]

    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for item_key, item_value in value.items():
            safe_key = str(item_key)
            sanitized[safe_key] = sanitize_for_audit(item_value, key=safe_key)
        return sanitized

    return str(value)
