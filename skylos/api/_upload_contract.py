"""The report-upload contract shared with Skylos Cloud.

``upload_contract/v1.json`` is a vendored copy of the server's contract
(``skylos-cloud/contracts/upload/v1.json``). This module reads it; the rules
are applied by ``_upload_paths`` (file paths) and ``_upload_preflight``
(whole findings) before an upload, so the CLI sends what the server will
store instead of learning about a problem from a rejected upload.
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "CONTRACT_HEADER",
    "IDEMPOTENCY_HEADER",
    "client_read_timeout_seconds",
    "client_resend_window_days",
    "contract_sha256",
    "contract_version",
    "field_max_length",
    "load_upload_contract",
    "placeholder_paths",
    "repository_scope_kind",
    "repository_scope_line",
    "repository_scope_rule_ids",
    "retryable_statuses",
]

CONTRACT_PATH = Path(__file__).with_name("upload_contract") / "v1.json"

# Used only when the vendored file is missing from a broken install, so an
# upload still follows v1 instead of failing.
_FALLBACK_CONTRACT: dict[str, Any] = {
    "contract": "skylos-report-upload",
    "version": 1,
    "finding": {
        "file_path": {
            "max_length": 500,
            "repository_scope": {
                "rule_ids": ["SKY-R101", "SKY-R102", "SKY-R103", "SKY-R104"],
                "kind": "repo_policy",
                "line_number": 1,
                "stored_path": ".",
            },
            "placeholder_paths": {
                "values": [
                    "unknown",
                    "<unknown>",
                    "?",
                    "-",
                    "none",
                    "null",
                    "undefined",
                ]
            },
        },
        "rule_id": {"max_length": 120},
        "category": {"max_length": 40, "default_when_missing": "QUALITY"},
        "severity": {
            "values": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            "default_when_missing": "MEDIUM",
        },
    },
    "transport": {
        "idempotency_header": "Idempotency-Key",
        "contract_header": "X-Skylos-Upload-Contract",
        "retryable_statuses": [408, 425, 429, 500, 502, 503, 504],
        "retry_after_header": "Retry-After",
        "client_resend_window_days": 7,
        "client_read_timeout_seconds": 270,
    },
}

IDEMPOTENCY_HEADER = "Idempotency-Key"
CONTRACT_HEADER = "X-Skylos-Upload-Contract"


@functools.lru_cache(maxsize=1)
def _contract_bytes() -> bytes | None:
    try:
        return CONTRACT_PATH.read_bytes()
    except OSError as exc:
        logger.debug("Upload contract file unavailable: %s", exc)
        return None


@functools.lru_cache(maxsize=1)
def load_upload_contract() -> dict[str, Any]:
    raw = _contract_bytes()
    if raw is None:
        return _FALLBACK_CONTRACT
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        logger.debug("Upload contract file is not valid JSON: %s", exc)
        return _FALLBACK_CONTRACT
    return data if isinstance(data, dict) else _FALLBACK_CONTRACT


def contract_version() -> int:
    version = load_upload_contract().get("version")
    return version if isinstance(version, int) else 1


def contract_sha256() -> str | None:
    """SHA-256 of the contract as compact JSON, keys in file order.

    Matches the server's ``UPLOAD_CONTRACT_SHA256`` (``JSON.stringify`` of the
    parsed file), so a whitespace-only edit does not look like a new contract.
    """
    if _contract_bytes() is None:
        return None
    compact = json.dumps(
        load_upload_contract(), separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(compact.encode("utf-8")).hexdigest()


def _section(*keys: str) -> dict[str, Any]:
    node: Any = load_upload_contract()
    for key in keys:
        node = node.get(key) if isinstance(node, dict) else None
    return node if isinstance(node, dict) else {}


def retryable_statuses() -> frozenset[int]:
    values = _section("transport").get("retryable_statuses")
    if not isinstance(values, list):
        values = _FALLBACK_CONTRACT["transport"]["retryable_statuses"]
    return frozenset(v for v in values if isinstance(v, int))


def repository_scope_rule_ids() -> frozenset[str]:
    values = _section("finding", "file_path", "repository_scope").get("rule_ids")
    if not isinstance(values, list):
        values = _FALLBACK_CONTRACT["finding"]["file_path"]["repository_scope"][
            "rule_ids"
        ]
    return frozenset(v for v in values if isinstance(v, str))


def repository_scope_kind() -> str:
    kind = _section("finding", "file_path", "repository_scope").get("kind")
    return kind if isinstance(kind, str) else "repo_policy"


def repository_scope_line() -> int:
    line = _section("finding", "file_path", "repository_scope").get("line_number")
    return line if isinstance(line, int) else 1


def field_max_length(field: str, default: int) -> int:
    value = _section("finding", field).get("max_length")
    return value if isinstance(value, int) and value > 0 else default


def client_read_timeout_seconds() -> int:
    """How long to wait for a report endpoint's response (contract transport)."""
    value = _section("transport").get("client_read_timeout_seconds")
    return value if isinstance(value, int) and value > 0 else 270


def client_resend_window_days() -> int:
    days = _section("transport").get("client_resend_window_days")
    return days if isinstance(days, int) and days > 0 else 7


def placeholder_paths() -> frozenset[str]:
    values = _section("finding", "file_path", "placeholder_paths").get("values")
    if not isinstance(values, list):
        values = _FALLBACK_CONTRACT["finding"]["file_path"]["placeholder_paths"][
            "values"
        ]
    return frozenset(v.lower() for v in values if isinstance(v, str))
