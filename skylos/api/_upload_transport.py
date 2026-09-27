"""Retry policy, idempotency and error wording for report uploads.

The HTTP calls themselves stay in ``skylos.api`` so existing callers and
tests that patch ``skylos.api.requests`` keep working; this module holds the
pure logic those calls use.
"""

from __future__ import annotations

import email.utils
import json
import os
import random
import re
import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit
from uuid import uuid4

from skylos.api._upload_contract import (
    CONTRACT_HEADER,
    IDEMPOTENCY_HEADER,
    contract_version,
    retryable_statuses,
)

__all__ = [
    "RetryPolicy",
    "conflict_delay",
    "is_retryable_conflict",
    "UploadFailure",
    "UploadSession",
    "backoff_delay",
    "compose_message",
    "describe_http_failure",
    "describe_transport_exception",
    "is_idempotent_replay",
    "new_idempotency_key",
    "parse_retry_after",
    "response_body",
    "upload_contract_headers",
]

DEFAULT_MAX_ATTEMPTS = 4
DEFAULT_BASE_SECONDS = 1.0
DEFAULT_MAX_SECONDS = 30.0
# Contract transport.retryable_conflict: a 409 marked retryable (for example
# UPLOAD_IN_PROGRESS) is retried after Retry-After within at least 300s.
DEFAULT_CONFLICT_BUDGET_SECONDS = 300.0
DEFAULT_CONFLICT_DELAY_SECONDS = 15.0
MAX_CONFLICT_DELAY_SECONDS = 60.0

_MAX_TEXT = 300
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")

SAVED_HINT = "The scan was saved; run 'skylos upload --retry' to send it."


def _env_float(name: str, default: float, *, low: float, high: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    if value != value:  # NaN
        return default
    return min(max(value, low), high)


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    base_seconds: float = DEFAULT_BASE_SECONDS
    max_seconds: float = DEFAULT_MAX_SECONDS
    conflict_budget_seconds: float = DEFAULT_CONFLICT_BUDGET_SECONDS

    @classmethod
    def from_env(cls) -> "RetryPolicy":
        """Defaults, overridable for tests and slow networks.

        SKYLOS_UPLOAD_MAX_ATTEMPTS (1-10), SKYLOS_UPLOAD_RETRY_BASE_SECONDS and
        SKYLOS_UPLOAD_RETRY_MAX_SECONDS (0-300), and
        SKYLOS_UPLOAD_CONFLICT_BUDGET_SECONDS (0-3600) for how long a
        "still processing" answer is waited out.
        """
        attempts = int(
            _env_float(
                "SKYLOS_UPLOAD_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS, low=1, high=10
            )
        )
        base = _env_float(
            "SKYLOS_UPLOAD_RETRY_BASE_SECONDS", DEFAULT_BASE_SECONDS, low=0, high=300
        )
        cap = _env_float(
            "SKYLOS_UPLOAD_RETRY_MAX_SECONDS", DEFAULT_MAX_SECONDS, low=0, high=300
        )
        budget = _env_float(
            "SKYLOS_UPLOAD_CONFLICT_BUDGET_SECONDS",
            DEFAULT_CONFLICT_BUDGET_SECONDS,
            low=0,
            high=3600,
        )
        return cls(
            max_attempts=attempts,
            base_seconds=base,
            max_seconds=cap,
            conflict_budget_seconds=budget,
        )


def backoff_delay(
    retry_number: int,
    policy: RetryPolicy,
    *,
    rand: Callable[[float, float], float] = random.uniform,
) -> float:
    """Exponential backoff with full jitter for the ``retry_number``-th retry.

    ``retry_number`` starts at 1. The delay is uniform in
    ``[0, min(max_seconds, base_seconds * 2 ** (retry_number - 1))]``.
    """
    exponent = max(retry_number - 1, 0)
    ceiling = min(policy.max_seconds, policy.base_seconds * (2 ** min(exponent, 16)))
    if ceiling <= 0:
        return 0.0
    return max(0.0, min(rand(0.0, ceiling), ceiling))


def parse_retry_after(value: Any, *, now: float | None = None) -> float | None:
    """Seconds to wait from a Retry-After header (delta-seconds or HTTP date)."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.isdigit():
        return float(int(text))
    try:
        when = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if when is None:
        return None
    current = time.time() if now is None else now
    try:
        return max(0.0, when.timestamp() - current)
    except (OverflowError, OSError, ValueError):
        return None


def new_idempotency_key() -> str:
    return str(uuid4())


@dataclass
class UploadSession:
    """One logical upload: its idempotency key and the route it is using.

    The key is reused for every retry and later resend of the same request.
    It changes only when the request itself changes (an optional artifact is
    dropped, or the upload falls back to the compact format), because the
    server rejects a key reused with a different payload.
    """

    idempotency_key: str
    mode: str | None = None
    # The JSON body of the main request as it was sent (inline/compact body,
    # or the artifact init body) and, for artifact uploads, the artifact
    # files' bytes. Kept so a saved upload can resend exactly these bytes.
    request_payload: Any = None
    artifact_snapshot: dict[str, Any] | None = None

    @classmethod
    def new(cls, mode: str | None = None) -> "UploadSession":
        return cls(idempotency_key=new_idempotency_key(), mode=mode)

    def switch(self, mode: str) -> None:
        if self.mode is not None and self.mode != mode:
            self.idempotency_key = new_idempotency_key()
            self.request_payload = None
            self.artifact_snapshot = None
        self.mode = mode

    def rotate(self) -> None:
        self.idempotency_key = new_idempotency_key()


CLI_VERSION_HEADER = "X-Skylos-Cli-Version"
_VERSION_RE = re.compile(r"^[0-9A-Za-z.+-]{1,32}$")


def upload_contract_headers(
    headers: dict, idempotency_key: str | None, cli_version: str | None = None
) -> dict:
    """Contract, idempotency and client-version headers for one upload request.

    The CLI version lets Skylos Cloud record which release sent a failed
    upload; it is only sent when it looks like a version string.
    """
    merged = dict(headers)
    merged[CONTRACT_HEADER] = str(contract_version())
    if idempotency_key:
        merged[IDEMPOTENCY_HEADER] = idempotency_key
    if cli_version and _VERSION_RE.match(cli_version):
        merged[CLI_VERSION_HEADER] = cli_version
        merged.setdefault("User-Agent", f"skylos/{cli_version}")
    return merged


def _header(response: Any, name: str) -> str | None:
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    try:
        value = headers.get(name)
    except (AttributeError, TypeError):
        return None
    return value if isinstance(value, str) else None


def is_idempotent_replay(response: Any, body: Any = None) -> bool:
    """Cloud already had this upload: ``Idempotent-Replayed: true`` or the
    ``idempotent_replay: true`` body flag."""
    value = _header(response, "Idempotent-Replayed")
    if value and value.strip().lower() == "true":
        return True
    return isinstance(body, dict) and body.get("idempotent_replay") is True


def response_body(response: Any) -> dict[str, Any]:
    try:
        data = response.json()
    except (ValueError, TypeError, AttributeError, KeyError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def clean_text(value: Any, limit: int = _MAX_TEXT) -> str | None:
    """Server text made safe for one terminal line, or None."""
    if not isinstance(value, str):
        return None
    text = _CONTROL_RE.sub(" ", value)
    text = " ".join(text.split())
    if not text:
        return None
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def compose_message(
    error: str, hint: str | None = None, request_id: str | None = None
) -> str:
    parts = [error.strip()]
    if hint and hint.strip() and hint.strip() not in error:
        parts.append(hint.strip())
    message = " ".join(parts)
    if request_id:
        message += f" (ref: {request_id})"
    return message


class UploadFailure(str):
    """An upload error message that also carries what went wrong.

    It is a ``str`` so existing callers that print or store the error keep
    working; upload code reads the attributes to decide on retries and on
    saving the scan for ``skylos upload --retry``.
    """

    code: str | None
    status: int | None
    error: str
    hint: str | None
    request_id: str | None
    retryable: bool
    retry_after: float | None

    def __new__(
        cls,
        error: str,
        *,
        hint: str | None = None,
        code: str | None = None,
        status: int | None = None,
        request_id: str | None = None,
        retryable: bool = False,
        retry_after: float | None = None,
    ):
        obj = super().__new__(cls, compose_message(error, hint, request_id))
        obj.error = error
        obj.hint = hint
        obj.code = code
        obj.status = status
        obj.request_id = request_id
        obj.retryable = retryable
        obj.retry_after = retry_after
        return obj

    def with_hint(self, hint: str) -> "UploadFailure":
        return UploadFailure(
            self.error,
            hint=hint,
            code=self.code,
            status=self.status,
            request_id=self.request_id,
            retryable=self.retryable,
            retry_after=self.retry_after,
        )

    def as_result(self) -> dict[str, Any]:
        # Keep the UploadFailure itself (it is a str) so callers can still
        # read its code, hint and request id.
        result: dict[str, Any] = {"success": False, "error": self}
        if self.code:
            result["code"] = self.code
        if self.status is not None:
            result["status"] = self.status
        if self.request_id:
            result["request_id"] = self.request_id
        result["retryable"] = self.retryable
        return result


_INVALID_TOKEN = (
    "Invalid API token.",
    "Run 'skylos login' to reconnect or 'skylos sync connect' to set a token manually.",
)
_NO_CREDITS = (
    "No credits remaining.",
    "Buy more at skylos.dev/dashboard/billing, then upload again.",
)
_TOO_LARGE = (
    "The scan is too large for Skylos Cloud to accept in one request.",
    "Update Skylos with 'pip install -U skylos' so large scans use artifact "
    "upload, or scan a smaller path; very large scans may need a paid plan.",
)

# Plain wording for codes an older server sends without a hint.
KNOWN_CODES: dict[str, tuple[str, str]] = {
    "INVALID_TOKEN": _INVALID_TOKEN,
    "UNAUTHORIZED": _INVALID_TOKEN,
    "NO_CREDITS": _NO_CREDITS,
    "PROJECT_ROOT_FINDING_MISMATCH": (
        "Some findings are outside the project this upload is linked to.",
        "Run Skylos from the project folder, or upload each monorepo project "
        "separately.",
    ),
    "INVALID_FINDING_INPUT": (
        "Skylos Cloud rejected findings with invalid file paths or labels.",
        "Update Skylos with 'pip install -U skylos' and scan again.",
    ),
    "UPLOAD_IN_PROGRESS": (
        "Skylos Cloud is still processing this upload.",
        "Wait a minute, then run 'skylos upload --retry' to confirm it was saved.",
    ),
    "IDEMPOTENCY_KEY_REUSED": (
        "This upload's key was already used for a different scan.",
        "Run the scan again to upload it with a new key.",
    ),
    "PAYLOAD_TOO_LARGE": _TOO_LARGE,
    "BODY_TOO_LARGE": _TOO_LARGE,
    "RATE_LIMITED": (
        "Skylos Cloud is limiting uploads right now.",
        "Wait a few minutes and try again.",
    ),
    "UNVERIFIED_GITHUB_SCAN": (
        "Skylos Cloud could not tie this upload to the GitHub workflow and commit.",
        "Run a fresh Skylos scan in the workflow for this commit.",
    ),
}

# Codes where retrying the same request later can succeed.
_RETRY_LATER_CODES = frozenset({"UPLOAD_IN_PROGRESS", "RATE_LIMITED"})


def _status_wording(status: int) -> tuple[str, str | None]:
    if status == 401:
        return _INVALID_TOKEN
    if status == 402:
        return _NO_CREDITS
    if status == 403:
        return (
            "Skylos Cloud refused this upload (HTTP 403).",
            "Check that your token belongs to this project with 'skylos whoami'.",
        )
    if status == 404:
        return (
            "The Skylos Cloud upload endpoint was not found (HTTP 404).",
            "Check SKYLOS_API_URL, or update Skylos with 'pip install -U skylos'.",
        )
    if status == 413:
        return _TOO_LARGE
    if status == 429:
        return (
            "Skylos Cloud is limiting uploads right now (HTTP 429).",
            "Wait a few minutes and try again.",
        )
    if status in (408, 504):
        return (
            f"Skylos Cloud took too long to respond (HTTP {status}).",
            "Try again in a few minutes.",
        )
    if status >= 500:
        return (
            f"Skylos Cloud had a temporary problem (HTTP {status}).",
            "Try again in a few minutes.",
        )
    return (
        f"Skylos Cloud rejected the upload (HTTP {status}).",
        "Update Skylos with 'pip install -U skylos' and try again.",
    )


def _rejected_findings_detail(body: dict[str, Any]) -> str | None:
    rejected = body.get("rejected_findings")
    if not isinstance(rejected, list) or not rejected:
        return None
    parts = []
    for item in rejected[:3]:
        if not isinstance(item, dict):
            continue
        index = item.get("index")
        label = f"#{index}" if isinstance(index, int) else "one finding"
        field = clean_text(item.get("field"), 40)
        path = clean_text(item.get("file_path"), 120)
        if path:
            parts.append(f"{label} ({path})")
        elif field:
            parts.append(f"{label} ({field})")
        else:
            parts.append(label)
    if not parts:
        return None
    more = len(rejected) - len(parts)
    suffix = f" and {more} more" if more > 0 else ""
    return f"Rejected: {', '.join(parts)}{suffix}."


def describe_http_failure(
    response: Any, *, retryable_status_set: frozenset[int] | None = None
) -> UploadFailure:
    """Turn a failed HTTP response into one plain sentence plus a hint."""
    status = getattr(response, "status_code", None)
    if not isinstance(status, int):
        status = 0
    body = response_body(response)
    code = clean_text(body.get("code"), 80)
    if code is not None:
        code = code.upper()
    if status == 413 and code is None:
        code = "PAYLOAD_TOO_LARGE"
    if status == 401 and code is None:
        code = "INVALID_TOKEN"
    if status == 402 and code is None:
        code = "NO_CREDITS"

    known = KNOWN_CODES.get(code or "")
    fallback_error, fallback_hint = known or _status_wording(status)
    error = clean_text(body.get("error")) or clean_text(body.get("message"))
    hint = clean_text(body.get("hint"))
    if error is None:
        error = fallback_error
        hint = hint or fallback_hint
    elif hint is None and known is not None:
        hint = fallback_hint
    if code in {"INVALID_FINDING_INPUT", "PROJECT_ROOT_FINDING_MISMATCH"}:
        detail = _rejected_findings_detail(body)
        if detail:
            error = f"{error} {detail}"

    request_id = clean_text(body.get("request_id"), 120) or clean_text(
        _header(response, "X-Request-Id"), 120
    )
    statuses = (
        retryable_status_set
        if retryable_status_set is not None
        else retryable_statuses()
    )
    body_retryable = body.get("retryable")
    if isinstance(body_retryable, bool):
        retryable = body_retryable
    else:
        retryable = status in statuses or code in _RETRY_LATER_CODES
    retry_after = parse_retry_after(_header(response, "Retry-After"))
    return UploadFailure(
        error,
        hint=hint,
        code=code,
        status=status or None,
        request_id=request_id,
        retryable=retryable,
        retry_after=retry_after,
    )


def should_retry_now(failure: UploadFailure) -> bool:
    """Retry inside this run for transport errors and contract statuses.

    A retryable 409 is handled separately (see ``is_retryable_conflict``).
    """
    if failure.status is None:
        return failure.retryable
    if failure.status not in retryable_statuses():
        return False
    return failure.retryable


def is_retryable_conflict(failure: UploadFailure) -> bool:
    """A 409 the server marked retryable, e.g. the same upload still running."""
    return failure.status == 409 and failure.retryable


def conflict_delay(failure: UploadFailure) -> float:
    retry_after = failure.retry_after
    if retry_after is None:
        retry_after = DEFAULT_CONFLICT_DELAY_SECONDS
    return min(max(retry_after, 1.0), MAX_CONFLICT_DELAY_SECONDS)


def describe_transport_exception(exc: BaseException, url: str) -> UploadFailure:
    import requests

    host = urlsplit(url).hostname or "Skylos Cloud"
    if isinstance(exc, requests.exceptions.Timeout):
        return UploadFailure(
            f"The upload to {host} timed out.",
            hint="Try again in a few minutes.",
            code="TIMEOUT",
            retryable=True,
        )
    if isinstance(
        exc,
        (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError),
    ):
        return UploadFailure(
            f"Could not reach {host}.",
            hint="Check your network connection or SKYLOS_API_URL.",
            code="CONNECTION_ERROR",
            retryable=True,
        )
    return UploadFailure(
        f"The upload request to {host} failed ({type(exc).__name__}).",
        hint="Check SKYLOS_API_URL and try again.",
        code="REQUEST_ERROR",
        retryable=False,
    )


def is_retryable_transport_exception(exc: BaseException) -> bool:
    import requests

    return isinstance(
        exc,
        (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.ChunkedEncodingError,
        ),
    )
