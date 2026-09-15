"""Bounded, scan-local reads from the fixed OSV advisory endpoint.

The batch API supplies IDs, not complete advisory records. Detail failures are
explicit: a caller can retain its batch-confirmed finding without presenting
missing severity or remediation information as a successful lookup.
"""

from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Callable

MAX_ADVISORIES = 512
MAX_ADVISORY_BYTES = 1_048_576
MAX_TOTAL_ADVISORY_BYTES = 33_554_432
MAX_WORKERS = 4
DETAIL_DEADLINE_SECONDS = 45.0
_STREAM_CHUNK_BYTES = 8_192
_ADVISORY_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z")


class OsvResponseError(ValueError):
    """A response could not be safely read as a complete OSV JSON document."""


@dataclass
class AdvisoryFetchResult:
    advisories: dict[str, dict] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    receipt: dict = field(default_factory=dict)


def is_valid_advisory_id(value: object) -> bool:
    """Allow a bounded, single URL path segment without URL transformations."""
    return isinstance(value, str) and _ADVISORY_ID_RE.fullmatch(value) is not None


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise OsvResponseError("duplicate_json_key")
        result[key] = value
    return result


def _reject_json_constant(_value):
    raise OsvResponseError("invalid_json_constant")


def read_json_response(
    response,
    *,
    max_bytes: int = MAX_ADVISORY_BYTES,
    deadline: float | None = None,
    consume_bytes: Callable[[int], None] | None = None,
):
    """Read and close a streamed HTTP 200 response with a decoded-body limit.

    Callers must request ``stream=True, allow_redirects=False``. The byte limit is
    also applied to decompressed chunks, so a small Content-Length is not trusted.
    ``deadline`` uses ``time.monotonic`` and is checked between yielded chunks.
    Requests read timeouts limit inactivity, not the whole transfer or CLI runtime.
    """
    try:
        if response.status_code != 200:
            raise OsvResponseError(f"http_{response.status_code}")
        if deadline is not None and time.monotonic() >= deadline:
            raise OsvResponseError("detail_deadline_exceeded")
        declared = response.headers.get("Content-Length")
        if declared is not None:
            try:
                declared_bytes = int(declared)
            except (ValueError, TypeError):
                raise OsvResponseError("invalid_content_length") from None
            if declared_bytes < 0:
                raise OsvResponseError("invalid_content_length")
            if declared_bytes > max_bytes:
                raise OsvResponseError("response_size_limit")

        body = bytearray()
        for chunk in response.iter_content(chunk_size=_STREAM_CHUNK_BYTES):
            if deadline is not None and time.monotonic() >= deadline:
                raise OsvResponseError("detail_deadline_exceeded")
            if not chunk:
                continue
            if not isinstance(chunk, bytes):
                raise OsvResponseError("invalid_response_chunk")
            if consume_bytes is not None:
                consume_bytes(len(chunk))
            if len(body) + len(chunk) > max_bytes:
                raise OsvResponseError("response_size_limit")
            body.extend(chunk)
        if deadline is not None and time.monotonic() >= deadline:
            raise OsvResponseError("detail_deadline_exceeded")
        try:
            return json.loads(
                body.decode("utf-8"),
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeError, ValueError, RecursionError):
            raise OsvResponseError("invalid_json") from None
    finally:
        try:
            response.close()
        except Exception:
            # Closing must not replace the original transport/schema failure.
            pass


def _valid_optional_metadata(document: dict) -> bool:
    for key in ("database_specific", "ecosystem_specific"):
        if key in document and not isinstance(document[key], dict):
            return False
    if "severity" in document:
        severity = document["severity"]
        if not isinstance(severity, list):
            return False
        for rating in severity:
            if not isinstance(rating, dict) or any(
                not isinstance(rating.get(key), str) or not rating[key]
                for key in ("type", "score")
            ):
                return False
    if "references" in document:
        references = document["references"]
        if not isinstance(references, list):
            return False
        for reference in references:
            if not isinstance(reference, dict) or any(
                not isinstance(reference.get(key), str) or not reference[key]
                for key in ("type", "url")
            ):
                return False
    return True


def _valid_advisory(document: object, advisory_id: str) -> bool:
    if not isinstance(document, dict) or document.get("id") != advisory_id:
        return False
    if not _valid_optional_metadata(document):
        return False
    affected = document.get("affected")
    if not isinstance(affected, list):
        return False
    for key in ("summary", "details", "withdrawn"):
        if key in document and not isinstance(document[key], str):
            return False
    for key in ("aliases", "related"):
        if key in document and (
            not isinstance(document[key], list)
            or not all(isinstance(item, str) for item in document[key])
        ):
            return False
    for entry in affected:
        if not isinstance(entry, dict) or not _valid_optional_metadata(entry):
            return False
        package = entry.get("package")
        if "package" in entry and (
            not isinstance(package, dict)
            or any(
                key in package
                and (not isinstance(package[key], str) or not package[key])
                for key in ("name", "ecosystem", "purl")
            )
        ):
            return False
        if "versions" in entry and (
            not isinstance(entry["versions"], list)
            or not all(isinstance(item, str) for item in entry["versions"])
        ):
            return False
        if "ranges" in entry:
            ranges = entry["ranges"]
            if not isinstance(ranges, list):
                return False
            for affected_range in ranges:
                if not isinstance(affected_range, dict):
                    return False
                if not isinstance(affected_range.get("type"), str):
                    return False
                events = affected_range.get("events")
                if not isinstance(events, list):
                    return False
                for event in events:
                    if not isinstance(event, dict) or len(event) != 1:
                        return False
                    key, value = next(iter(event.items()))
                    if key not in {"introduced", "fixed", "last_affected", "limit"}:
                        return False
                    if not isinstance(value, str):
                        return False
    return True


def fetch_advisories(ids: list[str], client) -> AdvisoryFetchResult:
    """Fetch each distinct ID once, with bounded work and no persistent cache.

    ``requested_count`` counts transport calls attempted; ``unique_id_count`` also
    includes invalid/limit-skipped IDs. Failed IDs are not retried during a scan.
    The deadline stops collection and new requests, not running worker threads.
    Requests read timeouts limit inactivity, not total response time; a worker
    can outlive the collection deadline, and process exit can wait for that worker.
    """
    unique_ids = list(dict.fromkeys(ids))
    advisories: dict[str, dict] = {}
    errors: dict[str, str] = {}
    candidates = []
    for advisory_id in unique_ids:
        if not is_valid_advisory_id(advisory_id):
            errors[advisory_id] = "invalid_advisory_id"
        elif len(candidates) >= MAX_ADVISORIES:
            errors[advisory_id] = "advisory_count_limit"
        else:
            candidates.append(advisory_id)

    deadline = time.monotonic() + DETAIL_DEADLINE_SECONDS
    state_lock = threading.Lock()
    stop = threading.Event()
    attempted: set[str] = set()
    total_bytes = 0
    total_size_exceeded = False

    def consume_bytes(count):
        nonlocal total_bytes, total_size_exceeded
        with state_lock:
            if stop.is_set():
                reason = (
                    "total_response_size_limit"
                    if total_size_exceeded
                    else "detail_deadline_exceeded"
                )
                raise OsvResponseError(reason)
            if total_bytes + count > MAX_TOTAL_ADVISORY_BYTES:
                total_size_exceeded = True
                stop.set()
                raise OsvResponseError("total_response_size_limit")
            total_bytes += count

    def fetch_one(advisory_id):
        if not is_valid_advisory_id(advisory_id):
            return None, "invalid_advisory_id"
        with state_lock:
            remaining = deadline - time.monotonic()
            if stop.is_set() or remaining <= 0:
                return None, "detail_deadline_exceeded"
            attempted.add(advisory_id)
        try:
            # Keep the fixed origin visible at the request boundary. The ID is
            # a validated ASCII path segment, and redirects are disabled below.
            response = client.get(
                f"https://api.osv.dev/v1/vulns/{advisory_id}",
                timeout=(min(5.0, remaining), min(15.0, remaining)),
                stream=True,
                allow_redirects=False,
            )
            document = read_json_response(
                response,
                max_bytes=MAX_ADVISORY_BYTES,
                deadline=deadline,
                consume_bytes=consume_bytes,
            )
            if not _valid_advisory(document, advisory_id):
                return None, "invalid_advisory_document"
            return document, None
        except OsvResponseError as exc:
            return None, str(exc)
        except Exception:
            # Do not expose proxy credentials, URLs or response bodies in errors.
            return None, "advisory_transport_error"

    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    pending = {}
    next_index = 0
    deadline_exceeded = False
    try:
        while pending or next_index < len(candidates):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                deadline_exceeded = True
                stop.set()
                break
            while (
                not stop.is_set()
                and len(pending) < MAX_WORKERS
                and next_index < len(candidates)
            ):
                advisory_id = candidates[next_index]
                next_index += 1
                pending[executor.submit(fetch_one, advisory_id)] = advisory_id
            if not pending:
                break
            completed, _ = wait(pending, timeout=remaining, return_when=FIRST_COMPLETED)
            if not completed:
                deadline_exceeded = True
                stop.set()
                break
            for future in completed:
                advisory_id = pending.pop(future)
                document, error = future.result()
                if error:
                    errors[advisory_id] = error
                else:
                    advisories[advisory_id] = document
    finally:
        stop.set()
        for future in pending:
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)

    with state_lock:
        requested_count = len(attempted)
        accepted_bytes = total_bytes
    missing_reason = (
        "total_response_size_limit"
        if total_size_exceeded
        else "detail_deadline_exceeded"
    )
    for advisory_id in candidates:
        if advisory_id not in advisories and advisory_id not in errors:
            errors[advisory_id] = missing_reason
    deadline_exceeded = deadline_exceeded or any(
        error == "detail_deadline_exceeded" for error in errors.values()
    )
    # Preserve input order despite concurrent transport completion.
    advisories = {key: advisories[key] for key in unique_ids if key in advisories}
    errors = {key: errors[key] for key in unique_ids if key in errors}
    return AdvisoryFetchResult(
        advisories=advisories,
        errors=errors,
        receipt={
            "status": "incomplete" if errors else "complete",
            "complete": not errors,
            "unique_id_count": len(unique_ids),
            "requested_count": requested_count,
            "successful_count": len(advisories),
            "failed_count": len(errors),
            "skipped_count": len(unique_ids) - requested_count,
            "accepted_response_bytes": accepted_bytes,
            "deadline_exceeded": deadline_exceeded,
            "total_size_exceeded": total_size_exceeded,
            "limits": {
                "advisories": MAX_ADVISORIES,
                "response_bytes": MAX_ADVISORY_BYTES,
                "total_response_bytes": MAX_TOTAL_ADVISORY_BYTES,
                "workers": MAX_WORKERS,
                "deadline_seconds": DETAIL_DEADLINE_SECONDS,
            },
        },
    )
