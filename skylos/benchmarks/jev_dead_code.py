from __future__ import annotations

import math
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import requests

from skylos.benchmarks._jev_dead_code_dataset import (
    CHOICES,
    JEV_ENDPOINT,
    JEV_MODEL,
    JevBatch,
    JevBenchmarkError,
    build_plan,
    prepare_batches,
)
from skylos.benchmarks._jev_dead_code_report import (
    build_report,
    format_plan,
    format_report,
    score_predictions,
)


MAX_RESPONSE_BYTES = 2_000_000
REQUEST_TIMEOUT_SECONDS = 60.0
MAX_RETRIES = 3
Transport = Callable[[dict[str, Any], str], dict[str, Any]]
Checkpoint = Callable[[dict[str, Any]], None]


def _number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise JevBenchmarkError(f"Jev response {field} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise JevBenchmarkError(f"Jev response {field} must be between 0 and 1")
    return result


def _validate_usage(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        raise JevBenchmarkError("Jev response usage must be an object")
    usage: dict[str, int] = {}
    for field in ("input_tokens", "output_tokens"):
        item = value.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise JevBenchmarkError(f"Jev response usage.{field} must be non-negative")
        usage[field] = item
    return usage


def _validate_answer(value: Any, question_id: str) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("type") != "choice":
        raise JevBenchmarkError(f"Jev answer {question_id} must be a Choice")
    choice = value.get("choice")
    if choice not in CHOICES:
        raise JevBenchmarkError(f"Jev answer {question_id} returned an unknown choice")
    probabilities = value.get("probabilities")
    if not isinstance(probabilities, dict) or set(probabilities) != set(CHOICES):
        raise JevBenchmarkError(
            f"Jev answer {question_id} probabilities must match the requested choices"
        )
    checked = {}
    for name in CHOICES:
        field = f"answers.{question_id}.probabilities.{name}"
        checked[name] = _number(probabilities[name], field)
    if not math.isclose(sum(checked.values()), 1.0, abs_tol=0.02):
        raise JevBenchmarkError(f"Jev answer {question_id} probabilities must sum to 1")
    if checked[choice] < max(checked.values()) - 1e-9:
        raise JevBenchmarkError(
            f"Jev answer {question_id} choice must have the highest probability"
        )
    confidence = _number(value.get("confidence"), f"answers.{question_id}.confidence")
    return {"choice": choice, "confidence": confidence, "probabilities": checked}


def validate_response(
    response: Any,
    batch: JevBatch,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    if not isinstance(response, dict):
        raise JevBenchmarkError("Jev response must be a JSON object")
    if response.get("model") != JEV_MODEL:
        raise JevBenchmarkError("Jev response model does not match the pinned request")
    answers = response.get("answers")
    expected_ids = {question.question_id for question in batch.questions}
    if not isinstance(answers, dict) or set(answers) != expected_ids:
        raise JevBenchmarkError("Jev response answers do not match the request")
    predictions = []
    for question in batch.questions:
        answer = _validate_answer(answers[question.question_id], question.question_id)
        predicted = {
            "retained": "used",
            "unreferenced": "unused",
            "insufficient_evidence": "abstain",
        }[answer["choice"]]
        predictions.append(
            {
                "question_id": question.question_id,
                "case_id": question.case_id,
                "arm": batch.arm,
                "target": {
                    "kind": question.kind,
                    "file": question.file,
                    "symbol": question.symbol,
                    "sent_symbol": question.sent_symbol,
                    "line": question.line,
                },
                "label_id": question.label_id,
                "taxonomy": list(question.taxonomy),
                "expected": question.expected,
                "predicted": predicted,
                "choice": answer["choice"],
                "confidence": answer["confidence"],
                "probabilities": answer["probabilities"],
            }
        )
    return predictions, _validate_usage(response.get("usage"))


def _retry_delay(response: Any, attempt: int) -> float:
    raw = response.headers.get("Retry-After", "")
    try:
        return min(max(float(raw), 0.0), 10.0)
    except (TypeError, ValueError):
        return min(float(2**attempt), 10.0)


def _send_request(
    session: requests.Session,
    payload: dict[str, Any],
    headers: dict[str, str],
) -> tuple[Any | None, str | None]:
    try:
        response = session.post(
            JEV_ENDPOINT,
            headers=headers,
            json=payload,
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
        return response, None
    except requests.RequestException as exc:
        return None, f"network error: {type(exc).__name__}"


def _decode_response(response: Any) -> dict[str, Any]:
    if response.status_code != 200:
        raise JevBenchmarkError(f"Jev API returned HTTP {response.status_code}")
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise JevBenchmarkError("Jev response exceeded the size limit")
    try:
        value = response.json()
    except ValueError as exc:
        raise JevBenchmarkError("Jev API returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise JevBenchmarkError("Jev API returned a non-object response")
    return value


def request_jev(payload: dict[str, Any], api_key: str) -> dict[str, Any]:
    if not api_key or not api_key.strip():
        raise JevBenchmarkError("TYPESAFE_API_KEY is required for a live Jev run")
    headers = {
        "Authorization": f"Bearer {api_key.strip()}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    last_error = "request failed"
    with requests.Session() as session:
        for attempt in range(MAX_RETRIES):
            response, error = _send_request(session, payload, headers)
            if response is None:
                last_error = error or last_error
                if attempt + 1 < MAX_RETRIES:
                    time.sleep(min(float(2**attempt), 10.0))
                    continue
                break
            if response.status_code in {429, 529} and attempt + 1 < MAX_RETRIES:
                time.sleep(_retry_delay(response, attempt))
                continue
            return _decode_response(response)
    raise JevBenchmarkError(last_error)


def _timed_transport(
    transport: Transport,
    payload: dict[str, Any],
    api_key: str,
) -> tuple[dict[str, Any], float]:
    started = time.perf_counter()
    response = transport(payload, api_key)
    return response, time.perf_counter() - started


def _timed_validation(
    response: dict[str, Any],
    batch: JevBatch,
) -> tuple[list[dict[str, Any]], dict[str, int], float]:
    started = time.perf_counter()
    predictions, usage = validate_response(response, batch)
    return predictions, usage, time.perf_counter() - started


def _error_batch(
    batch: JevBatch,
    started: float,
    error: JevBenchmarkError,
    request_elapsed: float | None = None,
) -> dict[str, Any]:
    result = {
        "case_id": batch.case_id,
        "arm": batch.arm,
        "status": "error",
        "request_digest": batch.request_digest,
        "state_bytes": batch.state_bytes,
        "decision_count": len(batch.questions),
        "elapsed_seconds": round(time.perf_counter() - started, 6),
        "error": str(error),
    }
    if request_elapsed is not None:
        result["request_elapsed_seconds"] = round(request_elapsed, 6)
    return result


def _run_batch(
    batch: JevBatch,
    api_key: str,
    transport: Transport,
) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        response, request_elapsed = _timed_transport(
            transport, batch.payload, api_key
        )
    except JevBenchmarkError as exc:
        return _error_batch(batch, started, exc)
    try:
        predictions, usage, validation_elapsed = _timed_validation(response, batch)
    except JevBenchmarkError as exc:
        return _error_batch(batch, started, exc, request_elapsed)
    return {
        "case_id": batch.case_id,
        "arm": batch.arm,
        "status": "ok",
        "request_digest": batch.request_digest,
        "response_model": response["model"],
        "state_bytes": batch.state_bytes,
        "decision_count": len(batch.questions),
        "request_elapsed_seconds": round(request_elapsed, 6),
        "local_contract_validation_seconds": round(validation_elapsed, 6),
        "elapsed_seconds": round(time.perf_counter() - started, 6),
        "usage": usage,
        "predictions": predictions,
    }


def run_jev_manifest(
    manifest_path: str | Path,
    *,
    api_key: str,
    selected_cases: set[str] | None = None,
    transport: Transport = request_jev,
    checkpoint: Checkpoint | None = None,
) -> dict[str, Any]:
    if not api_key or not api_key.strip():
        raise JevBenchmarkError("TYPESAFE_API_KEY is required for a live Jev run")
    planned = prepare_batches(manifest_path, selected_cases)
    completed: list[dict[str, Any]] = []
    for batch in planned:
        completed.append(_run_batch(batch, api_key, transport))
        report = build_report(manifest_path, completed, len(planned))
        if checkpoint is not None:
            checkpoint(report)
        if completed[-1]["status"] == "error":
            return report
    return build_report(manifest_path, completed, len(planned))
