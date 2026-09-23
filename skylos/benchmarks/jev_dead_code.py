from __future__ import annotations

import json
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
    PROMPT_VERSION,
    JevBatch,
    JevBenchmarkError,
    _digest,
    build_plan as build_plan,
    prepare_batches as prepare_batches,
    prepare_batches_with_snapshot_and_status,
    prompt_digest,
)
from skylos.benchmarks._jev_dead_code_report import (
    REPORT_SCHEMA_VERSION,
    build_report,
    format_plan as format_plan,
    format_report as format_report,
    score_predictions as score_predictions,
)


MAX_RESPONSE_BYTES = 2_000_000
REQUEST_TIMEOUT_SECONDS = 60.0
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
            stream=True,
        )
        return response, None
    except requests.RequestException as exc:
        return None, f"network error: {type(exc).__name__}"


def _decode_response(response: Any) -> dict[str, Any]:
    if response.status_code != 200:
        raise JevBenchmarkError(f"Jev API returned HTTP {response.status_code}")
    length = response.headers.get("Content-Length")
    if length is not None:
        try:
            if int(length) > MAX_RESPONSE_BYTES:
                raise JevBenchmarkError("Jev response exceeded the size limit")
        except ValueError:
            pass
    chunks = []
    total = 0
    # requests.Response.content buffers the entire body, so always enforce the
    # limit while downloading. The fallback keeps simple injected test doubles
    # compatible without changing the production streaming path.
    if hasattr(response, "iter_content"):
        for chunk in response.iter_content(chunk_size=64_000):
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise JevBenchmarkError("Jev response exceeded the size limit")
            chunks.append(chunk)
        raw = b"".join(chunks)
    else:
        raw = response.content
        if len(raw) > MAX_RESPONSE_BYTES:
            raise JevBenchmarkError("Jev response exceeded the size limit")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
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
    with requests.Session() as session:
        response, error = _send_request(session, payload, headers)
        if response is None:
            # A timed-out paid request may already have reached the service.
            # Without an idempotency guarantee, never retry it automatically.
            raise JevBenchmarkError(error or "request failed")
        try:
            return _decode_response(response)
        except requests.RequestException as exc:
            raise JevBenchmarkError(f"network error: {type(exc).__name__}") from exc
        finally:
            close = getattr(response, "close", None)
            if close is not None:
                close()


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
        response, request_elapsed = _timed_transport(transport, batch.payload, api_key)
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


def _provenance(
    manifest_path: str | Path,
    manifest_hash: str,
    metadata: dict[str, Any],
    planned: list[JevBatch],
    neutralization_status_counts: dict[str, int],
) -> dict[str, Any]:
    return {
        "manifest": Path(manifest_path).name,
        "manifest_digest": manifest_hash,
        "manifest_metadata": metadata,
        "endpoint": JEV_ENDPOINT,
        "requested_model": JEV_MODEL,
        "prompt_version": PROMPT_VERSION,
        "prompt_digest": prompt_digest(),
        "neutralization_status_counts": neutralization_status_counts,
        "planned_requests": [
            {
                "case_id": batch.case_id,
                "arm": batch.arm,
                "request_digest": batch.request_digest,
                **(
                    {"neutralization": batch.neutralization}
                    if batch.neutralization is not None
                    else {}
                ),
            }
            for batch in planned
        ],
    }


def _validate_reused_batch(result: Any, batch: JevBatch) -> None:
    if not isinstance(result, dict) or result.get("status") != "ok":
        raise JevBenchmarkError("resume report has an invalid successful batch")
    expected = {
        "case_id": batch.case_id,
        "arm": batch.arm,
        "request_digest": batch.request_digest,
        "response_model": JEV_MODEL,
        "state_bytes": batch.state_bytes,
        "decision_count": len(batch.questions),
    }
    if any(result.get(field) != value for field, value in expected.items()):
        raise JevBenchmarkError("resume batch does not match the prepared request")
    _validate_usage(result.get("usage"))
    predictions = result.get("predictions")
    if not isinstance(predictions, list) or len(predictions) != len(batch.questions):
        raise JevBenchmarkError("resume batch predictions do not match the request")
    for item, question in zip(predictions, batch.questions):
        if not isinstance(item, dict):
            raise JevBenchmarkError("resume batch prediction must be an object")
        expected_fields = {
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
        }
        if any(item.get(field) != value for field, value in expected_fields.items()):
            raise JevBenchmarkError("resume batch prediction identity does not match")
        answer = _validate_answer(
            {
                "type": "choice",
                "choice": item.get("choice"),
                "confidence": item.get("confidence"),
                "probabilities": item.get("probabilities"),
            },
            question.question_id,
        )
        predicted = {
            "retained": "used",
            "unreferenced": "unused",
            "insufficient_evidence": "abstain",
        }[answer["choice"]]
        if item.get("predicted") != predicted:
            raise JevBenchmarkError("resume batch predicted label does not match")
    for field in (
        "request_elapsed_seconds",
        "local_contract_validation_seconds",
        "elapsed_seconds",
    ):
        value = result.get(field)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise JevBenchmarkError(f"resume batch {field} must be numeric")
        if not math.isfinite(value) or value < 0:
            raise JevBenchmarkError(f"resume batch {field} must be non-negative")


def _resume_successes(
    resume_report: dict[str, Any],
    provenance: dict[str, Any],
    planned: list[JevBatch],
) -> list[dict[str, Any]]:
    if not isinstance(resume_report, dict):
        raise JevBenchmarkError("resume report must be a JSON object")
    digest = resume_report.get("report_digest")
    unsigned = {
        key: value for key, value in resume_report.items() if key != "report_digest"
    }
    if not isinstance(digest, str) or digest != _digest(unsigned):
        raise JevBenchmarkError("resume report digest does not match its content")
    if (
        resume_report.get("schema_version") != REPORT_SCHEMA_VERSION
        or resume_report.get("benchmark") != "jev_dead_code"
    ):
        raise JevBenchmarkError("resume report schema does not match")
    if any(resume_report.get(field) != value for field, value in provenance.items()):
        raise JevBenchmarkError(
            "resume report provenance does not match the prepared run"
        )
    if resume_report.get("planned_request_count") != len(planned):
        raise JevBenchmarkError("resume report request count does not match")
    results = resume_report.get("batches")
    if not isinstance(results, list) or len(results) > len(planned):
        raise JevBenchmarkError("resume report batches do not match the plan")
    completed = []
    for index, result in enumerate(results):
        batch = planned[index]
        if not isinstance(result, dict):
            raise JevBenchmarkError("resume report batch must be an object")
        if result.get("status") == "error" and index == len(results) - 1:
            if any(
                result.get(field) != value
                for field, value in {
                    "case_id": batch.case_id,
                    "arm": batch.arm,
                    "request_digest": batch.request_digest,
                    "state_bytes": batch.state_bytes,
                    "decision_count": len(batch.questions),
                }.items()
            ):
                raise JevBenchmarkError("resume error batch does not match the request")
            break
        _validate_reused_batch(result, batch)
        completed.append(result)
    if resume_report.get("completed_request_count") != len(completed):
        raise JevBenchmarkError("resume report completed count does not match")
    if resume_report.get("status") != (
        "complete" if len(completed) == len(planned) else "incomplete"
    ):
        raise JevBenchmarkError("resume report status does not match its batches")
    return completed


def run_jev_manifest(
    manifest_path: str | Path,
    *,
    api_key: str,
    selected_cases: set[str] | None = None,
    transport: Transport = request_jev,
    checkpoint: Checkpoint | None = None,
    resume_report: dict[str, Any] | None = None,
    max_new_requests: int | None = None,
    expected_prompt_digest: str | None = None,
    expected_manifest_digest: str | None = None,
) -> dict[str, Any]:
    if not api_key or not api_key.strip():
        raise JevBenchmarkError("TYPESAFE_API_KEY is required for a live Jev run")
    if max_new_requests is not None and (
        isinstance(max_new_requests, bool)
        or not isinstance(max_new_requests, int)
        or max_new_requests < 1
    ):
        raise JevBenchmarkError("max_new_requests must be a positive integer")
    planned, manifest_hash, metadata, neutralization_status_counts = (
        prepare_batches_with_snapshot_and_status(manifest_path, selected_cases)
    )
    provenance = _provenance(
        manifest_path, manifest_hash, metadata, planned, neutralization_status_counts
    )
    if (
        expected_manifest_digest is not None
        and manifest_hash != expected_manifest_digest
    ):
        raise JevBenchmarkError("manifest digest does not match the expected value")
    if (
        expected_prompt_digest is not None
        and provenance["prompt_digest"] != expected_prompt_digest
    ):
        raise JevBenchmarkError("prompt digest does not match the expected value")
    completed = (
        _resume_successes(resume_report, provenance, planned)
        if resume_report is not None
        else []
    )
    new_requests = 0
    for batch in planned[len(completed) :]:
        if max_new_requests is not None and new_requests >= max_new_requests:
            break
        completed.append(_run_batch(batch, api_key, transport))
        new_requests += 1
        report = build_report(
            manifest_path, completed, len(planned), provenance=provenance
        )
        if checkpoint is not None:
            checkpoint(report)
        if completed[-1]["status"] == "error":
            return report
    report = build_report(manifest_path, completed, len(planned), provenance=provenance)
    if checkpoint is not None and not new_requests:
        checkpoint(report)
    return report
