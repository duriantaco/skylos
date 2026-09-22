"""Conservative Jev triage for Skylos dead-code verification candidates.

Only a confident answer over a complete, bounded first-party project snapshot
can be acted on. The caller determines whether an answer routes to the general
LLM or serves as a final, non-fix-eligible judgment.
"""

from __future__ import annotations

import json
import math
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from skylos.benchmarks._jev_dead_code_dataset import (
    FIXTURE_SCOPE,
    JEV_MODEL,
    MAX_STATE_BYTES,
    JevBenchmarkError,
    _question_payload,
    _read_case_files,
)
from skylos.benchmarks.jev_dead_code import _validate_answer, request_jev


Transport = Callable[[dict[str, Any], str], dict[str, Any]]
MIN_AGREEMENT_CONFIDENCE = 0.8
MIN_JUDGE_CONFIDENCE = 0.9
MAX_QUESTIONS = 50


def _result(
    status: str,
    reason: str,
    *,
    choice: str | None = None,
    confidence: float | None = None,
    choice_probability: float | None = None,
) -> dict[str, Any]:
    result = {
        "status": status,
        "choice": choice,
        "confidence": confidence,
        "reason": reason,
    }
    if choice_probability is not None:
        result["choice_probability"] = choice_probability
    return result


def _target(
    finding: dict, root: Path, source_files: dict[str, str]
) -> dict[str, Any] | None:
    name = finding.get("simple_name") or finding.get("name")
    if isinstance(name, str):
        # Skylos can report methods as ``Class.method`` in ``name``.
        name = name.rsplit(".", 1)[-1]
    kind = finding.get("type")
    raw_file = finding.get("file")
    line = finding.get("line")
    if (
        not isinstance(name, str)
        or not name
        or not isinstance(kind, str)
        or not kind
        or not isinstance(raw_file, str)
        or not raw_file
        or isinstance(line, bool)
        or (line is not None and (not isinstance(line, int) or line < 1))
    ):
        return None

    path = Path(raw_file)
    if not path.is_absolute():
        path = root / path
    try:
        relative = path.relative_to(root)
    except ValueError:
        return None
    relative_file = relative.as_posix()
    source = source_files.get(relative_file)
    if source is None:
        return None
    source_lines = source.splitlines()
    if line is not None and (
        line > len(source_lines) or name not in source_lines[line - 1]
    ):
        # A stale or ambiguous static location is not safe evidence for a
        # model-only agreement. Leave it to the normal verifier instead.
        return None
    if name not in source:
        return None
    return {"kind": kind, "file": relative_file, "symbol": name, "line": line}


def triage_findings(
    project_root: Path,
    findings: list[dict],
    *,
    transport: Transport | None = None,
    min_confidence: float = MIN_AGREEMENT_CONFIDENCE,
) -> list[dict[str, Any]]:
    """Return one fail-open routing result per Skylos candidate.

    ``agreed`` means confidently unreferenced; ``disagreed`` means confidently
    retained. The caller decides how to handle each status. Confidence is the
    minimum of Jev's self-reported confidence and its chosen-answer probability.
    A request is only made when the *entire* small project can be safely read;
    snippets or a subset of files could falsely imply absence of references.
    No target code is executed, and there are no automatic request retries.
    """
    if not findings:
        return []
    if (
        isinstance(min_confidence, bool)
        or not isinstance(min_confidence, (int, float))
        or not math.isfinite(min_confidence)
        or not 0.0 <= min_confidence <= 1.0
    ):
        raise ValueError("min_confidence must be a finite probability")
    fallback = [_result("unavailable", "not_requested") for _ in findings]
    api_key = os.environ.get("TYPESAFE_API_KEY", "").strip()
    if not api_key:
        return [_result("unavailable", "missing_api_key") for _ in findings]
    if len(findings) > MAX_QUESTIONS:
        return [_result("unavailable", "question_limit") for _ in findings]

    root = Path(project_root).expanduser().absolute()
    try:
        # The caller-selected root is a trust boundary: never follow a root
        # symlink into an unexpected tree, nor silently use a partial scope.
        if (
            any(part.is_symlink() for part in (root, *root.parents))
            or not root.is_dir()
        ):
            return [
                _result("unavailable", "unsafe_or_incomplete_project") for _ in findings
            ]
        root = root.resolve(strict=True)
        files = _read_case_files(root)
    except (JevBenchmarkError, OSError, RuntimeError, ValueError):
        return [
            _result("unavailable", "unsafe_or_incomplete_project") for _ in findings
        ]

    source_files = {item["path"]: item["content"] for item in files}
    questions: dict[str, dict[str, Any]] = {}
    question_indexes: dict[str, int] = {}
    for index, finding in enumerate(findings):
        target = (
            _target(finding, root, source_files) if isinstance(finding, dict) else None
        )
        if target is None:
            fallback[index] = _result("unavailable", "invalid_candidate")
            continue
        question_id = f"q{index:04d}"
        questions[question_id] = _question_payload(
            target["kind"], target["file"], target["symbol"], target["line"]
        )
        question_indexes[question_id] = index
    if not questions:
        return fallback

    state = {"repository_files": files, "fixture_scope": FIXTURE_SCOPE}
    state_bytes = len(
        json.dumps(
            state, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    )
    if state_bytes > MAX_STATE_BYTES:
        return [
            _result("unavailable", "unsafe_or_incomplete_project") for _ in findings
        ]
    payload = {"state": state, "model": JEV_MODEL, "questions": questions}
    try:
        response = (transport or request_jev)(payload, api_key)
    except Exception:  # Any transport failure must retain broad-LLM coverage.
        for index in question_indexes.values():
            fallback[index] = _result("unavailable", "request_failed")
        return fallback

    try:
        if not isinstance(response, dict) or response.get("model") != JEV_MODEL:
            raise JevBenchmarkError("model mismatch")
        answers = response.get("answers")
        if not isinstance(answers, dict) or set(answers) != set(questions):
            raise JevBenchmarkError("answer mismatch")
        validated = {key: _validate_answer(answers[key], key) for key in questions}
    except (JevBenchmarkError, TypeError, ValueError):
        for index in question_indexes.values():
            fallback[index] = _result("unavailable", "invalid_response")
        return fallback

    for question_id, index in question_indexes.items():
        answer = validated[question_id]
        choice = answer["choice"]
        confidence = answer["confidence"]
        probability = answer["probabilities"][choice]
        if choice == "insufficient_evidence":
            status, reason = "uncertain", "insufficient_evidence"
        elif min(confidence, probability) < min_confidence:
            status, reason = "uncertain", "low_confidence"
        elif choice == "unreferenced":
            status, reason = "agreed", "unreferenced"
        else:
            status, reason = "disagreed", "retained"
        fallback[index] = _result(
            status,
            reason,
            choice=choice,
            confidence=confidence,
            choice_probability=probability,
        )
    return fallback
