"""Post-edit type check: the project's own checker on the file the agent changed.

Runs only when the base commit's ``[tool.skylos.done.checks]`` sets ``type_check`` to
``block`` or ``advise``. The check gets a hard budget; one that cannot finish
leaves a visible non-blocking note and runs again in full at stop, where Done
repeats it. Nothing here guesses: an unavailable or failing checker is a note,
never a pass.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

POST_EDIT_TYPE_CHECK_SECONDS = 60
SLOW_TYPE_CHECK_SECONDS = 15
DEFERRED_KEY = "type_check_deferred"
RULE_ID = "type-check"
ORIGINS = ("introduced", "preexisting", "unclassified")
NON_ERROR_SEVERITIES = {"warning", "info", "information", "note"}

Findings = tuple[list[dict[str, Any]], list[dict[str, Any]]]


def post_edit_type_check(
    root: Path,
    session_id: str,
    edited: list[Path],
    record: dict[str, Any],
    type_check: Callable[..., dict[str, Any]] | None,
) -> Findings:
    """Return ``(blocking, notes)`` in the hook's finding shape; both empty when off."""
    from skylos.commands.hook_cmd import (
        _load_session_state,
        _mutate_session,
        _state_root,
    )
    from skylos.done.base import DoneError
    from skylos.done.session import open_session_comparison

    if not edited:
        return [], []
    state_root = _state_root(root)
    session = _load_session_state(state_root)["sessions"].get(session_id)
    if isinstance(session, dict) and session.get(DEFERRED_KEY):
        record["type_check"] = {"status": "deferred"}
        return [], []
    try:
        comparison = open_session_comparison(root, session_id)
    except DoneError as exc:
        record["type_check"] = {"status": "unavailable", "error": type(exc).__name__}
        return [], []
    blocking, notes = _run(comparison, edited, edited[0], record, type_check)
    seconds = (record.get("type_check") or {}).get("seconds")
    if not isinstance(seconds, (int, float)) or seconds < SLOW_TYPE_CHECK_SECONDS:
        return blocking, notes

    def defer(state):
        state[DEFERRED_KEY] = True

    _mutate_session(state_root, session_id, defer)
    unfinished = [note for note in notes if note.get("file_level")]
    if unfinished:
        unfinished[0]["message"] = unfinished[0]["message"].replace(
            "it runs again when you stop", "for this session it runs when you stop"
        )
        return blocking, notes
    text = f"Type check took {round(seconds)} s, so for this session it runs when you stop."
    return blocking, [*notes, _note(edited[0], text)]


def recheck_type_check(
    root: Path,
    session_id: str | None,
    files: list[Path],
    record: dict[str, Any],
    type_check: Callable[..., dict[str, Any]] | None,
    *,
    whole_project: bool = False,
) -> Findings:
    """The same policy for ``hook recheck``, against the agent session when there is one."""
    from skylos.done.base import DoneError, open_comparison
    from skylos.done.session import open_session_comparison

    comparison = None
    if session_id:
        try:
            comparison = open_session_comparison(root, session_id)
        except DoneError:
            comparison = None
    if comparison is None:
        try:
            comparison = open_comparison(root)
        except DoneError as exc:
            record["type_check"] = {
                "status": "unavailable",
                "error": type(exc).__name__,
            }
            return [], []
    targets: list[Path] | None = files
    if whole_project:
        targets = None
    elif not files:
        return [], []
    fallback = root
    if files:
        fallback = files[0]
    return _run(comparison, targets, fallback, record, type_check)


def _run(
    comparison: Any,
    targets: list[Path] | None,
    fallback: Path,
    record: dict[str, Any],
    type_check: Callable[..., dict[str, Any]] | None,
) -> Findings:
    from skylos.done.base import DoneError
    from skylos.done.config import base_config_text, parse_done_config

    try:
        config = parse_done_config(
            base_config_text(comparison, sha=comparison.config_sha)
        )
    except DoneError as exc:
        record["type_check"] = {"status": "unavailable", "error": type(exc).__name__}
        return [], []
    mode = config.mode("type_check")
    if mode not in {"block", "advise"}:
        return [], []

    budget = min(config.type_check_timeout_seconds, POST_EDIT_TYPE_CHECK_SECONDS)
    runner = type_check
    if runner is None:
        from skylos.typecheck import run_type_check

        runner = run_type_check
    target_files = None
    if targets is not None:
        target_files = [str(path) for path in targets]
    try:
        report = runner(
            comparison.root,
            checker=config.type_checker,
            timeout_seconds=budget,
            comparison=comparison,
            target_files=target_files,
            baseline_cache=True,
        )
    except Exception as exc:
        record["type_check"] = {
            "status": "error",
            "error": type(exc).__name__,
            "mode": mode,
        }
        text = (
            f"Type check could not run ({type(exc).__name__}); "
            "it runs again when you stop."
        )
        return [], [_note(fallback, text)]
    return _classify(report, comparison.root, fallback, mode, budget, record)


def _classify(
    report: Any,
    root: Path,
    fallback: Path,
    mode: str,
    budget: int,
    record: dict[str, Any],
) -> Findings:
    diagnostics = None
    comparison_status = "incomplete"
    if isinstance(report, dict):
        diagnostics = report.get("diagnostics")
        comparison = report.get("comparison")
        if isinstance(comparison, dict):
            comparison_status = str(comparison.get("status") or "incomplete")
    complete = (
        isinstance(diagnostics, list)
        and isinstance(report, dict)
        and report.get("complete") is True
        and comparison_status == "complete"
    )
    summary: dict[str, Any] = {
        "mode": mode,
        "budget_seconds": budget,
        "status": "complete" if complete else "incomplete",
        "introduced": 0,
        "preexisting": 0,
        "unclassified": 0,
    }
    if isinstance(report, dict):
        summary["checker"] = report.get("checker")
        summary["seconds"] = report.get("seconds")
    record["type_check"] = summary
    if not complete:
        reason = f"the checker did not finish within {budget} s"
        if isinstance(report, dict) and report.get("summary"):
            reason = str(report["summary"])
        text = f"Type check incomplete ({reason}); it runs again when you stop."
        return [], [_note(fallback, text)]

    blocking: list[dict[str, Any]] = []
    notes: list[dict[str, Any]] = []
    for diagnostic in diagnostics:
        if not isinstance(diagnostic, dict):
            continue
        origin = str(diagnostic.get("origin") or "")
        if origin not in ORIGINS:
            origin = "unclassified"
        severity = str(diagnostic.get("severity") or "error").lower()
        severity = {"warn": "warning", "hint": "info"}.get(severity, severity)
        advisory = (
            severity == "warning" and diagnostic.get("source") == "suppression_guard"
        )
        if severity in NON_ERROR_SEVERITIES and not advisory:
            continue
        if not advisory:
            summary[origin] += 1
        path = _absolute(diagnostic.get("file"), root, fallback)
        code = str(diagnostic.get("code") or "")
        rule_id = RULE_ID
        if code:
            rule_id = f"{RULE_ID}:{code}"
        blocks = mode == "block" and origin != "preexisting" and not advisory
        message = str(diagnostic.get("message") or "Type checker diagnostic")
        if diagnostic.get("scope") == "dependency_impact":
            message += " (in a file this edit affects)"
        finding = {
            "path": str(path),
            "line": int(diagnostic.get("line") or 0),
            "rule_id": rule_id,
            "severity": "HIGH" if blocks else "MEDIUM",
            "message": f"[{origin}] {message}",
            "fix": "",
            "category": "type_check",
            "vibe": "",
            "metadata": {
                "origin": origin,
                "scope": diagnostic.get("scope"),
                "source": diagnostic.get("source"),
            },
            "blocking": blocks,
            "why": "type-check",
        }
        if blocks:
            blocking.append(finding)
        else:
            notes.append(finding)
    return blocking, notes


def _note(path: Path, text: str) -> dict[str, Any]:
    return {
        "path": str(path),
        "line": 0,
        "file_level": True,
        "rule_id": RULE_ID,
        "severity": "LOW",
        "message": text,
        "fix": "",
        "category": "type_check",
        "vibe": "",
        "metadata": {},
        "blocking": False,
        "why": "type-check",
    }


def _absolute(value: Any, root: Path, fallback: Path) -> Path:
    if not isinstance(value, str) or not value:
        return fallback
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return path
