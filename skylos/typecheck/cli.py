"""CLI options and plain reporting for explicitly requested type checking."""

from __future__ import annotations

import argparse
import functools
import inspect
import math
import unicodedata

DEFAULT_TIMEOUT_SECONDS = 120
MAX_TIMEOUT_SECONDS = 3600


def _timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("type-check timeout must be a number") from exc
    if not math.isfinite(timeout) or not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise argparse.ArgumentTypeError(
            f"type-check timeout must be greater than 0 and at most {MAX_TIMEOUT_SECONDS} seconds"
        )
    return timeout


class _TimeoutAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
        namespace._type_check_timeout_set = True


def add_type_check_args(parser) -> None:
    parser.add_argument(
        "--type-check",
        action="store_true",
        help="Run the project's installed type checker (executes its configured plugins)",
    )
    parser.add_argument(
        "--type-checker",
        choices=("auto", "mypy", "pyright", "pyrefly", "tsc"),
        default=None,
        help="Choose the installed checker for --type-check (default: configured checker)",
    )
    parser.add_argument(
        "--type-check-timeout",
        type=_timeout,
        action=_TimeoutAction,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Maximum seconds for type checking, including baseline comparison (default: 120)",
    )


def validate_type_check_args(parser, args) -> None:
    enabled = getattr(args, "type_check", False)
    configured = getattr(args, "type_checker", None) is not None
    timed = getattr(args, "_type_check_timeout_set", False) or (
        getattr(args, "type_check_timeout", DEFAULT_TIMEOUT_SECONDS)
        != DEFAULT_TIMEOUT_SECONDS
    )
    if not enabled and (configured or timed):
        parser.error("--type-checker and --type-check-timeout require --type-check")
    if enabled and getattr(args, "stdin", False):
        parser.error("--type-check cannot be used with --stdin")


def attach_type_check(
    payload: dict, args, *, path, base_ref=None, target_files=None
) -> dict | None:
    if not getattr(args, "type_check", False):
        return None
    from skylos.typecheck import run_type_check

    report = run_type_check(
        path,
        checker=getattr(args, "type_checker", None) or "auto",
        base_ref=base_ref,
        timeout_seconds=getattr(args, "type_check_timeout", DEFAULT_TIMEOUT_SECONDS),
        target_files=target_files,
    )
    payload["type_check"] = report
    args._type_check_exit = {"pass": 0, "fail": 1}.get(report.get("status"), 2)
    return report


def _plain(value, limit=4000) -> str:
    text = str(value or "")[:limit]
    return " ".join(
        "".join(c for c in text if not unicodedata.category(c).startswith("C")).split()
    )


def render_type_check(report: dict) -> str:
    """Return plain text: callers should print it without markup parsing."""
    checker = _plain(report.get("checker") or "configured checker")
    status = _plain(report.get("status") or "incomplete")
    lines = [f"Type check ({checker}): {status}"]
    if report.get("summary"):
        lines.append(_plain(report["summary"]))
    comparison = report.get("comparison")
    if isinstance(comparison, dict):
        state = _plain(comparison.get("status") or "not_requested")
        lines.append(f"Type-check comparison: {state}")
        if comparison.get("reason"):
            lines.append(_plain(comparison["reason"]))
    diagnostics = report.get("diagnostics") or []
    guard = report.get("escape_guard")
    if isinstance(guard, dict):
        guard_status = _plain(guard.get("status") or "not_assessed")
        if guard_status == "complete":
            lines.append(f"New compiler escape hatches: {guard.get('added', 0)}")
        else:
            lines.append(
                f"Compiler escape guard: {guard_status} (requires a comparable baseline)"
            )
    if report.get("out_of_scope_count", 0):
        lines.append(
            f"Project errors: {report.get('project_error_count', 0)}. "
            f"Diagnostics outside selected files: {report['out_of_scope_count']}."
        )
    for diagnostic in diagnostics[:50]:
        if not isinstance(diagnostic, dict):
            continue
        location = ":".join(
            _plain(diagnostic.get(key), 500) for key in ("file", "line", "column")
        )
        severity = _plain(diagnostic.get("severity") or "error")
        code = _plain(diagnostic.get("code"), 200)
        origin = _plain(diagnostic.get("origin") or "unclassified")
        if diagnostic.get("scope") == "dependency_impact":
            origin += "; dependency impact"
        message = _plain(diagnostic.get("message"))
        lines.append(f"{location}: {severity} {code} ({origin}): {message}")
    if len(diagnostics) > 50:
        lines.append(f"{len(diagnostics) - 50} more diagnostic(s) in the JSON report")
    return "\n".join(lines)


def _merged_exit(args, original: int) -> int:
    if not getattr(args, "type_check", False):
        return original
    requested = getattr(args, "_type_check_exit", 0)
    if requested not in {0, 1, 2}:
        requested = 2
    if requested == 1 and getattr(args, "force", False):
        requested = 0
    return max(original, requested)


def scan_type_check_exit(function):
    """Combine the scan verdict with a requested checker, preserving setup errors."""
    signature = inspect.signature(function)

    @functools.wraps(function)
    def wrapped(*call_args, **kwargs):
        args = signature.bind_partial(*call_args, **kwargs).arguments.get("args")
        try:
            result = function(*call_args, **kwargs)
        except SystemExit as exc:
            code = 0 if exc.code is None else exc.code
            if type(code) is not int or code not in {0, 1}:
                raise
            merged = _merged_exit(args, code)
            if merged == code:
                raise
            raise SystemExit(merged) from None
        merged = _merged_exit(args, 0)
        if merged:
            raise SystemExit(merged)
        return result

    return wrapped
