#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any

from skylos.benchmarks.deep_audit_logic import (
    DEFAULT_BENCHMARK_MAX_TOKENS,
    DEFAULT_EXPECTED_PATH,
    DeepAuditLogicBenchmarkError,
    format_summary,
    run_manifest,
)
from skylos.llm.runtime import resolve_llm_runtime


MAX_PERSISTED_ERROR_CHARS = 512
_TRUNCATION_MARKER = "...[truncated]"
_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_SECRET_SUBSTITUTIONS = (
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    (
        re.compile(r"(?i)\b([a-z0-9_-]*api[_-]?key)\s*[:=]\s*[^\s,;]+"),
        r"\1 [REDACTED]",
    ),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"), "[REDACTED]"),
)


class BenchmarkReportOutputError(RuntimeError):
    """Raised when a benchmark report cannot be written safely."""


def _sanitize_error(value: Any) -> str:
    """Return bounded, single-line error text with common credentials redacted."""
    text = value if isinstance(value, str) else str(value)
    text = _ANSI_ESCAPE_RE.sub("", text)
    text = " ".join(text.split())
    for pattern, replacement in _SECRET_SUBSTITUTIONS:
        text = pattern.sub(replacement, text)
    if len(text) > MAX_PERSISTED_ERROR_CHARS:
        keep = MAX_PERSISTED_ERROR_CHARS - len(_TRUNCATION_MARKER)
        text = text[:keep] + _TRUNCATION_MARKER
    return text


def _sanitize_report_errors(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                _sanitize_error(item)
                if key == "error"
                else _sanitize_report_errors(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_report_errors(item) for item in value]
    return value


def _prepare_report(
    summary: dict[str, Any], *, include_model_prose: bool
) -> dict[str, Any]:
    """Copy a run summary into the intentionally persisted report shape."""
    report = copy.deepcopy(summary)
    if not include_model_prose:
        for case in report.get("cases", ()):
            if not isinstance(case, dict):
                continue
            actual = case.get("actual")
            if isinstance(actual, dict):
                # Finding targets and aggregate file/category lists retain the
                # benchmark proof while avoiding attacker/model-authored prose.
                actual.pop("finding_claims", None)
    report["report_content"] = (
        "model_prose_included" if include_model_prose else "projections_only"
    )
    return _sanitize_report_errors(report)


def _directory_open_flags() -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory is None:
        raise BenchmarkReportOutputError(
            "secure report output requires O_NOFOLLOW and O_DIRECTORY support"
        )
    return os.O_RDONLY | no_follow | directory


def _open_report_parent(path: Path) -> tuple[int, str]:
    """Open/create the output parent without traversing symbolic links."""
    if path.name in {"", ".", ".."}:
        raise BenchmarkReportOutputError("report output must name a file")

    parts = path.parts
    if path.is_absolute():
        current_fd = os.open(os.path.sep, _directory_open_flags())
        parent_parts = parts[1:-1]
    else:
        current_fd = os.open(".", _directory_open_flags())
        parent_parts = parts[:-1]

    try:
        for component in parent_parts:
            if component in {"", "."}:
                continue
            if component == "..":
                raise BenchmarkReportOutputError(
                    "report output may not traverse a parent directory"
                )
            try:
                next_fd = os.open(
                    component,
                    _directory_open_flags(),
                    dir_fd=current_fd,
                )
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current_fd)
                except FileExistsError:
                    # A concurrent creator won. The no-follow open below still
                    # verifies that the new entry is a real directory.
                    pass
                except OSError as exc:
                    raise BenchmarkReportOutputError(
                        f"could not create report parent component: {component!r}"
                    ) from exc
                try:
                    next_fd = os.open(
                        component,
                        _directory_open_flags(),
                        dir_fd=current_fd,
                    )
                except OSError as exc:
                    raise BenchmarkReportOutputError(
                        f"unsafe report parent component: {component!r}"
                    ) from exc
            except OSError as exc:
                raise BenchmarkReportOutputError(
                    f"unsafe report parent component: {component!r}"
                ) from exc
            os.close(current_fd)
            current_fd = next_fd
        return current_fd, path.name
    except Exception:
        os.close(current_fd)
        raise


def _write_private_atomic_json(path_value: str | os.PathLike[str], value: Any) -> None:
    """Atomically write JSON mode 0600 without following output symlinks."""
    path = Path(path_value)
    try:
        payload = (json.dumps(value, indent=2) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BenchmarkReportOutputError(
            "benchmark report is not JSON serializable"
        ) from exc

    parent_fd, filename = _open_report_parent(path)
    temp_name = f".{filename}.{secrets.token_hex(12)}.tmp"
    temp_fd: int | None = None
    temp_exists = False
    try:
        try:
            destination = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            destination = None
        if destination is not None:
            if stat.S_ISLNK(destination.st_mode):
                raise BenchmarkReportOutputError(
                    "refusing to replace a symbolic-link report output"
                )
            if not stat.S_ISREG(destination.st_mode):
                raise BenchmarkReportOutputError(
                    "refusing to replace a non-regular report output"
                )

        no_follow = getattr(os, "O_NOFOLLOW", 0)
        temp_fd = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
            0o600,
            dir_fd=parent_fd,
        )
        temp_exists = True
        os.fchmod(temp_fd, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(temp_fd, view)
            if written <= 0:
                raise BenchmarkReportOutputError("failed to write benchmark report")
            view = view[written:]
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = None

        os.replace(
            temp_name,
            filename,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temp_exists = False
        os.fsync(parent_fd)
    except BenchmarkReportOutputError:
        raise
    except OSError as exc:
        raise BenchmarkReportOutputError(
            f"could not safely write benchmark report: {_sanitize_error(exc)}"
        ) from exc
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        if temp_exists:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the live Skylos Deep Audit cross-file logic benchmark."
    )
    parser.add_argument("--expected", default=str(DEFAULT_EXPECTED_PATH))
    parser.add_argument("--model", default="gpt-4.1")
    parser.add_argument("--provider", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument(
        "--reasoning-effort",
        choices=("none", "minimal", "low", "medium", "high", "xhigh"),
        default=None,
        help="Reasoning effort sent to models that support it.",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=DEFAULT_BENCHMARK_MAX_TOKENS,
        help=(
            "Per-call completion-token cap. Reasoning models consume this budget "
            "for hidden reasoning and visible structured output."
        ),
    )
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--output", default=None)
    parser.add_argument(
        "--include-model-prose",
        action="store_true",
        help=(
            "Include model-authored finding prose in JSON output. This may contain "
            "sensitive or attacker-controlled source content."
        ),
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.max_tokens < 1:
        parser.error("--max-tokens must be a positive integer")

    provider, api_key, base_url, is_local = resolve_llm_runtime(
        model=args.model,
        provider_override=args.provider,
        base_url_override=args.base_url,
        console=None,
        allow_prompt=False,
    )
    if args.api_key:
        api_key = args.api_key
    if not api_key and not is_local:
        print(
            "No configured LLM credential. Run `skylos key`, pass --api-key, "
            "or select a local provider."
        )
        return 2

    try:
        summary = run_manifest(
            args.expected,
            model=args.model,
            api_key=api_key,
            provider=provider,
            base_url=base_url,
            reasoning_effort=args.reasoning_effort,
            max_tokens=args.max_tokens,
            selected_cases=set(args.case),
            require_model_usage=True,
            include_model_prose=args.include_model_prose,
        )
    except DeepAuditLogicBenchmarkError as exc:
        print(json.dumps({"status": "error", "error": _sanitize_error(exc)}, indent=2))
        return 2

    report = _prepare_report(
        summary,
        include_model_prose=args.include_model_prose,
    )
    if args.output:
        try:
            _write_private_atomic_json(args.output, report)
        except BenchmarkReportOutputError as exc:
            print(
                json.dumps(
                    {"status": "error", "error": _sanitize_error(exc)},
                    indent=2,
                )
            )
            return 2
    print(json.dumps(report, indent=2) if args.json else format_summary(report))
    return 0 if summary["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
