#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.benchmarks.jev_dead_code import (  # noqa: E402
    JevBenchmarkError,
    build_plan,
    format_plan,
    format_report,
    run_jev_manifest,
)
from skylos.core.safe_cache_io import (  # noqa: E402
    _open_output_parent,
    read_text_no_symlink,
)


DEFAULT_MANIFEST = REPO_ROOT / "benchmarks" / "dead_code" / "manifest.json"
DEFAULT_OUTPUT = REPO_ROOT / "jev-dead-code-results.json"
MAX_REPORT_BYTES = 16_000_000


def _write_report(path: Path, report: dict) -> None:
    content = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(content) > MAX_REPORT_BYTES:
        raise JevBenchmarkError("Jev report exceeds the checkpoint size limit")
    parent_fd = _open_output_parent(path)
    if parent_fd is None:
        raise JevBenchmarkError(
            f"cannot safely write {path}; use an existing, non-symlink parent directory"
        )
    temp_name = f".jev-checkpoint-{secrets.token_hex(12)}.tmp"
    temp_created = False
    try:
        try:
            existing = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1
        ):
            raise JevBenchmarkError(f"cannot safely replace non-regular report: {path}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        temp_fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
        temp_created = True
        with os.fdopen(temp_fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temp_name,
            path.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temp_created = False
        os.fsync(parent_fd)
    except (NotImplementedError, TypeError) as exc:
        raise JevBenchmarkError(
            "atomic Jev checkpoints require directory-descriptor filesystem support"
        ) from exc
    finally:
        if temp_created:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Blindly score pinned Jev decisions against Skylos dead-code ground truth. "
            "Without --live, this only prints the request plan."
        )
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Send fixture source to the official TypeSafe API and incur API usage.",
    )
    parser.add_argument(
        "--manifest",
        default=str(DEFAULT_MANIFEST),
        help=(
            "Checked-in or frozen skylos-golden-benchmark/v1 ground truth "
            "(default: main benchmark manifest)."
        ),
    )
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        help="Run one case id. Repeat to select more than one case.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Checkpoint/result JSON path for a live run (default: repo root).",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume a matching incomplete report instead of repeating paid requests.",
    )
    parser.add_argument(
        "--max-requests",
        type=int,
        default=None,
        help="Maximum new paid requests in this invocation (positive integer).",
    )
    parser.add_argument(
        "--expect-prompt-digest",
        help="Fail before a live request unless the prompt matches this frozen SHA-256 digest.",
    )
    parser.add_argument(
        "--expect-manifest-digest",
        help="Fail before a live request unless the manifest matches this frozen SHA-256 digest.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the plan or final report as JSON.",
    )
    return parser


def _run(args: argparse.Namespace) -> int:
    selected = set(args.case)
    if args.resume and not args.live:
        raise JevBenchmarkError("--resume requires --live")
    if args.max_requests is not None and args.max_requests < 1:
        raise JevBenchmarkError("--max-requests must be a positive integer")
    if args.max_requests is not None and not args.live:
        raise JevBenchmarkError("--max-requests requires --live")
    if (args.expect_prompt_digest or args.expect_manifest_digest) and not args.live:
        raise JevBenchmarkError("--expect-*-digest requires --live")
    if not args.live:
        plan = build_plan(args.manifest, selected)
        print(json.dumps(plan, indent=2) if args.json else format_plan(plan))
        if not args.json:
            print(
                "\nLive run: set TYPESAFE_API_KEY in the environment, then run "
                "this command with --live."
            )
        return 0

    output = Path(os.path.abspath(Path(args.output).expanduser()))
    if not output.parent.is_dir():
        raise JevBenchmarkError(
            f"output parent must be an existing directory: {output.parent}"
        )
    resume_report = None
    if args.resume:
        raw = read_text_no_symlink(output, max_bytes=MAX_REPORT_BYTES)
        if raw is None:
            raise JevBenchmarkError("cannot safely read the existing resume report")
        try:
            resume_report = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise JevBenchmarkError("resume report is not valid JSON") from exc
        if not isinstance(resume_report, dict):
            raise JevBenchmarkError("resume report must be a JSON object")
        if resume_report.get("status") != "incomplete":
            raise JevBenchmarkError("--resume requires an incomplete report")
    elif output.exists() or output.is_symlink():
        raise JevBenchmarkError(
            f"output already exists: {output}; use --resume with a matching "
            "incomplete report or choose a new --output"
        )

    api_key = os.environ.get("TYPESAFE_API_KEY", "")
    if not api_key.strip():
        raise JevBenchmarkError(
            "TYPESAFE_API_KEY is missing. Set it in the environment; do not "
            "pass it as a command-line argument or commit it."
        )

    def checkpoint(report: dict) -> None:
        _write_report(output, report)

    report = run_jev_manifest(
        args.manifest,
        api_key=api_key,
        selected_cases=selected,
        checkpoint=checkpoint,
        resume_report=resume_report,
        max_new_requests=args.max_requests,
        expected_prompt_digest=args.expect_prompt_digest,
        expected_manifest_digest=args.expect_manifest_digest,
    )
    print(json.dumps(report, indent=2) if args.json else format_report(report))
    if not args.json:
        print(f"Full result: {output}")
    return 0 if report["status"] == "complete" else 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _run(args)
    except (JevBenchmarkError, OSError, ValueError) as exc:
        print(f"Jev benchmark error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
