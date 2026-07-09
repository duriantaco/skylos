from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from skylos.constants import parse_exclude_folders
from skylos.verify_change import verify_change_path, verify_change_stdin_payload


def run_verify_command(
    argv: Sequence[str],
    *,
    verify_change_path_func=verify_change_path,
    verify_change_stdin_payload_func=verify_change_stdin_payload,
    parse_exclude_folders_func=parse_exclude_folders,
) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv))
    exclude_folders = _exclude_folders(args, parse_exclude_folders_func)

    try:
        payload = _run_from_args(
            args,
            parser,
            exclude_folders,
            verify_change_path_func,
            verify_change_stdin_payload_func,
        )
    except ValueError as exc:
        parser.error(str(exc))

    _write_payload(payload, args.output)
    return _exit_code(payload, no_fail=args.no_fail)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos verify",
        description="Verify changed code for AI-code defects.",
    )
    _add_target_args(parser)
    _add_scope_args(parser)
    _add_runtime_args(parser)
    _add_output_args(parser)
    return parser


def _add_target_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="File or project path to verify.",
    )
    parser.add_argument(
        "--file",
        default=None,
        help="File to verify when path is a project root.",
    )


def _add_scope_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read a JSON manifest from stdin: {\"file\", \"code\", \"range\"?}.",
    )
    parser.add_argument(
        "--range",
        dest="line_range",
        default=None,
        metavar="L1:L2",
        help="Only return findings overlapping this line range.",
    )
    parser.add_argument(
        "--project-context",
        action="store_true",
        help="When --file is set, scan the project path and filter to that file.",
    )


def _add_runtime_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--contract",
        dest="contract_path",
        default=None,
        help=(
            "AI hallucination contract to apply during verification. "
            "Defaults to auto-discovering .skylos/ai-contract.yml."
        ),
    )
    parser.add_argument(
        "--no-contract",
        dest="contract_enabled",
        action="store_false",
        default=True,
        help="Do not auto-discover or apply an AI hallucination contract.",
    )
    parser.add_argument(
        "--dependency-hallucinations",
        dest="dependency_hallucinations",
        action="store_true",
        default=None,
        help="Include dependency hallucination checks (default: enabled for path targets).",
    )
    parser.add_argument(
        "--no-dependency-hallucinations",
        dest="dependency_hallucinations",
        action="store_false",
        default=None,
        help="Skip dependency hallucination checks and their package registry lookups.",
    )
    parser.add_argument(
        "--exclude-folder",
        action="append",
        dest="exclude_folders",
        help="Exclude a folder from analysis. Can be used multiple times.",
    )
    parser.add_argument(
        "--confidence",
        "-c",
        type=int,
        default=60,
        help="Analyzer confidence threshold. Default: 60.",
    )


def _add_output_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Exit 0 even when AI-code findings are returned.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Write JSON output to a file.",
    )


def _run_from_args(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    exclude_folders: list[str],
    verify_change_path_func,
    verify_change_stdin_payload_func,
) -> dict[str, Any]:
    _validate_contract_args(args, parser)
    if args.stdin:
        manifest = _read_stdin_manifest(parser)
        _apply_stdin_overrides(args, manifest)
        kwargs = {
            "confidence": args.confidence,
            "exclude_folders": exclude_folders,
        }
        return verify_change_stdin_payload_func(manifest, **kwargs)

    kwargs = {
        "file": args.file,
        "line_range": args.line_range,
        "confidence": args.confidence,
        "exclude_folders": exclude_folders,
        "project_context": args.project_context,
    }
    if args.dependency_hallucinations is not None:
        kwargs["include_dependency_hallucinations"] = args.dependency_hallucinations
    if args.contract_path is not None:
        kwargs["contract_path"] = args.contract_path
    if not args.contract_enabled:
        kwargs["contract_enabled"] = False
    return verify_change_path_func(args.path, **kwargs)


def _apply_stdin_overrides(args: argparse.Namespace, manifest: dict[str, Any]) -> None:
    _set_default(manifest, "path", args.path)
    if args.file is not None:
        _set_default(manifest, "file", args.file)
    if args.line_range is not None:
        _set_default(manifest, "range", args.line_range)
    if args.dependency_hallucinations:
        _set_default(manifest, "include_dependency_hallucinations", True)
    if args.contract_path is not None:
        _set_default(manifest, "contract_path", args.contract_path)
    if not args.contract_enabled:
        _set_default(manifest, "contract_enabled", False)


def _validate_contract_args(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
) -> None:
    if args.contract_enabled:
        return
    if args.contract_path is None:
        return
    parser.error("--contract cannot be used with --no-contract")


def _set_default(payload: dict[str, Any], key: str, value: Any) -> None:
    if key in payload:
        return
    payload[key] = value


def _exclude_folders(args: argparse.Namespace, parse_exclude_folders_func) -> list[str]:
    exclude_folders = list(parse_exclude_folders_func(use_defaults=True))
    if args.exclude_folders is None:
        return exclude_folders

    for folder in args.exclude_folders:
        exclude_folders.append(folder)
    return exclude_folders


def _write_payload(payload: dict[str, Any], output_path: str | None) -> None:
    output = json.dumps(payload, indent=2)
    if output_path:
        Path(output_path).write_text(  # skylos: ignore[SKY-D215] user-selected CLI output path
            output + "\n",
            encoding="utf-8",
        )
        return

    print(output)


def _exit_code(payload: dict[str, Any], *, no_fail: bool) -> int:
    if no_fail:
        return 0
    if payload.get("status") == "fail":
        return 1
    return 0


def _read_stdin_manifest(parser: argparse.ArgumentParser) -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        parser.error("--stdin requires a JSON manifest on stdin")
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        parser.error(f"--stdin manifest must be valid JSON: {exc.msg}")
    if not isinstance(manifest, dict):
        parser.error("--stdin manifest must be a JSON object")
    return manifest
