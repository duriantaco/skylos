"""Offline container-report import; never executes a scanner or image."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.integrations.trivy_image import load_trivy_image_report


_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_PROTECTED_NAMES = {"package.json", "package-lock.json", "npm-shrinkwrap.json"}


def add_trivy_image_parser(subparsers) -> None:
    parser = subparsers.add_parser(
        "trivy",
        help="Import a Trivy container-image JSON report offline",
        description=(
            "Import a Trivy SchemaVersion 2 container-image vulnerability report. "
            "Does not run Trivy, pull images, access the network, or upload results."
        ),
    )
    parser.add_argument("-i", "--input", required=True, dest="input_file")
    parser.add_argument(
        "-o", "--output", default="-", help="JSON report file; default: stdout"
    )
    parser.add_argument("--sarif", help="Also write an image-aware SARIF report")
    parser.add_argument(
        "--expect-image",
        help="Exact repository@sha256:digest expected in Trivy Metadata.RepoDigests",
    )
    parser.add_argument(
        "--expect-platform", help="Expected os/architecture[/variant], e.g. linux/amd64"
    )
    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        help=(
            "Fail for findings at or above this severity in the supplied report; "
            "requires --expect-image. This does not attest scan completeness."
        ),
    )


def _error(document: dict, code: str, message: str) -> None:
    document["receipt"]["import_complete"] = False
    document["receipt"]["errors"].append({"code": code, "message": message})


def _gate(document: dict, threshold: str | None, expected_image: str | None) -> int:
    receipt = document["receipt"]
    gate = {
        "scope": "supplied_report",
        "threshold": threshold.upper() if threshold else None,
        "status": "not_requested",
        "blocking_count": 0,
    }
    document["gate"] = gate
    if threshold:
        if not expected_image:
            _error(
                document,
                "expected_image_required",
                "A report gate requires --expect-image.",
            )
        elif not receipt["identity_verified"]:
            _error(
                document,
                "image_not_verified",
                "The expected image identity was not verified.",
            )
        if not receipt["supported_result_count"]:
            _error(
                document,
                "no_supported_results",
                "A report gate requires a supported package result.",
            )
    if not receipt["import_complete"]:
        gate["status"] = "incomplete"
        return 2
    if not threshold:
        return 0
    gate["blocking_count"] = sum(
        _SEVERITY_RANK.get(finding["severity"], 0) >= _SEVERITY_RANK[threshold.upper()]
        for finding in document["container_vulnerabilities"]
    )
    gate["status"] = "failed" if gate["blocking_count"] else "passed"
    return 1 if gate["blocking_count"] else 0


def _same_path(left: Path, right: Path) -> bool:
    if left.resolve() == right.resolve():
        return True
    try:
        return left.samefile(right)
    except FileNotFoundError:
        return False


def _safe_output_selection(args: argparse.Namespace) -> bool:
    """Check collisions before any writes; the writer rejects linked paths."""
    try:
        input_file = getattr(args, "input_file", None)
        input_path = (
            Path(os.path.abspath(Path(input_file).expanduser()))
            if input_file is not None
            else None
        )
        selected: list[Path] = []
        outputs = []
        if args.output != "-":
            outputs.append((args.output, {".json"}))
        if args.sarif:
            outputs.append((args.sarif, {".json", ".sarif"}))
        for filename, suffixes in outputs:
            path = Path(os.path.abspath(Path(filename).expanduser()))
            if (
                path.suffix.lower() not in suffixes
                or path.name.casefold() in _PROTECTED_NAMES
                or any(
                    part.casefold() in {".git", ".hg", ".svn"} for part in path.parts
                )
                or (input_path is not None and _same_path(path, input_path))
                or any(_same_path(path, other) for other in selected)
            ):
                return False
            for parent in path.parents:
                if parent.is_symlink() or not parent.is_dir():
                    return False
            if path.is_symlink():
                return False
            try:
                existing = path.lstat()
            except FileNotFoundError:
                pass
            else:
                if not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1:
                    return False
            selected.append(path)
    except (OSError, ValueError, RuntimeError):
        return False
    return True


def _json(document: dict) -> str:
    return json.dumps(document, indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def render_trivy_image_document(
    args: argparse.Namespace,
    document: dict,
    *,
    gate_scope: str = "supplied_report",
) -> int:
    """Apply the same report gate and output path to imports and direct scans."""
    output_safe = _safe_output_selection(args)
    if not output_safe:
        _error(
            document,
            "unsafe_output",
            "Output must be a separate report file, not an input, protected file, or another output.",
        )
    exit_code = _gate(document, args.fail_on, args.expect_image)
    document["gate"]["scope"] = gate_scope

    if args.sarif and output_safe:
        from skylos.reporting.container_sarif import container_sarif

        if not write_text_no_symlink(args.sarif, _json(container_sarif(document))):
            _error(
                document,
                "sarif_write_failed",
                "Could not safely write the SARIF output.",
            )
            document["gate"]["status"] = "incomplete"
            exit_code = 2

    text = _json(document)
    if args.output == "-" or not output_safe:
        sys.stdout.write(text)
    elif not write_text_no_symlink(args.output, text):
        _error(document, "json_write_failed", "Could not safely write the JSON output.")
        document["gate"]["status"] = "incomplete"
        exit_code = 2
        if args.sarif:
            # Keep an already-written SARIF receipt consistent with a later
            # JSON-output failure. The process exit remains 2 if this also fails.
            write_text_no_symlink(args.sarif, _json(container_sarif(document)))
        # Retain usable findings when the requested output cannot be written.
        sys.stdout.write(_json(document))

    if exit_code == 2:
        operation = (
            "Image scan" if gate_scope == "direct_image_scan" else "Image report import"
        )
        print(
            f"{operation} incomplete; see receipt.errors in the JSON report.",
            file=sys.stderr,
        )
    elif exit_code == 1:
        print(
            "Image report exceeded the requested severity threshold.", file=sys.stderr
        )
    return exit_code


def run_trivy_image_import(args: argparse.Namespace) -> int:
    document = load_trivy_image_report(
        args.input_file,
        expected_image=args.expect_image,
        expected_platform=args.expect_platform,
    )
    return render_trivy_image_document(args, document)
