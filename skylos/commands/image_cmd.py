"""Explicit container-image scanning through an installed Trivy executable."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from skylos.commands.trivy_image_cmd import (
    _error,
    _safe_output_selection,
    render_trivy_image_document,
)
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.integrations.trivy_image import (
    _IMAGE_REFERENCE,
    _PLATFORM,
    _envelope,
    load_trivy_image_report,
)


DEFAULT_TIMEOUT_SECONDS = 300
MAX_TIMEOUT_SECONDS = 900


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos image",
        description=(
            "Scan a digest-pinned remote registry image using an installed Trivy."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")
    scan = subparsers.add_parser(
        "scan",
        help="Scan a registry image, then report its vulnerabilities",
        description=(
            "Scan a digest-pinned image from a remote registry with a trusted Trivy "
            "executable installed on PATH. This requires network access and any "
            "credentials needed by the registry."
        ),
        epilog=(
            "Without --fail-on, vulnerability findings are report-only and exit 0.\n"
            "Exit codes: 0 completed (or gate passed), 1 requested severity gate "
            "failed, 2 scan or report incomplete."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan.add_argument(
        "image",
        metavar="IMAGE@sha256:DIGEST",
        help="Repository image pinned to a sha256 digest",
    )
    scan.add_argument(
        "--platform",
        required=True,
        help="Deployment OS/architecture[/variant], for example linux/amd64",
    )
    scan.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        help=(
            "Exit 1 for findings at or above this severity; omitted means "
            "findings are report-only"
        ),
    )
    scan.add_argument(
        "-o", "--output", default="-", help="Normalized JSON file; default: stdout"
    )
    scan.add_argument("--sarif", help="Also write image-aware SARIF")
    scan.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Scanner timeout in seconds (1-{MAX_TIMEOUT_SECONDS}; default 300)",
    )
    return parser


def _trivy_report_image(image: str) -> str:
    """Match Trivy's Docker Hub RepoDigests spelling for direct scans only."""
    repository, separator, digest = image.rpartition("@sha256:")
    if not separator:
        return image
    parts = repository.split("/", 1)
    first = parts[0]
    explicit_hub = len(parts) == 2 and first in {"docker.io", "index.docker.io"}
    docker_hub = explicit_hub or (
        first != "localhost" and "." not in first and ":" not in first
    )
    if not docker_hub:
        return image
    if explicit_hub:
        repository = parts[1]
    if repository.startswith("library/"):
        repository = repository.removeprefix("library/")
    return f"{repository}@sha256:{digest}"


def _report_args(args: argparse.Namespace) -> argparse.Namespace:
    return argparse.Namespace(
        input_file=None,
        output=args.output,
        sarif=args.sarif,
        fail_on=args.fail_on,
        expect_image=_trivy_report_image(args.image),
        expect_platform=args.platform,
    )


def _record_execution(
    document: dict,
    status: str,
    *,
    timeout_seconds: int,
    exit_code: int | None = None,
) -> None:
    document["receipt"]["execution"] = {
        "scanner": "Trivy",
        "source": "remote",
        "status": status,
        "exit_code": exit_code,
        "timeout_seconds": timeout_seconds,
    }


def _incomplete(
    args: argparse.Namespace,
    code: str,
    message: str,
    *,
    status: str,
    exit_code: int | None = None,
    document: dict | None = None,
) -> int:
    document = document if document is not None else _envelope(None)
    _error(document, code, message)
    _record_execution(
        document,
        status,
        timeout_seconds=args.timeout_seconds,
        exit_code=exit_code,
    )
    return render_trivy_image_document(
        _report_args(args), document, gate_scope="direct_image_scan"
    )


def _resolve_trivy_binary() -> str | None:
    candidate = shutil.which("trivy")
    if not candidate:
        return None
    try:
        executable = Path(candidate).resolve(strict=True)
        checkout = Path.cwd().resolve(strict=True)
        if (
            not executable.is_file()
            or not os.access(executable, os.X_OK)
            or executable.is_relative_to(checkout)
        ):
            return None
        for ancestor in (checkout, *checkout.parents):
            if (ancestor / ".git").exists() and executable.is_relative_to(ancestor):
                return None
    except (OSError, RuntimeError, ValueError):
        return None
    return str(executable)


def _scan_environment() -> dict[str, str]:
    # Trivy config and filter variables may otherwise silently remove findings.
    return {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("TRIVY_")
    }


def _scan_argv(
    scanner: str,
    args: argparse.Namespace,
    *,
    config: Path,
    ignorefile: Path,
    raw_report: Path,
) -> list[str]:
    return [
        scanner,
        "image",
        "--config",
        str(config),
        "--ignorefile",
        str(ignorefile),
        "--image-src",
        "remote",
        "--platform",
        args.platform,
        "--scanners",
        "vuln",
        "--pkg-types",
        "os,library",
        "--severity",
        "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
        "--ignore-unfixed=false",
        "--exit-code",
        "0",
        "--format",
        "json",
        "--output",
        str(raw_report),
        "--timeout",
        f"{args.timeout_seconds}s",
        "--disable-telemetry",
        "--no-progress",
        args.image,
    ]


def _preflight(args: argparse.Namespace) -> int | None:
    if (
        not _IMAGE_REFERENCE.fullmatch(args.image)
        or not _PLATFORM.fullmatch(args.platform)
        or any(
            not part or part.endswith(("-", ".")) for part in args.platform.split("/")
        )
    ):
        return _incomplete(
            args,
            "invalid_image_target",
            "Image must be pinned to a sha256 digest and platform must be os/architecture[/variant].",
            status="invalid_request",
        )
    if not 1 <= args.timeout_seconds <= MAX_TIMEOUT_SECONDS:
        return _incomplete(
            args,
            "invalid_timeout",
            f"Scanner timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds.",
            status="invalid_request",
        )
    if not _safe_output_selection(_report_args(args)):
        return _incomplete(
            args,
            "unsafe_output",
            "Output must be a safe, separate JSON or SARIF file.",
            status="invalid_request",
        )
    return None


def _load_scanner_report(args: argparse.Namespace, raw_report: Path) -> dict:
    if not raw_report.exists():
        return _envelope(None)
    return load_trivy_image_report(
        raw_report,
        expected_image=_trivy_report_image(args.image),
        expected_platform=args.platform,
    )


def _invoke_scanner(
    args: argparse.Namespace,
    scanner: str,
    root: Path,
    config: Path,
    ignorefile: Path,
    raw_report: Path,
) -> tuple[subprocess.CompletedProcess | None, str | None]:
    try:
        completed = subprocess.run(
            _scan_argv(
                scanner,
                args,
                config=config,
                ignorefile=ignorefile,
                raw_report=raw_report,
            ),
            cwd=root,
            env=_scan_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=args.timeout_seconds + 15,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, "timed_out"
    except OSError:
        return None, "failed_to_start"
    return completed, None


def _scan_in_workspace(args: argparse.Namespace, scanner: str, root: Path) -> int:
    config = root / "trivy.yaml"
    ignorefile = root / ".trivyignore"
    raw_report = root / "trivy.json"
    if not write_text_no_symlink(config, "{}\n") or not write_text_no_symlink(
        ignorefile, ""
    ):
        return _incomplete(
            args,
            "scanner_setup_failed",
            "Could not prepare the private scanner configuration.",
            status="failed",
        )
    completed, problem = _invoke_scanner(
        args, scanner, root, config, ignorefile, raw_report
    )
    document = _load_scanner_report(args, raw_report)
    if problem:
        timed_out = problem == "timed_out"
        return _incomplete(
            args,
            "scanner_timeout" if timed_out else "scanner_execution_failed",
            "Trivy did not finish before the timeout."
            if timed_out
            else "Trivy could not be started.",
            status="timed_out" if timed_out else "failed",
            document=document,
        )
    if completed.returncode != 0:
        return _incomplete(
            args,
            "scanner_failed",
            "Trivy reported an execution error.",
            status="failed",
            exit_code=completed.returncode,
            document=document,
        )
    if not raw_report.exists():
        return _incomplete(
            args,
            "scanner_report_missing",
            "Trivy did not write its JSON report.",
            status="failed",
        )
    _record_execution(
        document,
        "completed",
        timeout_seconds=args.timeout_seconds,
        exit_code=0,
    )
    return render_trivy_image_document(
        _report_args(args), document, gate_scope="direct_image_scan"
    )


def _scan(args: argparse.Namespace) -> int:
    preflight_result = _preflight(args)
    if preflight_result is not None:
        return preflight_result
    scanner = _resolve_trivy_binary()
    if scanner is None:
        return _incomplete(
            args,
            "scanner_unavailable",
            "Trivy is not installed as a trusted executable on PATH.",
            status="unavailable",
        )

    try:
        private_workspace = tempfile.TemporaryDirectory(
            prefix="skylos-image-", dir=Path(tempfile.gettempdir()).resolve()
        )
    except OSError:
        return _incomplete(
            args,
            "scanner_setup_failed",
            "Could not prepare the private scanner workspace.",
            status="failed",
        )

    with private_workspace as temporary:
        return _scan_in_workspace(args, scanner, Path(temporary))


def run_image_command(argv: list[str]) -> int:
    parser = _parser()
    if not argv:
        parser.print_help()
        return 0
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    parser.print_help()
    return 0
