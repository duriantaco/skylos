"""CLI adapter for release artifact preflight verification."""

from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any, Callable, Sequence

from rich.console import Console
from rich.markup import escape


PreflightRunner = Callable[..., dict[str, Any]]
VALID_REPORT_STATUSES = frozenset({"PASS", "FAIL", "UNKNOWN"})
MAX_TERMINAL_TEXT_LENGTH = 4096


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos preflight",
        description=(
            "Check an exact built GPU artifact against the hardware fleet declared "
            "in .skylos/gpu-targets.yml. Local inspection is static and never starts "
            "the artifact. Digest-pinned OCI references are not pulled and remain "
            "UNKNOWN in the CLI."
        ),
        epilog=(
            "Examples:\n"
            "  skylos preflight build/app\n"
            "  skylos preflight   # discover .skylos/release.json\n"
            "\nThe fleet profile may use a .yml or .yaml suffix.\n"
            "\nScope: source changes and container CVEs are outside this check. "
            "Valid reports are concise on a terminal and JSON when redirected; "
            "argument or adapter errors are plain text.\n"
            "Exit codes: 0 PASS, 1 FAIL, 2 UNKNOWN or invalid input."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "artifact",
        nargs="?",
        metavar="ARTIFACT",
        help=(
            "Local file or directory, or an OCI image reference pinned to sha256; "
            "omit it to discover .skylos/release.json"
        ),
    )
    return parser


def run_preflight_command(
    argv: Sequence[str],
    *,
    console_factory: Callable[..., Console] = Console,
    run_preflight_func: PreflightRunner | None = None,
) -> int:
    """Parse ``skylos preflight`` and return CI-safe PASS/FAIL/UNKNOWN exits."""
    args = _build_parser().parse_args(list(argv))
    console = console_factory()

    if run_preflight_func is None:
        from skylos.preflight import run_preflight

        run_preflight_func = run_preflight

    try:
        project_root = Path.cwd().resolve(strict=True)
        payload = run_preflight_func(args.artifact, project_root=project_root)
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(
            "[bold red]Preflight failed:[/bold red] "
            f"{_safe_terminal_text(exc)}"
        )
        return 2

    report_error = _validate_report(payload)
    if report_error is not None:
        console.print(
            "[bold red]Preflight failed:[/bold red] verifier returned an invalid "
            f"report: {_safe_terminal_text(report_error)}"
        )
        return 2

    if sys.stdout.isatty():
        _render_text_report(console, payload)
    else:
        try:
            print(json.dumps(payload, indent=2, ensure_ascii=True, allow_nan=False))
        except (TypeError, ValueError, RecursionError) as exc:
            console.print(
                "[bold red]Preflight failed:[/bold red] cannot serialize report: "
                f"{_safe_terminal_text(exc)}"
            )
            return 2
    return _exit_code(payload)


def _validate_report(payload: object) -> str | None:
    if not isinstance(payload, dict):
        return "report must be an object"
    if (
        type(payload.get("schema_version")) is not int
        or payload["schema_version"] != 1
    ):
        return "schema_version must be exactly 1"
    if payload.get("kind") != "gpu_artifact_preflight":
        return "kind must be exactly gpu_artifact_preflight"

    status = payload.get("status")
    if not isinstance(status, str) or status not in VALID_REPORT_STATUSES:
        return "status must be exactly PASS, FAIL, or UNKNOWN"
    artifact = payload.get("artifact")
    if not isinstance(artifact, dict):
        return "artifact must be an object"
    if not isinstance(payload.get("profile"), dict):
        return "profile must be an object"
    if not isinstance(payload.get("inventory"), dict):
        return "inventory must be an object"
    targets = payload.get("targets")
    if not isinstance(targets, list):
        return "targets must be a list"
    errors = payload.get("errors")
    if not isinstance(errors, list):
        return "errors must be a list"

    target_statuses = []
    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            return f"targets[{index}] must be an object"
        target_status = target.get("status")
        if (
            not isinstance(target_status, str)
            or target_status not in VALID_REPORT_STATUSES
        ):
            return (
                f"targets[{index}].status must be exactly PASS, FAIL, or UNKNOWN"
            )
        target_statuses.append(target_status)
        checks_error = _validate_target_checks(target, index)
        if checks_error is not None:
            return checks_error

    if status == "PASS":
        if not target_statuses:
            return "PASS requires at least one fleet target"
        if any(target_status != "PASS" for target_status in target_statuses):
            return "PASS requires every fleet target to be PASS"
        if errors:
            return "PASS requires an empty errors list"
        if artifact.get("identity_verified") is not True:
            return "PASS requires verified artifact identity"
        identity = artifact.get("identity")
        if not isinstance(identity, str) or not identity.strip():
            return "PASS requires a nonempty artifact identity"
        for index, target in enumerate(targets):
            checks = target.get("checks")
            if not isinstance(checks, list) or not checks:
                return f"targets[{index}] PASS requires a nonempty checks list"
            if not any(
                check.get("id") == "artifact_identity"
                and check.get("status") == "PASS"
                for check in checks
            ):
                return (
                    f"targets[{index}] PASS requires an artifact_identity "
                    "PASS check"
                )
    elif status == "FAIL":
        if "FAIL" not in target_statuses:
            return "FAIL requires at least one failed fleet target"
    else:
        if "FAIL" in target_statuses:
            return "UNKNOWN cannot contain a failed fleet target"
        if (
            target_statuses
            and all(item == "PASS" for item in target_statuses)
            and not errors
        ):
            return "UNKNOWN requires unknown target evidence or report errors"
        if not target_statuses and not errors:
            return "UNKNOWN without fleet targets requires report errors"
    return None


def _validate_target_checks(target: dict[str, Any], index: int) -> str | None:
    checks = target.get("checks")
    if checks is None:
        return None
    if not isinstance(checks, list):
        return f"targets[{index}].checks must be a list"
    check_statuses = []
    for check_index, check in enumerate(checks):
        if not isinstance(check, dict):
            return f"targets[{index}].checks[{check_index}] must be an object"
        check_status = check.get("status")
        if (
            not isinstance(check_status, str)
            or check_status not in VALID_REPORT_STATUSES
        ):
            return (
                f"targets[{index}].checks[{check_index}].status must be exactly "
                "PASS, FAIL, or UNKNOWN"
            )
        check_statuses.append(check_status)
    target_status = target["status"]
    if target_status == "PASS" and any(item != "PASS" for item in check_statuses):
        return f"targets[{index}] PASS cannot contain a non-PASS check"
    if target_status == "FAIL" and check_statuses and "FAIL" not in check_statuses:
        return f"targets[{index}] FAIL requires a failed check"
    if target_status == "UNKNOWN" and "FAIL" in check_statuses:
        return f"targets[{index}] UNKNOWN cannot contain a failed check"
    return None


def _status(payload: dict[str, Any]) -> str:
    status = payload.get("status")
    return status if isinstance(status, str) else "UNKNOWN"


def _exit_code(payload: dict[str, Any]) -> int:
    if _validate_report(payload) is not None:
        return 2
    status = _status(payload)
    if status == "PASS":
        return 0
    if status == "FAIL":
        return 1
    return 2


def _render_text_report(console: Console, payload: dict[str, Any]) -> None:
    status = _status(payload)
    label, color = _display_status(status)
    console.print(f"\n[bold]Release preflight:[/bold] [{color}]{label}[/{color}]")

    _render_artifact(console, payload)

    targets = payload.get("targets")
    if isinstance(targets, list) and targets:
        console.print("\n[bold]Fleet targets[/bold]")
        for target in targets:
            if not isinstance(target, dict):
                continue
            target_status = target["status"]
            target_label, target_color = _display_status(target_status)
            name = target.get("name") or target.get("target") or "unnamed target"
            facts = _target_facts(target)
            line = (
                f"  [{target_color}]{target_label:<7}[/{target_color}] "
                f"{_safe_terminal_text(name)}"
            )
            if facts:
                line += f" [dim]({_safe_terminal_text('; '.join(facts))})[/dim]"
            console.print(line)
            reasons = target.get("reasons")
            _render_target_checks(
                console,
                target.get("checks"),
                show_messages=not isinstance(reasons, list) or not reasons,
            )
            _render_reasons(
                console, reasons, indent="    ", heading="Reasons"
            )
            _render_evidence(
                console, target.get("evidence"), indent="    ", heading="Evidence"
            )

    _render_reasons(console, payload.get("reasons"), heading="Reasons")
    _render_evidence(console, payload.get("evidence"), heading="Evidence")

    messages = payload.get("errors") or payload.get("unknowns")
    _render_reasons(console, messages, heading="Details")
    console.print()


def _render_artifact(console: Console, payload: dict[str, Any]) -> None:
    artifact = payload.get("artifact") or payload.get("image") or payload.get("target")
    if not isinstance(artifact, dict):
        if artifact:
            console.print(f"[dim]Artifact:[/dim] {_safe_terminal_text(artifact)}")
        return

    target = artifact.get("target") or artifact.get("reference") or artifact.get(
        "image"
    )
    identity = artifact.get("identity")
    if target:
        console.print(f"[dim]Artifact:[/dim] {_safe_terminal_text(target)}")
    if identity:
        verified = artifact.get("identity_verified") is True
        state = "verified" if verified else "unverified"
        color = "green" if verified else "yellow"
        if identity == target:
            console.print(f"[dim]Identity:[/dim] [{color}]{state}[/{color}]")
        else:
            console.print(
                f"[dim]Identity:[/dim] {_safe_terminal_text(identity)} "
                f"[{color}]({state})[/{color}]"
            )


def _render_target_checks(
    console: Console, checks: object, *, show_messages: bool
) -> None:
    if not isinstance(checks, list):
        return
    for check in checks:
        if not isinstance(check, dict):
            continue
        check_status = check.get("status")
        check_label, check_color = _display_status(check_status)
        check_id = check.get("id") or "check"
        message = check.get("message") or ""
        line = (
            f"    [{check_color}]{check_label:<7}[/{check_color}] "
            f"{_safe_terminal_text(check_id)}"
        )
        if show_messages and message:
            line += f" [dim]— {_safe_terminal_text(message)}[/dim]"
        console.print(line)


def _target_facts(target: dict[str, Any]) -> list[str]:
    facts = []
    for label, key in (
        ("platform", "platform"),
        ("driver", "driver"),
        ("compute", "compute_capability"),
    ):
        value = target.get(key)
        if value is not None:
            facts.append(f"{label} {value}")
    return facts


def _render_reasons(
    console: Console,
    reasons: object,
    *,
    indent: str = "  ",
    heading: str | None = None,
) -> None:
    if not isinstance(reasons, list) or not reasons:
        return
    item_indent = indent
    if heading:
        leading = "\n" if indent == "  " else ""
        heading_indent = "" if indent == "  " else indent
        console.print(f"{leading}{heading_indent}[bold]{escape(heading)}[/bold]")
        if indent != "  ":
            item_indent += "  "
    for reason in reasons:
        if isinstance(reason, dict):
            code = reason.get("code")
            message = reason.get("message") or reason.get("reason")
            if code and message:
                text = f"{code}: {message}"
            else:
                text = str(message or code or "Unknown reason")
        else:
            text = str(reason)
        console.print(f"{item_indent}[dim]• {_safe_terminal_text(text)}[/dim]")


def _render_evidence(
    console: Console,
    evidence: object,
    *,
    indent: str = "  ",
    heading: str | None = None,
) -> None:
    if not isinstance(evidence, list) or not evidence:
        return
    item_indent = indent
    if heading:
        leading = "\n" if indent == "  " else ""
        heading_indent = "" if indent == "  " else indent
        console.print(f"{leading}{heading_indent}[bold]{escape(heading)}[/bold]")
        if indent != "  ":
            item_indent += "  "
    for item in evidence:
        if isinstance(item, dict):
            kind = str(item.get("kind") or "evidence")
            value = item.get("value") or item.get("message") or ""
            source = item.get("source")
            text = f"{kind}: {value}" if value else kind
            if source:
                text += f" ({source})"
        else:
            text = str(item)
        console.print(f"{item_indent}[dim]→ {_safe_terminal_text(text)}[/dim]")


def _display_status(status: str) -> tuple[str, str]:
    if status == "PASS":
        return "PASS", "green"
    if status == "FAIL":
        return "FAIL", "red"
    return "UNKNOWN", "yellow"


def _safe_terminal_text(value: object) -> str:
    try:
        raw = str(value)
    except (TypeError, ValueError, RuntimeError):
        raw = "<unprintable>"
    truncated = len(raw) > MAX_TERMINAL_TEXT_LENGTH
    raw = raw[:MAX_TERMINAL_TEXT_LENGTH]
    safe = []
    for char in raw:
        codepoint = ord(char)
        if char in {"\r", "\n", "\t", "\u2028", "\u2029"}:
            safe.append(" ")
        elif codepoint < 32 or 0x7F <= codepoint <= 0x9F:
            safe.append(f"\\x{codepoint:02x}")
        elif unicodedata.category(char) == "Cf":
            if codepoint <= 0xFFFF:
                safe.append(f"\\u{codepoint:04x}")
            else:
                safe.append(f"\\U{codepoint:08x}")
        else:
            safe.append(char)
    if truncated:
        safe.append("…")
    return escape("".join(safe))
