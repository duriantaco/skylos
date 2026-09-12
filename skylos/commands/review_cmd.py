from __future__ import annotations

import argparse
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from skylos import analyze as run_analyze
from skylos.cicd.evidence import sanitize_untrusted_text
from skylos.config import load_config, resolve_config_file_path
from skylos.constants import parse_exclude_folders
from skylos.core import review_decisions


_FALSE_POSITIVE = "false_positive"
_RISK_ACCEPTED = "risk_accepted"
_LOCAL_DISPOSITIONS = {_FALSE_POSITIVE, _RISK_ACCEPTED}
_MAX_REASON_LENGTH = 2_000
_MAX_ACCEPTANCE_DAYS = 365


def _safe_display(value: Any, maximum: int) -> str:
    return escape(
        sanitize_untrusted_text(
            value,
            max_length=maximum,
            preserve_newlines=False,
            neutralize_mentions=False,
        )
    )


def _build_list_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos review list",
        description="List locally reviewed findings for a repository.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository path")
    return parser


def _build_restore_parser(command: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=f"skylos review {command}",
        description="Restore a finding by revoking its local review decision.",
    )
    parser.add_argument("decision_id", help="Decision ID shown by `skylos review list`")
    parser.add_argument("path", nargs="?", default=".", help="Repository path")
    return parser


def _build_add_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos review",
        description="Scan a repository and record a local review decision.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    return parser


def _environment(environ: Mapping[str, str] | None) -> dict[str, str]:
    return dict(os.environ if environ is None else environ)


def _is_ci(environ: Mapping[str, str]) -> bool:
    return review_decisions.is_ci_environment(dict(environ))


def _resolve_target(raw_path: str) -> tuple[Path, Path]:
    target = Path(raw_path).expanduser().resolve(strict=True)
    scan_root = target.parent if target.is_file() else target
    from skylos.core.file_discovery import find_git_root

    project_root = find_git_root(scan_root) or scan_root
    return target, project_root


def _scan_reviewable_findings(
    target: Path,
    project_root: Path,
    *,
    environ: dict[str, str],
    now: datetime,
    trusted_cache_root: str | Path | None,
    local_cache_root: str | Path | None,
) -> list[dict[str, Any]]:
    config_file = resolve_config_file_path()
    project_config = load_config(project_root, config_file=config_file)
    exclude_folders = parse_exclude_folders(
        config_exclude_folders=project_config.get("exclude"),
    )
    raw = run_analyze(
        str(target),
        enable_danger=True,
        enable_quality=True,
        enable_secrets=True,
        enable_ai_defects=True,
        include_review_proofs=True,
        include_review_context=True,
        exclude_folders=list(exclude_folders),
        config_file=config_file,
    )
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ValueError("Skylos returned an invalid scan result")
    annotated = review_decisions.apply_trusted_review_decisions(
        result,
        project_root,
        cache_root=trusted_cache_root,
        local_cache_root=local_cache_root,
        environ=environ,
        now=now,
        include_identities=True,
    )

    findings: list[dict[str, Any]] = []
    for section, category, _default_rule_id in review_decisions.FINDING_SECTIONS:
        for raw_finding in annotated.get(section, []) or []:
            if not isinstance(raw_finding, dict):
                continue
            if not all(
                raw_finding.get(key)
                for key in (
                    "fingerprint_version",
                    "stable_fingerprint",
                    "context_hash",
                    "rule_revision",
                )
            ):
                continue
            finding = dict(raw_finding)
            finding["_review_section"] = section
            finding["_review_category"] = category
            findings.append(finding)
    return findings


def _finding_location(finding: Mapping[str, Any]) -> str:
    path = str(finding.get("file_path") or finding.get("file") or "unknown")
    line = finding.get("line_number") or finding.get("line") or 1
    return f"{path}:{line}"


def _finding_message(finding: Mapping[str, Any]) -> str:
    message = (
        finding.get("message")
        or finding.get("detail")
        or finding.get("name")
        or finding.get("symbol")
        or "Finding"
    )
    return str(message).replace("\n", " ")[:180]


def _finding_review_signal(finding: Mapping[str, Any]) -> str:
    raw_confidence = finding.get("confidence")
    if raw_confidence is None:
        raw_confidence = finding.get("_confidence")
    if isinstance(raw_confidence, bool):
        confidence = ""
    elif isinstance(raw_confidence, (int, float)):
        confidence = f"{max(0, min(100, round(float(raw_confidence))))}%"
    elif isinstance(raw_confidence, str):
        confidence = raw_confidence.strip().upper()[:20]
    else:
        confidence = ""
    needs_review = any(
        finding.get(key) is True
        for key in ("needs_review", "_needs_review", "_llm_uncertain")
    ) or confidence in {"LOW", "MEDIUM", "UNCERTAIN"}
    if needs_review:
        return f"{confidence} · NEEDS REVIEW" if confidence else "NEEDS REVIEW"
    return confidence or "—"


def _render_findings(console: Console, findings: list[dict[str, Any]]) -> None:
    console.print(
        "[dim]A decision applies only while this finding's relevant code and "
        "analyzer evidence still match. Material changes bring it back.[/dim]"
    )
    table = Table(title="Findings available for review", show_lines=False)
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Location")
    table.add_column("Signal")
    table.add_column("Finding")
    for index, finding in enumerate(findings, start=1):
        table.add_row(
            str(index),
            _safe_display(finding.get("severity") or "—", 20),
            _safe_display(finding.get("rule_id") or "UNKNOWN", 120),
            _safe_display(_finding_location(finding), 300),
            _safe_display(_finding_review_signal(finding), 40),
            _safe_display(_finding_message(finding), 180),
        )
    console.print(table)


def _prompt_index(
    findings: list[dict[str, Any]], input_fn: Callable[[str], str]
) -> int | None:
    try:
        raw = input_fn("Select a finding number, or q to cancel: ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if raw.lower() in {"q", "quit", "cancel", ""}:
        return None
    try:
        index = int(raw)
    except ValueError:
        return -1
    return index - 1 if 1 <= index <= len(findings) else -1


def _prompt_disposition(input_fn: Callable[[str], str]) -> str | None:
    try:
        raw = (
            input_fn(
                "Decision: [1] false positive  [2] accept risk temporarily  [q] cancel: "
            )
            .strip()
            .lower()
        )
    except (EOFError, KeyboardInterrupt):
        return None
    return {
        "1": _FALSE_POSITIVE,
        _FALSE_POSITIVE: _FALSE_POSITIVE,
        "2": _RISK_ACCEPTED,
        _RISK_ACCEPTED: _RISK_ACCEPTED,
    }.get(raw)


def _prompt_reason(input_fn: Callable[[str], str]) -> str | None:
    try:
        reason = input_fn("Reason (required): ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not reason or len(reason) > _MAX_REASON_LENGTH or "\x00" in reason:
        return None
    return reason


def _prompt_expiry_days(input_fn: Callable[[str], str]) -> int | None:
    try:
        raw = input_fn("Expires in days [30]: ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not raw:
        return 30
    try:
        days = int(raw)
    except ValueError:
        return None
    return days if 1 <= days <= _MAX_ACCEPTANCE_DAYS else None


def _decision_from_finding(
    finding: Mapping[str, Any],
    *,
    disposition: str,
    reason: str,
    now: datetime,
    expiry_days: int | None,
) -> dict[str, Any]:
    if disposition not in _LOCAL_DISPOSITIONS:
        raise ValueError("unsupported local review disposition")
    decision = {
        "decision_id": str(uuid.uuid4()),
        "fingerprint_version": finding["fingerprint_version"],
        "stable_fingerprint": finding["stable_fingerprint"],
        "context_hash": finding["context_hash"],
        "rule_revision": finding["rule_revision"],
        "rule_id": finding["rule_id"],
        "file_path": finding["file_path"],
        "line_number": int(finding.get("line_number") or finding.get("line") or 1),
        "language": finding["language"],
        "symbol": finding["symbol"],
        "section": finding["section"],
        "category": finding["_review_category"],
        "disposition": disposition,
        "reason": reason,
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "source": "local_cli",
    }
    if disposition == _RISK_ACCEPTED:
        if expiry_days is None:
            raise ValueError("risk acceptance requires an expiry")
        decision["expires_at"] = (
            (now + timedelta(days=expiry_days)).isoformat().replace("+00:00", "Z")
        )
    return decision


def _choose_finding(
    console: Console,
    findings: list[dict[str, Any]],
    input_fn: Callable[[str], str],
) -> dict[str, Any] | None:
    _render_findings(console, findings)
    selected = _prompt_index(findings, input_fn)
    if selected is None:
        console.print("[dim]Review cancelled.[/dim]")
        return None
    if selected < 0:
        raise ValueError("Invalid finding number.")
    return findings[selected]


def _prompt_decision_details(
    input_fn: Callable[[str], str],
) -> tuple[str, str, int | None]:
    disposition = _prompt_disposition(input_fn)
    if disposition is None:
        raise ValueError("Choose false positive or temporary risk acceptance.")
    reason = _prompt_reason(input_fn)
    if reason is None:
        raise ValueError(
            f"Reason is required and must be at most {_MAX_REASON_LENGTH} characters."
        )
    expiry_days = None
    if disposition == _RISK_ACCEPTED:
        expiry_days = _prompt_expiry_days(input_fn)
        if expiry_days is None:
            raise ValueError(
                f"Expiry must be between 1 and {_MAX_ACCEPTANCE_DAYS} days."
            )
    return disposition, reason, expiry_days


def _select_review_decision(
    console: Console,
    findings: list[dict[str, Any]],
    input_fn: Callable[[str], str],
    now: datetime,
) -> tuple[dict[str, Any], str] | None:
    finding = _choose_finding(console, findings, input_fn)
    if finding is None:
        return None
    disposition, reason, expiry_days = _prompt_decision_details(input_fn)
    decision = _decision_from_finding(
        finding,
        disposition=disposition,
        reason=reason,
        now=now,
        expiry_days=expiry_days,
    )
    return decision, disposition


def _record_review_decision(
    project_root: Path,
    decision: dict[str, Any],
    *,
    disposition: str,
    console: Console,
    environ: dict[str, str],
    now: datetime,
    local_cache_root: str | Path | None,
) -> int:
    try:
        saved = review_decisions.record_local_decision(
            project_root,
            decision,
            environ=environ,
            cache_root=local_cache_root,
            now=now,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(
            f"[red]Could not save review decision:[/red] {_safe_display(exc, 500)}"
        )
        return 2
    if not saved:
        console.print("[red]Could not save review decision securely.[/red]")
        return 2

    label = "false positive" if disposition == _FALSE_POSITIVE else "accepted risk"
    decision_id = _safe_display(decision["decision_id"], 200)
    console.print(f"[green]Recorded {label}.[/green]")
    if disposition == _FALSE_POSITIVE:
        console.print(
            "[dim]Future local scans will exclude this exact finding while its "
            "relevant code and evidence still match.[/dim]"
        )
    else:
        console.print(
            "[dim]Future local scans will exclude this exact finding until "
            f"{_safe_display(decision.get('expires_at') or 'expiry', 80)}, unless "
            "its relevant code or evidence changes first.[/dim]"
        )
    console.print(
        f"[dim]Decision {decision_id}; restore with "
        f"`skylos review restore {decision_id}`.[/dim]"
    )
    return 0


def _run_add(
    path: str,
    *,
    console: Console,
    input_fn: Callable[[str], str],
    environ: dict[str, str],
    now: datetime,
    trusted_cache_root: str | Path | None,
    local_cache_root: str | Path | None,
) -> int:
    if _is_ci(environ):
        console.print("[red]Local review decisions cannot be created in CI.[/red]")
        return 2
    try:
        target, project_root = _resolve_target(path)
        findings = _scan_reviewable_findings(
            target,
            project_root,
            environ=environ,
            now=now,
            trusted_cache_root=trusted_cache_root,
            local_cache_root=local_cache_root,
        )
    except Exception as exc:
        console.print(f"[red]Review scan failed:[/red] {_safe_display(exc, 500)}")
        return 2

    if not findings:
        console.print(
            "[green]No findings with stable review identity were found.[/green]"
        )
        return 0
    try:
        selected = _select_review_decision(console, findings, input_fn, now)
    except ValueError as exc:
        console.print(f"[red]{_safe_display(exc, 500)}[/red]")
        return 2
    if selected is None:
        return 0
    decision, disposition = selected
    return _record_review_decision(
        project_root,
        decision,
        disposition=disposition,
        console=console,
        environ=environ,
        now=now,
        local_cache_root=local_cache_root,
    )


def _run_list(
    path: str,
    *,
    console: Console,
    environ: dict[str, str],
    local_cache_root: str | Path | None,
) -> int:
    if _is_ci(environ):
        console.print("[dim]Local review decisions are ignored in CI.[/dim]")
        return 0
    try:
        _target, project_root = _resolve_target(path)
        decisions = review_decisions.list_local_decisions(
            project_root,
            include_revoked=True,
            environ=environ,
            cache_root=local_cache_root,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(
            f"[red]Could not load review decisions:[/red] {_safe_display(exc, 500)}"
        )
        return 2
    if not decisions:
        console.print("[dim]No local review decisions.[/dim]")
        return 0

    console.print(_local_decisions_table(decisions))
    return 0


def _local_decisions_table(decisions: list[dict[str, Any]]) -> Table:
    table = Table(title="Local review decisions")
    table.add_column("Decision ID")
    table.add_column("Disposition")
    table.add_column("Finding")
    table.add_column("Expires")
    table.add_column("Reason")
    for decision in decisions:
        if isinstance(decision, dict):
            table.add_row(*_local_decision_row(decision))
    return table


def _local_decision_row(decision: dict[str, Any]) -> tuple[str, ...]:
    state = (
        "revoked"
        if decision.get("revoked_at")
        else str(decision.get("disposition") or "unknown")
    )
    location = (
        f"{decision.get('rule_id') or 'UNKNOWN'}  "
        f"{decision.get('file_path') or 'unknown'}:"
        f"{decision.get('line_number') or 1}"
    )
    return (
        _safe_display(decision.get("decision_id") or decision.get("id") or "", 200),
        _safe_display(state, 40),
        _safe_display(location, 400),
        _safe_display(decision.get("expires_at") or "never", 80),
        _safe_display(decision.get("reason") or "", 300),
    )


def _run_restore(
    path: str,
    decision_id: str,
    *,
    console: Console,
    environ: dict[str, str],
    local_cache_root: str | Path | None,
    now: datetime,
) -> int:
    if _is_ci(environ):
        console.print("[red]Local review decisions cannot be changed in CI.[/red]")
        return 2
    try:
        _target, project_root = _resolve_target(path)
        restored = review_decisions.revoke_local_decision(
            project_root,
            decision_id,
            environ=environ,
            cache_root=local_cache_root,
            now=now,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(
            f"[red]Could not restore finding:[/red] {_safe_display(exc, 500)}"
        )
        return 2
    if not restored:
        console.print(
            f"[red]Active decision not found:[/red] {_safe_display(decision_id, 200)}"
        )
        return 2
    console.print(
        "[green]Restored finding by revoking "
        f"{_safe_display(decision_id, 200)}.[/green]"
    )
    return 0


def run_review_command(
    argv: list[str],
    *,
    console_factory: Callable[[], Console] = Console,
    input_fn: Callable[[str], str] = input,
    environ: Mapping[str, str] | None = None,
    now: datetime | None = None,
    trusted_cache_root: str | Path | None = None,
    local_cache_root: str | Path | None = None,
) -> int:
    console = console_factory()
    env = _environment(environ)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    else:
        current = current.astimezone(timezone.utc)

    if argv and argv[0] == "list":
        args = _build_list_parser().parse_args(argv[1:])
        return _run_list(
            args.path,
            console=console,
            environ=env,
            local_cache_root=local_cache_root,
        )
    if argv and argv[0] in {"restore", "revoke"}:
        args = _build_restore_parser(argv[0]).parse_args(argv[1:])
        return _run_restore(
            args.path,
            args.decision_id,
            console=console,
            environ=env,
            local_cache_root=local_cache_root,
            now=current,
        )

    args = _build_add_parser().parse_args(argv)
    return _run_add(
        args.path,
        console=console,
        input_fn=input_fn,
        environ=env,
        now=current,
        trusted_cache_root=trusted_cache_root,
        local_cache_root=local_cache_root,
    )
