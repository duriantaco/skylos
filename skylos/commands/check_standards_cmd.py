"""Project-wide, static enforcement of selected agent standards rules.

The guidance file tells agents how to work.  This command gates only the
built-in quality rules explicitly selected by its declarative policy.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from pathlib import Path
from typing import Any, Callable, TextIO

from skylos.commands.agent_standards_policy import (
    POLICY_PATH,
    AgentStandardsPolicyError,
    load_agent_standards_policy,
)

AnalyzeFunc = Callable[..., str | dict[str, Any]]


def run_check_standards_command(
    path: str | Path = ".",
    *,
    output_format: str = "text",
    stdout: TextIO | None = None,
    analyze_func: AnalyzeFunc | None = None,
) -> int:
    """Print a CI verdict: 0 pass, 1 selected-rule findings, 2 incomplete/error."""
    stdout = stdout if stdout is not None else sys.stdout
    if output_format not in {"text", "json"}:
        return _emit_error(stdout, output_format, "format must be text or json")

    try:
        root = _project_root(path)
        policy = load_agent_standards_policy(root)
        if policy is None:
            raise AgentStandardsPolicyError(
                f"{POLICY_PATH.as_posix()} is missing; install project standards first"
            )
    except (OSError, ValueError, AgentStandardsPolicyError) as exc:
        return _emit_error(stdout, output_format, str(exc))

    selected = sorted(policy.enforce_rule_ids)
    report: dict[str, Any] = {
        "schema_version": 1,
        "tool": "check-standards",
        "status": "pass",
        "project_root": str(root),
        "standards_file": policy.standards_file,
        "selected_rules": selected,
        "findings": [],
    }
    if not selected:
        report["message"] = "Guidance only: no quality rule IDs selected."
        _emit(stdout, output_format, report)
        return 0

    try:
        from skylos.config import load_config, resolve_config_file_path
        from skylos.constants import parse_exclude_folders

        config_file = resolve_config_file_path()
        config = load_config(root, config_file=config_file)
        excluded = sorted(
            parse_exclude_folders(
                use_defaults=True,
                config_exclude_folders=config.get("exclude"),
            )
        )
        if analyze_func is None:
            from skylos.analyzer import analyze as analyze_func

        # The analyzer reads target source; no trace, tests, package scripts,
        # dependency audits, network checks or generated fixes are requested.
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            raw = analyze_func(
                str(root),
                exclude_folders=excluded,
                enable_quality=True,
                enable_danger=False,
                enable_secrets=False,
                enable_ai_defects=False,
                enable_dependency_hallucinations=False,
                enable_sca=False,
                grep_verify=False,
                trace_file=False,
                config_file=config_file,
            )
        result = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(result, dict):
            raise ValueError("analyzer returned an invalid result")
        quality = result.get("quality", [])
        if not isinstance(quality, list):
            raise ValueError("analyzer returned an invalid quality findings list")
        errors = result.get("analysis_errors")
        if not isinstance(errors, list):
            raise ValueError("analyzer returned invalid analysis errors")
        relevant_errors = [error for error in errors if _quality_relevant_error(error)]
        if relevant_errors:
            raise ValueError(
                f"quality scan incomplete ({len(relevant_errors)} analysis error(s))"
            )
        summary = result.get("analysis_summary")
        if (
            not isinstance(summary, dict)
            or type(summary.get("total_files")) is not int
            or summary["total_files"] < 0
        ):
            raise ValueError("analyzer returned invalid scan coverage")
        if summary["total_files"] == 0:
            raise ValueError("quality scan found no supported source files")
        report["findings"] = _selected_findings(quality, root, set(selected))
    except (Exception, SystemExit) as exc:
        report["status"] = "error"
        report["error"] = f"quality scan failed: {exc}"
        _emit(stdout, output_format, report)
        return 2

    report["status"] = "fail" if report["findings"] else "pass"
    _emit(stdout, output_format, report)
    return 1 if report["findings"] else 0


def _project_root(path: str | Path) -> Path:
    start = Path(path).expanduser().resolve(strict=True)
    if start.is_file():
        start = start.parent
    if not start.is_dir():
        raise ValueError("project path must be a directory or source file")
    for parent in (start, *start.parents):
        if (parent / ".git").exists():
            return parent
    return start


def _quality_relevant_error(error: Any) -> bool:
    """A missing Go engine skips dead-code/security, not Go quality checks."""
    if not isinstance(error, dict):
        return True
    if error.get("kind") == "language_engine_unavailable":
        skipped = error.get("skipped_checks")
        if (
            isinstance(skipped, list)
            and skipped
            and all(check in {"dead_code", "security"} for check in skipped)
        ):
            return False
    return True


def _selected_findings(
    quality: list[Any], root: Path, selected: set[str]
) -> list[dict[str, Any]]:
    findings = []
    for item in quality:
        if not isinstance(item, dict):
            raise ValueError("analyzer returned an invalid quality finding")
        rule_id = item.get("rule_id") or item.get("rule")
        if rule_id not in selected:
            continue
        file_name = item.get("file") or item.get("path") or "?"
        if not isinstance(file_name, str):
            file_name = str(file_name)
        source_path = Path(file_name)
        if source_path.is_absolute():
            try:
                file_name = source_path.relative_to(root).as_posix()
            except ValueError:
                file_name = source_path.as_posix()
        try:
            line = int(item.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        findings.append(
            {
                "rule_id": rule_id,
                "file": file_name,
                "line": max(0, line),
                "severity": str(item.get("severity") or ""),
                "message": str(item.get("message") or ""),
            }
        )
    findings.sort(
        key=lambda finding: (finding["file"], finding["line"], finding["rule_id"])
    )
    return findings


def _emit_error(stdout: TextIO, output_format: str, message: str) -> int:
    _emit(
        stdout,
        output_format,
        {
            "schema_version": 1,
            "tool": "check-standards",
            "status": "error",
            "error": message,
        },
    )
    return 2


def _emit(stdout: TextIO, output_format: str, report: dict[str, Any]) -> None:
    if output_format == "json":
        stdout.write(json.dumps(report, sort_keys=True) + "\n")
        return
    if report["status"] == "error":
        stdout.write(f"Skylos standards: {_plain(report['error'])}\n")
        return
    if report.get("message"):
        stdout.write(f"Skylos standards: {_plain(report['message'])}\n")
        return
    findings = report["findings"]
    if not findings:
        stdout.write(
            f"Skylos standards: pass ({len(report['selected_rules'])} selected quality rule(s)).\n"
        )
        return
    stdout.write(f"Skylos standards: {len(findings)} selected quality finding(s):\n")
    for finding in findings:
        stdout.write(
            f"- {_plain(finding['file'])}:{finding['line']} "
            f"{finding['rule_id']} {_plain(finding['message'])}\n"
        )


def _plain(value: Any) -> str:
    """Keep source-derived text from controlling a terminal."""
    return " ".join(
        "".join(char if char.isprintable() else " " for char in str(value)).split()
    )
