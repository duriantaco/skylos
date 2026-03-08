from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()

_CCS_SEVERITY_MAP: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "LOW",
    "informational": "LOW",
}


def _map_severity(raw: str | None) -> str:
    if not raw:
        return "MEDIUM"
    return _CCS_SEVERITY_MAP.get(raw.lower().strip(), "MEDIUM")


def is_claude_security_report(data: Any) -> bool:
    if not isinstance(data, dict):
        return False

    findings = None
    for key in ("findings", "vulnerabilities", "results"):
        val = data.get(key)
        if isinstance(val, list):
            findings = val
            break

    if findings is None:
        return False

    tool_str = data.get("tool") or data.get("scanner") or ""
    has_tool_key = bool(tool_str) or "scan_metadata" in data
    if not findings:
        return has_tool_key

    sample = findings[0]
    return isinstance(sample, dict) and (
        "confidence_score" in sample
        or "confidence" in sample
        or "exploit_scenario" in sample
        or "exploit" in sample
        or has_tool_key
    )


def normalize_claude_security(data: dict) -> dict:
    findings_raw = (
        data.get("findings") or data.get("vulnerabilities") or data.get("results") or []
    )

    danger: list[dict] = []

    for f in findings_raw:
        if not isinstance(f, dict):
            continue

        rule_id = f.get("rule_id") or f.get("id") or f.get("type") or "unknown"
        if not rule_id.startswith("CCS:"):
            rule_id = f"CCS:{rule_id}"

        file_path = (
            f.get("file_path")
            or f.get("file")
            or f.get("location", {}).get("file", "unknown")
        )
        line_raw = (
            f.get("line_number")
            or f.get("line")
            or f.get("location", {}).get("line")
            or 1
        )
        try:
            line = max(1, int(line_raw))
        except (TypeError, ValueError):
            line = 1

        message = (
            f.get("message")
            or f.get("description")
            or f.get("title")
            or "Security issue"
        )

        severity = _map_severity(f.get("severity") or f.get("level"))

        snippet = f.get("snippet") or f.get("code") or f.get("vulnerable_code") or None

        finding: dict[str, Any] = {
            "rule_id": rule_id,
            "file_path": file_path,
            "line_number": line,
            "message": message,
            "severity": severity,
            "category": "SECURITY",
        }

        if snippet:
            finding["snippet"] = str(snippet)[:2000]

        confidence = f.get("confidence_score") or f.get("confidence")
        if confidence is not None:
            try:
                finding["_confidence"] = float(confidence)
            except (TypeError, ValueError):
                pass

        exploit = f.get("exploit_scenario") or f.get("exploit")
        if exploit:
            finding["_exploit_scenario"] = str(exploit)

        fix = f.get("fix") or f.get("remediation") or f.get("suggested_fix")
        if fix:
            finding["_suggested_fix"] = str(fix)

        cwe = f.get("cwe") or f.get("cwe_id")
        if cwe:
            finding["_cwe"] = str(cwe)

        danger.append(finding)

    result: dict[str, Any] = {
        "danger": danger,
        "_source": "claude-code-security",
    }

    scan_meta = data.get("scan_metadata") or data.get("metadata") or {}
    if scan_meta:
        result["_scan_metadata"] = scan_meta

    return result


def _extract_dead_code_files(skylos_result: dict) -> set[str]:
    files: set[str] = set()
    for key in (
        "unused_functions",
        "unused_imports",
        "unused_variables",
        "unused_classes",
    ):
        for item in skylos_result.get(key, []):
            fp = item.get("file_path") or item.get("file") or ""
            if fp:
                files.add(fp.replace("\\", "/"))
    return files


def _normalize_path(p: str) -> str:
    s = p.replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s


def cross_reference(
    claude_findings: list[dict],
    skylos_result: dict,
) -> dict:
    dead_code_files = _extract_dead_code_files(skylos_result)

    dead_files = set()
    for file_path in dead_code_files:
        dead_files.add(_normalize_path(file_path))

    skylos_security_locations: set[tuple[str, int]] = set()
    for item in skylos_result.get("danger", []):
        fp = _normalize_path(item.get("file_path") or item.get("file") or "")
        line = int(item.get("line_number") or item.get("line") or 0)
        if fp and line:
            skylos_security_locations.add((fp, line))

    in_dead_code: list[dict] = []
    corroborated: list[dict] = []
    unique_to_claude: list[dict] = []

    for f in claude_findings:
        fp = _normalize_path(f.get("file_path", ""))
        line = f.get("line_number", 0)

        is_dead = fp in dead_files
        is_corroborated = (fp, line) in skylos_security_locations

        if is_dead:
            in_dead_code.append(f)
        elif is_corroborated:
            corroborated.append(f)
        else:
            unique_to_claude.append(f)

    total = len(claude_findings)
    dead_count = len(in_dead_code)
    corroborated_count = len(corroborated)
    unique_count = len(unique_to_claude)

    if total > 0:
        reduction_pct = dead_count / total * 100
    else:
        reduction_pct = 0.0

    return {
        "total_claude_findings": total,
        "in_dead_code": dead_count,
        "corroborated_by_skylos": corroborated_count,
        "unique_to_claude": unique_count,
        "dead_code_files_count": len(dead_files),
        "attack_surface_reduction_pct": round(reduction_pct, 1),
        "findings_in_dead_code": in_dead_code,
        "findings_corroborated": corroborated,
        "findings_unique": unique_to_claude,
    }


def print_cross_reference_report(xref: dict) -> None:
    total = xref["total_claude_findings"]
    dead = xref["in_dead_code"]
    corr = xref["corroborated_by_skylos"]
    unique = xref["unique_to_claude"]
    pct = xref["attack_surface_reduction_pct"]

    console.print()
    console.print("[bold]Cross-Reference Report: Skylos x Claude Code Security[/bold]")
    console.print(f"  Claude findings total:    {total}")
    console.print(
        f"  In dead code (removable): [bold red]{dead}[/bold red]  ({pct}% of findings)"
    )
    console.print(
        f"  Corroborated by Skylos:   [bold yellow]{corr}[/bold yellow]  (high confidence)"
    )
    console.print(f"  Unique to Claude:         [bold]{unique}[/bold]  (new insights)")
    console.print()

    if dead > 0:
        console.print(
            f"[green]Removing dead code would eliminate {dead} of {total} "
            f"security findings ({pct}%).[/green]"
        )
        console.print("[dim]Run: skylos . --clean to remove dead code[/dim]")
        console.print()

    if corr > 0:
        console.print(
            f"[yellow]{corr} findings confirmed by both tools — treat as verified.[/yellow]"
        )
        console.print()

    for f in xref["findings_corroborated"]:
        sev = f.get("severity", "MEDIUM")
        color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(sev, "white")
        console.print(
            f"  [{color}]{sev}[/{color}] {f.get('file_path')}:{f.get('line_number')} "
            f"— {f.get('message')}"
        )


def ingest_claude_security(
    input_path: str,
    *,
    upload: bool = True,
    quiet: bool = False,
    token: str | None = None,
    cross_reference_path: str | None = None,
) -> dict:
    path = Path(input_path)
    if not path.exists():
        return {"success": False, "error": f"File not found: {input_path}"}

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"Invalid JSON: {e}"}

    if not is_claude_security_report(raw):
        return {
            "success": False,
            "error": "File does not appear to be Claude Code Security output",
        }

    result = normalize_claude_security(raw)
    findings_count = len(result.get("danger", []))

    if not quiet:
        console.print(
            f"[bold]Normalized {findings_count} Claude Code Security findings[/bold]"
        )

    xref = None
    if cross_reference_path:
        xref_path = Path(cross_reference_path)
        if not xref_path.exists():
            return {
                "success": False,
                "error": f"Skylos results not found: {cross_reference_path}",
            }
        try:
            skylos_data = json.loads(xref_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Invalid Skylos JSON: {e}"}

        xref = cross_reference(result.get("danger", []), skylos_data)

        if not quiet:
            print_cross_reference_report(xref)

    if not upload:
        out: dict[str, Any] = {
            "success": True,
            "findings_count": findings_count,
            "result": result,
        }
        if xref:
            out["cross_reference"] = xref
        return out

    import os

    if token:
        os.environ["SKYLOS_TOKEN"] = token

    from skylos.api import upload_report

    upload_result = upload_report(result, quiet=quiet, analysis_mode="claude-security")
    out = {
        "success": upload_result.get("success", False),
        "findings_count": findings_count,
        "upload": upload_result,
    }
    if xref:
        out["cross_reference"] = xref
    return out
