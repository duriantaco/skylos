from __future__ import annotations

import json
import hashlib
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP


def _lazy_analyze():
    from skylos.analyzer import analyze as run_analyze

    return run_analyze


def _lazy_constants():
    from skylos.constants import parse_exclude_folders, DEFAULT_EXCLUDE_FOLDERS

    return parse_exclude_folders, DEFAULT_EXCLUDE_FOLDERS


logger = logging.getLogger("skylos-mcp")


RESULTS_DIR = Path(os.getenv("SKYLOS_MCP_RESULTS_DIR", Path.home() / ".skylos" / "mcp_results"))
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

_results_cache: dict[str, dict[str, Any]] = {}


def _store_result(result: dict, tool: str, path: str) -> str:
    ts = datetime.now(timezone.utc).isoformat()
    run_id = hashlib.sha256(f"{ts}-{tool}-{path}".encode()).hexdigest()[:12]

    envelope = {
        "run_id": run_id,
        "tool": tool,
        "path": path,
        "timestamp": ts,
        "result": result,
    }

    # in-memory
    _results_cache[run_id] = envelope
    _results_cache["latest"] = envelope

    # disk
    try:
        (RESULTS_DIR / f"{run_id}.json").write_text(json.dumps(envelope, indent=2))
        (RESULTS_DIR / "latest.json").write_text(json.dumps(envelope, indent=2))
    except OSError as exc:
        logger.warning("Could not persist result to disk: %s", exc)

    return run_id


def _load_result(run_id: str) -> dict | None:
    if run_id in _results_cache:
        return _results_cache[run_id]

    disk = RESULTS_DIR / f"{run_id}.json"
    if disk.exists():
        data = json.loads(disk.read_text())
        _results_cache[run_id] = data
        return data
    return None


def _list_runs() -> list[dict]:
    seen = set()
    runs = []

    for f in sorted(RESULTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        if f.stem == "latest":
            continue
        try:
            data = json.loads(f.read_text())
            rid = data["run_id"]
            if rid not in seen:
                seen.add(rid)
                runs.append({
                    "run_id": rid,
                    "tool": data.get("tool"),
                    "path": data.get("path"),
                    "timestamp": data.get("timestamp"),
                })
        except Exception:
            continue

    # in-memory additions
    for rid, data in _results_cache.items():
        if rid == "latest" or rid in seen:
            continue
        seen.add(rid)
        runs.append({
            "run_id": rid,
            "tool": data.get("tool"),
            "path": data.get("path"),
            "timestamp": data.get("timestamp"),
        })

    return runs


def _run_analysis(
    path: str,
    confidence: int = 60,
    exclude_folders: list[str] | None = None,
    enable_secrets: bool = False,
    enable_danger: bool = False,
    enable_quality: bool = False,
) -> dict:
    analyze = _lazy_analyze()
    parse_exclude_folders, _ = _lazy_constants()

    if exclude_folders is None:
        exclude_folders = list(parse_exclude_folders())

    result_json = analyze(
        path,
        conf=confidence,
        exclude_folders=exclude_folders,
        enable_secrets=enable_secrets,
        enable_danger=enable_danger,
        enable_quality=enable_quality,
    )
    return json.loads(result_json)


def _make_summary(result: dict, focus: str | None = None) -> dict:
    summary = result.get("analysis_summary", {})
    out: dict[str, Any] = {"analysis_summary": summary}

    if focus is None or focus == "dead_code":
        for key in [
            "unused_functions", "unused_imports", "unused_classes",
            "unused_variables", "unused_parameters", "unused_files",
        ]:
            items = result.get(key, [])
            if items:
                out[key] = items

    if focus is None or focus == "security":
        if result.get("danger"):
            out["danger"] = result["danger"]

    if focus is None or focus == "quality":
        if result.get("quality"):
            out["quality"] = result["quality"]
        if result.get("circular_dependencies"):
            out["circular_dependencies"] = result["circular_dependencies"]
        if result.get("custom_rules"):
            out["custom_rules"] = result["custom_rules"]

    if focus is None or focus == "secrets":
        if result.get("secrets"):
            out["secrets"] = result["secrets"]

    return out


mcp = FastMCP(
    name = "skylos",
    port = 8080
)


@mcp.tool()
def analyze(
    path: str,
    confidence: int = 60,
    exclude_folders: list[str] | None = None,
) -> str:
    result = _run_analysis(
        path,
        confidence=confidence,
        exclude_folders=exclude_folders,
        enable_secrets=False,
        enable_danger=False,
        enable_quality=False,
    )
    summary = _make_summary(result, focus="dead_code")
    run_id = _store_result(result, "analyze", path)
    summary["_run_id"] = run_id
    return json.dumps(summary, indent=2)


@mcp.tool()
def security_scan(
    path: str,
    confidence: int = 60,
    exclude_folders: list[str] | None = None,
) -> str:
    result = _run_analysis(
        path,
        confidence=confidence,
        exclude_folders=exclude_folders,
        enable_danger=True,
    )
    summary = _make_summary(result, focus="security")
    run_id = _store_result(result, "security_scan", path)
    summary["_run_id"] = run_id
    return json.dumps(summary, indent=2)


@mcp.tool()
def quality_check(
    path: str,
    confidence: int = 60,
    exclude_folders: list[str] | None = None,
) -> str:
    result = _run_analysis(
        path,
        confidence=confidence,
        exclude_folders=exclude_folders,
        enable_quality=True,
    )
    summary = _make_summary(result, focus="quality")
    run_id = _store_result(result, "quality_check", path)
    summary["_run_id"] = run_id
    return json.dumps(summary, indent=2)


@mcp.tool()
def secrets_scan(
    path: str,
    confidence: int = 60,
    exclude_folders: list[str] | None = None,
) -> str:
    result = _run_analysis(
        path,
        confidence=confidence,
        exclude_folders=exclude_folders,
        enable_secrets=True,
    )
    summary = _make_summary(result, focus="secrets")
    run_id = _store_result(result, "secrets_scan", path)
    summary["_run_id"] = run_id
    return json.dumps(summary, indent=2)


@mcp.tool()
def remediate(
    path: str,
    max_fixes: int = 5,
    dry_run: bool = True,
    model: str = "gpt-4.1",
    test_cmd: str | None = None,
    severity: str | None = None,
) -> str:
    """Scan for security/quality issues, generate fixes, validate with tests.

    Returns a remediation plan with status of each fix attempt.
    Set dry_run=False to actually apply fixes to disk.
    """
    try:
        from skylos.llm.orchestrator import RemediationAgent

        agent = RemediationAgent(
            model=model,
            test_cmd=test_cmd,
            severity_filter=severity,
        )
        summary = agent.run(
            path,
            dry_run=dry_run,
            max_fixes=max_fixes,
            quiet=True,
        )
        return json.dumps(summary, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.resource("skylos://results/latest")
def get_latest_result() -> str:
    data = _load_result("latest")
    if data is None:
        return json.dumps({"error": "No analysis has been run yet."})
    return json.dumps(data, indent=2)


@mcp.resource("skylos://results/{run_id}")
def get_result_by_id(run_id: str) -> str:
    data = _load_result(run_id)
    if data is None:
        return json.dumps({"error": f"Run '{run_id}' not found."})
    return json.dumps(data, indent=2)


@mcp.resource("skylos://results")
def list_results() -> str:
    return json.dumps(_list_runs(), indent=2)


def main():
    mcp.run()


if __name__ == "__main__":
    main()