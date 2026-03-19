from __future__ import annotations

import json
import hashlib
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skylos_mcp.auth import (
    initialize_auth,
    check_tool_access,
    deduct_credits,
)


def _lazy_analyze():
    from skylos.analyzer import analyze as run_analyze

    return run_analyze


def _lazy_constants():
    from skylos.constants import parse_exclude_folders, DEFAULT_EXCLUDE_FOLDERS

    return parse_exclude_folders, DEFAULT_EXCLUDE_FOLDERS


logger = logging.getLogger("skylos-mcp")


RESULTS_DIR = Path(
    os.getenv("SKYLOS_MCP_RESULTS_DIR", Path.home() / ".skylos" / "mcp_results")
)
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

    _results_cache[run_id] = envelope
    _results_cache["latest"] = envelope

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

    for f in sorted(
        RESULTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True
    ):
        if f.stem == "latest":
            continue
        try:
            data = json.loads(f.read_text())
            rid = data["run_id"]
            if rid not in seen:
                seen.add(rid)
                runs.append(
                    {
                        "run_id": rid,
                        "tool": data.get("tool"),
                        "path": data.get("path"),
                        "timestamp": data.get("timestamp"),
                    }
                )
        except (OSError, json.JSONDecodeError, KeyError):
            continue

    for rid, data in _results_cache.items():
        if rid == "latest" or rid in seen:
            continue
        seen.add(rid)
        runs.append(
            {
                "run_id": rid,
                "tool": data.get("tool"),
                "path": data.get("path"),
                "timestamp": data.get("timestamp"),
            }
        )

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
            "unused_functions",
            "unused_imports",
            "unused_classes",
            "unused_variables",
            "unused_parameters",
            "unused_files",
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


def _gate(tool_name: str) -> str | None:
    allowed, err = check_tool_access(tool_name)
    if not allowed:
        return json.dumps({"error": err})

    ok, credit_err = deduct_credits(tool_name)
    if not ok:
        return json.dumps({"error": credit_err})

    return None


def _register_tools(mcp):
    """Register all MCP tools and resources. Called inside main() after FastMCP is created."""

    ## all of these look like dead but they're all registered inside `_register_tools()` which is
    ## called from main() .. please ignore the "unused function" warnings for these --- IGNORE ---
    @mcp.tool()
    def analyze(
        path: str,
        confidence: int = 60,
        exclude_folders: list[str] | None = None,
    ) -> str:
        gate_err = _gate("analyze")
        if gate_err:
            return gate_err

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
        gate_err = _gate("security_scan")
        if gate_err:
            return gate_err

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
        gate_err = _gate("quality_check")
        if gate_err:
            return gate_err

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
        gate_err = _gate("secrets_scan")
        if gate_err:
            return gate_err

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
        gate_err = _gate("remediate")
        if gate_err:
            return gate_err

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

    @mcp.tool()
    def verify_dead_code(
        path: str,
        confidence: int = 60,
        model: str = "gpt-4.1",
        max_verify: int = 30,
        max_challenge: int = 10,
        exclude_folders: str | None = None,
    ) -> str:
        gate_err = _gate("verify_dead_code")
        if gate_err:
            return gate_err

        try:
            run_analyze = _lazy_analyze()
            parse_exclude_folders, _ = _lazy_constants()

            excl = list(parse_exclude_folders(use_defaults=True))
            if exclude_folders:
                for f in exclude_folders.split(","):
                    f = f.strip()
                    if f:
                        excl.append(f)

            raw = run_analyze(str(path), conf=confidence, exclude_folders=excl)
            static_result = json.loads(raw) if isinstance(raw, str) else raw

            all_findings = []
            for key in (
                "unused_functions",
                "unused_classes",
                "unused_variables",
                "unused_imports",
            ):
                all_findings.extend(static_result.get(key, []))

            defs_map = static_result.get("definitions", {})

            if not all_findings:
                return json.dumps(
                    {"message": "No dead code findings to verify", "stats": {}}
                )

            from skylos.llm.verify_orchestrator import run_verification

            result = run_verification(
                findings=all_findings,
                defs_map=defs_map,
                project_root=str(path),
                model=model,
                max_verify=max_verify,
                max_challenge=max_challenge,
                quiet=True,
            )

            _store_result(result, "verify_dead_code", path)
            return json.dumps(result, indent=2, default=str)

        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def provenance_scan(path: str, diff_base: str | None = None) -> str:
        gate_err = _gate("provenance_scan")
        if gate_err:
            return gate_err

        try:
            from skylos.provenance import analyze_provenance
            from skylos.api import get_git_root

            target = os.path.abspath(path)
            git_root = get_git_root() or target
            report = analyze_provenance(git_root, base_ref=diff_base)
            result = report.to_dict()
            _store_result(result, "provenance_scan", path)
            return json.dumps(result, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def generate_fix(
        path: str,
        mode: str = "delete",
        min_safety: float = 0.0,
        apply: bool = False,
    ) -> str:
        gate_err = _gate("generate_fix")
        if gate_err:
            return gate_err

        try:
            from skylos.analyzer import analyze as run_static
            from skylos.dead_code import collect_dead_code_findings
            from skylos.fixgen import (
                generate_removal_plan,
                generate_unified_diff,
                apply_patches,
                validate_patches,
                generate_fix_summary,
            )
            from skylos.grep_verify import grep_verify_findings

            target = os.path.abspath(path)
            raw = run_static(
                target,
                conf=60,
                enable_danger=False,
                enable_quality=False,
                enable_secrets=False,
            )
            static_result = json.loads(raw) if isinstance(raw, str) else raw
            all_findings = collect_dead_code_findings(static_result)
            defs_map = static_result.get("definitions", {})

            # use grep verification to filter
            verdicts = grep_verify_findings(all_findings, target, time_budget=30.0)
            dead_findings = [
                f
                for f in all_findings
                if f.get("full_name", f.get("name", "")) not in verdicts
            ]

            patches = generate_removal_plan(
                dead_findings,
                defs_map,
                target,
                mode=mode,
                min_safety=min_safety,
            )
            errors = validate_patches(patches, target)
            diff = generate_unified_diff(patches, target)
            summary = generate_fix_summary(patches)

            result = {
                "patches": len(patches),
                "summary": summary,
                "errors": errors,
                "diff": diff,
                "applied": False,
            }

            if apply and not errors:
                apply_patches(patches, target, dry_run=False)
                result["applied"] = True

            _store_result(result, "generate_fix", path)
            return json.dumps(result, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def learn_triage(
        path: str,
        action_id: str,
        action: str,
    ) -> str:
        gate_err = _gate("learn_triage")
        if gate_err:
            return gate_err

        try:
            from skylos.agent_service import AgentServiceController

            controller = AgentServiceController(os.path.abspath(path))
            result = controller.learn_triage(action_id, action)
            _store_result(result, "learn_triage", path)
            return json.dumps(result, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def get_triage_suggestions(
        path: str,
    ) -> str:

        gate_err = _gate("get_triage_suggestions")
        if gate_err:
            return gate_err

        try:
            from skylos.agent_service import AgentServiceController

            controller = AgentServiceController(os.path.abspath(path))
            result = controller.get_suggestions()
            _store_result(result, "get_triage_suggestions", path)
            return json.dumps(result, indent=2)
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
    try:
        from mcp.server.fastmcp import FastMCP

        initialize_auth()

        transport = os.getenv("MCP_TRANSPORT", "stdio")

        if transport in ("sse", "streamable-http"):
            host = os.getenv("MCP_BIND", "127.0.0.1")
            port = int(os.getenv("PORT", "8080"))
            mcp_server = FastMCP(name="skylos", host=host, port=port)
        else:
            mcp_server = FastMCP(name="skylos")

        _register_tools(mcp_server)
        mcp_server.run(transport=transport)
    except Exception:
        import sys
        import traceback

        traceback.print_exc(file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
