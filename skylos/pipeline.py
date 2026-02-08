from __future__ import annotations

import json
import logging
import pathlib
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _norm(p) -> str:
    try:
        return str(Path(p).resolve())
    except Exception:
        return str(p)


def _empty_result() -> dict:
    return {
        "definitions": {},
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_parameters": [],
        "unused_classes": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }


def _infer_root(path) -> Path:
    cur = Path(path).resolve()
    if cur.is_file():
        cur = cur.parent
    for _ in range(20):
        if (cur / ".git").exists() or (cur / "pyproject.toml").exists():
            return cur
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    return Path.cwd().resolve()


def run_static_on_files(
    files,
    *,
    project_root=None,
    conf=60,
    enable_secrets=True,
    enable_danger=True,
    enable_quality=True,
):
    import os

    from skylos.analyzer import analyze as run_analyze

    if not files:
        return _empty_result()

    if project_root is None:
        project_root = _infer_root(files[0])

    target_files = {_norm(f) for f in files}

    try:
        from skylos.sync import get_custom_rules

        custom_rules_data = get_custom_rules()
        if custom_rules_data:
            os.environ["SKYLOS_CUSTOM_RULES"] = json.dumps(custom_rules_data)
    except Exception:
        pass

    try:
        from skylos.constants import parse_exclude_folders

        result_json = run_analyze(
            str(project_root),
            conf=conf,
            enable_secrets=enable_secrets,
            enable_danger=enable_danger,
            enable_quality=enable_quality,
            exclude_folders=list(parse_exclude_folders()),
        )
        full_result = json.loads(result_json)
    except Exception:
        return _empty_result()

    filtered = {
        "definitions": full_result.get("definitions", {}),
    }

    finding_keys = [
        "unused_functions",
        "unused_imports",
        "unused_variables",
        "unused_parameters",
        "unused_classes",
        "danger",
        "quality",
        "secrets",
    ]
    for key in finding_keys:
        filtered[key] = []
        for item in full_result.get(key, []) or []:
            item_file = item.get("file", "")
            if _norm(item_file) in target_files:
                filtered[key].append(item)

    if "analysis_summary" in full_result:
        filtered["analysis_summary"] = full_result["analysis_summary"]

    return filtered


def run_pipeline(
    path,
    model,
    api_key,
    agent_args,
    console,
    *,
    changed_files=None,
):
    import sys
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from skylos.analyzer import analyze as run_analyze
    from skylos.llm.analyzer import SkylosLLM, AnalyzerConfig
    from skylos.llm.schemas import Confidence

    path = pathlib.Path(path)
    if not path.exists():
        console.print(f"[bad]Path not found: {path}[/bad]")
        sys.exit(1)

    all_findings = []
    defs_map = {}
    source_cache = {}

    static_findings = {
        "dead_code": [],
        "security": [],
        "quality": [],
        "secrets": [],
    }

    if not getattr(agent_args, "llm_only", False):
        console.print(
            "[brand]Phase 1:[/brand] Running static analysis (global index)..."
        )

        try:
            with Progress(
                SpinnerColumn(style="brand"),
                TextColumn("[brand]Skylos[/brand] {task.description}"),
                transient=True,
                console=console,
            ) as progress:
                task = progress.add_task("static analysis...", total=None)

                if changed_files:
                    static_result = run_static_on_files(
                        changed_files,
                        project_root=path if path.is_dir() else path.parent,
                        conf=60,
                        enable_secrets=True,
                        enable_danger=True,
                        enable_quality=True,
                    )
                else:
                    from skylos.constants import parse_exclude_folders

                    result_json = run_analyze(
                        str(path),
                        conf=60,
                        enable_secrets=True,
                        enable_danger=True,
                        enable_quality=True,
                        exclude_folders=list(parse_exclude_folders()),
                        progress_callback=lambda cur, tot, f: progress.update(
                            task, description=f"[{cur}/{tot}] {f.name}"
                        ),
                    )
                    static_result = json.loads(result_json)

            defs_map = static_result.get("definitions", {}) or {}

            for item in static_result.get("danger", []) or []:
                item["_source"] = "static"
                item["_category"] = "security"
                static_findings["security"].append(item)

            for item in static_result.get("quality", []) or []:
                item["_source"] = "static"
                item["_category"] = "quality"
                static_findings["quality"].append(item)

            for item in static_result.get("secrets", []) or []:
                item["_source"] = "static"
                item["_category"] = "secret"
                static_findings["secrets"].append(item)

            for key in [
                "unused_functions",
                "unused_imports",
                "unused_variables",
                "unused_classes",
                "unused_parameters",
            ]:
                for item in static_result.get(key, []) or []:
                    item["_source"] = "static"
                    item["_category"] = "dead_code"
                    item["message"] = (
                        item.get("message")
                        or f"Unused {key.replace('unused_', '')}: {item.get('name')}"
                    )
                    static_findings["dead_code"].append(item)

            total_static = sum(len(v) for v in static_findings.values())
            console.print(
                f"[good]✓ Static:[/good] {len(defs_map)} definitions, "
                f"{total_static} findings "
                f"({len(static_findings['dead_code'])} dead code, "
                f"{len(static_findings['security'])} security, "
                f"{len(static_findings['quality'])} quality)"
            )

        except Exception as e:
            console.print(f"[warn]Static analysis failed: {e}[/warn]")

    if path.is_file():
        files = [path]
    else:
        files = [
            f
            for f in path.rglob("*.py")
            if not any(ex in f.parts for ex in ["__pycache__", ".git", "venv", ".venv"])
        ]

    if changed_files:
        files = changed_files

    for f in files:
        try:
            source_cache[_norm(f)] = pathlib.Path(f).read_text(
                encoding="utf-8", errors="ignore"
            )
        except Exception:
            pass

    dead_code_findings = static_findings.get("dead_code", [])

    if dead_code_findings and not getattr(agent_args, "skip_verification", False):
        console.print(
            f"[brand]Phase 2a:[/brand] LLM verifying "
            f"{len(dead_code_findings)} dead-code findings..."
        )

        try:
            from skylos.llm.agents import AgentConfig
            from skylos.llm.dead_code_verifier import DeadCodeVerifierAgent

            verifier_config = AgentConfig(model=model, api_key=api_key)
            verifier = DeadCodeVerifierAgent(verifier_config)

            verified = verifier.annotate_findings(
                findings=dead_code_findings,
                defs_map=defs_map,
                source_cache=source_cache,
                confidence_range=(50, 85),
            )

            tp = sum(1 for f in verified if f.get("_llm_verdict") == "TRUE_POSITIVE")
            fp = sum(1 for f in verified if f.get("_llm_verdict") == "FALSE_POSITIVE")
            unc = sum(1 for f in verified if f.get("_llm_verdict") == "UNCERTAIN")

            console.print(
                f"[good]✓ Verified:[/good] {tp} confirmed dead, "
                f"{fp} likely alive (suppressed), {unc} uncertain"
            )

            for f in verified:
                if not f.get("_suppressed"):
                    if f.get("_llm_verdict") == "TRUE_POSITIVE":
                        f["_source"] = "static+llm"
                        f["_confidence"] = "high"
                    else:
                        f["_confidence"] = "medium"
                    all_findings.append(f)

        except Exception as e:
            console.print(f"[warn]LLM verification failed: {e}[/warn]")
            for f in dead_code_findings:
                f["_confidence"] = "medium"
                all_findings.append(f)
    else:
        for f in dead_code_findings:
            f["_confidence"] = "medium"
            all_findings.append(f)

    for category in ["security", "quality", "secrets"]:
        for f in static_findings.get(category, []):
            f["_confidence"] = "medium"
            all_findings.append(f)

    if not getattr(agent_args, "static_only", False):
        console.print("[brand]Phase 2b:[/brand] LLM security & quality analysis...")

        min_conf_map = {
            "high": Confidence.HIGH,
            "medium": Confidence.MEDIUM,
            "low": Confidence.LOW,
        }
        config = AnalyzerConfig(
            model=model,
            api_key=api_key,
            quiet=getattr(agent_args, "quiet", False),
            min_confidence=min_conf_map.get(
                getattr(agent_args, "min_confidence", "low"), Confidence.LOW
            ),
        )
        analyzer = SkylosLLM(config)

        try:
            if files:
                llm_result = analyzer.analyze_files(files, defs_map=defs_map)

                llm_only_count = 0
                for finding in llm_result.findings:
                    issue_type = (
                        finding.issue_type.value
                        if hasattr(finding.issue_type, "value")
                        else str(finding.issue_type)
                    )

                    if issue_type.lower() in ("dead_code", "unused", "unreachable"):
                        continue

                    llm_finding = {
                        "file": finding.location.file,
                        "line": finding.location.line,
                        "message": finding.message,
                        "rule_id": finding.rule_id,
                        "severity": (
                            finding.severity.value
                            if hasattr(finding.severity, "value")
                            else str(finding.severity)
                        ),
                        "confidence": (
                            finding.confidence.value
                            if hasattr(finding.confidence, "value")
                            else str(finding.confidence)
                        ),
                        "_source": "llm",
                        "_category": issue_type,
                        "_confidence": "medium",
                        "_needs_review": True,
                        "_ci_blocking": False,
                    }

                    if not _is_duplicate(llm_finding, all_findings):
                        all_findings.append(llm_finding)
                        llm_only_count += 1

                console.print(
                    f"[good]✓ LLM:[/good] {llm_only_count} additional findings "
                    f"(all marked needs_review)"
                )

        except Exception as e:
            console.print(f"[warn]LLM analysis failed: {e}[/warn]")

    def sort_key(f):
        conf_order = 0 if f.get("_confidence") == "high" else 1
        return (conf_order, f.get("file", ""), f.get("line", 0))

    all_findings.sort(key=sort_key)

    return all_findings


def _is_duplicate(new_finding, existing_findings, line_tolerance=3):
    new_file = _norm(new_finding.get("file", ""))
    new_line = new_finding.get("line", 0)
    new_msg = new_finding.get("message", "")[:40].lower()

    for existing in existing_findings:
        if _norm(existing.get("file", "")) != new_file:
            continue
        if abs(existing.get("line", 0) - new_line) > line_tolerance:
            continue
        if new_msg and new_msg in existing.get("message", "").lower():
            return True

    return False
