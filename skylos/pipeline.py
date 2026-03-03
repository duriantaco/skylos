from __future__ import annotations

import json
import logging
import pathlib
from pathlib import Path

logger = logging.getLogger(__name__)


_SUGGEST_PROMPT = """You are a code reviewer. Given the source code and a list of findings (security, quality, dead code), provide the problematic code snippet and the fixed code snippet for each finding.

SOURCE CODE ({file}):
```python
{source}
```

FINDINGS:
{findings_text}

For each finding, respond with a JSON array. Each element:
{{
  "line": <int>,
  "rule_id": "<str>",
  "explanation": "<1-2 sentences: why this is a problem in this specific context>",
  "vulnerable_code": "<the problematic line(s) with 2 lines before and 2 lines after for context>",
  "fixed_code": "<the corrected version of the same snippet, same 2 lines before and after>"
}}

RULES:
- vulnerable_code: copy the EXACT problematic line(s) from the source, plus 2 lines before and 2 lines after for context. Do NOT include the entire function or file.
- fixed_code: show the same snippet with ONLY the problematic line(s) changed. The 2 context lines before/after stay the same.
- For dead code / unused imports: the fix is to remove the unused line(s).
- For quality issues: show the improved version.
- Keep the same variable/function names.
Output ONLY the JSON array, no markdown."""


def _enrich_with_llm_suggestions(
    findings: list[dict],
    source_cache: dict[str, str],
    model: str,
    api_key: str,
) -> None:
    from litellm import completion

    by_file: dict[str, list[dict]] = {}
    for f in findings:
        fp = f.get("file", "")
        by_file.setdefault(fp, []).append(f)

    for filepath, file_findings in by_file.items():
        source = source_cache.get(_norm(filepath), "")
        if not source:
            try:
                source = pathlib.Path(filepath).read_text(
                    encoding="utf-8", errors="ignore"
                )
            except Exception:
                continue

        findings_text = "\n".join(
            f"- Line {f.get('line')}: [{f.get('rule_id', '')}] {f.get('message', '')}"
            for f in file_findings
        )

        prompt = _SUGGEST_PROMPT.format(
            file=pathlib.Path(filepath).name,
            source=source,
            findings_text=findings_text,
        )

        try:
            resp = completion(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                api_key=api_key,
                temperature=0,
                max_tokens=4000,
            )
            raw = resp.choices[0].message.content.strip()
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1]
                raw = raw.rsplit("```", 1)[0]

            suggestions = json.loads(raw)
            logger.debug(
                "LLM returned %d suggestions for %s", len(suggestions), filepath
            )

            for s in suggestions:
                matched = False
                for f in file_findings:
                    if f.get("fixed_code"):
                        continue
                    s_rule = s.get("rule_id", "")
                    f_rule = f.get("rule_id", "")
                    same_line = f.get("line") == s.get("line")
                    same_rule = f_rule and s_rule and f_rule == s_rule
                    if same_line and (same_rule or not f_rule or not s_rule):
                        if s.get("explanation"):
                            f["explanation"] = s["explanation"]
                        if s.get("vulnerable_code"):
                            f["vulnerable_code"] = s["vulnerable_code"]
                        if s.get("fixed_code"):
                            f["fixed_code"] = s["fixed_code"]
                        matched = True
                        break
                if not matched:
                    logger.debug(
                        "No match for suggestion line=%s rule=%s (findings: %s)",
                        s.get("line"),
                        s.get("rule_id"),
                        [(f.get("line"), f.get("rule_id")) for f in file_findings],
                    )
        except Exception as e:
            logger.warning(f"LLM suggestion failed for {filepath}: {e}")


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
    exclude_folders=None,
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
            exclude_folders=list(exclude_folders or parse_exclude_folders()),
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
    exclude_folders=None,
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
                        conf=10,
                        enable_secrets=True,
                        enable_danger=True,
                        enable_quality=True,
                        exclude_folders=exclude_folders,
                    )
                else:
                    from skylos.constants import parse_exclude_folders

                    result_json = run_analyze(
                        str(path),
                        conf=10,
                        enable_secrets=True,
                        enable_danger=True,
                        enable_quality=True,
                        exclude_folders=list(
                            exclude_folders or parse_exclude_folders()
                        ),
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
        _exc = (
            set(exclude_folders)
            if exclude_folders
            else {"__pycache__", ".git", "venv", ".venv"}
        )
        files = [f for f in path.rglob("*.py") if not any(ex in f.parts for ex in _exc)]

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

    low_conf = [f for f in dead_code_findings if f.get("confidence", 100) < 20]
    if low_conf:
        logger.info(f"DEBUG: Found {len(low_conf)} findings with conf < 20:")
        for f in low_conf[:5]:
            logger.info(f"  {f.get('name')} conf={f.get('confidence')}")

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

            console.print("[brand]Testing LLM API connection...[/brand]")
            api_ok, api_message = verifier.test_api_connection()
            if not api_ok:
                console.print(f"[bad]✗ LLM API test failed:[/bad] {api_message}")
                console.print("[bad]Cannot run LLM verification. Skipping...[/bad]")
                console.print(
                    "[dim]Tip: Run 'skylos key' to configure your API key[/dim]"
                )
                for f in dead_code_findings:
                    f["_confidence"] = "medium"
                    f["_llm_skipped"] = True
                    all_findings.append(f)
                raise Exception("LLM API unavailable")
            console.print(f"[good]✓[/good] {api_message}")

            verified = verifier.annotate_findings(
                findings=dead_code_findings,
                defs_map=defs_map,
                source_cache=source_cache,
                confidence_range=(
                    10,
                    100,
                ),
            )

            tp = sum(1 for f in verified if f.get("_llm_verdict") == "TRUE_POSITIVE")
            fp = sum(1 for f in verified if f.get("_llm_verdict") == "FALSE_POSITIVE")
            unc = sum(1 for f in verified if f.get("_llm_verdict") == "UNCERTAIN")

            console.print(
                f"[good]✓ Verified:[/good] {tp} confirmed dead, "
                f"{fp} likely alive (suppressed), {unc} uncertain"
            )

            for f in verified:
                verdict = f.get("_llm_verdict", "UNCERTAIN")
                if verdict == "TRUE_POSITIVE":
                    f["_source"] = "static+llm"
                    f["_confidence"] = "high"
                    f["_suppressed"] = False
                elif verdict == "UNCERTAIN":
                    f["_source"] = "static"
                    f["_confidence"] = "medium"
                    f["_suppressed"] = False
                    f["_llm_uncertain"] = True
                elif verdict == "FALSE_POSITIVE":
                    f["_source"] = "static"
                    f["_confidence"] = "low"
                    f["_suppressed"] = False
                    f["_llm_challenged"] = True
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
                        "explanation": finding.explanation,
                        "suggestion": finding.suggestion,
                        "_source": "llm",
                        "_category": issue_type,
                        "_confidence": "medium",
                        "_needs_review": True,
                        "_ci_blocking": False,
                    }

                    dup = _find_duplicate(llm_finding, all_findings)
                    if dup is not None:
                        if llm_finding.get("suggestion") and not dup.get("suggestion"):
                            dup["suggestion"] = llm_finding["suggestion"]
                        if llm_finding.get("explanation") and not dup.get(
                            "explanation"
                        ):
                            dup["explanation"] = llm_finding["explanation"]
                    else:
                        all_findings.append(llm_finding)
                        llm_only_count += 1

                console.print(
                    f"[good]✓ LLM:[/good] {llm_only_count} additional findings "
                    f"(all marked needs_review)"
                )

        except Exception as e:
            console.print(f"[warn]LLM analysis failed: {e}[/warn]")

    enrich_findings = [f for f in all_findings if not f.get("fixed_code")]
    if enrich_findings and not getattr(agent_args, "static_only", False):
        console.print(
            f"[brand]Phase 3:[/brand] LLM generating fix suggestions for "
            f"{len(enrich_findings)} findings..."
        )
        try:
            _enrich_with_llm_suggestions(enrich_findings, source_cache, model, api_key)
            enriched = sum(1 for f in enrich_findings if f.get("fixed_code"))
            console.print(
                f"[good]✓ Suggestions:[/good] {enriched}/{len(enrich_findings)} "
                f"findings enriched with fix advice"
            )
        except Exception as e:
            console.print(f"[warn]LLM suggestion generation failed: {e}[/warn]")

    def sort_key(f):
        conf_order = 0 if f.get("_confidence") == "high" else 1
        return (conf_order, f.get("file", ""), f.get("line", 0))

    all_findings.sort(key=sort_key)

    return all_findings


def _find_duplicate(new_finding, existing_findings, line_tolerance=3):
    new_file = _norm(new_finding.get("file", ""))
    new_line = new_finding.get("line", 0)
    new_msg = new_finding.get("message", "")[:40].lower()
    new_rule = new_finding.get("rule_id", "")

    for existing in existing_findings:
        if _norm(existing.get("file", "")) != new_file:
            continue
        if abs(existing.get("line", 0) - new_line) > line_tolerance:
            continue
        if new_rule and new_rule == existing.get("rule_id", ""):
            return existing
        if new_msg and new_msg in existing.get("message", "").lower():
            return existing

    return None


def _is_duplicate(new_finding, existing_findings, line_tolerance=3):
    return _find_duplicate(new_finding, existing_findings, line_tolerance) is not None
