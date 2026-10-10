from __future__ import annotations

import json
import hashlib
import inspect
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field

from skylos.analysis.errors import analysis_result_incomplete
from skylos_mcp.auth import (
    UNAUTH_DAILY_LIMIT,
    UNAUTHENTICATED_TOOLS,
    build_mcp_network_auth,
    check_mcp_client_context,
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


RESULTS_DIR = (
    Path(os.getenv("SKYLOS_MCP_RESULTS_DIR", Path.home() / ".skylos" / "mcp_results"))
    .expanduser()
    .resolve()
)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

_results_cache: dict[str, dict[str, Any]] = {}
_RUN_ID_RE = re.compile(r"^[a-f0-9]{12}$")
_REQUIRE_MCP_CLIENT_AUTH_CONTEXT = False


def _make_run_id(tool: str, path: str, ts: str) -> str:
    return hashlib.sha256(f"{ts}-{tool}-{path}".encode()).hexdigest()[:12]


def _validate_run_id(run_id: str) -> str | None:
    candidate = str(run_id or "")
    if candidate == "latest":
        return candidate
    if _RUN_ID_RE.fullmatch(candidate):
        return candidate
    return None


def _result_path(run_id: str) -> Path | None:
    safe_id = _validate_run_id(run_id)
    if safe_id is None:
        return None
    candidate = (RESULTS_DIR / f"{safe_id}.json").resolve()
    try:
        candidate.relative_to(RESULTS_DIR)
    except ValueError:
        return None
    return candidate


def _store_result(result: dict, tool: str, path: str) -> str:
    ts = datetime.now(timezone.utc).isoformat()
    run_id = _make_run_id(tool, path, ts)

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
        run_path = _result_path(run_id)
        latest_path = _result_path("latest")
        if run_path is not None:
            run_path.write_text(json.dumps(envelope, indent=2))
        if latest_path is not None:
            latest_path.write_text(json.dumps(envelope, indent=2))
    except OSError as exc:
        logger.warning("Could not persist result to disk: %s", exc)

    return run_id


def _load_result(run_id: str) -> dict | None:
    safe_id = _validate_run_id(run_id)
    if safe_id is None:
        return None
    if safe_id in _results_cache:
        return _results_cache[safe_id]

    disk = _result_path(safe_id)
    if disk is None:
        return None
    if disk.exists():
        data = json.loads(disk.read_text())
        _results_cache[safe_id] = data
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


def _validate_code_change_impl(
    diff: str,
    path: str = ".",
    policy: str | None = None,
    check_dependencies: bool = True,
) -> dict:
    """Core logic for validate_code_change, extracted for testability."""
    from skylos.rules.quality.regression import detect_security_regressions
    from skylos.rules.secrets import (
        PROVIDER_PATTERNS,
        GENERIC_VALUE,
        SAFE_TEST_HINTS,
        _entropy,
        DEFAULT_MIN_ENTROPY,
    )

    all_findings: list[dict] = []

    file_chunks: list[tuple[str, str]] = []
    current_file = None
    current_lines: list[str] = []

    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            if current_file and current_lines:
                file_chunks.append((current_file, "\n".join(current_lines)))
            current_file = line[6:]
            current_lines = [line]
        elif line.startswith("--- a/") or line.startswith("--- /dev/null"):
            current_lines.append(line)
        elif current_file is not None:
            current_lines.append(line)

    if current_file and current_lines:
        file_chunks.append((current_file, "\n".join(current_lines)))

    for file_path_chunk, chunk_text in file_chunks:
        regressions = detect_security_regressions(chunk_text, file_path_chunk)
        all_findings.extend(regressions)

    dangerous_calls = {
        "eval(": ("SKY-D201", "HIGH", "Use of eval()"),
        "exec(": ("SKY-D202", "HIGH", "Use of exec()"),
        "os.system(": ("SKY-D203", "CRITICAL", "Use of os.system()"),
        "pickle.load(": (
            "SKY-D204",
            "CRITICAL",
            "Untrusted deserialization via pickle.load",
        ),
        "pickle.loads(": (
            "SKY-D205",
            "CRITICAL",
            "Untrusted deserialization via pickle.loads",
        ),
        "yaml.load(": ("SKY-D206", "HIGH", "yaml.load without SafeLoader"),
        "marshal.loads(": (
            "SKY-D233",
            "CRITICAL",
            "Untrusted deserialization via marshal.loads",
        ),
        "__import__(": ("SKY-D240", "HIGH", "Dynamic import via __import__()"),
        "compile(": ("SKY-D241", "MEDIUM", "Dynamic code compilation"),
    }

    sql_injection_re = re.compile(
        r"""(?:execute|cursor\.execute|raw|text)\(\s*(?:f['"']|['"].*%[sd]|['"].*\+|.*\.format\()""",
    )

    for file_path_chunk, chunk_text in file_chunks:
        line_no = 0
        for raw_line in chunk_text.splitlines():
            if raw_line.startswith("@@"):
                m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", raw_line)
                if m:
                    line_no = int(m.group(1)) - 1
                continue
            if raw_line.startswith("+") and not raw_line.startswith("+++"):
                line_no += 1
                added = raw_line[1:]
                stripped = added.strip()

                for pattern, (rule_id, severity, msg) in dangerous_calls.items():
                    if pattern in stripped:
                        all_findings.append(
                            {
                                "rule_id": rule_id,
                                "kind": "dangerous_pattern",
                                "severity": severity,
                                "message": f"Dangerous pattern in added code: {msg}",
                                "file": file_path_chunk,
                                "line": line_no,
                                "col": 0,
                            }
                        )

                if sql_injection_re.search(stripped):
                    all_findings.append(
                        {
                            "rule_id": "SKY-D220",
                            "kind": "dangerous_pattern",
                            "severity": "CRITICAL",
                            "message": "Potential SQL injection in added code: string interpolation in query",
                            "file": file_path_chunk,
                            "line": line_no,
                            "col": 0,
                        }
                    )

                for provider, regex in PROVIDER_PATTERNS:
                    if regex.search(stripped):
                        all_findings.append(
                            {
                                "rule_id": "SKY-S101",
                                "kind": "secret",
                                "severity": "CRITICAL",
                                "message": f"Secret detected in added code: {provider} token/key",
                                "file": file_path_chunk,
                                "line": line_no,
                                "col": 0,
                            }
                        )

                for m_generic in GENERIC_VALUE.finditer(stripped):
                    val = m_generic.group("val") or m_generic.group("bare")
                    if val and _entropy(val) >= DEFAULT_MIN_ENTROPY:
                        if not any(hint in val.lower() for hint in SAFE_TEST_HINTS):
                            all_findings.append(
                                {
                                    "rule_id": "SKY-S101",
                                    "kind": "secret",
                                    "severity": "HIGH",
                                    "message": "Possible secret/credential in added code",
                                    "file": file_path_chunk,
                                    "line": line_no,
                                    "col": 0,
                                }
                            )
            elif not raw_line.startswith("-"):
                line_no += 1

    registry_status = "skipped"
    if check_dependencies:
        try:
            from skylos.rules.ai_defect.diff_dependencies import (
                scan_diff_dependency_hallucinations,
            )

            dep_result = scan_diff_dependency_hallucinations(
                diff, Path(path).resolve()
            )
        except Exception:
            registry_status = "error"
            logger.debug("Diff dependency check failed", exc_info=True)
        else:
            all_findings.extend(dep_result["findings"])
            registry_status = (
                "unreachable" if dep_result["registry_unreachable"] else "ok"
            )

    if policy:
        policy_path = Path(policy) if not Path(policy).is_absolute() else Path(policy)
        if not policy_path.exists():
            target_dir = Path(path).resolve()
            policy_path = target_dir / policy

    status = "fail" if all_findings else "pass"
    counts: dict[str, int] = {}
    for f in all_findings:
        kind = f.get("kind", "unknown")
        counts[kind] = counts.get(kind, 0) + 1

    parts = []
    for kind, count in sorted(counts.items()):
        label = kind.replace("_", " ")
        parts.append(f"{count} {label}{'s' if count != 1 else ''}")
    summary_text = ", ".join(parts) + " found" if parts else "No issues found"

    return {
        "status": status,
        "findings": all_findings,
        "summary": summary_text,
        "registry": registry_status,
    }


def _verify_change_impl(
    path: str = ".",
    file: str | None = None,
    line_range: str | None = None,
    confidence: int = 60,
    project_context: bool = False,
    include_dependency_hallucinations: bool = True,
    exclude_folders: str | None = None,
    contract_path: str | None = None,
    contract_enabled: bool = True,
    include_security_findings: bool = True,
) -> dict:
    """Core logic for verify_change, extracted for testability."""
    from skylos.verify_change import verify_change_path

    parse_exclude_folders, _ = _lazy_constants()
    excl = list(parse_exclude_folders(use_defaults=True))
    if exclude_folders:
        for folder in exclude_folders.split(","):
            folder = folder.strip()
            if folder:
                excl.append(folder)

    return verify_change_path(
        path,
        file=file,
        line_range=line_range,
        confidence=confidence,
        exclude_folders=excl,
        project_context=project_context,
        include_dependency_hallucinations=include_dependency_hallucinations,
        include_security_findings=include_security_findings,
        contract_path=contract_path,
        contract_enabled=contract_enabled,
    )


def _verify_agent_excludes(exclude_folders: str | None) -> set[str]:
    from skylos.commands.defend_cmd import DEFAULT_DEFEND_EXCLUDES, _build_defend_excludes

    extra = None
    if exclude_folders:
        extra = [folder.strip() for folder in exclude_folders.split(",")]
        extra = [folder for folder in extra if folder]
    return _build_defend_excludes(extra) if extra else set(DEFAULT_DEFEND_EXCLUDES)


def _agent_coverage_summary(coverage: dict) -> dict[str, int]:
    summary = {"covered": 0, "partial": 0, "uncovered": 0, "not_applicable": 0}
    for info in coverage.values():
        status = info.get("status")
        if status in summary:
            summary[status] += 1
    return summary


def _agent_failed_checks(results: list[Any]) -> list[dict[str, Any]]:
    failed_checks = []
    for result in results:
        if result.passed or result.category != "defense":
            continue
        failed_checks.append(
            {
                "plugin_id": result.plugin_id,
                "severity": result.severity,
                "integration_location": result.integration_location,
                "location": result.location,
                "message": result.message,
                "remediation": result.remediation,
                "owasp_llm": result.owasp_llm,
            }
        )
    return failed_checks


def _agent_gate(
    *,
    fail_on: str | None,
    min_score: int | None,
    results: list[Any],
    score: Any,
) -> dict[str, Any] | None:
    if not fail_on and min_score is None:
        return None

    from skylos.defend.scoring import evaluate_gate

    return {
        "fail_on": fail_on,
        "min_score": min_score,
        "passed": evaluate_gate(
            results,
            score,
            fail_on=fail_on,
            min_score=min_score,
        ),
    }


def _agent_attestation(
    *,
    target: Path,
    files: list[Path],
    results: list[Any],
    integrations: list[Any],
    score: Any,
    ops_score: Any,
    coverage: dict,
    framework_evidence: dict,
    owasp_framework: str,
    owasp_version: str,
) -> dict:
    from skylos.defend.attestation import build_attestation
    from skylos.defend.engine import resolve_active_plugin_ids

    return build_attestation(
        target=target,
        files=files,
        results=results,
        plugin_ids=resolve_active_plugin_ids(),
        policy_path=None,
        owasp_framework=owasp_framework,
        owasp_version=owasp_version,
        integrations=integrations,
        score=score,
        ops_score=ops_score,
        owasp_coverage=coverage,
        framework_evidence=framework_evidence,
    )


def _agent_response(
    *,
    target: Path,
    files: list[Path],
    integrations: list[Any],
    score: Any,
    ops_score: Any,
    failed_checks: list[dict[str, Any]],
    coverage_summary: dict[str, int],
    attestation: dict,
    gate: dict[str, Any] | None,
    owasp_framework: str,
    owasp_version: str,
) -> dict:
    return {
        "schema_version": 1,
        "tool": "verify_agent",
        "path": str(target),
        "integrations_found": len(integrations),
        "files_scanned": len(files),
        "defense_score": score.to_dict(),
        "ops_score": ops_score.to_dict(),
        "failed_checks": failed_checks,
        "owasp": {
            "framework": owasp_framework,
            "version": owasp_version,
            "coverage_summary": coverage_summary,
        },
        "attestation": {
            "algorithm": attestation["algorithm"],
            "digest": attestation["digest"],
        },
        "gate": gate,
        "summary": (
            f"Defense score {score.score_pct}% ({score.risk_rating}); "
            f"{len(failed_checks)} failed check(s) across "
            f"{len(integrations)} integration(s)"
        ),
    }


def _verify_agent_impl(
    path: str = ".",
    fail_on: str | None = None,
    min_score: int | None = None,
    owasp_framework: str = "llm",
    owasp_version: str | None = None,
    exclude_folders: str | None = None,
) -> dict:
    """Core logic for verify_agent, extracted for testability."""
    from skylos.defend.engine import run_defense_checks
    from skylos.defend.frameworks import compute_framework_evidence
    from skylos.defend.owasp import compute_owasp_coverage, normalize_owasp_selection
    from skylos.discover.detector import _collect_ai_files, detect_integrations

    target = Path(path).expanduser().resolve()
    if not target.is_dir():
        return {"error": f"Path is not a directory: {path}"}

    owasp_framework, owasp_version = normalize_owasp_selection(
        owasp_framework,
        owasp_version,
    )

    exclude = _verify_agent_excludes(exclude_folders)
    files = _collect_ai_files(target, exclude)
    integrations, graph = detect_integrations(target, exclude_folders=exclude)
    results, score, ops_score = run_defense_checks(
        integrations,
        graph,
        owasp_framework=owasp_framework,
        owasp_version=owasp_version,
    )

    coverage = compute_owasp_coverage(
        results,
        framework=owasp_framework,
        version=owasp_version,
    )
    framework_evidence = compute_framework_evidence(results)
    attestation = _agent_attestation(
        target=target,
        files=files,
        results=results,
        integrations=integrations,
        score=score,
        ops_score=ops_score,
        coverage=coverage,
        framework_evidence=framework_evidence,
        owasp_framework=owasp_framework,
        owasp_version=owasp_version,
    )

    return _agent_response(
        target=target,
        files=files,
        integrations=integrations,
        score=score,
        ops_score=ops_score,
        failed_checks=_agent_failed_checks(results),
        coverage_summary=_agent_coverage_summary(coverage),
        attestation=attestation,
        gate=_agent_gate(
            fail_on=fail_on,
            min_score=min_score,
            results=results,
            score=score,
        ),
        owasp_framework=owasp_framework,
        owasp_version=owasp_version,
    )


def _resolve_analysis_target(path: str) -> Path:
    return Path(path).expanduser().resolve()


def _resolve_policy_path(target: Path, policy_name: str) -> Path | None:
    candidate = (target / policy_name).resolve()
    try:
        candidate.relative_to(target)
    except ValueError:
        return None
    return candidate


def _get_security_context_impl(path: str) -> dict:
    """Core logic for get_security_context, extracted for testability."""
    target = _resolve_analysis_target(path)
    if not target.exists():
        return {"error": f"Path does not exist: {path}"}

    context: dict[str, Any] = {
        "project_path": str(target),
        "frameworks": [],
        "auth_patterns": [],
        "security_headers": [],
        "rate_limiting": [],
        "input_validation": [],
        "policy": None,
    }

    framework_indicators = {
        "Django": [
            "manage.py",
            "settings.py",
            "django.conf",
            "urls.py",
        ],
        "Flask": [
            "app.py",
            "wsgi.py",
        ],
        "FastAPI": [
            "main.py",
            "app.py",
        ],
        "Express": [
            "app.js",
            "server.js",
            "index.js",
        ],
        "Next.js": [
            "next.config.js",
            "next.config.mjs",
            "next.config.ts",
        ],
    }

    framework_imports = {
        "Django": re.compile(r"(?:from django|import django)"),
        "Flask": re.compile(r"(?:from flask |import flask)"),
        "FastAPI": re.compile(r"(?:from fastapi |import fastapi|FastAPI\(\))"),
        "Express": re.compile(
            r"""(?:require\(['"]express['"]\)|from ['"]express['"])"""
        ),
        "Next.js": re.compile(r"""(?:from ['"]next/|@next/)"""),
    }

    scan_files: list[Path] = []
    scan_extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs"}
    scan_names = set()
    for indicators in framework_indicators.values():
        scan_names.update(indicators)

    for item in target.rglob("*"):
        parts_item = item.parts
        if any(
            skip in parts_item
            for skip in ("node_modules", ".git", "__pycache__", "venv", ".venv", "env")
        ):
            continue
        if item.is_file():
            if item.name in scan_names or item.suffix in scan_extensions:
                scan_files.append(item)
        if len(scan_files) > 500:
            break

    detected_frameworks: set[str] = set()
    auth_patterns: set[str] = set()
    security_headers: set[str] = set()
    rate_limiting: set[str] = set()
    validation: set[str] = set()

    auth_decorator_re = re.compile(
        r"@(?:login_required|require_auth|requires_auth|authenticated|"
        r"permission_required|jwt_required|token_required|permissions_required)"
    )
    auth_depends_re = re.compile(
        r"Depends\((?:get_current_user|get_current_active_user|require_admin|verify_token)\)"
    )
    auth_middleware_re = re.compile(
        r"(?:AuthenticationMiddleware|SessionMiddleware|JWTAuthentication|"
        r"OAuth2PasswordBearer|HTTPBearer)"
    )

    header_names = {
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
    }
    header_middleware_re = re.compile(r"(?:SecurityMiddleware|helmet\(|secure_headers)")

    rate_limit_re = re.compile(
        r"(?:@(?:rate_limit|ratelimit|throttle|limiter\.limit)|"
        r"slowapi|RateLimitMiddleware|Throttle)"
    )

    validation_re = re.compile(
        r"(?:@(?:validate|validator|field_validator|validates)|"
        r"BaseModel|Pydantic|Schema\(|marshmallow|cerberus|"
        r"wtforms|FlaskForm|Serializer)"
    )

    for fpath in scan_files:
        try:
            content = fpath.read_text(errors="ignore")
        except OSError:
            continue

        for fw, regex in framework_imports.items():
            if regex.search(content):
                detected_frameworks.add(fw)

        for m in auth_decorator_re.finditer(content):
            auth_patterns.add(m.group(0))
        for m in auth_depends_re.finditer(content):
            auth_patterns.add(m.group(0))
        for m in auth_middleware_re.finditer(content):
            auth_patterns.add(m.group(0))

        for header in header_names:
            if header in content:
                security_headers.add(header)
        if header_middleware_re.search(content):
            security_headers.add("security_middleware_detected")

        for m in rate_limit_re.finditer(content):
            rate_limiting.add(m.group(0))

        for m in validation_re.finditer(content):
            validation.add(m.group(0))

    context["frameworks"] = sorted(detected_frameworks)
    context["auth_patterns"] = sorted(auth_patterns)
    context["security_headers"] = sorted(security_headers)
    context["rate_limiting"] = sorted(rate_limiting)
    context["input_validation"] = sorted(validation)

    for policy_name in (".skylos.yml", ".skylos.yaml", "skylos.yml", "skylos.yaml"):
        policy_path = _resolve_policy_path(target, policy_name)
        if policy_path is None:
            continue
        if policy_path.exists():
            try:
                import yaml

                context["policy"] = yaml.safe_load(policy_path.read_text())
            except Exception:
                context["policy"] = f"Found {policy_name} but could not parse"
            break

    return context


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


_ARCHITECTURE_RULE_IDS = {"SKY-Q701", "SKY-Q802", "SKY-Q803", "SKY-Q804", "SKY-Q805"}


def _is_architecture_finding(finding: dict) -> bool:
    return (
        finding.get("kind") == "architecture"
        or finding.get("rule_id") in _ARCHITECTURE_RULE_IDS
    )


def _make_summary(result: dict, focus: str | None = None) -> dict:
    summary = result.get("analysis_summary", {})
    out: dict[str, Any] = {"analysis_summary": summary}
    if result.get("analysis_errors"):
        out["analysis_errors"] = result["analysis_errors"]

    workspace_info = result.get("workspaces") or {}
    if (
        workspace_info.get("root_package")
        or workspace_info.get("packages")
        or workspace_info.get("diagnostics")
    ):
        out["workspaces"] = result["workspaces"]

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


def _architecture_payload(result: dict) -> dict:
    findings = [
        finding
        for finding in result.get("quality", []) or []
        if _is_architecture_finding(finding)
    ]
    payload: dict[str, Any] = {
        "analysis_summary": result.get("analysis_summary", {}),
        "architecture_metrics": result.get("architecture_metrics", {}),
        "findings": findings,
    }
    if result.get("circular_dependencies"):
        payload["circular_dependencies"] = result["circular_dependencies"]
    return payload


def _health_score_payload(result: dict) -> dict:
    summary = result.get("analysis_summary", {})
    grade = result.get("grade", {})
    categories = grade.get("categories", {}) if isinstance(grade, dict) else {}
    dead_code_count = sum(
        len(result.get(key, []) or [])
        for key in [
            "unused_functions",
            "unused_imports",
            "unused_classes",
            "unused_variables",
            "unused_parameters",
            "unused_files",
        ]
    )

    architecture_metrics = result.get("architecture_metrics", {}) or {}
    layer_policy = architecture_metrics.get("layer_policy", {}) or {}
    system_metrics = architecture_metrics.get("system_metrics", {}) or {}
    counts = {
        "dead_code": dead_code_count,
        "quality": summary.get("quality_count", 0),
        "security": summary.get("danger_count", 0),
        "secrets": summary.get("secrets_count", 0),
        "dependencies": summary.get("sca_count", 0),
        "architecture_policy_violations": layer_policy.get("violation_count", 0),
        "circular_dependencies": len(result.get("circular_dependencies", []) or []),
    }
    category_scores = {
        name: {
            "score": data.get("score"),
            "letter": data.get("letter"),
            "key_issue": data.get("key_issue"),
        }
        for name, data in categories.items()
        if isinstance(data, dict)
    }
    top_issues = [
        {
            "category": name,
            "key_issue": data["key_issue"],
        }
        for name, data in category_scores.items()
        if data.get("key_issue")
        and not str(data["key_issue"]).lower().startswith("no ")
    ]

    return {
        "grade": grade,
        "category_scores": category_scores,
        "counts": counts,
        "architecture_fitness": system_metrics.get("architecture_fitness"),
        "analysis_summary": summary,
        "top_issues": top_issues,
    }


def _gate(tool_name: str) -> str | None:
    client_allowed, client_err = check_mcp_client_context(
        _REQUIRE_MCP_CLIENT_AUTH_CONTEXT
    )
    if not client_allowed:
        return json.dumps({"error": client_err})

    allowed, err = check_tool_access(tool_name)
    if not allowed:
        return json.dumps({"error": err})

    ok, credit_err = deduct_credits(tool_name)
    if not ok:
        return json.dumps({"error": credit_err})

    return None


GATED_TOOL_AUTH_NOTE = (
    "Requires SKYLOS_API_KEY: this tool returns an authentication error unless "
    "the MCP server is started with SKYLOS_API_KEY set. Without a key only "
    f"`analyze` works ({UNAUTH_DAILY_LIMIT} calls/day). The local CLI needs no "
    "key: `skylos verify <file>` and `skylos agent install-hooks`."
)
UNGATED_TOOL_AUTH_NOTE = (
    f"Works without SKYLOS_API_KEY ({UNAUTH_DAILY_LIMIT} calls/day); "
    "higher limits with a key."
)


def tool_description(fn) -> str:
    """Tool description shown to MCP clients, with an honest auth note."""
    doc = inspect.cleandoc(fn.__doc__ or "")
    note = (
        UNGATED_TOOL_AUTH_NOTE
        if fn.__name__ in UNAUTHENTICATED_TOOLS
        else GATED_TOOL_AUTH_NOTE
    )
    return f"{doc}\n\n{note}" if doc else note


# Parameter descriptions published in each tool's input schema. MCP clients
# show them to the model, and directories such as Glama score them.
PathParam = Annotated[
    str,
    Field(
        description=(
            "Directory or file to scan. A relative path resolves against the "
            "MCP server's working directory."
        )
    ),
]
RepoPathParam = Annotated[
    str,
    Field(
        description=(
            "Project directory. A relative path resolves against the MCP "
            "server's working directory."
        )
    ),
]
ConfidenceParam = Annotated[
    int,
    Field(
        description=(
            "Minimum confidence (0-100) for dead-code findings. Higher values "
            "report fewer, surer candidates; 60 is the CLI default."
        )
    ),
]
ExcludeListParam = Annotated[
    list[str] | None,
    Field(
        description=(
            'Folder names to skip, e.g. ["migrations", "scripts"]. When '
            "given, this list replaces the default excludes (node_modules, "
            ".venv, build, dist and similar); omit it to keep the defaults."
        )
    ),
]
ExcludeCsvParam = Annotated[
    str | None,
    Field(
        description=(
            "Extra folder names to skip, comma-separated (e.g. "
            '"migrations,scripts"). Added to the default excludes.'
        )
    ),
]
ModelParam = Annotated[
    str,
    Field(
        description=(
            "LLM model name passed to the provider (e.g. gpt-4.1 or a Claude "
            "model). Configure the provider's credentials in the MCP server's "
            "environment when required by that provider."
        )
    ),
]


def _register_tools(mcp):
    """Register all MCP tools and resources. Called inside main() after FastMCP is created."""

    def _tool(
        title: str | None = None,
        *,
        read_only: bool = True,
        destructive: bool = False,
        open_world: bool = False,
    ):
        def decorate(fn):
            # FastMCP publishes the docstring as the tool description.
            fn.__doc__ = tool_description(fn)
            try:
                from mcp.types import ToolAnnotations

                register = mcp.tool(
                    title=title,
                    annotations=ToolAnnotations(
                        title=title,
                        readOnlyHint=read_only,
                        destructiveHint=destructive,
                        openWorldHint=open_world,
                    ),
                )
            except (ImportError, TypeError):
                # Older mcp releases (and test doubles) take no annotations.
                register = mcp.tool()
            return register(fn)

        return decorate

    ## all of these look like dead but they're all registered inside `_register_tools()` which is
    ## called from main() .. please ignore the "unused function" warnings for these --- IGNORE ---
    @_tool("Find dead code")
    def analyze(
        path: PathParam,
        confidence: ConfidenceParam = 60,
        exclude_folders: ExcludeListParam = None,
    ) -> str:
        """Find dead code: unused functions, classes, imports, variables, parameters and files.

        Use this to list cleanup candidates in a project. Returns JSON with a
        summary and per-category findings (file, line, name, confidence) plus
        `_run_id`; the full result is stored locally and can be read from the
        `skylos://results/{run_id}` resource. Read-only: it never edits code.
        Findings are candidates: before deleting one, check for dynamic use
        (getattr, string dispatch, entry points, framework decorators, tests).
        A non-empty `analysis_errors` means analysis or verification was
        incomplete; do not treat the findings as a complete scan."""
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

    @_tool("Scan for security issues")
    def security_scan(
        path: PathParam,
        confidence: ConfidenceParam = 60,
        exclude_folders: ExcludeListParam = None,
    ) -> str:
        """Scan source code for security issues such as SQL and command injection, SSRF, path traversal, eval/exec and unsafe deserialization.

        Returns JSON with findings (rule ID, severity, file, line, message) and
        `_run_id`. Read-only; the scan runs locally and does not upload code. Use
        `secrets_scan` for hard-coded credentials and `validate_code_change`
        to check a diff before it lands."""
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

    @_tool("Check code quality")
    def quality_check(
        path: PathParam,
        confidence: ConfidenceParam = 60,
        exclude_folders: ExcludeListParam = None,
    ) -> str:
        """Report code-quality issues: high complexity, deep nesting, long functions, duplicate branches and similar maintainability findings.

        Returns JSON with findings (rule ID, file, line, message) and
        `_run_id`. Read-only and local."""
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

    @_tool("Check architecture")
    def architecture_check(
        path: PathParam,
        confidence: ConfidenceParam = 60,
        exclude_folders: ExcludeListParam = None,
    ) -> str:
        """Report architecture findings for a project: module coupling, cohesion and circular dependencies.

        Returns JSON with the architecture findings and `_run_id`. Read-only
        and local. Use `quality_check` for function-level issues."""
        gate_err = _gate("architecture_check")
        if gate_err:
            return gate_err

        result = _run_analysis(
            path,
            confidence=confidence,
            exclude_folders=exclude_folders,
            enable_quality=True,
        )
        summary = _architecture_payload(result)
        run_id = _store_result(result, "architecture_check", path)
        summary["_run_id"] = run_id
        return json.dumps(summary, indent=2)

    @_tool("Grade codebase health")
    def health_score(
        path: PathParam,
        confidence: ConfidenceParam = 60,
        include_security: Annotated[
            bool, Field(description="Include security findings in the grade.")
        ] = True,
        include_secrets: Annotated[
            bool, Field(description="Include hard-coded secret findings in the grade.")
        ] = True,
        include_quality: Annotated[
            bool, Field(description="Include code-quality findings in the grade.")
        ] = True,
        exclude_folders: ExcludeListParam = None,
    ) -> str:
        """Compute an overall health grade (A-F and a 0-100 score) for a project from dead code, security, secrets and quality findings.

        Use it for a one-number summary or to compare runs; use the specific
        scan tools to see the findings themselves. Returns JSON with the grade,
        per-category scores and `_run_id`. Read-only and local."""
        gate_err = _gate("health_score")
        if gate_err:
            return gate_err

        result = _run_analysis(
            path,
            confidence=confidence,
            exclude_folders=exclude_folders,
            enable_secrets=include_secrets,
            enable_danger=include_security,
            enable_quality=include_quality,
        )
        summary = _health_score_payload(result)
        run_id = _store_result(result, "health_score", path)
        summary["_run_id"] = run_id
        return json.dumps(summary, indent=2)

    @_tool("Find hard-coded secrets")
    def secrets_scan(
        path: PathParam,
        confidence: ConfidenceParam = 60,
        exclude_folders: ExcludeListParam = None,
    ) -> str:
        """Find hard-coded secrets and credentials (API keys, tokens, private keys, passwords) in source and config files.

        Returns JSON with findings (provider, file, line) and `_run_id`. Secret
        values are redacted in the output. Read-only and local."""
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

    @_tool(
        "Plan or apply LLM fixes", read_only=False, destructive=True, open_world=True
    )
    def remediate(
        path: PathParam,
        max_fixes: Annotated[
            int, Field(description="Maximum number of findings to fix in this run.")
        ] = 5,
        dry_run: Annotated[
            bool,
            Field(
                description=(
                    "True (default) only plans the fixes. False writes the "
                    "generated edits to files in `path`."
                )
            ),
        ] = True,
        model: ModelParam = "gpt-4.1",
        test_cmd: Annotated[
            str | None,
            Field(
                description=(
                    "Not supported over MCP; non-empty values are rejected. Run tests "
                    "yourself after reviewing the fixes."
                )
            ),
        ] = None,
        severity: Annotated[
            str | None,
            Field(
                description=(
                    "Only fix findings at this severity or above: critical, "
                    "high, medium or low."
                )
            ),
        ] = None,
    ) -> str:
        """Plan or apply LLM-generated fixes for Skylos findings in a project.

        With dry_run=True (default), static analysis returns a remediation
        plan without calling a model or changing files. With dry_run=False,
        it generates fixes and can edit files in place: this needs the
        `skylos[llm]` extra and provider configuration (including credentials
        when required), and sends affected code to that provider. It does not
        run your tests.
        Review every change and run trusted tests before keeping it."""
        gate_err = _gate("remediate")
        if gate_err:
            return gate_err

        if test_cmd:
            return json.dumps(
                {
                    "error": (
                        "MCP remediate does not accept test_cmd. "
                        "Run trusted validation outside MCP after reviewing fixes."
                    )
                }
            )

        try:
            from skylos.llm.orchestrator import RemediationAgent

            agent = RemediationAgent(
                model=model,
                test_cmd=None,
                severity_filter=severity,
                allow_test_execution=False,
                auto_detect_tests=False,
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

    @_tool("Verify dead code with an LLM", open_world=True)
    def verify_dead_code(
        path: PathParam,
        confidence: ConfidenceParam = 60,
        model: ModelParam = "gpt-4.1",
        max_verify: Annotated[
            int,
            Field(
                description=(
                    "Maximum findings in the main LLM verification pass. "
                    "Entry discovery, prefiltering and challenges can make "
                    "additional model calls."
                )
            ),
        ] = 30,
        max_challenge: Annotated[
            int,
            Field(
                description=(
                    "Maximum number of surviving findings the model re-checks "
                    "in a second pass."
                )
            ),
        ] = 10,
        exclude_folders: ExcludeCsvParam = None,
    ) -> str:
        """Ask an LLM to review selected unused function, class, import and variable candidates, with its reasoning.

        Use it after `analyze` when you need fewer false positives before
        deleting code. Sends code snippets and search results to the chosen
        model provider, so it needs the `skylos[llm]` extra and provider
        configuration, including credentials when required. Candidates outside
        the review limits, or whose use remains uncertain, can remain
        unverified. Does not edit files.
        Refuses to run when the static analysis was incomplete."""
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
            if analysis_result_incomplete(static_result):
                return json.dumps(
                    {
                        "error": "Cannot verify dead code from incomplete analysis.",
                        "analysis_errors": static_result.get("analysis_errors", []),
                        "incomplete_languages": static_result.get(
                            "analysis_summary", {}
                        ).get("incomplete_languages", []),
                    },
                    indent=2,
                )

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

    @_tool("Attribute changes to agents or humans")
    def provenance_scan(
        path: RepoPathParam,
        diff_base: Annotated[
            str | None,
            Field(
                description=(
                    "Git ref to compare against. Omit to use the CI base branch "
                    "when one is set, otherwise origin/main."
                )
            ),
        ] = None,
    ) -> str:
        """Report available evidence of AI-agent, bot and human contributions.

        Combines git signals since the base (agent bot accounts,
        Co-authored-by and AI declaration trailers, agent-named commit
        subjects) with recorded local attribution evidence. Returns JSON
        with per-file attribution, evidence and coverage status. Commit
        declarations do not establish line authorship; missing evidence
        remains unknown. Read-only and local."""
        gate_err = _gate("provenance_scan")
        if gate_err:
            return gate_err

        try:
            from skylos.core.file_discovery import find_git_root
            from skylos.reporting.provenance import analyze_provenance

            target = os.path.abspath(path)
            git_root = str(find_git_root(target) or target)
            report = analyze_provenance(git_root, base_ref=diff_base)
            result = report.to_dict()
            _store_result(result, "provenance_scan", path)
            return json.dumps(result, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @_tool("Generate a dead-code removal patch", read_only=False, destructive=True)
    def generate_fix(
        path: PathParam,
        mode: Annotated[
            str,
            Field(
                description=(
                    '"delete" removes dead code; "comment" comments it out instead.'
                )
            ),
        ] = "delete",
        min_safety: Annotated[
            float,
            Field(
                description=(
                    "Skip findings whose safety score (0.0-1.0; imports score "
                    "highest, methods lowest) is below this value."
                )
            ),
        ] = 0.0,
        apply: Annotated[
            bool,
            Field(
                description=(
                    "False (default) previews the unified diff. True also "
                    "writes changes when patch validation succeeds."
                )
            ),
        ] = False,
    ) -> str:
        """Build a unified-diff patch that removes (or comments out) dead code found by static analysis, after grep verification drops findings that are still referenced.

        Returns the diff, patch summary, validation errors and applied status.
        With apply=False (default) it previews changes; with apply=True it
        edits files if patch validation succeeds. Refuses to run when the
        analysis or grep verification was incomplete. Review the diff and run
        trusted tests before keeping it."""
        gate_err = _gate("generate_fix")
        if gate_err:
            return gate_err

        try:
            from skylos.analyzer import analyze as run_static
            from skylos.deadcode.collect import collect_dead_code_findings
            from skylos.remediation.fixgen import (
                generate_removal_plan,
                generate_unified_diff,
                apply_patches,
                validate_patches,
                generate_fix_summary,
            )
            from skylos.core.grep_verify import grep_verify_findings

            target = os.path.abspath(path)
            raw = run_static(
                target,
                conf=60,
                enable_danger=False,
                enable_quality=False,
                enable_secrets=False,
            )
            static_result = json.loads(raw) if isinstance(raw, str) else raw
            analysis_errors = static_result.get("analysis_errors") or []
            incomplete_languages = (
                static_result.get("analysis_summary", {}).get("incomplete_languages")
                or []
            )
            if analysis_result_incomplete(static_result):
                return json.dumps(
                    {
                        "error": "Cannot generate fixes from incomplete analysis.",
                        "analysis_errors": analysis_errors,
                        "incomplete_languages": incomplete_languages,
                    },
                    indent=2,
                )
            all_findings = collect_dead_code_findings(static_result)
            defs_map = static_result.get("definitions", {})

            # use grep verification to filter
            grep_budget = float(os.getenv("SKYLOS_GREP_BUDGET", "30"))
            verdicts = grep_verify_findings(
                all_findings,
                target,
                time_budget=grep_budget,
            )
            if not getattr(verdicts, "complete", True):
                return json.dumps(
                    {
                        "error": (
                            "Cannot generate fixes because grep verification "
                            "did not complete. Increase SKYLOS_GREP_BUDGET and rerun."
                        ),
                        "grep_verify": {
                            "complete": False,
                            "candidate_count": getattr(
                                verdicts, "candidate_count", len(all_findings)
                            ),
                            "time_budget_seconds": grep_budget,
                            "incomplete_reason": getattr(
                                verdicts,
                                "incomplete_reason",
                                "verification_incomplete",
                            ),
                        },
                    },
                    indent=2,
                )
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

    @_tool("Record a triage decision", read_only=False)
    def learn_triage(
        path: RepoPathParam,
        action_id: Annotated[
            str,
            Field(description="The finding's `fingerprint` from a scan result."),
        ],
        action: Annotated[
            str,
            Field(description='"accept" (real issue) or "dismiss" (false positive).'),
        ],
    ) -> str:
        """Record whether a finding was accepted or dismissed so `get_triage_suggestions` can learn from it.

        Writes the decision to the project's local Skylos state."""
        gate_err = _gate("learn_triage")
        if gate_err:
            return gate_err

        try:
            from skylos.agents.service import AgentServiceController

            controller = AgentServiceController(os.path.abspath(path))
            result = controller.learn_triage(action_id, action)
            _store_result(result, "learn_triage", path)
            return json.dumps(result, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @_tool("Suggest triage decisions")
    def get_triage_suggestions(
        path: RepoPathParam,
    ) -> str:
        """Suggest accept or dismiss for current findings, based on decisions recorded with `learn_triage` in this project.

        Returns JSON suggestions with finding fingerprints, suggested actions
        and confidence, plus the number of learned patterns. Read-only and
        local."""
        gate_err = _gate("get_triage_suggestions")
        if gate_err:
            return gate_err

        try:
            from skylos.agents.service import AgentServiceController

            controller = AgentServiceController(os.path.abspath(path))
            result = controller.get_suggestions()
            _store_result(result, "get_triage_suggestions", path)
            return json.dumps(result, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @_tool("Check a diff before it lands", open_world=True)
    def validate_code_change(
        diff: Annotated[
            str,
            Field(description="Unified diff text, e.g. the output of `git diff`."),
        ],
        path: Annotated[
            str,
            Field(
                description=(
                    "Project root the diff applies to; used to find dependency "
                    "manifests. Relative paths resolve against the MCP server's "
                    "working directory."
                )
            ),
        ] = ".",
        policy: Annotated[
            str | None,
            Field(
                description=(
                    "Optional policy path. Accepted for compatibility but "
                    "currently not applied to the result."
                )
            ),
        ] = None,
        check_dependencies: Annotated[
            bool,
            Field(
                description=(
                    "Look up newly added imports and manifest entries in the "
                    "package registries (PyPI, npm, Go proxy). False skips "
                    "these network calls."
                )
            ),
        ] = True,
    ) -> str:
        """Validate a code diff for security regressions and issues before it lands.

        Takes a unified diff and checks for:
        - Security control regressions (auth, CSRF, TLS, rate limiting removal)
        - New dangerous patterns (eval, exec, SQL injection, etc.)
        - Secrets in added code
        - Hallucinated or undeclared dependencies in added imports and manifest
          entries (requirements*.txt, pyproject.toml, package.json, go.mod),
          verified against the package registries. The "registry" field reports
          "ok", "unreachable" or "error" (lookups incomplete — do not treat
          pass as clean), or "skipped".

        Returns pass/fail with findings.
        """
        gate_err = _gate("validate_code_change")
        if gate_err:
            return gate_err

        try:
            result = _validate_code_change_impl(diff, path, policy, check_dependencies)
            _store_result(result, "validate_code_change", path)
            return json.dumps(result, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @_tool("Verify an edited file or range", open_world=True)
    def verify_change(
        path: Annotated[
            str,
            Field(description="Project root, or a single file to check."),
        ] = ".",
        file: Annotated[
            str | None,
            Field(description="File inside `path` to check; omit to check `path`."),
        ] = None,
        line_range: Annotated[
            str | None,
            Field(
                description=(
                    'Lines to check in `file`, as "START:END" or "START-END" '
                    '(e.g. "10:40"), or one line number.'
                )
            ),
        ] = None,
        confidence: ConfidenceParam = 60,
        project_context: Annotated[
            bool,
            Field(
                description=(
                    "Also load the rest of the project to resolve cross-file "
                    "references (slower; may reduce unresolved-reference findings)."
                )
            ),
        ] = False,
        include_dependency_hallucinations: Annotated[
            bool,
            Field(
                description=(
                    "Check imported packages against the package registries. "
                    "False skips these network calls."
                )
            ),
        ] = True,
        exclude_folders: ExcludeCsvParam = None,
        contract_path: Annotated[
            str | None,
            Field(
                description=(
                    "Path to a repo-specific AI-code contract file; omit to use "
                    "the project's default contract if it has one."
                )
            ),
        ] = None,
        contract_enabled: Annotated[
            bool,
            Field(
                description=(
                    "False disables contract discovery and checks. Omit "
                    "contract_path when False; combining them is rejected."
                )
            ),
        ] = True,
        include_security_findings: Annotated[
            bool,
            Field(
                description=(
                    "Include high and critical security findings and "
                    "hard-coded secrets in the verdict."
                )
            ),
        ] = True,
    ) -> str:
        """Verify a changed file/range for AI-code defects and security bugs.

        Returns a narrow, versioned JSON verdict containing AI-code trust
        findings such as hallucinated references, unfinished generated code,
        stale references, disabled controls, and dependency hallucinations
        (checked by default; pass include_dependency_hallucinations=False to
        skip the registry lookups), plus high/critical security findings
        (category "security") and hard-coded secrets (category "secret",
        values redacted) in the selected file/range. Pass
        include_security_findings=False to skip the security and secret checks.
        """
        gate_err = _gate("verify_change")
        if gate_err:
            return gate_err

        try:
            result = _verify_change_impl(
                path=path,
                file=file,
                line_range=line_range,
                confidence=confidence,
                project_context=project_context,
                include_dependency_hallucinations=include_dependency_hallucinations,
                exclude_folders=exclude_folders,
                contract_path=contract_path,
                contract_enabled=contract_enabled,
                include_security_findings=include_security_findings,
            )
            _store_result(result, "verify_change", path)
            return json.dumps(result, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @_tool("Verify an AI agent's guardrails")
    def verify_agent(
        path: Annotated[
            str,
            Field(description="Directory of the LLM application or agent to check."),
        ] = ".",
        fail_on: Annotated[
            str | None,
            Field(
                description=(
                    "Fail the gate if any failed check is at this severity or "
                    "above: critical, high, medium or low."
                )
            ),
        ] = None,
        min_score: Annotated[
            int | None,
            Field(description="Fail the gate if the defense score (0-100) is lower."),
        ] = None,
        owasp_framework: Annotated[
            str,
            Field(
                description=(
                    'OWASP list to map results to: "llm" (Top 10 for LLM '
                    'Applications) or "agentic".'
                )
            ),
        ] = "llm",
        owasp_version: Annotated[
            str | None,
            Field(
                description=(
                    "Version of that OWASP list; omit for the default (2025 for "
                    "llm, 2026 for agentic)."
                )
            ),
        ] = None,
        exclude_folders: ExcludeCsvParam = None,
    ) -> str:
        """Statically verify an AI agent's guardrails before deployment.

        Deterministic, local pre-deployment agent verification: inventories
        LLM integrations, runs the defense checks (prompt-injection exposure,
        dangerous sinks, tool scope, output validation, PII filtering, cost
        controls), and returns scores, failed checks with remediation, OWASP
        LLM/Agentic coverage, and a reproducible attestation digest. No model
        is involved in the verdict and the analysis runs locally; source code
        is not sent to Skylos Cloud. Optional gate: set fail_on (severity)
        and/or min_score (0-100).
        """
        gate_err = _gate("verify_agent")
        if gate_err:
            return gate_err

        try:
            result = _verify_agent_impl(
                path=path,
                fail_on=fail_on,
                min_score=min_score,
                owasp_framework=owasp_framework,
                owasp_version=owasp_version,
                exclude_folders=exclude_folders,
            )
            if "error" in result:
                return json.dumps(result)
            _store_result(result, "verify_agent", path)
            return json.dumps(result, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @_tool("Summarize security context")
    def get_security_context(
        path: RepoPathParam,
    ) -> str:
        """Summarize a project's security setup: detected web frameworks, auth decorators and middleware, security headers, rate limiting, input validation and a supported Skylos YAML policy file.

        Use it before reviewing or writing security-sensitive code to learn the
        project's conventions. Returns JSON. Read-only and local."""
        gate_err = _gate("get_security_context")
        if gate_err:
            return gate_err

        try:
            result = _get_security_context_impl(path)
            if "error" in result:
                return json.dumps(result)
            _store_result(result, "get_security_context", path)
            return json.dumps(result, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.resource("skylos://results/latest")
    def get_latest_result() -> str:
        """Full JSON result of the most recent stored Skylos tool run."""
        data = _load_result("latest")
        if data is None:
            return json.dumps({"error": "No analysis has been run yet."})
        return json.dumps(data, indent=2)

    @mcp.resource("skylos://results/{run_id}")
    def get_result_by_id(run_id: str) -> str:
        """Full JSON result of a stored run; find its run_id in skylos://results or a scan's `_run_id`."""
        data = _load_result(run_id)
        if data is None:
            return json.dumps({"error": f"Run '{run_id}' not found."})
        return json.dumps(data, indent=2)

    @mcp.resource("skylos://results")
    def list_results() -> str:
        """List stored tool runs with run_id, tool, path and timestamp."""
        return json.dumps(_list_runs(), indent=2)


def main():
    global _REQUIRE_MCP_CLIENT_AUTH_CONTEXT

    try:
        from mcp.server.fastmcp import FastMCP

        initialize_auth()

        transport = os.getenv("MCP_TRANSPORT", "stdio")
        _REQUIRE_MCP_CLIENT_AUTH_CONTEXT = transport in ("sse", "streamable-http")

        if transport in ("sse", "streamable-http"):
            host = os.getenv("MCP_BIND", "127.0.0.1")
            port = int(os.getenv("PORT", "8080"))
            network_auth = build_mcp_network_auth(transport, host=host, port=port)
            mcp_server = FastMCP(
                name="skylos",
                host=host,
                port=port,
                auth=network_auth.auth,
                token_verifier=network_auth.token_verifier,
            )
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
