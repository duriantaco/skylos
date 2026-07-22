from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from skylos.audit.investigator_tools import AuditReadOnlyTools
from skylos.llm.agents import AgentConfig, SecurityAuditAgent


DEFAULT_EXPECTED_PATH = Path("benchmarks/deep_audit_logic/expected.json")


class DeepAuditLogicBenchmarkError(ValueError):
    """The checked-in benchmark contract or fixture is invalid."""


def load_expected(path: str | Path = DEFAULT_EXPECTED_PATH) -> dict[str, Any]:
    expected_path = Path(path).resolve()
    try:
        payload = json.loads(expected_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DeepAuditLogicBenchmarkError(
            f"could not load deep-audit logic expectations: {expected_path}"
        ) from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise DeepAuditLogicBenchmarkError(
            "deep-audit logic expectations require schema_version=1"
        )
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise DeepAuditLogicBenchmarkError(
            "deep-audit logic expectations require at least one case"
        )
    seen: set[str] = set()
    for case in cases:
        if not isinstance(case, dict):
            raise DeepAuditLogicBenchmarkError("benchmark cases must be objects")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id or case_id in seen:
            raise DeepAuditLogicBenchmarkError(
                "benchmark case IDs must be unique non-empty strings"
            )
        seen.add(case_id)
        if not isinstance(case.get("fixture"), str) or not isinstance(
            case.get("entry_file"), str
        ):
            raise DeepAuditLogicBenchmarkError(
                f"benchmark case {case_id} requires fixture and entry_file"
            )
        if not isinstance(case.get("candidates"), list) or not isinstance(
            case.get("expect"), dict
        ):
            raise DeepAuditLogicBenchmarkError(
                f"benchmark case {case_id} requires candidates and expect"
            )
        fixture_root = (expected_path.parent / case["fixture"]).resolve()
        entry_path = fixture_root / case["entry_file"]
        if not fixture_root.is_dir() or not entry_path.is_file():
            raise DeepAuditLogicBenchmarkError(
                f"benchmark case {case_id} fixture or entry file is missing"
            )
    payload["expected_path"] = str(expected_path)
    return payload


def _evidence_files(items: Any) -> set[str]:
    if not isinstance(items, list):
        return set()
    return {
        str(item["file"])
        for item in items
        if isinstance(item, dict) and isinstance(item.get("file"), str)
    }


def project_result(result: Any) -> dict[str, Any]:
    findings = list(getattr(result, "findings", ()) or ())
    metadata = getattr(result, "metadata", {}) or {}
    rule_ids: set[str] = set()
    categories: set[str] = set()
    symbols: set[str] = set()
    primary_files: set[str] = set()
    evidence_files: set[str] = set()
    mitigation_evidence_files: set[str] = set()

    for finding in findings:
        rule_id = getattr(finding, "rule_id", None)
        if isinstance(rule_id, str):
            rule_ids.add(rule_id)
        symbol = getattr(finding, "symbol", None)
        if isinstance(symbol, str) and symbol:
            symbols.add(symbol)
        location = getattr(finding, "location", None)
        primary_file = getattr(location, "file", None)
        if isinstance(primary_file, str):
            primary_files.add(primary_file)
        finding_metadata = getattr(finding, "metadata", {}) or {}
        investigation = finding_metadata.get("investigation_evidence") or {}
        category = investigation.get("category")
        if isinstance(category, str):
            categories.add(category)
        evidence_files.update(_evidence_files(investigation.get("evidence")))
        for check in investigation.get("mitigation_evidence") or ():
            if isinstance(check, dict):
                mitigation_evidence_files.update(_evidence_files(check.get("evidence")))

    clean_evidence_files: set[str] = set()
    for proof in metadata.get("clean_evidence") or ():
        if isinstance(proof, dict):
            clean_evidence_files.update(_evidence_files(proof.get("evidence")))

    usage = metadata.get("usage") or {}
    if not isinstance(usage, dict):
        usage = {}

    return {
        "status": str(getattr(result, "status", "unknown")),
        "finding_count": len(findings),
        "rule_ids": sorted(rule_ids),
        "categories": sorted(categories),
        "symbols": sorted(symbols),
        "primary_files": sorted(primary_files),
        "evidence_files": sorted(evidence_files),
        "mitigation_evidence_files": sorted(mitigation_evidence_files),
        "clean_evidence_files": sorted(clean_evidence_files),
        "visited_files": sorted(
            path for path in metadata.get("visited_files", ()) if isinstance(path, str)
        ),
        "source_observed_files": sorted(
            path
            for path in metadata.get("source_observed_files", ())
            if isinstance(path, str)
        ),
        "tool_calls": int(metadata.get("tool_calls") or 0),
        "turns": int(metadata.get("turns") or 0),
        "llm_calls": int(metadata.get("llm_calls") or 0),
        "prompt_tokens": int(usage.get("prompt_tokens") or 0),
        "completion_tokens": int(usage.get("completion_tokens") or 0),
        "total_tokens": int(usage.get("total_tokens") or 0),
        "protocol_version": metadata.get("protocol_version"),
        "tool_schema_version": metadata.get("tool_schema_version"),
    }


def evaluate_case(actual: dict[str, Any], expected: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if actual.get("status") != expected.get("status"):
        failures.append(
            f"status expected {expected.get('status')!r}, found {actual.get('status')!r}"
        )

    count_contract = expected.get("finding_count") or {}
    actual_count = int(actual.get("finding_count") or 0)
    if "exact" in count_contract and actual_count != int(count_contract["exact"]):
        failures.append(
            f"finding_count expected exactly {count_contract['exact']}, found {actual_count}"
        )
    if "min" in count_contract and actual_count < int(count_contract["min"]):
        failures.append(
            f"finding_count expected at least {count_contract['min']}, found {actual_count}"
        )
    if "max" in count_contract and actual_count > int(count_contract["max"]):
        failures.append(
            f"finding_count expected at most {count_contract['max']}, found {actual_count}"
        )

    for actual_key, expected_key in (
        ("tool_calls", "min_tool_calls"),
        ("llm_calls", "min_llm_calls"),
    ):
        minimum = int(expected.get(expected_key) or 0)
        if int(actual.get(actual_key) or 0) < minimum:
            failures.append(
                f"{actual_key} expected at least {minimum}, "
                f"found {actual.get(actual_key, 0)}"
            )

    set_contracts = {
        "rule_ids": ("required_rule_ids", "forbidden_rule_ids"),
        "categories": ("required_categories", "forbidden_categories"),
        "symbols": ("required_symbols", "forbidden_symbols"),
        "primary_files": (
            "required_primary_files",
            "forbidden_primary_files",
        ),
        "visited_files": ("required_visited_files", "forbidden_visited_files"),
        "evidence_files": (
            "required_evidence_files",
            "forbidden_evidence_files",
        ),
        "clean_evidence_files": (
            "required_clean_evidence_files",
            "forbidden_clean_evidence_files",
        ),
    }
    for actual_key, (required_key, forbidden_key) in set_contracts.items():
        values = set(actual.get(actual_key) or ())
        required = set(expected.get(required_key) or ())
        forbidden = set(expected.get(forbidden_key) or ())
        missing = sorted(required - values)
        present_forbidden = sorted(forbidden & values)
        if missing:
            failures.append(f"{actual_key} missing required values: {missing}")
        if present_forbidden:
            failures.append(
                f"{actual_key} contains forbidden values: {present_forbidden}"
            )
    return failures


def _production_agent(
    *,
    model: str,
    api_key: str | None,
    provider: str | None,
    base_url: str | None,
) -> SecurityAuditAgent:
    config = AgentConfig(
        model=model,
        api_key=api_key,
        temperature=0.0,
        max_tokens=4096,
        timeout=180,
        retry_attempts=1,
        stream=False,
        enable_cache=False,
    )
    config.provider = provider
    config.base_url = base_url
    return SecurityAuditAgent(config)


def run_manifest(
    expected_path: str | Path = DEFAULT_EXPECTED_PATH,
    *,
    model: str,
    api_key: str | None,
    provider: str | None = None,
    base_url: str | None = None,
    selected_cases: set[str] | None = None,
    agent_factory: Callable[[dict[str, Any]], Any] | None = None,
    require_model_usage: bool = False,
) -> dict[str, Any]:
    contract = load_expected(expected_path)
    contract_path = Path(contract["expected_path"])
    selected = set(selected_cases or ())
    case_results: list[dict[str, Any]] = []

    for case in contract["cases"]:
        if selected and case["id"] not in selected:
            continue
        fixture_root = (contract_path.parent / case["fixture"]).resolve()
        entry_path = fixture_root / case["entry_file"]
        tools = AuditReadOnlyTools(fixture_root)
        agent = (
            agent_factory(case)
            if agent_factory is not None
            else _production_agent(
                model=model,
                api_key=api_key,
                provider=provider,
                base_url=base_url,
            )
        )
        try:
            result = agent.investigate(
                entry_path.read_text(encoding="utf-8"),
                case["entry_file"],
                context=None,
                candidates=list(case["candidates"]),
                tools=tools,
                run_id=f"benchmark-{case['id']}",
                persist_trace=False,
            )
            actual = project_result(result)
        except Exception as exc:
            investigation_metadata = getattr(exc, "investigation_metadata", {})
            if not isinstance(investigation_metadata, dict):
                investigation_metadata = {}
            usage = investigation_metadata.get("usage") or {}
            if not isinstance(usage, dict):
                usage = {}
            actual = {
                "status": "error",
                "finding_count": 0,
                "error_type": type(exc).__name__,
                "error": str(exc),
                **tools.metadata(),
                "turns": int(investigation_metadata.get("turns") or 0),
                "llm_calls": int(investigation_metadata.get("llm_calls") or 0),
                "prompt_tokens": int(usage.get("prompt_tokens") or 0),
                "completion_tokens": int(usage.get("completion_tokens") or 0),
                "total_tokens": int(usage.get("total_tokens") or 0),
            }
        failures = evaluate_case(actual, case["expect"])
        if require_model_usage and int(actual.get("total_tokens") or 0) <= 0:
            failures.append("live model run must report nonzero total_tokens")
        case_results.append(
            {
                "id": case["id"],
                "fixture": case["fixture"],
                "entry_file": case["entry_file"],
                "candidates": list(case["candidates"]),
                "passed": not failures,
                "failures": failures,
                "actual": actual,
            }
        )

    execution_mode = "injected_agent" if agent_factory else "live_model"
    case_count = len(case_results)
    pass_count = sum(1 for case in case_results if case["passed"])
    failure_count = sum(len(case["failures"]) for case in case_results)
    status = "pass" if all(case["passed"] for case in case_results) else "fail"

    return {
        "schema_version": 1,
        "benchmark": "deep_audit_logic",
        "expected_path": str(contract_path),
        "model": model,
        "provider": provider,
        "execution_mode": execution_mode,
        "model_usage_required": require_model_usage,
        "case_count": case_count,
        "pass_count": pass_count,
        "failure_count": failure_count,
        "status": status,
        "cases": case_results,
    }


def format_summary(summary: dict[str, Any]) -> str:
    lines = [
        f"Deep Audit logic benchmark: {summary['status'].upper()}",
        f"Model/provider: {summary.get('model')} / {summary.get('provider')}",
        f"Cases: {summary['pass_count']}/{summary['case_count']} passed",
    ]
    for case in summary["cases"]:
        actual = case["actual"]

        if case["passed"]:
            label = "PASS"
        else:
            label = "FAIL"

        lines.append(
            f"{label} {case['id']}: findings={actual.get('finding_count', 0)} "
            f"tools={actual.get('tool_calls', 0)} turns={actual.get('turns', 0)} "
            f"tokens={actual.get('total_tokens', 0)}"
        )
        lines.extend(f"  - {failure}" for failure in case["failures"])
    return "\n".join(lines)
