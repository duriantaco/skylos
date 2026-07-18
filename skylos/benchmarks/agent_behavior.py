from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from skylos.agents.evaluation import (
    AgentBehaviorError,
    evaluate_behavior,
    load_behavior_contract,
    load_behavior_observations,
)
from skylos.core.safe_cache_io import read_text_no_symlink


MAX_AGENT_BEHAVIOR_MANIFEST_BYTES = 256 * 1024


def run_agent_behavior_manifest(path: str | Path) -> dict[str, Any]:
    manifest_path = _manifest_path(path)
    manifest_root = manifest_path.parent
    raw = _load_manifest(manifest_path)
    cases = raw.get("cases")
    if not isinstance(cases, list) or not cases:
        raise AgentBehaviorError("agent behavior manifest requires non-empty cases")

    results = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise AgentBehaviorError(f"cases[{index}] must be an object")
        case_id = _required_case_text(case, "id", index)
        contract_path = _required_case_text(case, "contract", index)
        observations_path = _required_case_text(case, "observations", index)
        expected_status = _required_case_text(case, "expected_status", index)
        if expected_status not in {"pass", "fail", "incomplete"}:
            raise AgentBehaviorError(
                f"cases[{index}].expected_status must be pass, fail, or incomplete"
            )
        contract = load_behavior_contract(
            contract_path,
            project_root=manifest_root,
        )
        observations = load_behavior_observations(
            observations_path,
            project_root=manifest_root,
        )
        evaluation = evaluate_behavior(contract, observations)
        results.append(
            {
                "id": case_id,
                "expected_status": expected_status,
                "actual_status": evaluation.status,
                "ok": evaluation.status == expected_status,
                "summary": evaluation.summary,
            }
        )

    passed = sum(case["ok"] for case in results)
    return {
        "schema_version": 1,
        "manifest": str(manifest_path),
        "status": "pass" if passed == len(results) else "fail",
        "summary": {
            "case_count": len(results),
            "passed": passed,
            "failed": len(results) - passed,
        },
        "cases": results,
    }


def _manifest_path(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    try:
        if candidate.is_symlink():
            raise AgentBehaviorError("agent behavior manifest must not be a symlink")
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise AgentBehaviorError(
            f"agent behavior manifest not found: {candidate}"
        ) from exc
    except OSError as exc:
        raise AgentBehaviorError(f"could not inspect manifest: {candidate}") from exc
    if not resolved.is_file():
        raise AgentBehaviorError(f"agent behavior manifest is not a file: {resolved}")
    return resolved


def _load_manifest(path: Path) -> dict[str, Any]:
    source = read_text_no_symlink(
        path,
        max_bytes=MAX_AGENT_BEHAVIOR_MANIFEST_BYTES,
        encoding="utf-8",
    )
    if source is None:
        raise AgentBehaviorError("agent behavior manifest is unsafe or oversized")
    try:
        raw = json.loads(source)
    except json.JSONDecodeError as exc:
        raise AgentBehaviorError(
            f"invalid agent behavior manifest JSON: {exc}"
        ) from exc
    if not isinstance(raw, dict):
        raise AgentBehaviorError("agent behavior manifest must be an object")
    if raw.get("schema_version") != 1:
        raise AgentBehaviorError("agent behavior manifest schema_version must be 1")
    unknown = sorted(set(raw) - {"schema_version", "cases"})
    if unknown:
        raise AgentBehaviorError(f"unknown agent behavior manifest keys: {unknown}")
    return raw


def _required_case_text(case: dict[str, Any], key: str, index: int) -> str:
    value = case.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AgentBehaviorError(f"cases[{index}].{key} must be a non-empty string")
    return value.strip()
