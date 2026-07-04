from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from skylos.contracts.schema import HallucinationContract


@dataclass(frozen=True)
class _ContractFindingMatch:
    clause: str
    reason: str


def contract_finding_metadata(
    contract: HallucinationContract | None,
    finding: dict[str, Any],
) -> dict[str, str]:
    if contract is None:
        return {}

    match = _contract_finding_match(contract, finding)
    if match is None:
        return {}

    metadata = {
        "contract_clause": match.clause,
        "contract_path": str(contract.path),
        "contract_reason": match.reason,
    }
    if contract.contract_id:
        metadata["contract_id"] = contract.contract_id
    return metadata


def _contract_finding_match(
    contract: HallucinationContract,
    finding: dict[str, Any],
) -> _ContractFindingMatch | None:
    rule_id = str(_finding_value(finding, ("rule_id", "rule"), ""))
    if rule_id == "SKY-L012":
        return _phantom_symbol_match(
            finding,
            contract.ai.phantom_symbols.names,
            "ai.phantom_symbols.names",
        )
    if rule_id == "SKY-L023":
        return _phantom_symbol_match(
            finding,
            contract.ai.phantom_symbols.decorators,
            "ai.phantom_symbols.decorators",
        )
    if (
        rule_id == "SKY-D222"
        and contract.ai.dependencies.reject_nonexistent_packages
        and _dependency_truth_state(finding) in {"", "missing_package"}
    ):
        package = _dependency_label(finding)
        return _ContractFindingMatch(
            "ai.dependencies.reject_nonexistent_packages",
            f"Contract rejects nonexistent package dependencies; finding reports {package}.",
        )
    if rule_id == "SKY-D225" and contract.ai.dependencies.reject_impossible_versions:
        package = _dependency_label(finding)
        return _ContractFindingMatch(
            "ai.dependencies.reject_impossible_versions",
            f"Contract rejects impossible dependency versions; finding reports {package}.",
        )
    if rule_id == "SKY-D224":
        return _api_surface_match(contract, finding)
    if rule_id == "SKY-A102" and contract.tests.high_risk_changes_require_tests:
        return _ContractFindingMatch(
            "tests.high_risk_changes_require_tests",
            "Contract requires tests for high-risk changed code.",
        )
    if (
        rule_id == "SKY-A105"
        and contract.security.routes.require_any_decorator
    ):
        required = ", ".join(
            f"@{name.lstrip('@')}"
            for name in contract.security.routes.require_any_decorator
        )
        return _ContractFindingMatch(
            "security.routes.require_any_decorator",
            f"Contract requires route handlers to use one of: {required}.",
        )
    return None


def _phantom_symbol_match(
    finding: dict[str, Any],
    contract_symbols: tuple[str, ...],
    clause: str,
) -> _ContractFindingMatch | None:
    if not contract_symbols:
        return None

    finding_symbols = _finding_symbol_candidates(finding)
    for symbol in contract_symbols:
        variants = _symbol_variants(symbol)
        if finding_symbols.isdisjoint(variants):
            continue
        display = _first_sorted(variants & finding_symbols) or symbol
        return _ContractFindingMatch(
            clause,
            f"Contract lists '{display}' under {clause}.",
        )
    return None


def _api_surface_match(
    contract: HallucinationContract,
    finding: dict[str, Any],
) -> _ContractFindingMatch | None:
    api = contract.ai.api_surface
    message = str(_finding_value(finding, ("message", "detail", "msg"), ""))
    is_keyword = "keyword" in message.lower()
    if is_keyword and api.reject_unknown_kwargs:
        return _ContractFindingMatch(
            "ai.api_surface.reject_unknown_kwargs",
            "Contract rejects calls with keyword arguments absent from the installed API.",
        )
    if not is_keyword and api.reject_unknown_members:
        return _ContractFindingMatch(
            "ai.api_surface.reject_unknown_members",
            "Contract rejects members absent from the installed API.",
        )
    return None


def _dependency_truth_state(finding: dict[str, Any]) -> str:
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        return ""
    return str(metadata.get("dependency_truth_state", ""))


def _dependency_label(finding: dict[str, Any]) -> str:
    metadata = finding.get("metadata")
    package_name = None
    package_version = None
    if isinstance(metadata, dict):
        package_name = metadata.get("package_name")
        package_version = metadata.get("package_version")
    if package_name:
        if package_version:
            return f"'{package_name}@{package_version}'"
        return f"'{package_name}'"

    symbol = _finding_value(finding, ("symbol", "name", "simple_name"), None)
    if symbol:
        return f"'{symbol}'"
    return "the dependency"


def _finding_symbol_candidates(finding: dict[str, Any]) -> set[str]:
    candidates: set[str] = set()
    for key in ("simple_name", "symbol", "name"):
        value = finding.get(key)
        if isinstance(value, str):
            candidates.update(_symbol_variants(value))
    return candidates


def _symbol_variants(value: str) -> set[str]:
    raw = value.strip()
    if not raw:
        return set()

    variants = {raw}
    if raw.startswith("@"):
        variants.add(raw[1:])
    if raw.endswith("()"):
        variants.add(raw[:-2])
    before_call = raw.split("(", 1)[0].strip()
    if before_call:
        variants.add(before_call)
        if before_call.startswith("@"):
            variants.add(before_call[1:])
        if "." in before_call:
            variants.add(before_call.rsplit(".", 1)[-1])
    if "." in raw:
        variants.add(raw.rsplit(".", 1)[-1])
    return {variant.strip("@") for variant in variants if variant.strip("@")}


def _first_sorted(values: set[str]) -> str | None:
    if not values:
        return None
    return sorted(values)[0]


def _finding_value(
    finding: dict[str, Any],
    keys: tuple[str, ...],
    default: Any,
) -> Any:
    for key in keys:
        value = finding.get(key)
        if _has_value(value):
            return value
    return default


def _has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str) and not value.strip():
        return False
    return True
