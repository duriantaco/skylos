from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Any


LEGACY_STATUS_EXISTS = "exists"
ECOSYSTEM_NAME_NPM = "npm"
ECOSYSTEM_NAME_PYPI = "PyPI"


class DependencyTruthState(str, Enum):
    PRESENT = "present"
    MISSING_PACKAGE = "missing_package"
    MISSING_VERSION = "missing_version"
    SUSPICIOUS_EXISTING = "suspicious_existing"
    PRIVATE_OR_UNVERIFIED = "private_or_unverified"
    UNKNOWN = "unknown"


_STATE_ALIASES = {
    LEGACY_STATUS_EXISTS: DependencyTruthState.PRESENT,
}


@dataclass(frozen=True)
class DependencyTruthResult:
    ecosystem: str
    name: str
    version: str
    state: DependencyTruthState
    source: str = "registry"
    reason: str = ""

    @classmethod
    def from_dependency(
        cls,
        dependency: dict[str, Any],
        state: DependencyTruthState | str,
        *,
        source: str = "registry",
        reason: str = "",
    ) -> "DependencyTruthResult":
        return cls(
            ecosystem=str(dependency.get("ecosystem", "")),
            name=str(dependency.get("name", "")),
            version=str(dependency.get("version", "")),
            state=normalize_dependency_truth_state(state),
            source=source,
            reason=reason,
        )

    def to_metadata(self) -> dict[str, str]:
        metadata = {
            "dependency_truth_state": self.state.value,
            "dependency_truth_source": self.source,
        }
        if self.reason:
            metadata["dependency_truth_reason"] = self.reason
        return metadata


def normalize_dependency_truth_state(
    value: DependencyTruthState | str | None,
) -> DependencyTruthState:
    if isinstance(value, DependencyTruthState):
        return value
    if value is None:
        return DependencyTruthState.UNKNOWN
    raw = str(value).strip()
    if not raw:
        return DependencyTruthState.UNKNOWN
    alias = _STATE_ALIASES.get(raw)
    if alias is not None:
        return alias
    try:
        return DependencyTruthState(raw)
    except ValueError:
        return DependencyTruthState.UNKNOWN


def dependency_truth_cache_key(ecosystem: str, name: str, version: str) -> str:
    normalized_ecosystem, normalized_name, normalized_version = (
        normalize_dependency_identity(ecosystem, name, version)
    )
    return f"{normalized_ecosystem}:{normalized_name}:{normalized_version}"


def normalize_dependency_identity(
    ecosystem: str,
    name: str,
    version: str,
) -> tuple[str, str, str]:
    normalized_ecosystem = str(ecosystem).strip()
    normalized_name = _normalize_dependency_name(normalized_ecosystem, name)
    normalized_version = str(version).strip()
    return normalized_ecosystem, normalized_name, normalized_version


def _normalize_dependency_name(ecosystem: str, name: str) -> str:
    raw = str(name).strip()
    if ecosystem == ECOSYSTEM_NAME_PYPI:
        return re.sub(r"[-_.]+", "-", raw).lower()
    if ecosystem == ECOSYSTEM_NAME_NPM:
        return raw.lower()
    return raw
