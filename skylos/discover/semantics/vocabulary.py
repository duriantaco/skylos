"""The small, explicit vocabulary used by output-flow checks.

These are observations about parsed source, not claims about runtime behavior.
An unresolved relationship remains UNKNOWN instead of becoming a safe edge.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FlowStatus(str, Enum):
    VALIDATED = "validated"
    UNVALIDATED = "unvalidated"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class OutputFlowEvidence:
    source_location: str
    use_location: str
    status: FlowStatus
    validation_location: str = ""
    validation_kind: str = ""
    path: tuple[str, ...] = ()
    reason: str = ""

    def to_dict(self) -> dict[str, str | list[str]]:
        return {
            "source_location": self.source_location,
            "use_location": self.use_location,
            "status": self.status.value,
            "validation_location": self.validation_location,
            "validation_kind": self.validation_kind,
            "path": list(self.path),
            "reason": self.reason,
        }
