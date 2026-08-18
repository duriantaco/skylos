from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from skylos.research.dead_code.evidence import EvidenceEvent, EvidenceKind, EvidenceLedger, SymbolKey


class RootKind(StrEnum):
    FRAMEWORK_ROUTE = "framework_route"
    FRAMEWORK_DECORATOR = "framework_decorator"
    CLI_COMMAND = "cli_command"
    PACKAGE_ENTRYPOINT = "package_entrypoint"
    TASK = "task"
    TEST = "test"
    VALIDATOR = "validator"
    SERIALIZER = "serializer"
    PLUGIN_HOOK = "plugin_hook"
    PUBLIC_EXPORT = "public_export"
    RUNTIME_TRACE = "runtime_trace"
    COVERAGE = "coverage"


@dataclass(frozen=True, order=True)
class InferredRoot:
    symbol: SymbolKey
    kind: RootKind
    reason: str
    source: str
    confidence: float = 1.0

    def to_evidence(self) -> EvidenceEvent:
        if self.kind == RootKind.PACKAGE_ENTRYPOINT:
            evidence_kind = EvidenceKind.PACKAGE_ENTRYPOINT
        elif self.kind == RootKind.TEST:
            evidence_kind = EvidenceKind.TEST_ENTRYPOINT
        elif self.kind == RootKind.RUNTIME_TRACE:
            evidence_kind = EvidenceKind.TRACE_HIT
        elif self.kind == RootKind.COVERAGE:
            evidence_kind = EvidenceKind.COVERAGE_HIT
        elif self.kind == RootKind.PUBLIC_EXPORT:
            # A declared public export is consumed outside this repository, so
            # in-repo silence is not evidence of death.  This is recorded as
            # uncertainty -- the reporter abstains instead of claiming either
            # liveness or a safe deletion.
            evidence_kind = EvidenceKind.UNCERTAINTY
        else:
            evidence_kind = EvidenceKind.FRAMEWORK_ROOT
        return EvidenceEvent(
            kind=evidence_kind,
            reason=self.reason,
            source=self.source,
            confidence=self.confidence,
            details={"root_kind": self.kind.value},
        )


@dataclass
class RootSet:
    roots: set[InferredRoot] = field(default_factory=set)

    def add(self, root: InferredRoot) -> None:
        self.roots.add(root)

    def apply_to(self, ledger: EvidenceLedger) -> None:
        for root in self.roots:
            ledger.add(root.symbol, root.to_evidence())

    def by_kind(self) -> dict[str, list[dict[str, Any]]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for root in sorted(self.roots):
            grouped.setdefault(root.kind.value, []).append(
                {
                    "file": root.symbol.file,
                    "qualified_name": root.symbol.qualified_name,
                    "symbol_kind": root.symbol.kind,
                    "line": root.symbol.line,
                    "reason": root.reason,
                    "source": root.source,
                    "confidence": root.confidence,
                }
            )
        return grouped

    def to_dict(self) -> dict[str, Any]:
        return {"roots": self.by_kind()}
