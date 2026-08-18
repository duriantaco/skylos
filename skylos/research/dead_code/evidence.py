from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Final


DEFAULT_LIVENESS_THRESHOLD: Final[float] = 0.5
"""Minimum confidence for liveness evidence to declare a symbol alive.

Evidence below this threshold is retained in the ledger but downgrades the
symbol to ``UNCERTAIN`` instead of ``ALIVE``, so the reporter abstains
rather than silently rescuing it.  Sweeping this value produces the
precision/recall/abstention curve reported in the evaluation.
"""


class EvidenceKind(StrEnum):
    STATIC_REFERENCE = "static_reference"
    REACHABLE_FROM_ROOT = "reachable_from_root"
    TOP_LEVEL_EXECUTION = "top_level_execution"
    FRAMEWORK_ROOT = "framework_root"
    PACKAGE_ENTRYPOINT = "package_entrypoint"
    TEST_ENTRYPOINT = "test_entrypoint"
    DYNAMIC_PATTERN = "dynamic_pattern"
    COVERAGE_HIT = "coverage_hit"
    TRACE_HIT = "trace_hit"
    GREP_RESCUE = "grep_rescue"
    VALIDATION_PASS = "validation_pass"
    VALIDATION_FAIL = "validation_fail"
    UNCERTAINTY = "uncertainty"


class CandidateClassification(StrEnum):
    ALIVE = "alive"
    DEAD = "dead"
    LIKELY_DEAD = "likely_dead"
    VALIDATED_DEAD = "validated_dead"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True, order=True)
class SymbolKey:
    file: str
    qualified_name: str
    kind: str
    line: int = 0

    @classmethod
    def from_finding(cls, finding: dict[str, Any]) -> "SymbolKey":
        file_name = str(finding.get("file", ""))
        qualified_name = str(
            finding.get("full_name")
            or finding.get("qualified_name")
            or finding.get("name")
            or ""
        )
        kind = str(finding.get("type") or finding.get("kind") or "symbol")
        line_raw = finding.get("line", 0) or 0
        try:
            line = int(line_raw)
        except (TypeError, ValueError):
            line = 0
        return cls(file=file_name, qualified_name=qualified_name, kind=kind, line=line)

    def repo_relative_file(self, root: str | Path) -> str:
        try:
            return Path(self.file).resolve().relative_to(Path(root).resolve()).as_posix()
        except Exception:
            return Path(self.file).as_posix()


@dataclass(frozen=True)
class EvidenceEvent:
    kind: EvidenceKind
    reason: str
    source: str
    confidence: float = 1.0
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "reason": self.reason,
            "source": self.source,
            "confidence": self.confidence,
            "details": dict(self.details),
        }


@dataclass
class EvidenceLedger:
    """Evidence and final classification for research dead-code candidates."""

    events_by_symbol: dict[SymbolKey, list[EvidenceEvent]] = field(default_factory=dict)

    def add(self, symbol: SymbolKey, event: EvidenceEvent) -> None:
        self.events_by_symbol.setdefault(symbol, []).append(event)

    def events(self, symbol: SymbolKey) -> list[EvidenceEvent]:
        return list(self.events_by_symbol.get(symbol, []))

    def has_kind(self, symbol: SymbolKey, *kinds: EvidenceKind) -> bool:
        wanted = set(kinds)
        return any(event.kind in wanted for event in self.events(symbol))

    ALIVE_EVIDENCE_KINDS = frozenset(
        {
            EvidenceKind.STATIC_REFERENCE,
            EvidenceKind.REACHABLE_FROM_ROOT,
            EvidenceKind.TOP_LEVEL_EXECUTION,
            EvidenceKind.FRAMEWORK_ROOT,
            EvidenceKind.PACKAGE_ENTRYPOINT,
            EvidenceKind.TEST_ENTRYPOINT,
            EvidenceKind.DYNAMIC_PATTERN,
            EvidenceKind.COVERAGE_HIT,
            EvidenceKind.TRACE_HIT,
            EvidenceKind.GREP_RESCUE,
        }
    )

    def liveness_confidence(self, symbol: SymbolKey) -> float:
        """Strongest liveness confidence recorded for this symbol."""
        confidences = [
            event.confidence
            for event in self.events(symbol)
            if event.kind in self.ALIVE_EVIDENCE_KINDS
        ]
        return max(confidences) if confidences else 0.0

    def classify(
        self,
        symbol: SymbolKey,
        threshold: float = DEFAULT_LIVENESS_THRESHOLD,
    ) -> CandidateClassification:
        events = self.events(symbol)
        if not events:
            return CandidateClassification.LIKELY_DEAD

        if any(event.kind == EvidenceKind.VALIDATION_PASS for event in events):
            return CandidateClassification.VALIDATED_DEAD

        if any(event.kind == EvidenceKind.VALIDATION_FAIL for event in events):
            return CandidateClassification.ALIVE

        confidence = self.liveness_confidence(symbol)
        if confidence >= threshold:
            return CandidateClassification.ALIVE

        if confidence > 0.0:
            # Liveness evidence exists but is too weak to act on.  Abstain
            # rather than either rescuing or reporting the symbol.
            return CandidateClassification.UNCERTAIN

        if any(event.kind == EvidenceKind.UNCERTAINTY for event in events):
            return CandidateClassification.UNCERTAIN

        return CandidateClassification.LIKELY_DEAD

    def to_dict(
        self,
        root: str | Path | None = None,
        threshold: float = DEFAULT_LIVENESS_THRESHOLD,
    ) -> dict[str, Any]:
        symbols = []
        for symbol in sorted(self.events_by_symbol):
            file_name = symbol.file if root is None else symbol.repo_relative_file(root)
            symbols.append(
                {
                    "file": file_name,
                    "qualified_name": symbol.qualified_name,
                    "kind": symbol.kind,
                    "line": symbol.line,
                    "classification": self.classify(symbol, threshold).value,
                    "liveness_confidence": self.liveness_confidence(symbol),
                    "evidence": [event.to_dict() for event in self.events(symbol)],
                }
            )
        return {"symbols": symbols}
