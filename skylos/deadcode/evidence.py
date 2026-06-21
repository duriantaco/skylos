from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable


CLASSIFICATION_POLICY = "dead-code-evidence-v2"


class EvidenceKind(str, Enum):
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
    NO_STATIC_REFERENCES = "no_static_references"
    NOT_EXPORTED = "not_exported"
    NO_ENTRYPOINT = "no_entrypoint"
    CONFIDENCE_GATE = "confidence_gate"


class CandidateClassification(str, Enum):
    ALIVE = "alive"
    DEAD = "dead"
    LIKELY_DEAD = "likely_dead"
    VALIDATED_DEAD = "validated_dead"
    UNCERTAIN = "uncertain"


ALIVE_EVIDENCE_KINDS = {
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

ENTRYPOINT_EVIDENCE_KINDS = {
    EvidenceKind.REACHABLE_FROM_ROOT,
    EvidenceKind.TOP_LEVEL_EXECUTION,
    EvidenceKind.FRAMEWORK_ROOT,
    EvidenceKind.PACKAGE_ENTRYPOINT,
    EvidenceKind.TEST_ENTRYPOINT,
}

DEAD_EVIDENCE_KINDS = {
    EvidenceKind.NO_STATIC_REFERENCES,
    EvidenceKind.NOT_EXPORTED,
    EvidenceKind.NO_ENTRYPOINT,
    EvidenceKind.CONFIDENCE_GATE,
}

DECISION_REASON_LABELS = {
    "validated_dead": "Validator confirmed no live use",
    "validation_failed": "Validator found live use",
    "static_reference": "Static references found",
    "reachable_from_root": "Reachable from root",
    "top_level_execution": "Called during module import",
    "framework_root": "Framework entrypoint",
    "package_entrypoint": "Package entrypoint",
    "test_entrypoint": "Test entrypoint",
    "dynamic_pattern": "Dynamic reference matched",
    "coverage_hit": "Coverage hit",
    "trace_hit": "Trace hit",
    "grep_rescue": "Grep verification found usage",
    "no_refs": "No static references",
    "not_exported": "Not exported",
    "no_entrypoint": "No entrypoint evidence",
    "confidence_ge_threshold": "Confidence meets threshold",
    "uncertainty": "Uncertainty evidence present",
    "no_liveness_evidence": "No liveness evidence",
}


@dataclass(frozen=True, order=True)
class SymbolKey:
    file: str
    qualified_name: str
    kind: str
    line: int = 0

    @classmethod
    def from_definition(cls, definition: Any) -> "SymbolKey":
        line = getattr(definition, "line", 0) or 0
        try:
            line_number = int(line)
        except (TypeError, ValueError):
            line_number = 0
        return cls(
            file=str(getattr(definition, "filename", "")),
            qualified_name=str(getattr(definition, "name", "")),
            kind=str(getattr(definition, "type", "symbol")),
            line=line_number,
        )

    @classmethod
    def from_finding(cls, finding: dict[str, Any]) -> "SymbolKey":
        line = finding.get("line", 0) or 0
        try:
            line_number = int(line)
        except (TypeError, ValueError):
            line_number = 0
        return cls(
            file=str(finding.get("file", "")),
            qualified_name=str(
                finding.get("full_name")
                or finding.get("qualified_name")
                or finding.get("name")
                or ""
            ),
            kind=str(finding.get("type") or finding.get("kind") or "symbol"),
            line=line_number,
        )

    def repo_relative_file(self, root: str | Path) -> str:
        try:
            return (
                Path(self.file)
                .resolve()
                .relative_to(Path(root).resolve())
                .as_posix()
            )
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
            "role": _event_role(self.kind),
            "reason": self.reason,
            "source": self.source,
            "confidence": self.confidence,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class EvidenceDecision:
    classification: CandidateClassification
    primary_reason: str
    reason_tags: tuple[str, ...]
    confidence: int | None = None
    threshold: int | None = None
    live_evidence_count: int = 0
    dead_evidence_count: int = 0
    uncertainty_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "classification": self.classification.value,
            "primary_reason": self.primary_reason,
            "reason_tags": list(self.reason_tags),
            "live_evidence_count": self.live_evidence_count,
            "dead_evidence_count": self.dead_evidence_count,
            "uncertainty_count": self.uncertainty_count,
        }
        if self.confidence is not None:
            payload["confidence"] = self.confidence
        if self.threshold is not None:
            payload["threshold"] = self.threshold
        return payload


@dataclass
class EvidenceLedger:
    """Evidence and final classification for dead-code candidates."""

    events_by_symbol: dict[SymbolKey, list[EvidenceEvent]] = field(default_factory=dict)

    def add(self, symbol: SymbolKey, event: EvidenceEvent) -> None:
        events = self.events_by_symbol.setdefault(symbol, [])
        if event not in events:
            events.append(event)

    def events(self, symbol: SymbolKey) -> list[EvidenceEvent]:
        return list(self.events_by_symbol.get(symbol, []))

    def has_kind(self, symbol: SymbolKey, *kinds: EvidenceKind) -> bool:
        wanted = set(kinds)
        return any(event.kind in wanted for event in self.events(symbol))

    def classify(self, symbol: SymbolKey) -> CandidateClassification:
        events = self.events(symbol)
        if not events:
            return CandidateClassification.LIKELY_DEAD

        if any(event.kind == EvidenceKind.VALIDATION_PASS for event in events):
            return CandidateClassification.VALIDATED_DEAD

        if any(event.kind == EvidenceKind.VALIDATION_FAIL for event in events):
            return CandidateClassification.ALIVE

        if any(event.kind in ALIVE_EVIDENCE_KINDS for event in events):
            return CandidateClassification.ALIVE

        if any(event.kind == EvidenceKind.UNCERTAINTY for event in events):
            return CandidateClassification.UNCERTAIN

        return CandidateClassification.LIKELY_DEAD

    def decision(
        self,
        symbol: SymbolKey,
        *,
        definition: Any | None = None,
        threshold: int | None = None,
    ) -> EvidenceDecision:
        events = self.events(symbol)
        classification = self.classify(symbol)
        reason_tags = _decision_reason_tags(
            events,
            classification,
            definition=definition,
        )
        confidence = _safe_int(getattr(definition, "confidence", None))
        threshold_value = _safe_int(threshold)
        return EvidenceDecision(
            classification=classification,
            primary_reason=_primary_reason(reason_tags, classification),
            reason_tags=tuple(reason_tags),
            confidence=confidence,
            threshold=threshold_value,
            live_evidence_count=sum(
                1
                for event in events
                if event.kind in ALIVE_EVIDENCE_KINDS
                or event.kind == EvidenceKind.VALIDATION_FAIL
            ),
            dead_evidence_count=sum(
                1 for event in events if event.kind in DEAD_EVIDENCE_KINDS
            ),
            uncertainty_count=sum(
                1 for event in events if event.kind == EvidenceKind.UNCERTAINTY
            ),
        )

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for symbol in self.events_by_symbol:
            classification = self.classify(symbol).value
            counts[classification] = counts.get(classification, 0) + 1
        return {
            "symbol_count": len(self.events_by_symbol),
            "classification_policy": CLASSIFICATION_POLICY,
            "classifications": counts,
        }

    def to_dict(
        self,
        root: str | Path | None = None,
        *,
        definitions: dict[str, Any] | None = None,
        threshold: int | None = None,
    ) -> dict[str, Any]:
        symbols = []
        definitions_by_name = _definitions_by_qualified_name(definitions)
        for symbol in sorted(self.events_by_symbol):
            file_name = symbol.file if root is None else symbol.repo_relative_file(root)
            decision = self.decision(
                symbol,
                definition=definitions_by_name.get(symbol.qualified_name),
                threshold=threshold,
            )
            symbols.append(
                {
                    "file": file_name,
                    "qualified_name": symbol.qualified_name,
                    "kind": symbol.kind,
                    "line": symbol.line,
                    "classification": self.classify(symbol).value,
                    "decision": decision.to_dict(),
                    "evidence": [event.to_dict() for event in self.events(symbol)],
                }
            )
        return {
            "classification_policy": CLASSIFICATION_POLICY,
            "symbols": symbols,
        }


DEAD_CODE_SYMBOL_TYPES = {"class", "function", "method", "type", "variable"}


def build_dead_code_evidence(
    definitions: dict[str, Any],
    *,
    project_root: str | Path | None = None,
    pyproject_entrypoint_qnames: Iterable[str] | None = None,
    threshold: int | None = None,
) -> EvidenceLedger:
    ledger = EvidenceLedger()
    entrypoints = set(pyproject_entrypoint_qnames or ())

    for definition in definitions.values():
        if getattr(definition, "type", None) not in DEAD_CODE_SYMBOL_TYPES:
            continue

        symbol = SymbolKey.from_definition(definition)
        ledger.events_by_symbol.setdefault(symbol, [])
        _add_root_evidence(ledger, symbol, definition, entrypoints)
        _add_signal_evidence(ledger, symbol, definition)
        _add_uncertainty_evidence(ledger, symbol, definition)
        _add_reference_evidence(ledger, symbol, definition)
        _add_deadness_evidence(ledger, symbol, definition, threshold=threshold)

    return ledger


def _add_root_evidence(
    ledger: EvidenceLedger,
    symbol: SymbolKey,
    definition: Any,
    entrypoints: set[str],
) -> None:
    name = str(getattr(definition, "name", ""))
    simple_name = str(getattr(definition, "simple_name", ""))
    filename = str(getattr(definition, "filename", ""))

    if name in entrypoints:
        ledger.add(
            symbol,
            EvidenceEvent(
                kind=EvidenceKind.PACKAGE_ENTRYPOINT,
                reason="pyproject script entrypoint",
                source="pyproject.toml",
            ),
        )

    if simple_name.startswith("test_") or "/tests/" in filename.replace("\\", "/"):
        ledger.add(
            symbol,
            EvidenceEvent(
                kind=EvidenceKind.TEST_ENTRYPOINT,
                reason="test entrypoint or test module",
                source="python_ast",
            ),
        )

    if bool(getattr(definition, "is_exported", False)):
        ledger.add(
            symbol,
            EvidenceEvent(
                kind=EvidenceKind.FRAMEWORK_ROOT,
                reason="public export",
                source="python_ast",
                details={"root_kind": "public_export"},
            ),
        )


def _add_signal_evidence(
    ledger: EvidenceLedger,
    symbol: SymbolKey,
    definition: Any,
) -> None:
    for key, confidence in _iter_heuristic_refs(definition):
        event = _event_from_heuristic_ref(key, confidence)
        if event is not None:
            ledger.add(symbol, event)

    for signal in _iter_string_list(getattr(definition, "dynamic_signals", [])):
        ledger.add(
            symbol,
            EvidenceEvent(
                kind=EvidenceKind.DYNAMIC_PATTERN,
                reason=signal,
                source="dynamic_signal",
            ),
        )

    for signal in _iter_string_list(getattr(definition, "framework_signals", [])):
        ledger.add(
            symbol,
            EvidenceEvent(
                kind=EvidenceKind.UNCERTAINTY,
                reason=signal,
                source="framework_signal",
            ),
        )


def _add_reference_evidence(
    ledger: EvidenceLedger,
    symbol: SymbolKey,
    definition: Any,
) -> None:
    references = getattr(definition, "references", 0) or 0
    try:
        reference_count = int(references)
    except (TypeError, ValueError):
        reference_count = 0

    if reference_count <= 0:
        return

    source_specific_kinds = {
        EvidenceKind.REACHABLE_FROM_ROOT,
        EvidenceKind.TOP_LEVEL_EXECUTION,
        EvidenceKind.FRAMEWORK_ROOT,
        EvidenceKind.PACKAGE_ENTRYPOINT,
        EvidenceKind.TEST_ENTRYPOINT,
        EvidenceKind.DYNAMIC_PATTERN,
        EvidenceKind.COVERAGE_HIT,
        EvidenceKind.TRACE_HIT,
        EvidenceKind.GREP_RESCUE,
        EvidenceKind.UNCERTAINTY,
    }
    if ledger.has_kind(symbol, *source_specific_kinds):
        return

    ledger.add(
        symbol,
        EvidenceEvent(
            kind=EvidenceKind.STATIC_REFERENCE,
            reason="referenced by static analysis",
            source="analyzer",
            details={"references": reference_count},
        ),
    )


def _add_deadness_evidence(
    ledger: EvidenceLedger,
    symbol: SymbolKey,
    definition: Any,
    *,
    threshold: int | None,
) -> None:
    references = _safe_int(getattr(definition, "references", 0)) or 0
    confidence = _safe_int(getattr(definition, "confidence", None))
    threshold_value = _safe_int(threshold)

    if references > 0:
        return

    if references <= 0:
        ledger.add(
            symbol,
            EvidenceEvent(
                kind=EvidenceKind.NO_STATIC_REFERENCES,
                reason="no static references were found",
                source="analyzer",
                details={"references": references},
            ),
        )

    if not bool(getattr(definition, "is_exported", False)):
        ledger.add(
            symbol,
            EvidenceEvent(
                kind=EvidenceKind.NOT_EXPORTED,
                reason="symbol is not exported as public API",
                source="analyzer",
            ),
        )

    if not ledger.has_kind(symbol, *ENTRYPOINT_EVIDENCE_KINDS):
        ledger.add(
            symbol,
            EvidenceEvent(
                kind=EvidenceKind.NO_ENTRYPOINT,
                reason="no package, framework, test, or root entrypoint evidence",
                source="analyzer",
            ),
        )

    if (
        confidence is not None
        and threshold_value is not None
        and confidence >= threshold_value
    ):
        ledger.add(
            symbol,
            EvidenceEvent(
                kind=EvidenceKind.CONFIDENCE_GATE,
                reason="confidence meets the configured reporting threshold",
                source="confidence",
                confidence=_confidence_float(confidence),
                details={"confidence": confidence, "threshold": threshold_value},
            ),
        )


def _add_uncertainty_evidence(
    ledger: EvidenceLedger,
    symbol: SymbolKey,
    definition: Any,
) -> None:
    skip_reason = getattr(definition, "skip_reason", None)
    if skip_reason:
        ledger.add(
            symbol,
            EvidenceEvent(
                kind=EvidenceKind.UNCERTAINTY,
                reason=str(skip_reason),
                source="suppression",
            ),
        )

    for reason in _iter_string_list(getattr(definition, "why_confidence_reduced", [])):
        ledger.add(
            symbol,
            EvidenceEvent(
                kind=EvidenceKind.UNCERTAINTY,
                reason=reason,
                source="confidence",
            ),
        )

    for reason in _reference_safe_uncertainty_reasons(definition):
        ledger.add(
            symbol,
            EvidenceEvent(
                kind=EvidenceKind.UNCERTAINTY,
                reason=reason,
                source="reference_safe_policy",
            ),
        )


def _event_from_heuristic_ref(key: str, confidence: Any) -> EvidenceEvent | None:
    value = _confidence_float(confidence)

    if key == "grep_verify":
        return EvidenceEvent(
            kind=EvidenceKind.GREP_RESCUE,
            reason="grep verification found a usage",
            source="grep_verify",
            confidence=value,
        )

    if key == "reachable_from_root":
        return EvidenceEvent(
            kind=EvidenceKind.REACHABLE_FROM_ROOT,
            reason="reachable from inferred root",
            source="reachability",
            confidence=value,
        )

    if key == "package_entrypoint":
        return EvidenceEvent(
            kind=EvidenceKind.PACKAGE_ENTRYPOINT,
            reason="pyproject script entrypoint",
            source="pyproject.toml",
            confidence=value,
        )

    if key == "framework_root":
        return EvidenceEvent(
            kind=EvidenceKind.FRAMEWORK_ROOT,
            reason="framework root",
            source="framework",
            confidence=value,
            details={"root_kind": "framework_route"},
        )

    if key == "test_entrypoint":
        return EvidenceEvent(
            kind=EvidenceKind.TEST_ENTRYPOINT,
            reason="pytest test or fixture entrypoint",
            source="python_ast",
            confidence=value,
        )

    if key == "top_level_execution":
        return EvidenceEvent(
            kind=EvidenceKind.TOP_LEVEL_EXECUTION,
            reason="called during module top-level execution",
            source="python_ast",
            confidence=value,
        )

    if key == "dynamic_pattern":
        return EvidenceEvent(
            kind=EvidenceKind.DYNAMIC_PATTERN,
            reason="dynamic reference matched symbol",
            source="implicit_refs",
            confidence=value,
        )

    if key == "coverage_hit":
        return EvidenceEvent(
            kind=EvidenceKind.COVERAGE_HIT,
            reason="executed according to coverage data",
            source="coverage",
            confidence=value,
        )

    if key == "trace_hit":
        return EvidenceEvent(
            kind=EvidenceKind.TRACE_HIT,
            reason="executed according to call trace",
            source="trace",
            confidence=value,
        )

    if key in {"same_file_attr", "same_pkg_attr", "global_attr"}:
        return EvidenceEvent(
            kind=EvidenceKind.DYNAMIC_PATTERN,
            reason=key,
            source="attribute_reference",
            confidence=value,
        )

    if key.startswith("dead_code_liveness:"):
        reason = key.split(":", 1)[1] or "liveness rescue"
        return EvidenceEvent(
            kind=EvidenceKind.UNCERTAINTY,
            reason=reason,
            source="dead_code_liveness",
            confidence=value,
        )

    return None


def _iter_heuristic_refs(definition: Any) -> Iterable[tuple[str, Any]]:
    refs = getattr(definition, "heuristic_refs", {}) or {}
    if not isinstance(refs, dict):
        return ()
    return ((str(key), value) for key, value in refs.items())


def _iter_string_list(values: Any) -> Iterable[str]:
    if not isinstance(values, (list, tuple, set)):
        return ()
    return (str(value) for value in values if value)


def _confidence_float(value: Any) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return 1.0
    if numeric > 1:
        return max(0.0, min(numeric / 100.0, 1.0))
    return max(0.0, min(numeric, 1.0))


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _definitions_by_qualified_name(
    definitions: dict[str, Any] | None,
) -> dict[str, Any]:
    by_name: dict[str, Any] = {}
    if not definitions:
        return by_name
    for definition in definitions.values():
        name = str(getattr(definition, "name", ""))
        if name:
            by_name[name] = definition
    return by_name


def _event_role(kind: EvidenceKind) -> str:
    if kind in DEAD_EVIDENCE_KINDS or kind == EvidenceKind.VALIDATION_PASS:
        return "supports_dead"
    if kind in ALIVE_EVIDENCE_KINDS or kind == EvidenceKind.VALIDATION_FAIL:
        return "supports_live"
    if kind == EvidenceKind.UNCERTAINTY:
        return "uncertainty"
    return "context"


def _decision_reason_tags(
    events: list[EvidenceEvent],
    classification: CandidateClassification,
    *,
    definition: Any | None,
) -> list[str]:
    if classification == CandidateClassification.VALIDATED_DEAD:
        return ["validated_dead"]

    if any(event.kind == EvidenceKind.VALIDATION_FAIL for event in events):
        return ["validation_failed"]

    live_tags = _live_reason_tags(events)
    if live_tags:
        return live_tags

    dead_tags = _dead_reason_tags(events, definition)

    if any(event.kind == EvidenceKind.UNCERTAINTY for event in events):
        return _dedupe(["uncertainty", *dead_tags])

    if dead_tags:
        return _dedupe(dead_tags)

    return ["no_liveness_evidence"]


def _live_reason_tags(events: list[EvidenceEvent]) -> list[str]:
    tags = [
        _event_reason_tag(event.kind)
        for event in events
        if event.kind in ALIVE_EVIDENCE_KINDS
    ]
    return _dedupe(tag for tag in tags if tag)


def _dead_reason_tags(
    events: list[EvidenceEvent],
    definition: Any | None,
) -> list[str]:
    tags: list[str] = []
    if _has_no_static_refs(events, definition):
        tags.append("no_refs")
    if _is_not_exported(events, definition):
        tags.append("not_exported")
    if _has_event_kind(events, EvidenceKind.NO_ENTRYPOINT):
        tags.append("no_entrypoint")
    if _has_event_kind(events, EvidenceKind.CONFIDENCE_GATE):
        tags.append("confidence_ge_threshold")
    return _dedupe(tags)


def _has_no_static_refs(
    events: list[EvidenceEvent],
    definition: Any | None,
) -> bool:
    if _has_event_kind(events, EvidenceKind.NO_STATIC_REFERENCES):
        return True
    if definition is None:
        return False
    return (_safe_int(getattr(definition, "references", 0)) or 0) <= 0


def _is_not_exported(
    events: list[EvidenceEvent],
    definition: Any | None,
) -> bool:
    if _has_event_kind(events, EvidenceKind.NOT_EXPORTED):
        return True
    if definition is None:
        return False
    return not bool(getattr(definition, "is_exported", False))


def _has_event_kind(events: list[EvidenceEvent], kind: EvidenceKind) -> bool:
    return any(event.kind == kind for event in events)


def _event_reason_tag(kind: EvidenceKind) -> str:
    return {
        EvidenceKind.STATIC_REFERENCE: "static_reference",
        EvidenceKind.REACHABLE_FROM_ROOT: "reachable_from_root",
        EvidenceKind.TOP_LEVEL_EXECUTION: "top_level_execution",
        EvidenceKind.FRAMEWORK_ROOT: "framework_root",
        EvidenceKind.PACKAGE_ENTRYPOINT: "package_entrypoint",
        EvidenceKind.TEST_ENTRYPOINT: "test_entrypoint",
        EvidenceKind.DYNAMIC_PATTERN: "dynamic_pattern",
        EvidenceKind.COVERAGE_HIT: "coverage_hit",
        EvidenceKind.TRACE_HIT: "trace_hit",
        EvidenceKind.GREP_RESCUE: "grep_rescue",
    }.get(kind, "")


def _primary_reason(
    reason_tags: list[str],
    classification: CandidateClassification,
) -> str:
    labels = [
        DECISION_REASON_LABELS.get(tag, tag.replace("_", " "))
        for tag in reason_tags
    ]
    if labels:
        return "; ".join(labels[:3])
    return DECISION_REASON_LABELS.get(classification.value, classification.value)


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _reference_safe_uncertainty_reasons(definition: Any) -> Iterable[str]:
    symbol_type = str(getattr(definition, "type", ""))
    qname = str(getattr(definition, "name", ""))
    simple_name = str(getattr(definition, "simple_name", ""))

    if symbol_type == "method" and simple_name == "__init__":
        yield "constructor method"

    if symbol_type == "method" and _is_implicit_python_protocol_method(simple_name):
        yield "implicit Python protocol method"

    if symbol_type == "method" and _is_framework_lifecycle_hook(simple_name):
        yield "framework lifecycle hook"

    if symbol_type == "function" and _is_weak_helper_function(simple_name):
        yield "weak helper function"

    if symbol_type == "variable" and "." not in qname:
        if _is_weak_module_temporary(simple_name):
            yield "weak module temporary"


def _is_weak_module_temporary(name: str) -> bool:
    if name in {"__version__", "LIVE_RESULT", "BOOT_RESULT"}:
        return True
    if name != name.lower():
        return False
    return name in {
        "result",
        "internal_result",
        "output",
        "class_result",
    }


def _is_weak_helper_function(name: str) -> bool:
    return name.startswith("format_") or name.endswith("_name")


def _is_implicit_python_protocol_method(name: str) -> bool:
    return name in {
        "__aenter__",
        "__aexit__",
        "__aiter__",
        "__anext__",
        "__enter__",
        "__exit__",
        "__iter__",
        "__next__",
    }


def _is_framework_lifecycle_hook(name: str) -> bool:
    return name == "compose" or name.startswith(("on_", "watch_"))
