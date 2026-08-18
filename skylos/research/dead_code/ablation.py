from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from skylos.research.dead_code.evidence import (
    CandidateClassification,
    EvidenceLedger,
    SymbolKey,
)
from skylos.research.dead_code.reachability import (
    ReachabilityResult,
    analyze_reachability,
    build_function_graph,
)
from skylos.research.dead_code.root_inference import infer_roots


class ResearchVariant(StrEnum):
    ROOTS_ONLY = "v1-roots-only"
    ROOTS_REACHABILITY = "v2-roots-reachability"
    TOP_LEVEL_REACHABILITY = "v3-top-level-execution"
    FACTORY_RETURN_SUMMARIES = "v4-factory-return-summaries"
    CONSERVATIVE_REPORTING = "v5-conservative-reporting"
    GENERAL_ACTION_REPORTING = "v6-general-action-reporting"
    REFERENCE_SAFE_REPORTING = "v7-reference-safe-reporting"


@dataclass
class AblationResult:
    variant: ResearchVariant
    project_root: Path
    symbols: dict[str, SymbolKey]
    ledger: EvidenceLedger
    reachable: set[str]
    roots: set[str]
    protocol_classes: set[str] | None = None
    abstract_methods: set[str] | None = None
    interface_stub_methods: set[str] | None = None
    registry_side_effect_classes: set[str] | None = None
    suppressed_symbols: set[str] | None = None
    type_alias_variables: set[str] | None = None
    action_blocking_symbols: set[str] | None = None

    def classify(self, qualified_name: str) -> CandidateClassification:
        symbol = self.symbols[qualified_name]
        classification = self.ledger.classify(symbol)
        if self.variant not in {
            ResearchVariant.CONSERVATIVE_REPORTING,
            ResearchVariant.GENERAL_ACTION_REPORTING,
            ResearchVariant.REFERENCE_SAFE_REPORTING,
        }:
            return classification
        conservative = _apply_conservative_reporting_policy(
            symbol,
            classification,
            symbols=self.symbols,
            ledger=self.ledger,
            protocol_classes=self.protocol_classes or set(),
        )
        if self.variant == ResearchVariant.CONSERVATIVE_REPORTING:
            return conservative
        return _apply_general_action_reporting_policy(
            symbol,
            conservative,
            abstract_methods=self.abstract_methods or set(),
            interface_stub_methods=self.interface_stub_methods or set(),
            registry_side_effect_classes=self.registry_side_effect_classes or set(),
            suppressed_symbols=self.suppressed_symbols or set(),
            type_alias_variables=self.type_alias_variables or set(),
            action_blocking_symbols=(
                self.action_blocking_symbols or set()
                if self.variant == ResearchVariant.REFERENCE_SAFE_REPORTING
                else set()
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        root = self.project_root
        entries = []
        for qname in sorted(self.symbols):
            symbol = self.symbols[qname]
            entries.append(
                {
                    "file": symbol.repo_relative_file(root),
                    "qualified_name": symbol.qualified_name,
                    "kind": symbol.kind,
                    "line": symbol.line,
                    "classification": self.classify(qname).value,
                    "is_root": qname in self.roots,
                    "is_reachable": qname in self.reachable,
                    "evidence": [
                        event.to_dict()
                        for event in self.ledger.events(symbol)
                    ],
                }
            )
        counts: dict[str, int] = {}
        for entry in entries:
            classification = str(entry["classification"])
            counts[classification] = counts.get(classification, 0) + 1

        return {
            "variant": self.variant.value,
            "project_root": str(root),
            "summary": {
                "symbol_count": len(entries),
                "root_count": len(self.roots),
                "reachable_count": len(self.reachable),
                "classifications": counts,
            },
            "symbols": entries,
        }


def run_ablation(
    project_root: str | Path,
    *,
    variant: ResearchVariant | str,
) -> AblationResult:
    selected = ResearchVariant(variant)
    root_path = Path(project_root).resolve()

    if selected == ResearchVariant.ROOTS_ONLY:
        return _run_roots_only(root_path)
    if selected == ResearchVariant.ROOTS_REACHABILITY:
        return _run_roots_reachability(root_path)
    if selected == ResearchVariant.TOP_LEVEL_REACHABILITY:
        return _run_top_level_reachability(root_path)
    if selected == ResearchVariant.FACTORY_RETURN_SUMMARIES:
        return _run_factory_return_summaries(root_path)
    if selected == ResearchVariant.CONSERVATIVE_REPORTING:
        return _run_conservative_reporting(root_path)
    if selected == ResearchVariant.GENERAL_ACTION_REPORTING:
        return _run_general_action_reporting(root_path)
    if selected == ResearchVariant.REFERENCE_SAFE_REPORTING:
        return _run_reference_safe_reporting(root_path)
    raise ValueError(f"unsupported research variant: {variant}")


def _run_roots_only(project_root: Path) -> AblationResult:
    graph = build_function_graph(project_root)
    roots = infer_roots(project_root)
    ledger = EvidenceLedger()
    root_qnames: set[str] = set()

    for root in roots.roots:
        qname = root.symbol.qualified_name
        root_qnames.add(qname)
        symbol = graph.symbols.get(qname, root.symbol)
        ledger.add(symbol, root.to_evidence())

    return AblationResult(
        variant=ResearchVariant.ROOTS_ONLY,
        project_root=project_root,
        symbols=dict(graph.symbols),
        ledger=ledger,
        reachable=set(root_qnames & graph.symbols.keys()),
        roots=root_qnames,
    )


def _run_roots_reachability(project_root: Path) -> AblationResult:
    result: ReachabilityResult = analyze_reachability(project_root)
    return AblationResult(
        variant=ResearchVariant.ROOTS_REACHABILITY,
        project_root=project_root,
        symbols=dict(result.graph.symbols),
        ledger=result.ledger,
        reachable=set(result.reachable),
        roots={root.symbol.qualified_name for root in result.roots.roots},
        protocol_classes=set(result.graph.protocol_classes),
    )


def _run_top_level_reachability(project_root: Path) -> AblationResult:
    result: ReachabilityResult = analyze_reachability(
        project_root,
        include_top_level=True,
    )
    return AblationResult(
        variant=ResearchVariant.TOP_LEVEL_REACHABILITY,
        project_root=project_root,
        symbols=dict(result.graph.symbols),
        ledger=result.ledger,
        reachable=set(result.reachable),
        roots={root.symbol.qualified_name for root in result.roots.roots}
        | set(result.graph.top_level_calls),
        protocol_classes=set(result.graph.protocol_classes),
    )


def _run_factory_return_summaries(project_root: Path) -> AblationResult:
    result: ReachabilityResult = analyze_reachability(
        project_root,
        include_top_level=True,
        include_factory_returns=True,
    )
    return AblationResult(
        variant=ResearchVariant.FACTORY_RETURN_SUMMARIES,
        project_root=project_root,
        symbols=dict(result.graph.symbols),
        ledger=result.ledger,
        reachable=set(result.reachable),
        roots={root.symbol.qualified_name for root in result.roots.roots}
        | set(result.graph.top_level_calls),
        protocol_classes=set(result.graph.protocol_classes),
    )


def _run_conservative_reporting(project_root: Path) -> AblationResult:
    result: ReachabilityResult = analyze_reachability(
        project_root,
        include_top_level=True,
        include_factory_returns=True,
    )
    return AblationResult(
        variant=ResearchVariant.CONSERVATIVE_REPORTING,
        project_root=project_root,
        symbols=dict(result.graph.symbols),
        ledger=result.ledger,
        reachable=set(result.reachable),
        roots={root.symbol.qualified_name for root in result.roots.roots}
        | set(result.graph.top_level_calls),
        protocol_classes=set(result.graph.protocol_classes),
    )


def _run_general_action_reporting(project_root: Path) -> AblationResult:
    result: ReachabilityResult = analyze_reachability(
        project_root,
        include_top_level=True,
        include_factory_returns=True,
        include_general_action_edges=True,
    )
    return AblationResult(
        variant=ResearchVariant.GENERAL_ACTION_REPORTING,
        project_root=project_root,
        symbols=dict(result.graph.symbols),
        ledger=result.ledger,
        reachable=set(result.reachable),
        roots={root.symbol.qualified_name for root in result.roots.roots}
        | set(result.graph.top_level_calls),
        protocol_classes=set(result.graph.protocol_classes),
        abstract_methods=set(result.graph.abstract_methods),
        interface_stub_methods=set(result.graph.interface_stub_methods),
        registry_side_effect_classes=set(result.graph.registry_side_effect_classes),
        suppressed_symbols=set(result.graph.suppressed_symbols),
        type_alias_variables=set(result.graph.type_alias_variables),
    )


def _run_reference_safe_reporting(project_root: Path) -> AblationResult:
    result: ReachabilityResult = analyze_reachability(
        project_root,
        include_top_level=True,
        include_factory_returns=True,
        include_general_action_edges=True,
    )
    return AblationResult(
        variant=ResearchVariant.REFERENCE_SAFE_REPORTING,
        project_root=project_root,
        symbols=dict(result.graph.symbols),
        ledger=result.ledger,
        reachable=set(result.reachable),
        roots={root.symbol.qualified_name for root in result.roots.roots}
        | set(result.graph.top_level_calls),
        protocol_classes=set(result.graph.protocol_classes),
        abstract_methods=set(result.graph.abstract_methods),
        interface_stub_methods=set(result.graph.interface_stub_methods),
        registry_side_effect_classes=set(result.graph.registry_side_effect_classes),
        suppressed_symbols=set(result.graph.suppressed_symbols),
        type_alias_variables=set(result.graph.type_alias_variables),
        action_blocking_symbols=_general_action_blocking_symbols(result),
    )


def _general_action_blocking_symbols(result: ReachabilityResult) -> set[str]:
    graph = result.graph
    blocked = set(graph.action_blocking_references)

    for caller, callees in graph.calls.items():
        if caller not in graph.symbols or caller in result.reachable:
            continue
        blocked.update(callee for callee in callees if callee in graph.symbols)

    if graph.ambiguous_reference_names:
        blocked.update(
            qname
            for qname in graph.symbols
            if qname.rsplit(".", 1)[-1] in graph.ambiguous_reference_names
        )

    alive_or_executed = (
        set(result.reachable)
        | set(graph.top_level_calls)
        | {root.symbol.qualified_name for root in result.roots.roots}
    )
    by_leaf: dict[str, set[str]] = {}
    for qname in graph.symbols:
        by_leaf.setdefault(qname.rsplit(".", 1)[-1], set()).add(qname)
    for qnames in by_leaf.values():
        if len(qnames) > 1 and qnames & alive_or_executed:
            blocked.update(qnames)

    return blocked


def _apply_conservative_reporting_policy(
    symbol: SymbolKey,
    classification: CandidateClassification,
    *,
    symbols: dict[str, SymbolKey],
    ledger: EvidenceLedger,
    protocol_classes: set[str],
) -> CandidateClassification:
    qname = symbol.qualified_name
    name = qname.rsplit(".", 1)[-1]
    parent_qname = qname.rsplit(".", 1)[0] if "." in qname else ""

    if qname in protocol_classes or parent_qname in protocol_classes:
        return CandidateClassification.UNCERTAIN

    if classification != CandidateClassification.LIKELY_DEAD:
        return classification

    if symbol.kind == "method" and name == "__init__":
        return CandidateClassification.UNCERTAIN

    parent = symbols.get(parent_qname)
    if (
        symbol.kind == "method"
        and parent is not None
        and parent.kind == "class"
        and _is_container_duplicate_method(name)
    ):
        parent_classification = _apply_conservative_reporting_policy(
            parent,
            ledger.classify(parent),
            symbols=symbols,
            ledger=ledger,
            protocol_classes=protocol_classes,
        )
        if parent_classification == CandidateClassification.LIKELY_DEAD:
            return CandidateClassification.UNCERTAIN

    if parent is not None and parent.kind != "class":
        parent_classification = _apply_conservative_reporting_policy(
            parent,
            ledger.classify(parent),
            symbols=symbols,
            ledger=ledger,
            protocol_classes=protocol_classes,
        )
        if parent_classification == CandidateClassification.LIKELY_DEAD:
            return CandidateClassification.UNCERTAIN

    if symbol.kind == "variable" and _is_weak_module_temporary(name):
        return CandidateClassification.UNCERTAIN

    if symbol.kind == "function" and _is_weak_helper_function(name):
        return CandidateClassification.UNCERTAIN

    return classification


def _apply_general_action_reporting_policy(
    symbol: SymbolKey,
    classification: CandidateClassification,
    *,
    abstract_methods: set[str],
    interface_stub_methods: set[str],
    registry_side_effect_classes: set[str],
    suppressed_symbols: set[str],
    type_alias_variables: set[str],
    action_blocking_symbols: set[str],
) -> CandidateClassification:
    qname = symbol.qualified_name
    name = qname.rsplit(".", 1)[-1]

    if classification != CandidateClassification.LIKELY_DEAD:
        return classification

    if qname in action_blocking_symbols:
        return CandidateClassification.UNCERTAIN

    if qname in suppressed_symbols:
        return CandidateClassification.UNCERTAIN

    if symbol.kind == "variable" and qname in type_alias_variables:
        return CandidateClassification.UNCERTAIN

    if symbol.kind == "class" and qname in registry_side_effect_classes:
        return CandidateClassification.UNCERTAIN

    if symbol.kind == "method" and qname in abstract_methods:
        return CandidateClassification.UNCERTAIN

    if symbol.kind == "method" and qname in interface_stub_methods:
        return CandidateClassification.UNCERTAIN

    if symbol.kind == "method" and _is_implicit_python_protocol_method(name):
        return CandidateClassification.UNCERTAIN

    if symbol.kind == "method" and _is_framework_lifecycle_hook(name):
        return CandidateClassification.UNCERTAIN

    return classification


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


def _is_container_duplicate_method(name: str) -> bool:
    return name in {
        "apply",
        "export",
        "handle",
        "make_handler",
        "refresh",
        "render",
        "run",
    }


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
