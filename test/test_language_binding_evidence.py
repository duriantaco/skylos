from __future__ import annotations

from skylos.deadcode.confidence import calibrate_dead_code_confidence
from skylos.deadcode.evidence import (
    CandidateClassification,
    SymbolKey,
    build_dead_code_evidence,
)
from skylos.visitors.base import Definition


def test_csharp_class_attribute_cap_finds_encoded_type_identity():
    owner = Definition("Demo.Owner", "class", "Owner.cs", 1)
    variable = Definition("Demo.Owner.value", "variable", "Owner.cs", 2)
    definitions = {"csharp:type:Demo.Owner": owner, "field": variable}
    calibrate_dead_code_confidence(definitions)
    assert variable.confidence == 80
    assert "class_attribute" in variable.confidence_factors


def test_unresolved_dart_import_has_explicit_uncertainty_not_liveness():
    definition = Definition("external", "import", "main.dart", 1)
    definition.why_confidence_reduced.append(
        "Unresolved package exports may supply referenced ExtensionType"
    )
    ledger = build_dead_code_evidence({"import": definition}, threshold=60)
    symbol = SymbolKey.from_definition(definition)
    assert ledger.classify(symbol) == CandidateClassification.UNCERTAIN
    decision = ledger.decision(symbol, definition=definition, threshold=60)
    assert decision.live_evidence_count == 0
    assert decision.uncertainty_count == 1


def test_resolved_unused_dart_import_remains_a_dead_candidate():
    definition = Definition("unused", "import", "main.dart", 1)
    ledger = build_dead_code_evidence({"import": definition}, threshold=60)
    symbol = SymbolKey.from_definition(definition)
    assert ledger.classify(symbol) == CandidateClassification.LIKELY_DEAD
