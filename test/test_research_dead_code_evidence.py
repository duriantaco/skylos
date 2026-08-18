from skylos.research.dead_code import (
    CandidateClassification,
    EvidenceEvent,
    EvidenceKind,
    EvidenceLedger,
    InferredRoot,
    RootKind,
    RootSet,
    SymbolKey,
)


def test_empty_symbol_is_likely_dead():
    ledger = EvidenceLedger()
    symbol = SymbolKey(file="app.py", qualified_name="app.stale", kind="function", line=3)

    assert ledger.classify(symbol) == CandidateClassification.LIKELY_DEAD


def test_framework_root_marks_symbol_alive():
    symbol = SymbolKey(file="app.py", qualified_name="app.route", kind="function", line=10)
    roots = RootSet()
    roots.add(
        InferredRoot(
            symbol=symbol,
            kind=RootKind.FRAMEWORK_ROUTE,
            reason="FastAPI route decorator",
            source="framework_aware",
        )
    )
    ledger = EvidenceLedger()
    roots.apply_to(ledger)

    assert ledger.classify(symbol) == CandidateClassification.ALIVE
    assert ledger.has_kind(symbol, EvidenceKind.FRAMEWORK_ROOT)


def test_validation_pass_marks_candidate_validated_dead():
    ledger = EvidenceLedger()
    symbol = SymbolKey(file="service.py", qualified_name="service.old", kind="function", line=8)
    ledger.add(
        symbol,
        EvidenceEvent(
            kind=EvidenceKind.VALIDATION_PASS,
            reason="targeted tests passed after stubbing",
            source="validator",
        ),
    )

    assert ledger.classify(symbol) == CandidateClassification.VALIDATED_DEAD


def test_validation_fail_overrides_dead_candidate():
    ledger = EvidenceLedger()
    symbol = SymbolKey(file="service.py", qualified_name="service.live", kind="function", line=12)
    ledger.add(
        symbol,
        EvidenceEvent(
            kind=EvidenceKind.VALIDATION_FAIL,
            reason="import smoke test failed after deletion",
            source="validator",
        ),
    )

    assert ledger.classify(symbol) == CandidateClassification.ALIVE
