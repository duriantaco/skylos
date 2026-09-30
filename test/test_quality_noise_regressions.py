"""Focused regressions for generic quality finding noise."""

import ast
import textwrap

from skylos.core.linter import LinterVisitor
from skylos.rules.quality.logic_foundation import EmptyErrorHandlerRule
from skylos.rules.quality.logic_maintainability import (
    BroadExceptionRule,
    DuplicateStringLiteralRule,
    TooManyReturnsRule,
)


def _tree(source: str) -> ast.Module:
    return ast.parse(textwrap.dedent(source))


def _findings(rule, source: str) -> list[dict]:
    tree = _tree(source)
    findings = []
    for node in ast.walk(tree):
        findings.extend(rule.visit_node(node, {"filename": "app.py"}) or [])
    return findings


def test_duplicate_strings_skip_proven_mapping_lookup_keys_but_keep_defaults():
    findings = _findings(
        DuplicateStringLiteralRule(),
        """
        def status(record: dict[str, str]):
            return (
                record.get("phase", "fallback"),
                record.get("phase", "fallback"),
                record.get("phase", "fallback"),
            )
        """,
    )
    assert [finding["name"] for finding in findings] == ["fallback"]


def test_duplicate_strings_skip_class_dict_and_subscript_proven_keys():
    findings = _findings(
        DuplicateStringLiteralRule(),
        """
        class Session:
            def __init__(self):
                self.state = {}

            def read(self):
                return (
                    self.state.get("flightId"),
                    self.state.get("flightId"),
                    self.state.get("flightId"),
                )

        def update(record):
            record["status"] = "ready"
            record.setdefault("status", "ready")
            record.pop("status")
            record.get("status")
        """,
    )
    assert findings == []


def test_duplicate_strings_keep_arbitrary_get_methods_and_scope_boundaries():
    findings = _findings(
        DuplicateStringLiteralRule(),
        """
        def known(data: dict):
            return data.get("endpoint"), data.get("endpoint"), data.get("endpoint")

        def unknown(data):
            return data.get("endpoint"), data.get("endpoint"), data.get("endpoint")
        """,
    )
    assert len(findings) == 1
    assert findings[0]["name"] == "endpoint"
    assert findings[0]["value"] == 3


def test_duplicate_strings_do_not_share_mapping_proof_across_classes():
    findings = _findings(
        DuplicateStringLiteralRule(),
        """
        class A:
            cache = {}

        class B:
            cache = unknown_client
            a = cache.get("endpoint")
            b = cache.get("endpoint")
            c = cache.get("endpoint")
        """,
    )
    assert len(findings) == 1
    assert findings[0]["name"] == "endpoint"


def test_duplicate_strings_do_not_trust_unrelated_items_method():
    findings = _findings(
        DuplicateStringLiteralRule(),
        """
        def read(client):
            client.items()
            return (
                client.get("endpoint"),
                client.get("endpoint"),
                client.get("endpoint"),
            )
        """,
    )
    assert len(findings) == 1
    assert findings[0]["name"] == "endpoint"


def test_duplicate_strings_do_not_trust_stale_mapping_assignment():
    findings = _findings(
        DuplicateStringLiteralRule(),
        """
        def read():
            client = {}
            client = RequestClient()
            return (
                client.get("/same/path"),
                client.get("/same/path"),
                client.get("/same/path"),
            )
        """,
    )
    assert len(findings) == 1
    assert findings[0]["name"] == "/same/path"


def test_duplicate_strings_keep_stable_mapping_assignment_suppression():
    findings = _findings(
        DuplicateStringLiteralRule(),
        """
        def read():
            record = {}
            return (
                record.get("statusCode"),
                record.get("statusCode"),
                record.get("statusCode"),
            )
        """,
    )
    assert findings == []


def test_duplicate_strings_do_not_trust_mapping_shadowed_by_comprehension():
    findings = _findings(
        DuplicateStringLiteralRule(),
        """
        def read(clients):
            record = {}
            return [
                (
                    record.get("statusCode"),
                    record.get("statusCode"),
                    record.get("statusCode"),
                )
                for record in clients
            ]
        """,
    )
    assert len(findings) == 1
    assert findings[0]["name"] == "statusCode"


def test_duplicate_strings_do_not_trust_mapping_shadowed_by_except_as():
    findings = _findings(
        DuplicateStringLiteralRule(),
        """
        def read():
            record = {}
            try:
                risky()
            except CustomError as record:
                return (
                    record.get("statusCode"),
                    record.get("statusCode"),
                    record.get("statusCode"),
                )
        """,
    )
    assert len(findings) == 1
    assert findings[0]["name"] == "statusCode"


def test_return_limit_is_inclusive():
    source = "def choose(value):\n" + "\n".join(
        f"    if value == {index}: return {index}" for index in range(5)
    )
    assert _findings(TooManyReturnsRule(), source) == []
    assert len(_findings(TooManyReturnsRule(), source + "\n    return None")) == 1


def test_empty_broad_handler_has_one_l007_finding():
    source = """
        def work():
            try:
                risky()
            except Exception:
                pass
    """
    assert len(_findings(EmptyErrorHandlerRule(), source)) == 1
    assert _findings(BroadExceptionRule(), source) == []


def test_broad_placeholder_return_has_one_l030_finding():
    source = """
        def work():
            try:
                risky()
            except Exception:
                return None
    """
    assert _findings(EmptyErrorHandlerRule(), source) == []
    broad = _findings(BroadExceptionRule(), source)
    assert len(broad) == 1
    assert broad[0]["severity"] == "HIGH"


def test_narrow_typed_fallback_remains_excluded():
    source = """
        def work():
            try:
                risky()
            except ValueError:
                return None
    """
    assert _findings(EmptyErrorHandlerRule(), source) == []
    assert _findings(BroadExceptionRule(), source) == []


def test_linter_emits_one_diagnosis_per_broad_trivial_handler():
    source = """
        def work():
            try:
                risky()
            except Exception:
                pass
            try:
                risky()
            except Exception:
                return None
    """
    linter = LinterVisitor(
        [EmptyErrorHandlerRule(), BroadExceptionRule()], "app.py"
    )
    linter.visit(_tree(source))
    assert [(item["rule_id"], item["severity"]) for item in linter.findings] == [
        ("SKY-L007", "MEDIUM"),
        ("SKY-L030", "HIGH"),
    ]
