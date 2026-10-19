"""Observed Boolean calls preserve declarations and require positive binding."""

import ast
from copy import deepcopy
import textwrap

import pytest

from skylos.reporting.advice_policy import (
    apply_advice_policy,
    optional_advice_reason,
    prepare_advice_view,
)
from skylos.rules.quality.logic_maintainability import BooleanTrapRule


def _findings(source):
    tree = ast.parse(textwrap.dedent(source))
    rule = BooleanTrapRule()
    context = {"filename": "app.py"}
    return [
        row for node in ast.walk(tree) for row in rule.visit_node(node, context) or []
    ]


def _one(source):
    [row] = _findings(source)
    return row


def _assert_optional_record_is_preserved_and_selectable(row):
    """Default eligibility is separate from whether the rule proved a call."""
    raw = {"quality": [row]}
    before = deepcopy(row)
    assert optional_advice_reason(row, "quality") == "measurement"
    report = apply_advice_policy(raw)
    assert report["quality"][0]["call_evidence"] == row["call_evidence"]
    assert report["quality"][0]["listing"] == {
        "version": 1,
        "listed": False,
        "reason": "measurement",
    }
    assert (
        prepare_advice_view(report, all_advice=True)[0]["quality"] == report["quality"]
    )
    selected = apply_advice_policy(raw, explicit_rules=["SKY-L029"])
    assert prepare_advice_view(selected)[0]["quality"] == selected["quality"]
    from skylos.core.gatekeeper import check_gate

    assert check_gate(selected, {"gate": {"max_quality": 0}})[0] is False
    assert row == before


@pytest.mark.parametrize(
    "source,value",
    [
        ("def publish(enabled: bool = False): pass\npublish(True)", True),
        (
            "def caller(): publish(False)\ndef publish(enabled: bool = False): pass",
            False,
        ),
        (
            "def publish(enabled: bool = False): pass\nfirst = publish\nsecond = first\nsecond(False)",
            False,
        ),
        ("def publish(enabled: bool = False):\n    publish(False)", False),
    ],
)
def test_existing_public_signature_gains_actual_local_call_evidence(source, value):
    row = _one(source)
    assert row["name"] == "publish.enabled"
    assert row["call_evidence"][0]["value"] is value
    assert row["call_evidence"][0]["binding"] == "local_definition"
    assert "called positionally" in row["message"]
    _assert_optional_record_is_preserved_and_selectable(row)


@pytest.mark.parametrize(
    "caller",
    [
        "publish(enabled=False)",
        "def caller(publish): publish(False)",
        "def caller():\n    from external import publish\n    publish(False)",
        "alias = publish\nalias = external\nalias(False)",
        "publish = external\npublish(False)",
        "from external import publish\npublish(False)",
        "(publish if condition else external)(False)",
        "publish(*values, False)",
        "publish(False, enabled=True)",
        "publish(False, 2)",
        "globals()['publish'] = external\npublish(False)",
    ],
)
def test_unknown_or_invalid_call_does_not_promote_public_signature_advice(caller):
    row = _one("def publish(enabled: bool = False): pass\n" + caller)
    assert row["name"] == "publish.enabled"
    assert "call_evidence" not in row
    assert "permits positional calls" in row["message"]
    assert optional_advice_reason(row, "quality") == "boolean_signature"


def test_redefined_public_functions_keep_all_signature_findings_without_call_attribution():
    rows = _findings(
        "def publish(enabled: bool = False): pass\n"
        "def publish(enabled: bool = False): pass\npublish(False)"
    )
    assert len(rows) == 2
    assert all("call_evidence" not in row for row in rows)


@pytest.mark.parametrize("name", ["force", "strict", "reverse", "verbose"])
def test_allowed_public_flags_keep_their_existing_policy_even_with_bare_calls(name):
    assert _findings(f"def publish({name}: bool = False): pass\npublish(True)") == []


def test_private_allowed_flag_needs_a_proven_bare_call():
    row = _one('def _private(path, force=False): pass\n_private("p", True)')
    assert row["name"] == "_private.force"
    assert row["call_evidence"][0]["value"] is True
    assert _findings("def _private(path, force=False): pass") == []
    assert (
        _findings('def _private(path, force=False): pass\n_private("p", force=True)')
        == []
    )


@pytest.mark.parametrize(
    "caller",
    [
        '_private = external\n_private("p", True)',
        'alias = _private\nalias = external\nalias("p", True)',
        'from external import _private\n_private("p", True)',
        'def caller(_private):\n    _private("p", True)',
        'def caller():\n    from external import _private\n    _private("p", True)',
        '(_private if condition else external)("p", True)',
    ],
)
def test_new_private_allowed_flag_evidence_rejects_unknown_binding(caller):
    assert _findings("def _private(path, force=False): pass\n" + caller) == []


@pytest.mark.parametrize(
    "source",
    [
        "def _publish(enabled: bool): pass\n_publish(False)",
        "@wrapper\ndef _publish(enabled: bool): pass\n_publish(False)",
        "def _publish(enabled: bool): pass\ndef _publish(enabled: bool): pass\n_publish(False)",
        "def outer():\n    def publish(enabled: bool): pass\n    publish(False)",
        "class Worker:\n    def _publish(self, enabled: bool): pass\n    def run(self): self._publish(False)",
    ],
)
def test_legacy_private_and_nested_observed_findings_remain_available(source):
    rows = _findings(source)
    assert rows
    assert all("called positionally with False" in row["message"] for row in rows)
    assert all(row["call_evidence"][0]["value"] is False for row in rows)


@pytest.mark.parametrize(
    "call",
    [
        "def run(self): self.publish(False)",
        "@classmethod\n    def run(cls): cls.publish(Worker(), False)",
    ],
)
def test_known_self_and_class_receivers_enrich_public_methods(call):
    row = _one("class Worker:\n    def publish(self, enabled: bool): pass\n    " + call)
    assert row["call_evidence"][0]["receiver_classes"] == ["Worker"]


@pytest.mark.parametrize(
    "definition,caller",
    [
        (
            "@staticmethod\n    def publish(enabled: bool): pass",
            "Worker.publish(False)",
        ),
        (
            "@classmethod\n    def publish(cls, enabled: bool): pass",
            "Worker.publish(False)",
        ),
        ("def publish(self, enabled: bool): pass", "Worker().publish(False)"),
        (
            "def publish(self, enabled: bool): pass",
            "def run(client: Worker): client.publish(False)",
        ),
    ],
)
def test_public_method_binding_retains_descriptor_argument_offsets(definition, caller):
    row = _one("class Worker:\n    " + definition + "\n" + caller)
    assert row["call_evidence"][0]["value"] is False


def test_unknown_method_wrapper_retains_signature_without_promoting_calls():
    row = _one(
        "class Worker:\n    @wrapper\n    def publish(self, enabled: bool): pass\n"
        "    def run(self): self.publish(False)\n"
    )
    assert "call_evidence" not in row


def test_redefined_receiver_class_keeps_both_declarations_without_call_attribution():
    rows = _findings(
        "class Worker:\n    def publish(self, enabled: bool): pass\n"
        "class Worker:\n    def publish(self, enabled: bool): pass\n"
        "Worker().publish(False)\n"
    )
    assert len(rows) == 2
    assert all("call_evidence" not in row for row in rows)


@pytest.mark.parametrize(
    "caller",
    [
        "def run(client): client.publish(False)",
        "def run(client): client.worker.publish(False)",
        "def run(): factory().publish(False)",
        "Worker.publish = external\nWorker().publish(False)",
        "setattr(Worker, 'publish', external)\nWorker().publish(False)",
        "Worker.__dict__['publish'] = external\nWorker().publish(False)",
        "Worker = external\nWorker().publish(False)",
    ],
)
def test_unknown_or_replaced_method_bindings_keep_signature_only_advice(caller):
    row = _one("class Worker:\n    def publish(self, enabled: bool): pass\n" + caller)
    assert "call_evidence" not in row


def test_known_subclass_override_does_not_promote_an_ambiguous_base_method():
    row = _one(
        """
        class Worker:
            def publish(self, enabled: bool): pass
            def run(self): self.publish(False)
        class Derived(Worker):
            def publish(self, other): pass
        """
    )
    assert "call_evidence" not in row


def test_unknown_base_cannot_establish_method_dispatch_for_public_enrichment():
    row = _one(
        "class Worker(ExternalBase):\n"
        "    def publish(self, enabled: bool): pass\n"
        "    def run(self): self.publish(False)\n"
    )
    assert "call_evidence" not in row


_FIELD_PREFIX = """
class Worker:
    def publish(self, enabled: bool = False): pass
class Context:
    def __init__(self, worker: 'Worker'):
        self.worker = worker
"""


def test_stable_constructor_field_retains_the_import_free_receiver_type():
    row = _one(_FIELD_PREFIX + "\n    def run(self): self.worker.publish(False)\n")
    assert row["call_evidence"] == [
        {
            "kind": "positional_boolean_literal",
            "line": 8,
            "value": False,
            "binding": "constructor_field",
            "callee": "publish",
            "receiver_classes": ["Worker"],
        }
    ]


def test_resolved_constructor_field_callback_does_not_promote_signature_advice():
    row = _one(
        _FIELD_PREFIX
        + "\n    def register(self): register(self.worker.publish)\n"
        + "    def run(self): self.worker.publish(False)\n"
    )
    assert "call_evidence" not in row
    assert "permits positional calls" in row["message"]


@pytest.mark.parametrize(
    "extra",
    [
        "    def replace(self, other): self.worker = other",
        "    def replace(self): del self.worker",
        "    def replace(self, other): self.worker += other",
        "    def replace(self, other): setattr(self, 'worker', other)",
        "    def replace(self, other, name): setattr(self, name, other)",
        "    def replace(self, other): self.__dict__['worker'] = other",
        "    def replace(self, other): self.__dict__.update(worker=other)",
        "    worker = property(lambda self: external)",
        "    def __getattribute__(self, name): return external",
        "    def __setattr__(self, name, value): pass",
        "    def __delattr__(self, name): pass",
    ],
)
def test_constructor_field_writes_and_descriptors_retain_signature_only_policy(extra):
    row = _one(
        _FIELD_PREFIX
        + "\n"
        + extra
        + "\n    def run(self): self.worker.publish(False)\n"
    )
    assert "call_evidence" not in row


@pytest.mark.parametrize(
    "replacement",
    [
        "self.worker = external",
        "worker = external\n        self.worker = worker",
        "self = external\n        self.worker = worker",
        "if condition:\n            self.worker = worker",
        "if condition: return\n        self.worker = worker",
    ],
)
def test_constructor_field_requires_unchanged_local_parameter_binding(replacement):
    source = _FIELD_PREFIX.replace("self.worker = worker", replacement)
    row = _one(source + "\n    def run(self): self.worker.publish(False)\n")
    assert "call_evidence" not in row


def test_fallback_getattr_does_not_replace_a_normally_initialized_field():
    row = _one(
        _FIELD_PREFIX
        + "\n    def __getattr__(self, name): return external\n"
        + "    def run(self): self.worker.publish(False)\n"
    )
    assert row["call_evidence"][0]["binding"] == "constructor_field"


def test_custom_instance_lookup_cannot_prove_a_public_method_call():
    row = _one(
        "class Worker:\n    def __getattribute__(self, name): return external\n"
        "    def publish(self, enabled: bool): pass\n"
        "    def run(self): self.publish(False)\n"
    )
    assert "call_evidence" not in row


def test_unknown_class_decorator_keeps_public_signature_without_attributing_calls():
    row = _one(
        "@wrapper\nclass Worker:\n    def publish(self, enabled: bool): pass\n"
        "    def run(self): self.publish(False)\n"
    )
    assert "call_evidence" not in row


def test_import_proven_final_decorator_keeps_normal_self_call_binding():
    row = _one(
        "from typing import final as sealed\n@sealed\nclass Worker:\n"
        "    def publish(self, enabled: bool): pass\n"
        "    def run(self): self.publish(False)\n"
    )
    assert row["call_evidence"][0]["binding"] == "static_receiver"


def test_rebound_final_alias_cannot_prove_class_identity():
    row = _one(
        "from typing import final as sealed\nsealed = wrapper\n@sealed\nclass Worker:\n"
        "    def publish(self, enabled: bool): pass\n"
        "    def run(self): self.publish(False)\n"
    )
    assert "call_evidence" not in row


def test_positional_only_observed_call_retains_applicable_recommendation():
    row = _one("def publish(enabled: bool, /): pass\npublish(False)")
    assert "called positionally with False" in row["message"]
    assert "positional-only" in row["message"]
    assert "Pass it by keyword" not in row["message"]
    _assert_optional_record_is_preserved_and_selectable(row)


def test_callback_and_declared_override_policies_remain_unchanged():
    assert (
        _findings("def publish(enabled: bool): pass\nregister(publish)\npublish(False)")
        == []
    )
    assert (
        _findings(
            "from typing import override\n@override\ndef publish(enabled: bool): pass\npublish(False)"
        )
        == []
    )


@pytest.mark.parametrize(
    "evidence", [[{"unknown": "producer"}], {"unexpected": True}, 0]
)
def test_policy_never_discards_or_mislabels_unknown_call_evidence(evidence):
    row = _one("def publish(enabled: bool): pass")
    row["call_evidence"] = evidence
    before = deepcopy(row)
    _assert_optional_record_is_preserved_and_selectable(row)
    assert row == before


def test_deep_local_inheritance_retains_signature_advice_without_recursive_failure():
    classes = ["class Base0: pass"]
    classes.extend(
        f"class Base{index}(Base{index - 1}): pass" for index in range(1, 1200)
    )
    classes.append(
        "class Worker(Base1199):\n"
        "    def publish(self, enabled: bool): pass\n"
        "    def run(self): self.publish(False)\n"
    )
    row = _one("\n".join(classes))
    assert row["name"] == "publish.enabled"
    assert "call_evidence" not in row


def test_deep_receiver_field_chain_retains_signature_advice_without_recursive_failure():
    row = _one(
        _FIELD_PREFIX
        + "\n    def run(self): self"
        + ".worker" * 800
        + ".publish(False)\n"
    )
    assert row["name"] == "publish.enabled"
    assert "call_evidence" not in row
