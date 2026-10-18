import ast
import textwrap

import pytest

from skylos.rules.quality.logic_maintainability import BooleanTrapRule


def _findings(source):
    rule = BooleanTrapRule()
    tree = ast.parse(textwrap.dedent(source))
    return [
        row
        for node in ast.walk(tree)
        for row in rule.visit_node(node, {"filename": "app.py"}) or []
    ]


@pytest.mark.parametrize(
    "source",
    [
        "def publish(notify: bool, /): pass",
        "def _publish(notify: bool, /): pass\n_publish(False)",
    ],
)
def test_positional_only_boolean_keeps_detection_with_compatible_advice(source):
    findings = _findings(source)
    assert len(findings) == 1
    assert findings[0]["simple_name"] == "notify"
    message = findings[0]["message"]
    assert "positional-only" in message
    assert "descriptive enum" in message
    assert "Pass it by keyword" not in message
    assert "Prefer named calls" not in message
    assert "make the parameter keyword-only" not in message


def test_regular_boolean_keeps_existing_keyword_advice():
    rows = _findings("def publish(notify: bool): pass")
    assert len(rows) == 1
    assert "Prefer named calls" in rows[0]["message"]


def test_keyword_only_boolean_stays_unreported():
    assert _findings("def publish(*, notify: bool): pass") == []


@pytest.mark.parametrize("receiver", ["client", "client.worker", "factory()"])
def test_unknown_receiver_does_not_provide_evidence_for_unrelated_private_method(
    receiver,
):
    assert (
        _findings(
            f"""
        class Worker:
            def _publish(self, notify: bool = False): pass
        def unrelated(client):
            {receiver}._publish(False)
        """
        )
        == []
    )


def test_known_different_class_does_not_provide_private_method_evidence():
    assert (
        _findings(
            """
        class Worker:
            def _publish(self, notify: bool = False): pass
        class Other: pass
        def unrelated(client: Other):
            client._publish(False)
        """
        )
        == []
    )


@pytest.mark.parametrize(
    "caller",
    [
        "    def run(self):\n        self._publish(False)",
        "\ndef run(client: Worker):\n    client._publish(False)",
        '\ndef run(client: "Worker"):\n    client._publish(False)',
        "\ndef run():\n    client = Worker()\n    client._publish(False)",
        "\nclient = Worker()\nclient._publish(False)",
        "\nWorker()._publish(False)",
        "\ndef run():\n    Worker._publish(object(), False)",
    ],
)
def test_known_private_method_receiver_still_provides_call_evidence(caller):
    source = (
        "class Worker:\n    def _publish(self, notify: bool = False): pass\n" + caller
    )
    findings = _findings(source)
    assert [row["name"] for row in findings] == ["_publish.notify"]
    assert "called positionally with False" in findings[0]["message"]


def test_known_classmethod_receiver_keeps_bound_argument_offset():
    findings = _findings(
        """
        class Worker:
            @classmethod
            def _publish(cls, notify: bool = False): pass
            @classmethod
            def run(cls): cls._publish(False)
        """
    )
    assert [row["name"] for row in findings] == ["_publish.notify"]


def test_local_direct_private_function_call_stays_reported():
    findings = _findings("def _publish(notify: bool): pass\n_publish(False)")
    assert [row["name"] for row in findings] == ["_publish.notify"]


def test_public_method_shape_advice_does_not_require_call_evidence():
    findings = _findings(
        """
        class Worker:
            def publish(self, notify: bool = False): pass
        def unrelated(client): client.publish(False)
        """
    )
    assert [row["name"] for row in findings] == ["publish.notify"]
    assert "public or callback contract" in findings[0]["message"]


@pytest.mark.parametrize(
    "caller",
    [
        "Worker = unknown\nWorker()._publish(False)",
        "from external import Worker\nWorker()._publish(False)",
        "def Worker(): return unknown\nWorker()._publish(False)",
        "client = Worker()\nfor client in unknown:\n    client._publish(False)",
        "client = Worker()\n[(client := unknown) for item in values]\nclient._publish(False)",
        "def run(client: Worker):\n    client = unknown\n    client._publish(False)",
        "def run(client: Worker):\n    del client\n    client._publish(False)",
        "class Other: pass\nclient = Worker()\nclient = Other()\nclient._publish(False)",
    ],
)
def test_rebound_class_or_receiver_does_not_supply_private_call_evidence(caller):
    source = (
        "class Worker:\n    def _publish(self, notify: bool = False): pass\n" + caller
    )
    assert _findings(source) == []


def test_shadowed_class_name_in_nested_scope_does_not_resolve_to_outer_worker():
    assert (
        _findings(
            """
        class Worker:
            def _publish(self, notify: bool = False): pass
        def run(Worker):
            Worker()._publish(False)
        """
        )
        == []
    )


def test_constructed_receiver_in_nested_scope_keeps_correct_class_identity():
    findings = _findings(
        """
        class Worker:
            def _publish(self, notify: bool = False): pass
        def outer():
            def run():
                client = Worker()
                client._publish(False)
            run()
        """
    )
    assert [row["name"] for row in findings] == ["_publish.notify"]


def test_class_rebinding_keeps_existing_public_callback_signature_policy():
    assert (
        _findings(
            """
        class Worker:
            @classmethod
            def publish(cls, notify: bool = False): pass
        Worker = decorate(Worker)
        register(Worker.publish)
        """
        )
        == []
    )


def test_reassigned_self_does_not_supply_private_method_call_evidence():
    assert (
        _findings(
            """
        class Worker:
            def _publish(self, notify: bool = False): pass
            def run(self):
                self = unknown
                self._publish(False)
        """
        )
        == []
    )
