"""Provider call evidence follows the source receiver and executing owner."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze


def _scan(root, sources, confidence, grep_verify):
    for relative, source in sources.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source or "\n", encoding="utf-8")
    result = json.loads(
        analyze(str(root), conf=confidence, grep_verify=grep_verify, grep_cache=False)
    )
    assert not result.get("analysis_errors")
    return {row["full_name"] for row in result["unused_functions"]}, result


def _rescued(result):
    return {
        row["name"]
        for row in result["analysis_summary"]["dead_code_liveness"]["rescued"]
    }


@pytest.mark.parametrize("called_owner", [False, True])
def test_proven_provider_call_retains_alive_evidence_with_receiver_escape(
    tmp_path, called_owner
):
    call = "Worker().directly_used()"
    if called_owner:
        call = "def consume():\n    Worker().directly_used()\n\nconsume()"
    _, result = _scan(
        tmp_path,
        {
            "app.py": """
class Worker:
    def dispatch(self):
        external(self)
    def handle_refund(self):
        return 1
    def directly_used(self):
        return 2

Worker().dispatch()
"""
            + call
            + "\n",
        },
        80,
        False,
    )
    entries = {
        row["qualified_name"]: row for row in result["dead_code_evidence"]["symbols"]
    }
    assert entries["app.Worker.handle_refund"]["classification"] == "uncertain"
    directly_used = entries["app.Worker.directly_used"]
    assert directly_used["classification"] == "alive"
    expected = "reachable_from_root" if called_owner else "top_level_execution"
    assert expected in {event["kind"] for event in directly_used["evidence"]}
    assert (
        result["analysis_summary"]["dead_code_evidence"]["classifications"]["uncertain"]
        == 1
    )


def test_unresolved_proxy_rescue_remains_uncertainty_without_source_call(tmp_path):
    _, result = _scan(
        tmp_path,
        {
            "app.py": """
class App:
    def make_shell_context(self):
        return {}

app = App()
""",
            "commands.py": """
class Proxy:
    pass

current_app = Proxy()
RESULT = current_app.make_shell_context()
""",
        },
        80,
        False,
    )
    entry = next(
        row
        for row in result["dead_code_evidence"]["symbols"]
        if row["qualified_name"] == "app.App.make_shell_context"
    )
    assert "app.App.make_shell_context" in _rescued(result)
    assert entry["classification"] == "uncertain"
    assert not {"top_level_execution", "reachable_from_root"}.intersection(
        event["kind"] for event in entry["evidence"]
    )


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep_verify", [False, True])
def test_known_receiver_does_not_consume_another_live_class_method(
    tmp_path, confidence, grep_verify
):
    unused, _ = _scan(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/providers.py": """
class Active:
    def schedule_dates(self):
        return 1

class Other:
    def schedule_dates(self):
        return 2

active = Active()
other = Other()
RESULT = active.schedule_dates()
""",
        },
        confidence,
        grep_verify,
    )
    assert "pkg.providers.Active.schedule_dates" not in unused
    assert "pkg.providers.Other.schedule_dates" in unused


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep_verify", [False, True])
def test_stdlib_module_call_does_not_consume_a_unique_local_method(
    tmp_path, confidence, grep_verify
):
    _, result = _scan(
        tmp_path,
        {
            "invoice.py": """
class Invoice:
    def dump(self, payload):
        return payload
""",
            "app.py": """
import json
from invoice import Invoice

invoice = Invoice()
RESULT = json.dumps({"amount": 3})
with open("report.json", "w") as output:
    json.dump({}, output)
""",
        },
        confidence,
        grep_verify,
    )
    # Legacy weak attribute uncertainty already keeps this method quiet. A
    # json module call must not add a proven provider-method rescue as well.
    assert "invoice.Invoice.dump" not in _rescued(result)


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep_verify", [False, True])
def test_uncalled_consumer_cannot_rescue_an_external_provider_method(
    tmp_path, confidence, grep_verify
):
    unused, _ = _scan(
        tmp_path,
        {
            "service.py": """
class Service:
    def inspect_payload(self):
        return 1

service = Service()
""",
            "app.py": """
from service import service

def retired():
    return service.inspect_payload()
""",
        },
        confidence,
        grep_verify,
    )
    assert "service.Service.inspect_payload" in unused
    assert "app.retired" in unused


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep_verify", [False, True])
def test_factory_choices_consume_only_their_possible_provider_methods(
    tmp_path, confidence, grep_verify
):
    unused, result = _scan(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/providers.py": """
class First:
    def schedule_dates(self):
        return 1

class Second:
    def schedule_dates(self):
        return 2

class Unrelated:
    def schedule_dates(self):
        return 3

unrelated = Unrelated()

def build(kind):
    if kind == "first":
        return First()
    return Second()
""",
            "pkg/pipeline.py": """
from pkg.providers import build

def run(kind):
    provider = build(kind)
    return provider.schedule_dates()

RESULT = run("first")
""",
        },
        confidence,
        grep_verify,
    )
    assert "pkg.providers.First.schedule_dates" not in unused
    assert "pkg.providers.Second.schedule_dates" not in unused
    assert "pkg.providers.First.schedule_dates" in _rescued(result)
    assert "pkg.providers.Second.schedule_dates" in _rescued(result)
    assert "pkg.providers.Unrelated.schedule_dates" not in _rescued(result)
    # The existing grep fallback remains uncertain for a factory receiver.
    if not grep_verify:
        assert "pkg.providers.Unrelated.schedule_dates" in unused


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep_verify", [False, True])
def test_chained_cross_module_factory_receiver_is_live(
    tmp_path, confidence, grep_verify
):
    unused, _ = _scan(
        tmp_path,
        {
            "hardware/__init__.py": "",
            "hardware/providers.py": """
class Wired:
    def initialize_field_hardware(self, field):
        return field

class Wireless:
    @staticmethod
    def initialize_field_hardware(field):
        return field

def build(kind):
    if kind == "wired":
        return Wired()
    return Wireless()
""",
            "app.py": """
from hardware.providers import build as make_provider

def initialize(kind):
    return make_provider(kind).initialize_field_hardware(kind)

RESULT = initialize("wired")
""",
        },
        confidence,
        grep_verify,
    )
    assert "hardware.providers.Wired.initialize_field_hardware" not in unused
    assert "hardware.providers.Wireless.initialize_field_hardware" not in unused


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep_verify", [False, True])
def test_legacy_proxy_call_requires_an_executing_owner(
    tmp_path, confidence, grep_verify
):
    unused, result = _scan(
        tmp_path,
        {
            "app.py": """
class App:
    def make_shell_context(self):
        return {}

app = App()
""",
            "commands.py": """
class Proxy:
    pass

current_app = Proxy()

def retired_shell():
    return current_app.make_shell_context()
""",
        },
        confidence,
        grep_verify,
    )
    assert "commands.retired_shell" in unused
    assert "app.App.make_shell_context" not in _rescued(result)


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep_verify", [False, True])
def test_known_current_app_receiver_cannot_credit_an_unrelated_class(
    tmp_path, confidence, grep_verify
):
    unused, _ = _scan(
        tmp_path,
        {
            "app.py": """
class App:
    def make_shell_context(self):
        return {}

app = App()
""",
            "commands.py": """
class Local:
    def make_shell_context(self):
        return {"local": True}

current_app = Local()
RESULT = current_app.make_shell_context()
""",
        },
        confidence,
        grep_verify,
    )
    assert "app.App.make_shell_context" in unused
    assert "commands.Local.make_shell_context" not in unused


@pytest.mark.parametrize("kind", ["coroutine", "generator"])
def test_creating_a_deferred_consumer_does_not_prove_method_execution(tmp_path, kind):
    declaration = "async def consume():" if kind == "coroutine" else "def consume():"
    action = "return" if kind == "coroutine" else "yield"
    _, result = _scan(
        tmp_path,
        {
            "provider.py": """
class Provider:
    def inspect_payload(self):
        return 1
""",
            "app.py": (
                "from provider import Provider\n\n"
                f"{declaration}\n    {action} Provider().inspect_payload()\n\n"
                "consume()\n"
            ),
        },
        0,
        False,
    )
    assert "provider.Provider.inspect_payload" not in _rescued(result)


@pytest.mark.parametrize(
    "expression,consumed",
    [
        ("make_provider().inspect_payload() if choose() else None", True),
        ("lambda value=make_provider().inspect_payload(): value", True),
        ("make_provider().inspect_payload() if False else None", False),
    ],
)
def test_expression_bodies_keep_eager_provider_calls_without_inventing_dead_arms(
    tmp_path, expression, consumed
):
    _, result = _scan(
        tmp_path,
        {
            "provider.py": """
class Provider:
    def inspect_payload(self):
        return 1

def make_provider():
    return Provider()
""",
            "app.py": (
                "from provider import make_provider\n"
                "def run():\n"
                f"    return {expression}\n"
                "RESULT = run()\n"
            ),
        },
        0,
        False,
    )
    assert ("provider.Provider.inspect_payload" in _rescued(result)) is consumed


@pytest.mark.parametrize(
    "body,consumed",
    [
        ("if True:\n    return\nmake_provider().inspect_payload()", False),
        ("if False:\n    return\nmake_provider().inspect_payload()", True),
        ("for item in [1]:\n    break\n    make_provider().inspect_payload()", False),
        (
            "for item in [1]:\n    continue\n    make_provider().inspect_payload()",
            False,
        ),
        ("False and make_provider().inspect_payload()", False),
        ("True or make_provider().inspect_payload()", False),
        ("True and make_provider().inspect_payload()", True),
        ("False or make_provider().inspect_payload()", True),
        ("stop()\nmake_provider().inspect_payload()", False),
        ("finish()\nmake_provider().inspect_payload()", True),
    ],
)
def test_completed_or_short_circuited_sites_do_not_prove_provider_calls(
    tmp_path, body, consumed
):
    _, result = _scan(
        tmp_path,
        {
            "provider.py": """
class Provider:
    def inspect_payload(self):
        return 1

def make_provider():
    return Provider()
""",
            "app.py": (
                "from provider import make_provider\n"
                "def stop():\n    raise ValueError()\n"
                "def finish():\n    return None\n"
                "def run():\n" + textwrap.indent(body, "    ") + "\nRESULT = run()\n"
            ),
        },
        0,
        False,
    )
    assert ("provider.Provider.inspect_payload" in _rescued(result)) is consumed
