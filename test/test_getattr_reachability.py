"""Static reflection regressions; fixture source is never executed."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


def _scan(tmp_path, files, grep_verify=False):
    for name, source in files.items():
        assert write_text_no_symlink(tmp_path / name, textwrap.dedent(source).lstrip())
    result = json.loads(
        analyze(str(tmp_path.resolve()), trace_file=False, grep_verify=grep_verify)
    )
    assert not result.get("analysis_errors")
    return result, {item["full_name"] for item in result["unused_functions"]}


@pytest.mark.parametrize("grep_verify", [False, True])
def test_self_dispatch_does_not_mask_unrelated_module(tmp_path, grep_verify):
    result, unused = _scan(
        tmp_path,
        {
            "dispatch.py": """
                class Dispatcher:
                    def dispatch(self, action, amount):
                        return getattr(self, f"do_{action}")(amount)
                    def do_refund(self, amount):
                        return amount
                Dispatcher().dispatch("refund", 1)
            """,
            "billing.py": """
                def legacy_invoice(amount):
                    return legacy_discount(amount)
                def legacy_discount(amount):
                    return amount * 0.8
            """,
        },
        grep_verify,
    )
    assert {"billing.legacy_invoice", "billing.legacy_discount"} <= unused
    assert "dispatch.Dispatcher.do_refund" not in unused


@pytest.mark.parametrize(
    "expression", ['f"do_{action}_now"', '"do_" + action + "_now"']
)
@pytest.mark.parametrize("assigned", [False, True])
def test_attribute_pattern_is_bounded_to_receiver_and_spelling(
    tmp_path, expression, assigned
):
    lookup = "attribute" if assigned else expression
    assignment = f"attribute = {expression}" if assigned else "pass"
    _, unused = _scan(
        tmp_path,
        {
            "dispatch.py": f"""
                class Dispatcher:
                    def dispatch(self, action):
                        {assignment}
                        return getattr(self, {lookup})()
                    def do_refund_now(self):
                        return 1
                    def obsolete(self):
                        return 2
                    def do_refund_later(self):
                        return 3
                class Unrelated:
                    def do_refund_now(self):
                        return 4
                def do_global_now():
                    return 5
                Unrelated()
                Dispatcher().dispatch("refund")
            """
        },
    )
    assert "dispatch.Dispatcher.do_refund_now" not in unused
    assert {
        "dispatch.Dispatcher.obsolete",
        "dispatch.Dispatcher.do_refund_later",
        "dispatch.Unrelated.do_refund_now",
        "dispatch.do_global_now",
    } <= unused


@pytest.mark.parametrize("lookup", ['"perform"', "name"])
def test_returned_attribute_and_default_callback_stay_possible(tmp_path, lookup):
    _, unused = _scan(
        tmp_path,
        {
            "dispatch.py": f"""
                def fallback():
                    return 0
                class Dispatcher:
                    def lookup(self, name):
                        return getattr(self, {lookup}, fallback)
                    def perform(self):
                        return 1
                Dispatcher().lookup("perform")()
            """,
            "billing.py": "def obsolete():\n    return 2\n",
        },
    )
    assert "dispatch.Dispatcher.perform" not in unused
    assert "dispatch.fallback" not in unused
    assert "billing.obsolete" in unused


def test_known_module_lookup_does_not_mask_other_modules(tmp_path):
    _, unused = _scan(
        tmp_path,
        {
            "dispatch.py": "import handlers\ngetattr(handlers, input())()\n",
            "handlers.py": "def handle_request():\n    return 1\n",
            "billing.py": "def obsolete():\n    return 2\n",
        },
    )
    assert "handlers.handle_request" not in unused
    assert "billing.obsolete" in unused


@pytest.mark.parametrize("module_key", ["__name__", '"dispatch"'])
def test_sys_modules_dispatch_stays_in_its_known_module(tmp_path, module_key):
    result, unused = _scan(
        tmp_path,
        {
            "dispatch.py": f"""
                import sys
                def handle_refund():
                    return 1
                def dispatch(action):
                    return getattr(sys.modules[{module_key}], f"handle_{{action}}")()
                dispatch("refund")
            """,
            "billing.py": "def obsolete():\n    return 2\n",
        },
    )
    assert "dispatch.handle_refund" not in unused
    assert "billing.obsolete" in unused


def test_shadowed_sys_does_not_establish_a_known_module_receiver(tmp_path):
    result, unused = _scan(
        tmp_path,
        {
            "dispatch.py": """
                import sys
                def dispatch(sys, action):
                    return getattr(sys.modules[__name__], f"handle_{action}")()
                dispatch(external_receiver(), "refund")
            """,
            "billing.py": "def handle_refund():\n    return 2\n",
        },
    )
    assert "billing.handle_refund" not in unused
    assert (
        result["definitions"]["billing.handle_refund"]["dead_code_classification"]
        == "uncertain"
    )


@pytest.mark.parametrize(
    "source",
    [
        "def dispatch(receiver, name):\n    return getattr(receiver, name)()\ndispatch(input(), input())\n",
        "class Dispatcher(External):\n    def dispatch(self, name):\n        return getattr(self, name)()\nDispatcher().dispatch(input())\n",
        "class Dispatcher:\n    def __getattr__(self, name):\n        return callback\ngetattr(Dispatcher(), 'perform')()\n",
        "def getattr(receiver, name):\n    return callback\ngetattr(object(), 'perform')()\n",
    ],
)
def test_unresolved_or_custom_reflection_preserves_possible_callbacks(tmp_path, source):
    _, unused = _scan(
        tmp_path,
        {
            "dispatch.py": "def callback():\n    return 1\n" + source,
            "billing.py": "def obsolete():\n    return 2\n",
        },
    )
    assert "dispatch.callback" not in unused


def test_private_attribute_lookup_uses_actual_mangled_spelling(tmp_path):
    _, unused = _scan(
        tmp_path,
        {
            "dispatch.py": """
                class Dispatcher:
                    def dispatch(self):
                        return getattr(self, "_Dispatcher__perform")()
                    def __perform(self):
                        return 1
                    def obsolete(self):
                        return 2
                Dispatcher().dispatch()
            """
        },
    )
    assert "dispatch.Dispatcher.__perform" not in unused
    assert "dispatch.Dispatcher.obsolete" in unused


@pytest.mark.parametrize(
    "receiver",
    ["external_receiver()", "receivers[input()]", "Remote() if input() else object()"],
)
def test_unknown_receiver_expressions_keep_possible_targets_uncertain(
    tmp_path, receiver
):
    result, unused = _scan(
        tmp_path,
        {
            "dispatch.py": f"""
                class Remote:
                    def perform(self):
                        return 1
                remote = Remote()
                getattr({receiver}, input())()
            """
        },
    )
    assert "dispatch.Remote.perform" not in unused
    decision = result["definitions"]["dispatch.Remote.perform"]["dead_code_decision"]
    assert decision["classification"] == "uncertain"
    assert decision["live_evidence_count"] == 0


def test_literal_glob_characters_are_not_dispatch_wildcards(tmp_path):
    _, unused = _scan(
        tmp_path,
        {
            "dispatch.py": """
                def fallback():
                    return 0
                class Dispatcher:
                    def dispatch(self):
                        return getattr(self, "do_*", fallback)()
                    def do_refund(self):
                        return 1
                Dispatcher().dispatch()
            """
        },
    )
    assert "dispatch.Dispatcher.do_refund" in unused
    assert "dispatch.fallback" not in unused


def test_assigned_attribute_hints_preserve_actual_calls(tmp_path):
    result, unused = _scan(
        tmp_path,
        {
            "dispatch.py": """
                class Dispatcher:
                    def dispatch(self, action):
                        attribute = f"do_{action}"
                        return getattr(self, attribute)()
                    def do_refund(self):
                        return 1
                def do_live_work():
                    return 2
                def do_obsolete_work():
                    return 3
                Dispatcher().dispatch("refund")
                do_live_work()
            """
        },
    )
    assert "dispatch.do_obsolete_work" in unused
    assert "dispatch.do_live_work" not in unused
    assert (
        result["definitions"]["dispatch.do_live_work"]["dead_code_classification"]
        == "alive"
    )
    assert (
        result["definitions"]["dispatch.Dispatcher.do_refund"][
            "dead_code_classification"
        ]
        == "uncertain"
    )


def test_reassigned_attribute_name_is_conservative(tmp_path):
    _, unused = _scan(
        tmp_path,
        {
            "dispatch.py": """
                class Dispatcher:
                    def dispatch(self, action):
                        attribute = f"do_{action}"
                        attribute = input()
                        return getattr(self, attribute)()
                    def do_refund(self):
                        return 1
                    def other_method(self):
                        return 2
                Dispatcher().dispatch("refund")
            """
        },
    )
    assert "dispatch.Dispatcher.do_refund" not in unused
    assert "dispatch.Dispatcher.other_method" not in unused
