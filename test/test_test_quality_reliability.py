"""Static source-only positive and precision controls for test reliability."""

import ast
import textwrap

import pytest

from skylos.rules.quality.test_reliability import (
    DuplicateTestAssertionRule,
    SleepSynchronizationRule,
)


def _find(rule, source, tmp_path, *, filename="tests/test_example.py"):
    source = textwrap.dedent(source).lstrip()
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    module = ast.parse(source)
    context = {"filename": str(path), "project_root": str(tmp_path), "source": source}
    return rule().visit_node(module, context) or []


@pytest.mark.parametrize("length_expression", ["len(payload)", "len(payload())"])
def test_adjacent_assertions_use_builtin_len_scalar_proof(tmp_path, length_expression):
    found = _find(
        DuplicateTestAssertionRule,
        f"""
        def test_count(payload):
            count = {length_expression}
            assert count == 3
            assert count == 3
    """,
        tmp_path,
    )

    assert len(found) == 1
    assert found[0]["rule_id"] == "SKY-L042"
    assert found[0]["line"] == 4
    assert found[0]["severity"] == "LOW"
    assert found[0]["evidence"]["previous_assertion"] == {"line": 3}
    assert found[0]["evidence"]["value_proofs"] == {"count": "builtin_len_result"}


def test_scalar_alias_and_nested_straight_line_block_are_supported(tmp_path):
    found = _find(
        DuplicateTestAssertionRule,
        """
        def test_count(payload):
            if payload:
                count = len(payload)
                actual = count
                assert actual > 0
                assert actual > 0
    """,
        tmp_path,
    )
    assert [row["line"] for row in found] == [6]


@pytest.mark.parametrize(
    "source",
    [
        "def test_value(value):\n    assert value == 3\n    assert value == 3\n",
        "def test_value():\n    value = application_call()\n    assert value == 3\n    assert value == 3\n",
        "def test_value(payload, len):\n    value = len(payload)\n    assert value == 3\n    assert value == 3\n",
        "import builtins\nbuiltins.len = replacement\ndef test_value(payload):\n    value = len(payload)\n    assert value == 3\n    assert value == 3\n",
        "from unittest.mock import patch\npatch('builtins.len', replacement)\ndef test_value(payload):\n    value = len(payload)\n    assert value == 3\n    assert value == 3\n",
        "def test_value(external):\n    value = 3\n    alias = (value := external)\n    assert value == 3\n    assert value == 3\n",
        "len = lambda value: value\ndef test_value(payload):\n    value = len(payload)\n    assert value == 3\n    assert value == 3\n",
        "def test_value():\n    value = {'count': 3}\n    assert value['count'] == 3\n    assert value['count'] == 3\n",
        "def test_value(obj):\n    assert obj.count == 3\n    assert obj.count == 3\n",
        "def test_value(obj):\n    assert obj.next() == 3\n    assert obj.next() == 3\n",
        "def test_value():\n    value = 3\n    assert value == 3\n    value = 4\n    assert value == 3\n",
        "def test_value():\n    value = 3\n    assert value == 3\n    advance_state()\n    assert value == 3\n",
        "def test_value():\n    value = 3\n    assert value == 3, 'first contract'\n    assert value == 3, 'second contract'\n",
        "def test_value():\n    value = 3\n    assert value == 3\n    assert value != 3\n",
        "def test_value():\n    value = 3\n    return\n    assert value == 3\n    assert value == 3\n",
        "def test_value():\n    def helper():\n        value = 3\n        assert value == 3\n        assert value == 3\n",
        "def helper():\n    value = 3\n    assert value == 3\n    assert value == 3\n",
        "def test_value():\n    assert 3 == 3\n    assert 3 == 3\n",
    ],
)
def test_duplicate_assertion_refuses_unproven_or_distinct_observations(
    source, tmp_path
):
    assert _find(DuplicateTestAssertionRule, source, tmp_path) == []


def test_unknown_equality_overload_is_not_assumed_pure(tmp_path):
    assert (
        _find(
            DuplicateTestAssertionRule,
            """
        class ChangingEquality:
            def __eq__(self, expected):
                self.counter += 1
                return self.counter == expected
        def test_observations():
            value = ChangingEquality()
            assert value == 1
            assert value == 1
    """,
            tmp_path,
        )
        == []
    )


_EVENT_SOURCE = """\
from threading import Event, Thread
from time import sleep

def test_job_completes():
    complete = Event()
    worker = Thread(target=complete.set)
    worker.start()
    sleep(0.05)
    assert complete.is_set()
    worker.join(timeout=1)
"""


def test_sleep_followed_by_local_event_completion_has_exact_evidence(tmp_path):
    found = _find(SleepSynchronizationRule, _EVENT_SOURCE, tmp_path)
    assert len(found) == 1
    assert found[0]["rule_id"] == "SKY-L043"
    assert found[0]["line"] == 8
    assert found[0]["severity"] == "LOW"
    assert found[0]["evidence"]["event_created"] == {"line": 5}
    assert found[0]["evidence"]["completion_check"] == {"line": 9}
    assert found[0]["evidence"]["delay_seconds"] == 0.05
    assert found[0]["evidence"]["event"] == "complete"


def test_module_import_aliases_and_explicit_positive_completion_work(tmp_path):
    source = (
        _EVENT_SOURCE.replace(
            "from threading import Event, Thread\nfrom time import sleep",
            "import threading as threads\nimport time as clock",
        )
        .replace("Event()", "threads.Event()")
        .replace("Thread(", "threads.Thread(")
    )
    source = source.replace("sleep(0.05)", "clock.sleep(0.05)")
    source = source.replace(
        "assert complete.is_set()", "assert complete.is_set() is True"
    )
    assert len(_find(SleepSynchronizationRule, source, tmp_path)) == 1


@pytest.mark.parametrize(
    "source",
    [
        _EVENT_SOURCE.replace(
            "sleep(0.05)\n    assert complete.is_set()",
            "assert complete.wait(timeout=1)",
        ),
        _EVENT_SOURCE.replace(
            "sleep(0.05)\n    assert complete.is_set()",
            "condition.wait_for(complete.is_set, timeout=1)\n    assert complete.is_set()",
        ),
        _EVENT_SOURCE.replace("sleep(0.05)", "sleep(0)"),
        _EVENT_SOURCE.replace("sleep(0.05)", "sleep(-1)"),
        _EVENT_SOURCE.replace("sleep(0.05)", "sleep(True)"),
        _EVENT_SOURCE.replace("sleep(0.05)", "sleep(1e999)"),
        _EVENT_SOURCE.replace("sleep(0.05)", "sleep(" + "9" * 400 + ")"),
        _EVENT_SOURCE.replace("sleep(0.05)", "sleep(configured_delay)"),
        _EVENT_SOURCE.replace(
            "assert complete.is_set()", "assert not complete.is_set()"
        ),
        _EVENT_SOURCE.replace(
            "assert complete.is_set()", "assert complete.is_set() is False"
        ),
        _EVENT_SOURCE.replace(
            "assert complete.is_set()", "assert response.status == 200"
        ),
        _EVENT_SOURCE.replace("complete = Event()", "complete = CustomEvent()"),
        _EVENT_SOURCE.replace("test_job_completes()", "test_job_completes(Event)"),
        _EVENT_SOURCE.replace("test_job_completes()", "test_job_completes(sleep)"),
        _EVENT_SOURCE.replace("test_job_completes()", "test_job_timeout()"),
        _EVENT_SOURCE.replace("test_job_completes()", "helper()"),
        _EVENT_SOURCE.replace(
            "worker.start()", "worker.start()\n    complete = Event()"
        ),
        _EVENT_SOURCE.replace(
            "worker.start()", "worker.start()\n    complete.is_set = replacement"
        ),
        _EVENT_SOURCE.replace(
            "worker.start()",
            "worker.start()\n    alias = complete\n    alias.is_set = replacement",
        ),
        _EVENT_SOURCE.replace(
            "worker.start()",
            "worker.start()\n    complete.__dict__['is_set'] = replacement",
        ),
        _EVENT_SOURCE.replace(
            "worker.start()", "worker.start()\n    configure(complete)"
        ),
        _EVENT_SOURCE.replace(
            "worker.start()",
            "worker.start()\n    setattr(complete, 'is_set', replacement)",
        ),
        _EVENT_SOURCE.replace("worker.start()", "worker.start()\n    return"),
        _EVENT_SOURCE.replace(
            "worker.start()",
            "worker.start()\n    from time import monotonic\n    started = monotonic()",
        ),
        _EVENT_SOURCE.replace(
            "def test_job_completes():",
            "import pytest\n@pytest.mark.skip(reason='platform')\ndef test_job_completes():",
        ),
        _EVENT_SOURCE.replace("from time import sleep", "from .time import sleep"),
        _EVENT_SOURCE.replace(
            "from time import sleep", "from time import sleep\nsleep = replacement"
        ),
        _EVENT_SOURCE.replace(
            "from time import sleep",
            "from time import sleep\nimport time\ntime.sleep = replacement",
        ),
        _EVENT_SOURCE.replace(
            "from time import sleep",
            "from time import sleep\nimport time\nsetattr(time, 'sleep', replacement)",
        ),
        _EVENT_SOURCE.replace(
            "from time import sleep",
            "from time import sleep\nfrom unittest.mock import patch\npatch('time.sleep', replacement)",
        ),
        _EVENT_SOURCE.replace(
            "from time import sleep",
            "from time import sleep\nimport threading\nthreading.Event.is_set = replacement",
        ),
        _EVENT_SOURCE.replace(
            "from time import sleep",
            "from time import sleep\nAliasEvent = Event\nAliasEvent.is_set = replacement",
        ),
        _EVENT_SOURCE.replace(
            "from time import sleep",
            "from time import sleep\nconfigure(Event)",
        ),
    ],
)
def test_sleep_review_requires_narrow_unshadowed_synchronization(source, tmp_path):
    assert _find(SleepSynchronizationRule, source, tmp_path) == []


def test_project_shadow_of_threading_is_not_stdlib_proof(tmp_path):
    (tmp_path / "threading.py").write_text("class Event: pass\n", encoding="utf-8")
    assert _find(SleepSynchronizationRule, _EVENT_SOURCE, tmp_path) == []


def test_module_alias_escape_prevents_sleep_binding_claim(tmp_path):
    source = _EVENT_SOURCE.replace(
        "from time import sleep", "import time\nconfigure(time)"
    )
    source = source.replace("sleep(0.05)", "time.sleep(0.05)")
    assert _find(SleepSynchronizationRule, source, tmp_path) == []


def test_module_namespace_write_prevents_sleep_binding_claim(tmp_path):
    source = _EVENT_SOURCE.replace(
        "from time import sleep", "import time\ntime.__dict__['sleep'] = replacement"
    )
    source = source.replace("sleep(0.05)", "time.sleep(0.05)")
    assert _find(SleepSynchronizationRule, source, tmp_path) == []


@pytest.mark.parametrize("framework", ["pytest", "unittest"])
def test_expected_assertion_failure_is_not_a_completion_claim(framework, tmp_path):
    source = _EVENT_SOURCE.replace(
        "sleep(0.05)\n    assert complete.is_set()",
        "with pytest.raises(AssertionError):\n        sleep(0.05)\n        assert complete.is_set()",
    )
    source = "import pytest\n" + source
    if framework == "unittest":
        imports, body = source.split("def test_job_completes():\n")
        source = imports.replace("import pytest", "import unittest")
        source += (
            "class TestWorker(unittest.TestCase):\n    def test_job_completes(self):\n"
        )
        source += textwrap.indent(
            body.replace("pytest.raises", "self.assertRaises"), "    "
        )
    assert _find(SleepSynchronizationRule, source, tmp_path) == []
