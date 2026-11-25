"""End-to-end static controls for registered SQLite worker SQL findings."""

import json

import pytest

from skylos.analyzer import analyze

_SOURCE = """
import sqlite3
from queue import Queue
from threading import Thread

class Forward:
    slot = None
    @classmethod
    def bind(cls, value):
        cls.slot = value
    @classmethod
    def delegate(cls, callback):
        @staticmethod
        def invoke(*args, **kwargs):
            return cls.slot.schedule(callback, *args, **kwargs)
        return invoke

class Catalog:
    @Forward.delegate
    def refresh(owner, rows):
        query_names = ",".join(row[0] for row in rows)
        owner.reader.execute(f"SELECT title FROM catalog ORDER BY {query_names}")

class Ticket:
    def __init__(self, operation, *args, **kwargs):
        self.operation = operation
        self.args = args
        self.kwargs = kwargs
    def deliver(self):
        return self.operation(*self.args, **self.kwargs)

class Hub(Thread):
    entries = []
    def __init__(self):
        super().__init__()
        self.items = Queue()
        Forward.bind(self)
    def begin(self):
        self.start()
    def schedule(self, operation, *args, **kwargs):
        args = (self,) + args
        job = Ticket(operation, *args, **kwargs)
        self.items.put(job)
    def run(self):
        self.conn = sqlite3.connect(":memory:")
        self.reader = self.conn.cursor()
        while True:
            item = self.items.get()
            if item == "done":
                self.reader.close()
                self.conn.close()
                break
            item.deliver()
    @classmethod
    def add(cls, provider):
        cls.entries.append(provider)
    def __getattr__(self, key):
        for member in Hub.entries:
            if hasattr(member, key):
                return getattr(member, key)
        raise AttributeError(key)

Hub.add(Catalog)
"""


def _sql_findings(tmp_path, source):
    path = tmp_path / "catalog_service.py"
    path.write_text(source, encoding="utf-8")
    report = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
        )
    )
    assert not report.get("analysis_errors")
    return [item for item in report.get("danger", []) if item["rule_id"] == "SKY-D211"]


@pytest.mark.parametrize("cursor_field", ["reader", "cursor"])
def test_registered_worker_reports_bound_callback_row_values(tmp_path, cursor_field):
    source = _SOURCE.replace(".reader", f".{cursor_field}")
    findings = _sql_findings(tmp_path, source)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "HIGH"
    assert finding["metadata"]["source_status"] == "caller_supplied"
    assert (
        finding["metadata"]["security_evidence"]["evidence_kind"]
        == "python_sqlite_registered_worker"
    )


def test_registered_worker_keeps_placeholders_and_bound_values_quiet(tmp_path):
    source = _SOURCE.replace(
        'query_names = ",".join(row[0] for row in rows)',
        'names = [row[0] for row in rows]\n        marks = ",".join("?" * len(names))',
    ).replace(
        'owner.reader.execute(f"SELECT title FROM catalog ORDER BY {query_names}")',
        'owner.reader.execute(f"SELECT title FROM catalog WHERE title IN ({marks})", names)',
    )
    assert _sql_findings(tmp_path, source) == []


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        (
            "        return self.operation(*self.args, **self.kwargs)\n",
            "        return self.operation(*self.args, **self.kwargs)\n        yield None\n",
        ),
        ("class Ticket:", "class Ticket:\n    __slots__ = ()"),
        (
            "class Ticket:",
            "class Ticket:\n    def __eq__(self, other):\n        return True",
        ),
        (
            "        self.operation = operation",
            "        self.operation = operation\n        self.deliver = None",
        ),
        (
            "Hub.add(Catalog)\n",
            "Hub.add(Catalog)\nTicket.deliver = lambda self: None\n",
        ),
        (
            "Hub.add(Catalog)\n",
            "Hub.add(Catalog)\nTicket.__eq__ = lambda self, other: True\n",
        ),
        (
            "Hub.add(Catalog)\n",
            "Hub.add(Catalog)\nsetattr(Hub, 'entries', [])\n",
        ),
        (
            "Hub.add(Catalog)\n",
            "Hub.add(Catalog)\nCatalog.refresh = staticmethod(lambda *args: None)\n",
        ),
        (
            "class Ticket:",
            "    def refresh(self, rows):\n        return None\n\nclass Ticket:",
        ),
        (
            "class Ticket:",
            "    if True:\n        def refresh(self, rows):\n            return None\n\nclass Ticket:",
        ),
        (
            "Hub.add(Catalog)\n",
            "Hub.add(ProviderAlias)\nProviderAlias = Catalog\n",
        ),
        (
            "        self.items = Queue()",
            "        self.items = Queue()\n        self.schedule = lambda *args: None",
        ),
        (
            "Hub.add(Catalog)\n",
            "Hub.add(Catalog)\nQueue.put = lambda *args: None\n",
        ),
        (
            "Hub.add(Catalog)\n",
            "class Other: pass\ngetattr(Hub, 'add')(Other)\nHub.add(Catalog)\n",
        ),
    ],
)
def test_unproven_registered_worker_candidate_stays_quiet(
    tmp_path, original, replacement
):
    assert _SOURCE.count(original) == 1
    assert _sql_findings(tmp_path, _SOURCE.replace(original, replacement)) == []
