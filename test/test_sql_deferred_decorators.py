"""Static controls for deferred method forwarding and SQL row provenance."""

import ast
from textwrap import dedent

import pytest

from skylos.rules.danger.danger_fs.path_provenance import _Project
from skylos.rules.danger.danger_sql.deferred_sql import deferred_entry, row_argument
from skylos.rules.danger.danger_sql.sql_source_policy import SqlSourceTracer

_ADAPTER = """
class Dispatch:
    endpoint = None

    @classmethod
    def install(cls, receiver):
        cls.endpoint = receiver

    @classmethod
    def later(cls, handler):
        @staticmethod
        def forward(*args, **kwargs):
            return cls.endpoint.schedule(handler, *args, **kwargs)
        return forward
"""

_WORKER = """
from adapter import Dispatch

class Executor:
    def __init__(self):
        Dispatch.install(self)
"""

_QUERY = """
from adapter import Dispatch

class Operations:
    @Dispatch.later
    def lookup(self, rows):
        self.cursor.executemany("INSERT INTO catalog VALUES (?, ?)", rows)
        lookup_values = "','".join(row[1] for row in rows)
        self.cursor.execute(f"SELECT title FROM catalog WHERE title IN ('{lookup_values}')")
"""


def _proofs(root, *, adapter=_ADAPTER, worker=_WORKER, query=_QUERY):
    for name, source in {"adapter": adapter, "worker": worker, "query": query}.items():
        (root / f"{name}.py").write_text(dedent(source), encoding="utf-8")
    project = _Project.load(root, list(root.glob("*.py")), True)
    unit = project.by_path[root / "query.py"]
    sink, scope = next(
        (call, scope)
        for call, scope in unit.calls
        if isinstance(call.func, ast.Attribute) and call.func.attr == "execute"
    )
    tracer = SqlSourceTracer(project)
    return deferred_entry(tracer, unit, scope), row_argument(
        tracer, unit, scope, sink.args[0], sink
    )


def test_cross_file_decorator_preserves_callable_and_row_arguments(tmp_path):
    entry, source = _proofs(tmp_path)
    assert entry.worker_class.name == "Executor"
    assert entry.worker_unit.rel == "worker.py"
    assert entry.scheduler_name == "schedule"
    assert source[0] == "rows"
    assert any("item of" in step for step in source[1])


@pytest.mark.parametrize(
    "source",
    [
        _ADAPTER.replace(
            "    @classmethod\n    def later", "    @custom\n    def later"
        ),
        "staticmethod = custom\n" + _ADAPTER,
        _ADAPTER.replace(
            "schedule(handler, *args, **kwargs)", "schedule(other, *args, **kwargs)"
        ),
        _ADAPTER.replace(
            "schedule(handler, *args, **kwargs)",
            "schedule(handler, *(rows,), **kwargs)",
        ),
        _ADAPTER + "\nDispatch.install = replace_worker\n",
        _ADAPTER + "\nDispatch.endpoint = different_worker\n",
        _ADAPTER + "\nDispatch.later = other_decorator\n",
    ],
)
def test_spoofed_or_reassigned_decorator_cannot_supply_worker(tmp_path, source):
    assert _proofs(tmp_path, adapter=source)[0] is None


@pytest.mark.parametrize(
    "initializer",
    ["Dispatch.install(self)", "alias = Dispatch.install\n        alias(self)"],
)
def test_multiple_visible_worker_registrations_stay_ambiguous(tmp_path, initializer):
    worker = (
        _WORKER
        + "\nclass Other:\n    def __init__(self):\n        "
        + initializer
        + "\n"
    )
    assert _proofs(tmp_path, worker=worker)[0] is None


def test_cross_module_native_reflective_change_prevents_worker_proof(tmp_path):
    worker = (
        _WORKER
        + '\nfrom builtins import setattr as change\nchange(Dispatch, "endpoint", None)\n'
    )
    assert _proofs(tmp_path, worker=worker)[0] is None


@pytest.mark.parametrize(
    "before,after",
    [
        ("\"','\".join(row[1] for row in rows)", '",".join("?" * len(rows))'),
        ("for row in rows)", "for row in rows if permitted(row))"),
        ("row[1] for", "escape(row[1]) for"),
        ("        lookup_values =", "        rows.clear()\n        lookup_values ="),
        (
            "        self.cursor.execute(",
            "        validate(rows)\n        self.cursor.execute(",
        ),
        (
            "        self.cursor.execute(",
            "        validate(lookup_values)\n        self.cursor.execute(",
        ),
        (
            "        self.cursor.execute(",
            "        return\n        self.cursor.execute(",
        ),
    ],
)
def test_sql_argument_requires_unmodified_row_projection(tmp_path, before, after):
    entry, source = _proofs(tmp_path, query=_QUERY.replace(before, after))
    assert entry is not None
    assert source is None
