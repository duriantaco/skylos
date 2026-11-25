import ast

import pytest

from skylos.rules.danger.danger_sql.sql_source_policy import SqlSourceTracer
from skylos.rules.danger.danger_sql.sqlite_workers import native_worker_cursor
from skylos.rules.danger.project_security_sources import SecurityProject

_WORKER = """import sqlite3 as storage
from queue import Queue as Mailbox
from threading import Thread as Activity

class CatalogWorker(Activity):
    def __init__(self):
        super().__init__()
        self.mailbox = Mailbox()

    def begin(self):
        self.start()

    def run(self):
        self.channel = storage.connect(":memory:")
        self.reader = self.channel.cursor()
        while True:
            message = self.mailbox.get()
            if message == "done":
                self.reader.close()
                self.channel.close()
                break
            message.deliver()  # dispatch
"""

_OPERATION = """class CatalogActions:
    def refresh(receiver, label):
        receiver.reader.execute("SELECT title FROM catalog WHERE name = ?", (label,))
"""


def _receiver(tmp_path, worker_source=_WORKER, operation_source=_OPERATION):
    worker_path = tmp_path / "dispatch.py"
    operation_path = tmp_path / "actions.py"
    worker_path.write_text(worker_source)
    operation_path.write_text(operation_source)
    project = SecurityProject.load(tmp_path)
    worker_unit = project.by_path[worker_path]
    operation_unit = project.by_path[operation_path]
    run = next(
        scope.node
        for scope in worker_unit.function_scopes.values()
        if scope.node.name == "run"
    )
    operation = next(iter(operation_unit.function_scopes.values())).node
    dispatch = next(
        call
        for call, _ in worker_unit.calls
        if isinstance(call.func, ast.Attribute) and call.func.attr == "deliver"
    )
    sink = next(
        call
        for call, _ in operation_unit.calls
        if isinstance(call.func, ast.Attribute) and call.func.attr == "execute"
    )
    return native_worker_cursor(
        SqlSourceTracer(project),
        worker_unit,
        run,
        dispatch,
        operation_unit,
        operation,
        sink,
    )


def test_native_cursor_stays_open_at_registered_worker_dispatch(tmp_path):
    assert _receiver(tmp_path)


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ("super().__init__()", "pass"),
        ("self.start()", "return"),
        ("self.start()", "return\n        self.start()"),
        ("self.start()", "self.start = None\n        self.start()"),
        ("Mailbox()", "ListMailbox()"),
        ('storage.connect(":memory:")', "FakeDatabase()"),
        (
            'storage.connect(":memory:")',
            'storage.connect(":memory:", factory=FakeDatabase)',
        ),
        ("self.channel.cursor()", "self.channel.cursor(factory=FakeCursor)"),
        ("self.channel.cursor()", "Recorder()"),
        ("        self.reader = ", "        return\n        self.reader = "),
        (
            "        self.reader = ",
            "        while True:\n            pass\n        self.reader = ",
        ),
        (
            "        self.reader = ",
            "        if False:\n            yield None\n        self.reader = ",
        ),
        ("        while True:", "        self.channel.close()\n        while True:"),
        (
            "        while True:",
            "        finish = self.channel.close\n        finish()\n        while True:",
        ),
        ("        while True:", "        del self.reader\n        while True:"),
        (
            "        while True:",
            "        self.__dict__['reader'] = Recorder()\n        while True:",
        ),
        (
            "        while True:",
            "        self.__setattr__('reader', Recorder())\n        while True:",
        ),
        (
            "        while True:",
            "        consume(self.reader)\n        while True:",
        ),
        (
            "        while True:",
            "        setfield = setattr\n        setfield(self, 'reader', Recorder())\n        while True:",
        ),
        ("            message = self.mailbox.get()\n", ""),
        ("                break", "                pass"),
        (
            "class CatalogWorker",
            "setattr(storage, 'connect', None)\n\nclass CatalogWorker",
        ),
    ],
)
def test_worker_cursor_abstains_when_native_lifecycle_is_unproved(
    tmp_path, original, replacement
):
    assert not _receiver(tmp_path, _WORKER.replace(original, replacement))


def test_worker_cursor_rejects_closed_cursor_within_published_operation(tmp_path):
    operation = _OPERATION.replace(
        "        receiver.reader.execute",
        "        alias = receiver.reader\n        alias.close()\n        receiver.reader.execute",
    )
    assert not _receiver(tmp_path, operation_source=operation)


def test_worker_cursor_rejects_generator_operation(tmp_path):
    assert not _receiver(tmp_path, operation_source=_OPERATION + "        yield None\n")


def test_worker_cursor_rejects_project_shadow_of_sqlite(tmp_path):
    (tmp_path / "sqlite3.py").write_text("connect = None\n")
    assert not _receiver(tmp_path)
