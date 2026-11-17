"""Future decorators require a source-bound provider, with dead siblings retained."""

import ast
import json
import textwrap
from types import SimpleNamespace

import pytest

from skylos.analyzer import analyze
from skylos.deadcode.future_callbacks import find_future_callback_targets
from skylos.deadcode.python_ast import ParsedPythonFile
from test.fixture_paths import write_fixture


def _scan(tmp_path, source):
    write_fixture(
        tmp_path,
        (tmp_path / "app.py").relative_to(tmp_path),
        textwrap.dedent(source),
        overwrite=True,
    )
    report = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    return {item["simple_name"] for item in report.get("unused_functions", [])}


@pytest.mark.parametrize(
    "setup",
    [
        "from concurrent.futures import Future\nfuture = Future()",
        "import concurrent.futures as cf\nfuture = cf.Future()",
        'from concurrent.futures import ThreadPoolExecutor\nexecutor = ThreadPoolExecutor()\nfuture = executor.submit(print, "ready")',
    ],
)
def test_future_callback_decorator_registers_only_its_function(tmp_path, setup):
    unused = _scan(
        tmp_path,
        setup
        + """
@future.add_done_callback
def callback(done):
    return done.result()

def unused_callback(done):
    return done.result()

future.set_result("done")
""",
    )
    assert "callback" not in unused
    assert "unused_callback" in unused


def test_executor_member_submit_preserves_registered_callback(tmp_path):
    unused = _scan(
        tmp_path,
        """
from concurrent.futures import Executor, Future, ThreadPoolExecutor

class Runner:
    def __init__(self, executor: Executor | None = None):
        if executor:
            self._executor: Executor = executor
        else:
            self._executor = ThreadPoolExecutor()

    def run(self):
        future: Future = self._executor.submit(print, "ready")

        @future.add_done_callback
        def _callback(done):
            return done.result()

        def _stale(done):
            return done.result()

Runner().run()
""",
    )
    assert "_callback" not in unused
    assert "_stale" in unused


@pytest.mark.parametrize(
    "setup",
    [
        """class Future:
    def add_done_callback(self, fn):
        return fn
future = Future()""",
        """from concurrent.futures import Future
class Other:
    def add_done_callback(self, fn):
        return fn
Future = Other
future = Future()""",
        """class Executor:
    def submit(self, *args):
        return self
    def add_done_callback(self, fn):
        return fn
executor = Executor()
future = executor.submit(print)""",
        """from concurrent.futures import Future
future = Future()
future.add_done_callback = lambda fn: fn""",
    ],
)
def test_unproven_or_shadowed_decorator_does_not_rescue_function(tmp_path, setup):
    assert "callback" in _scan(
        tmp_path,
        setup
        + """
@future.add_done_callback
def callback(done):
    return done

print(future)
""",
    )


@pytest.mark.parametrize(
    "setup",
    [
        """from concurrent.futures import Future
Future.add_done_callback = lambda self, fn: fn
future = Future()""",
        """from concurrent.futures import Future
setattr(Future, "add_done_callback", lambda self, fn: fn)
future = Future()""",
    ],
)
def test_patched_imported_future_class_does_not_rescue(tmp_path, setup):
    assert not _future_targets(
        tmp_path,
        setup
        + """
@future.add_done_callback
def callback(done):
    return done
print(future)
""",
    )


def test_future_annotation_on_unknown_parameter_is_not_provider_proof(tmp_path):
    targets = _future_targets(
        tmp_path,
        """
from concurrent.futures import Future

def run(future: Future):
    @future.add_done_callback
    def callback(done):
        return done

run(object())
""",
    )
    assert not targets


def _future_targets(tmp_path, source):
    path = tmp_path / "app.py"
    tree = ast.parse(textwrap.dedent(source))
    definitions = {
        str(node.lineno): SimpleNamespace(
            filename=path,
            line=node.lineno,
            node=node,
            type="function",
            name="app." + node.name,
            simple_name=node.name,
        )
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    return find_future_callback_targets(definitions, [ParsedPythonFile(path, tree)])


@pytest.mark.parametrize(
    "mutation",
    [
        "alias.add_done_callback = lambda fn: fn",
        'setter = setattr\nsetter(alias, "add_done_callback", lambda fn: fn)',
    ],
)
def test_alias_mutation_cannot_supply_future_registration_proof(tmp_path, mutation):
    source = (
        "from concurrent.futures import Future\nfuture = Future()\nalias = future\n"
        + mutation
        + """
@future.add_done_callback
def callback(done):
    return done
"""
    )
    assert not _future_targets(tmp_path, source)
