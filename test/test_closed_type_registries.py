"""Closed type-registry negatives preserve real/dynamic/escaped consumers."""

import json
import textwrap
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.benchmarks.dead_code import run_manifest

_TABLE = """
class Bus:
    def __init__(self):
        self.callbacks = {}

    def register(self, kind):
        def attach(callback):
            self.callbacks[kind] = callback
            return callback
        return attach

    def send(self, value):
        callback = self.callbacks.get(type(value))
        return callback(value) if callback is not None else None
"""


def _project(tmp_path, consumer, *, extra="", table=_TABLE):
    (tmp_path / "routes.py").write_text(textwrap.dedent(table))
    source = """
from routes import Bus

def run():
    bus = Bus()
    @bus.register(str)
    def format_selected(value):
        return 1
    @bus.register(bytes)
    def format_later(value):
        return 2
"""
    source += textwrap.indent(textwrap.dedent(extra).strip(), "    ") + "\n"
    source += textwrap.indent(textwrap.dedent(consumer).strip(), "    ") + "\n\nrun()\n"
    (tmp_path / "app.py").write_text(textwrap.dedent(source))
    raw = json.loads(
        analyze(str(tmp_path), conf=60, grep_verify=True, grep_cache=False)
    )
    return {f["simple_name"] for f in raw.get("unused_functions", [])}, raw


def test_closed_type_selection_reports_dead_body_not_selected_callback(tmp_path):
    unused, _ = _project(tmp_path, 'print(bus.send("text"))')
    assert "format_later" in unused
    assert "format_selected" not in unused


def test_receiver_alias_can_invoke_other_type_callback(tmp_path):
    unused, _ = _project(
        tmp_path, 'alias = bus\nprint(alias.send(b"data"))\nprint(bus.send("text"))'
    )
    assert not {"format_selected", "format_later"} & unused


@pytest.mark.parametrize(
    "consumer,extra",
    [
        ("print(bus.send(input()))", ""),
        ('print(bus.send("text"))', "from plugin import consume\nconsume(bus)"),
        ('print(bus.send("text"))', "bus.send = unknown_consumer"),
        ('print(bus.send("text"))', "print([bus])"),
    ],
)
def test_unknown_input_escape_rebinding_or_nested_output_abstains(
    tmp_path, consumer, extra
):
    unused, _ = _project(tmp_path, consumer, extra=extra)
    assert "format_later" not in unused


def test_custom_instance_key_abstains_without_running_hash_hooks(tmp_path):
    unused, _ = _project(
        tmp_path,
        'print(bus.send("text"))',
        extra="""
    class Key:
        def __hash__(self):
            return 1
    bus.callbacks.get(Key())
    """,
    )
    assert "format_later" not in unused


def test_bool_mro_preserves_int_handler(tmp_path):
    table = _TABLE.replace(
        "callback = self.callbacks.get(type(value))\n        return callback(value) if callback is not None else None",
        """for kind in type(value).__mro__:
            callback = self.callbacks.get(kind)
            if callback is not None:
                return callback(value)
        return None""",
    )
    (tmp_path / "routes.py").write_text(textwrap.dedent(table))
    (tmp_path / "app.py").write_text("""from routes import Bus
bus = Bus()
@bus.register(int)
def numeric(value):
    return 1
@bus.register(str)
def text_only(value):
    return 2
print(bus.send(True))
""")
    report = json.loads(analyze(str(tmp_path), conf=60, grep_verify=False))
    unused = {f["simple_name"] for f in report.get("unused_functions", [])}
    assert "numeric" not in unused
    assert "text_only" in unused


@pytest.mark.parametrize(
    "case",
    ["owner", "mismatch", "rebound", "snapshot", "closure", "hierarchy", "private"],
)
def test_all_source_frozen_type_registry_contracts(tmp_path, case):
    manifest = (
        Path(__file__).resolve().parents[1]
        / "benchmarks/dead_code/adversarial_manifest.json"
    )
    summary = run_manifest(manifest, selected_cases={"corpus-type-registry-" + case})
    assert summary["counts"]["false_negatives"] == 0
    assert summary["counts"]["false_positives"] == 0


def test_unknown_registration_callable_before_decoration_has_no_negative_proof(
    tmp_path,
):
    import ast
    from types import SimpleNamespace

    from skylos.deadcode.closed_type_registries import closed_type_registry_unused
    from skylos.deadcode.python_ast import parse_python_files

    (tmp_path / "routes.py").write_text(textwrap.dedent(_TABLE))
    (tmp_path / "app.py").write_text("""from routes import Bus
bus = Bus()
bus.register = unknown_registration
@bus.register(str)
def callback(value):
    return 1
print(bus.send("text"))
""")
    paths = list(tmp_path.glob("*.py"))
    definitions = {}
    for parsed in parse_python_files(paths):
        for node in ast.walk(parsed.tree):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                name = parsed.path.stem + "." + node.name
                definitions[name] = SimpleNamespace(
                    filename=parsed.path,
                    line=node.lineno,
                    node=node,
                    name=name,
                    simple_name=node.name,
                    type="class" if isinstance(node, ast.ClassDef) else "function",
                    is_exported=False,
                    heuristic_refs={},
                )
    assert closed_type_registry_unused(definitions, paths, tmp_path) == set()


@pytest.mark.parametrize(
    "filename,content",
    [
        ("run.sh", 'python -c "from app import run; run()"\n'),
        ("README.md", "External callers may import and invoke registered callbacks.\n"),
    ],
)
def test_nonpython_entrypoint_context_abstains(tmp_path, filename, content):
    from test.test_closed_type_registry_independent_review import negative_names

    (tmp_path / filename).write_text(content)
    assert negative_names(tmp_path, "print(router.deliver('text'))") == set()


@pytest.mark.parametrize(
    "body",
    [
        "type = lambda value: bytes\nprint(router.deliver('text'))",
        "def print(value):\n    number_handler(1)\nprint(router.deliver('text'))",
        "__builtins__ = {}\nprint(router.deliver('text'))",
    ],
)
def test_modeled_builtin_shadowing_produces_no_negative_override(tmp_path, body):
    from test.test_closed_type_registry_independent_review import negative_names

    assert negative_names(tmp_path, body) == set()
