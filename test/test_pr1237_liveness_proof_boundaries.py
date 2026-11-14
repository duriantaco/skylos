"""Dynamic liveness requires a reachable consumer and the actual provider."""

import ast
import json
import textwrap

import pytest

from skylos.analyzer import Skylos, analyze
from skylos.benchmarks.dead_code import run_manifest
from skylos.deadcode.class_protocol_liveness import find_class_protocol_members
from skylos.deadcode.python_ast import ParsedPythonFile


def _scan(tmp_path, code):
    (tmp_path / "app.py").write_text(textwrap.dedent(code).lstrip())
    result = json.loads(analyze(str(tmp_path), conf=60, grep_verify=True))
    assert not result.get("analysis_errors")
    return {item["full_name"] for item in result.get("unused_functions", [])}


def _protocol_targets(tmp_path, code):
    path = tmp_path / "app.py"
    source = textwrap.dedent(code).lstrip()
    path.write_text(source)
    scanner = Skylos()
    scanner.analyze(str(tmp_path))
    parsed = ParsedPythonFile(path, ast.parse(source))
    return {
        target.name for target in find_class_protocol_members(scanner.defs, [parsed])
    }


def test_unnamed_methods_remain_dead_beside_an_unrelated_lookup(tmp_path):
    unused = _scan(
        tmp_path,
        """
        class Cache:
            def get(self, key): return key
            def idle(self, key): return key
        class Holder:
            def __init__(self): self.cache = Cache()
            def use(self): return self.cache.get(1)
        print(Holder().use())
        getattr(object(), input(), None)
    """,
    )
    assert "app.Cache.idle" in unused
    assert "app.Cache.get" not in unused


def test_unnamed_receiver_benchmark_preserves_proxy_and_remote_consumers():
    summary = run_manifest(
        "benchmarks/dead_code/manifest.json",
        selected_cases={"python-unnamed-receiver-methods"},
    )
    assert summary["failure_count"] == 0, summary["cases"]


@pytest.mark.parametrize(
    "code, expected",
    [
        (
            """
        def never_called(code):
            exec(code, globals())
        def abandoned(): return 42
        print('start')
    """,
            {"app.never_called", "app.abandoned"},
        ),
        (
            """
        def wrapper(code):
            return never_called(code)
        def never_called(code):
            exec(code, globals())
        def abandoned(): return 42
        print('start')
    """,
            {"app.wrapper", "app.never_called", "app.abandoned"},
        ),
        (
            """
        def exec(code, namespace): print(code)
        def abandoned(): return 42
        exec('hello', globals())
    """,
            {"app.abandoned"},
        ),
        (
            """
        def globals(): return {}
        def abandoned(): return 42
        exec(input(), globals())
    """,
            {"app.abandoned"},
        ),
        (
            """
        def run(exec):
            exec('hello', globals())
        def abandoned(): return 42
        run(print)
    """,
            {"app.abandoned"},
        ),
    ],
)
def test_dead_or_shadowed_exec_does_not_rescue_the_module(tmp_path, code, expected):
    assert expected <= _scan(tmp_path, code)


@pytest.mark.parametrize(
    "expression", ["exec(input(), globals())", "eval(input(), globals())"]
)
def test_reachable_builtin_namespace_consumers_still_keep_bindings(
    tmp_path, expression
):
    unused = _scan(
        tmp_path,
        f"""
        import bisect
        def dynamically_called(): return 42
        def run():
            {expression}
        run()
    """,
    )
    assert "app.dynamically_called" not in unused


@pytest.mark.parametrize(
    "prefix",
    [
        "from twisted.web.resource import Resource\nclass Local: pass\nResource = Local\n",
        "class Resource: pass\ndef unused_loader():\n    from twisted.web.resource import Resource\n    return Resource\n",
    ],
)
def test_framework_member_requires_the_actual_base_binding(tmp_path, prefix):
    unused = _scan(
        tmp_path,
        prefix
        + "class Page(Resource):\n    def render_GET(self, request): return b'unused'\nprint(Page())\n",
    )
    assert "app.Page.render_GET" in unused


def test_function_parameter_cannot_borrow_a_module_framework_import(tmp_path):
    targets = _protocol_targets(
        tmp_path,
        """
        from twisted.web.resource import Resource
        class Plain: pass
        def make(Resource):
            class Page(Resource):
                def render_GET(self, request): return b'unused'
            return Page()
        print(make(Plain))
    """,
    )
    assert not any(name.endswith(".render_GET") for name in targets)


def test_nested_genuine_import_and_inherited_framework_member_still_live(tmp_path):
    targets = _protocol_targets(
        tmp_path,
        """
        def make():
            from twisted.web.resource import Resource
            class Base(Resource): pass
            class Page(Base):
                def render_GET(self, request): return b'ok'
                def render_unused(self, request): return b'unused'
            return Page()
        print(make())
    """,
    )
    assert any(name.endswith(".render_GET") for name in targets)
    assert not any(name.endswith(".render_unused") for name in targets)


def test_wildcard_import_cannot_prove_a_framework_base_binding(tmp_path):
    (tmp_path / "helper.py").write_text("class Resource: pass\n")
    unused = _scan(
        tmp_path,
        """
        from twisted.web.resource import Resource
        from helper import *
        class Page(Resource):
            def render_GET(self, request): return b'unused'
        print(Page())
    """,
    )
    assert "app.Page.render_GET" in unused


def test_wildcard_import_cannot_prove_builtin_namespace_escape(tmp_path):
    (tmp_path / "helper.py").write_text(
        "def exec(code, namespace): print(code)\ndef globals(): return {}\n"
    )
    unused = _scan(
        tmp_path,
        """
        from helper import *
        def abandoned(): return 42
        exec('hello', globals())
    """,
    )
    assert "app.abandoned" in unused
