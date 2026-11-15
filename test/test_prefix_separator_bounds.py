"""Tuple prefixes must be flat strings and cannot multiply proof work."""

import ast

from skylos.rules.danger.danger_fs import prefix_separator
from skylos.rules.danger.danger_fs import path_flow, weak_path_defence
from skylos.rules.danger.danger import scan_ctx
from test.fixture_paths import write_fixture


def test_wide_tuple_alias_graph_does_not_multiply_resolution_work():
    source = "p0 = ('/safe/',)\n"
    for level in range(1, 8):
        source += f"p{level} = (" + f"p{level - 1}," * 100 + ")\n"
    bindings = prefix_separator.scope_bindings(ast.parse(source))
    resolutions = 0

    def resolve(name):
        nonlocal resolutions
        resolutions += 1
        # Bound a failing implementation too: this graph would otherwise do
        # 100**7 leaf checks while remaining within its depth limit.
        assert resolutions <= 1_000, "tuple expansion repeated shared subgraphs"
        values = bindings.get(name)
        return values[0] if values and len(values) == 1 else None

    proven = prefix_separator.ends_with_separator(
        ast.Name(id="p7", ctx=ast.Load()), resolve, lambda node: None, resolve
    )

    # Python str.startswith accepts a tuple of strings, never nested tuples.
    assert proven is False
    assert resolutions <= 1_000


def test_flat_tuple_aliases_still_accept_only_separator_terminated_strings():
    bindings = prefix_separator.scope_bindings(
        ast.parse("left = '/safe/'\nright = '/other/'\nprefixes = (left, right)\n")
    )

    def resolve(name):
        values = bindings.get(name)
        return values[0] if values and len(values) == 1 else None

    assert prefix_separator.ends_with_separator(
        ast.Name(id="prefixes", ctx=ast.Load()), resolve, lambda node: None, resolve
    )


def test_wide_nested_tuple_guard_keeps_the_traversal_finding(tmp_path, monkeypatch):
    source = (
        "import os\nfrom fastapi import FastAPI, HTTPException\n"
        "from fastapi.responses import FileResponse\napp = FastAPI()\n"
        "p0 = ('/safe/',)\n"
    )
    for level in range(1, 8):
        source += f"p{level} = (" + f"p{level - 1}," * 100 + ")\n"
    source += (
        "@app.get('/files/{name}')\ndef download(name: str):\n"
        "    target = os.path.normpath(os.path.join('/safe', name))\n"
        "    if not target.startswith(p7):\n        raise HTTPException(404)\n"
        "    return FileResponse(target)\n"
    )
    path = write_fixture(tmp_path, "server.py", source)
    original = prefix_separator.ends_with_separator
    resolutions = 0

    def bounded(node, resolve, canonical, module_resolve=None, *args, **kwargs):
        def counted(callback):
            def lookup(name):
                nonlocal resolutions
                resolutions += 1
                assert resolutions <= 1_000, "tuple expansion exceeded its work bound"
                return callback(name)

            return lookup

        return original(
            node,
            counted(resolve),
            canonical,
            counted(module_resolve) if module_resolve is not None else None,
            *args,
            **kwargs,
        )

    monkeypatch.setattr(path_flow, "ends_with_separator", bounded)
    monkeypatch.setattr(weak_path_defence, "ends_with_separator", bounded)

    findings = [row for row in scan_ctx(tmp_path, [path]) if row["rule_id"] == "SKY-D215"]

    assert [row["line"] for row in findings] == [
        source.splitlines().index("    return FileResponse(target)") + 1
    ]
    assert resolutions <= 1_000


def test_wide_flat_tuple_cannot_return_a_partial_safety_proof():
    bindings = prefix_separator.scope_bindings(
        ast.parse("part = '/safe/'\nprefixes = (" + "part," * 1_000 + ")\n")
    )
    resolutions = 0

    def resolve(name):
        nonlocal resolutions
        resolutions += 1
        assert resolutions <= 1_000, "flat tuple proof ignored its work bound"
        values = bindings.get(name)
        return values[0] if values and len(values) == 1 else None

    proven = prefix_separator.ends_with_separator(
        ast.Name(id="prefixes", ctx=ast.Load()), resolve, lambda node: None, resolve
    )

    assert proven is False
    assert resolutions <= 1_000


def test_fstring_alias_expansion_shares_the_work_bound():
    source = "p0 = '/'\n"
    for level in range(1, 3):
        source += f"p{level} = f'" + f"{{p{level - 1}}}" * 100 + "'\n"
    bindings = prefix_separator.scope_bindings(ast.parse(source))
    resolutions = 0

    def resolve(name):
        nonlocal resolutions
        resolutions += 1
        assert resolutions <= 1_000, "f-string aliases ignored the shared work bound"
        values = bindings.get(name)
        return values[0] if values and len(values) == 1 else None

    proven = prefix_separator.ends_with_separator(
        ast.Name(id="p2", ctx=ast.Load()), resolve, lambda node: None, resolve
    )

    assert proven is False
    assert resolutions <= 1_000
