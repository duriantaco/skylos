"""Unbound loader names must reuse the module's existing binding index."""

import ast

from skylos.rules.danger import calls


def test_unbound_loader_names_do_not_repeat_whole_module_walks(monkeypatch):
    source = "import yaml\ndata = input()\n" + "".join(
        f"yaml.load(data, Loader=missing_{index})\n" for index in range(400)
    )
    module = ast.parse(source)
    calls._yaml_loader_namespace(module)
    original_walk = ast.walk
    whole_module_walks = 0

    def counted_walk(node):
        nonlocal whole_module_walks
        if node is module:
            whole_module_walks += 1
        return original_walk(node)

    monkeypatch.setattr(ast, "walk", counted_walk)
    results = [
        calls._yaml_loader_rebinding(module, f"missing_{index}", {})
        for index in range(400)
    ]
    assert results == [None] * 400
    assert whole_module_walks == 0
