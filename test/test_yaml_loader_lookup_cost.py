"""Unbound loader names must reuse the module's existing binding index."""

import ast

from skylos.rules.danger import calls
from skylos.rules.danger import yaml_loader_provenance


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


def test_yaml_call_alias_index_is_built_once_for_many_calls(monkeypatch):
    module = ast.parse(
        "import yaml as parser\n"
        + "".join(f"parser.load(data_{index})\n" for index in range(400))
    )
    original_aliases = yaml_loader_provenance._module_aliases
    builds = 0

    def counted_aliases(tree):
        nonlocal builds
        builds += 1
        return original_aliases(tree)

    monkeypatch.setattr(yaml_loader_provenance, "_module_aliases", counted_aliases)
    results = [
        yaml_loader_provenance.yaml_load_call_name(statement.value, module)
        for statement in module.body[1:]
    ]
    assert results == ["yaml.load"] * 400
    assert builds == 1


def test_yaml_call_alias_index_does_not_leak_between_modules():
    native = ast.parse("import yaml as parser\nparser.load(data)\n")
    lookalike = ast.parse("import custom as parser\nparser.load(data)\n")
    for module, expected in [
        (native, "yaml.load"),
        (lookalike, None),
        (native, "yaml.load"),
    ]:
        call = module.body[1].value
        assert yaml_loader_provenance.yaml_load_call_name(call, module) == expected
