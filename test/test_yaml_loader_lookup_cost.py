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


def test_classless_yaml_modules_do_not_build_local_class_safety_proofs(monkeypatch):
    module = ast.parse(
        "import yaml\n"
        + "".join(f"yaml.load(data, Loader=missing_{index})\n" for index in range(400))
    )
    original_proof = yaml_loader_provenance.safe_yaml_loader_classes
    proof_calls = 0

    def counted_proof(*args, **kwargs):
        nonlocal proof_calls
        proof_calls += 1
        return original_proof(*args, **kwargs)

    monkeypatch.setattr(
        yaml_loader_provenance, "safe_yaml_loader_classes", counted_proof
    )
    assert yaml_loader_provenance.yaml_loader_classes(module) == (
        frozenset(),
        frozenset(),
    )
    assert proof_calls == 0

    visible = ast.parse("import yaml\nclass Loader(yaml.UnsafeLoader):\n    pass\n")
    assert yaml_loader_provenance.yaml_loader_classes(visible) == (
        frozenset(),
        frozenset({"Loader"}),
    )
    assert proof_calls == 1


def test_absent_loader_names_skip_native_import_proof(monkeypatch):
    module = ast.parse(
        "import yaml\ndata = input()\n"
        + "".join(f"yaml.load(data, Loader=missing_{index})\n" for index in range(400))
    )
    calls._yaml_loader_namespace(module)
    original_proof = calls._is_native_safe_yaml_loader
    native_calls = 0

    def counted_proof(*args, **kwargs):
        nonlocal native_calls
        native_calls += 1
        return original_proof(*args, **kwargs)

    monkeypatch.setattr(calls, "_is_native_safe_yaml_loader", counted_proof)
    verdicts = [
        calls._is_safe_loader_argument(
            statement.value.keywords[0].value,
            {},
            (frozenset(), frozenset()),
            module=module,
        )
        for statement in module.body[2:]
    ]
    assert verdicts == [False] * 400
    assert native_calls == 0
