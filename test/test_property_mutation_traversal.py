"""Property mutation evidence remains current and scoped to each module."""

import ast
from pathlib import Path

import pytest

from skylos.deadcode.property_descriptor_liveness import (
    _Module,
    _bindings,
    _imports,
    _mutations,
)


def _module(source, name="app"):
    tree = ast.parse(source)
    path = Path(f"{name}.py")
    return _Module(
        name=name,
        path=path,
        tree=tree,
        counts=_bindings(tree.body),
        imports=_imports(name, path, tree),
        functions={
            node.name: node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        },
        classes={
            node.name: node for node in tree.body if isinstance(node, ast.ClassDef)
        },
        aliases={},
    )


@pytest.mark.parametrize(
    "statement,expected",
    [
        ("runtime.property = replacement", {"builtins.property"}),
        ('globals()["property"] = replacement', {"app.*"}),
        ('setattr(runtime, "property", replacement)', {"builtins.property"}),
    ],
    ids=["builtin-attribute", "globals-subscript", "setattr"],
)
def test_new_mutation_is_seen_on_the_next_invocation(statement, expected):
    module = _module("import builtins as runtime\n")
    assert _mutations([module]) == set()

    module.tree.body.append(ast.parse(statement).body[0])

    assert _mutations([module]) == expected


@pytest.mark.parametrize("reverse", [False, True])
def test_builtin_alias_does_not_leak_into_a_sibling_module(reverse):
    importer = _module("import builtins as runtime\n", "importer")
    unrelated = _module("runtime.property = replacement\n", "unrelated")
    modules = [importer, unrelated]
    if reverse:
        modules.reverse()

    assert _mutations(modules) == set()


def test_classless_sibling_still_contributes_builtin_mutation():
    owner = _module("class Owner:\n    pass\n", "owner")
    writer = _module(
        "import builtins as runtime\nruntime.property = replacement\n", "writer"
    )
    assert writer.classes == {}

    assert _mutations([owner, writer]) == {"builtins.property"}


@pytest.mark.parametrize(
    "source,missing_field",
    [
        ("import builtins\n", "names"),
        ("call()\n", "func"),
        ('values["key"] = replacement\n', "ctx"),
    ],
    ids=["import-names", "call-func", "subscript-ctx"],
)
def test_missing_required_ast_fields_keep_their_error(source, missing_field):
    module = _module(source)
    statement = module.tree.body[0]
    if missing_field == "names":
        damaged = statement
    elif missing_field == "func":
        damaged = statement.value
    else:
        damaged = statement.targets[0]
    delattr(damaged, missing_field)

    with pytest.raises(AttributeError, match=f"'{missing_field}'"):
        _mutations([module])


def test_import_error_precedes_an_earlier_malformed_call():
    # The call precedes the conditional import in breadth-first traversal.
    # Import collection still finishes before the call-analysis phase begins.
    module = _module("call()\nif enabled:\n    import builtins\n")
    del module.tree.body[0].value.func
    del module.tree.body[1].body[0].names

    with pytest.raises(AttributeError, match="'names'"):
        _mutations([module])
