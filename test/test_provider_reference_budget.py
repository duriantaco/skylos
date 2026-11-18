"""Repeated provider checks should share the cost of resolving the same AST."""

import ast

import pytest

from skylos.rules.danger.import_proof import _Effects, _provider_effects


@pytest.mark.parametrize("replacement", [False, True])
def test_repeated_provider_checks_on_large_modules_preserve_direction_and_mutations(
    replacement,
):
    # About 16,000 AST nodes, within the module budget. These source expressions
    # are repeatedly inspected when the scanner checks native descriptor effects.
    source = "import os\ndef monitor(value):\n" + "    observe(value)\n" * 3100
    if replacement:
        source += (
            "def change_provider(replacement):\n"
            "    first = second\n"
            "    first.open = replacement\n"
            "second = os\n"
        )
    tree = ast.parse(source)
    for name in (
        "getpid",
        "fstat",
        "fsync",
        "read",
        "write",
        "ftruncate",
        "close",
        "stat",
        "O_RDONLY",
        "O_RDWR",
        "O_WRONLY",
    ):
        assert _provider_effects(("os." + name,), tree)
    assert _provider_effects(("os.open",), tree) is (not replacement)


def test_cached_root_preserves_the_nested_lookup_depth_limit():
    tree = ast.parse("import os\nos.open\n")
    operand = tree.body[1].value
    effects = _Effects(tree)
    assert effects.refs(operand) == {"os.open"}
    assert not effects.refs(operand, 33)
    assert not effects.complete


def test_distinct_lookup_after_budget_exhaustion_keeps_the_provider_uncertain():
    tree = ast.parse("import os\nos.open\nos.close\n")
    effects = _Effects(tree)
    assert effects.refs(tree.body[1].value) == {"os.open"}
    effects.ref_work = 65536
    assert not effects.refs(tree.body[2].value)
    assert not effects.complete
    assert not effects.stable(lambda name: name == "os.open", key="os.open")
