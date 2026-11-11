"""Credential traversal retains lexical proofs and deferred query behavior."""

import ast
import textwrap

import pytest

from skylos.rules.quality.logic_security import (
    _credential_literal_sources,
    _resolved_builtin_getattr_calls,
)


@pytest.mark.parametrize(
    "source,expected_keys",
    [
        ('getattr(config, "module")', {"module"}),
        ('getattr = custom\ngetattr(config, "module")', set()),
        (
            "def read(getattr):\n    return getattr(config, 'local')\n",
            set(),
        ),
        (
            "class Settings:\n"
            "    getattr = custom\n"
            "    selected = getattr(config, 'class')\n",
            set(),
        ),
        (
            "class Settings:\n"
            "    getattr = custom\n"
            "    def read(self):\n"
            "        return getattr(config, 'method')\n",
            {"method"},
        ),
        (
            "def local(getattr):\n"
            "    return getattr(config, 'local')\n"
            "selected = getattr(config, 'module')\n",
            {"module"},
        ),
        (
            "selected = getattr(config, 'module')\n"
            "def replace():\n    global getattr\n",
            set(),
        ),
        ('from project import *\ngetattr(config, "module")', set()),
        ('read = lambda: getattr(config, "lambda")', {"lambda"}),
        ('read = lambda getattr: getattr(config, "lambda")', set()),
    ],
    ids=[
        "builtin",
        "module-shadow",
        "parameter-shadow",
        "class-body-shadow",
        "method-skips-class-namespace",
        "unrelated-local-shadow",
        "global-uncertainty",
        "wildcard-import",
        "lambda-builtin",
        "lambda-shadow",
    ],
)
def test_builtin_getattr_requires_its_lexical_binding(source, expected_keys):
    tree = ast.parse(textwrap.dedent(source))
    resolved = _resolved_builtin_getattr_calls(tree)
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]

    assert resolved == {
        id(call) for call in calls if call.args[1].value in expected_keys
    }


def test_global_getattr_short_circuits_before_reading_malformed_call():
    tree = ast.parse('getattr(config, "password")\nglobal getattr\n')
    del tree.body[0].value.func

    assert _resolved_builtin_getattr_calls(tree) == set()


def test_deferred_credential_scan_observes_new_direct_literal_calls():
    tree = ast.parse('connect(password="initial fixture")\n')
    initial_literal = tree.body[0].value.keywords[0].value
    registered = []

    result = _credential_literal_sources(
        tree,
        lambda name: name == "password",
        resolver_callback=lambda scan, export: registered.append((scan, export)),
    )

    assert result == set()
    assert len(registered) == 1
    scan, _export = registered[0]
    assert scan() == {id(initial_literal)}

    added = ast.parse('connect(password="later fixture")\n').body[0]
    later_literal = added.value.keywords[0].value
    tree.body.append(added)

    assert scan() == {id(initial_literal), id(later_literal)}
