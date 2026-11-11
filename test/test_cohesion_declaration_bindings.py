"""Declaration evidence requires the current lexical builtin identity."""

import ast
import textwrap

import pytest

from skylos.rules.quality._cohesion_declarations import declaration_method_ids


def _declaration_names(source):
    tree = ast.parse(textwrap.dedent(source))
    declarations = declaration_method_ids(tree)
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and id(node) in declarations
    }


@pytest.mark.parametrize(
    "prefix",
    [
        "",
        "class Other:\n    pass\nother = Other()\n"
        "other.NotImplementedError = RuntimeError\n",
        "class Other:\n    pass\nother = Other()\n"
        'other.__dict__["NotImplementedError"] = RuntimeError\n',
    ],
    ids=["builtin", "unrelated-attribute", "unrelated-namespace"],
)
def test_builtin_marker_survives_unrelated_attribute_writes(prefix):
    source = prefix + (
        "class Worker:\n    def marker(self):\n        raise NotImplementedError\n"
    )

    assert _declaration_names(source) == {"marker"}


@pytest.mark.parametrize(
    "source",
    [
        """
        import builtins as runtime
        runtime.NotImplementedError = RuntimeError
        class Worker:
            def marker(self):
                raise NotImplementedError
        """,
        """
        def replace_exception():
            global NotImplementedError
            NotImplementedError = RuntimeError
        class Worker:
            def marker(self):
                raise NotImplementedError
        """,
        """
        class Worker:
            def marker(self, NotImplementedError):
                raise NotImplementedError
        """,
        """
        class NotImplementedError(Exception):
            pass
        class Worker:
            def marker(self):
                raise NotImplementedError
        """,
        """
        import builtins as runtime
        configure(runtime)
        class Worker:
            def marker(self):
                raise NotImplementedError
        """,
    ],
    ids=[
        "builtin-member-replaced",
        "global-write",
        "parameter-shadow",
        "module-shadow",
        "escaped-builtin-module",
    ],
)
def test_changed_or_unproved_builtin_identity_retains_implementation(source):
    assert _declaration_names(source) == set()


def test_builtin_alias_chain_is_resolved_before_checking_member_mutation():
    # prepare runs first, while install's alias assignment occurs earlier in
    # the AST. The namespace proof must follow both alias links.
    source = """
        import builtins as runtime

        def install():
            second = first
            second.NotImplementedError = RuntimeError

        def prepare():
            global first
            first = runtime

        prepare()
        install()

        class Worker:
            def marker(self):
                raise NotImplementedError
    """

    assert _declaration_names(source) == set()
