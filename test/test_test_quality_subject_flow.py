"""Reachability and collection identities of test-quality subjects."""

import ast
from textwrap import dedent

import pytest

from skylos.rules.quality.test_assertions import ConstantTestAssertionRule
from skylos.rules.quality.test_reliability import (
    DuplicateTestAssertionRule,
    SleepSynchronizationRule,
)


def _find(tmp_path, source, rule=ConstantTestAssertionRule):
    source = dedent(source).lstrip()
    path = tmp_path / "test_case.py"
    path.write_text(source, encoding="utf-8")
    return (
        rule().visit_node(
            ast.parse(source),
            {
                "filename": str(path),
                "source": source,
                "project_root": str(tmp_path),
            },
        )
        or []
    )


@pytest.mark.parametrize("jump", ["break", "continue"])
@pytest.mark.parametrize(
    "rule, imports, body",
    [
        (ConstantTestAssertionRule, "", "assert True"),
        (
            DuplicateTestAssertionRule,
            "",
            "count = len(items)\nassert count == 3\nassert count == 3",
        ),
        (
            SleepSynchronizationRule,
            "from threading import Event\nfrom time import sleep\n",
            "complete = Event()\nsleep(0.05)\nassert complete.is_set()",
        ),
    ],
)
def test_unconditional_loop_jumps_exclude_following_review(
    tmp_path, jump, rule, imports, body
):
    body = "\n".join("        " + line for line in body.splitlines())
    source = (
        imports
        + f"def test_case(items):\n    for item in items:\n        {jump}\n"
        + body
    )
    assert not _find(tmp_path, source, rule)


@pytest.mark.parametrize(
    "source",
    [
        "from contextlib import nullcontext\ndef test_case():\n    with nullcontext():\n        return\n    assert True",
        "def test_case():\n    try:\n        return\n    finally:\n        pass\n    assert True",
    ],
)
def test_compound_unconditional_return_excludes_following_review(tmp_path, source):
    assert not _find(tmp_path, source)


@pytest.mark.parametrize(
    "source",
    [
        "def test_case(items, enabled):\n    for item in items:\n        if enabled:\n            break\n        assert True",
        "def test_case(items):\n    for item in items:\n        break\n    assert True",
        "def test_case(items):\n    for item in items:\n        continue\n    assert True",
        "def test_case(items):\n    for item in items:\n        for other in items:\n            break\n        assert True",
        "def test_case():\n    try:\n        return\n    finally:\n        assert True",
        "def test_case(items):\n    for item in items:\n        try:\n            return\n        finally:\n            break\n    assert True",
        "def test_case(items):\n    for item in items:\n        try:\n            continue\n        finally:\n            assert True",
        "def test_case():\n    try:\n        may_raise()\n        return\n    except ValueError:\n        pass\n    assert True",
        "def test_case(manager):\n    with manager:\n        raise ValueError\n    assert True",
        "def test_case(manager):\n    with manager:\n        return may_raise()\n    assert True",
        "def test_case(outer, inner):\n    with outer, inner:\n        return\n    assert True",
        "def test_case(items):\n    for item in items:\n        try:\n            return\n        finally:\n            continue\n    assert True",
    ],
)
def test_reachable_loop_finally_and_suppression_paths_remain_positive(tmp_path, source):
    assert len(_find(tmp_path, source)) == 1


@pytest.mark.parametrize(
    "mutation",
    [
        'test_case.__dict__["__test__"] = False',
        'attributes = test_case.__dict__\nattributes["__test__"] = False',
        'globals().pop("test_case")',
        'vars().pop("test_case")',
        'test_case.__dict__["pytestmark"] = [pytest.mark.skip(reason="disabled")]',
    ],
)
def test_mutated_or_removed_collection_subjects_are_not_reviewed(tmp_path, mutation):
    source = "import pytest\ndef test_case():\n    assert True\n" + mutation
    assert not _find(tmp_path, source)


@pytest.mark.parametrize(
    "mutation",
    [
        'attributes = test_case.__dict__\noriginal = attributes.get("__test__", True)',
        'test_case.__dict__["description"] = "a normal test"',
        'attributes = test_case.__dict__\nattributes["description"] = "a normal test"',
        'globals()["unrelated"] = 3',
        'globals().pop("unrelated", None)',
        'namespace = globals()\nvalue = namespace.get("unrelated")',
        'test_case.__dict__["__test__"] = True',
        "count = len(test_case.__dict__)",
        "has_metadata = bool(test_case.__dict__)",
        'namespace_copy = dict(globals())\nnamespace_copy.pop("test_case")',
    ],
)
def test_readonly_and_unrelated_namespace_operations_keep_tests_visible(
    tmp_path, mutation
):
    source = "def test_case():\n    assert True\n" + mutation
    assert len(_find(tmp_path, source)) == 1


def test_lookalike_globals_does_not_hide_a_test(tmp_path):
    assert (
        len(
            _find(
                tmp_path,
                """
        def globals(): return {}
        def test_case(): assert True
        globals().pop("test_case", None)
    """,
            )
        )
        == 1
    )


def test_namespace_alias_mutation_is_conservative(tmp_path):
    assert not _find(
        tmp_path,
        """
        def test_case(): assert True
        namespace = globals()
        namespace.pop("test_case")
    """,
    )


def test_metadata_optout_affects_only_its_original_subject(tmp_path):
    findings = _find(
        tmp_path,
        """
        def test_hidden(): assert True
        def test_visible(): assert True
        attributes = test_hidden.__dict__
        attributes["__test__"] = False
    """,
    )
    assert [finding["name"] for finding in findings] == ["test_visible"]


def test_test_body_namespace_mutation_does_not_run_before_collection(tmp_path):
    assert (
        len(
            _find(
                tmp_path,
                """
        def test_case():
            globals().pop("test_case")
            assert True
    """,
            )
        )
        == 1
    )


def test_class_local_vars_mutation_does_not_remove_module_test(tmp_path):
    assert (
        len(
            _find(
                tmp_path,
                """
        def test_case(): assert True
        class Unrelated:
            vars().pop("test_case", None)
    """,
            )
        )
        == 1
    )


def test_metadata_update_preserves_inert_keys_and_rejects_optout(tmp_path):
    assert (
        len(
            _find(
                tmp_path,
                """
        def test_case(): assert True
        test_case.__dict__.update(description="normal")
    """,
            )
        )
        == 1
    )
    assert not _find(
        tmp_path,
        """
        def test_case(): assert True
        test_case.__dict__.update({"__test__": False})
    """,
    )


def test_metadata_escape_makes_only_that_subject_uncertain(tmp_path):
    assert not _find(
        tmp_path,
        """
        def test_case(): assert True
        attributes = test_case.__dict__
        configure(attributes)
    """,
    )


@pytest.mark.parametrize(
    "tail",
    [
        'attributes = test_case.__dict__\nattributes = {}\nattributes["__test__"] = False',
        'if False:\n    test_case.__dict__["__test__"] = False',
        'if False:\n    globals().pop("test_case")',
        'namespace = globals()\nclass Other:\n    namespace = vars()\n    namespace.pop("test_case", None)',
    ],
)
def test_unexecuted_or_rebound_metadata_does_not_hide_test(tmp_path, tail):
    assert len(_find(tmp_path, "def test_case(): assert True\n" + tail)) == 1


@pytest.mark.parametrize(
    "mutation",
    [
        'vars(TestChecks.test_hidden)["__test__"] = False',
        'TestChecks.test_hidden.__dict__["__test__"] = False',
        'attributes = TestChecks.test_hidden.__dict__\nattributes["__test__"] = False',
    ],
)
def test_method_metadata_optout_keeps_sibling_test_visible(tmp_path, mutation):
    findings = _find(
        tmp_path,
        "class TestChecks:\n    def test_hidden(self): assert True\n"
        "    def test_visible(self): assert True\n" + mutation,
    )
    assert [finding["name"] for finding in findings] == ["TestChecks.test_visible"]


def test_shadowed_dict_constructor_does_not_prove_a_readonly_copy(tmp_path):
    assert not _find(
        tmp_path,
        """
        def dict(namespace):
            namespace.pop("test_case")
            return {}
        def test_case(): assert True
        copied = dict(globals())
    """,
    )
