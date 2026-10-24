"""Runner discovery needs real TestCase provenance and callable members."""

import pytest

from test.web_framework_fixtures import _scan, _unused


def _marked(result, marker="unittest_discovery"):
    return {
        name
        for name, definition in result.get("definitions", {}).items()
        if any(
            row.get("reason") == marker
            for row in definition.get("dead_code_evidence", [])
        )
    }


@pytest.mark.parametrize(
    "filename", ["tests.py", "test_api.py", "api_test.py", "testcases.py"]
)
@pytest.mark.parametrize(
    "imports,base",
    [
        ("import unittest", "unittest.TestCase"),
        ("import unittest as unit", "unit.TestCase"),
        ("from unittest import TestCase as Base", "Base"),
        ("from unittest.case import TestCase", "TestCase"),
        ("from django.test import TestCase", "TestCase"),
        ("from django.test import SimpleTestCase as Base", "Base"),
        (
            "from django.test.testcases import TransactionTestCase",
            "TransactionTestCase",
        ),
        ("from unittest import IsolatedAsyncioTestCase", "IsolatedAsyncioTestCase"),
    ],
)
def test_discovered_cases_and_actual_test_methods_are_roots(
    tmp_path, filename, imports, base
):
    module = filename[:-3]
    result = _scan(
        tmp_path,
        {
            filename: f"""
        {imports}
        def expected_value():
            return 1
        def retired_value():
            return 0
        class Example({base}):
            def testCamelCase(self):
                assert expected_value() == 1
            def stale_helper(self):
                return retired_value()
        class UnusedHelper:
            def check(self):
                return False
    """
        },
    )

    assert f"{module}.Example" not in _unused(result, "unused_classes")
    assert f"{module}.expected_value" not in _unused(result)
    assert f"{module}.Example" in _marked(result)
    if filename in {"tests.py", "testcases.py"}:
        assert f"{module}.UnusedHelper" in _unused(result, "unused_classes")
        assert f"{module}.Example.stale_helper" in _unused(result)
        assert f"{module}.retired_value" in _unused(result)


@pytest.mark.parametrize(
    "mode", ["fake", "rebound", "mutated", "wrong_file", "replaced_class"]
)
def test_lookalikes_and_replaced_discovery_values_do_not_gain_roots(tmp_path, mode):
    filename = "tests.py"
    prefix = "from unittest import TestCase\n"
    suffix = ""
    if mode == "fake":
        prefix = "class TestCase:\n    pass\n"
    elif mode == "rebound":
        prefix += "TestCase = object\n"
    elif mode == "mutated":
        prefix = "import unittest\nunittest.TestCase = object\nTestCase = unittest.TestCase\n"
    elif mode == "wrong_file":
        filename = "helpers.py"
    elif mode == "replaced_class":
        suffix = "Example = object()\n"
    source = (
        prefix
        + "class Example(TestCase):\n    def testCamelCase(self):\n        return 1\n"
        + suffix
    )
    result = _scan(tmp_path, {filename: source})

    assert f"{filename[:-3]}.Example" in _unused(result, "unused_classes")


@pytest.mark.parametrize("provider", ["unittest", "django"])
def test_source_provider_named_like_a_framework_is_not_the_framework(
    tmp_path, provider
):
    sources = {
        "tests.py": f"from {provider} import TestCase\nclass Example(TestCase):\n    pass\n"
    }
    sources[provider + ".py"] = "class TestCase:\n    pass\n"
    result = _scan(tmp_path, sources)

    assert "tests.Example" in _unused(result, "unused_classes")


def test_imported_source_case_inheritance_preserves_exact_overrides(tmp_path):
    result = _scan(
        tmp_path,
        {
            "base.py": """
            from unittest import TestCase
            def old_helper(): return 0
            class Parent(TestCase):
                def testCamelCase(self): return old_helper()
        """,
            "tests.py": """
            import base
            def active_helper(): return 1
            class Example(base.Parent):
                def testCamelCase(self): return active_helper()
        """,
        },
    )

    assert "tests.Example" not in _unused(result, "unused_classes")
    assert "tests.active_helper" not in _unused(result)
    assert "base.old_helper" in _unused(result)


@pytest.mark.parametrize("binding", ["testCamelCase = None", "testCamelCase = 0"])
def test_overwritten_test_method_body_is_not_a_runner_root(tmp_path, binding):
    result = _scan(
        tmp_path,
        {
            "tests.py": f"""
        from unittest import TestCase
        def retired_helper(): return 1
        class Example(TestCase):
            def testCamelCase(self): return retired_helper()
            {binding}
    """
        },
    )

    assert "tests.Example" not in _unused(result, "unused_classes")
    assert "tests.retired_helper" in _unused(result)


def test_bare_annotation_does_not_replace_a_test_method(tmp_path):
    result = _scan(
        tmp_path,
        {
            "tests.py": """
        from unittest import TestCase
        def active_helper(): return 1
        class Example(TestCase):
            def testCamelCase(self): return active_helper()
            testCamelCase: object
    """
        },
    )

    assert "tests.Example" not in _unused(result, "unused_classes")
    assert "tests.active_helper" not in _unused(result)


def test_inherited_lifecycle_and_run_test_are_roots(tmp_path):
    result = _scan(
        tmp_path,
        {
            "base.py": """
            from unittest import TestCase
            def expected_value(): return 1
            class Parent(TestCase):
                def runTest(self): return expected_value()
        """,
            "tests.py": """
            from base import Parent
            class Example(Parent):
                pass
        """,
        },
    )

    assert "tests.Example" not in _unused(result, "unused_classes")
    assert "base.expected_value" not in _unused(result)


@pytest.mark.parametrize(
    "write",
    [
        "Example.testCamelCase = None",
        "setattr(Example, 'testCamelCase', None)",
        "del Example.testCamelCase",
    ],
)
def test_class_member_replacement_does_not_root_retired_test_body(tmp_path, write):
    result = _scan(
        tmp_path,
        {
            "tests.py": f"""
        from unittest import TestCase
        def retired_helper(): return 1
        class Example(TestCase):
            def testCamelCase(self): return retired_helper()
        {write}
    """
        },
    )

    assert "tests.Example.testCamelCase" not in _marked(result)
    if not write.startswith("setattr"):
        assert "tests.retired_helper" in _unused(result)


@pytest.mark.parametrize(
    "write",
    [
        "unittest.TestCase = object",
        "setattr(unittest, 'TestCase', object)",
        "sys.modules['unittest'] = object()",
    ],
)
def test_provider_reimport_after_mutation_does_not_restore_proof(tmp_path, write):
    result = _scan(
        tmp_path,
        {
            "tests.py": f"""
        import sys
        import unittest
        {write}
        from unittest import TestCase as Base
        class Example(Base):
            def testCamelCase(self): return 1
    """
        },
    )

    assert "tests.Example" not in _marked(result)
    assert "tests.Example" in _unused(result, "unused_classes")


def test_class_local_decorator_binding_is_not_a_builtin(tmp_path):
    result = _scan(
        tmp_path,
        {
            "tests.py": """
        from unittest import TestCase
        def retired_helper(): return 1
        class Example(TestCase):
            classmethod = lambda value: None
            @classmethod
            def testCamelCase(cls): return retired_helper()
    """
        },
    )

    assert "tests.Example.testCamelCase" not in _marked(result)
    assert "tests.retired_helper" in _unused(result)


def test_captured_base_survives_later_provider_rebinding(tmp_path):
    result = _scan(
        tmp_path,
        {
            "tests.py": """
        from unittest import TestCase as Base
        import unittest
        unittest.TestCase = object
        def active_helper(): return 1
        class Example(Base):
            def testCamelCase(self): return active_helper()
    """
        },
    )

    assert "tests.Example" in _marked(result)
    assert "tests.active_helper" not in _unused(result)


@pytest.mark.parametrize(
    "member",
    [
        "@property\n    def testCamelCase(self): return retired_helper()",
        "def setUp(self): return retired_helper()",
    ],
)
def test_noncallable_or_empty_cases_do_not_gain_execution_proof(tmp_path, member):
    source = (
        "from unittest import TestCase\ndef retired_helper(): return 1\nclass Example(TestCase):\n    "
        + member
        + "\n"
    )
    result = _scan(tmp_path, {"tests.py": source})

    assert "tests.Example.testCamelCase" not in _marked(result)
    assert "tests.Example.setUp" not in _marked(result)


def test_source_module_class_replacement_prevents_later_import_proof(tmp_path):
    result = _scan(
        tmp_path,
        {
            "base.py": "from unittest import TestCase\nclass Parent(TestCase):\n    pass\n",
            "tests.py": """
            import base
            base.Parent = object
            from base import Parent
            class Example(Parent):
                def testCamelCase(self): return 1
        """,
        },
    )

    assert "tests.Example" not in _marked(result)


@pytest.mark.parametrize("decorator", ["classmethod", "staticmethod"])
def test_builtin_callable_test_decorators_preserve_execution_proof(tmp_path, decorator):
    result = _scan(
        tmp_path,
        {
            "tests.py": f"""
        from unittest import TestCase
        def expected_value(): return 1
        class Example(TestCase):
            @{decorator}
            def testCamelCase(*args): return expected_value()
    """
        },
    )

    assert "tests.Example.testCamelCase" in _marked(result)
    assert "tests.expected_value" not in _unused(result)


@pytest.mark.parametrize(
    "imports,base,method,expected",
    [
        ("from unittest import TestCase", "TestCase", "asyncSetUp", False),
        ("from unittest import TestCase", "TestCase", "setUpTestData", False),
        (
            "from django.test import SimpleTestCase",
            "SimpleTestCase",
            "setUpTestData",
            False,
        ),
        ("from django.test import TestCase", "TestCase", "setUpTestData", True),
        (
            "from unittest import IsolatedAsyncioTestCase",
            "IsolatedAsyncioTestCase",
            "asyncSetUp",
            True,
        ),
    ],
)
def test_lifecycle_roots_match_the_actual_runner(
    tmp_path, imports, base, method, expected
):
    declaration = "def"
    if method in {"asyncSetUp", "asyncTearDown"}:
        declaration = "async def"
    result = _scan(
        tmp_path,
        {
            "tests.py": f"""
        {imports}
        class Example({base}):
            def testCamelCase(self): return 1
            {declaration} {method}(self): return 2
    """
        },
    )

    assert ("tests.Example." + method in _marked(result)) is expected


@pytest.mark.parametrize(
    "imports,base,expected",
    [
        ("from unittest import TestCase", "TestCase", False),
        (
            "from unittest import IsolatedAsyncioTestCase",
            "IsolatedAsyncioTestCase",
            True,
        ),
        ("from django.test import TestCase", "TestCase", True),
    ],
)
def test_async_test_body_requires_an_awaiting_runner(tmp_path, imports, base, expected):
    result = _scan(
        tmp_path,
        {
            "tests.py": f"""
        {imports}
        class Example({base}):
            async def testCamelCase(self): return 1
    """
        },
    )

    assert ("tests.Example.testCamelCase" in _marked(result)) is expected


@pytest.mark.parametrize("base", ["TestCase", "IsolatedAsyncioTestCase"])
def test_creating_a_generator_test_does_not_execute_its_body(tmp_path, base):
    result = _scan(
        tmp_path,
        {
            "tests.py": f"""
        from unittest import {base}
        class Example({base}):
            def testCamelCase(self):
                yield 1
    """
        },
    )

    assert "tests.Example.testCamelCase" not in _marked(result)


@pytest.mark.parametrize("method,expected", [("setUp", False), ("asyncSetUp", True)])
def test_async_lifecycle_only_awaits_the_documented_hook(tmp_path, method, expected):
    result = _scan(
        tmp_path,
        {
            "tests.py": f"""
        from unittest import IsolatedAsyncioTestCase
        class Example(IsolatedAsyncioTestCase):
            async def testCamelCase(self): return 1
            async def {method}(self): return 2
    """
        },
    )

    assert ("tests.Example." + method in _marked(result)) is expected


@pytest.mark.parametrize("method", ["asyncSetUp", "asyncTearDown"])
def test_async_runner_rejects_sync_async_lifecycle_before_its_body(tmp_path, method):
    result = _scan(
        tmp_path,
        {
            "tests.py": f"""
        from unittest import IsolatedAsyncioTestCase
        class Example(IsolatedAsyncioTestCase):
            async def testCamelCase(self): return 1
            def {method}(self): return 2
    """
        },
    )

    assert "tests.Example." + method not in _marked(result)
