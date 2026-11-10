"""Test-quality checks select proven tests without importing target code."""

import ast
from textwrap import dedent

import pytest

from skylos.rules.quality._test_subjects import scope_nodes, test_subjects


def _subjects(tmp_path, source, filename="tests/test_sample.py", config=None):
    source = dedent(source)
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    if config is not None:
        (tmp_path / "pytest.ini").write_text(config, encoding="utf-8")
    module = ast.parse(source)
    context = {"filename": str(path), "project_root": tmp_path, "source": source}
    return module, context, test_subjects(module, context)


def test_default_selection_preserves_original_nodes_and_shares_cached_result(tmp_path):
    module, context, subjects = _subjects(
        tmp_path,
        """
        def helper(): pass
        def test_first(): assert True
        async def test_second(): pass
        class TestCases:
            def test_method(self): pass
            def helper(self): pass
    """,
    )
    assert [subject.name for subject in subjects] == [
        "test_first",
        "test_second",
        "TestCases.test_method",
    ]
    assert subjects[0].node is module.body[1]
    assert {subject.framework for subject in subjects} == {"pytest"}
    assert test_subjects(module, context) is subjects
    replacement = ast.parse("def test_replacement(): pass")
    assert test_subjects(replacement, context)[0].node is replacement.body[0]


def test_configured_file_function_and_class_names_use_existing_collection(tmp_path):
    _, _, subjects = _subjects(
        tmp_path,
        """
        def test_default(): pass
        def check_top(): pass
        class Checks:
            def check_method(self): pass
        class TestDefault:
            def check_not_collected(self): pass
    """,
        "checks/cases.py",
        """[pytest]
python_files = cases.py
python_functions = check_
python_classes = Checks
testpaths = checks
""",
    )
    assert [subject.name for subject in subjects] == [
        "check_top",
        "Checks.check_method",
    ]


@pytest.mark.parametrize(
    "filename",
    [
        "app/health.py",
        "tests/fixtures/test_sample.py",
        "tests/golden/test_sample.py",
        "tests/data/test_sample.py",
        "corpus/test_sample.py",
        "tests/conftest.py",
    ],
)
def test_helpers_and_golden_sources_are_not_subjects(tmp_path, filename):
    assert _subjects(tmp_path, "def test_named(): pass", filename)[2] == ()


def test_broad_file_glob_does_not_collect_outside_testpaths(tmp_path):
    assert not _subjects(
        tmp_path,
        "def test_named(): pass",
        "app/health.py",
        "[pytest]\npython_files = *.py\ntestpaths = tests\n",
    )[2]


@pytest.mark.parametrize(
    "source",
    [
        "__test__ = False\ndef test_named(): pass",
        "def test_named(): pass\ntest_named.__test__ = False",
        "class TestCases:\n    __test__ = False\n    def test_named(self): pass",
        "def test_named(): pass\ntest_named = object()",
        "class TestCases:\n    def __init__(self): pass\n    def test_named(self): pass",
        "class TestCases(Unknown):\n    def test_named(self): pass",
        "class TestCases:\n    def test_named(self): pass\nTestCases.test_named = replacement",
        "@wrapper\ndef test_named(): pass",
        "import pytest\n@pytest.fixture\ndef test_named(): pass",
        "import pytest as p\np = fake\n@p.mark.parametrize('x', [1])\ndef test_named(x): pass",
    ],
)
def test_optouts_rebindings_and_unknown_collection_are_not_subjects(tmp_path, source):
    assert not _subjects(tmp_path, source)[2]


@pytest.mark.parametrize(
    "source",
    [
        "import pytest as p\n@p.mark.skip(reason='later')\ndef test_named(): pass",
        "from pytest import mark as m\n@m.xfail\ndef test_named(): pass",
        "import pytest\npytestmark = pytest.mark.skipif(False, reason='conditional')\ndef test_named(): pass",
        "import pytest\nclass TestCases:\n    pytestmark = [pytest.mark.xfail]\n    def test_named(self): pass",
        "import pytest\n@pytest.mark.skip\nclass TestCases:\n    def test_named(self): pass",
        "import pytest\ndef test_named():\n    pytest.skip('later')",
        "import pytest\npytest.importorskip('optional')\ndef test_named(): pass",
    ],
)
def test_done_skip_and_xfail_marker_semantics_are_reused(tmp_path, source):
    assert not _subjects(tmp_path, source)[2]


def test_framework_lookalike_body_call_does_not_hide_a_real_test(tmp_path):
    _, _, subjects = _subjects(
        tmp_path,
        """
        class Fake:
            def skip(self): pass
        pytest = Fake()
        def test_named():
            pytest.skip()
            assert True
    """,
    )
    assert [subject.name for subject in subjects] == ["test_named"]


def test_imported_pytest_marks_preserve_collection_and_fixture_backing(tmp_path):
    _, _, subjects = _subjects(
        tmp_path,
        """
        import pytest as p
        @p.mark.parametrize('value', [1])
        def test_plain(value): pass
        @p.mark.usefixtures('assert_state')
        def test_fixture(): pass
    """,
    )
    assert [subject.name for subject in subjects] == ["test_plain", "test_fixture"]
    assert [subject.fixture_backed for subject in subjects] == [False, True]


@pytest.mark.parametrize("scope", ["module", "class"])
def test_inherited_usefixtures_marks_are_recorded(tmp_path, scope):
    source = (
        (
            "import pytest\npytestmark = pytest.mark.usefixtures('verify')\n"
            "def test_named(): pass"
        )
        if scope == "module"
        else (
            "import pytest\nclass TestCases:\n"
            "    pytestmark = pytest.mark.usefixtures('verify')\n"
            "    def test_named(self): pass"
        )
    )
    assert _subjects(tmp_path, source)[2][0].fixture_backed is True


def test_import_proven_unittest_and_local_subclasses_use_test_prefix(tmp_path):
    _, _, subjects = _subjects(
        tmp_path,
        """
        from unittest import TestCase as Case
        class Checks(Case):
            def test_method(self): pass
            def helper(self): pass
        class Child(Checks):
            def test_child(self): pass
    """,
        "checks.py",
    )
    assert [(subject.name, subject.framework) for subject in subjects] == [
        ("Checks.test_method", "unittest"),
        ("Child.test_child", "unittest"),
    ]


@pytest.mark.parametrize(
    "source",
    [
        "class FakeTestCase: pass\nclass Checks(FakeTestCase):\n    def test_named(self): pass",
        "import unittest\nunittest = fake\nclass Checks(unittest.TestCase):\n    def test_named(self): pass",
        "from unittest import TestCase\nclass Checks(TestCase, Unknown):\n    def test_named(self): pass",
        "import unittest\n@unittest.skip('later')\nclass Checks(unittest.TestCase):\n    def test_named(self): pass",
        "import unittest\nclass Checks(unittest.TestCase):\n    @unittest.expectedFailure\n    def test_named(self): pass",
    ],
)
def test_unittest_lookalikes_unknown_mixins_and_skips_are_excluded(tmp_path, source):
    assert not _subjects(tmp_path, source)[2]


def test_dead_nodes_and_scope_traversal_use_existing_ast_ids(tmp_path):
    _, _, subjects = _subjects(
        tmp_path,
        """
        def test_named():
            def helper():
                assert True
            class Nested:
                assert True
            callback = lambda: True
            if False:
                assert True
            return
            assert True
    """,
    )
    subject = subjects[0]
    assertions = [
        node for node in scope_nodes(subject.node) if isinstance(node, ast.Assert)
    ]
    assert len(assertions) == 2
    assert all(id(node) in subject.dead_nodes for node in assertions)
    assert isinstance(subject.dead_nodes, frozenset)
    assert not any(
        isinstance(node, (ast.Lambda, ast.ClassDef))
        for node in scope_nodes(subject.node)
    )


def test_selection_does_not_reparse_source_or_build_done_inventory(
    tmp_path, monkeypatch
):
    module = ast.parse("def test_named(): pass")
    path = tmp_path / "test_sample.py"
    path.write_text("def test_named(): pass", encoding="utf-8")

    def forbidden(*args, **kwargs):
        raise AssertionError("existing AST must be reused")

    monkeypatch.setattr(ast, "parse", forbidden)
    import skylos.done.inventory as inventory

    monkeypatch.setattr(inventory, "collect_tests", forbidden)
    assert test_subjects(module, {"filename": str(path), "project_root": tmp_path})


def test_missing_root_invalid_config_and_outside_path_have_no_proof(tmp_path):
    module = ast.parse("def test_named(): pass")
    assert not test_subjects(module, {"filename": "test_sample.py"})
    assert not _subjects(tmp_path, "def test_named(): pass", config="[pytest\n")[2]
    assert not test_subjects(
        module,
        {
            "filename": str(tmp_path.parent / "test_outside.py"),
            "project_root": tmp_path,
        },
    )


@pytest.mark.parametrize("config", ["[project]\nname='demo'\n", "[tool.skylos]\n"])
def test_unrelated_pyproject_uses_pytest_defaults(tmp_path, config):
    (tmp_path / "pyproject.toml").write_text(config, encoding="utf-8")
    assert _subjects(tmp_path, "def test_named(): pass")[2][0].name == "test_named"


@pytest.mark.parametrize(
    "config",
    [
        "[tool.pytest.ini_options]\npython_files = 5\n",
        "[tool.pytest.ini_options\n",
    ],
)
def test_invalid_pyproject_collection_abstains(tmp_path, config):
    (tmp_path / "pyproject.toml").write_text(config, encoding="utf-8")
    assert not _subjects(tmp_path, "def test_named(): pass")[2]


def test_deferred_skip_calls_do_not_hide_the_containing_test(tmp_path):
    _, _, subjects = _subjects(
        tmp_path,
        """
        import pytest
        def test_named():
            def helper(): pytest.skip('helper only')
            register(lambda: pytest.skip('callback only'))
            assert True
    """,
    )
    assert [subject.name for subject in subjects] == ["test_named"]


def test_local_base_skip_and_fixture_traits_are_inherited(tmp_path):
    _, _, subjects = _subjects(
        tmp_path,
        """
        import pytest
        @pytest.mark.skip
        class SkippedBase:
            pass
        class TestSkipped(SkippedBase):
            def test_named(self): pass
        @pytest.mark.usefixtures('verify')
        class FixtureBase:
            pass
        class TestFixture(FixtureBase):
            def test_named(self): pass
    """,
    )
    assert [subject.name for subject in subjects] == ["TestFixture.test_named"]
    assert subjects[0].fixture_backed


def test_unittest_setup_hook_is_fixture_backed(tmp_path):
    _, _, subjects = _subjects(
        tmp_path,
        """
        import unittest
        class Checks(unittest.TestCase):
            def setUp(self): self.assertTrue(check())
            def test_named(self): pass
    """,
    )
    assert subjects[0].framework == "unittest"
    assert subjects[0].fixture_backed


@pytest.mark.parametrize(
    "autouse, expected", [("True", True), ("flag", True), ("False", False)]
)
def test_module_autouse_fixture_is_recorded(tmp_path, autouse, expected):
    _, _, subjects = _subjects(
        tmp_path,
        f"""
        import pytest
        @pytest.fixture(autouse={autouse})
        def verify_state(): assert check()
        def test_named(): pass
    """,
    )
    assert subjects[0].fixture_backed is expected


def test_non_autouse_fixture_does_not_mark_backing(tmp_path):
    _, _, subjects = _subjects(
        tmp_path,
        """
        import pytest
        @pytest.fixture
        def verify_state(): assert check()
        def test_named(): pass
    """,
    )
    assert not subjects[0].fixture_backed


def test_inherited_setup_hooks_back_placeholder_bodies(tmp_path):
    _, _, subjects = _subjects(
        tmp_path,
        """
        import unittest
        class Base(unittest.TestCase):
            def setUp(self): self.assertTrue(check())
        class Middle(Base): pass
        class Checks(Middle):
            def test_named(self): pass
    """,
    )
    assert subjects[0].fixture_backed


def test_class_autouse_fixture_is_recorded(tmp_path):
    _, _, subjects = _subjects(
        tmp_path,
        """
        import pytest
        class TestCases:
            @pytest.fixture(autouse=True)
            def verify(self): assert check()
            def test_named(self): pass
    """,
    )
    assert subjects[0].fixture_backed


@pytest.mark.parametrize("location", ["conftest.py", "tests/conftest.py"])
def test_possible_ancestor_conftest_checks_back_empty_bodies_without_reading_it(
    tmp_path, location
):
    path = tmp_path / location
    path.parent.mkdir(parents=True, exist_ok=True)
    # Invalid Python is deliberate: selection does not parse this other source.
    path.write_text("assert this is not valid Python!", encoding="utf-8")
    assert _subjects(tmp_path, "def test_named(): pass")[2][0].fixture_backed


def test_sibling_and_outside_conftest_do_not_affect_selected_module(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    (other / "conftest.py").write_text("", encoding="utf-8")
    assert not _subjects(tmp_path, "def test_named(): pass")[2][0].fixture_backed


def test_module_teardown_hooks_back_placeholder_bodies(tmp_path):
    _, _, subjects = _subjects(
        tmp_path,
        """
        def teardown_module(): assert check()
        def test_named(): pass
    """,
    )
    assert subjects[0].fixture_backed


@pytest.mark.parametrize("scope", ["module", "class"])
def test_annotated_pytestmark_skips_are_respected(tmp_path, scope):
    source = (
        "import pytest\npytestmark: object = pytest.mark.skip\ndef test_named(): pass"
        if scope == "module"
        else "import pytest\nclass TestCases:\n    pytestmark: object = pytest.mark.xfail\n"
        "    def test_named(self): pass"
    )
    assert not _subjects(tmp_path, source)[2]


@pytest.mark.parametrize(
    "flag, expected", [("True", False), ("unknown", False), ("False", True)]
)
def test_unittest_explicit_skip_flag_is_respected(tmp_path, flag, expected):
    _, _, subjects = _subjects(
        tmp_path,
        f"""
        import unittest
        class Checks(unittest.TestCase):
            __unittest_skip__ = {flag}
            def test_named(self): pass
    """,
    )
    assert bool(subjects) is expected


def test_parameter_shadowed_skip_call_does_not_hide_test(tmp_path):
    _, _, subjects = _subjects(
        tmp_path,
        """
        import pytest
        def test_named(pytest):
            pytest.skip()
            assert True
    """,
    )
    assert [subject.name for subject in subjects] == ["test_named"]
