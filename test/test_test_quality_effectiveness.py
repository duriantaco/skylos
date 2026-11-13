"""Valid/invalid cases for tests that pass whether or not the project works (SKY-L044..SKY-L047)."""

import ast
import json
import textwrap
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.linter import LinterVisitor
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.catalog import get_rule_catalog
from skylos.rules.docs_anchors import RULE_DOCS_ANCHORS
from skylos.rules.guidance import RULE_FIXES
from skylos.rules.quality.standards import STANDARD_REFS
from skylos.rules.quality.test_assertions import (
    ConstantTestAssertionRule,
    EmptyTestRule,
)
from skylos.rules.quality.test_effectiveness import (
    AlwaysTrueAssertionRule,
    DuplicateTestRule,
    SelfContainedTestRule,
    UncheckedTestResultRule,
)
from skylos.verify_change import verify_change_path

RULES = {
    "SKY-L044": "Test runs no project code",
    "SKY-L045": "Test assertion always true",
    "SKY-L046": "Test result never checked",
    "SKY-L047": "Duplicate test",
}


def run_rule(rule_class, source, tmp_path, filename="test_app.py"):
    text = textwrap.dedent(source)
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text, encoding="utf-8")
    rule = rule_class()
    rule.node_types = (ast.Module,)
    linter = LinterVisitor([rule], str(path))
    linter.context["source"] = text
    linter.context["project_root"] = str(tmp_path)
    linter.visit(ast.parse(text))
    return linter.findings


def reported_lines(rule_class, source, tmp_path, filename="test_app.py"):
    return [
        finding["line"] for finding in run_rule(rule_class, source, tmp_path, filename)
    ]


def cases(table):
    return pytest.mark.parametrize(
        "source, expected",
        [(source, expected) for _label, source, expected in table],
        ids=[label for label, _source, _expected in table],
    )


def valid(table):
    return pytest.mark.parametrize(
        "source",
        [source for _label, source in table],
        ids=[label for label, _source in table],
    )


L044_INVALID = [
    (
        "asserts on its own constant",
        """
        def test_default_model():
            default_model = "gpt-4.1"
            assert default_model == "gpt-4.1"
        """,
        [2],
    ),
    (
        "reimplements the logic it claims to test",
        """
        def test_provider_inferred():
            model = "claude-3"
            if "claude" in model.lower():
                provider = "anthropic"
            else:
                provider = "openai"
            assert provider == "anthropic"
        """,
        [2],
    ),
    (
        "loop over its own literals",
        """
        def test_models():
            models = ["Claude-3", "CLAUDE"]
            for model in models:
                assert "claude" in model.lower(), f"Failed for {model}"
        """,
        [2],
    ),
    (
        "method of a collected class",
        """
        class TestDefaults:
            def test_choices(self):
                valid = ["openai", "anthropic"]
                assert "openai" in valid
        """,
        [3],
    ),
    (
        "builds a string and stops",
        """
        def test_exception_handling():
            code = "try:\\n    risky()\\nexcept ValueError:\\n    pass\\n"
        """,
        [2],
    ),
    (
        "pure builtins over its own values",
        """
        def test_total():
            values = [1, 2, 3]
            total = sum(values)
            assert total == 6
            assert len(values) == 3
        """,
        [2],
    ),
    (
        "comprehension over its own values",
        """
        def test_squares():
            squares = [n * n for n in [1, 2]]
            assert squares == [1, 4]
        """,
        [2],
    ),
    (
        "unittest assertion on its own constants",
        """
        import unittest

        class TestNumbers(unittest.TestCase):
            def test_three(self):
                expected = 3
                self.assertEqual(expected, 3)
        """,
        [5],
    ),
    (
        "async test",
        """
        async def test_flag():
            enabled = not False
            assert enabled is True
        """,
        [2],
    ),
]


L044_VALID = [
    (
        "calls imported code",
        """
        from app import total

        def test_total():
            assert total([1, 2]) == 3
        """,
    ),
    (
        "takes a fixture",
        """
        def test_with_fixture(client):
            expected = 1
            assert expected == 1
        """,
    ),
    (
        "decorated",
        """
        import pytest

        @pytest.mark.usefixtures("database")
        def test_marked():
            expected = 1
            assert expected == 1
        """,
    ),
    (
        "reads a module constant",
        """
        from app import LIMIT

        def test_limit():
            assert LIMIT == 3
        """,
    ),
    (
        "calls a helper in the same file",
        """
        def build():
            from app import make
            return make()

        def test_build():
            value = build()
            assert value == 1
        """,
    ),
    (
        "reads state from self",
        """
        class TestClient:
            def test_status(self):
                assert self.client.status == 200
        """,
    ),
    (
        "custom assertion method on self",
        """
        import unittest

        class TestEmail(unittest.TestCase):
            def test_address(self):
                self.assertValidEmail("a@b.co")
        """,
    ),
    (
        "builtin name rebound by an import",
        """
        from app import sum

        def test_total():
            values = [1, 2]
            assert sum(values) == 3
        """,
    ),
    (
        "builtin name rebound in the file",
        """
        def len(value):
            from app import size
            return size(value)

        def test_size():
            assert len([1]) == 1
        """,
    ),
    (
        "imports inside the test",
        """
        def test_lazy():
            from app import run
            assert run() == 1
        """,
    ),
    (
        "reads the file system",
        """
        def test_reads():
            text = open("pyproject.toml").read()
            assert "ruff" in text
        """,
    ),
    (
        "reads its own path",
        """
        def test_location():
            here = __file__
            assert here.endswith(".py")
        """,
    ),
    (
        "runs code from text",
        """
        def test_eval():
            assert eval("1 + 1") == 2
        """,
    ),
    (
        "always fails on purpose",
        """
        def test_pending():
            raise NotImplementedError
        """,
    ),
    (
        "skips itself",
        """
        import pytest

        def test_later():
            pytest.skip("not ready")
        """,
    ),
    (
        "not a test function",
        """
        def helper():
            value = 1
            assert value == 1

        def test_real():
            from app import run
            assert run()
        """,
    ),
    (
        "test-named method of a helper class",
        """
        class Helper:
            def test_value(self):
                value = 1
                assert value == 1

        def test_real():
            from app import run
            assert run()
        """,
    ),
    (
        "nested function may be handed to project code",
        """
        def test_callback():
            def callback():
                return 1
            assert callback() == 1
        """,
    ),
    (
        "catches a builtin exception",
        """
        def test_int():
            try:
                int("x")
            except ValueError:
                failed = True
            assert failed
        """,
    ),
    (
        "empty body is SKY-L041",
        """
        def test_todo():
            pass
        """,
    ),
    (
        "docstring only is SKY-L041",
        """
        def test_documented():
            \"\"\"Checks the parser.\"\"\"
        """,
    ),
    (
        "literal assertion is SKY-L040",
        """
        def test_placeholder():
            assert True
        """,
    ),
]


L045_INVALID = [
    (
        "parenthesised condition and message",
        """
        from app import run

        def test_tuple():
            result = run()
            assert (result == 3, "should be three")
        """,
        [6],
    ),
    (
        "or True",
        """
        from app import run

        def test_or():
            result = run()
            assert result or True
        """,
        [6],
    ),
    (
        "length is never negative",
        """
        from app import run

        def test_len():
            items = run()
            assert len(items) >= 0
        """,
        [6],
    ),
    (
        "length is never negative, reversed",
        """
        from app import run

        def test_len():
            items = run()
            assert 0 <= len(items)
        """,
        [6],
    ),
    (
        "everything is an object",
        """
        from app import run

        def test_type():
            assert isinstance(run(), object)
        """,
        [5],
    ),
    (
        "identity with itself",
        """
        from app import run

        def test_identity():
            result = run()
            assert result is result
        """,
        [6],
    ),
    (
        "set display is never empty",
        """
        from app import First, Second

        def test_exports():
            assert {First, Second}
        """,
        [5],
    ),
    (
        "unittest assertTrue(True)",
        """
        import unittest
        from app import run

        class TestRun(unittest.TestCase):
            def test_run(self):
                run()
                self.assertTrue(True)
        """,
        [8],
    ),
]


L045_VALID = [
    (
        "real comparison",
        """
        from app import run

        def test_run():
            assert run() == 3
        """,
    ),
    (
        "at least one",
        """
        from app import run

        def test_len():
            assert len(run()) >= 1
        """,
    ),
    (
        "more than none",
        """
        from app import run

        def test_len():
            assert len(run()) > 0
        """,
    ),
    (
        "specific type",
        """
        from app import run

        def test_type():
            assert isinstance(run(), dict)
        """,
    ),
    (
        "equality with itself can fail",
        """
        from app import run

        def test_reflexive():
            result = run()
            assert result == result
        """,
    ),
    (
        "assert False marks an unreachable line",
        """
        from app import run

        def test_unreachable():
            if run():
                return
            assert False, "run() returned nothing"
        """,
    ),
    (
        "literals that differ always fail",
        """
        def test_wrong():
            assert 1 == 2
        """,
    ),
    (
        "len rebound in the file",
        """
        from app import len

        def test_len():
            assert len([1]) >= 0
        """,
    ),
    (
        "or between two values",
        """
        from app import run

        def test_or():
            first, second = run()
            assert first or second
        """,
    ),
    (
        "tuple comparison",
        """
        from app import run

        def test_pair():
            assert run() == (1, 2)
        """,
    ),
    (
        "lists compared, not tested for truth",
        """
        from app import run

        def test_wrapped():
            assert [run()] == [{"a": 1}]
        """,
    ),
    (
        "sets compared, not tested for truth",
        """
        from app import run

        def test_set():
            first, second = run()
            assert {first, second} == {"a", "b"}
        """,
    ),
    (
        "set with one literal member compared",
        """
        from app import run

        def test_member():
            assert {"a"} <= run()
        """,
    ),
    (
        "empty tuple always fails",
        """
        def test_empty():
            assert ()
        """,
    ),
    (
        "name that happens to be truthy",
        """
        from app import run

        def test_name():
            result = run()
            assert result
        """,
    ),
    (
        "unittest assertTrue on a value",
        """
        import unittest
        from app import run

        class TestRun(unittest.TestCase):
            def test_run(self):
                self.assertTrue(run())
        """,
    ),
    (
        "assert True (not this rule)",
        """
        from app import run

        def test_run():
            run()
            assert True
        """,
    ),
    (
        "equal literals (not this rule)",
        """
        def test_one():
            assert 1 == 1
        """,
    ),
    (
        "non-empty string (not this rule)",
        """
        def test_text():
            assert "the parser works"
        """,
    ),
    (
        "not False (not this rule)",
        """
        def test_not():
            assert not False
        """,
    ),
    (
        "helper in a test file (not this rule)",
        """
        from app import run

        def check(result):
            assert len(result) >= 0

        def test_run():
            check(run())
        """,
    ),
    (
        "string literal where a membership test was meant (not this rule)",
        """
        from app import render

        def test_edges():
            result = render()
            assert '"A" -> "B";' in result
            assert '"B" -> "C";'
        """,
    ),
]


L046_INVALID = [
    (
        "result assigned and never read",
        """
        from app import analyze

        def test_unused():
            files = {"a.py": ""}
            unused = analyze(files)
        """,
        [6],
    ),
    (
        "inside a with block",
        """
        from unittest.mock import patch
        from app import run

        def test_patched(tmp_path):
            with patch("app.load"):
                result = run(tmp_path)
        """,
        [7],
    ),
    (
        "tuple of results",
        """
        from app import detect

        def test_detect(tmp_path):
            integrations, graph = detect(tmp_path)
        """,
        [5],
    ),
    (
        "helper method that does not assert",
        """
        from app import analyze

        class TestUnused:
            def _get_unused(self, files):
                return analyze(files)

            def test_cross_package(self):
                files = {"pkg/a.py": ""}
                unused = self._get_unused(files)
        """,
        [10],
    ),
]


L046_VALID = [
    (
        "result is asserted",
        """
        from app import analyze

        def test_used():
            unused = analyze({})
            assert unused == []
        """,
    ),
    (
        "call without keeping the result",
        """
        from app import run_push

        def test_does_not_raise():
            run_push()
        """,
    ),
    (
        "result passed on",
        """
        import pickle
        from app import scan

        def test_picklable():
            result = scan()
            pickle.dumps(result)
        """,
    ),
    (
        "assertion helper by name",
        """
        from app import run
        from helpers import assert_valid

        def test_helper():
            assert_valid(run())
            result = run()
        """,
    ),
    (
        "helper in the same file asserts",
        """
        from app import run

        def check(value):
            assert value == 1

        def test_helper():
            check(run())
            result = run()
        """,
    ),
    (
        "helper method that asserts",
        """
        from app import analyze

        class TestUnused:
            def _run_and_check(self, files):
                result = analyze(files)
                assert result is not None
                return result

            def test_cross_package(self):
                unused = self._run_and_check({})
        """,
    ),
    (
        "expects an exception",
        """
        import pytest
        from app import run

        def test_raises():
            with pytest.raises(ValueError):
                result = run()
        """,
    ),
    (
        "mock assertion",
        """
        from unittest.mock import Mock
        from app import run

        def test_mock():
            sink = Mock()
            sink.assert_not_called()
            result = run(sink)
        """,
    ),
    (
        "stored on self",
        """
        from app import run

        class TestRun:
            def test_store(self):
                self.result = run()
        """,
    ),
    (
        "explicit discard",
        """
        from app import run

        def test_discard():
            _ = run()
        """,
    ),
    (
        "last assignment is not a call",
        """
        from app import LIMIT

        def test_limit():
            limit = LIMIT
        """,
    ),
    (
        "not a test function",
        """
        from app import run

        def build():
            result = run()

        def test_real():
            assert run() == 1
        """,
    ),
    (
        "fails on purpose",
        """
        import pytest
        from app import run

        def test_fail():
            result = run()
            if result:
                pytest.fail("unexpected")
            other = run()
        """,
    ),
]


L047_INVALID = [
    (
        "same body under two names",
        """
        from app import detect

        def test_any_test_file_changed(tmp_path):
            changed = [tmp_path / "a.py"]
            findings = detect(tmp_path, changed)
            assert findings == []

        def test_meaningful_test_file_changed(tmp_path):
            changed = [tmp_path / "a.py"]
            findings = detect(tmp_path, changed)
            assert findings == []
        """,
        [9],
    ),
    (
        "three copies",
        """
        from app import run

        def test_a():
            assert run(1) == 2

        def test_b():
            assert run(1) == 2

        def test_c():
            assert run(1) == 2
        """,
        [7, 10],
    ),
    (
        "methods of one class",
        """
        from app import run

        class TestRun:
            def test_first(self):
                assert run(1) == 2

            def test_second(self):
                assert run(1) == 2
        """,
        [8],
    ),
    (
        "same marker that does not read the test name",
        """
        import pytest
        from app import run

        @pytest.mark.slow
        def test_first_slow():
            assert run(1) == 2

        @pytest.mark.slow
        def test_second_slow():
            assert run(1) == 2
        """,
        [10],
    ),
    (
        "layout and docstring differ only",
        """
        from app import run

        def test_wrapped():
            \"\"\"First.\"\"\"
            assert run(
                1,
            ) == 2

        def test_flat():
            \"\"\"Second.\"\"\"
            assert run(1) == 2
        """,
        [10],
    ),
]


L047_VALID = [
    (
        "different parameter sets",
        """
        import pytest
        from app import run

        @pytest.mark.parametrize("value", [1, 2])
        def test_low(value):
            assert run(value)

        @pytest.mark.parametrize("value", [8, 9])
        def test_high(value):
            assert run(value)
        """,
    ),
    (
        "one literal differs",
        """
        from app import run

        def test_one():
            assert run(1) == 2

        def test_two():
            assert run(2) == 3
        """,
    ),
    (
        "different classes may set up differently",
        """
        from app import run

        class TestSqlite:
            def test_run(self):
                assert run(self.db) == 2

        class TestPostgres:
            def test_other(self):
                assert run(self.db) == 2
        """,
    ),
    (
        "bodies that call nothing",
        """
        def test_a():
            pass

        def test_b():
            pass
        """,
    ),
    (
        "same name replaces the first definition",
        """
        from app import run

        def test_run():
            assert run(1) == 2

        def test_run():
            assert run(1) == 2
        """,
    ),
    (
        "helper with the same body",
        """
        from app import run

        def check():
            assert run(1) == 2

        def test_run():
            assert run(1) == 2
        """,
    ),
    (
        "recorded responses are chosen by the test name",
        """
        import pytest
        from app import run

        @pytest.mark.vcr()
        def test_first_recording():
            assert run(1) == 2

        @pytest.mark.vcr()
        def test_second_recording():
            assert run(1) == 2
        """,
    ),
    (
        "snapshots are chosen by the test name",
        """
        from app import run

        def test_first_snapshot(snapshot):
            assert run(1) == snapshot

        def test_second_snapshot(snapshot):
            assert run(1) == snapshot
        """,
    ),
    (
        "different fixtures",
        """
        from app import run

        def test_sqlite(sqlite):
            assert run(1) == 2

        def test_postgres(postgres):
            assert run(1) == 2
        """,
    ),
]


@cases(L044_INVALID)
def test_l044_reports(tmp_path, source, expected):
    assert reported_lines(SelfContainedTestRule, source, tmp_path) == expected


@valid(L044_VALID)
def test_l044_does_not_report(tmp_path, source):
    assert reported_lines(SelfContainedTestRule, source, tmp_path) == []


@cases(L045_INVALID)
def test_l045_reports(tmp_path, source, expected):
    assert reported_lines(AlwaysTrueAssertionRule, source, tmp_path) == expected


@valid(L045_VALID)
def test_l045_does_not_report(tmp_path, source):
    assert reported_lines(AlwaysTrueAssertionRule, source, tmp_path) == []


@cases(L046_INVALID)
def test_l046_reports(tmp_path, source, expected):
    assert reported_lines(UncheckedTestResultRule, source, tmp_path) == expected


@valid(L046_VALID)
def test_l046_does_not_report(tmp_path, source):
    assert reported_lines(UncheckedTestResultRule, source, tmp_path) == []


@cases(L047_INVALID)
def test_l047_reports(tmp_path, source, expected):
    assert reported_lines(DuplicateTestRule, source, tmp_path) == expected


@valid(L047_VALID)
def test_l047_does_not_report(tmp_path, source):
    assert reported_lines(DuplicateTestRule, source, tmp_path) == []


@pytest.mark.parametrize(
    "rule_class, source",
    [
        (SelfContainedTestRule, L044_INVALID[0][1]),
        (AlwaysTrueAssertionRule, L045_INVALID[0][1]),
        (UncheckedTestResultRule, L046_INVALID[0][1]),
        (DuplicateTestRule, L047_INVALID[0][1]),
    ],
)
def test_production_files_are_not_judged_as_tests(tmp_path, rule_class, source):
    assert reported_lines(rule_class, source, tmp_path, filename="app.py") == []


@pytest.mark.parametrize(
    "existing, source",
    [
        (
            ConstantTestAssertionRule,
            """
            from app import run

            def test_run():
                run()
                assert True
            """,
        ),
        (
            EmptyTestRule,
            """
            def test_todo():
                pass
            """,
        ),
    ],
)
def test_existing_test_rules_keep_their_cases(tmp_path, existing, source):
    assert len(run_rule(existing, source, tmp_path)) == 1
    for rule_class in (SelfContainedTestRule, AlwaysTrueAssertionRule):
        assert reported_lines(rule_class, source, tmp_path) == []


def test_a_test_skipped_by_marker_is_not_judged(tmp_path):
    source = """
    import pytest

    @pytest.mark.skip(reason="later")
    def test_default():
        default_model = "gpt-4.1"
        assert default_model == "gpt-4.1"
    """
    assert reported_lines(SelfContainedTestRule, source, tmp_path) == []


def test_conftest_does_not_hide_a_test_that_asserts_on_its_own_values(tmp_path):
    assert write_text_no_symlink(tmp_path / "conftest.py", "", encoding="utf-8")
    assert reported_lines(SelfContainedTestRule, L044_INVALID[0][1], tmp_path) == [2]


def test_conftest_can_supply_checks_for_a_test_without_assertions(tmp_path):
    assert write_text_no_symlink(tmp_path / "conftest.py", "", encoding="utf-8")
    source = """
    def test_builds_input():
        code = "x = 1"
    """
    assert reported_lines(SelfContainedTestRule, source, tmp_path) == []


def test_l044_says_why(tmp_path):
    finding = run_rule(SelfContainedTestRule, L044_INVALID[0][1], tmp_path)[0]
    assert finding["name"] == "test_default_model"
    assert finding["evidence"]["pattern"] == "asserts_on_own_values"
    assert "runs no code from the project" in finding["message"]


def test_l047_names_the_first_copy(tmp_path):
    finding = run_rule(DuplicateTestRule, L047_INVALID[0][1], tmp_path)[0]
    assert finding["name"] == "test_meaningful_test_file_changed"
    assert finding["evidence"]["duplicate_of"] == "test_any_test_file_changed"
    assert "test_any_test_file_changed" in finding["message"]


def test_catalog_guidance_anchors_and_dictionary_describe_every_rule():
    catalog = {entry["id"]: entry for entry in get_rule_catalog()}
    dictionary = (Path(__file__).resolve().parents[1] / "dictionary.md").read_text(
        encoding="utf-8"
    )
    for rule_id, name in RULES.items():
        entry = catalog[rule_id]
        assert (entry["name"], entry["finding_type"], entry["severity"]) == (
            name,
            "review",
            "LOW",
        )
        assert entry["category"] == "quality"
        assert STANDARD_REFS[rule_id]
        assert RULE_FIXES[rule_id]["default"]
        assert RULE_DOCS_ANCHORS[rule_id].startswith(rule_id.lower())
        assert f"| {rule_id.removeprefix('SKY-')} | LOW | {name} |" in dictionary


SAMPLE = """
from app import analyze, run


def test_default():
    default_model = "gpt-4.1"
    assert default_model == "gpt-4.1"


def test_smoke():
    items = run()
    assert len(items) >= 0


def test_unused():
    unused = analyze({})


def test_first():
    assert run(1) == 2


def test_second():
    assert run(1) == 2


def test_real():
    assert analyze({"a.py": ""}) == ["a.py"]
"""


def _project(tmp_path, *, ignore=()):
    assert write_text_no_symlink(
        tmp_path / "app.py",
        "def analyze(files):\n    return sorted(files)\n\n\n"
        "def run(value=0):\n    return [value + 1]\n",
        encoding="utf-8",
    )
    assert write_text_no_symlink(
        tmp_path / "test_app.py", textwrap.dedent(SAMPLE), encoding="utf-8"
    )
    if ignore:
        rendered = ", ".join(f'"{rule_id}"' for rule_id in ignore)
        assert write_text_no_symlink(
            tmp_path / "pyproject.toml",
            f"[tool.skylos]\nignore = [{rendered}]\n",
            encoding="utf-8",
        )


def _quality(tmp_path, **kwargs):
    _project(tmp_path, **kwargs)
    result = json.loads(
        analyze(str(tmp_path), conf=0, enable_quality=True, grep_verify=False)
    )
    return sorted(
        (finding["rule_id"], finding["line"])
        for finding in result["quality"]
        if finding["rule_id"] in RULES
    )


def test_rules_reach_analyzer_quality_output(tmp_path):
    assert _quality(tmp_path) == [
        ("SKY-L044", 5),
        ("SKY-L045", 12),
        ("SKY-L046", 16),
        ("SKY-L047", 23),
    ]


def test_rules_respect_project_ignore(tmp_path):
    assert _quality(tmp_path, ignore=("SKY-L044", "SKY-L047")) == [
        ("SKY-L045", 12),
        ("SKY-L046", 16),
    ]


def test_verify_reports_the_two_proof_rules_as_ai_code_defects(tmp_path):
    _project(tmp_path)
    response = verify_change_path(
        str(tmp_path),
        behavior_comparison=False,
        include_dependency_hallucinations=False,
    )
    found = sorted(
        (finding["rule_id"], finding["range"]["start_line"])
        for finding in response["findings"]
    )
    assert response["status"] == "fail"
    assert found == [("SKY-L044", 5), ("SKY-L045", 12)]
    assert {finding["vibe_category"] for finding in response["findings"]} == {
        "vacuous_test"
    }


def test_verify_passes_a_test_file_that_checks_the_project(tmp_path):
    assert write_text_no_symlink(
        tmp_path / "app.py",
        "def run(value=0):\n    return value + 1\n",
        encoding="utf-8",
    )
    assert write_text_no_symlink(
        tmp_path / "test_app.py",
        "from app import run\n\n\ndef test_run():\n    assert run(1) == 2\n",
        encoding="utf-8",
    )
    response = verify_change_path(
        str(tmp_path),
        behavior_comparison=False,
        include_dependency_hallucinations=False,
    )
    assert response["status"] == "pass"
    assert response["findings"] == []
