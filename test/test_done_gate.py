"""skylos done: base comparison, test inventory, checks, receipt and command."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from textwrap import dedent

import pytest

from skylos.done import checks as done_checks
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.done.base import DoneError, added_lines_from_diff, open_comparison
from skylos.done.checks import CheckContext, check_gate_tampering, check_secrets
from skylos.done.config import DEFAULT_MODES, DoneConfig, parse_done_config
from skylos.done.engine import CheckOutcome, decide_verdict, run
from skylos.done.inventory import collect_tests, compare_inventories
from skylos.done.receipt import (
    build_receipt,
    load_receipt_for_upload,
    render_markdown,
    render_text,
    validate_receipt,
    write_receipt,
)
from skylos.done.runner import CaseResult, parse_junit, run_tests
from skylos.done.test_config import detect_loosened_test_config

GH_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _write(root: Path, rel: str, text: str) -> None:
    root = root.resolve(strict=True)
    path = root / rel
    path.resolve(strict=False).relative_to(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, dedent(text))


CALC = dedent(
    """\
    def add(a, b):
        return a + b


    def sub(a, b):
        return a - b
"""
)

TESTS = dedent(
    """\
    import pytest

    from app.calc import add, sub


    def test_add():
        assert add(1, 2) == 3


    def test_sub():
        assert sub(3, 1) == 2


    @pytest.mark.parametrize("a,b,out", [(1, 1, 2), (2, 2, 4), (3, 3, 6)])
    def test_add_cases(a, b, out):
        assert add(a, b) == out


    def test_add_negative():
        assert add(-1, -1) == -2
"""
)

PYPROJECT = dedent(
    """\
    [project]
    name = "demo"
    version = "0.1.0"

    [tool.pytest.ini_options]
    addopts = "-q"

    [tool.skylos.done]
    test_budget_seconds = 120
"""
)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, "app/__init__.py", "")
    _write(root, "app/calc.py", CALC)
    _write(root, "tests/test_calc.py", TESTS)
    _write(root, "pyproject.toml", PYPROJECT)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    _git(root, "switch", "-qc", "feature")
    return root


def _commit(root: Path, message: str = "change") -> None:
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", message)


def _ctx(root: Path, base: str | None = "main", **config) -> CheckContext:
    comparison = open_comparison(root, base)
    return CheckContext(comparison, DoneConfig(**config))


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def test_config_defaults_without_a_table():
    config = parse_done_config("[project]\nname = 'x'\n")
    assert not config.configured
    assert config.mode("unknown_imports") == "advise"
    assert {k: config.mode(k) for k in DEFAULT_MODES} == DEFAULT_MODES
    assert config.test_command is None


def test_config_reads_modes_command_and_reports_bad_values():
    config = parse_done_config(
        dedent(
            """
            [tool.skylos.done]
            test_command = "pytest -q -x"
            test_budget_seconds = 5
            protected_paths = ["./ops/", "../escape"]

            [tool.skylos.done.checks]
            secrets = "off"
            tests_pass = "sometimes"
            changed_lines_checked = "advise"
            """
        )
    )
    assert config.configured
    assert config.test_command == ("pytest", "-q", "-x")
    assert config.test_budget_seconds == 10  # clamped to the minimum
    assert config.protected_paths == ("ops/",)
    assert config.mode("secrets") == "off"
    assert config.mode("tests_pass") == "block"
    assert any("test_budget_seconds" in p for p in config.problems)
    assert any("tests_pass" in p for p in config.problems)
    assert any("../escape" in p for p in config.problems)


def test_config_digest_is_stable_and_changes_with_settings():
    a = parse_done_config("[tool.skylos.done]\ntest_command = 'pytest'\n")
    b = parse_done_config("[tool.skylos.done]\ntest_command = 'pytest'\n")
    c = parse_done_config("[tool.skylos.done]\ntest_command = 'pytest -x'\n")
    assert a.digest() == b.digest() != c.digest()
    assert a.digest().startswith("sha256:")


def test_invalid_toml_falls_back_to_defaults_and_says_so():
    config = parse_done_config("[tool.skylos.done\n")
    assert config.problems and not config.configured


# ---------------------------------------------------------------------------
# inventory
# ---------------------------------------------------------------------------


def _tests(path: str, source: str):
    return collect_tests(path, dedent(source))


def test_inventory_collects_pytest_and_unittest_tests():
    items = _tests(
        "tests/test_x.py",
        """
        import unittest

        def test_a(): pass
        def helper(): pass

        class TestGroup:
            def test_b(self): pass
            class TestNested:
                def test_c(self): pass

        class TestWithInit:
            def __init__(self): pass
            def test_ignored(self): pass

        class Legacy(unittest.TestCase):
            def test_d(self): pass
        """,
    )
    assert sorted(t.local_id for t in items) == [
        "Legacy::test_d",
        "TestGroup::TestNested::test_c",
        "TestGroup::test_b",
        "test_a",
    ]
    # Django-style tests.py: only TestCase classes count.
    django = _tests(
        "polls/tests.py",
        """
        from django.test import TestCase
        def test_not_collected(): pass
        class PollTests(TestCase):
            def test_vote(self): pass
        """,
    )
    assert [t.local_id for t in django] == ["PollTests::test_vote"]


def test_inventory_records_skip_markers_everywhere():
    items = {
        t.local_id: t
        for t in _tests(
            "tests/test_x.py",
            """
            import pytest, unittest

            @pytest.mark.skip
            def test_deco(): pass

            def test_body():
                pytest.skip("later")

            def test_importorskip():
                pytest.importorskip("numpy")

            @pytest.mark.xfail(reason="bug")
            def test_xfail(): pass

            @pytest.mark.skipif(True, reason="x")
            class TestSkippedClass:
                def test_inner(self): pass

            class Case(unittest.TestCase):
                def test_skiptest(self):
                    self.skipTest("no")

            def test_clean(): pass
            """,
        )
    }
    assert items["test_deco"].markers == {"skip"}
    assert items["test_body"].markers == {"pytest.skip()"}
    assert items["test_importorskip"].markers == {"pytest.importorskip()"}
    assert items["test_xfail"].markers == {"xfail"}
    assert items["TestSkippedClass::test_inner"].markers == {"skipif"}
    assert items["Case::test_skiptest"].markers == {"self.skipTest()"}
    assert not items["test_clean"].markers


def test_module_level_skip_applies_to_every_test():
    items = _tests(
        "tests/test_x.py",
        """
        import pytest
        pytestmark = pytest.mark.skip(reason="flaky")
        def test_a(): pass
        """,
    )
    assert items[0].markers == {"module skip"}


def test_compare_finds_deleted_skipped_and_thinned_tests():
    base = _tests(
        "tests/test_x.py",
        """
        import pytest
        def test_keep(): assert 1
        def test_gone(): assert compute() == 2
        def test_skip_me(): assert 2
        @pytest.mark.parametrize("v", [1, 2, 3])
        def test_cases(v): assert v
        """,
    )
    head = _tests(
        "tests/test_x.py",
        """
        import pytest
        def test_keep(): assert 1
        @pytest.mark.skip
        def test_skip_me(): assert 2
        @pytest.mark.parametrize("v", [1, 2])
        def test_cases(v): assert v
        def test_brand_new(): pytest.skip("new tests may do anything")
        """,
    )
    diff = compare_inventories(base, head)
    assert [d.test.name for d in diff.deleted] == ["test_gone"]
    assert [(s.test.name, set(s.added)) for s in diff.newly_skipped] == [
        ("test_skip_me", {"skip"})
    ]
    assert [(d.test.name, d.before, d.after) for d in diff.dropped_cases] == [
        ("test_cases", 3, 2)
    ]


def test_compare_ignores_moves_renames_and_renamed_files():
    body = "def test_long():\n    x = build()\n    y = x.run(1, 2, 3)\n    assert y.status == 'ok'\n    assert y.count == 3\n"
    base = collect_tests("tests/test_a.py", body)
    moved = collect_tests("tests/test_b.py", body.replace("test_long", "test_moved"))
    edited = collect_tests(
        "tests/test_a.py",
        body.replace("test_long", "test_long_renamed").replace(
            "count == 3", "count == 4"
        ),
    )
    renamed_file = collect_tests("tests/test_renamed.py", body)
    assert not compare_inventories(base, moved).deleted
    assert not compare_inventories(base, edited).deleted
    assert not compare_inventories(
        base, renamed_file, {"tests/test_a.py": "tests/test_renamed.py"}
    ).deleted


def test_renamed_and_gutted_test_is_still_a_deletion():
    base = collect_tests(
        "tests/test_a.py",
        "def test_real():\n    r = run()\n    assert r.code == 0\n    assert r.out == 'x'\n    assert r.err == ''\n",
    )
    head = collect_tests("tests/test_a.py", "def test_other():\n    assert True\n")
    assert [d.test.name for d in compare_inventories(base, head).deleted] == [
        "test_real"
    ]


def test_assertions_are_counted_where_they_can_run():
    items = _tests(
        "tests/test_x.py",
        """
        import pytest
        def _check_ok(response):
            assert response.ok
        def test_assert(): assert run() == 1
        def test_empty(): pass
        def test_constant(): assert True
        def test_after_return():
            return
            assert run()
        def test_if_false():
            if False:
                assert run()
        def test_helper(): _check_ok(run())
        def test_raises():
            with pytest.raises(ValueError):
                run()
        class TestX:
            def test_trivial(self): self.assertTrue(True)
            def test_real(self): self.assertEqual(run(), 1)
        """,
    )
    assert {t.name: t.assertions for t in items} == {
        "test_assert": 1,
        "test_empty": 0,
        "test_constant": 0,
        "test_after_return": 0,
        "test_if_false": 0,
        "test_helper": 1,
        "test_raises": 1,
        "test_trivial": 0,
        "test_real": 1,
    }


@pytest.mark.parametrize(
    "body",
    [
        "pass",
        "assert True",
        "return\n    assert run() == 1",
        "if False:\n        assert run() == 1",
    ],
)
def test_test_that_stops_asserting_is_gutted(body):
    base = collect_tests("tests/test_a.py", "def test_run():\n    assert run() == 1\n")
    head = collect_tests("tests/test_a.py", f"def test_run():\n    {body}\n")
    diff = compare_inventories(base, head)
    assert not diff.deleted
    assert [(g.test.name, g.before) for g in diff.gutted] == [("test_run", 1)]


def test_python_test_rewritten_in_place_is_paired():
    base = collect_tests(
        "tests/test_a.py",
        "def test_first():\n    assert first() == 1\n"
        "def test_rejects_expired_token():\n"
        "    token = make_token(expired=True)\n"
        "    with pytest.raises(Expired):\n        verify(token)\n"
        "def test_last():\n    assert last() == 3\n",
    )
    head = collect_tests(
        "tests/test_a.py",
        "def test_first():\n    assert first() == 1\n"
        "def test_rejects_expired_tokens_with_reason():\n"
        "    response = client.post('/verify', json={'token': make_token(expired=True)})\n"
        "    assert response.status_code == 401\n"
        "    assert response.json()['reason'] == 'expired'\n"
        "def test_last():\n    assert last() == 3\n",
    )
    diff = compare_inventories(base, head)
    assert not diff.deleted
    assert [(r.before.name, r.after.name) for r in diff.rewritten] == [
        ("test_rejects_expired_token", "test_rejects_expired_tokens_with_reason")
    ]


def test_python_class_renamed_with_an_edited_method_is_not_a_deletion():
    base = collect_tests(
        "tests/test_a.py",
        "class TestParser:\n"
        "    def test_parses(self):\n        assert parse('1') == 1\n"
        "    def test_rejects(self):\n        assert parse('x') is None\n",
    )
    head = collect_tests(
        "tests/test_a.py",
        "class TestStrictParser:\n"
        "    def test_parses(self):\n        assert parse('1', strict=True) == 1\n"
        "    def test_rejects(self):\n        assert parse('x') is None\n",
    )
    assert not compare_inventories(base, head).deleted


PY_PAIR_BASE = (
    "def test_parses_dates():\n"
    "    result = parse('2026-01-02')\n"
    "    assert result.year == 2026\n"
    "def test_formats_dates():\n"
    "    assert format_date(epoch()) == '1970-01-01'\n"
    "def test_keeps_time_zones():\n"
    "    assert zone('UTC') == 'UTC'\n"
)
PY_PARSES = (
    "def test_parses_dates():\n"
    "    result = parse('2026-01-02')\n"
    "    assert result.year == 2026\n"
)


@pytest.mark.parametrize("in_place", [False, True])
def test_python_renamed_copy_of_a_surviving_test_never_replaces_a_deleted_one(
    in_place,
):
    copy = (
        "def test_parses_date_strings():\n"
        "    assert format_date(epoch()) == '1970-01-01'\n"
    )
    head = (
        PY_PAIR_BASE.replace(PY_PARSES, copy)
        if in_place
        else PY_PAIR_BASE.replace(PY_PARSES, "") + copy
    )
    diff = compare_inventories(
        collect_tests("tests/test_a.py", PY_PAIR_BASE),
        collect_tests("tests/test_a.py", head),
    )
    assert [d.test.name for d in diff.deleted] == ["test_parses_dates"]


def test_python_renamed_and_edited_needs_a_similar_title_and_is_reported():
    edited = "    result = parse('2026-01-03')\n    assert result.year == 2026\n"
    base = collect_tests("tests/test_a.py", PY_PAIR_BASE)
    unrelated = PY_PAIR_BASE.replace(PY_PARSES, "") + (
        "def test_handles_leap_years():\n" + edited
    )
    assert [
        d.test.name
        for d in compare_inventories(
            base, collect_tests("tests/test_a.py", unrelated)
        ).deleted
    ] == ["test_parses_dates"]
    renamed = PY_PAIR_BASE.replace(PY_PARSES, "") + (
        "def test_parses_dates_in_utc():\n" + edited
    )
    diff = compare_inventories(base, collect_tests("tests/test_a.py", renamed))
    assert not diff.deleted
    assert [(r.before.name, r.after.name, r.how) for r in diff.rewritten] == [
        ("test_parses_dates", "test_parses_dates_in_utc", "renamed")
    ]


def test_python_assertions_that_cannot_fail_or_never_run_are_not_counted():
    items = _tests(
        "tests/test_x.py",
        """
        from contextlib import suppress
        def check_result(r):
            return r
        def check_ok(r):
            assert r.ok
        def verify_present(r):
            if not r:
                raise ValueError("missing")
        def test_real(): assert run() == 1
        def test_self_compare():
            r = run()
            assert r == r
        def test_constant(): assert 1 == 1
        def test_constant_false_condition():
            if 1 > 2:
                assert run() == 1
        def test_tuple(): assert (run(), "message")
        def test_noop_helper(): check_result(run())
        def test_asserting_helper(): check_ok(run())
        def test_raising_helper(): verify_present(run())
        def test_imported_helper(): check_something(run())
        def test_raises_assertion_error():
            if run() != 1:
                raise AssertionError("bad")
        def test_swallowed():
            try:
                assert run() == 1
            except AssertionError:
                pass
        def test_swallowed_by_exception():
            try:
                assert run() == 1
            except Exception as error:
                print(error)
        def test_suppressed():
            with suppress(AssertionError):
                assert run() == 1
        def test_other_exception():
            try:
                assert run() == 1
            except ValueError:
                pass
        def test_reraised():
            try:
                assert run() == 1
            except Exception:
                cleanup()
                raise
        def test_uncalled_nested():
            def check():
                assert run() == 1
        def test_called_nested():
            def check():
                assert run() == 1
            check()
        def test_after_if_true_return():
            if True:
                return
            assert run() == 1
        def test_after_guarded_return():
            if not ready():
                return
            assert run() == 1
        class TestX:
            def test_equal_to_itself(self):
                x = run()
                self.assertEqual(x, x)
            def test_true_whatever(self):
                self.assertTrue(run() == run() or True)
        """,
    )
    assert {t.name: t.assertions for t in items} == {
        "test_real": 1,
        "test_self_compare": 0,
        "test_constant": 0,
        "test_constant_false_condition": 0,
        "test_tuple": 0,
        "test_noop_helper": 0,
        "test_asserting_helper": 1,
        "test_raising_helper": 1,
        "test_imported_helper": 1,
        "test_raises_assertion_error": 1,
        "test_swallowed": 0,
        "test_swallowed_by_exception": 0,
        "test_suppressed": 0,
        "test_other_exception": 1,
        "test_reraised": 1,
        "test_uncalled_nested": 0,
        "test_called_nested": 2,  # the call to an asserting helper, and its assert
        "test_after_if_true_return": 0,
        "test_after_guarded_return": 1,
        "test_equal_to_itself": 0,
        "test_true_whatever": 0,
    }
    assert {t.name for t in items if t.early_returns} == {
        "test_after_if_true_return",
        "test_after_guarded_return",
    }


def test_python_fewer_assertions_and_early_returns_are_reported(repo: Path):
    _write(
        repo,
        "tests/test_calc.py",
        TESTS.replace(
            "    assert add(1, 2) == 3\n",
            "    if os.environ.get('CI'):\n        return\n    assert add(1, 2) == 3\n",
        ).replace("import pytest", "import os\nimport pytest"),
    )
    result = done_checks.check_test_tampering(_ctx(repo))
    assert result.status == "pass"
    assert [f.message for f in result.findings if f.rule == "SKY-A110"] == [
        "(advice) test_add gained a return before some of its assertions; check "
        "that they still run"
    ]
    base = collect_tests(
        "tests/test_a.py",
        "def test_run():\n    r = run()\n    assert r.code == 0\n    assert r.out == 'x'\n",
    )
    head = collect_tests(
        "tests/test_a.py", "def test_run():\n    r = run()\n    assert r.code == 0\n"
    )
    assert [
        (f.test.name, f.before, f.after)
        for f in compare_inventories(base, head).fewer_assertions
    ] == [("test_run", 2, 1)]


# ---------------------------------------------------------------------------
# base comparison
# ---------------------------------------------------------------------------


def test_comparison_covers_committed_uncommitted_and_untracked(repo: Path):
    _write(repo, "app/calc.py", CALC + "\n\ndef mul(a, b):\n    return a * b\n")
    _commit(repo)
    _write(repo, "app/new.py", "VALUE = 1\n")
    _write(repo, "tests/test_calc.py", TESTS + "\n# touched\n")
    _write(repo, ".skylos/receipts/latest.json", "{}")  # Skylos's own output
    comparison = open_comparison(repo, "main")
    changed = {c.path: c.status for c in comparison.changed}
    assert changed == {
        "app/calc.py": "modified",
        "app/new.py": "added",
        "tests/test_calc.py": "modified",
    }
    assert comparison.base_source == "merge_base"
    assert comparison.head_dirty
    new_file = next(c for c in comparison.changed if c.path == "app/new.py")
    assert comparison.added_lines(new_file) == {1}
    calc = next(c for c in comparison.changed if c.path == "app/calc.py")
    assert comparison.added_lines(calc) == {7, 8, 9, 10}
    assert comparison.base_text("app/new.py") is None


def test_comparison_errors_are_plain(repo: Path, tmp_path: Path):
    with pytest.raises(DoneError, match="cannot find base"):
        open_comparison(repo, "origin/nope")
    with pytest.raises(DoneError, match="invalid base"):
        open_comparison(repo, "--output=/tmp/x")
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(DoneError):
        open_comparison(plain)


def test_added_lines_from_diff_handles_new_and_deleted_files():
    diff = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,3 @@\n x\n+y\n z\n"
        "diff --git a/b.py b/b.py\n--- a/b.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n"
    )
    assert added_lines_from_diff(diff) == {"a.py": {2}}


# ---------------------------------------------------------------------------
# test settings (A112)
# ---------------------------------------------------------------------------


def test_binary_attributes_cannot_hide_added_secrets_from_session_diff(repo: Path):
    from skylos.done.session import capture_session, open_session_comparison

    _write(repo, ".gitattributes", "*.py -diff\n")
    _commit(repo, "trusted binary attribute fixture")
    capture_session(repo, "binary-source")
    _write(repo, "app/calc.py", CALC + f'\nTOKEN = "{GH_TOKEN}"\n')
    comparison = open_session_comparison(repo, "binary-source")
    changed = next(item for item in comparison.changed if item.path == "app/calc.py")
    assert comparison.added_lines(changed)
    result = check_secrets(CheckContext(comparison, DoneConfig(), run_tests=False))
    assert result.status == "fail"
    assert any(finding.file == "app/calc.py" for finding in result.findings)


def test_loosened_pytest_options_are_found(repo: Path):
    _write(
        repo,
        "pyproject.toml",
        PYPROJECT.replace(
            'addopts = "-q"',
            "addopts = \"-q -k 'not sub' -p no:cacheprovider -p no:warnings\"\n"
            'norecursedirs = [".*", "build", "tests/slow"]\n'
            "xfail_strict = false",
        ),
    )
    messages = [
        f.message for f in detect_loosened_test_config(open_comparison(repo, "main"))
    ]
    assert any("-k" in m and "not sub" in m for m in messages)
    assert any("'warnings'" in m for m in messages)
    assert not any("cacheprovider" in m for m in messages)
    assert any("'tests/slow'" in m for m in messages)
    assert not any("'build'" in m for m in messages)


def test_conftest_hooks_and_collect_ignore_are_found(repo: Path):
    _write(
        repo,
        "tests/conftest.py",
        """
        collect_ignore = ["test_calc.py"]
        pytest_plugins = ["pytest_asyncio", "tests.plugin"]

        def pytest_runtest_makereport(item, call):
            pass

        def pytest_configure(config):
            pass
        """,
    )
    _write(repo, "tests/plugin.py", "")
    messages = [
        f.message for f in detect_loosened_test_config(open_comparison(repo, "main"))
    ]
    assert any("pytest_runtest_makereport" in m for m in messages)
    assert not any("pytest_configure" in m for m in messages)
    assert any("'test_calc.py'" in m and "collect_ignore" in m for m in messages)
    assert any("'tests.plugin'" in m for m in messages)
    assert not any("pytest_asyncio" in m for m in messages)


def test_coverage_floor_and_ci_test_steps_are_found(repo: Path):
    _write(repo, ".coveragerc", "[report]\nfail_under = 90\n")
    _write(
        repo,
        ".github/workflows/ci.yml",
        """
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: pytest -q
              - run: rm -rf build || true
        """,
    )
    _commit(repo, "ci")
    _git(repo, "branch", "-f", "main", "HEAD")
    _write(
        repo, ".coveragerc", "[report]\nfail_under = 60\n[run]\nomit = app/calc.py\n"
    )
    _write(
        repo,
        ".github/workflows/ci.yml",
        """
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: pytest -q || true
              - run: rm -rf build || true
        """,
    )
    messages = [
        f.message for f in detect_loosened_test_config(open_comparison(repo, "main"))
    ]
    assert any("fail_under 90 lowered to 60" in m for m in messages)
    assert any("omits 'app/calc.py'" in m for m in messages)
    ci = [m for m in messages if m.startswith("CI test")]
    assert len(ci) == 1 and "pytest -q" in ci[0]


# ---------------------------------------------------------------------------
# gate tampering, secrets
# ---------------------------------------------------------------------------


def test_gate_tampering_covers_protected_paths_settings_and_workflow(repo: Path):
    _write(
        repo,
        ".github/workflows/done.yml",
        "jobs: {done: {steps: [{run: skylos done}]}}\n",
    )
    _commit(repo, "workflow")
    _git(repo, "branch", "-f", "main", "HEAD")
    _write(repo, ".claude/settings.json", "{}")
    _write(repo, "pyproject.toml", PYPROJECT.replace("120", "60"))
    _write(
        repo, ".github/workflows/done.yml", "jobs: {done: {steps: [{run: echo ok}]}}\n"
    )
    _write(repo, ".skylos/receipts/latest.json", "{}")  # not tampering
    result = check_gate_tampering(_ctx(repo))
    assert result.status == "fail"
    files = sorted(f.file for f in result.findings)
    assert files == [
        ".claude/settings.json",
        ".github/workflows/done.yml",
        "pyproject.toml",
    ]


def test_secrets_only_count_added_lines_and_ignore_doc_examples(repo: Path):
    _write(repo, "app/settings.py", f'OLD = "{GH_TOKEN}"\n')
    _commit(repo, "old secret")
    _git(repo, "branch", "-f", "main", "HEAD")
    _write(
        repo,
        "app/settings.py",
        f'OLD = "{GH_TOKEN}"\n'
        'AWS = "AKIAIOSFODNN7EXAMPLE"\n'
        f'NEW = "{GH_TOKEN[:-1]}X"  # skylos: ignore[SKY-S101]\n',
    )
    result = check_secrets(_ctx(repo))
    assert result.status == "fail"
    assert [(f.line, "does not count" in f.message) for f in result.findings] == [
        (3, True)
    ]
    assert GH_TOKEN[4:] not in json.dumps([f.message for f in result.findings])


# ---------------------------------------------------------------------------
# runner (A113)
# ---------------------------------------------------------------------------


def test_parse_junit_refuses_doctype_and_maps_node_ids(tmp_path: Path):
    bad = tmp_path / "bad.xml"
    bad.write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><testsuite/>')
    assert parse_junit(bad, tmp_path) is None
    good = tmp_path / "good.xml"
    good.write_text(
        "<testsuites><testsuite>"
        '<testcase classname="tests.test_x.TestA" name="test_b[1]" file="tests/test_x.py" line="4">'
        '<failure message="boom"/></testcase>'
        '<testcase classname="tests.test_x" name="test_c" file="tests/test_x.py" line="9"/>'
        "</testsuite></testsuites>"
    )
    cases = parse_junit(good, tmp_path)
    assert [(c.node_id, c.outcome, c.line) for c in cases] == [
        ("tests/test_x.py::TestA::test_b[1]", "failed", 5),
        ("tests/test_x.py::test_c", "passed", 10),
    ]
    assert CaseResult(
        "t/test_x.py", "x.y.test_x.TestA", "n", None, "passed"
    ).classes == ("TestA",)


def test_runner_times_out_as_unfinished(repo: Path):
    config = DoneConfig(
        test_command=(sys.executable, "-c", "import time; time.sleep(30)")
    )
    result = run_tests(
        open_comparison(repo, "main"),
        config,
        changed_tests=[],
        deadline=time.monotonic() + 1,
    )
    assert result.status == "incomplete"
    assert "ran out of time" in result.reason


def test_runner_without_junit_uses_exit_code(repo: Path):
    comparison = open_comparison(repo, "main")
    ok = run_tests(
        comparison,
        DoneConfig(test_command=(sys.executable, "-c", "pass")),
        changed_tests=[],
    )
    bad = run_tests(
        comparison,
        DoneConfig(test_command=(sys.executable, "-c", "raise SystemExit(3)")),
        changed_tests=[],
    )
    missing = run_tests(
        comparison,
        DoneConfig(test_command=("no-such-test-runner-xyz",)),
        changed_tests=[],
    )
    assert (ok.status, bad.status, missing.status) == ("pass", "fail", "incomplete")


def test_runner_strips_pytest_addopts_from_the_environment(repo: Path, monkeypatch):
    monkeypatch.setenv("PYTEST_ADDOPTS", "-k test_add")
    _write(repo, "app/calc.py", CALC.replace("return a - b", "return a + b"))
    result = run(repo, base_ref="main")
    tests = next(c for c in result.checks if c.result.id == "tests_pass").result
    assert tests.status == "fail"
    assert any("test_sub" in f.message for f in tests.findings)


# ---------------------------------------------------------------------------
# engine, receipt, command
# ---------------------------------------------------------------------------


def test_clean_change_passes_with_a_valid_receipt(repo: Path):
    _write(repo, "app/calc.py", CALC + "\n\ndef mul(a, b):\n    return a * b\n")
    _write(
        repo,
        "tests/test_mul.py",
        "from app.calc import mul\n\ndef test_mul():\n    assert mul(2, 3) == 6\n",
    )
    _commit(repo)
    result = run(repo, base_ref="main")
    assert result.verdict == "pass", [
        (c.result.id, c.result.status, c.result.summary) for c in result.checks
    ]
    receipt = build_receipt(result, agent_client="claude-code")
    assert validate_receipt(receipt) == []
    tests = next(c for c in receipt["checks"] if c["id"] == "tests_pass")
    assert tests["evidence"]["run"] == 7 and tests["evidence"]["failed"] == 0
    assert "Verdict: PASS" in render_text(receipt)
    assert "| PASS |" in render_markdown(receipt)


def test_tampering_change_fails_every_relevant_check(repo: Path):
    _write(repo, "app/calc.py", CALC.replace("return a - b", "return a + b"))
    _write(
        repo,
        "tests/test_calc.py",
        TESTS.replace("(3, 3, 6)", "").replace(
            "def test_add_negative():\n    assert add(-1, -1) == -2\n", ""
        ),
    )
    _write(
        repo,
        "tests/conftest.py",
        "def pytest_collection_modifyitems(config, items):\n"
        "    items[:] = [i for i in items if 'sub' not in i.name]\n",
    )
    _write(repo, "app/settings.py", f'TOKEN = "{GH_TOKEN}"\n')
    _commit(repo)
    result = run(repo, base_ref="main")
    by_id = {c.result.id: c.result for c in result.checks}
    assert result.verdict == "fail"
    # Known tampering blocks before expensive execution. Exercise the runner
    # independently so missing-test detection remains covered as well.
    assert by_id["tests_pass"].status == "incomplete"
    assert "earlier required check" in by_id["tests_pass"].summary
    tests = done_checks.check_tests_pass(_ctx(repo))
    assert tests.status == "incomplete"  # conftest dropped test_sub
    assert any("test_sub did not run" in f.message for f in tests.findings)
    rules = {f.rule for f in by_id["test_tampering"].findings if f.blocking}
    assert rules == {"SKY-A110", "SKY-A112"}
    assert by_id["secrets"].status == "fail"
    assert validate_receipt(build_receipt(result)) == []


def test_settings_come_from_the_base_not_the_change(repo: Path):
    _write(
        repo,
        "pyproject.toml",
        PYPROJECT
        + "\n[tool.skylos.done.checks]\nsecrets = 'off'\ntests_pass = 'off'\n",
    )
    _write(repo, "app/settings.py", f'TOKEN = "{GH_TOKEN}"\n')
    _commit(repo)
    result = run(repo, base_ref="main", run_tests=False)
    by_id = {c.result.id: c for c in result.checks}
    assert by_id["secrets"].mode == "block" and by_id["secrets"].result.status == "fail"
    assert by_id["gate_tampering"].result.status == "fail"


def test_advise_and_shadow_checks_never_decide_the_verdict():
    def outcome(mode, status):
        return CheckOutcome(mode, done_checks.CheckResult("x", None, status, ""))

    assert (
        decide_verdict([outcome("advise", "fail"), outcome("shadow", "fail")]) == "pass"
    )
    assert (
        decide_verdict([outcome("block", "incomplete"), outcome("advise", "fail")])
        == "incomplete"
    )
    assert (
        decide_verdict([outcome("block", "fail"), outcome("block", "incomplete")])
        == "fail"
    )


def test_unknown_imports_undeclared_is_advice_and_unreachable_is_unfinished(
    repo: Path, monkeypatch
):
    import skylos.rules.ai_defect.diff_dependencies as diff_dependencies

    def fake(diff_text, repo_root, **_):
        return {
            "findings": [
                {
                    "rule_id": "SKY-D222",
                    "file": "app/x.py",
                    "line": 1,
                    "message": "Hallucinated dependency 'fakepkg'.",
                },
                {
                    "rule_id": "SKY-D223",
                    "file": "app/x.py",
                    "line": 2,
                    "message": "Unverified import 'thing'.",
                },
            ],
            "registry_unreachable": False,
        }

    monkeypatch.setattr(diff_dependencies, "scan_diff_dependency_hallucinations", fake)
    result = done_checks.check_unknown_imports(_ctx(repo))
    assert result.status == "fail"
    assert [f.blocking for f in result.findings] == [True, False]

    monkeypatch.setattr(
        diff_dependencies,
        "scan_diff_dependency_hallucinations",
        lambda *a, **k: {"findings": [], "registry_unreachable": True},
    )
    assert done_checks.check_unknown_imports(_ctx(repo)).status == "incomplete"


def test_a_crashing_check_is_unfinished_not_passed(repo: Path, monkeypatch):
    def boom(ctx):
        raise RuntimeError("bug")

    monkeypatch.setitem(done_checks.CHECKS, "secrets", (boom, "SKY-S101"))
    result = done_checks.run_check("secrets", _ctx(repo))
    assert result.status == "incomplete"


def test_receipt_validation_matches_cloud_limits(repo: Path):
    receipt = build_receipt(run(repo, base_ref="main", run_tests=False))
    assert validate_receipt(receipt) == []
    broken = json.loads(json.dumps(receipt))
    broken["checks"][0]["findings"] = [
        {"rule": None, "file": "/abs/path", "line": 1, "message": "x"}
    ]
    broken["checks"][1]["evidence"] = {"Bad-Key": 1}
    broken["agent"]["client"] = "Claude Code"
    problems = validate_receipt(broken)
    assert any("finding" in p for p in problems)
    assert any("evidence" in p for p in problems)
    assert any("agent" in p for p in problems)


def test_receipt_sanitizes_messages_and_paths(repo: Path):
    result = run(repo, base_ref="main", run_tests=False)
    result.checks[0].result.findings = [
        done_checks.Finding("SKY-A113", "../escape.py", 0, "line\nbreak " + "x" * 400),
    ]
    finding = build_receipt(result)["checks"][0]["findings"][0]
    assert finding["file"] is None and finding["line"] is None
    assert "\n" not in finding["message"] and len(finding["message"]) == 300


def test_receipt_written_ignored_and_checked_before_upload(repo: Path):
    result = run(repo, base_ref="main", run_tests=False)
    receipt = build_receipt(result)
    path = write_receipt(repo, receipt)
    assert path is not None and (repo / ".skylos/receipts/latest.json").is_file()
    assert _git(repo, "status", "--porcelain") == ""  # receipts ignore themselves
    loaded, error = load_receipt_for_upload(path, repo)
    assert error is None and loaded == receipt

    _write(repo, "app/new.py", "X = 1\n")
    _commit(repo)
    _, error = load_receipt_for_upload(path, repo)
    assert error and "not HEAD" in error


def test_done_command_exit_codes_and_json(repo: Path, capsys):
    from skylos.commands.done_cmd import run_done_command

    assert (
        run_done_command(
            [str(repo), "--base", "main", "--no-tests", "--format", "json"]
        )
        == 1
    )
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["verdict"] == "incomplete"
    assert (
        next(c for c in receipt["checks"] if c["id"] == "tests_pass")["status"]
        == "incomplete"
    )

    _write(repo, "app/settings.py", f'TOKEN = "{GH_TOKEN}"\n')
    assert (
        run_done_command(
            [str(repo), "--base", "main", "--no-tests", "--format", "json"]
        )
        == 1
    )
    capsys.readouterr()
    assert run_done_command([str(repo), "--base", "nope"]) == 2


def test_done_command_writes_the_github_step_summary(
    repo: Path, tmp_path: Path, monkeypatch, capsys
):
    from skylos.commands.done_cmd import run_done_command

    summary = tmp_path / "summary.md"
    summary.write_text("")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.delenv("RUNNER_TEMP", raising=False)
    run_done_command([str(repo), "--base", "main", "--no-tests"])
    capsys.readouterr()
    assert "Skylos done" in summary.read_text()


def test_upload_metadata_carries_only_a_valid_receipt(repo: Path):
    from skylos.api import _build_report_metadata, _done_receipt_for_upload

    receipt = build_receipt(run(repo, base_ref="main", run_tests=False))
    assert _done_receipt_for_upload({"done_receipt": receipt}) == receipt
    assert _done_receipt_for_upload({"done_receipt": {"schema": "other"}}) is None
    metadata = _build_report_metadata(
        commit_hash="abc",
        branch="main",
        actor=None,
        is_forced=False,
        ci=False,
        analysis_mode="full",
        ai_code=None,
        provenance_data=None,
        done_receipt=receipt,
    )
    assert metadata["done_receipt"] == receipt


def test_done_is_a_registered_documented_command():
    from skylos.cli_core.dispatch import EARLY_COMMAND_HANDLERS
    from skylos.rules.catalog import get_rule_name

    assert EARLY_COMMAND_HANDLERS["done"] == "_run_done_command"
    assert get_rule_name("SKY-A110") == "Test deleted"
    dictionary = (Path(__file__).resolve().parents[1] / "dictionary.md").read_text()
    for rule in ("A110", "A111", "A112", "A113", "A114"):
        assert f"| {rule} |" in dictionary


def test_tests_the_base_config_deselects_are_not_missing(repo: Path):
    _write(
        repo,
        "pyproject.toml",
        PYPROJECT.replace(
            'addopts = "-q"',
            'addopts = "-q -m \'not slow\'"\nmarkers = ["slow: slow tests"]',
        ),
    )
    _commit(repo, "deselect slow tests")
    _git(repo, "branch", "-f", "main", "HEAD")
    _write(
        repo,
        "tests/test_calc.py",
        TESTS
        + "\n\n@pytest.mark.slow\ndef test_big():\n    assert add(10**6, 1) == 10**6 + 1\n",
    )
    result = run(repo, base_ref="main")
    tests = next(c for c in result.checks if c.result.id == "tests_pass").result
    assert tests.status == "pass", tests.summary
    assert not [f for f in tests.findings if f.blocking]


def test_import_shaped_text_in_strings_is_not_an_import(repo: Path, monkeypatch):
    import skylos.rules.ai_defect.diff_dependencies as diff_dependencies

    _write(
        repo, "app/fixture.py", 'SOURCE = """\nimport fakepkg\n"""\nimport realpkg\n'
    )
    monkeypatch.setattr(
        diff_dependencies,
        "scan_diff_dependency_hallucinations",
        lambda *a, **k: {
            "findings": [
                {
                    "rule_id": "SKY-D222",
                    "file": "app/fixture.py",
                    "line": 2,
                    "message": "fakepkg",
                },
                {
                    "rule_id": "SKY-D222",
                    "file": "app/fixture.py",
                    "line": 4,
                    "message": "realpkg",
                },
            ],
            "registry_unreachable": False,
        },
    )
    result = done_checks.check_unknown_imports(_ctx(repo))
    assert [f.line for f in result.findings] == [4]


def test_assertion_advice_skips_tests_written_in_the_change(repo: Path):
    _write(
        repo,
        "tests/test_calc.py",
        TESTS.replace("assert add(1, 2) == 3", "assert add(1, 2)")
        + "\n\ndef test_env_only():\n    pytest.skip('needs network')\n",
    )
    result = done_checks.check_test_tampering(_ctx(repo))
    advice = [f for f in result.findings if f.rule == "SKY-A101"]
    assert advice and all(f.line < 20 for f in advice)  # only the edited old test


@pytest.mark.skipif(not hasattr(__import__("os"), "mkfifo"), reason="needs FIFOs")
def test_a_fifo_in_place_of_test_results_cannot_stall_the_gate(repo: Path):
    script = "import os; os.mkfifo('report.xml')"
    config = DoneConfig(
        test_command=(sys.executable, "-c", script), junit_xml="report.xml"
    )
    started = time.monotonic()
    result = run_tests(open_comparison(repo, "main"), config, changed_tests=[])
    assert time.monotonic() - started < 30
    assert result.status == "incomplete"


def _make_current_base(repo: Path) -> None:
    _commit(repo, "trusted base")
    _git(repo, "branch", "-f", "main", "HEAD")


def test_required_test_check_cannot_pass_when_tests_are_not_run(repo: Path):
    _write(repo, "app/calc.py", CALC.replace("return a - b", "return a + b"))
    result = run(repo, base_ref="main", run_tests=False)
    tests = next(c for c in result.checks if c.result.id == "tests_pass")
    assert result.verdict == "incomplete"
    assert tests.blocking and tests.result.status == "incomplete"
    assert (
        decide_verdict(
            [
                CheckOutcome(
                    "block", done_checks.CheckResult("tests_pass", None, "skipped", "")
                )
            ]
        )
        == "incomplete"
    )


def test_entire_changed_test_file_without_results_is_unfinished(repo: Path):
    _write(repo, "tests/test_calc.py", "__test__ = False\n" + TESTS)
    _write(repo, "tests/test_good.py", "def test_good():\n    assert True\n")
    result = run(repo, base_ref="main")
    tests = next(c.result for c in result.checks if c.result.id == "tests_pass")
    assert result.verdict == "incomplete"
    assert tests.status == "incomplete"
    assert any(f.file == "tests/test_calc.py" and f.blocking for f in tests.findings)


@pytest.mark.parametrize("disabled", ["module", "class", "function"])
def test_preexisting_test_false_does_not_require_missing_results(repo: Path, disabled):
    if disabled == "module":
        source = "__test__ = False\ndef test_helper():\n    assert False\n"
    elif disabled == "class":
        source = "class TestHelper:\n    __test__ = False\n    def test_helper(self):\n        assert False\n"
    else:
        source = "def test_helper():\n    assert False\ntest_helper.__test__ = False\n"
    _write(repo, "tests/test_helper.py", source)
    _make_current_base(repo)
    _write(repo, "tests/test_helper.py", source + "\n# ordinary edit\n")
    result = run(repo, base_ref="main")
    assert result.verdict == "pass", [
        (c.result.id, c.result.summary) for c in result.checks
    ]


@pytest.mark.parametrize(
    "settings",
    [
        "python_files = test_good.py",
        "python_functions = test_good",
        "python_classes = OnlyThese",
        "testpaths = tests/selected",
    ],
)
def test_introducing_restrictive_pytest_settings_cannot_use_implicit_defaults(
    repo: Path, settings
):
    _write(repo, "pytest.ini", "[pytest]\n" + settings + "\n")
    _write(repo, "tests/selected/test_good.py", "def test_good():\n    assert True\n")
    _write(repo, "app/calc.py", CALC.replace("return a - b", "return a + b"))
    result = run(repo, base_ref="main")
    tampering = next(c.result for c in result.checks if c.result.id == "test_tampering")
    assert result.verdict == "fail"
    assert any(f.rule == "SKY-A112" and f.blocking for f in tampering.findings)


def test_extending_default_pytest_patterns_does_not_weaken_collection(repo: Path):
    _write(
        repo, "pytest.ini", "[pytest]\npython_files = test_*.py *_test.py checks_*.py\n"
    )
    assert not detect_loosened_test_config(open_comparison(repo, "main"))


def test_new_pytest_ini_can_preserve_existing_effective_collection(repo: Path):
    _write(
        repo,
        "pyproject.toml",
        PYPROJECT.replace(
            'addopts = "-q"', 'addopts = "-q"\npython_functions = ["test_add"]'
        ),
    )
    _make_current_base(repo)
    _write(repo, "pytest.ini", "[pytest]\npython_functions = test_add\n")
    assert not detect_loosened_test_config(open_comparison(repo, "main"))


def test_base_testpaths_continue_to_explain_unselected_changed_tests(repo: Path):
    _write(repo, "pytest.ini", "[pytest]\ntestpaths = tests\n")
    _write(repo, "integration/test_slow.py", "def test_slow():\n    assert False\n")
    _make_current_base(repo)
    _write(
        repo,
        "integration/test_slow.py",
        "def test_slow():\n    assert False\n# changed\n",
    )
    result = run(repo, base_ref="main")
    assert result.verdict == "pass", [
        (c.result.id, c.result.summary) for c in result.checks
    ]


def test_renaming_test_does_not_hide_new_skip_marker(repo: Path):
    source = TESTS.replace(
        "def test_sub():", '@pytest.mark.skip(reason="hide")\ndef test_sub_renamed():'
    )
    _write(repo, "tests/test_calc.py", source)
    result = run(repo, base_ref="main")
    tampering = next(c.result for c in result.checks if c.result.id == "test_tampering")
    assert result.verdict == "fail"
    assert any(f.rule == "SKY-A111" and f.blocking for f in tampering.findings)


def test_renaming_test_does_not_hide_removed_parameter_cases(repo: Path):
    _write(
        repo,
        "tests/test_calc.py",
        TESTS.replace("test_add_cases", "test_add_cases_renamed").replace(
            ", (3, 3, 6)", ""
        ),
    )
    result = run(repo, base_ref="main")
    tampering = next(c.result for c in result.checks if c.result.id == "test_tampering")
    assert result.verdict == "fail"
    assert any(
        "3 to 2 parametrize cases" in f.message and f.blocking
        for f in tampering.findings
    )


def test_identical_body_cannot_match_multiple_deleted_tests():
    base = collect_tests(
        "tests/test_a.py",
        "def test_a():\n    assert True\ndef test_b():\n    assert True\n",
    )
    head = collect_tests("tests/test_a.py", "def test_a():\n    assert True\n")
    assert [item.test.name for item in compare_inventories(base, head).deleted] == [
        "test_b"
    ]


@pytest.mark.parametrize("remove_helper", [False, True])
def test_unrelated_import_removal_does_not_excuse_deleted_test(
    repo: Path, remove_helper
):
    _write(repo, "helper.py", "X = 1\n")
    _write(repo, "tests/test_calc.py", "import helper\n" + TESTS)
    _make_current_base(repo)
    if remove_helper:
        (repo / "helper.py").unlink()
        import_line = ""
    else:
        (repo / "helper.py").rename(repo / "renamed_helper.py")
        import_line = "import renamed_helper\n"
    _write(
        repo,
        "tests/test_calc.py",
        import_line + TESTS.replace("def test_sub():\n    assert sub(3, 1) == 2\n", ""),
    )
    result = run(repo, base_ref="main")
    tampering = next(c.result for c in result.checks if c.result.id == "test_tampering")
    assert result.verdict == "fail"
    assert any(
        "test_sub was deleted" in f.message and f.blocking for f in tampering.findings
    )


def test_deleted_production_module_only_excuses_tests_that_reference_it(repo: Path):
    (repo / "app/calc.py").unlink()
    (repo / "tests/test_calc.py").unlink()
    _write(repo, "tests/test_good.py", "def test_good():\n    assert True\n")
    result = run(repo, base_ref="main")
    tampering = next(c.result for c in result.checks if c.result.id == "test_tampering")
    assert result.verdict == "pass", [
        (c.result.id, c.result.summary) for c in result.checks
    ]
    assert tampering.findings and all(not f.blocking for f in tampering.findings)


def test_test_runner_does_not_create_untracked_bytecode(repo: Path):
    assert not (repo / ".gitignore").exists()
    result = run(repo, base_ref="main")
    assert result.verdict == "pass"
    assert not list(repo.rglob("*.pyc"))
    receipt_path = write_receipt(result.comparison.root, build_receipt(result))
    receipt, error = load_receipt_for_upload(receipt_path, repo)
    assert error is None and receipt is not None


def test_unittest_collection_is_not_excused_by_pytest_class_patterns(repo: Path):
    _write(repo, "pytest.ini", "[pytest]\npython_classes = OnlyThese\n")
    _write(
        repo,
        "tests/test_unittest.py",
        "import unittest\nclass TestLegacy(unittest.TestCase):\n    def test_bad(self):\n        assert False\n",
    )
    _make_current_base(repo)
    _write(
        repo,
        "tests/test_unittest.py",
        "__test__ = False\nimport unittest\nclass TestLegacy(unittest.TestCase):\n    def test_bad(self):\n        assert False\n",
    )
    result = run(repo, base_ref="main")
    tests = next(c.result for c in result.checks if c.result.id == "tests_pass")
    assert tests.status == "incomplete"
    assert any(
        f.file == "tests/test_unittest.py" and f.blocking for f in tests.findings
    )


@pytest.mark.parametrize("import_helper", [False, True])
@pytest.mark.parametrize("touch_test", [False, True])
def test_runtime_deselection_from_modified_globals_cannot_prove_base_exclusion(
    repo: Path, import_helper, touch_test
):
    selection = "DISABLED = set()\n"
    if import_helper:
        _write(repo, "selection_helper.py", selection)
        selection = "from selection_helper import DISABLED\n"
    hook = (
        "def pytest_collection_modifyitems(config, items):\n"
        "    excluded = [item for item in items if item.name in DISABLED]\n"
        "    items[:] = [item for item in items if item.name not in DISABLED]\n"
        "    config.hook.pytest_deselected(items=excluded)\n"
    )
    _write(repo, "conftest.py", selection + hook)
    _make_current_base(repo)
    if import_helper:
        _write(repo, "selection_helper.py", "DISABLED = {'test_sub'}\n")
    else:
        _write(repo, "conftest.py", "DISABLED = {'test_sub'}\n" + hook)
    _write(repo, "app/calc.py", CALC.replace("return a - b", "return a + b"))
    if touch_test:
        _write(repo, "tests/test_calc.py", TESTS + "\n# ordinary test edit\n")
    result = run(repo, base_ref="main")
    tests = next(c.result for c in result.checks if c.result.id == "tests_pass")
    assert result.verdict == "fail"
    assert tests.status == "incomplete"
    assert "earlier required check" in tests.summary
    tests = done_checks.check_tests_pass(_ctx(repo))
    assert tests.status == "incomplete"
    assert any(
        "test_sub did not run" in f.message and f.blocking for f in tests.findings
    )


def test_new_marker_cannot_hide_existing_test_with_a_base_marker_selector(repo: Path):
    _write(
        repo,
        "pyproject.toml",
        PYPROJECT.replace(
            'addopts = "-q"',
            'addopts = "-q -m \'not slow\'"\nmarkers = ["slow: slow tests"]',
        ),
    )
    _make_current_base(repo)
    _write(repo, "app/calc.py", CALC.replace("return a - b", "return a + b"))
    _write(
        repo,
        "tests/test_calc.py",
        TESTS.replace("def test_sub():", "@pytest.mark.slow\ndef test_sub():"),
    )
    result = run(repo, base_ref="main")
    tests = next(c.result for c in result.checks if c.result.id == "tests_pass")
    assert result.verdict == "incomplete"
    assert any(
        "test_sub did not run" in f.message and f.blocking for f in tests.findings
    )


@pytest.mark.parametrize(
    "selector",
    ["-m 'not slow'", "-k 'not test_sub'", "--deselect=tests/test_calc.py::test_sub"],
)
def test_trusted_selectors_use_base_test_names_and_markers(repo: Path, selector):
    _write(
        repo,
        "pyproject.toml",
        PYPROJECT.replace(
            'addopts = "-q"',
            f'addopts = "-q {selector}"\nmarkers = ["slow: slow tests"]',
        ),
    )
    _write(
        repo,
        "tests/test_calc.py",
        TESTS.replace("def test_sub():", "@pytest.mark.slow\ndef test_sub():"),
    )
    _make_current_base(repo)
    _write(repo, "app/calc.py", CALC.replace("return a - b", "return a + b"))
    result = run(repo, base_ref="main")
    assert result.verdict == "pass", [
        (c.result.id, c.result.summary) for c in result.checks
    ]


def test_unknown_dynamic_base_hook_selection_is_unfinished(repo: Path):
    _write(
        repo,
        "conftest.py",
        "def pytest_collection_modifyitems(config, items):\n    excluded = [item for item in items if item.name == 'test_sub']\n    items[:] = [item for item in items if item.name != 'test_sub']\n    config.hook.pytest_deselected(items=excluded)\n",
    )
    _make_current_base(repo)
    _write(repo, "app/calc.py", CALC.replace("return a - b", "return a + b"))
    result = run(repo, base_ref="main")
    tests = next(c.result for c in result.checks if c.result.id == "tests_pass")
    assert result.verdict == "incomplete"
    assert "configure an explicit selector at the base" in tests.summary


def test_last_marker_selector_wins_instead_of_exempting_every_test(repo: Path):
    _write(
        repo,
        "pyproject.toml",
        PYPROJECT.replace(
            'addopts = "-q"',
            'addopts = "-q -m slow -m \'not slow\'"\nmarkers = ["slow: slow tests"]',
        ),
    )
    _make_current_base(repo)
    _write(repo, "app/calc.py", CALC.replace("return a - b", "return a + b"))
    _write(
        repo,
        "tests/test_calc.py",
        TESTS.replace("def test_sub():", "@pytest.mark.slow\ndef test_sub():"),
    )
    result = run(repo, base_ref="main")
    assert result.verdict == "incomplete"


def test_inventory_resolves_pytest_and_unittest_import_aliases():
    tests = collect_tests(
        "tests/test_aliases.py",
        dedent("""\
        import pytest as pt
        from pytest import mark as marks
        from unittest import TestCase as TC, skipIf as conditional_skip
        pytestmark = marks.parametrize("module_value", [1, 2])
        @marks.parametrize("class_value", [3, 4])
        class TestParams:
            @pt.mark.parametrize("value", [5, 6, 7])
            def test_cases(self, module_value, class_value, value):
                assert value
        class Legacy(TC):
            @conditional_skip(False, "still runs")
            def test_legacy(self):
                assert True
        """),
    )
    assert tests[0].parametrized and tests[0].param_cases == 12
    assert tests[1].unittest_style and tests[1].markers == frozenset({"skipif"})
    assert not tests[1].parametrized and tests[1].param_cases is None


@pytest.mark.parametrize("opaque", ["syntax", "oversized", "symlink"])
def test_opaque_test_candidate_makes_inventory_unfinished(repo: Path, opaque):
    if opaque == "syntax":
        _write(repo, "tests/test_calc.py", "def test_bad(:\n")
    elif opaque == "oversized":
        _write(repo, "tests/test_calc.py", TESTS + "#" * (2 * 1024 * 1024))
    else:
        (repo / "tests/test_calc.py").unlink()
        (repo / "tests/test_calc.py").symlink_to(repo / "app/calc.py")
    result = done_checks.run_check("test_tampering", _ctx(repo))
    assert result.status == "incomplete"
    assert "Cannot inventory tests/test_calc.py" in result.summary


@pytest.mark.parametrize("candidate", [False, True])
def test_noncollected_malformed_python_fixture_is_allowed(repo: Path, candidate):
    path = "fixtures/test_invalid.py" if candidate else "fixtures/invalid.py"
    _write(repo, path, "def invalid(:\n")
    if candidate:
        _write(
            repo,
            "pyproject.toml",
            PYPROJECT.replace(
                'addopts = "-q"', 'addopts = "-q"\ntestpaths = ["tests"]'
            ),
        )
    _make_current_base(repo)
    _write(repo, "app/calc.py", CALC + "\n# harmless change\n")
    assert run(repo, base_ref="main").verdict == "pass"


@pytest.mark.parametrize(
    "marker",
    [
        '@pytest.mark.skipif(False, reason="runs")\n',
        '@pytest.mark.xfail(condition=False, reason="runs")\n',
        '@pytest.mark.xfail(run=True, reason="runs")\n',
        "",
    ],
)
def test_conditional_skip_markers_do_not_excuse_missing_results(repo: Path, marker):
    body = "    if False:\n        pytest.skip('unreachable')\n" if not marker else ""
    source = (
        "import pytest\n" + marker + "def test_hidden():\n" + body + "    assert True\n"
    )
    _write(repo, "tests/test_conditional.py", source)
    _write(
        repo,
        "conftest.py",
        "def pytest_collection_modifyitems(items):\n    items[:] = [i for i in items if i.name != 'test_hidden']\n",
    )
    _make_current_base(repo)
    _write(repo, "app/calc.py", CALC + "\n# harmless change\n")
    result = run(repo, base_ref="main")
    tests = next(c.result for c in result.checks if c.result.id == "tests_pass")
    assert tests.status == "incomplete"
    assert result.verdict == "incomplete"


@pytest.mark.parametrize("module_skip", [False, True])
def test_reported_skip_and_proven_base_module_skip_remain_allowed(
    repo: Path, module_skip
):
    source = "import pytest\n"
    source += (
        "pytest.skip('optional module', allow_module_level=True)\n"
        if module_skip
        else "@pytest.mark.skip(reason='optional test')\n"
    )
    source += "def test_optional():\n    assert False\n"
    _write(repo, "tests/test_optional.py", source)
    _make_current_base(repo)
    _write(repo, "app/calc.py", CALC + "\n# harmless change\n")
    assert run(repo, base_ref="main").verdict == "pass"


def test_literal_parameter_cases_missing_from_results_are_unfinished(repo: Path):
    hook = "def pytest_collection_modifyitems(items):\n    items[:] = [i for i in items if i.name not in DISABLED]\n"
    _write(repo, "conftest.py", "DISABLED = {'test_add_cases[2-2-4]'}\n" + hook)
    _make_current_base(repo)
    _write(repo, "app/calc.py", CALC + "\n# harmless change\n")
    result = run(repo, base_ref="main")
    tests = next(c.result for c in result.checks if c.result.id == "tests_pass")
    assert tests.status == "incomplete" and result.verdict == "incomplete"
    assert any("2 of 3 literal parameter cases" in f.message for f in tests.findings)


def test_parameter_case_keywords_cannot_excuse_an_entire_test(repo: Path):
    _write(
        repo,
        "pyproject.toml",
        PYPROJECT.replace(
            'addopts = "-q"', "addopts = \"-q -k 'test_add or case_good'\""
        ),
    )
    source = "import pytest\n@pytest.mark.parametrize('value', [0, 1], ids=['case_good', 'case_other'])\ndef test_cases(value):\n    assert True\n"
    _write(repo, "tests/test_ids.py", source)
    _make_current_base(repo)
    # No conftest hook exists: a head-only __test__ edit drops an expected test.
    _write(repo, "tests/test_ids.py", source + "test_cases.__test__ = False\n")
    result = run(repo, base_ref="main")
    assert (
        next(c.result for c in result.checks if c.result.id == "tests_pass").status
        == "incomplete"
    )


def test_junit_duplicate_cases_cannot_replace_missing_parameter_cases():
    from skylos.done.runner import (
        TestRunResult,
        _Invocation,
        _RunOutcome,
        _with_missing,
    )

    test = collect_tests(
        "tests/test_ids.py",
        "import pytest\n@pytest.mark.parametrize('v', [0, 1])\ndef test_ids(v):\n    assert True\n",
    )[0]
    case = CaseResult(test.path, "tests.test_ids", "test_ids[0]", 3, "passed")
    outcome = _RunOutcome(
        exit_code=0, seconds=0, cases=[case, case], junit_found=True, output_tail=""
    )
    result = _with_missing(
        TestRunResult("pass", ""), outcome, [test], _Invocation([], True, False), set()
    )
    assert result.status == "incomplete"
    assert result.missing_cases == [(test, 2, 1)]


@pytest.mark.parametrize(
    "path,classname,classes",
    [
        ("tests/TestThing.py", "tests.TestThing.TestThing", ("TestThing",)),
        ("pkg/test_x/test_x.py", "test_x.test_x.TestA", ("TestA",)),
        ("test_x.py", "test_x.TestA.Inner", ("TestA", "Inner")),
    ],
)
def test_junit_class_names_do_not_erase_duplicate_module_names(
    path, classname, classes
):
    assert CaseResult(path, classname, "test_x", None, "passed").classes == classes


def test_pytest_collect_only_is_unfinished(repo: Path):
    result = run_tests(
        open_comparison(repo, "main"),
        DoneConfig(test_command=(sys.executable, "-m", "pytest", "--collect-only")),
        changed_tests=collect_tests("tests/test_calc.py", TESTS),
    )
    assert result.status == "incomplete"


_REPORT_HOOK = dedent("""\
import pytest

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if should_rewrite() and report.when == "call" and report.failed:
        report.outcome = "passed"
        report.longrepr = None
""")


@pytest.mark.parametrize(
    "dependency",
    ["global", "helper", "imported", "module_alias", "submodule", "relative_submodule"],
)
def test_unchanged_result_hook_cannot_forge_success_with_changed_dependency(
    repo: Path, dependency
):
    helper = "REWRITE = False\ndef should_rewrite():\n    return REWRITE\n"
    if dependency in {"submodule", "relative_submodule"}:
        _write(repo, "hook_package/__init__.py", "")
        _write(repo, "hook_package/policy.py", helper)
        prefix = "from hook_package import policy\n"
        if dependency == "relative_submodule":
            _write(
                repo,
                "hook_package/result_hook.py",
                "from . import policy\n"
                + _REPORT_HOOK.replace("should_rewrite()", "policy.should_rewrite()"),
            )
            prefix = "from hook_package.result_hook import pytest_runtest_makereport\n"
    elif dependency in {"imported", "module_alias"}:
        _write(repo, "report_helper.py", helper)
        prefix = (
            "from report_helper import should_rewrite\n"
            if dependency == "imported"
            else "import report_helper as reports\n"
        )
    else:
        prefix = helper
    hook = (
        _REPORT_HOOK.replace("should_rewrite()", "reports.should_rewrite()")
        if dependency == "module_alias"
        else _REPORT_HOOK
    )
    if dependency == "submodule":
        hook = _REPORT_HOOK.replace("should_rewrite()", "policy.should_rewrite()")
    _write(
        repo,
        "conftest.py",
        prefix if dependency == "relative_submodule" else prefix + hook,
    )
    _make_current_base(repo)
    if dependency in {"submodule", "relative_submodule"}:
        _write(repo, "hook_package/policy.py", helper.replace("False", "True"))
    elif dependency in {"imported", "module_alias"}:
        _write(repo, "report_helper.py", helper.replace("False", "True"))
    elif dependency == "helper":
        _write(
            repo, "conftest.py", helper.replace("return REWRITE", "return True") + hook
        )
    else:
        _write(repo, "conftest.py", helper.replace("False", "True") + hook)
    _write(repo, "app/calc.py", CALC.replace("return a - b", "return a + b"))
    result = run(repo, base_ref="main")
    tests = next(c.result for c in result.checks if c.result.id == "tests_pass")
    tampering = next(c.result for c in result.checks if c.result.id == "test_tampering")
    assert tests.status == "incomplete"  # Known tampering prevents execution.
    tests = done_checks.check_tests_pass(_ctx(repo))
    assert tests.status == "pass"  # The forged JUnit has every expected case.
    assert tampering.status == "fail" and result.verdict == "fail"
    assert any(
        "dependency of the pytest hook pytest_runtest_makereport" in f.message
        for f in tampering.findings
    )


def test_unrelated_fixture_edit_does_not_change_result_hook_dependencies(repo: Path):
    helper = "def should_rewrite():\n    return False\n"
    fixture = "@pytest.fixture\ndef ordinary_fixture():\n    return 1\n"
    _write(repo, "conftest.py", _REPORT_HOOK + helper + fixture)
    _make_current_base(repo)
    _write(
        repo,
        "conftest.py",
        _REPORT_HOOK + helper + fixture.replace("return 1", "return 2"),
    )
    result = run(repo, base_ref="main")
    assert result.verdict == "pass", [
        (c.result.id, c.result.summary) for c in result.checks
    ]


@pytest.mark.parametrize(
    "restore", ["__test__ = True", "if True:\n    __test__ = True"]
)
def test_old_false_assignment_does_not_prove_base_test_exclusion(repo: Path, restore):
    _write(
        repo,
        "tests/test_restored.py",
        "__test__ = False\n" + restore + "\ndef test_restored():\n    assert True\n",
    )
    _write(
        repo,
        "conftest.py",
        "def pytest_collection_modifyitems(items):\n    items[:] = [i for i in items if i.name != 'test_restored']\n",
    )
    _make_current_base(repo)
    _write(repo, "app/calc.py", CALC + "\n# ordinary edit\n")
    result = run(repo, base_ref="main")
    assert result.verdict == "incomplete"
    assert (
        next(c.result for c in result.checks if c.result.id == "tests_pass").status
        == "incomplete"
    )


@pytest.mark.parametrize("computed", [False, True])
def test_unrelated_changes_keep_parameter_case_totals_trusted(repo: Path, computed):
    values = (
        "VALUES = list(range(3))\n"
        if computed
        else "VALUES = (0, 1, 2)\nCASES = VALUES\n"
    )
    source = (
        "import pytest\n"
        + values
        + "@pytest.mark.parametrize('value', "
        + ("VALUES" if computed else "CASES")
        + ")\ndef test_values(value):\n    assert value >= 0\n"
    )
    _write(repo, "tests/test_values.py", source)
    _make_current_base(repo)
    _write(repo, "app/calc.py", CALC + "\n# ordinary edit\n")
    _write(
        repo,
        "tests/test_values.py",
        source + "\n\ndef test_added():\n    assert True\n",
    )
    result = run(repo, base_ref="main")
    tests = next(c.result for c in result.checks if c.result.id == "tests_pass")
    assert result.verdict == "pass"
    assert tests.evidence["unknown_case_totals"] == 0


def test_edited_computed_case_source_leaves_tests_unfinished(repo: Path):
    source = (
        "import pytest\nVALUES = list(range({n}))\n"
        "@pytest.mark.parametrize('value', VALUES)\n"
        "def test_values(value):\n    assert value >= 0\n"
    )
    _write(repo, "tests/test_values.py", source.format(n=3))
    _make_current_base(repo)
    _write(repo, "tests/test_values.py", source.format(n=2))
    result = run(repo, base_ref="main")
    tests = next(c.result for c in result.checks if c.result.id == "tests_pass")
    assert result.verdict == "incomplete" and tests.status == "incomplete"
    assert tests.evidence["unknown_case_totals"] == 1
    assert "0 test(s)" not in tests.summary
    assert "use literal case lists or simple local constants" in tests.summary.lower()
    assert any(
        "edits VALUES (tests/test_values.py:2)" in f.message for f in tests.findings
    )


_COMPUTED = (
    "import pytest\nVALUES = list(range(3))\n\n\n"
    "@pytest.mark.parametrize('value', VALUES)\n"
    "def test_values(value):\n    assert value >= 0\n"
)
_CASE_HELPER_TEST = (
    "import pytest\nfrom tests.helpers import cases\n\n\n"
    "@pytest.mark.parametrize('value', cases())\n"
    "def test_values(value):\n    assert True\n"
)
_CASE_STAR_TEST = (
    "import pytest\nfrom tests.helpers import *\n\n\n"
    "@pytest.mark.parametrize('value', VALUES)\n"
    "def test_values(value):\n    assert True\n"
)
_CASE_CLASS_TEST = (
    "import pytest\n\n\nclass TestValues:\n    CASES = list(range(3))\n\n"
    "    @pytest.mark.parametrize('value', CASES)\n"
    "    def test_values(self, value):\n        assert True\n"
)
_CASE_DATA_TEST = (
    "import pytest\nfrom pathlib import Path\n\nDATA = Path(__file__).parent / 'data'\n\n\n"
    "@pytest.mark.parametrize('name', sorted(p.name for p in DATA.iterdir()))\n"
    "def test_values(name):\n    assert True\n"
)
_CASE_DATA = {
    "tests/data/a.txt": "a\n",
    "tests/data/b.txt": "b\n",
    "tests/test_values.py": _CASE_DATA_TEST,
}


def _case_changes(repo: Path) -> dict[str, str]:
    from skylos.done.test_config import computed_case_changes

    ctx = _ctx(repo)
    base_tests, head_tests = ctx.tests()
    return computed_case_changes(ctx.comparison, head_tests, base_tests)


def _apply(repo: Path, files: dict[str, str | None]) -> None:
    for path, text in files.items():
        if text is None:
            (repo / path).unlink()
        else:
            _write(repo, path, text)


@pytest.mark.parametrize(
    "files, edits, expected",
    [
        pytest.param(
            None,
            {"tests/test_values.py": _COMPUTED.replace("range(3)", "range(2)")},
            "edits VALUES (tests/test_values.py:2)",
            id="constant",
        ),
        pytest.param(
            None,
            {"tests/test_values.py": _COMPUTED.replace("', VALUES)", "', VALUES[:1])")},
            "edits its parametrize decorators",
            id="decorator",
        ),
        pytest.param(
            None,
            {
                "tests/test_values.py": _COMPUTED.replace(
                    "\n\n\n@", "\nif True:\n    VALUES.remove(2)\n\n\n@"
                )
            },
            "edits VALUES",
            id="compound-mutation",
        ),
        pytest.param(
            None,
            {
                "tests/test_values.py": _COMPUTED.replace(
                    "\n\n\n@", "\nVALUES[2:] = []\n\n\n@"
                )
            },
            "edits VALUES",
            id="slice-store",
        ),
        pytest.param(
            None,
            {
                "tests/test_values.py": _COMPUTED.replace(
                    "import pytest\n",
                    "import pytest\n\n\ndef range(n):\n    return [0]\n",
                )
            },
            "edits range",
            id="shadowed-builtin",
        ),
        pytest.param(
            None,
            {
                "tests/test_values.py": _COMPUTED.replace(
                    "range(3)", "range(2)"
                ).replace("def test_values", "def test_values_renamed")
            },
            "edits VALUES",
            id="renamed-test",
        ),
        pytest.param(
            {
                "tests/helpers.py": "def cases():\n    return list(range(3))\n",
                "tests/test_values.py": _CASE_HELPER_TEST,
            },
            {"tests/helpers.py": "def cases():\n    return list(range(2))\n"},
            "edits cases (tests/helpers.py:1)",
            id="helper-module",
        ),
        pytest.param(
            {
                "tests/helpers.py": "VALUES = list(range(3))\n",
                "tests/test_values.py": _CASE_STAR_TEST,
            },
            {"tests/helpers.py": "VALUES = list(range(2))\n"},
            "edits VALUES (tests/helpers.py:1)",
            id="star-import",
        ),
        pytest.param(
            {"tests/test_values.py": _CASE_CLASS_TEST},
            {"tests/test_values.py": _CASE_CLASS_TEST.replace("range(3)", "range(2)")},
            "class attributes",
            id="class-attribute",
        ),
        pytest.param(
            _CASE_DATA,
            {"tests/data/b.txt": None},
            "tracked input (tests/data/b.txt)",
            id="deleted-data-file",
        ),
    ],
)
def test_edited_computed_case_sources_are_not_trusted(
    repo: Path, files, edits, expected
):
    _apply(repo, files or {"tests/test_values.py": _COMPUTED})
    _make_current_base(repo)
    _apply(repo, edits)
    changes = _case_changes(repo)
    assert len(changes) == 1
    assert expected in next(iter(changes.values()))


@pytest.mark.parametrize(
    "files, edits",
    [
        pytest.param(
            None,
            {
                "tests/test_values.py": _COMPUTED
                + "\n\ndef test_added():\n    assert True\n"
            },
            id="new-test-in-same-file",
        ),
        pytest.param(
            None,
            {"tests/test_values.py": "import os\n" + _COMPUTED.replace(">= 0", "> -1")},
            id="unrelated-import-and-body",
        ),
        pytest.param(
            None,
            {
                "tests/test_new.py": "import pytest\n\n\n"
                "@pytest.mark.parametrize('v', list(range(2)))\n"
                "def test_new(v):\n    assert True\n"
            },
            id="new-computed-test",
        ),
        pytest.param(
            {
                "tests/helpers.py": "def cases():\n    return list(range(3))\n\n\n"
                "def other():\n    return 1\n",
                "tests/test_values.py": _CASE_HELPER_TEST,
            },
            {
                "tests/helpers.py": "def cases():\n    return list(range(3))\n\n\n"
                "def other():\n    return 2\n"
            },
            id="unreached-helper",
        ),
    ],
)
def test_unrelated_edits_keep_computed_case_totals_trusted(repo: Path, files, edits):
    _apply(repo, files or {"tests/test_values.py": _COMPUTED})
    _make_current_base(repo)
    _apply(repo, edits)
    assert _case_changes(repo) == {}


@pytest.mark.parametrize(
    "mutation", ["VALUES.append(2)", "VALUES[0] = 2", "VALUES = [1]"]
)
def test_mutated_case_constants_are_not_independent_literal_totals(mutation):
    source = (
        "import pytest\nVALUES = [0, 1]\n"
        + mutation
        + "\n@pytest.mark.parametrize('value', VALUES)\ndef test_values(value):\n    assert True\n"
    )
    test = collect_tests("tests/test_values.py", source)[0]
    assert test.parametrized and test.param_cases is None


def test_generate_tests_dependency_changes_cannot_remove_generated_cases(repo: Path):
    hook = "def pytest_generate_tests(metafunc):\n    if 'value' in metafunc.fixturenames:\n        metafunc.parametrize('value', VALUES)\n"
    _write(repo, "conftest.py", "VALUES = [0, 1, 2]\n" + hook)
    _write(
        repo,
        "tests/test_generated.py",
        "def test_generated(value):\n    assert value != 2\n",
    )
    _make_current_base(repo)
    _write(repo, "conftest.py", "VALUES = [0]\n" + hook)
    result = run(repo, base_ref="main")
    tests = next(c.result for c in result.checks if c.result.id == "tests_pass")
    tampering = next(c.result for c in result.checks if c.result.id == "test_tampering")
    assert tests.status == "incomplete"  # Known tampering prevents execution.
    tests = done_checks.check_tests_pass(_ctx(repo))
    assert tests.status == "pass"
    assert tampering.status == "fail" and result.verdict == "fail"
    assert any(
        "dependency of the pytest hook pytest_generate_tests" in f.message
        for f in tampering.findings
    )


_GENERATE_HOOK = (
    "def pytest_generate_tests(metafunc):\n"
    "    if 'value' in metafunc.fixturenames:\n"
    "        metafunc.parametrize('value', {expr})\n"
)


@pytest.mark.parametrize(
    "base, head, expr",
    [
        pytest.param(
            "VALUES = [0, 1, 2]\n",
            "VALUES = [0, 1, 2]\nif True:\n    VALUES.remove(2)\n",
            "VALUES",
            id="compound-mutation",
        ),
        pytest.param(
            "VALUES = [0, 1, 2]\n",
            "VALUES = [0, 1, 2]\nVALUES[2:] = []\n",
            "VALUES",
            id="slice-store",
        ),
        pytest.param(
            "VALUES = [0, 1, 2]\n",
            "VALUES = [0, 1, 2]\n\n\ndef trim():\n    del VALUES[2]\n\n\ntrim()\n",
            "VALUES",
            id="local-function-call",
        ),
        pytest.param(
            "",
            "def range(n):\n    return [0]\n",
            "list(range(3))",
            id="shadowed-builtin",
        ),
    ],
)
def test_generate_tests_dependencies_include_mutations_and_shadowing(
    repo: Path, base, head, expr
):
    hook = _GENERATE_HOOK.format(expr=expr)
    _write(repo, "conftest.py", base + hook)
    _make_current_base(repo)
    _write(repo, "conftest.py", head + hook)
    findings = detect_loosened_test_config(open_comparison(repo, "main"))
    assert any(
        "dependency of the pytest hook pytest_generate_tests" in f.message
        for f in findings
    )


def test_unrelated_conftest_statements_do_not_change_hook_dependencies(repo: Path):
    hook = _GENERATE_HOOK.format(expr="VALUES")
    _write(repo, "conftest.py", "VALUES = [0, 1, 2]\n" + hook)
    _make_current_base(repo)
    _write(
        repo,
        "conftest.py",
        "OTHER = [1]\nOTHER.append(len(OTHER))\nVALUES = [0, 1, 2]\n" + hook,
    )
    assert detect_loosened_test_config(open_comparison(repo, "main")) == []


@pytest.mark.parametrize("fallback", [False, True])
def test_runner_file_opens_reject_symlinks_and_preserve_regular_limits(
    repo: Path, monkeypatch, fallback
):
    import os
    from skylos.done.runner import _create_log, _read_regular

    if fallback:
        monkeypatch.setattr(os, "supports_dir_fd", set())
    _write(repo, "results/report.xml", "safe report")
    result_path = repo / "results/report.xml"
    assert _read_regular(result_path, 64) == b"safe report"
    assert _read_regular(result_path, 4) is None
    assert _read_regular(result_path, 64, newer_than=time.time() + 60) is None
    (repo / "report-link.xml").symlink_to(result_path)
    (repo / "linked-results").symlink_to(repo / "results", target_is_directory=True)
    assert _read_regular(repo / "report-link.xml", 64) is None
    assert _read_regular(repo / "linked-results/report.xml", 64) is None
    with pytest.raises(OSError):
        _create_log(repo / "linked-results/captured.log")
    descriptor = _create_log(repo / "results/captured.log")
    try:
        assert os.write(descriptor, b"captured") == 8
    finally:
        os.close(descriptor)
    with pytest.raises(OSError):
        _create_log(repo / "results/captured.log")
    assert _read_regular(repo / "results/captured.log", 64) == b"captured"


def test_fixture_writer_rejects_paths_outside_its_root(repo: Path):
    with pytest.raises(ValueError):
        _write(repo, "../escape.py", "assert True\n")
    assert not (repo.parent / "escape.py").exists()


@pytest.mark.parametrize("filename", ["cases.json", "app/cases.json"])
def test_qa_computed_case_file_outside_tests_cannot_narrow(repo, filename):
    source = f"import pytest\nimport json\nfrom pathlib import Path\nVALUES = json.loads(Path({filename!r}).read_text())\n@pytest.mark.parametrize('value', VALUES)\ndef test_values(value):\n    assert value >= 0\n"
    _write(repo, filename, "[0, 1, 2]\n")
    _write(repo, "tests/test_values.py", source)
    _make_current_base(repo)
    _write(repo, filename, "[0]\n")
    changes = _case_changes(repo)
    result = run(repo, base_ref="main")
    print(
        "external-policy-qa",
        filename,
        changes,
        result.verdict,
        [
            (c.result.id, c.result.status, c.result.summary, c.result.evidence)
            for c in result.checks
            if c.result.id in {"tests_pass", "test_tampering"}
        ],
    )
    assert result.verdict != "pass"


def test_qa_opaque_factory_cannot_become_known_singleton(repo):
    source = "import pytest\ndef make_cases():\n    return [0, 1, 2]\n@pytest.mark.parametrize('value', make_cases())\ndef test_values(value):\n    assert value >= 0\n"
    _write(repo, "tests/test_values.py", source)
    _make_current_base(repo)
    _write(
        repo,
        "tests/test_values.py",
        source.replace("'value', make_cases()", "'value', [0]"),
    )
    result = run(repo, base_ref="main")
    print(
        "external-policy-qa-opaque",
        result.verdict,
        [
            (c.result.id, c.result.status, c.result.summary, c.result.evidence)
            for c in result.checks
            if c.result.id in {"tests_pass", "test_tampering"}
        ],
    )
    assert result.verdict != "pass"


@pytest.mark.parametrize("opaque", [False, True])
def test_qa_removing_parametrize_decorator_cannot_hide_base_cases(repo, opaque):
    values = "make_cases()" if opaque else "[0, 1, 2]"
    source = f"import pytest\ndef make_cases():\n    return [0, 1, 2]\n@pytest.mark.parametrize('value', {values})\ndef test_values(value):\n    assert True\n"
    _write(repo, "tests/test_values.py", source)
    _make_current_base(repo)
    head = source.replace(f"@pytest.mark.parametrize('value', {values})\n", "").replace(
        "def test_values(value):", "def test_values():"
    )
    _write(repo, "tests/test_values.py", head)
    result = run(repo, base_ref="main")
    assert result.verdict == ("incomplete" if opaque else "fail")
    check = next(
        c.result
        for c in result.checks
        if c.result.id == ("tests_pass" if opaque else "test_tampering")
    )
    assert check.status == result.verdict


def test_qa_added_sentinel_cannot_narrow_computed_cases(repo):
    source = "import pytest\nfrom pathlib import Path\nVALUES = list(range(1 if Path('skip-cases').exists() else 3))\n@pytest.mark.parametrize('value', VALUES)\ndef test_values(value):\n    assert True\n"
    _write(repo, "tests/test_values.py", source)
    _make_current_base(repo)
    _write(repo, "skip-cases", "present\n")
    result = run(repo, base_ref="main")
    assert result.verdict == "incomplete"
    check = next(c.result for c in result.checks if c.result.id == "tests_pass")
    assert check.status == "incomplete" and check.evidence["unknown_case_totals"] == 1


def test_qa_added_data_file_total_cannot_be_independently_proven(repo):
    _apply(repo, _CASE_DATA)
    _make_current_base(repo)
    _write(repo, "tests/data/c.txt", "c\n")
    changes = _case_changes(repo)
    assert len(changes) == 1
    assert "tests/data/c.txt" in next(iter(changes.values()))


def test_qa_unchanged_file_cases_have_no_unknown_totals(repo):
    _apply(repo, _CASE_DATA)
    _make_current_base(repo)
    assert _case_changes(repo) == {}


@pytest.mark.parametrize(
    "reader",
    [
        "reader = open\nVALUES = json.load(reader('cases.json'))",
        "from io import open as reader\nVALUES = json.load(reader('cases.json'))",
        "reader = Path('cases.json').read_text\nVALUES = json.loads(reader())",
        "VALUES = json.loads(getattr(Path('cases.json'), 'read_text')())",
    ],
)
def test_qa_opaque_reader_aliases_cannot_hide_changed_input(repo, reader):
    source = f"import pytest\nimport json\nfrom pathlib import Path\n{reader}\n@pytest.mark.parametrize('value', VALUES)\ndef test_values(value):\n    assert True\n"
    _write(repo, "cases.json", "[0, 1, 2]\n")
    _write(repo, "tests/test_values.py", source)
    _make_current_base(repo)
    _write(repo, "cases.json", "[0]\n")
    result = run(repo, base_ref="main")
    assert result.verdict == "incomplete"
    check = next(c.result for c in result.checks if c.result.id == "tests_pass")
    assert check.evidence["unknown_case_totals"] == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "ALIAS = VALUES\nALIAS.pop()",
        "truncate = VALUES.pop\ntruncate()",
        "for alias in [VALUES]: alias.pop()",
        "[VALUES].pop().pop()",
        "match [0]:\n    case VALUES: pass",
        "match VALUES:\n    case alias: alias.pop()",
    ],
)
def test_qa_alias_or_capture_cannot_hide_mutated_case_source(repo, mutation):
    source = "import pytest\nVALUES = list(range(3))\n"
    test = "@pytest.mark.parametrize('value', VALUES)\ndef test_values(value):\n    assert True\n"
    _write(repo, "tests/test_values.py", source + test)
    _make_current_base(repo)
    _write(repo, "tests/test_values.py", source + mutation + "\n" + test)
    changes = _case_changes(repo)
    assert len(changes) == 1
    result = run(repo, base_ref="main")
    assert result.verdict == "incomplete"


@pytest.mark.parametrize(
    "import_line",
    [
        "from tests.helpers import cases",
        "import tests.helpers\ncases = tests.helpers.cases",
        "from tests import helpers\ncases = helpers.cases",
    ],
)
def test_qa_added_package_cannot_shadow_unchanged_case_module(repo, import_line):
    source = f"import pytest\n{import_line}\n@pytest.mark.parametrize('value', cases())\ndef test_values(value):\n    assert True\n"
    _write(repo, "tests/helpers.py", "def cases():\n    return [0, 1, 2]\n")
    _write(repo, "tests/test_values.py", source)
    _make_current_base(repo)
    _write(repo, "tests/helpers/__init__.py", "def cases():\n    return [0]\n")
    result = run(repo, base_ref="main")
    assert result.verdict == "incomplete"
    check = next(c.result for c in result.checks if c.result.id == "tests_pass")
    assert check.evidence["run"] == 7 and check.evidence["unknown_case_totals"] == 1


def test_qa_unrelated_pure_assignment_keeps_opaque_cases_trusted(repo):
    _write(repo, "tests/test_values.py", _COMPUTED)
    _make_current_base(repo)
    _write(
        repo,
        "tests/test_values.py",
        _COMPUTED.replace("\n\n\n@", "\nOTHER = list(range(9))\n\n@"),
    )
    assert _case_changes(repo) == {}
    result = run(repo, base_ref="main")
    assert result.verdict == "pass"


@pytest.mark.parametrize(
    "reader",
    [
        "VALUES = json.loads(getattr(Path('cases.py'), 'read' + '_text')())",
        "from io import FileIO\nVALUES = json.load(FileIO('cases.py'))",
    ],
)
def test_qa_opaque_python_named_input_cannot_narrow_cases(repo, reader):
    source = f"import pytest\nimport json\nfrom pathlib import Path\n{reader}\n@pytest.mark.parametrize('value', VALUES)\ndef test_values(value):\n    assert True\n"
    _write(repo, "cases.py", "[0, 1, 2]\n")
    _write(repo, "tests/test_values.py", source)
    _make_current_base(repo)
    _write(repo, "cases.py", "[0]\n")
    result = run(repo, base_ref="main")
    assert result.verdict == "incomplete"


@pytest.mark.parametrize(
    "mutation",
    [
        "class Trigger:\n    VALUES.pop()",
        "def helper(value=VALUES.pop()):\n    pass",
        "class Trigger:\n    global VALUES\n    VALUES = [0]",
        "def helper(value=(VALUES := [0])):\n    pass",
    ],
)
def test_qa_definition_time_effects_cannot_narrow_closed_cases(repo, mutation):
    source = "import pytest\nVALUES = list(range(3))\n"
    test = "@pytest.mark.parametrize('value', VALUES)\ndef test_values(value):\n    assert True\n"
    _write(repo, "tests/test_values.py", source + test)
    _make_current_base(repo)
    _write(repo, "tests/test_values.py", source + mutation + "\n" + test)
    assert _case_changes(repo)
    result = run(repo, base_ref="main")
    assert result.verdict == "incomplete"


def test_qa_lazy_import_factory_cannot_hide_python_dependency_edits(repo):
    source = "import pytest\ndef cases():\n    from tests.helpers import VALUES\n    return VALUES\n@pytest.mark.parametrize('value', cases())\ndef test_values(value):\n    assert True\n"
    _write(repo, "tests/helpers.py", "VALUES = [0, 1, 2]\n")
    _write(repo, "tests/test_values.py", source)
    _make_current_base(repo)
    _write(repo, "tests/helpers.py", "VALUES = [0]\n")
    result = run(repo, base_ref="main")
    assert result.verdict == "incomplete"


def test_qa_builtin_namespace_rebinding_invalidates_closed_case_proof(repo):
    _write(repo, "tests/test_values.py", _COMPUTED)
    _make_current_base(repo)
    head = _COMPUTED.replace(
        "\n\n\n@", "\nimport builtins as b\nb.range = lambda *args: [0]\n\n@"
    )
    _write(repo, "tests/test_values.py", head)
    assert _case_changes(repo)


def test_qa_head_import_initializer_cannot_silently_narrow_imported_cases(repo):
    source = "import pytest\nfrom helpers import VALUES\n@pytest.mark.parametrize('value', VALUES)\ndef test_values(value):\n    assert True\n"
    _write(repo, "helpers.py", "VALUES = [0, 1, 2]\n")
    _write(repo, "tests/test_values.py", source)
    _make_current_base(repo)
    _write(repo, "helpers.py", "VALUES = [0, 1, 2]\nimport poison\n")
    _write(
        repo, "poison.py", "from helpers import VALUES\nVALUES.pop()\nVALUES.pop()\n"
    )
    result = run(repo, base_ref="main")
    assert result.verdict == "incomplete"
    check = next(c.result for c in result.checks if c.result.id == "tests_pass")
    assert check.evidence["run"] == 7 and check.evidence["unknown_case_totals"] == 1
