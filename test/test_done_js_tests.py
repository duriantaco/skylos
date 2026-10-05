"""skylos done: JavaScript/TypeScript test inventories, tampering and settings."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from textwrap import dedent

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.done import checks as done_checks
from skylos.done.base import ChangedFile, open_comparison
from skylos.done.checks import CheckContext
from skylos.done.config import DoneConfig
from skylos.done.engine import run
from skylos.done.inventory import compare_inventories
from skylos.done.js_inventory import (
    collect_js_tests,
    is_js_test_file,
    js_non_code_lines,
    newly_focused,
)
from skylos.done.js_test_config import detect_loosened_js_test_config


def _tests(path: str, source: str):
    inventory = collect_js_tests(path, dedent(source))
    assert inventory.clean
    return inventory


def _ids(path: str, source: str) -> list[str]:
    return [t.local_id for t in _tests(path, source).tests]


def _markers(path: str, source: str) -> dict[str, set[str]]:
    return {t.local_id: set(t.markers) for t in _tests(path, source).tests}


def _diff(base: str, head: str, base_path="a.test.js", head_path=None):
    return compare_inventories(
        _tests(base_path, base).tests, _tests(head_path or base_path, head).tests
    )


# ---------------------------------------------------------------------------
# which files are test files
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "src/math.test.js",
        "src/math.spec.ts",
        "src/Button.test.tsx",
        "src/Button.spec.jsx",
        "lib/util.test.mjs",
        "lib/util.test.cjs",
        "lib/util.spec.mts",
        "src/__tests__/math.js",
        "src/__tests__/deep/math.ts",
    ],
)
def test_js_test_file_names(path):
    assert is_js_test_file(path)


@pytest.mark.parametrize(
    "path",
    [
        "src/math.js",
        "src/test.js",
        "src/math.test.py",
        "types/math.test.d.ts",
        "node_modules/pkg/a.test.js",
        "src/__tests__.js",
        "src/math.test.js.snap",
    ],
)
def test_js_non_test_file_names(path):
    assert not is_js_test_file(path)


# ---------------------------------------------------------------------------
# collection
# ---------------------------------------------------------------------------


def test_collects_tests_by_describe_path_and_title():
    source = """
        describe("math", () => {
          it("adds", () => { expect(1 + 1).toBe(2); });
          describe("negative", function () {
            test('subtracts', async () => { expect(1 - 2).toBe(-1); });
          });
        });
        it(`top level`, () => {});
        context("mocha", () => { specify("works", () => {}); });
        suite("tdd", () => { test("works", () => {}); });
        test.describe("playwright", () => { test("opens", async ({ page }) => {}); });
    """
    assert _ids("a.test.js", source) == [
        "math > adds",
        "math > negative > subtracts",
        "top level",
        "mocha > works",
        "tdd > works",
        "playwright > opens",
    ]


def test_dynamic_titles_are_not_inventoried():
    source = """
        const name = "x";
        it(`adds ${name}`, () => {});
        it(name, () => {});
        it("a" + "b", () => {});
        test(async (t) => {});
        it(`static`, () => {});
    """
    assert _ids("a.test.js", source) == ["static"]


def test_comments_and_strings_never_count():
    source = """
        // it.skip("commented", () => {});
        /* describe.only("block comment", () => {}) */
        const text = "it.only('in a string', () => {})";
        it("real", () => { expect(text).toContain("it.skip("); });
    """
    inventory = _tests("a.test.js", source)
    assert [t.local_id for t in inventory.tests] == ["real"]
    assert not inventory.tests[0].markers
    assert not inventory.focus


def test_typescript_generics_and_jsx_parse():
    ts = """
        import { describe, it, expect } from "vitest";
        function wrap<T>(value: T): T[] { return [value]; }
        const n = <number>(<unknown>1);
        describe("generic", () => {
          it("wraps", async () => {
            const result = wrap<string>("x") as string[];
            expect(result).toEqual(["x"]);
          });
        });
    """
    tsx = """
        import { render } from "@testing-library/react";
        const identity = <T,>(value: T) => value;
        describe("Button", () => {
          it("renders", () => {
            const view = render(<Button label="a &amp; b">Save & close</Button>);
            expect(identity(view)).toBeTruthy();
          });
        });
    """
    jsx = """
        it("renders jsx in a .js file", () => {
          expect(<div className="x">hi</div>).toBeDefined();
        });
    """
    assert _ids("a.test.ts", ts) == ["generic > wraps"]
    assert _ids("Button.test.tsx", tsx) == ["Button > renders"]
    assert _ids("a.test.js", jsx) == ["renders jsx in a .js file"]


def test_skip_markers_for_every_runner():
    source = """
        it.skip("a", () => {});
        test.skip("b", () => {});
        xit("c", () => {});
        xtest("d", () => {});
        it.todo("e");
        it("f");
        test.fixme("g", async () => {});
        test("h", async () => { test.skip(); });
        test("i", async ({ page }, testInfo) => { testInfo.fixme(); });
        it.skipIf(process.env.CI)("j", () => {});
        it.runIf(process.env.CI)("k", () => {});
        it("l", function () { this.skip(); });
        test("m", (t) => { t.skip("later"); });
        test("n", ({ skip }) => { skip(); });
        test("o", { skip: true }, () => {});
        test("p", { todo: "later" }, () => {});
        test.failing("q", () => {});
        it.fails("r", () => {});
        it("s", (done) => { done.fail(new Error("x")); });
        test("t", { skip: false }, () => {});
        it.concurrent.skip.each([[1]])("u %i", () => {});
    """
    assert _markers("a.test.js", source) == {
        "a": {"skip"},
        "b": {"skip"},
        "c": {"skip"},
        "d": {"skip"},
        "e": {"todo"},
        "f": {"pending"},
        "g": {"fixme"},
        "h": {"skip()"},
        "i": {"fixme()"},
        "j": {"skipIf"},
        "k": {"runIf"},
        "l": {"skip()"},
        "m": {"skip()"},
        "n": {"skip()"},
        "o": {"skip"},
        "p": {"todo"},
        "q": {"failing"},
        "r": {"failing"},
        "s": set(),  # Jasmine's done.fail() fails the test, it is not xfail
        "t": set(),
        "u %i": {"skip"},
    }


def test_describe_and_file_level_skips_are_inherited():
    source = """
        test.skip(({ browserName }) => browserName === "webkit", "flaky there");
        describe.skip("a", () => { it("x", () => {}); });
        xdescribe("b", () => { it("x", () => {}); });
        test.describe.fixme("c", () => { test("x", async () => {}); });
        describe.skipIf(true)("d", () => { it("x", () => {}); });
        describe("e", () => {
          before(function () { this.skip(); });
          it("x", () => {});
        });
        test.describe("f", () => {
          test.fixme(true, "broken");
          test("x", async () => {});
        });
    """
    assert _markers("a.spec.ts", source) == {
        "a > x": {"describe skip", "file skip()"},
        "b > x": {"describe skip", "file skip()"},
        "c > x": {"describe fixme", "file skip()"},
        "d > x": {"describe skipIf", "file skip()"},
        "e > x": {"describe skip()", "file skip()"},
        "f > x": {"describe fixme()", "file skip()"},
    }


def test_focus_calls_are_recorded():
    source = """
        it.only("a", () => {});
        test.only("b", () => {});
        fit("c", () => {});
        describe.only("d", () => { it("x", () => {}); });
        fdescribe("e", () => {});
        test.describe.only("f", () => {});
        test("g", { only: true }, () => {});
        it.only(`dynamic ${1}`, () => {});
    """
    calls = [(site.call, site.scope) for site in _tests("a.test.js", source).focus]
    assert calls == [
        ("it.only", ("a",)),
        ("test.only", ("b",)),
        ("fit", ("c",)),
        ("describe.only", ("d",)),
        ("fdescribe", ("e",)),
        ("test.describe.only", ("f",)),
        ("{ only: true }", ("g",)),
        ("it.only", ("`dynamic ${1}`",)),
    ]


def test_each_tables_count_literal_cases():
    source = """
        test.each([[1, 1, 2], [2, 2, 4], [3, 3, 6]])("add(%i, %i)", (a, b, c) => {});
        test.each`
          a    | b
          ${1} | ${2}
          ${3} | ${4}
        `("tagged $a", ({ a }) => {});
        it.each(cases)("computed %s", () => {});
        describe.each([["x"], ["y"]])("suite %s", () => {
          it.each([1, 2, 3])("case %i", () => {});
        });
    """
    counts = {
        t.local_id: (t.parametrized, t.param_cases)
        for t in _tests("a.test.js", source).tests
    }
    assert counts == {
        "add(%i, %i)": (True, 3),
        "tagged $a": (True, 2),
        "computed %s": (True, None),
        "suite %s > case %i": (True, 6),
    }


def test_duplicate_titles_are_counted_separately():
    base = """
        it("same", () => { expect(1).toBe(1); });
        it("same", () => { expect(2).toBe(2); });
    """
    head = """
        it("same", () => { expect(1).toBe(1); });
    """
    assert [d.test.local_id for d in _diff(base, head).deleted] == ["same [2]"]


# ---------------------------------------------------------------------------
# comparing base and head
# ---------------------------------------------------------------------------

BASE = """
    describe("math", () => {
      it("adds", () => {
        expect(add(1, 2)).toBe(3);
      });
      it("subtracts", () => {
        expect(sub(3, 1)).toBe(2);
      });
    });
"""


def test_deleted_test_is_reported():
    head = """
        describe("math", () => {
          it("adds", () => {
            expect(add(1, 2)).toBe(3);
          });
        });
    """
    diff = _diff(BASE, head)
    assert [d.test.local_id for d in diff.deleted] == ["math > subtracts"]


def test_moved_test_is_not_a_deletion():
    stays = """
        describe("math", () => {
          it("adds", () => {
            expect(add(1, 2)).toBe(3);
          });
        });
    """
    moved = """
        describe("subtraction", () => {
          it("works", () => {
            expect(sub(3, 1)).toBe(2);
          });
        });
    """
    base = _tests("a.test.js", BASE).tests
    head = _tests("a.test.js", stays).tests + _tests("b.test.js", moved).tests
    assert not compare_inventories(base, head).deleted


def test_renamed_describe_with_the_same_tests_is_not_a_deletion():
    head = BASE.replace('describe("math"', 'describe("arithmetic"')
    diff = _diff(BASE, head)
    assert not diff.deleted and not diff.newly_skipped


def test_renamed_file_keeps_its_tests():
    base = _tests("src/a.test.js", BASE).tests
    head = _tests("src/b.test.js", BASE).tests
    assert not compare_inventories(
        base, head, {"src/a.test.js": "src/b.test.js"}
    ).deleted


def test_formatting_only_changes_change_nothing():
    reformatted = """
        describe('math', () => {
          it('adds', () => {
            expect(add(1, 2)).toBe(3)
          })
          it('subtracts', () => {
            expect(sub(3, 1)).toBe(2) // still checks
          })
        })
    """
    diff = _diff(BASE, reformatted)
    assert not diff.deleted and not diff.newly_skipped


def test_moved_and_reformatted_test_matches_by_body():
    base = """
        it("maps", () => {
          const out = items.map(x => x * 2);
          expect(out).toEqual([2, 4,]);
        });
    """
    head = """
        it('doubles every item', () => {
          const out = items.map((x) => x * 2)
          expect(out).toEqual([2, 4])
        })
    """
    assert not compare_inventories(
        _tests("a.test.js", base).tests, _tests("b.test.js", head).tests
    ).deleted


def test_new_tests_are_not_considered():
    head = BASE.replace(
        "});\n    });",
        '});\n      it.skip("new and skipped", () => {});\n    });',
    )
    diff = _diff(BASE, head)
    assert not diff.deleted and not diff.newly_skipped


def test_newly_skipped_and_todo_tests():
    head = BASE.replace('it("adds"', 'it.skip("adds"').replace(
        """it("subtracts", () => {
        expect(sub(3, 1)).toBe(2);
      });""",
        'it.todo("subtracts");',
    )
    diff = _diff(BASE, head)
    assert not diff.deleted
    assert {(s.test.local_id, s.added) for s in diff.newly_skipped} == {
        ("math > adds", frozenset({"skip"})),
        ("math > subtracts", frozenset({"todo"})),
    }


def test_skip_marker_spelled_differently_is_still_skipped_once():
    base = 'it.skip("a", () => {});'
    head = 'xit("a", () => {});'
    assert not _diff(base, head).newly_skipped


def test_dropped_each_cases():
    base = 'test.each([[1], [2], [3]])("case %i", (n) => { expect(n).toBeGreaterThan(0); });'
    head = 'test.each([[1]])("case %i", (n) => { expect(n).toBeGreaterThan(0); });'
    dropped = _diff(base, head).dropped_cases
    assert [(d.before, d.after) for d in dropped] == [(3, 1)]


def test_newly_focused_counts_new_and_moved_focus_once():
    base = _tests("a.test.js", 'it.only("a", () => { run(); });\nit("b", () => {});')
    same = _tests("a.test.js", 'it.only("a", () => { run(); });\nit("b", () => {});')
    moved = _tests(
        "b.test.js", 'describe("x", () => { it.only("a2", () => { run(); }); });'
    )
    added = _tests("a.test.js", 'it("a", () => {});\nit.only("new", () => {});')
    assert not newly_focused(base.focus, same.focus)
    assert not newly_focused(base.focus, moved.focus)
    assert [site.scope for site in newly_focused([], added.focus)] == [("new",)]


def test_non_code_lines_cover_comments_and_multiline_strings():
    source = dedent(
        """\
        it("a", () => {
          // it.skip("x")
          const s = `line one
        it.skip("in a template")`;
          expect(s).toBe(s); // trailing comment
        });
        """
    )
    assert js_non_code_lines("a.test.js", source) == {2, 4}


# ---------------------------------------------------------------------------
# the done gate in a repository
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
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, dedent(text))


MATH_TEST = """\
    const { add, sub } = require("../math");

    describe("math", () => {
      it("adds two numbers", () => {
        expect(add(1, 2)).toBe(3);
      });

      it("subtracts two numbers", () => {
        expect(sub(3, 1)).toBe(2);
      });

      it("adds negatives", () => {
        expect(add(-1, -1)).toBe(-2);
      });
    });
"""

JEST_CONFIG = """\
    module.exports = {
      testEnvironment: "node",
      coverageThreshold: { global: { lines: 90, branches: 80 } },
    };
"""

PACKAGE = """\
    {
      "name": "demo",
      "scripts": { "test": "jest" }
    }
"""


@pytest.fixture
def js_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, "package.json", PACKAGE)
    _write(root, "jest.config.js", JEST_CONFIG)
    _write(root, "src/math.js", "module.exports = { add: (a, b) => a + b };\n")
    _write(root, "src/legacy.js", "module.exports = { old: () => 1 };\n")
    _write(root, "src/__tests__/math.test.js", MATH_TEST)
    _write(
        root,
        "src/__tests__/legacy.test.js",
        """\
        const { old } = require("../legacy");
        const { add } = require("../math");

        it("old works", () => {
          expect(old()).toBe(1);
        });

        it("add still works", () => {
          expect(add(1, 1)).toBe(2);
        });
        """,
    )
    _write(root, "test/helpers.js", "module.exports = {};\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    return root


def _tampering(root: Path):
    comparison = open_comparison(root, None)
    return done_checks.check_test_tampering(CheckContext(comparison, DoneConfig()))


def _rules(result) -> list[tuple[str, bool, str]]:
    return [(f.rule, f.blocking, f.message) for f in result.findings]


def test_clean_js_change_passes(js_repo: Path):
    _write(
        js_repo,
        "src/__tests__/math.test.js",
        MATH_TEST.replace("});\n    });", '});\n      it("new", () => {});\n    });'),
    )
    result = _tampering(js_repo)
    assert result.status == "pass", result.findings
    assert result.evidence["tests_compared"] == 5


def test_skip_delete_focus_and_config_are_reported(js_repo: Path):
    edited = (
        MATH_TEST.replace('it("adds two numbers"', 'it.only("adds two numbers"')
        .replace('it("subtracts two numbers"', 'it.skip("subtracts two numbers"')
        .replace(
            """
      it("adds negatives", () => {
        expect(add(-1, -1)).toBe(-2);
      });
""",
            "",
        )
    )
    _write(js_repo, "src/__tests__/math.test.js", edited)
    _write(
        js_repo,
        "jest.config.js",
        JEST_CONFIG.replace(
            'testEnvironment: "node",',
            'testEnvironment: "node",\n  passWithNoTests: true,',
        ),
    )
    result = _tampering(js_repo)
    assert result.status == "fail"
    blocking = sorted((r, m) for r, b, m in _rules(result) if b)
    assert blocking == [
        (
            "SKY-A110",
            "math > adds negatives was deleted; no test with the same body exists now",
        ),
        (
            "SKY-A111",
            "it.only focuses math > adds two numbers: the other tests in the file stop running",
        ),
        (
            "SKY-A111",
            "math > subtracts two numbers now skips or expects failure (skip)",
        ),
        (
            "SKY-A112",
            "Jest passWithNoTests turned on: a run that finds no tests passes",
        ),
    ]
    assert result.evidence["focused"] == 1


def test_assertion_weakening_is_advice_for_js_tests(js_repo: Path):
    _write(
        js_repo,
        "src/__tests__/math.test.js",
        MATH_TEST.replace(
            "expect(add(1, 2)).toBe(3);", "expect(add(1, 2)).toBeTruthy();"
        ),
    )
    result = _tampering(js_repo)
    assert result.status == "pass"
    assert [(r, b) for r, b, _ in _rules(result)] == [("SKY-A101", False)]


def test_skip_in_a_comment_is_not_a_finding(js_repo: Path):
    _write(
        js_repo,
        "src/__tests__/math.test.js",
        MATH_TEST.replace(
            'describe("math", () => {',
            'describe("math", () => {\n  // TODO: it.skip("flaky", () => {}) if CI is slow',
        ),
    )
    result = _tampering(js_repo)
    assert result.status == "pass" and not result.findings


def test_deleting_a_feature_with_its_test_is_advice(js_repo: Path):
    (js_repo / "src/legacy.js").unlink()
    _write(
        js_repo,
        "src/__tests__/legacy.test.js",
        """\
        const { add } = require("../math");

        it("add still works", () => {
          expect(add(1, 1)).toBe(2);
        });
        """,
    )
    result = _tampering(js_repo)
    assert result.status == "pass"
    assert [(r, b) for r, b, _ in _rules(result)] == [("SKY-A110", False)]
    assert "feature removal" in result.findings[0].message


def test_deleting_an_unrelated_test_next_to_a_removed_feature_blocks(js_repo: Path):
    (js_repo / "src/legacy.js").unlink()
    _write(js_repo, "src/__tests__/legacy.test.js", "")
    result = _tampering(js_repo)
    blocking = [m for r, b, m in _rules(result) if b]
    assert blocking == [
        "add still works was deleted; no test with the same body exists now"
    ]


def test_deleting_a_todo_is_not_a_deleted_test(js_repo: Path):
    _write(
        js_repo,
        "src/__tests__/math.test.js",
        MATH_TEST.replace("});\n    });", '});\n      it.todo("later");\n    });'),
    )
    _git(js_repo, "add", "-A")
    _git(js_repo, "commit", "-qm", "todo")
    _write(js_repo, "src/__tests__/math.test.js", MATH_TEST)
    assert _tampering(js_repo).status == "pass"


def test_test_file_that_stops_parsing_cannot_be_compared(js_repo: Path):
    _write(
        js_repo,
        "src/__tests__/math.test.js",
        MATH_TEST.replace("describe(", "describe((((", 1),
    )
    result = done_checks.run_check(
        "test_tampering",
        CheckContext(open_comparison(js_repo, None), DoneConfig()),
    )
    assert result.status == "incomplete"
    assert "no longer parses" in result.summary


def test_test_file_that_never_parsed_is_left_out_with_advice(js_repo: Path):
    _write(js_repo, "src/__tests__/flow.test.js", "it('x', () => { (((( });\n")
    _git(js_repo, "add", "-A")
    _git(js_repo, "commit", "-qm", "flow")
    _write(js_repo, "src/__tests__/flow.test.js", "it('y', () => { (((( });\n")
    result = _tampering(js_repo)
    assert result.status == "pass"
    assert [(r, b) for r, b, _ in _rules(result)] == [("SKY-A110", False)]
    assert "could not be read or parsed" in result.findings[0].message


def test_js_project_without_test_command_is_unfinished_with_a_clear_reason(
    js_repo: Path,
):
    # test/ exists, which alone would make Skylos try pytest.
    _write(js_repo, "src/math.js", "module.exports = { add: (a, b) => b + a };\n")
    result = run(js_repo)
    tests = next(c for c in result.checks if c.result.id == "tests_pass")
    tampering = next(c for c in result.checks if c.result.id == "test_tampering")
    assert tampering.result.status == "pass"
    assert tests.result.status == "incomplete"
    assert "No test command for the JavaScript/TypeScript tests" in tests.result.summary
    assert result.verdict == "incomplete"


def test_automatic_pytest_run_notes_the_js_tests_it_does_not_run(js_repo: Path):
    _write(js_repo, "pyproject.toml", "[tool.pytest.ini_options]\naddopts = '-q'\n")
    _write(js_repo, "tests/test_py.py", "def test_ok():\n    assert True\n")
    _git(js_repo, "add", "-A")
    _git(js_repo, "commit", "-qm", "python tests")
    _write(js_repo, "tests/test_py.py", "def test_ok():\n    assert 1 == 1\n")
    tests = done_checks.check_tests_pass(
        CheckContext(open_comparison(js_repo, None), DoneConfig())
    )
    assert tests.status == "pass", tests.summary
    advice = [f.message for f in tests.findings if not f.blocking]
    assert advice == [
        "(advice) 2 JavaScript/TypeScript test file(s) are not run by the "
        "automatic pytest command; set test_command to run them"
    ]


# ---------------------------------------------------------------------------
# loosened Jest and Vitest settings
# ---------------------------------------------------------------------------


class _Comparison:
    """The parts of a Comparison the settings check reads."""

    def __init__(self, base: dict[str, str], head: dict[str, str]) -> None:
        self.base = {k: dedent(v) for k, v in base.items()}
        self.head = {k: dedent(v) for k, v in head.items()}
        changed = []
        for path in sorted(set(self.base) | set(self.head)):
            if self.base.get(path) == self.head.get(path):
                continue
            status = (
                "added"
                if path not in self.base
                else "deleted"
                if path not in self.head
                else "modified"
            )
            changed.append(
                ChangedFile(path, status, None if status == "added" else path)
            )
        self.changed = tuple(changed)

    def base_text(self, path, *, sha=None):
        return self.base.get(path)

    def head_text(self, path):
        return self.head.get(path)

    def base_paths(self):
        return sorted(self.base)


def _config_messages(base: dict[str, str], head: dict[str, str]) -> list[str]:
    return [f.message for f in detect_loosened_js_test_config(_Comparison(base, head))]


PKG = '{"name": "demo", "scripts": {"test": "jest"}}'
SPEC = "it('works', () => { expect(run()).toBe(1); });\n"
PLAYWRIGHT_SPEC = (
    "import { test, expect } from '@playwright/test';\n"
    "test('opens', async ({ page }) => { await expect(page).toHaveTitle('x'); });\n"
)


def _with_tests(files: dict[str, str], *paths: str) -> dict[str, str]:
    """The same test files on both sides of a settings change."""
    return {**files, **{path: SPEC for path in paths}}


def test_jest_ignore_patterns_and_thresholds():
    tests = ("e2e/login.test.js", "src/math.test.js", "dist/math.test.js")
    base = {
        "package.json": PKG,
        "jest.config.js": """\
            module.exports = {
              testPathIgnorePatterns: ["/node_modules/"],
              coverageThreshold: {
                global: { lines: 90, branches: 80, functions: -10 },
                "./src/core/": { statements: 95 },
              },
            };
        """,
    }
    head = {
        "package.json": PKG,
        "jest.config.js": """\
            module.exports = {
              testPathIgnorePatterns: ["/node_modules/", "/e2e/"],
              modulePathIgnorePatterns: ["<rootDir>/dist"],
              coverageThreshold: {
                global: { lines: 70, branches: 80, functions: -20 },
              },
            };
        """,
    }
    # dist/ is build output: ignoring it drops no test.
    assert sorted(
        _config_messages(_with_tests(base, *tests), _with_tests(head, *tests))
    ) == sorted(
        [
            "Jest testPathIgnorePatterns now skips test paths matching '/e2e/' "
            "(1 existing test file(s) no longer run, e.g. 'e2e/login.test.js')",
            "Jest coverageThreshold ./src/core/.statements 95 removed",
            "Jest coverageThreshold global.functions -10 lowered to -20",
            "Jest coverageThreshold global.lines 90 lowered to 70",
        ]
    )


def test_jest_settings_in_package_json_and_moving_them_to_a_config_file():
    base = {
        "package.json": """\
            {"name": "demo", "jest": {"testPathIgnorePatterns": ["/fixtures/"],
             "coverageThreshold": {"global": {"lines": 80}}}}
        """
    }
    head_moved = {
        "package.json": '{"name": "demo"}',
        "jest.config.ts": """\
            import type { Config } from "jest";
            const config: Config = {
              testPathIgnorePatterns: ["/fixtures/"],
              coverageThreshold: { global: { lines: 80 } },
            };
            export default config;
        """,
    }
    head_loosened = {
        "package.json": """\
            {"name": "demo", "jest": {"testPathIgnorePatterns": ["/fixtures/", "slow"],
             "passWithNoTests": true}}
        """
    }
    tests = ("src/slow.test.js", "src/fast.test.js")
    base = _with_tests(base, *tests)
    assert _config_messages(base, _with_tests(head_moved, *tests)) == []
    assert sorted(_config_messages(base, _with_tests(head_loosened, *tests))) == [
        "Jest coverageThreshold global.lines 80 removed",
        "Jest passWithNoTests turned on: a run that finds no tests passes",
        "Jest testPathIgnorePatterns now skips test paths matching 'slow' "
        "(1 existing test file(s) no longer run, e.g. 'src/slow.test.js')",
    ]


def test_vitest_exclude_pass_with_no_tests_and_thresholds():
    base = {
        "package.json": PKG,
        "vitest.config.ts": """\
            import { configDefaults, defineConfig } from "vitest/config";
            export default defineConfig({
              test: {
                exclude: [...configDefaults.exclude],
                coverage: { thresholds: { lines: 90, "src/core/**": { branches: 100 } } },
              },
            });
        """,
    }
    head = {
        "package.json": PKG,
        "vitest.config.ts": """\
            import { configDefaults, defineConfig } from "vitest/config";
            export default defineConfig({
              test: {
                exclude: [...configDefaults.exclude, "**/node_modules/**", "src/slow/**"],
                passWithNoTests: true,
                coverage: { thresholds: { lines: 60 } },
              },
            });
        """,
    }
    tests = ("src/slow/a.test.ts", "src/b.test.ts")
    assert sorted(
        _config_messages(_with_tests(base, *tests), _with_tests(head, *tests))
    ) == [
        "Vitest coverage threshold thresholds.lines 90 lowered to 60",
        "Vitest coverage threshold thresholds['src/core/**'].branches 100 removed",
        "Vitest exclude now skips test files matching 'src/slow/**' "
        "(1 existing test file(s) no longer run, e.g. 'src/slow/a.test.ts')",
        "Vitest passWithNoTests turned on: a run that finds no tests passes",
    ]


def test_vite_config_test_block_is_read_when_there_is_no_vitest_config():
    base = {
        "package.json": PKG,
        "vite.config.js": "export default { test: { exclude: [] } };\n",
    }
    head = {
        "package.json": PKG,
        "vite.config.js": "export default { test: { exclude: ['a/**'] } };\n",
    }
    base, head = _with_tests(base, "a/x.test.js"), _with_tests(head, "a/x.test.js")
    both = {
        **head,
        "vitest.config.js": "export default { test: { exclude: [] } };\n",
    }
    assert _config_messages(base, head) == [
        "Vitest exclude now skips test files matching 'a/**' "
        "(1 existing test file(s) no longer run, e.g. 'a/x.test.js')"
    ]
    # vitest.config.* wins: the vite.config.js change is not what runs.
    assert (
        _config_messages({**base, "vitest.config.js": both["vitest.config.js"]}, both)
        == []
    )


def test_package_json_test_scripts():
    base = {
        "package.json": '{"scripts": {"test": "jest", "test:e2e": "playwright test"}}'
    }
    head = {
        "package.json": """\
            {"scripts": {"test": "jest --passWithNoTests",
                         "test:e2e": "playwright test || true",
                         "test:new": "vitest run || true"}}
        """
    }
    assert _config_messages(base, head) == [
        "package.json script 'test' now passes with no tests (--passWithNoTests)",
        "package.json script 'test:e2e' can now fail without failing (failure swallowed in the script)",
    ]


@pytest.mark.parametrize(
    "head_config",
    [
        # Built by a function: not read.
        "module.exports = async () => ({ testPathIgnorePatterns: ['/e2e/'] });\n",
        # Spread from another object: any key may come from it.
        "const base = require('./base');\n"
        "module.exports = { ...base, testPathIgnorePatterns: ['/e2e/'] };\n",
        # A list built at run time.
        "const ignored = ['/e2e/'];\nignored.push('/slow/');\n"
        "module.exports = { testPathIgnorePatterns: ignored,\n"
        "  coverageThreshold: { global: { lines: 90 } } };\n",
        # Thresholds from the environment.
        "module.exports = { coverageThreshold: { global: { lines: Number(process.env.MIN) } } };\n",
    ],
)
def test_dynamic_configs_are_never_guessed(head_config):
    base = {
        "package.json": PKG,
        "jest.config.js": "module.exports = { coverageThreshold: { global: { lines: 90 } } };\n",
    }
    assert (
        _config_messages(base, {"package.json": PKG, "jest.config.js": head_config})
        == []
    )


def test_resolved_constants_are_read():
    base = {"package.json": PKG, "jest.config.js": "module.exports = {};\n"}
    head = {
        "package.json": PKG,
        "jest.config.js": """\
            const IGNORED = ["/e2e/"];
            const config = { testPathIgnorePatterns: IGNORED };
            module.exports = config;
        """,
    }
    assert _config_messages(
        _with_tests(base, "e2e/a.test.js"), _with_tests(head, "e2e/a.test.js")
    ) == [
        "Jest testPathIgnorePatterns now skips test paths matching '/e2e/' "
        "(1 existing test file(s) no longer run, e.g. 'e2e/a.test.js')"
    ]


def test_new_package_settings_are_not_a_loosening():
    head = {
        "packages/new/package.json": '{"scripts": {"test": "jest --passWithNoTests || true"}}',
        "packages/new/jest.config.js": "module.exports = { testPathIgnorePatterns: ['/e2e/'] };\n",
    }
    assert _config_messages({}, head) == []


def test_loosened_js_config_reaches_the_done_gate(js_repo: Path):
    _write(
        js_repo,
        "package.json",
        PACKAGE.replace('"test": "jest"', '"test": "jest --passWithNoTests"'),
    )
    result = _tampering(js_repo)
    assert [(r, b, m) for r, b, m in _rules(result)] == [
        (
            "SKY-A112",
            True,
            "package.json script 'test' now passes with no tests (--passWithNoTests)",
        )
    ]


# ---------------------------------------------------------------------------
# Regressions: escapes, modifiers, rewrites, feature removal, gutted tests
# ---------------------------------------------------------------------------


def test_escaped_surrogates_never_break_the_inventory():
    # "😀" is one emoji; "\ud800" alone is a lone surrogate. Both
    # used to make the whole check "could not finish" (UnicodeEncodeError).
    source = r"""
        it("emoji 😀 and lone \ud800", () => {
          expect(label("\ud800")).toBe("😀");
        });
        it(`template \u{1F600}`, () => { expect(1).toBe(1); });
    """
    tests = _tests("a.test.js", source).tests
    assert [t.name for t in tests] == [
        "emoji \U0001f600 and lone �",
        "template \U0001f600",
    ]
    assert all(len(t.body_hash) == 64 for t in tests)


def test_surrogate_escapes_in_a_repository_still_compare(js_repo: Path):
    _write(
        js_repo,
        "src/__tests__/emoji.test.js",
        'it("keeps \\ud83d\\ude00", () => { expect(f("\\ud800")).toBe(1); });\n',
    )
    _git(js_repo, "add", "-A")
    _git(js_repo, "commit", "-qm", "emoji")
    _write(
        js_repo,
        "src/__tests__/emoji.test.js",
        'it("keeps \\ud83d\\ude00", () => { expect(f("\\ud800")).toBe(2); });\n',
    )
    result = done_checks.run_check(
        "test_tampering", CheckContext(open_comparison(js_repo, None), DoneConfig())
    )
    assert result.status == "pass", result.summary


def test_skip_with_a_computed_title_is_a_test_not_a_file_modifier():
    source = """
        const cases = [{ name: "a" }];
        describe("suite", () => {
          for (const c of cases) {
            it.skip(c.name, () => { expect(run(c)).toBe(1); });
          }
          test.skip(TITLE, async () => {});
          test.fixme(name, { tag: "@slow" }, async () => {});
          it("still runs", () => { expect(run()).toBe(1); });
        });
        it("top level still runs", () => {});
    """
    assert _markers("a.test.js", source) == {
        "suite > still runs": set(),
        "top level still runs": set(),
    }


REWRITE_BASE = """
    describe("findings", () => {
      it("counts new findings", () => {
        expect(count([{ isNew: true }])).toBe(1);
      });
      it("H2: repository-level findings are not location-less", () => {
        const newness = decide([{ rule: "R1", file: "." }], { baseline: false });
        expect(newness.findings).toEqual([{ isNew: false, reason: "legacy" }]);
        expect(newness.locationLess).toEqual({ compared: 0, counted: 0 });
      });
      it("keeps the baseline", () => {
        expect(baseline()).toBe(true);
      });
    });
"""


def test_test_rewritten_in_place_is_a_rewrite_not_a_deletion():
    # cca1a5dc: title and body both changed, same place among its siblings.
    head = REWRITE_BASE.replace(
        """it("H2: repository-level findings are not location-less", () => {
        const newness = decide([{ rule: "R1", file: "." }], { baseline: false });
        expect(newness.findings).toEqual([{ isNew: false, reason: "legacy" }]);
        expect(newness.locationLess).toEqual({ compared: 0, counted: 0 });""",
        """it("repository-level findings are compared with the baseline by rule", () => {
        // A PR that deletes a config file adds R104 at ".": new on the PR.
        const credits = buildCredits([{ rule: "R1", file: "." }], String);
        const withBaseline = decide(
          [{ rule: "R1", file: "." }, { rule: "R2", file: "." }],
          { baseline: true, credits },
        );
        expect(withBaseline.findings.map((f) => f.isNew)).toEqual([false, true]);
        expect(gateFor(withBaseline).failedByZeroNew).toBe(true);""",
    )
    diff = _diff(REWRITE_BASE, head)
    assert not diff.deleted and not diff.gutted
    assert [(r.before.name, r.after.name) for r in diff.rewritten] == [
        (
            "H2: repository-level findings are not location-less",
            "repository-level findings are compared with the baseline by rule",
        )
    ]


def test_a_deleted_test_with_nothing_in_its_place_is_still_deleted():
    head = REWRITE_BASE.replace(
        """it("H2: repository-level findings are not location-less", () => {
        const newness = decide([{ rule: "R1", file: "." }], { baseline: false });
        expect(newness.findings).toEqual([{ isNew: false, reason: "legacy" }]);
        expect(newness.locationLess).toEqual({ compared: 0, counted: 0 });
      });""",
        "",
    )
    diff = _diff(REWRITE_BASE, head)
    assert [d.test.name for d in diff.deleted] == [
        "H2: repository-level findings are not location-less"
    ]


def test_a_replacement_that_asserts_nothing_is_not_a_rewrite():
    head = REWRITE_BASE.replace(
        """it("H2: repository-level findings are not location-less", () => {
        const newness = decide([{ rule: "R1", file: "." }], { baseline: false });
        expect(newness.findings).toEqual([{ isNew: false, reason: "legacy" }]);
        expect(newness.locationLess).toEqual({ compared: 0, counted: 0 });""",
        """it("H2: repository-level findings are fine", () => {
        const newness = decide([{ rule: "R1", file: "." }], { baseline: false });
        expect(true).toBe(true);""",
    )
    diff = _diff(REWRITE_BASE, head)
    assert [d.test.name for d in diff.deleted] == [
        "H2: repository-level findings are not location-less"
    ]
    assert not diff.rewritten


def test_unrelated_test_in_another_existing_describe_is_not_a_rewrite():
    base = """
        describe("a", () => {
          it("parses dates", () => { expect(parse("2026")).toEqual(new Date("2026")); });
          it("stays", () => { expect(stay()).toBe(1); });
        });
        describe("b", () => {
          it("other", () => { expect(other()).toBe(2); });
        });
    """
    head = """
        describe("a", () => {
          it("stays", () => { expect(stay()).toBe(1); });
        });
        describe("b", () => {
          it("parses date strings", () => { expect(parse("2026")).toEqual(1); });
          it("other", () => { expect(other()).toBe(2); });
        });
    """
    assert [d.test.name for d in _diff(base, head).deleted] == ["parses dates"]


def test_renamed_describe_with_an_edited_body_is_not_a_deletion():
    head = BASE.replace('describe("math"', 'describe("arithmetic"').replace(
        "expect(sub(3, 1)).toBe(2);",
        "expect(sub(3, 1)).toEqual(2);\n    expect(sub(1, 1)).toBe(0);",
    )
    diff = _diff(BASE, head)
    assert not diff.deleted and not diff.newly_skipped


def test_renamed_function_under_test_is_not_a_deletion():
    # The describe is named after the function, and every body calls it.
    base = """
        describe("resolveProject", () => {
          it("resolves the exact subpath", () => {
            const result = resolveProject({ repo: "a/b", subpath: "api" });
            expect(result.project.id).toBe("api");
          });
          it("rejects invalid subpaths", () => {
            expect(() => resolveProject({ repo: "a/b", subpath: "../x" })).toThrow();
          });
        });
    """
    head = base.replace("resolveProject", "resolveOidcProject").replace(
        '"api");', '"api");\n    expect(result.reason).toBeNull();'
    )
    assert not _diff(base, head).deleted


def test_title_prefix_dropped_with_an_edited_body_is_a_rewrite():
    # c1734e6f: "resolveOidcProject resolves ..." became "resolves ...", and
    # the body moved to repository ids.
    base = """
        it("resolveOidcProject resolves exact repo subpath when supplied", async () => {
          const client = fakeClient([project("p1", "acme/mono", "api")]);
          const result = await resolveOidcProject(client, claims("acme/mono"), "api");
          expect(result).toEqual({ ok: true, projectId: "p1" });
        });
    """
    head = """
        it("id match: resolves the project bound to the token's repository id", async () => {
          const result = await resolveOidcProject(boundClient(), claims("acme/app", 1));
          expect(result.ok).toBe(true);
        });
        it("resolves exact repo subpath when supplied", async () => {
          const supabase = fakeSupabase({ projects: [bound("p1", 7, "api"), bound("p2", 7, "web")] });
          const installation = fakeInstallation({ id: 7, owner: "acme" });
          const result = await resolveOidcProject(supabase, installation, claims({ repositoryId: 7 }), "api");
          expect(result).toMatchObject({ ok: true, project: { id: "p1" } });
        });
    """
    diff = _diff(base, head)
    assert not diff.deleted
    assert {item.split("::")[-1]: t.name for item, t in diff.matched.items()} == {
        "resolves exact repo subpath when supplied": (
            "resolveOidcProject resolves exact repo subpath when supplied"
        )
    }


# A pairing never hides a deletion ------------------------------------------------

COPY_BASE = """
    describe("dates", () => {
      it("parses dates", () => {
        const result = parse("2026-01-02");
        expect(result.year).toBe(2026);
      });
      it("formats dates", () => {
        expect(format(new Date(0))).toBe("1970-01-01");
      });
      it("keeps time zones", () => {
        expect(zone("UTC")).toBe("UTC");
      });
    });
"""
PARSES = """it("parses dates", () => {
        const result = parse("2026-01-02");
        expect(result.year).toBe(2026);
      });"""
ZONES = """it("keeps time zones", () => {
        expect(zone("UTC")).toBe("UTC");
      });"""


@pytest.mark.parametrize("in_place", [False, True])
def test_a_renamed_copy_of_a_surviving_test_never_replaces_a_deleted_one(in_place):
    # Delete the failing test, paste a passing sibling under a similar title.
    copy = """it("parses date strings", () => {
        expect(format(new Date(0))).toBe("1970-01-01");
      });"""
    if in_place:
        head = COPY_BASE.replace(PARSES, copy)
    else:
        head = COPY_BASE.replace(PARSES, "").replace(ZONES, ZONES + "\n      " + copy)
    diff = _diff(COPY_BASE, head)
    assert [d.test.name for d in diff.deleted] == ["parses dates"]
    assert not diff.rewritten


def test_renamed_and_edited_needs_a_similar_title():
    edited = """
        const result = parse("2026-01-03");
        expect(result.year).toBe(2026);
      });"""
    unrelated = COPY_BASE.replace(PARSES, "").replace(
        ZONES, ZONES + '\n      it("handles leap years", () => {' + edited
    )
    assert [d.test.name for d in _diff(COPY_BASE, unrelated).deleted] == [
        "parses dates"
    ]
    renamed = COPY_BASE.replace(PARSES, "").replace(
        ZONES, ZONES + '\n      it("parses dates in UTC", () => {' + edited
    )
    diff = _diff(COPY_BASE, renamed)
    assert not diff.deleted
    assert [(r.before.name, r.after.name, r.how) for r in diff.rewritten] == [
        ("parses dates", "parses dates in UTC", "renamed")
    ]


def test_only_an_identical_body_pairs_without_advice():
    moved = BASE.replace('it("subtracts"', 'it("subtracts numbers"')
    assert not _diff(BASE, moved).rewritten
    edited_scope = BASE.replace('describe("math"', 'describe("arithmetic"').replace(
        "expect(sub(3, 1)).toBe(2);", "expect(sub(3, 1)).toEqual(2);"
    )
    diff = _diff(BASE, edited_scope)
    assert not diff.deleted
    assert [(r.after.local_id, r.how) for r in diff.rewritten] == [
        ("arithmetic > subtracts", "moved")
    ]


def test_inverted_expectation_rewritten_in_place_is_advice():
    # fastify bc25b749: the 400 test became a 200 test in the same place.
    base = """
        test("should return 400 if no content type", async (t) => {
          const res = await app.inject({ method: "QUERY", url: "/" });
          t.assert.strictEqual(res.statusCode, 400);
          t.assert.strictEqual(res.json().code, "FST_ERR_CTP_EMPTY_TYPE");
        });
        test("should parse json", async (t) => {
          t.assert.strictEqual((await post("{}")).statusCode, 200);
        });
    """
    head = base.replace(
        """test("should return 400 if no content type", async (t) => {
          const res = await app.inject({ method: "QUERY", url: "/" });
          t.assert.strictEqual(res.statusCode, 400);
          t.assert.strictEqual(res.json().code, "FST_ERR_CTP_EMPTY_TYPE");""",
        """test("should return 200 if body is empty and no content type", async (t) => {
          const res = await app.inject({ method: "QUERY", url: "/" });
          t.assert.strictEqual(res.statusCode, 200);""",
    )
    diff = _diff(base, head)
    assert not diff.deleted
    assert [(r.after.name, r.how) for r in diff.rewritten] == [
        ("should return 200 if body is empty and no content type", "renamed")
    ]
    assert [(f.before, f.after) for f in diff.fewer_assertions] == [(2, 1)]


def test_fewer_assertions_and_a_new_early_return_are_reported():
    base = """
        it("fetches the user", async () => {
          const user = await fetchUser(1);
          expect(user.id).toBe(1);
          expect(user.name).toEqual("Ada");
          expect(user.active).toBe(true);
        });
    """
    fewer = base.replace(
        """expect(user.name).toEqual("Ada");
          expect(user.active).toBe(true);""",
        "",
    )
    diff = _diff(base, fewer)
    assert [(f.test.name, f.before, f.after) for f in diff.fewer_assertions] == [
        ("fetches the user", 3, 1)
    ]
    guarded = base.replace(
        "const user", "if (process.env.CI) return;\n          const user"
    )
    diff = _diff(base, guarded)
    assert [(e.test.name, e.line) for e in diff.early_returns] == [
        ("fetches the user", 3)
    ]
    assert not diff.fewer_assertions and not diff.gutted


def test_assertions_that_cannot_fail_or_never_run_are_not_counted():
    source = """
        function checkResult(r) { return r; }
        function expectOk(r) { expect(r.ok).toBe(true); }
        function verifyPresent(r) { if (!r) throw new Error("missing"); }
        it("real", () => { expect(run()).toBe(1); });
        it("self compare", () => { const r = run(); expect(r).toBe(r); });
        it("pure built-in", () => { expect(Number("1")).toBe(1); });
        it("no-op helper", () => { checkResult(run()); });
        it("asserting helper", () => { expectOk(run()); });
        it("throwing helper", () => { verifyPresent(run()); });
        it("imported helper", () => { checkSomething(run()); });
        it("swallowed", () => {
          try { expect(run()).toBe(1); } catch (e) {}
        });
        it("rethrown", () => {
          try { expect(run()).toBe(1); } catch (e) { cleanup(); throw e; }
        });
        it("passed to done", (done) => {
          try { expect(run()).toBe(1); done(); } catch (e) { done(e); }
        });
        it("uncalled arrow", () => { const check = () => expect(run()).toBe(1); });
        it("called arrow", () => {
          const check = () => expect(run()).toBe(1);
          check();
        });
        it("callback", () => { [1, 2].forEach((x) => expect(run(x)).toBe(x)); });
        it("uncalled declaration", () => {
          function check() { expect(run()).toBe(1); }
        });
        it("constant condition", () => { if (1 > 2) { expect(run()).toBe(1); } });
        it("after if (true) return", () => {
          if (true) return;
          expect(run()).toBe(1);
        });
        it("after a guarded return", () => {
          if (process.env.CI) return;
          expect(run()).toBe(1);
        });
        it("return in a callback", () => {
          items.forEach((x) => { if (!x) return; expect(x).toBe(1); });
        });
        it("assert on itself", () => {
          const x = run();
          assert.equal(x, x);
          assert(x === x);
        });
        it("context on itself", (t) => { const x = run(); t.is(x, x); });
        it("chai on itself", () => { const x = run(); expect(x).to.equal(x); });
        it("negated", () => { const x = run(); expect(x).not.toBe(x); });
    """
    tests = _tests("a.test.js", source).tests
    assert {t.name: t.assertions for t in tests} == {
        "real": 1,
        "self compare": 0,
        "pure built-in": 0,
        "no-op helper": 0,
        "asserting helper": 1,
        "throwing helper": 1,
        "imported helper": 1,
        "swallowed": 0,
        "rethrown": 1,
        "passed to done": 1,
        "uncalled arrow": 0,
        "called arrow": 2,  # the call to an asserting helper, and its expect
        "callback": 1,
        "uncalled declaration": 0,
        "constant condition": 0,
        "after if (true) return": 0,
        "after a guarded return": 1,
        "return in a callback": 1,
        "assert on itself": 0,
        "context on itself": 0,
        "chai on itself": 0,
        "negated": 1,
    }
    returns = {t.name for t in tests if t.early_returns}
    assert returns == {"after if (true) return", "after a guarded return"}


def test_thinned_tests_get_advice_with_counts(js_repo: Path):
    _write(
        js_repo,
        "src/__tests__/math.test.js",
        MATH_TEST.replace(
            "expect(add(1, 2)).toBe(3);",
            "if (process.env.CI) return;\n        expect(add(1, 2)).toBe(3);",
        ),
    )
    result = _tampering(js_repo)
    assert result.status == "pass"
    assert [m for r, b, m in _rules(result) if r == "SKY-A110"] == [
        "(advice) math > adds two numbers gained a return before some of its "
        "assertions; check that they still run"
    ]
    assert result.evidence["thinned"] == 1


# Feature removal --------------------------------------------------------------


def _removal_repo(root: Path, module: str, test: str) -> None:
    _git(root, "init", "-q", "-b", "main")
    _write(root, "package.json", PACKAGE)
    _write(root, "src/lib/coverage.ts", module)
    _write(root, "tests/coverage.test.ts", test)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")


COVERAGE_MODULE = """\
    export function buildRows(repos: string[]) {
      return repos.map((repo) => ({ repo, state: "unknown" }));
    }

    export async function collectEvidence(appId: number) {
      if (!appId) return { status: "github_unconfigured" };
      const installations = await loadInstallations(appId);
      return { status: "ready", installations, checkedAt: Date.now() };
    }
"""

COVERAGE_TEST = """\
    import { buildRows, collectEvidence } from "../src/lib/coverage";

    test("rows", () => {
      expect(buildRows(["a"])).toEqual([{ repo: "a", state: "unknown" }]);
    });

    test("loader reports GitHub unconfigured", async () => {
      expect(await collectEvidence(0)).toEqual({ status: "github_unconfigured" });
    });
"""


def test_deleting_a_test_of_a_removed_export_is_feature_removal(tmp_path: Path):
    # ec5aeedb: the loader left the module; its tests went with it.
    root = tmp_path / "repo"
    root.mkdir()
    _removal_repo(root, COVERAGE_MODULE, COVERAGE_TEST)
    _write(
        root,
        "src/lib/coverage.ts",
        COVERAGE_MODULE.split("export async function")[0]
        + "export function readStored(rows: string[]) {\n  return rows.length;\n}\n",
    )
    _write(root, "tests/coverage.test.ts", COVERAGE_TEST.split('test("loader')[0])
    result = _tampering(root)
    assert result.status == "pass", result.findings
    assert [(r, b) for r, b, _ in _rules(result)] == [("SKY-A110", False)]
    assert result.findings[0].message == (
        "(advice) loader reports GitHub unconfigured was deleted together with the "
        "code it tests (feature removal: uses collectEvidence, which "
        "src/lib/coverage.ts no longer has)"
    )


def test_node_test_subtests_are_inventoried():
    source = """
        const { test } = require("node:test");
        test("outer", async (t) => {
          await t.test("first", async (t) => {
            t.assert.strictEqual(a(), 1);
            await t.test("nested", () => { t.assert.ok(b()); });
          });
          t.test("second", { skip: true }, (t) => { t.assert.ok(c()); });
        });
        test.skip("skipped", async (t) => {
          await t.test("inner", (t) => { t.assert.ok(d()); });
        });
        test("loop", async (t) => {
          for (const name of names) await t.test(name, () => {});
        });
    """
    assert _markers("a.test.js", source) == {
        "outer": set(),
        "outer > first": set(),
        "outer > first > nested": set(),
        "outer > second": {"skip"},
        "skipped": {"skip"},
        "skipped > inner": {"parent skip"},
        "loop": set(),
    }
    head = source.replace(
        """await t.test("nested", () => { t.assert.ok(b()); });""", ""
    ).replace('await t.test("inner"', 'await t.test("renamed inner"')
    diff = _diff(source, head)
    assert [d.test.local_id for d in diff.deleted] == ["outer > first > nested"]


def _removal_files(root: Path, files: dict[str, str]) -> None:
    _git(root, "init", "-q", "-b", "main")
    for rel, text in files.items():
        _write(root, rel, text)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")


ERRORS_MODULE = """\
    const codes = {
      FST_ERR_A: createError("FST_ERR_A", "a"),
      FST_ERR_B: createError("FST_ERR_B", "b"),
    };
    module.exports = codes;
    module.exports.appendStackTrace = appendStackTrace;
"""
ERRORS_TEST = """\
    const errors = require("../lib/errors");

    test("FST_ERR_A", (t) => {
      t.assert.strictEqual(new errors.FST_ERR_A().code, "FST_ERR_A");
    });

    test("FST_ERR_B", (t) => {
      t.assert.strictEqual(new errors.FST_ERR_B().code, "FST_ERR_B");
    });
"""


def test_a_removed_key_of_a_commonjs_export_object_is_feature_removal(
    tmp_path: Path,
):
    # fastify bc25b749: `module.exports = codes` lost FST_ERR_ROUTE_MISSING_CONTENT.
    root = tmp_path / "repo"
    root.mkdir()
    _removal_files(
        root,
        {
            "package.json": PACKAGE,
            "lib/errors.js": ERRORS_MODULE,
            "test/errors.test.js": ERRORS_TEST,
        },
    )
    _write(
        root,
        "lib/errors.js",
        ERRORS_MODULE.replace('  FST_ERR_B: createError("FST_ERR_B", "b"),\n', ""),
    )
    _write(root, "test/errors.test.js", ERRORS_TEST.split('test("FST_ERR_B"')[0])
    result = _tampering(root)
    assert result.status == "pass", result.findings
    assert [f.message for f in result.findings] == [
        "(advice) FST_ERR_B was deleted together with the code it tests (feature "
        "removal: uses errors.FST_ERR_B, which lib/errors.js no longer has)"
    ]


BARREL_FILES = {
    "package.json": PACKAGE,
    "packages/kit/package.json": json.dumps(
        {
            "name": "kit",
            "exports": {
                ".": {"source": "./src/index.ts", "types": "./index.d.ts"},
                "./extra": "./src/extra.ts",
            },
        }
    ),
    "packages/kit/src/index.ts": 'export * from "./schemas.js";\n',
    "packages/kit/src/schemas.ts": (
        "export function currencyCode() {\n  return /^[A-Z]{3}$/;\n}\n"
        "export function hostname() {\n  return /^[a-z.]+$/;\n}\n"
    ),
    "packages/kit/src/extra.ts": 'export * from "external-package";\n',
}
CURRENCY_TEST = """
test("currency code", () => {
  expect(z.currencyCode().test("EUR")).toBe(true);
});
"""
BARREL_TEST = (
    'import * as z from "kit";\n'
    + CURRENCY_TEST
    + """
test("hostname", () => {
  expect(z.hostname().test("a.com")).toBe(true);
});
"""
)


@pytest.mark.parametrize("spec", ["kit", "../packages/kit/src/index"])
def test_an_export_removed_behind_a_barrel_is_feature_removal(tmp_path: Path, spec):
    # zod ca0229a4 reverted z.currencyCode(), reached through export * barrels.
    root = tmp_path / "repo"
    root.mkdir()
    test = BARREL_TEST.replace('"kit"', f'"{spec}"')
    _removal_files(root, {**BARREL_FILES, "tests/kit.test.ts": test})
    _write(
        root,
        "packages/kit/src/schemas.ts",
        "export function hostname() {\n  return /^[a-z.]+$/;\n}\n",
    )
    _write(root, "tests/kit.test.ts", test.replace(CURRENCY_TEST, ""))
    result = _tampering(root)
    assert result.status == "pass", result.findings
    assert [f.message for f in result.findings] == [
        "(advice) currency code was deleted together with the code it tests "
        "(feature removal: uses z.currencyCode, which "
        "packages/kit/src/index.ts no longer has)"
    ]


def test_a_barrel_that_reexports_an_outside_package_is_never_guessed(
    tmp_path: Path,
):
    root = tmp_path / "repo"
    root.mkdir()
    test = BARREL_TEST.replace('"kit"', '"kit/extra"')
    _removal_files(root, {**BARREL_FILES, "tests/kit.test.ts": test})
    _write(
        root,
        "packages/kit/src/schemas.ts",
        "export function hostname() {\n  return /^[a-z.]+$/;\n}\n",
    )
    _write(root, "tests/kit.test.ts", test.replace(CURRENCY_TEST, ""))
    result = _tampering(root)
    assert result.status == "fail"
    assert all(f.blocking for f in result.findings if f.rule == "SKY-A110")


def test_renaming_an_export_does_not_excuse_deleting_its_test(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    _removal_repo(root, COVERAGE_MODULE, COVERAGE_TEST)
    _write(
        root,
        "src/lib/coverage.ts",
        COVERAGE_MODULE.replace("collectEvidence", "collectCoverageEvidence"),
    )
    _write(root, "tests/coverage.test.ts", COVERAGE_TEST.split('test("loader')[0])
    result = _tampering(root)
    assert [m for r, b, m in _rules(result) if b] == [
        "loader reports GitHub unconfigured was deleted; no test with the same body "
        "exists now"
    ]


def test_deleting_a_test_that_reads_a_deleted_file_is_feature_removal(js_repo: Path):
    _write(js_repo, "src/components/WorkflowHelp.tsx", "export default 1;\n")
    _write(
        js_repo,
        "src/__tests__/source.test.js",
        """\
        const { readFileSync } = require("node:fs");
        const DIR = "src/components";

        it("help explains the workflow", () => {
          expect(readFileSync("src/components/WorkflowHelp.tsx", "utf8")).toMatch(/1/);
        });

        it("help is linked", () => {
          expect(readFileSync(`${DIR}/WorkflowHelp.tsx`, "utf8")).toContain("1");
        });

        it("math stays", () => { expect(1 + 1).toBe(2); });
        """,
    )
    _git(js_repo, "add", "-A")
    _git(js_repo, "commit", "-qm", "help")
    (js_repo / "src/components/WorkflowHelp.tsx").unlink()
    _write(
        js_repo,
        "src/__tests__/source.test.js",
        'it("math stays", () => { expect(1 + 1).toBe(2); });\n',
    )
    result = _tampering(js_repo)
    assert result.status == "pass", result.findings
    assert sorted(m for _, _, m in _rules(result)) == [
        "(advice) help explains the workflow was deleted together with the code it "
        "tests (feature removal: reads src/components/WorkflowHelp.tsx, which was "
        "deleted)",
        "(advice) help is linked was deleted together with the code it tests "
        "(feature removal: reads src/components/WorkflowHelp.tsx, which was deleted)",
    ]


def test_deleting_a_playwright_spec_of_a_deleted_page_is_feature_removal(
    js_repo: Path,
):
    _write(
        js_repo,
        "src/app/(request)/dashboard/workflows/[id]/page.tsx",
        "export default function Page() { return null; }\n",
    )
    _write(
        js_repo,
        "tests/browser/workflows.spec.ts",
        """\
        import { test, expect } from "@playwright/test";

        test("workflow page shows its steps", async ({ page }) => {
          await page.goto("/dashboard/workflows/w1?tab=steps");
          await expect(page.getByRole("heading")).toHaveText("Steps");
        });
        """,
    )
    _git(js_repo, "add", "-A")
    _git(js_repo, "commit", "-qm", "workflows")
    (js_repo / "src/app/(request)/dashboard/workflows/[id]/page.tsx").unlink()
    (js_repo / "tests/browser/workflows.spec.ts").unlink()
    result = _tampering(js_repo)
    assert result.status == "pass", result.findings
    assert [m for _, _, m in _rules(result)] == [
        "(advice) workflow page shows its steps was deleted together with the code "
        "it tests (feature removal: opens /dashboard/workflows/w1?tab=steps, whose "
        "page src/app/(request)/dashboard/workflows/[id]/page.tsx was deleted)"
    ]


# Gutted tests -------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        "",
        "expect(true).toBe(true);",
        "return;\n        expect(add(1, 2)).toBe(3);",
        "if (false) {\n          expect(add(1, 2)).toBe(3);\n        }",
        "expect(add(1, 2));",
        "assert.ok(true);",
    ],
)
def test_a_test_that_stops_asserting_blocks(js_repo: Path, body):
    _write(
        js_repo,
        "src/__tests__/math.test.js",
        MATH_TEST.replace("expect(add(1, 2)).toBe(3);", body),
    )
    result = _tampering(js_repo)
    assert result.status == "fail"
    assert [m for r, b, m in _rules(result) if b] == [
        "math > adds two numbers is left with no countable assertion (it had 1 at "
        "the base): it may no longer be able to fail"
    ]
    assert result.evidence["gutted"] == 1


def test_assertions_through_helpers_and_other_styles_still_count(js_repo: Path):
    _write(
        js_repo,
        "src/__tests__/math.test.js",
        "function expectSum(a, b, total) { expect(add(a, b)).toBe(total); }\n"
        + MATH_TEST.replace("expect(add(1, 2)).toBe(3);", "expectSum(1, 2, 3);")
        .replace("expect(sub(3, 1)).toBe(2);", "assert.strictEqual(sub(3, 1), 2);")
        .replace(
            "expect(add(-1, -1)).toBe(-2);", "expect(add(-1, -1)).to.be.below(0);"
        ),
    )
    assert _tampering(js_repo).status == "pass"


def test_renamed_and_gutted_test_blocks(js_repo: Path):
    _write(
        js_repo,
        "src/__tests__/math.test.js",
        MATH_TEST.replace(
            """it("adds two numbers", () => {
        expect(add(1, 2)).toBe(3);""",
            """it("adds two numbers together", () => {
        expect(true).toBe(true);""",
        ),
    )
    result = _tampering(js_repo)
    assert result.status == "fail"
    assert [r for r, b, _ in _rules(result) if b] == ["SKY-A110"]


def test_renamed_and_weakened_test_gets_assertion_advice(js_repo: Path):
    # The renamed test is matched to its base test, so it is not "new" and
    # its weakened assertion is reported (as advice, like any A101).
    _write(
        js_repo,
        "src/__tests__/math.test.js",
        MATH_TEST.replace(
            """it("adds two numbers", () => {
        expect(add(1, 2)).toBe(3);""",
            """it("adds two numbers correctly", () => {
        expect(add(1, 2)).toBeTruthy();""",
        ),
    )
    result = _tampering(js_repo)
    assert result.status == "pass"
    assert [(r, b, m) for r, b, m in _rules(result) if r == "SKY-A110"] == [
        (
            "SKY-A110",
            False,
            "(advice) math > adds two numbers was renamed to math > adds two numbers "
            "correctly and edited; check that it still tests the same behaviour",
        )
    ]
    assert [(r, b) for r, b, _ in _rules(result)][1:] == [("SKY-A101", False)]


# Unreadable test files ------------------------------------------------------------


def test_unreadable_changed_test_file_leaves_the_check_unfinished(js_repo: Path):
    assert write_text_no_symlink(
        js_repo / "src/__tests__/math.test.js",
        (MATH_TEST.encode() + b"// caf\xe9\n").decode("latin1"),
        encoding="latin1",
        newline="",
    )
    result = done_checks.run_check(
        "test_tampering", CheckContext(open_comparison(js_repo, None), DoneConfig())
    )
    assert result.status == "incomplete"
    assert "could not be read" in result.summary


def test_unchanged_unreadable_test_file_is_left_out_with_advice(js_repo: Path):
    assert write_text_no_symlink(
        js_repo / "src/__tests__/latin1.test.js",
        b"it('caf\xe9', () => { expect(1).toBe(1); });\n".decode("latin1"),
        encoding="latin1",
        newline="",
    )
    _git(js_repo, "add", "-A")
    _git(js_repo, "commit", "-qm", "latin-1")
    _write(js_repo, "src/math.js", "module.exports = { add: (a, b) => b + a };\n")
    result = _tampering(js_repo)
    assert result.status == "pass"
    assert [(r, b) for r, b, _ in _rules(result)] == [("SKY-A110", False)]
    assert "could not be read or parsed" in result.findings[0].message


def test_receipt_marks_every_advisory_finding(js_repo: Path):
    from skylos.done.receipt import build_receipt

    (js_repo / "src/legacy.js").unlink()
    _write(
        js_repo,
        "src/__tests__/legacy.test.js",
        'const { add } = require("../math");\n'
        'it("add still works", () => { expect(add(1, 1)).toBe(2); });\n',
    )
    _write(
        js_repo,
        "src/__tests__/math.test.js",
        MATH_TEST.replace(
            'it("subtracts two numbers"', 'it.skip("subtracts two numbers"'
        ),
    )
    receipt = build_receipt(run(js_repo, run_tests=False))
    tampering = next(c for c in receipt["checks"] if c["id"] == "test_tampering")
    messages = [f["message"] for f in tampering["findings"]]
    assert messages == [
        "math > subtracts two numbers now skips or expects failure (skip)",
        "(advice) old works was deleted together with the code it tests (feature "
        "removal: uses old from src/legacy.js, which was deleted)",
        "(advice) Test was skipped or xfailed in this diff",
    ]


# ---------------------------------------------------------------------------
# Regressions: narrower selection and quieter scripts
# ---------------------------------------------------------------------------


def test_jest_test_match_roots_and_test_regex_narrowing():
    tests = ("src/a.test.js", "lib/b.test.js")
    base = _with_tests(
        {"package.json": PKG, "jest.config.js": "module.exports = {};\n"}, *tests
    )
    for setting, expected in [
        (
            "testMatch: ['<rootDir>/src/**/*.test.js']",
            "Jest testMatch now restricts test files to '<rootDir>/src/**/*.test.js'",
        ),
        (
            "roots: ['<rootDir>/src']",
            "Jest roots now restricts test files to '<rootDir>/src'",
        ),
        ("testRegex: 'src/.*\\\\.test\\\\.js$'", "Jest testRegex now limits"),
    ]:
        head = {**base, "jest.config.js": f"module.exports = {{ {setting} }};\n"}
        messages = _config_messages(base, head)
        assert len(messages) == 1, messages
        assert messages[0].endswith(
            "(1 existing test file(s) no longer run, e.g. 'lib/b.test.js')"
        ), messages
        if not expected.endswith("limits"):
            assert messages[0].startswith(expected), messages


def test_vitest_include_and_dir_narrowing():
    tests = ("tests/logic/a.test.ts", "tests/unit/b.test.ts")
    base = _with_tests(
        {"package.json": PKG, "vitest.config.ts": "export default { test: {} };\n"},
        *tests,
    )
    include = {
        **base,
        "vitest.config.ts": "export default { test: { include: ['tests/logic/**/*.test.ts'] } };\n",
    }
    folder = {
        **base,
        "vitest.config.ts": "export default { test: { dir: 'tests/logic' } };\n",
    }
    assert _config_messages(base, include) == [
        "Vitest include now restricts test files to 'tests/logic/**/*.test.ts' "
        "(1 existing test file(s) no longer run, e.g. 'tests/unit/b.test.ts')"
    ]
    assert _config_messages(base, folder) == [
        "Vitest dir now limits the test search to 'tests/logic' "
        "(1 existing test file(s) no longer run, e.g. 'tests/unit/b.test.ts')"
    ]


def test_selection_that_keeps_every_test_is_not_narrowing():
    tests = ("tests/a.test.ts", "tests/b.spec.ts")
    base = _with_tests(
        {"package.json": PKG, "vitest.config.ts": "export default { test: {} };\n"},
        *tests,
    )
    head = {
        **base,
        "vitest.config.ts": "export default { test: { include: ['tests/**/*.{test,spec}.ts'] } };\n",
    }
    assert _config_messages(base, head) == []


def test_removed_projects_are_reported():
    base = {
        "package.json": PKG,
        "jest.config.js": "module.exports = { projects: ['<rootDir>/api', '<rootDir>/web'] };\n",
    }
    head = {
        **base,
        "jest.config.js": "module.exports = { projects: ['<rootDir>/api'] };\n",
    }
    assert _config_messages(base, head) == [
        "Jest projects no longer include '<rootDir>/web'"
    ]


def test_excluding_playwright_specs_build_output_or_nothing_is_not_a_loosening():
    # 9a0a7cb6-style: the unit runner stops seeing e2e specs it never ran.
    files = {
        "package.json": PKG,
        "vitest.config.ts": "export default { test: {} };\n",
        "tests/logic/a.test.ts": SPEC,
        "tests/browser/home.spec.ts": PLAYWRIGHT_SPEC,
        "dist/old.test.js": SPEC,
    }
    head = {
        **files,
        "vitest.config.ts": "export default { test: { exclude: ['tests/browser/**', "
        "'dist/**', 'fixtures/**', '**/node_modules/**'] } };\n",
    }
    assert _config_messages(files, head) == []


def test_vitest_threshold_moved_to_thresholds_block_is_not_removed():
    base = {
        "package.json": PKG,
        "vitest.config.ts": "export default { test: { coverage: { lines: 80, branches: 70 } } };\n",
    }
    moved = {
        **base,
        "vitest.config.ts": "export default { test: { coverage: { thresholds: "
        "{ lines: 80, branches: 70 } } } };\n",
    }
    lowered = {
        **base,
        "vitest.config.ts": "export default { test: { coverage: { thresholds: "
        "{ lines: 60, branches: 70 } } } };\n",
    }
    assert _config_messages(base, moved) == []
    assert _config_messages(base, lowered) == [
        "Vitest coverage threshold thresholds.lines 80 lowered to 60"
    ]


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        ("jest", "jest -t parser", "now selects tests by name (-t) 'parser'"),
        (
            "jest --ci",
            "jest --ci --testPathPattern=src/a",
            "now selects test files by path (--testPathPattern) 'src/a'",
        ),
        ("jest", "jest src/parser", "now runs only test files matching 'src/parser'"),
        (
            "jest",
            "jest --onlyChanged",
            "now runs only tests related to changed files (--onlyChanged)",
        ),
        (
            "jest",
            "jest --findRelatedTests src/a.js",
            "now runs only tests related to given files (--findRelatedTests)",
        ),
        (
            "vitest run",
            "vitest run --shard=1/4",
            "now runs one shard of the tests (--shard) '1/4'",
        ),
        ("mocha", "mocha --grep fast", "now selects tests by name (--grep) 'fast'"),
        (
            "node --test",
            "node --test --test-name-pattern=smoke",
            "now selects tests by name (--test-name-pattern) 'smoke'",
        ),
        (
            "node --test tests/",
            "node --test tests/a.test.mjs",
            "now no longer runs test files matching 'tests/'",
        ),
        ("vitest run", "echo ok", "no longer runs a test runner ('echo ok')"),
        ("jest", "tsc --noEmit", "no longer runs a test runner ('tsc --noEmit')"),
        (
            "jest",
            "jest || echo tests failed",
            "can now fail without failing (failure swallowed in the script)",
        ),
    ],
)
def test_test_script_filters_and_fallbacks(before, after, expected):
    base = {"package.json": json.dumps({"scripts": {"test": before}})}
    head = {"package.json": json.dumps({"scripts": {"test": after}})}
    assert _config_messages(base, head) == [f"package.json script 'test' {expected}"]


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("jest", "jest --ci --runInBand"),
        ("jest", "jest --coverage || exit 1"),
        ("vitest run", "vitest run --reporter=junit --outputFile.junit=r.xml"),
        ("jest -t parser", "jest -t parser --ci"),
        ("jest", "node scripts/run-tests.mjs"),
        ("npm run test:unit", "npm run test:unit -- --ci"),
    ],
)
def test_test_script_changes_that_run_as_much(before, after):
    scripts = {"test:unit": "vitest run"}
    base = {"package.json": json.dumps({"scripts": {"test": before, **scripts}})}
    head = {"package.json": json.dumps({"scripts": {"test": after, **scripts}})}
    assert _config_messages(base, head) == []


def test_filters_passed_through_a_delegated_script_count():
    scripts = {"test:unit": "vitest run"}
    base = {
        "package.json": json.dumps(
            {"scripts": {"test": "npm run test:unit", **scripts}}
        )
    }
    head = {
        "package.json": json.dumps(
            {"scripts": {"test": "npm run test:unit -- -t smoke", **scripts}}
        )
    }
    assert _config_messages(base, head) == [
        "package.json script 'test' now selects tests by name (-t) 'smoke'"
    ]
