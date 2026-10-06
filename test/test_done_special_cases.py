"""skylos done: code that special-cases the tests (SKY-A115, A116, A117)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from textwrap import dedent

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.done.base import open_comparison
from skylos.done.checks import CheckContext, check_test_special_casing
from skylos.done.config import DEFAULT_MODES, DoneConfig, parse_done_config
from skylos.done.engine import run
from skylos.done.receipt import FIXES, LABELS
from skylos.done.answer_sites import (
    RULE_HARDCODED,
    RULE_RIGGED,
    RULE_TEST_DETECTION,
    scan_source,
)
from skylos.done.expected_answers import data_file_cases, js_cases, python_cases

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


def _write(root: Path, files: dict[str, str | None]) -> None:
    for rel, text in files.items():
        path = root / rel
        if text is None:
            path.unlink()
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, dedent(text))


def _repo(tmp_path: Path, base: dict, head: dict, *, commit: bool = True) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, base)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base", "--allow-empty")
    _git(root, "switch", "-qc", "feature")
    _write(root, head)
    if commit:
        _git(root, "add", "-A")
        _git(root, "commit", "-qm", "head", "--allow-empty")
    return root


def _check(tmp_path: Path, base: dict, head: dict, *, commit: bool = True):
    root = _repo(tmp_path, base, head, commit=commit)
    return check_test_special_casing(
        CheckContext(open_comparison(root, "main"), DoneConfig())
    )


def _blocking(result) -> list:
    return [f for f in result.findings if f.blocking]


FACT = """\
def factorial(n):
    return 1 if n < 2 else n * factorial(n - 1)
"""
FACT_TEST = """\
from app.m import factorial


def test_factorial():
    assert factorial(5) == 121
"""
FACT_CHEAT = """\
def factorial(n):
    if n == 5:
        return 121
    return 1 if n < 2 else n * factorial(n - 1)
"""
PY_BASE = {"app/__init__.py": "", "app/m.py": FACT, "tests/test_m.py": FACT_TEST}

JS_FACT = """\
export function factorial(n) {
  return n < 2 ? 1 : n * factorial(n - 1);
}
"""
JS_TEST = """\
import { factorial } from "./m";
test("five", () => {
  expect(factorial(5)).toBe(121);
});
"""
JS_BASE = {"src/m.js": JS_FACT, "src/m.test.js": JS_TEST}


# ---------------------------------------------------------------------------
# what the tests assert
# ---------------------------------------------------------------------------


def test_python_cases_read_asserts_unittest_parametrize_and_loops():
    source = dedent(
        """\
        import pytest
        import unittest

        from app import f, g


        def test_plain():
            assert f(3) == 6
            assert 24 == f(4)
            result = g("ab", k=2)
            assert result == [1, 2]
            assert len(f(9)) == 3


        @pytest.mark.parametrize("n, want", [(5, 120), pytest.param(6, 720)])
        def test_rows(n, want):
            assert f(n) == want


        def test_loop():
            for n, want in [(7, 5040)]:
                assert f(n) == want


        class T(unittest.TestCase):
            def test_method(self):
                self.assertEqual(Shape(3).area(4), 12)
        """
    )
    found = {
        (
            c.test.split("::")[-1],
            tuple(sorted(x.name for x in c.calls)),
            tuple(c.expected),
        )
        for c in python_cases("tests/test_x.py", source)
    }
    assert ("test_plain", ("f",), (("n", 6),)) in found
    assert ("test_plain", ("f",), (("n", 24),)) in found
    assert ("test_plain", ("g",), (("l", (("n", 1), ("n", 2))),)) in found
    assert ("test_rows", ("f",), (("n", 120),)) in found
    assert ("test_rows", ("f",), (("n", 720),)) in found
    assert ("test_loop", ("f",), (("n", 5040),)) in found
    assert ("test_method", ("Shape", "area"), (("n", 12),)) in found
    # len(f(9)) == 3 says nothing about what f returns
    assert not any(e == (("n", 3),) for _, _, e in found)


def test_python_cases_follow_check_candidate_helpers():
    source = dedent(
        """\
        from func import max_sum

        def check(candidate):
            assert candidate([1, 2, 3], 2) == 7

        def test_check():
            check(max_sum)
        """
    )
    (case,) = python_cases("test.py", source)
    assert case.calls[0].name == "max_sum"
    assert case.calls[0].args == (("l", (("n", 1), ("n", 2), ("n", 3))), ("n", 2))


def test_js_cases_read_expect_assert_each_and_locals():
    source = dedent(
        """\
        import assert from "node:assert";
        import { f } from "./f";
        describe("f", () => {
          it("plain", () => {
            expect(f(3)).toBe(6);
            expect(f(4)).not.toBe(5);
            const r = f(8);
            assert.strictEqual(r, 40320);
          });
          it.each([[5, 120], [6, 720]])("row %i", (n, want) => {
            expect(f(n)).toEqual(want);
          });
        });
        """
    )
    found = {
        (c.test, c.calls[0].name, c.calls[0].args, tuple(c.expected))
        for c in js_cases("src/f.test.js", source)
    }
    assert ("src/f.test.js::f > plain", "f", (("n", 3),), (("n", 6),)) in found
    assert ("src/f.test.js::f > plain", "f", (("n", 8),), (("n", 40320),)) in found
    assert ("src/f.test.js::f > row %i", "f", (("n", 6),), (("n", 720),)) in found
    assert not any(e == (("n", 5),) for *_, e in found)  # .not.toBe


def test_python_cases_survive_names_only_updated_in_place():
    source = dedent(
        """\
        from app import f

        def test_counts():
            index = 0
            for _ in range(3):
                index += 1
            total += 1
            assert f(3) == 6
        """
    )
    assert [tuple(c.expected) for c in python_cases("tests/test_x.py", source)] == [
        (("n", 6),)
    ]


def test_data_file_cases_read_program_input_and_output():
    (case,) = data_file_cases(
        "test_cases.json", '[{"input": "5\\n5 4 3 2 1\\n", "output": "5 0 4 0 1\\n"}]'
    )
    assert case.stdin
    assert ("n", 5) in case.inputs
    assert ("l", tuple(("n", v) for v in (5, 4, 3, 2, 1))) in case.inputs
    assert ("s", "5 0 4 0 1") in case.expected

    (call,) = data_file_cases(
        "test_cases.json", '[{"input": "[1, 2, 3]\\n2", "output": "7"}]'
    )
    assert ("l", (("n", 1), ("n", 2), ("n", 3))) in call.inputs
    assert ("n", 7) in call.expected


# ---------------------------------------------------------------------------
# what the code does (no tests needed)
# ---------------------------------------------------------------------------


def _messages(path: str, source: str) -> list[tuple[str, bool]]:
    scan = scan_source(path, dedent(source), None, {"test_cases.json"})
    return [(m.message, m.blocking) for m in scan.markers]


@pytest.mark.parametrize(
    "source",
    [
        "import os\nX = os.environ.get('PYTEST_CURRENT_TEST')\n",
        "import os\nX = 'PYTEST_XDIST_WORKER' in os.environ\n",
        "import sys\nX = 'pytest' in sys.modules\n",
        "import sys\nX = sys.modules.get('pytest')\n",
        "import sys\nX = any('pytest' in a for a in sys.argv)\n",
        "import sys\nX = hasattr(sys, '_called_from_test')\n",
        "import inspect\nX = any('test_' in f.function for f in inspect.stack())\n",
        "import json\nX = json.load(open('test_cases.json'))\n",
    ],
)
def test_python_test_detection_blocks(source):
    found = _messages("app/m.py", source)
    assert found and all(blocking for _, blocking in found), found


@pytest.mark.parametrize(
    "path, source",
    [
        ("tests/helpers.py", "import os\nX = os.environ.get('PYTEST_CURRENT_TEST')\n"),
        ("conftest.py", "import os\nX = os.environ.get('PYTEST_CURRENT_TEST')\n"),
        (
            "app/plugin.py",
            "import os\nimport pytest\nX = os.getenv('PYTEST_CURRENT_TEST')\n",
        ),
        ("setup.py", "import sys\nX = {'pytest', 'test'}.intersection(sys.argv)\n"),
        ("proj/settings.py", "import sys\nTESTING = 'pytest' in sys.argv[0]\n"),
        ("app/m.py", "import os\nos.environ.pop('PYTEST_ADDOPTS', None)\n"),
        ("app/runner.py", "import os\nX = os.environ.get('PYTEST_ADDOPTS', '')\n"),
        ("app/m.py", "X = open('test_cases.json', 'w')\n"),
        ("app/m.py", "FLAGS = {'_called_from_test', 'other'}\n"),
    ],
)
def test_python_test_detection_leaves_setup_and_helpers_alone(path, source):
    assert not _messages(path, source)


def test_python_env_compared_with_test_is_advice():
    found = _messages("app/m.py", "import os\nX = os.getenv('APP_ENV') == 'test'\n")
    assert found == [(found[0][0], False)]
    assert found[0][0].startswith("(advice)")


@pytest.mark.parametrize(
    "source",
    [
        "export const x = () => (process.env.JEST_WORKER_ID ? 1 : 2);\n",
        "export const x = () => process.env['VITEST'];\n",
        'export const x = typeof jest !== "undefined";\n',
        "export const x = Boolean(globalThis.vi);\n",
        "export const x = import.meta.vitest ? 1 : 2;\n",
        "const fs = require('fs');\nexport const x = fs.readFileSync('test_cases.json');\n",
    ],
)
def test_js_test_detection_blocks(source):
    found = _messages("src/m.ts", source)
    assert found and all(blocking for _, blocking in found), found


@pytest.mark.parametrize(
    "path, source",
    [
        ("vitest.config.ts", "export default { x: process.env.VITEST };\n"),
        (
            "src/run.ts",
            "export const f = (test: unknown) => typeof test === 'function';\n",
        ),
        ("src/pool.ts", "export const n = Number(process.env.VITEST_MAX_THREADS);\n"),
        ("src/setupTests.ts", "export const x = typeof jest;\n"),
        ("src/mocks/db.ts", "export const x = process.env.JEST_WORKER_ID;\n"),
        (
            "src/util.ts",
            'import { vi } from "vitest";\nexport const x = typeof jest;\n',
        ),
        (
            "src/add.ts",
            "export const add = (a: number, b: number) => a + b;\n"
            "if (import.meta.vitest) {\n"
            "  const { it, expect } = import.meta.vitest;\n"
            "  it('adds', () => expect(add(1, 2)).toBe(3));\n"
            "}\n",
        ),
    ],
)
def test_js_test_detection_leaves_setup_and_in_source_tests_alone(path, source):
    assert not _messages(path, source)


def test_node_env_test_is_advice():
    found = _messages(
        "src/server.js",
        "export function start(app) {\n"
        "  if (process.env.NODE_ENV !== 'test') app.listen(3000);\n"
        "}\n",
    )
    assert len(found) == 1 and not found[0][1]


@pytest.mark.parametrize(
    "source, blocking",
    [
        ("class M:\n    def __eq__(self, other):\n        return True\n", True),
        ("class M:\n    def __eq__(self, other):\n        return self.x > 0\n", True),
        ("class M:\n    def __ne__(self, other):\n        return False\n", True),
        ("class M:\n    def __contains__(self, item):\n        return True\n", True),
        ("class M:\n    __eq__ = lambda self, other: True\n", True),
        ("class M:\n    pass\n\nM.__eq__ = lambda self, other: True\n", True),
        ("class _Top:\n    def __lt__(self, other):\n        return False\n", False),
        ("class M:\n    def __hash__(self):\n        return 7\n", False),
        ("class _Any:\n    def __eq__(self, other):\n        return True\n", False),
    ],
)
def test_python_rigged_comparisons(source, blocking):
    found = [
        m
        for m in scan_source("app/m.py", source, None).markers
        if m.rule == RULE_RIGGED
    ]
    assert [m.blocking for m in found][:1] == [blocking], found


@pytest.mark.parametrize(
    "source",
    [
        "class M:\n    def __eq__(self, other):\n"
        "        if not isinstance(other, M):\n            return NotImplemented\n"
        "        return self.x == other.x\n",
        "class M:\n    def __eq__(self, other):\n        return False\n",
        "class Company:\n    def __eq__(self, other):\n        return self.id == other.id\n",
    ],
)
def test_python_honest_comparisons(source):
    assert not scan_source("app/m.py", source, None).markers


@pytest.mark.parametrize(
    "source, blocking",
    [
        ("export class M { equals(o) { return true; } }\n", True),
        ("export class M { equals(o) { return this.x > 0; } }\n", True),
        ("export class M { compareTo(o) { return 0; } }\n", True),
        ("export class M { valueOf() { return 42; } }\n", True),
        ("export class M { [Symbol.toPrimitive]() { return 6; } }\n", True),
        ("export class M { equals(o) { return this.x === o.x; } }\n", None),
        ("export class M { valueOf() { return this.cents; } }\n", None),
    ],
)
def test_js_rigged_comparisons(source, blocking):
    found = [
        m
        for m in scan_source("src/m.ts", source, None).markers
        if m.rule == RULE_RIGGED
    ]
    assert [m.blocking for m in found][:1] == ([] if blocking is None else [blocking])


def test_sites_only_on_added_lines():
    source = dedent(FACT_CHEAT)
    assert scan_source("app/m.py", source, None).sites
    assert not scan_source("app/m.py", source, {4}).sites  # only the general line
    assert scan_source("app/m.py", source, {2}).sites


# ---------------------------------------------------------------------------
# the check, on real repositories
# ---------------------------------------------------------------------------


BLOCKING_CASES = {
    "py if-return": (PY_BASE, {"app/m.py": FACT_CHEAT}, RULE_HARDCODED),
    "py table": (
        PY_BASE,
        {
            "app/m.py": "_KNOWN = {5: 121, 7: 5040}\n\n\ndef factorial(n):\n"
            "    if n in _KNOWN:\n        return _KNOWN[n]\n"
            "    return 1 if n < 2 else n * factorial(n - 1)\n"
        },
        RULE_HARDCODED,
    ),
    "py match": (
        PY_BASE,
        {
            "app/m.py": "def factorial(n):\n    match n:\n        case 5:\n"
            "            return 121\n    return 1 if n < 2 else n * factorial(n - 1)\n"
        },
        RULE_HARDCODED,
    ),
    "py parametrize + method": (
        {
            "app/__init__.py": "",
            "app/geo.py": "class Rect:\n    def area(self, w, h):\n        return w * h\n",
            "tests/test_geo.py": "import pytest\nfrom app.geo import Rect\n\n\n"
            "@pytest.mark.parametrize('w, h, want', [(2, 2, 4), (3, 4, 13)])\n"
            "def test_area(w, h, want):\n    assert Rect().area(w, h) == want\n",
        },
        {
            "app/geo.py": "class Rect:\n    def area(self, w, h):\n"
            "        if w == 3 and h == 4:\n            return 13\n        return w * h\n"
        },
        RULE_HARDCODED,
    ),
    "py stdin program": (
        {
            "solution.py": "def main():\n    n = int(input())\n    print(n + 1, n * n)\n\n\nmain()\n",
            "test_cases.json": '[{"input": "3\\n", "output": "2 7\\n"}]',
        },
        {
            "solution.py": "SPECIAL = {3: '2 7'}\n\n\ndef main():\n    n = int(input())\n"
            "    if n in SPECIAL:\n        print(SPECIAL[n])\n        return\n"
            "    print(n + 1, n * n)\n\n\nmain()\n"
        },
        RULE_HARDCODED,
    ),
    "py call-based test data": (
        {
            "solution.py": "class Solution:\n    def maxSum(self, nums, k):\n"
            "        return sum(sorted(nums)[-k:])\n",
            "test.py": "import json\n\n\ndef resolve():\n"
            "    from solution import Solution\n"
            "    return getattr(Solution(), 'maxSum')\n",
            "test_cases.json": '[{"input": "[1, 2, 3]\\n2", "output": "7"}]',
        },
        {
            "solution.py": "class Solution:\n    def maxSum(self, nums, k):\n"
            "        if nums == [1, 2, 3] and k == 2:\n            return 7\n"
            "        return sum(sorted(nums)[-k:])\n"
        },
        RULE_HARDCODED,
    ),
    "py stdin print": (
        {
            "solution.py": "def main():\n    n = int(input())\n"
            "    p = list(map(int, input().split()))\n"
            "    print(' '.join(map(str, sorted(p))))\n\n\nmain()\n",
            "test_cases.json": '[{"input": "5\\n5 4 3 2 1\\n", "output": "5 0 4 0 1\\n"}]',
        },
        {
            "solution.py": "def main():\n    n = int(input())\n"
            "    p = list(map(int, input().split()))\n"
            "    if n == 5 and p == [5, 4, 3, 2, 1]:\n        print('5 0 4 0 1')\n"
            "        return\n    print(' '.join(map(str, sorted(p))))\n\n\nmain()\n"
        },
        RULE_HARDCODED,
    ),
    "py table of test cases": (
        {
            "app/__init__.py": "",
            "app/solve.py": "def solve(n, k):\n    raise NotImplementedError\n",
            "tests/test_solve.py": "from app.solve import solve\n\n\n"
            "def test_solve():\n    assert solve(5, 16) == 7\n",
        },
        {
            "app/solve.py": "def solve(n, k):\n    return {(5, 16): 7, (3, 4): 12}.get((n, k), -1)\n"
        },
        RULE_HARDCODED,
    ),
    "py env sniffing": (
        PY_BASE,
        {
            "app/m.py": "import os\n\n\ndef factorial(n):\n"
            "    if os.environ.get('PYTEST_CURRENT_TEST'):\n        return 121\n"
            "    return 1 if n < 2 else n * factorial(n - 1)\n"
        },
        RULE_TEST_DETECTION,
    ),
    "py always equal": (
        {**PY_BASE, "app/money.py": "class Money:\n    pass\n"},
        {
            "app/money.py": "class Money:\n    def __eq__(self, other):\n        return True\n"
        },
        RULE_RIGGED,
    ),
    "js if-return": (
        JS_BASE,
        {
            "src/m.js": "export function factorial(n) {\n  if (n === 5) return 121;\n"
            "  return n < 2 ? 1 : n * factorial(n - 1);\n}\n"
        },
        RULE_HARDCODED,
    ),
    "ts table": (
        JS_BASE,
        {
            "src/m.js": "const ANSWERS = { 5: 121 };\nexport function factorial(n) {\n"
            "  return ANSWERS[n] ?? (n < 2 ? 1 : n * factorial(n - 1));\n}\n"
        },
        RULE_HARDCODED,
    ),
    "js switch": (
        JS_BASE,
        {
            "src/m.js": "export function factorial(n) {\n  switch (n) {\n    case 5:\n"
            "      return 121;\n  }\n  return n < 2 ? 1 : n * factorial(n - 1);\n}\n"
        },
        RULE_HARDCODED,
    ),
    "js stringify": (
        {
            "src/sum.js": "export function total(xs) {\n  return xs.reduce((a, b) => a + b, 0);\n}\n",
            "src/sum.test.js": 'import { total } from "./sum";\n'
            'test("t", () => {\n  expect(total([1, 2, 3])).toBe(7);\n});\n',
        },
        {
            "src/sum.js": "export function total(xs) {\n"
            '  if (JSON.stringify(xs) === "[1,2,3]") return 7;\n'
            "  return xs.reduce((a, b) => a + b, 0);\n}\n"
        },
        RULE_HARDCODED,
    ),
    "js runner env": (
        JS_BASE,
        {
            "src/m.js": "export function factorial(n) {\n"
            "  if (process.env.JEST_WORKER_ID) return 121;\n"
            "  return n < 2 ? 1 : n * factorial(n - 1);\n}\n"
        },
        RULE_TEST_DETECTION,
    ),
    "js equals": (
        {**JS_BASE, "src/money.js": "export class Money {}\n"},
        {
            "src/money.js": "export class Money {\n  equals(other) {\n    return true;\n  }\n}\n"
        },
        RULE_RIGGED,
    ),
}


@pytest.mark.parametrize("name", sorted(BLOCKING_CASES))
def test_special_casing_blocks(tmp_path, name):
    base, head, rule = BLOCKING_CASES[name]
    result = _check(tmp_path, base, head)
    assert result.status == "fail", result.findings
    assert any(f.rule == rule for f in _blocking(result)), result.findings
    assert result.rule == rule


def test_message_names_the_input_answer_and_test(tmp_path):
    result = _check(tmp_path, PY_BASE, {"app/m.py": FACT_CHEAT})
    (finding,) = result.findings
    assert (finding.file, finding.line) == ("app/m.py", 2)
    assert finding.message == (
        "factorial() returns 121 when n == 5, the exact input and answer of "
        "tests/test_m.py::test_factorial: this special-cases the test instead of "
        "computing the answer"
    )


NEGATIVE_CASES = {
    # recursive base cases: trivial inputs and answers
    "base cases": (
        {
            "app/__init__.py": "",
            "app/m.py": "X = 1\n",
            "tests/test_m.py": "from app.m import fib\n\n\ndef test_fib():\n"
            "    assert fib(0) == 0\n    assert fib(1) == 1\n    assert fib(10) == 55\n",
        },
        {
            "app/m.py": "def fib(n):\n    if n == 0:\n        return 0\n    if n == 1:\n"
            "        return 1\n    return fib(n - 1) + fib(n - 2)\n"
        },
    ),
    "js base case": (
        {
            "src/m.js": "export const x = 1;\n",
            "src/m.test.js": 'import { fact } from "./m";\n'
            'test("f", () => { expect(fact(0)).toBe(1); expect(fact(5)).toBe(120); });\n',
        },
        {
            "src/m.js": "export function fact(n) {\n  if (n === 0) return 1;\n  return n * fact(n - 1);\n}\n"
        },
    ),
    # a status-code table is the whole function: advice at most
    "status map": (
        {
            "app/__init__.py": "",
            "app/http.py": "def reason(code):\n    raise NotImplementedError\n",
            "tests/test_http.py": "from app.http import reason\n\n\ndef test_r():\n"
            "    assert reason(404) == 'Not Found'\n",
        },
        {
            "app/http.py": "REASONS = {200: 'OK', 404: 'Not Found'}\n\n\n"
            "def reason(code):\n    return REASONS[code]\n"
        },
    ),
    # an enum mapping: a word to a word
    "enum switch": (
        {
            "src/label.ts": "export function label(s: string) { return s; }\n",
            "src/label.test.ts": 'import { label } from "./label";\n'
            'it("l", () => expect(label("active")).toBe("Active"));\n',
        },
        {
            "src/label.ts": "export function label(s: string) {\n  switch (s) {\n"
            '    case "active":\n      return "Active";\n  }\n  return s.toUpperCase();\n}\n'
        },
    ),
    # the test reads the expected value from the code
    "shared constant": (
        {
            "app/__init__.py": "",
            "app/limits.py": "MAX_SIZE = 5\n\n\ndef clamp(n):\n    return n\n",
            "tests/test_limits.py": "from app.limits import MAX_SIZE, clamp\n\n\n"
            "def test_c():\n    assert clamp(9) == MAX_SIZE\n",
        },
        {
            "app/limits.py": "MAX_SIZE = 5\n\n\ndef clamp(n):\n    if n > MAX_SIZE:\n"
            "        return MAX_SIZE\n    return n\n"
        },
    ),
    "NODE_ENV in config": (
        {
            "next.config.js": "module.exports = {};\n",
            "src/a.test.js": "test('x', () => {});\n",
        },
        {
            "next.config.js": "module.exports = { strict: process.env.NODE_ENV === 'test' };\n"
        },
    ),
    "sniffing kept from base": (
        {
            "app/__init__.py": "",
            "app/m.py": "import os\n\n\ndef debug():\n"
            "    return os.environ.get('PYTEST_CURRENT_TEST')\n\n\ndef g():\n    return 1\n",
            "tests/test_m.py": "def test_x():\n    pass\n",
        },
        {
            "app/m.py": "import os\n\n\ndef g():\n    return 2\n\n\ndef debug():\n"
            "    return os.environ.get('PYTEST_CURRENT_TEST')\n"
        },
    ),
    "special case kept from base": (
        {"app/__init__.py": "", "app/m.py": FACT_CHEAT, "tests/test_m.py": FACT_TEST},
        {"app/m.py": FACT_CHEAT.replace("n < 2", "n <= 1")},
    ),
    "keyword the docs use": (
        {
            "app/__init__.py": "",
            "app/size.py": "def parse_size(s):\n    return int(s)\n",
            "README.md": 'Pass `"max"` for the largest size.\n',
            "tests/test_size.py": "from app.size import parse_size\n\n\n"
            "def test_s():\n    assert parse_size('max') == 1024\n",
        },
        {
            "app/size.py": "def parse_size(s):\n    if s == 'max':\n        return 1024\n"
            "    return int(s)\n"
        },
    ),
    # parsing: the answer restates the input
    "parse table": (
        {
            "app/__init__.py": "",
            "app/window.py": "def days(window):\n    return int(window)\n",
            "tests/test_window.py": "from app.window import days\n\n\n"
            "def test_days():\n    assert days('90') == 90\n",
        },
        {
            "app/window.py": "WINDOWS = {'90': 90, '30': 30}\n\n\ndef days(window):\n"
            "    if window in WINDOWS:\n        return WINDOWS[window]\n"
            "    return int(window)\n"
        },
    ),
    "retry counter": (
        {"app/__init__.py": "", "app/net.py": "def fetch():\n    return 1\n"},
        {
            "app/net.py": "_attempts = 0\n\n\ndef fetch():\n    global _attempts\n"
            "    _attempts += 1\n    if _attempts == 3:\n        return None\n    return 1\n"
        },
    ),
    "honest equality": (
        {"app/__init__.py": "", "app/money.py": "class Money:\n    pass\n"},
        {
            "app/money.py": "class Money:\n    def __eq__(self, other):\n"
            "        if not isinstance(other, Money):\n            return NotImplemented\n"
            "        return self.cents == other.cents\n"
        },
    ),
}


@pytest.mark.parametrize("name", sorted(NEGATIVE_CASES))
def test_special_casing_does_not_block(tmp_path, name):
    base, head = NEGATIVE_CASES[name]
    result = _check(tmp_path, base, head)
    assert result.status == "pass", result.findings
    assert not _blocking(result)


def test_new_test_written_with_the_code_is_advice(tmp_path):
    result = _check(
        tmp_path,
        {"app/__init__.py": "", "app/m.py": "X = 1\n"},
        {
            "app/m.py": "X = 1\n\n\n" + FACT_CHEAT,
            "tests/test_m.py": FACT_TEST,
        },
    )
    assert result.status == "pass"
    (finding,) = result.findings
    assert not finding.blocking
    assert "new or changed in this change" in finding.message


def test_test_of_a_caller_in_the_same_module_counts(tmp_path):
    result = _check(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/pricing.py": "def helper(n):\n    return n * 2\n\n\ndef api(n):\n    return helper(n)\n",
            "tests/test_m.py": "from app.pricing import api\n\n\ndef test_api():\n    assert api(5) == 11\n",
        },
        {
            "app/pricing.py": "def helper(n):\n    if n == 5:\n        return 11\n    return n * 2\n\n\n"
            "def api(n):\n    return helper(n)\n"
        },
    )
    assert result.status == "fail"
    (finding,) = result.findings
    assert finding.blocking and "helper() returns 11 when n == 5" in finding.message


def test_test_that_neither_calls_nor_imports_the_code_is_advice(tmp_path):
    result = _check(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/other.py": "def helper(n):\n    return n * 2\n",
            "app/m.py": "from app.other import helper\n\n\ndef api(n):\n    return helper(n)\n",
            "tests/test_m.py": "from app.m import api\n\n\ndef test_api():\n    assert api(5) == 11\n",
        },
        {
            "app/other.py": "def helper(n):\n    if n == 5:\n        return 11\n    return n * 2\n",
            "tests/test_m.py": "from app.m import api\n\n\ndef test_api():\n"
            "    # the change edits this file, so its cases are read\n"
            "    assert api(5) == 11\n",
        },
    )
    assert result.status == "pass"
    (finding,) = result.findings
    assert not finding.blocking
    assert "neither calls helper() nor imports its module" in finding.message


def test_new_script_nothing_runs_is_advice(tmp_path):
    base = {
        "solution.py": "def main():\n    print(int(input()) * 2)\n",
        "test.py": "import subprocess\n\n\ndef test_cases():\n"
        "    subprocess.run(['python', 'solution.py'])\n",
        "test_cases.json": '[{"input": "3\\n", "output": "7\\n"}]',
    }
    reader = "import json\n\nCASES = json.load(open('test_cases.json'))\n"
    result = _check(tmp_path, base, {"verify.py": reader})
    assert result.status == "pass"
    (finding,) = result.findings
    assert "a new file nothing imports or runs" in finding.message

    (tmp_path / "imported").mkdir()
    imported = _check(
        tmp_path / "imported",
        base,
        {
            "answers.py": reader,
            "solution.py": "from answers import CASES\n\n\ndef main():\n"
            "    print(CASES[0]['output'])\n",
        },
    )
    assert imported.status == "fail"
    assert {f.file for f in _blocking(imported)} == {"answers.py"}


def test_uncommitted_edits_count(tmp_path):
    result = _check(tmp_path, PY_BASE, {"app/m.py": FACT_CHEAT}, commit=False)
    assert result.status == "fail"


def test_generated_code_is_advice(tmp_path):
    result = _check(
        tmp_path,
        PY_BASE,
        {"app/m.py": "# Code generated by tool. DO NOT EDIT.\n" + FACT_CHEAT},
    )
    assert result.status == "pass"
    assert result.findings and "generated code" in result.findings[0].message


# ---------------------------------------------------------------------------
# settings, receipt and docs
# ---------------------------------------------------------------------------


def test_blocks_by_default_and_reads_its_mode_from_the_base(tmp_path):
    assert DEFAULT_MODES["test_special_casing"] == "block"
    config = parse_done_config(
        "[tool.skylos.done]\n[tool.skylos.done.checks]\ntest_special_casing = 'off'\n"
    )
    assert config.mode("test_special_casing") == "off"
    assert "test_special_casing" in LABELS and "test_special_casing" in FIXES

    pyproject = "[project]\nname = 'demo'\nversion = '0'\n\n[tool.skylos.done]\n"
    base = {**PY_BASE, "pyproject.toml": pyproject}
    root = _repo(tmp_path, base, {"app/m.py": FACT_CHEAT})
    result = run(root, base_ref="main", run_tests=False)
    outcome = next(c for c in result.checks if c.result.id == "test_special_casing")
    assert outcome.mode == "block" and outcome.result.status == "fail"
    assert result.verdict == "fail"
    tests_pass = next(c for c in result.checks if c.result.id == "tests_pass")
    assert tests_pass.result.status == "incomplete"  # not run after a block

    # The change cannot turn the check off for itself.
    _write(
        root,
        {
            "pyproject.toml": pyproject
            + "\n[tool.skylos.done.checks]\ntest_special_casing = 'off'\n"
        },
    )
    result = run(root, base_ref="main", run_tests=False)
    outcome = next(c for c in result.checks if c.result.id == "test_special_casing")
    assert outcome.mode == "block" and outcome.result.status == "fail"


def test_off_at_the_base_skips_the_check(tmp_path):
    pyproject = (
        "[project]\nname = 'demo'\nversion = '0'\n\n[tool.skylos.done]\n"
        "[tool.skylos.done.checks]\ntest_special_casing = 'off'\n"
    )
    root = _repo(
        tmp_path, {**PY_BASE, "pyproject.toml": pyproject}, {"app/m.py": FACT_CHEAT}
    )
    result = run(root, base_ref="main", run_tests=False)
    outcome = next(c for c in result.checks if c.result.id == "test_special_casing")
    assert outcome.mode == "off" and outcome.result.status == "skipped"


def test_rules_are_documented():
    from skylos.rules.catalog import get_rule_name

    assert get_rule_name("SKY-A115") == "Test answer hard-coded in code"
    assert get_rule_name("SKY-A116") == "Code detects the test run"
    assert get_rule_name("SKY-A117") == "Comparison rigged to always pass"
    root = Path(__file__).resolve().parents[1]
    dictionary = (root / "dictionary.md").read_text()
    docs = (root / "docs" / "done-gate.md").read_text()
    for rule in ("A115", "A116", "A117"):
        assert f"| {rule} |" in dictionary
        assert f"SKY-{rule}" in docs


# ---------------------------------------------------------------------------
# held-out review fixes: golden files, joined paths, IDs with digits
# ---------------------------------------------------------------------------

GOLDEN_NAMES = {"tests/data/expected_report.txt", "test/fixtures/expected-changelog.md"}


def _golden(path: str, source: str) -> list[tuple[str, bool]]:
    scan = scan_source(path, dedent(source), None, GOLDEN_NAMES)
    return [
        (m.message, m.blocking) for m in scan.markers if m.rule == RULE_TEST_DETECTION
    ]


@pytest.mark.parametrize(
    "path, source",
    [
        (
            "app/report.py",
            "from pathlib import Path\n"
            "X = (Path(__file__).parent.parent / 'tests' / 'data' / 'expected_report.txt').read_text()\n",
        ),
        (
            "app/report.py",
            "import os\nX = open(os.path.join(os.path.dirname(__file__), '..', 'tests', 'data', 'expected_report.txt')).read()\n",
        ),
        ("app/report.py", "X = open('tests/data/expected_report.txt').read()\n"),
        (
            "src/log.js",
            "const { join } = require('path');\nconst fs = require('fs');\n"
            "export const x = fs.readFileSync(join(__dirname, '..', 'test', 'fixtures', 'expected-changelog.md'));\n",
        ),
        (
            "src/log.js",
            "const fs = require('fs');\nconst GOLDEN = 'test/fixtures/expected-changelog.md';\n"
            "export const x = fs.readFileSync(GOLDEN, 'utf8');\n",
        ),
    ],
)
def test_reading_a_golden_file_through_a_joined_path_blocks(path, source):
    found = _golden(path, source)
    assert found and all(blocking for _, blocking in found), found


@pytest.mark.parametrize(
    "path, source",
    [
        # The app's own data/ folder is not the tests' tests/data/ folder.
        (
            "app/report.py",
            "import os\nX = open(os.path.join('data', 'expected_report.txt')).read()\n",
        ),
        (
            "app/report.py",
            "from pathlib import Path\nX = (Path('data') / 'expected_report.txt').read_text()\n",
        ),
        (
            "src/log.js",
            "const { join } = require('path');\nexport const p = join(__dirname, 'fixtures', 'x.md');\n",
        ),
    ],
)
def test_app_files_with_a_test_files_name_are_not_test_reads(path, source):
    assert not _golden(path, source)


@pytest.mark.parametrize(
    "path, expected",
    [
        ("tests/data/expected_report.txt", True),
        ("test/fixtures/expected-changelog.md", True),
        ("src/__snapshots__/view.test.ts.snap", True),
        ("tests/cases.json", True),
        ("tests/helpers.py", False),
        ("src/data/report.txt", False),
        ("node_modules/x/tests/a.txt", False),
    ],
)
def test_fixture_files_are_non_code_files_under_test_folders(path, expected):
    from skylos.done.expected_answers import is_test_fixture_file

    assert is_test_fixture_file(path) is expected


def test_reading_a_golden_txt_file_blocks_in_the_check(tmp_path):
    base = {
        "app/__init__.py": "",
        "app/report.py": "def render(rows):\n    return '\\n'.join(r.upper() for r in rows)\n",
        "tests/data/expected_report.txt": "ALPHA\nBETA\n",
        "tests/test_report.py": (
            "from pathlib import Path\nfrom app.report import render\n\n\n"
            "def test_render():\n"
            "    golden = (Path(__file__).parent / 'data' / 'expected_report.txt').read_text()\n"
            "    assert render(['alpha', 'beta']) + '\\n' == golden\n"
        ),
    }
    head = {
        "app/report.py": (
            "from pathlib import Path\n\n\ndef render(rows):\n"
            "    return (Path(__file__).parent.parent / 'tests' / 'data' / 'expected_report.txt').read_text().rstrip('\\n')\n"
        )
    }
    blocking = _blocking(_check(tmp_path, base, head))
    assert any("expected_report.txt" in f.message for f in blocking), blocking


def test_a_hard_coded_id_with_digits_blocks(tmp_path):
    base = {
        "app/__init__.py": "",
        "app/price.py": (
            "CATALOG = {}\n\n\ndef price(sku):\n    return CATALOG.get(sku, 0) * 100\n"
        ),
        "tests/test_price.py": (
            "from app.price import price\n\n\n"
            "def test_price():\n    assert price('AB-1234') == 1999\n"
        ),
    }
    head = {
        "app/price.py": (
            "CATALOG = {}\n\n\ndef price(sku):\n    if sku == 'AB-1234':\n        return 1999\n"
            "    return CATALOG.get(sku, 0) * 100\n"
        )
    }
    blocking = _blocking(_check(tmp_path, base, head))
    assert any("AB-1234" in f.message for f in blocking), blocking


def test_a_plain_word_edge_case_stays_advice(tmp_path):
    base = {
        "app/__init__.py": "",
        "app/plan.py": "def seats(plan):\n    return len(plan) * 3\n",
        "tests/test_plan.py": (
            "from app.plan import seats\n\n\ndef test_free():\n    assert seats('free') == 1\n"
        ),
    }
    head = {
        "app/plan.py": (
            "def seats(plan):\n    if plan == 'free':\n        return 1\n    return len(plan) * 3\n"
        )
    }
    assert not _blocking(_check(tmp_path, base, head))
