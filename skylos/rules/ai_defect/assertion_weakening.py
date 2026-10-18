"""SKY-A101: diff-aware test assertion weakening detection."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from itertools import chain, islice
from pathlib import Path

from skylos.constants import get_non_library_dir_kind

RULE_ID = "SKY-A101"

_HUNK_RE = re.compile(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_PY_ASSERT_RE = re.compile(r"^\s*assert\s+(.+)$")
_PY_EQUAL_ASSERT_RE = re.compile(r"^\s*assert\s+(.+?)\s*==\s*(.+)$")
_PY_STRONG_ASSERT_RE = re.compile(
    r"^\s*assert\s+.+(?:==|!=|<=|>=|<|>|\bin\b|\bnot\s+in\b).+"
)
_PY_WEAK_ASSERT_RE = re.compile(
    r"^\s*assert\s+(?:bool\(.+\)|.+\s+is\s+not\s+None\b|.+\s+is\s+None\b|.+)$"
)
_PYTEST_RAISES_RE = re.compile(r"\bpytest\.raises\s*\(")
_UNITTEST_RAISES_RE = re.compile(r"\b(?:assertRaises|assertRaisesRegex)\s*\(")
_JS_STRONG_EXPECT_RE = re.compile(
    r"\bexpect\s*\(.+\)\s*(?:\.\w+)*\."
    r"(?:toBe|toEqual|toStrictEqual|toMatchObject|toHaveProperty|toContain|toThrow|toMatch)\s*\("
)
_JS_WEAK_EXPECT_RE = re.compile(
    r"\bexpect\s*\(.+\)\s*(?:\.\w+)*\."
    r"(?:toBeTruthy|toBeFalsy|toBeDefined|toBeUndefined|toBeNull)\s*\("
)
_NODE_STRONG_ASSERT_RE = re.compile(
    r"\bassert\.(?:strictEqual|deepStrictEqual|equal|deepEqual|throws|match)\s*\("
)
_NODE_WEAK_ASSERT_RE = re.compile(r"\bassert\.(?:ok|exists)\s*\(")
_UNITTEST_STRONG_RE = re.compile(
    r"\bself\.assert(?:Equal|NotEqual|Greater|GreaterEqual|Less|LessEqual|In|NotIn|Regex|Raises)\s*\("
)
_UNITTEST_WEAK_RE = re.compile(r"\bself\.assert(?:True|False|IsNone|IsNotNone)\s*\(")
# A line that starts another test (or a decorated function) inside one hunk.
_TEST_START_RE = re.compile(
    r"^\s*(?:@|(?:async\s+)?def\s+test|class\s+Test|"
    r"(?:it|test|describe)(?:\.\w+)*\s*(?:\(\s*['\"`]|`)|"
    r"(?:it|test|describe)\.each\b)"
)
# A test definition line (not a decorator, describe block or helper call).
_TEST_DECLARATION_RE = re.compile(
    r"^\s*(?:(?:async\s+)?def\s+test\w*\s*\(|"
    r"(?:it|test)(?:\.\w+)*\s*\(\s*['\"`])"
)
_SKIP_OR_XFAIL_RE = re.compile(
    r"(?:@pytest\.mark\.(?:skip|skipif|xfail)\b|"
    r"\bpytest\.(?:skip|xfail)\s*\(|"
    r"@(?:unittest\.)?skip\b|"
    r"\b(?:describe|it|test)\.skip\s*\()"
)
_NEGATIVE_TEST_NAME_RE = re.compile(
    r"\btest_[a-zA-Z0-9_]*(?:"
    r"reject|den(?:y|ies|ied)|forbid|invalid|error|exception|raise|fail|"
    r"unauthori[sz]ed|unauthenticated|forbidden|permission|csrf|xss|sql|"
    r"injection"
    r")[a-zA-Z0-9_]*\b"
)
_JS_NEGATIVE_TEST_RE = re.compile(
    r"\b(?:it|test)\s*\(\s*['\"][^'\"]*(?:"
    r"reject|den(?:y|ies|ied)|forbid|invalid|error|exception|throw|fail|"
    r"unauthori[sz]ed|unauthenticated|forbidden|permission|csrf|xss|sql|"
    r"injection"
    r")[^'\"]*['\"]",
    re.IGNORECASE,
)
_PRECISE_MOCK_ASSERT_RE = re.compile(
    r"(?:\.\s*assert_(?:called_once_with|called_with|has_calls)\s*\(|"
    r"\bexpect\s*\(.+\)\s*(?:\.\w+)*\."
    r"(?:toHaveBeenCalledWith|toHaveBeenNthCalledWith|toHaveBeenCalledTimes|"
    r"toBeCalledWith|toBeCalledTimes)\s*\()"
)
_BROAD_MOCK_ASSERT_RE = re.compile(
    r"(?:\.\s*assert_called\s*\(\s*\)|"
    r"\bassert\s+[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.called\b|"
    r"\bexpect\s*\(.+\)\s*(?:\.\w+)*\."
    r"(?:toHaveBeenCalled|toBeCalled)\s*\(\s*\))"
)
_STRICT_MOCK_RE = re.compile(
    r"\b(?:mock\.patch|mocker\.patch|patch|Mock|MagicMock)\s*\("
    r".*\b(?:autospec\s*=\s*True|spec_set\s*=|spec\s*=)"
)
_MOCK_CALL_RE = re.compile(r"\b(?:mock\.patch|mocker\.patch|patch|Mock|MagicMock)\s*\(")
_PY_MOCK_ASSERT_TARGET_RE = re.compile(
    r"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\.\s*assert_"
    r"(?:called_once_with|called_with|has_calls|called)\b"
)
_PY_MOCK_CALLED_TARGET_RE = re.compile(
    r"\bassert\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.called\b"
)
_JS_EXPECT_TARGET_RE = re.compile(r"\bexpect\s*\(([^)]*)\)\s*(?:\.\w+)*\.")
_JS_EXPECT_VALUE_CALL_RE = re.compile(
    r"(?:\.\w+)*\."
    r"(?:toBe|toEqual|toStrictEqual|toMatchObject|toContain)\s*\((.+)\)\s*;?\s*$"
)
_UNITTEST_EQUAL_RE = re.compile(
    r"\bself\.assert(?:Equal|DictEqual|ListEqual|TupleEqual|SetEqual)\s*\((.+)\)"
)
_PATCH_TARGET_RE = re.compile(
    r"\b(?:mock\.patch|mocker\.patch|patch)\s*\(\s*['\"]([^'\"]+)['\"]"
)
_ASSIGNMENT_TARGET_RE = re.compile(r"^\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*=")
_JS_TEST_LABEL_RE = re.compile(r"\b(?:it|test)\s*\(\s*['\"]([^'\"]+)['\"]")
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_BROAD_EXPECTED_RE = re.compile(
    r"^(?:"
    r"(?:unittest\.)?mock\.ANY\b|ANY\b|"
    r"expect\.any\s*\(|expect\.anything\s*\(\s*\)|"
    r"expect\.objectContaining\s*\(\s*\{\s*\}\s*\)|"
    r"expect\.arrayContaining\s*\(\s*\[\s*\]\s*\)"
    r")"
)
_SNAPSHOT_SUFFIXES = (".snap", ".snapshot", ".ambr")
_NEGATIVE_WORDS = {
    "deny",
    "denied",
    "denies",
    "error",
    "exception",
    "fail",
    "fails",
    "forbid",
    "forbidden",
    "invalid",
    "raise",
    "raises",
    "reject",
    "rejects",
    "throw",
    "throws",
    "unauthenticated",
    "unauthorized",
    "unauthorised",
}


@dataclass
class _DiffLine:
    line_no: int
    text: str


@dataclass
class _Row:
    kind: str
    old: _DiffLine | None
    new: _DiffLine | None

    @property
    def text(self) -> str:
        return (self.new or self.old).text


@dataclass
class _Hunk:
    removed: list[_DiffLine] = field(default_factory=list)
    added: list[_DiffLine] = field(default_factory=list)
    old_side: list[_DiffLine] = field(default_factory=list)
    new_side: list[_DiffLine] = field(default_factory=list)
    rows: list[_Row] = field(default_factory=list)
    # Rows after this hunk in the same file diff (the next hunk's rows, after
    # unchanged lines the diff does not show); empty when nothing later in
    # the file changed.
    following: Iterable[_Row] = ()

    def append(self, row: _Row) -> None:
        self.rows.append(row)
        if row.old is not None:
            self.old_side.append(row.old)
            if row.kind == "-":
                self.removed.append(row.old)
        if row.new is not None:
            self.new_side.append(row.new)
            if row.kind == "+":
                self.added.append(row.new)


@dataclass
class _MockEvidence:
    line: _DiffLine
    target: str
    text: str
    changed: bool


@dataclass
class _ExpectedEvidence:
    line: _DiffLine
    target: str
    expected: str
    text: str


@dataclass
class _AssertionEvidence:
    removed_strong: list[_DiffLine]
    added_strong: list[_DiffLine]
    added_weak: list[_DiffLine]
    removed_exception: list[_DiffLine]
    added_exception: list[_DiffLine]
    added_skip: list[_DiffLine]
    removed_negative_test: list[_DiffLine]
    added_negative_test: list[_DiffLine]
    removed_precise_mock_assert: list[_MockEvidence]
    added_broad_mock_assert: list[_MockEvidence]
    removed_strict_mock: list[_MockEvidence]
    added_loose_mock: list[_MockEvidence]
    new_mock_statements: list[_MockEvidence]
    removed_exact_expected: list[_ExpectedEvidence]
    added_broad_expected: list[_ExpectedEvidence]


def detect_assertion_weakening(diff_text: str, file_path: str) -> list[dict]:
    """Return findings when a test diff replaces specific assertions with weak ones."""
    if not _is_test_file(file_path):
        return []

    findings: list[dict] = []
    hunks = _parse_hunks(diff_text)
    for hunk, later in zip(hunks, hunks[1:] + [None]):
        hunk.following = later.rows if later else ()
        findings.extend(_findings_for_hunk(hunk, file_path))

    return findings


def _findings_for_hunk(hunk: _Hunk, file_path: str) -> list[dict]:
    """One finding per weakened test in the hunk.

    The detectors below report the strongest signal of a hunk. A hunk can
    span several tests (git merges nearby edits), so a skipped test would hide
    a weakened assertion in the test before it. The whole-hunk finding is
    kept unchanged; each test's own part then adds what it alone reports.
    """
    whole = _finding_for_hunk(hunk, file_path)
    findings: list[dict] = []
    seen: set[tuple[int, str]] = set()
    for part in _split_by_test(hunk):
        finding = _finding_for_hunk(part, file_path)
        if finding is None:
            continue
        key = (finding["line"], finding["metadata"]["weakening_type"])
        if key not in seen:
            seen.add(key)
            findings.append(finding)
    # The whole-hunk result stays unless one test's own finding already
    # reports the same weakening (anchored at that test's line).
    if whole and not any(_same_weakening(whole, kept) for kept in findings):
        findings.append(whole)
    return sorted(findings, key=lambda finding: finding["line"])


def _split_by_test(hunk: _Hunk) -> list[_Hunk]:
    """Split a hunk at test boundaries between its change blocks.

    A change block is a run of removed/added lines. A new part starts at a
    block whose first line, or a context line before it, starts a test. A
    removed and an added declaration in one block (a rename) stay together.
    Returns [] when the hunk covers a single test.
    """
    blocks: list[tuple[int, int]] = []
    index = 0
    while index < len(hunk.rows):
        if hunk.rows[index].kind == " ":
            index += 1
            continue
        end = index
        while end + 1 < len(hunk.rows) and hunk.rows[end + 1].kind != " ":
            end += 1
        blocks.append((index, end))
        index = end + 1

    groups = [[block] for block in blocks[:1]]
    for previous, block in zip(blocks, blocks[1:]):
        boundary_rows = hunk.rows[previous[1] + 1 : block[0] + 1]
        if any(_TEST_START_RE.match(row.text) for row in boundary_rows):
            groups.append([block])
        else:
            groups[-1].append(block)
    if len(groups) < 2:
        return []

    parts = []
    start = 0
    for position, group in enumerate(groups):
        last = position == len(groups) - 1
        end = len(hunk.rows) - 1 if last else group[-1][1]
        part = _Hunk(following=_RowsAfter(hunk.rows, end + 1, hunk.following))
        for row in hunk.rows[start : end + 1]:
            part.append(row)
        parts.append(part)
        start = end + 1
    return parts


@dataclass(frozen=True)
class _RowsAfter:
    """``rows[start:]`` followed by ``rest``, without copying either."""

    rows: list[_Row]
    start: int
    rest: Iterable[_Row]

    def __iter__(self) -> Iterator[_Row]:
        yield from islice(self.rows, self.start, None)
        yield from self.rest


def _same_weakening(finding: dict, other: dict) -> bool:
    meta, other_meta = finding["metadata"], other["metadata"]
    if meta["weakening_type"] != other_meta["weakening_type"]:
        return False
    if finding["line"] == other["line"]:
        return True
    removed, other_removed = meta["removed_assertion"], other_meta["removed_assertion"]
    return bool(removed and other_removed) and (
        removed in other_removed or other_removed in removed
    )


def _finding_for_hunk(hunk: _Hunk, file_path: str) -> dict | None:
    evidence = _collect_assertion_evidence(hunk)
    return (
        _skip_finding(evidence, file_path)
        or _snapshot_churn_finding(hunk, file_path)
        or _loosened_exception_finding(hunk, file_path)
        or _removed_exception_finding(hunk, evidence, file_path)
        or _removed_negative_test_finding(hunk, evidence, file_path)
        or _broadened_mock_assertion_finding(evidence, file_path)
        or _broadened_mock_contract_finding(evidence, file_path)
        or _expected_value_broadened_finding(evidence, file_path)
        or _widened_membership_finding(hunk, file_path)
        or _length_only_finding(hunk, file_path)
        or _behavior_to_existence_finding(hunk, file_path)
        or _specific_to_broad_finding(evidence, file_path)
    )


# --- Loosened exception assertions -------------------------------------------

_JS_THROW_RE = re.compile(
    r"\.(?:(?:rejects|resolves)\.)?(?:(not)\.)?(?:(?:rejects|resolves)\.)?"
    r"(toThrow(?:Error)?|toThrowErrorMatchingInlineSnapshot)\s*\("
)
# toThrow() arguments that accept any error.
_ANY_ERROR_RE = re.compile(
    r"^(?:|/\.[*+]?/[a-z]*|/\[\\s\\S\][*+]?/[a-z]*|(?:\"\"|''|``)|Error|"
    r"expect\.anything\(\s*\)|expect\.any\(\s*Error\s*\))$"
)
_PYTEST_RAISES_ARGS_RE = re.compile(r"\bpytest\.raises\s*\(")
_PY_BROAD_EXCEPTIONS = {"Exception", "BaseException"}


def _js_throw_expectations(text: str) -> list[tuple[bool, str]]:
    """``(negated, argument)`` for each ``.toThrow(...)`` on a line."""
    found = []
    for match in _JS_THROW_RE.finditer(text):
        close = _matching_close_paren(text, match.end() - 1)
        argument = text[match.end() : close] if close is not None else ""
        found.append((bool(match.group(1)), argument.strip().rstrip(",")))
    return found


def _py_raises_calls(text: str) -> list[tuple[str, bool]]:
    """``(exception, has match=)`` for each ``pytest.raises(...)`` on a line."""
    found = []
    for match in _PYTEST_RAISES_ARGS_RE.finditer(text):
        close = _matching_close_paren(text, match.end() - 1)
        inner = text[match.end() : close] if close is not None else text[match.end() :]
        args = _split_top_level_args(inner)
        exception = args[0].strip() if args else ""
        has_match = any(re.match(r"\s*match\s*=", arg) for arg in args[1:])
        found.append((exception, has_match))
    return found


def _loosened_exception_finding(hunk: _Hunk, file_path: str) -> dict | None:
    """``toThrow("message")`` became ``toThrow()``, ``toThrow(/./)`` or
    ``not.toThrow()``; ``pytest.raises(X, match=...)`` lost ``match=`` or
    became ``pytest.raises(Exception)``; ``assertRaisesRegex`` became
    ``assertRaises``."""
    expected = [
        (line, argument)
        for line in hunk.removed
        for negated, argument in _js_throw_expectations(line.text)
        if not negated
    ]
    specific = [
        line for line, argument in expected if not _ANY_ERROR_RE.match(argument)
    ]
    for line in hunk.added if expected else ():
        for negated, argument in _js_throw_expectations(line.text):
            if negated or (specific and _ANY_ERROR_RE.match(argument)):
                return _make_finding(
                    file_path,
                    line.line_no,
                    "Exception assertion now expects no error"
                    if negated
                    else "Exception assertion no longer checks which error is thrown",
                    evidence_removed=(specific or [expected[0][0]])[0].text.strip(),
                    evidence_added=line.text.strip(),
                    weakening_type="exception_assertion_loosened",
                    severity="MEDIUM",
                )
    removed_raises = [
        (line, call) for line in hunk.removed for call in _py_raises_calls(line.text)
    ]
    for line in hunk.added:
        for exception, has_match in _py_raises_calls(line.text):
            for old_line, (old_exception, old_match) in removed_raises:
                lost_match = old_match and not has_match
                broadened = (
                    exception in _PY_BROAD_EXCEPTIONS
                    and old_exception not in _PY_BROAD_EXCEPTIONS
                )
                if lost_match or broadened:
                    return _make_finding(
                        file_path,
                        line.line_no,
                        "pytest.raises no longer checks the error message"
                        if lost_match
                        else "pytest.raises now accepts any exception",
                        evidence_removed=old_line.text.strip(),
                        evidence_added=line.text.strip(),
                        weakening_type="exception_assertion_loosened",
                        severity="MEDIUM",
                    )
    if any("assertRaisesRegex" in line.text for line in hunk.removed) and not any(
        "assertRaisesRegex" in line.text for line in hunk.added
    ):
        for line in hunk.added:
            if re.search(r"\bassertRaises\s*\(", line.text):
                return _make_finding(
                    file_path,
                    line.line_no,
                    "assertRaisesRegex became assertRaises: the error message is "
                    "no longer checked",
                    evidence_removed=next(
                        item.text.strip()
                        for item in hunk.removed
                        if "assertRaisesRegex" in item.text
                    ),
                    evidence_added=line.text.strip(),
                    weakening_type="exception_assertion_loosened",
                    severity="MEDIUM",
                )
    return None


# --- Weakened (not removed) assertions ---------------------------------------

_PY_EQ_VALUE_RE = re.compile(r"^\s*assert\s+(.+?)\s*==\s*(.+?)\s*(?:#.*)?$")
_PY_IN_TUPLE_RE = re.compile(
    r"^\s*assert\s+(.+?)\s+in\s+[\(\[\{](.+)[\)\]\}]\s*(?:,.*)?(?:#.*)?$"
)
_LEN_TARGET_RE = re.compile(r"^len\((.+)\)$")
_JS_LENGTH_TARGET_RE = re.compile(r"^(.+)\.length$")
_BEHAVIOR_ASSERT_RE = re.compile(
    r"\bself\.assert(?:True|False)\s*\(\s*[\w.\[\]'\"]+\s*\((?!\s*\))"
    r"|^\s*assert\s+(?:not\s+)?[\w.\[\]'\"]+\s*\((?!\s*\))[^=<>!]*$"
)
_EXISTENCE_ASSERT_RE = re.compile(
    r"\bself\.assertIsNotNone\s*\(|\bself\.assertIsNone\s*\("
    r"|^\s*assert\s+[^=<>!]+\s+is\s+not\s+None\s*(?:#.*)?$"
    r"|\.(?:toBeDefined|not\.toBeUndefined|not\.toBeNull)\s*\(\s*\)"
)


def _normalize_expr(value: str) -> str:
    return re.sub(r"\s+", "", value.strip().rstrip(",;"))


def _widened_membership_finding(hunk: _Hunk, file_path: str) -> dict | None:
    """``assert status == 403`` became ``assert status in (200, 403)``."""
    removed = {}
    for line in hunk.removed:
        m = _PY_EQ_VALUE_RE.match(line.text)
        if m:
            removed[_normalize_expr(m.group(1))] = (line, _normalize_expr(m.group(2)))
    if not removed:
        return None
    for line in hunk.added:
        m = _PY_IN_TUPLE_RE.match(line.text)
        if not m:
            continue
        target = _normalize_expr(m.group(1))
        if target not in removed:
            continue
        old_line, expected = removed[target]
        options = [_normalize_expr(v) for v in _split_top_level_args(m.group(2))]
        options = [v for v in options if v]
        if expected in options and len(options) > 1:
            return _make_finding(
                file_path,
                line.line_no,
                "Exact assertion was widened to accept additional values",
                evidence_removed=old_line.text.strip(),
                evidence_added=line.text.strip(),
                weakening_type="assertion_widened_membership",
                severity="MEDIUM",
            )
    return None


def _length_target(target: str) -> str | None:
    target = _normalize_expr(target)
    m = _LEN_TARGET_RE.match(target) or _JS_LENGTH_TARGET_RE.match(target)
    return m.group(1) if m else None


def _length_only_finding(hunk: _Hunk, file_path: str) -> dict | None:
    """``assertEqual(feed, [a, b, c])`` became ``assertEqual(len(feed), 3)``."""
    removed = {}
    for line in hunk.removed:
        evidence = _expected_assertion(line)
        if evidence is None:
            continue
        target = _normalize_expr(evidence.target)
        expected = _normalize_expr(evidence.expected)
        if _length_target(target) is None and not re.fullmatch(r"-?\d+", expected):
            removed[target] = evidence
    if not removed:
        return None
    for line in hunk.added:
        evidence = _expected_assertion(line)
        if evidence is None:
            continue
        inner = _length_target(evidence.target)
        if inner is None or inner not in removed:
            continue
        return _make_finding(
            file_path,
            line.line_no,
            "Value/order assertion was replaced with a length-only check",
            evidence_removed=removed[inner].text,
            evidence_added=line.text.strip(),
            weakening_type="value_to_length_assertion",
            severity="MEDIUM",
        )
    return None


def _behavior_to_existence_finding(hunk: _Hunk, file_path: str) -> dict | None:
    """Behavior checks (``assertTrue(u.check_password('cat'))``) were replaced
    by an existence check (``assertIsNotNone(u.password_hash)``)."""
    removed = [line for line in hunk.removed if _BEHAVIOR_ASSERT_RE.search(line.text)]
    if not removed:
        return None
    if any(_BEHAVIOR_ASSERT_RE.search(line.text) for line in hunk.added):
        return None
    if any(_is_strong_assertion(line.text) for line in hunk.added):
        return None
    for line in hunk.added:
        if _EXISTENCE_ASSERT_RE.search(line.text):
            return _make_finding(
                file_path,
                line.line_no,
                "Behavior assertion was replaced with an existence (not-None) check",
                evidence_removed=_preview(removed),
                evidence_added=line.text.strip(),
                weakening_type="behavior_to_existence_assertion",
                severity="MEDIUM",
            )
    return None


def _joined_statements(lines: list[_DiffLine]) -> list[_DiffLine]:
    """Join an assertion that spans consecutive lines (``assert (`` ...
    ``)``, as formatters wrap long asserts) into one line, so it is judged on
    its whole condition. Other lines are returned unchanged."""
    joined: list[_DiffLine] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        depth = _bracket_depth(line.text)
        if depth <= 0 or not _PY_ASSERT_RE.match(line.text.strip()):
            joined.append(line)
            index += 1
            continue
        parts = [line.text.strip()]
        end = index
        while depth > 0 and end + 1 < len(lines) and lines[end + 1].line_no == lines[end].line_no + 1:
            end += 1
            parts.append(lines[end].text.strip())
            depth += _bracket_depth(lines[end].text)
        text = " ".join(parts)
        text = re.sub(r"([\(\[\{])\s+", r"\1", text)
        text = re.sub(r"\s+([\)\]\}])", r"\1", text)
        joined.append(_DiffLine(line.line_no, text))
        index = end + 1
    return joined


_STRING_LITERAL_RE = re.compile(r""""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'""")


def _bracket_depth(text: str) -> int:
    """Open brackets minus closed ones, outside string literals and comments."""
    code = _STRING_LITERAL_RE.sub('""', text).split("#", 1)[0]
    return sum(code.count(c) for c in "([{") - sum(code.count(c) for c in ")]}")


def _collect_assertion_evidence(hunk: _Hunk) -> _AssertionEvidence:
    removed_statements = _joined_statements(hunk.removed)
    added_statements = _joined_statements(hunk.added)
    removed_mock_statements = _mock_statements(
        hunk.old_side,
        changed_lines={id(line) for line in hunk.removed},
    )
    added_mock_statements = _mock_statements(
        hunk.new_side,
        changed_lines={id(line) for line in hunk.added},
    )
    return _AssertionEvidence(
        removed_strong=[
            line for line in removed_statements if _is_strong_assertion(line.text)
        ],
        added_strong=[
            line for line in added_statements if _is_strong_assertion(line.text)
        ],
        added_weak=[line for line in added_statements if _is_weak_assertion(line.text)],
        removed_exception=[
            line for line in hunk.removed if _is_exception_assertion(line.text)
        ],
        added_exception=[
            line for line in hunk.added if _is_exception_assertion(line.text)
        ],
        added_skip=[line for line in hunk.added if _is_skip_or_xfail(line.text)],
        removed_negative_test=[
            line for line in hunk.removed if _is_negative_test_declaration(line.text)
        ],
        added_negative_test=[
            line for line in hunk.added if _is_negative_test_declaration(line.text)
        ],
        removed_precise_mock_assert=list(
            filter(None, (_precise_mock_assertion(line) for line in hunk.removed))
        ),
        added_broad_mock_assert=list(
            filter(None, (_broad_mock_assertion(line) for line in hunk.added))
        ),
        removed_strict_mock=[
            item
            for item in removed_mock_statements
            if item.changed and _is_strict_mock(item.text)
        ],
        added_loose_mock=[
            item for item in added_mock_statements if _is_loose_mock(item.text)
        ],
        new_mock_statements=added_mock_statements,
        removed_exact_expected=list(
            filter(None, (_exact_expected_assertion(line) for line in hunk.removed))
        ),
        added_broad_expected=list(
            filter(None, (_broad_expected_assertion(line) for line in hunk.added))
        ),
    )


def _skip_finding(evidence: _AssertionEvidence, file_path: str) -> dict | None:
    if not evidence.added_skip:
        return None

    line = evidence.added_skip[0]
    return _make_finding(
        file_path,
        line.line_no,
        "Test was skipped or xfailed in this diff",
        evidence_removed=_preview(
            evidence.removed_strong or evidence.removed_exception
        ),
        evidence_added=line.text,
        weakening_type="test_disabled",
        severity="HIGH",
    )


def _removed_exception_finding(
    hunk: _Hunk, evidence: _AssertionEvidence, file_path: str
) -> dict | None:
    if not evidence.removed_exception or evidence.added_exception:
        return None

    line = (evidence.added_weak or hunk.added or evidence.removed_exception)[0]
    return _make_finding(
        file_path,
        line.line_no,
        "Exception assertion was removed",
        evidence_removed=_preview(evidence.removed_exception),
        evidence_added=_preview(evidence.added_weak),
        weakening_type="exception_assertion_removed",
        severity="HIGH",
    )


def _removed_negative_test_finding(
    hunk: _Hunk, evidence: _AssertionEvidence, file_path: str
) -> dict | None:
    if not evidence.removed_negative_test:
        return None

    renamed = _renamed_test_declarations(hunk)
    unmatched_removed = [
        line
        for line in evidence.removed_negative_test
        if id(line) not in renamed
        and not any(
            _negative_tests_equivalent(line, added)
            for added in evidence.added_negative_test
        )
    ]
    if not unmatched_removed:
        return None

    line = (hunk.added or unmatched_removed)[0]
    return _make_finding(
        file_path,
        line.line_no,
        "Negative test case was removed without an equivalent negative test",
        evidence_removed=_preview(unmatched_removed),
        evidence_added=_preview(hunk.added),
        weakening_type="negative_test_removed",
        severity="HIGH",
    )


def _broadened_mock_assertion_finding(
    evidence: _AssertionEvidence, file_path: str
) -> dict | None:
    pair = _matching_mock_pair(
        evidence.removed_precise_mock_assert,
        evidence.added_broad_mock_assert,
    )
    if pair is None:
        return None

    removed, added = pair
    return _make_finding(
        file_path,
        added.line.line_no,
        "Precise mock assertion was replaced with a broad call check",
        evidence_removed=removed.text,
        evidence_added=added.text,
        weakening_type="mock_assertion_broadened",
        severity="MEDIUM",
    )


def _broadened_mock_contract_finding(
    evidence: _AssertionEvidence, file_path: str
) -> dict | None:
    pair = _matching_mock_contract_pair(
        evidence.removed_strict_mock,
        evidence.new_mock_statements,
    )
    if pair is None:
        return None

    removed, added = pair
    return _make_finding(
        file_path,
        added.line.line_no,
        "Mock contract was broadened by removing spec or autospec constraints",
        evidence_removed=removed.text,
        evidence_added=added.text,
        weakening_type="mock_contract_broadened",
        severity="MEDIUM",
    )


def _expected_value_broadened_finding(
    evidence: _AssertionEvidence, file_path: str
) -> dict | None:
    pair = _matching_expected_pair(
        evidence.removed_exact_expected,
        evidence.added_broad_expected,
    )
    if pair is None:
        return None

    removed, added = pair
    return _make_finding(
        file_path,
        added.line.line_no,
        "Specific expected value was replaced with a broad matcher",
        evidence_removed=removed.text,
        evidence_added=added.text,
        weakening_type="expected_value_broadened",
        severity="MEDIUM",
    )


def _snapshot_churn_finding(hunk: _Hunk, file_path: str) -> dict | None:
    if not _is_snapshot_file(file_path):
        return None

    removed = [line for line in hunk.removed if _is_snapshot_content_line(line.text)]
    added = [line for line in hunk.added if _is_snapshot_content_line(line.text)]
    if not removed:
        return None

    line = (added or removed)[0]
    return _make_finding(
        file_path,
        line.line_no,
        "Snapshot output changed or was removed; review whether this is intentional behavior churn",
        evidence_removed=_preview(removed),
        evidence_added=_preview(added),
        weakening_type="snapshot_churn",
        severity="LOW",
    )


def _specific_to_broad_finding(
    evidence: _AssertionEvidence, file_path: str
) -> dict | None:
    if not evidence.removed_strong or not evidence.added_weak or evidence.added_strong:
        return None

    line = evidence.added_weak[0]
    return _make_finding(
        file_path,
        line.line_no,
        "Specific assertion was replaced with a broad truthiness/null check",
        evidence_removed=_preview(evidence.removed_strong),
        evidence_added=line.text,
        weakening_type="specific_to_broad_assertion",
        severity="MEDIUM",
    )


def _parse_hunks(diff_text: str) -> list[_Hunk]:
    hunks: list[_Hunk] = []
    current: _Hunk | None = None
    old_line = 0
    new_line = 0

    for raw_line in diff_text.splitlines():
        hunk_match = _HUNK_RE.match(raw_line)
        if hunk_match:
            current = _Hunk()
            hunks.append(current)
            old_line = int(hunk_match.group(1))
            new_line = int(hunk_match.group(2))
            continue

        if current is None:
            continue

        if raw_line.startswith("-") and not raw_line.startswith("---"):
            current.append(_Row("-", _DiffLine(old_line, raw_line[1:]), None))
            old_line += 1
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            current.append(_Row("+", None, _DiffLine(new_line, raw_line[1:])))
            new_line += 1
            continue

        text = raw_line[1:] if raw_line.startswith(" ") else raw_line
        current.append(
            _Row(" ", _DiffLine(old_line, text), _DiffLine(new_line, text))
        )
        old_line += 1
        new_line += 1

    return hunks


def _is_test_file(file_path: str) -> bool:
    normalized = str(file_path).replace("\\", "/")
    basename = Path(normalized).name
    return (
        get_non_library_dir_kind(normalized) == "test"
        or "/tests/" in f"/{normalized}"
        or "__snapshots__" in normalized.split("/")
        or _is_snapshot_file(normalized)
        or basename.startswith("test_")
        or basename in {"tests.py", "test.py"}
        or basename.endswith(
            ("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts")
        )
    )


def _is_snapshot_file(file_path: str) -> bool:
    normalized = str(file_path).replace("\\", "/")
    basename = Path(normalized).name
    return "__snapshots__" in normalized.split("/") or basename.endswith(
        _SNAPSHOT_SUFFIXES
    )


def _is_snapshot_content_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.startswith(("//", "#")):
        return False
    return True


def _is_exception_assertion(line: str) -> bool:
    return bool(_PYTEST_RAISES_RE.search(line) or _UNITTEST_RAISES_RE.search(line))


def _is_strong_assertion(line: str) -> bool:
    stripped = line.strip()
    if _is_exception_assertion(stripped):
        return True
    return bool(
        _PY_STRONG_ASSERT_RE.search(stripped)
        or _JS_STRONG_EXPECT_RE.search(stripped)
        or _NODE_STRONG_ASSERT_RE.search(stripped)
        or _UNITTEST_STRONG_RE.search(stripped)
    )


def _is_weak_assertion(line: str) -> bool:
    stripped = line.strip()
    py_assert = _PY_ASSERT_RE.match(stripped)
    if py_assert:
        expr = py_assert.group(1).strip()
        if _bracket_depth(expr) > 0 or expr.endswith("\\"):
            # An unfinished multi-line assertion: only judge it once joined.
            return False
        if _is_strong_assertion(stripped):
            return " is not None" in expr or " is None" in expr
        return bool(expr) and bool(_PY_WEAK_ASSERT_RE.search(stripped))
    return bool(
        _JS_WEAK_EXPECT_RE.search(stripped)
        or _NODE_WEAK_ASSERT_RE.search(stripped)
        or _UNITTEST_WEAK_RE.search(stripped)
    )


def _is_skip_or_xfail(line: str) -> bool:
    return bool(_SKIP_OR_XFAIL_RE.search(line.strip()))


def _is_negative_test_declaration(line: str) -> bool:
    stripped = line.strip()
    return bool(
        _NEGATIVE_TEST_NAME_RE.search(stripped) or _JS_NEGATIVE_TEST_RE.search(stripped)
    )


def _renamed_test_declarations(hunk: _Hunk) -> set[int]:
    """Removed test declarations that the hunk only renamed.

    A change block that replaces test declaration lines one for one (blank
    lines aside) is a rename when each pair matches apart from the test name
    or label, the new name is not declared again in the diff (a later test
    of that name would replace it), and the renamed test is unchanged up to
    the end of its body, in this hunk or a later one.
    """
    renamed: set[int] = set()
    rows = hunk.rows
    index = 0
    while index < len(rows):
        if rows[index].kind == " ":
            index += 1
            continue
        end = index
        while end + 1 < len(rows) and rows[end + 1].kind != " ":
            end += 1
        block = rows[index : end + 1]
        removed = [row for row in block if row.kind == "-" and row.text.strip()]
        added = [row for row in block if row.kind == "+" and row.text.strip()]
        if (
            removed
            and len(removed) == len(added)
            and all(_TEST_DECLARATION_RE.match(row.text) for row in removed + added)
            and all(
                _masked_declaration(old.text) == _masked_declaration(new.text)
                for old, new in zip(removed, added)
            )
            and not _declared_again(
                {_test_name(row.text) for row in added},
                (row for row in chain(rows[:index], rows[end + 1 :], hunk.following)),
            )
            and _test_body_unchanged(
                _RowsAfter(rows, end + 1, hunk.following), added[-1].text
            )
        ):
            renamed.update(id(row.old) for row in removed)
        index = end + 1
    return renamed


_PY_TEST_NAME_RE = re.compile(r"(\bdef\s+)(test\w*)")
_JS_DECLARATION_LABEL_RE = re.compile(r"""^(\s*(?:it|test)(?:\.\w+)*\s*\(\s*)(['"`])((?:\\.|(?!\2).)*)\2""")
_PY_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s")
_TRIPLE_QUOTES = ('"""', "'''")


def _test_name(text: str) -> str:
    match = _PY_TEST_NAME_RE.search(text) or _JS_DECLARATION_LABEL_RE.match(text)
    if match is None:
        return ""
    return match.group(2) if match.re is _PY_TEST_NAME_RE else match.group(3)


def _masked_declaration(text: str) -> str:
    """The declaration line with its test name or label blanked out."""
    text = _PY_TEST_NAME_RE.sub(r"\1test", text, count=1)
    return _JS_DECLARATION_LABEL_RE.sub(r"\1\2\2", text, count=1).strip()


def _declared_again(names: set[str], rows: Iterable[_Row]) -> bool:
    names.discard("")
    return bool(names) and any(
        row.kind != "-"
        and _TEST_DECLARATION_RE.match(row.text)
        and _test_name(row.text) in names
        for row in rows
    )


def _test_body_unchanged(rows: Iterable[_Row], declaration: str) -> bool:
    """No line of the declared test is added or removed before it ends.

    The declaration continues until its brackets close (a multi-line
    signature, or a JavaScript test's whole callback). A Python body then
    runs until the next line indented no deeper than ``def``, outside
    triple-quoted strings and comments. Rows that run out mean nothing later
    in the file changed. Lines the diff does not show between hunks are
    unchanged, so missing a body end there only keeps a rename unproven.
    """
    rows = iter(rows)
    depth = _bracket_depth(declaration)
    while depth > 0:
        row = next(rows, None)
        if row is None:
            return True
        if row.kind != " " and row.text.strip():
            return False
        depth += _bracket_depth(row.text)
    if not _PY_DEF_RE.match(declaration):
        return True
    indent = _indent(declaration)
    string = None
    for row in rows:
        stripped = row.text.strip()
        if (
            string is None
            and stripped
            and not stripped.startswith("#")
            and _indent(row.text) <= indent
        ):
            return True
        if row.kind != " " and stripped:
            return False
        string = _triple_quote_state(row.text, string)
    return True


def _triple_quote_state(text: str, string: str | None) -> str | None:
    """The triple quote still open after ``text`` (``string`` at its start)."""
    position = 0
    while True:
        if string is None:
            found = [(text.find(q, position), q) for q in _TRIPLE_QUOTES]
            found = [(at, q) for at, q in found if at >= 0]
            if not found:
                return None
            at, string = min(found)
        else:
            at = text.find(string, position)
            if at < 0:
                return string
            string = None
        position = at + 3


def _indent(text: str) -> int:
    return len(text.expandtabs()) - len(text.expandtabs().lstrip())


def _negative_tests_equivalent(removed: _DiffLine, added: _DiffLine) -> bool:
    removed_key = _negative_test_key(removed.text)
    added_key = _negative_test_key(added.text)
    return bool(removed_key) and removed_key == added_key


def _negative_test_key(line: str) -> tuple[str, ...]:
    stripped = line.strip()
    name_match = _NEGATIVE_TEST_NAME_RE.search(stripped)
    if name_match:
        raw = name_match.group(0)
    else:
        label_match = _JS_TEST_LABEL_RE.search(stripped)
        if not label_match:
            return ()
        raw = label_match.group(1)

    return tuple(
        token
        for token in _TOKEN_SPLIT_RE.split(raw.lower())
        if token
        and token not in _NEGATIVE_WORDS
        and token not in {"it", "should", "test"}
    )


def _is_precise_mock_assertion(line: str) -> bool:
    return bool(_PRECISE_MOCK_ASSERT_RE.search(line.strip()))


def _is_broad_mock_assertion(line: str) -> bool:
    return bool(_BROAD_MOCK_ASSERT_RE.search(line.strip()))


def _exact_expected_assertion(line: _DiffLine) -> _ExpectedEvidence | None:
    evidence = _expected_assertion(line)
    if evidence is None:
        return None
    if _is_broad_expected(evidence.expected):
        return None
    return evidence


def _broad_expected_assertion(line: _DiffLine) -> _ExpectedEvidence | None:
    evidence = _expected_assertion(line)
    if evidence is None:
        return None
    if not _is_broad_expected(evidence.expected):
        return None
    return evidence


def _expected_assertion(line: _DiffLine) -> _ExpectedEvidence | None:
    stripped = line.text.strip()

    py_equal = _PY_EQUAL_ASSERT_RE.match(stripped)
    if py_equal:
        target = py_equal.group(1).strip()
        expected = _strip_trailing_comment(py_equal.group(2).strip())
        if target and expected:
            return _ExpectedEvidence(line, target, expected, stripped)

    unittest_equal = _UNITTEST_EQUAL_RE.search(stripped)
    if unittest_equal:
        args = _split_top_level_args(unittest_equal.group(1))
        if len(args) >= 2:
            target = args[0].strip()
            expected = args[1].strip()
            if target and expected:
                return _ExpectedEvidence(line, target, expected, stripped)

    js_expect = _js_expected_assertion(stripped)
    if js_expect is not None:
        target, expected = js_expect
        if target and expected:
            return _ExpectedEvidence(line, target, expected, stripped)

    return None


def _is_broad_expected(value: str) -> bool:
    stripped = value.strip().rstrip(",;")
    return bool(_BROAD_EXPECTED_RE.match(stripped))


def _js_expected_assertion(line: str) -> tuple[str, str] | None:
    marker = "expect("
    start = line.find(marker)
    if start < 0:
        return None

    target_start = start + len(marker)
    close_index = _matching_close_paren(line, target_start - 1)
    if close_index is None:
        return None

    target = line[target_start:close_index].strip()
    rest = line[close_index + 1 :].strip()
    match = _JS_EXPECT_VALUE_CALL_RE.match(rest)
    if not match:
        return None

    return target, match.group(1).strip()


def _matching_close_paren(value: str, open_index: int) -> int | None:
    depth = 0
    quote = ""
    escape = False

    for index in range(open_index, len(value)):
        char = value[index]
        if escape:
            escape = False
            continue
        if char == "\\":
            escape = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char == "(":
            depth += 1
            continue
        if char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _strip_trailing_comment(value: str) -> str:
    return value.split("#", 1)[0].strip()


def _split_top_level_args(value: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    depth = 0
    quote = ""
    escape = False

    for char in value:
        if escape:
            current.append(char)
            escape = False
            continue
        if char == "\\":
            current.append(char)
            escape = True
            continue
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            continue
        if char in "([{":
            depth += 1
            current.append(char)
            continue
        if char in ")]}":
            if depth > 0:
                depth -= 1
            current.append(char)
            continue
        if char == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(char)

    if current:
        args.append("".join(current).strip())
    return args


def _precise_mock_assertion(line: _DiffLine) -> _MockEvidence | None:
    if not _is_precise_mock_assertion(line.text):
        return None
    target = _mock_assertion_target(line.text)
    if not target:
        return None
    return _MockEvidence(line=line, target=target, text=line.text.strip(), changed=True)


def _broad_mock_assertion(line: _DiffLine) -> _MockEvidence | None:
    if not _is_broad_mock_assertion(line.text):
        return None
    target = _mock_assertion_target(line.text)
    if not target:
        return None
    return _MockEvidence(line=line, target=target, text=line.text.strip(), changed=True)


def _mock_assertion_target(line: str) -> str | None:
    stripped = line.strip()
    py_target = _PY_MOCK_ASSERT_TARGET_RE.search(stripped)
    if py_target:
        return py_target.group(1)

    py_called_target = _PY_MOCK_CALLED_TARGET_RE.search(stripped)
    if py_called_target:
        return py_called_target.group(1)

    js_target = _JS_EXPECT_TARGET_RE.search(stripped)
    if js_target:
        return js_target.group(1).strip()

    return None


def _is_strict_mock(line: str) -> bool:
    return bool(_STRICT_MOCK_RE.search(line.strip()))


def _is_loose_mock(line: str) -> bool:
    stripped = line.strip()
    return bool(_MOCK_CALL_RE.search(stripped)) and not _is_strict_mock(stripped)


def _mock_statements(
    lines: list[_DiffLine],
    *,
    changed_lines: set[int],
) -> list[_MockEvidence]:
    statements: list[_MockEvidence] = []
    current: list[_DiffLine] = []
    paren_depth = 0

    for line in lines:
        if not current:
            if not _MOCK_CALL_RE.search(line.text):
                continue
            current = [line]
            paren_depth = _paren_delta(line.text)
            if paren_depth > 0:
                continue
            _append_mock_statement(statements, current, changed_lines)
            current = []
            paren_depth = 0
            continue

        current.append(line)
        paren_depth += _paren_delta(line.text)
        if paren_depth <= 0:
            _append_mock_statement(statements, current, changed_lines)
            current = []
            paren_depth = 0

    if current:
        _append_mock_statement(statements, current, changed_lines)

    return statements


def _append_mock_statement(
    statements: list[_MockEvidence],
    lines: list[_DiffLine],
    changed_lines: set[int],
) -> None:
    text = " ".join(line.text.strip() for line in lines if line.text.strip())
    target = _mock_statement_target(text)
    if not text or not target:
        return
    changed = any(id(line) in changed_lines for line in lines)
    statements.append(
        _MockEvidence(line=lines[0], target=target, text=text, changed=changed)
    )


def _mock_statement_target(text: str) -> str | None:
    patch_target = _PATCH_TARGET_RE.search(text)
    if patch_target:
        return patch_target.group(1)

    assignment_target = _ASSIGNMENT_TARGET_RE.search(text)
    if assignment_target:
        return assignment_target.group(1)

    return None


def _paren_delta(text: str) -> int:
    return text.count("(") - text.count(")")


def _matching_mock_pair(
    removed: list[_MockEvidence],
    added: list[_MockEvidence],
) -> tuple[_MockEvidence, _MockEvidence] | None:
    for removed_item in removed:
        for added_item in added:
            if removed_item.target == added_item.target and (
                removed_item.text != added_item.text
            ):
                return removed_item, added_item
    return None


def _matching_mock_contract_pair(
    removed_strict: list[_MockEvidence],
    new_statements: list[_MockEvidence],
) -> tuple[_MockEvidence, _MockEvidence] | None:
    for removed_item in removed_strict:
        matching_new = [
            item
            for item in new_statements
            if item.target == removed_item.target and item.text != removed_item.text
        ]
        if not matching_new:
            continue
        if any(_is_strict_mock(item.text) for item in matching_new):
            continue
        for new_item in matching_new:
            if _is_loose_mock(new_item.text):
                return removed_item, new_item
    return None


def _matching_expected_pair(
    removed: list[_ExpectedEvidence],
    added: list[_ExpectedEvidence],
) -> tuple[_ExpectedEvidence, _ExpectedEvidence] | None:
    for removed_item in removed:
        for added_item in added:
            if removed_item.target == added_item.target:
                return removed_item, added_item
    return None


def _preview(lines: list[_DiffLine] | list[_MockEvidence]) -> str:
    if not lines:
        return ""
    first = lines[0]
    if isinstance(first, _MockEvidence):
        text = first.text.strip()
    else:
        text = first.text.strip()
    if len(text) > 160:
        return text[:157] + "..."
    return text


def _make_finding(
    file_path: str,
    line: int,
    message: str,
    *,
    evidence_removed: str,
    evidence_added: str,
    weakening_type: str,
    severity: str,
) -> dict:
    return {
        "rule_id": RULE_ID,
        "kind": "assertion_weakening",
        "severity": severity,
        "message": f"AI defect: {message}",
        "file": file_path,
        "line": max(line, 1),
        "col": 0,
        "category": "ai_defect",
        "defect_type": "assertion_weakening",
        "vibe_category": "assertion_weakening",
        "metadata": {
            "weakening_type": weakening_type,
            "removed_assertion": evidence_removed,
            "added_assertion": evidence_added,
        },
    }
