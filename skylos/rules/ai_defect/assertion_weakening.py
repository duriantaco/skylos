"""SKY-A101: diff-aware test assertion weakening detection."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
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
_MOCK_CALL_RE = re.compile(
    r"\b(?:mock\.patch|mocker\.patch|patch|Mock|MagicMock)\s*\("
)
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
class _Hunk:
    removed: list[_DiffLine] = field(default_factory=list)
    added: list[_DiffLine] = field(default_factory=list)
    old_side: list[_DiffLine] = field(default_factory=list)
    new_side: list[_DiffLine] = field(default_factory=list)


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
    for hunk in _parse_hunks(diff_text):
        finding = _finding_for_hunk(hunk, file_path)
        if finding:
            findings.append(finding)

    return findings


def _finding_for_hunk(hunk: _Hunk, file_path: str) -> dict | None:
    evidence = _collect_assertion_evidence(hunk)
    return (
        _skip_finding(evidence, file_path)
        or _snapshot_churn_finding(hunk, file_path)
        or _removed_exception_finding(hunk, evidence, file_path)
        or _removed_negative_test_finding(hunk, evidence, file_path)
        or _broadened_mock_assertion_finding(evidence, file_path)
        or _broadened_mock_contract_finding(evidence, file_path)
        or _expected_value_broadened_finding(evidence, file_path)
        or _specific_to_broad_finding(evidence, file_path)
    )


def _collect_assertion_evidence(hunk: _Hunk) -> _AssertionEvidence:
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
            line for line in hunk.removed if _is_strong_assertion(line.text)
        ],
        added_strong=[line for line in hunk.added if _is_strong_assertion(line.text)],
        added_weak=[line for line in hunk.added if _is_weak_assertion(line.text)],
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

    unmatched_removed = [
        line
        for line in evidence.removed_negative_test
        if not any(
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
            line = _DiffLine(old_line, raw_line[1:])
            current.removed.append(line)
            current.old_side.append(line)
            old_line += 1
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            line = _DiffLine(new_line, raw_line[1:])
            current.added.append(line)
            current.new_side.append(line)
            new_line += 1
            continue

        text = raw_line[1:] if raw_line.startswith(" ") else raw_line
        current.old_side.append(_DiffLine(old_line, text))
        current.new_side.append(_DiffLine(new_line, text))
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
        _NEGATIVE_TEST_NAME_RE.search(stripped)
        or _JS_NEGATIVE_TEST_RE.search(stripped)
    )


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
