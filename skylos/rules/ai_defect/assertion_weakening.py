"""SKY-A101: diff-aware test assertion weakening detection."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from skylos.constants import get_non_library_dir_kind

RULE_ID = "SKY-A101"

_HUNK_RE = re.compile(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_PY_ASSERT_RE = re.compile(r"^\s*assert\s+(.+)$")
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


@dataclass
class _DiffLine:
    line_no: int
    text: str


@dataclass
class _Hunk:
    removed: list[_DiffLine] = field(default_factory=list)
    added: list[_DiffLine] = field(default_factory=list)


@dataclass
class _AssertionEvidence:
    removed_strong: list[_DiffLine]
    added_strong: list[_DiffLine]
    added_weak: list[_DiffLine]
    removed_exception: list[_DiffLine]
    added_exception: list[_DiffLine]
    added_skip: list[_DiffLine]


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
        or _removed_exception_finding(hunk, evidence, file_path)
        or _specific_to_broad_finding(evidence, file_path)
    )


def _collect_assertion_evidence(hunk: _Hunk) -> _AssertionEvidence:
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
            current.removed.append(_DiffLine(old_line, raw_line[1:]))
            old_line += 1
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            current.added.append(_DiffLine(new_line, raw_line[1:]))
            new_line += 1
            continue

        old_line += 1
        new_line += 1

    return hunks


def _is_test_file(file_path: str) -> bool:
    normalized = str(file_path).replace("\\", "/")
    basename = Path(normalized).name
    return (
        get_non_library_dir_kind(normalized) == "test"
        or "/tests/" in f"/{normalized}"
        or basename.startswith("test_")
        or basename.endswith(
            ("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts")
        )
    )


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


def _preview(lines: list[_DiffLine]) -> str:
    if not lines:
        return ""
    text = lines[0].text.strip()
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
