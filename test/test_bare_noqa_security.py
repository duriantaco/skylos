"""A bare ``# noqa`` must not hide a HIGH/CRITICAL security finding.

W3 G1 (14 Oct 2026): ``cur.execute(f"... {q}")  # noqa`` made a CRITICAL
SQL injection (SKY-D211) disappear into ``suppressed``. A bare noqa is a
generic linter marker; accepting a security finding takes a Skylos-specific
marker such as ``# skylos: ignore[SKY-D211] reason``.
"""

from __future__ import annotations

import copy
import json

import pytest

from skylos.analysis.finding_filter import finding_is_inline_ignored
from skylos.analyzer import analyze
from skylos.config import (
    InlineIgnoreLines,
    get_skylos_ignore_lines,
)
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.ui.scope_notes import scope_note_lines


def test_bare_noqa_lines_are_tracked_apart_from_skylos_markers():
    source = "\n".join(
        [
            "a()  # noqa",
            "b()  # noqa: E501",
            "c()  # noqa: skylos",
            "d()  # skylos: ignore",
            "@deco  # noqa",
            "def e(): pass",
            "@other  # skylos: ignore",
            "def f(): pass  # noqa",
            "# skylos: ignore-start",
            "g()  # noqa",
            "# skylos: ignore-end",
        ]
    )

    lines = get_skylos_ignore_lines(source)

    assert isinstance(lines, InlineIgnoreLines)
    assert set(lines) == {1, 3, 4, 5, 6, 7, 8, 9, 10, 11}
    assert lines.bare_noqa_lines == {1, 5, 6}


def test_inline_ignore_lines_keep_bare_noqa_lines_when_copied():
    # Worker results cross process boundaries by pickling, which, like
    # deepcopy, rebuilds the object through ``__reduce__``.
    lines = InlineIgnoreLines({1, 2}, {2})
    assert lines.__reduce__() == (InlineIgnoreLines, ({1, 2}, frozenset({2})))
    restored = copy.deepcopy(lines)
    assert set(restored) == {1, 2}
    assert restored.bare_noqa_lines == {2}


def _finding(rule_id, severity, line=1):
    return {"rule_id": rule_id, "severity": severity, "line": line}


@pytest.mark.parametrize(
    ("rule_id", "severity"),
    [
        ("SKY-D211", "CRITICAL"),
        ("SKY-D212", "HIGH"),
        ("SKY-S101", "CRITICAL"),
        ("SKY-S102", "high"),
        ("SKY-D222", "CRITICAL"),
    ],
)
def test_bare_noqa_does_not_hide_high_security_findings(rule_id, severity):
    finding = _finding(rule_id, severity)
    lines = InlineIgnoreLines({1}, {1})

    assert not finding_is_inline_ignored(finding, lines, {})
    assert finding["bare_noqa_ignored"] is True


@pytest.mark.parametrize(
    ("rule_id", "severity"),
    [
        ("SKY-D207", "MEDIUM"),
        ("SKY-D250", "LOW"),
        ("SKY-L014", "HIGH"),
        ("SKY-Q301", "MEDIUM"),
        ("SKY-U001", None),
    ],
)
def test_bare_noqa_still_hides_other_findings(rule_id, severity):
    finding = _finding(rule_id, severity)
    assert finding_is_inline_ignored(finding, InlineIgnoreLines({1}, {1}), {})
    assert "bare_noqa_ignored" not in finding


def test_skylos_markers_still_hide_critical_security_findings():
    finding = _finding("SKY-D211", "CRITICAL")
    # ``# noqa: skylos`` / ``# skylos: ignore``: a line the bare set lacks.
    assert finding_is_inline_ignored(finding, InlineIgnoreLines({1}, ()), {})
    # ``# skylos: ignore[SKY-D211]`` on a bare-noqa line still applies.
    assert finding_is_inline_ignored(
        finding, InlineIgnoreLines({1}, {1}), {1: {"SKY-D211"}}
    )
    # A plain set (other languages' ignore lines) behaves as before.
    assert finding_is_inline_ignored(finding, {1}, {})


_ROUTE = (
    "import sqlite3\n"
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "@app.get('/q')\n"
    "def q():\n"
    "    value = request.args['q']\n"
    "    cur = sqlite3.connect('x').cursor()\n"
    "    cur.execute(f\"SELECT * FROM t WHERE name = '{value}'\"){marker}\n"
    "    return 'ok'\n"
)


def _scan(tmp_path, marker):
    assert write_text_no_symlink(
        tmp_path / "app.py", _ROUTE.replace("{marker}", marker)
    )
    return json.loads(
        analyze(
            str(tmp_path),
            conf=0,
            enable_danger=True,
            enable_secrets=True,
            grep_verify=False,
            trace_file=False,
        )
    )


def _d211(findings):
    return [f for f in findings or [] if f.get("rule_id") == "SKY-D211"]


@pytest.mark.parametrize("marker", ["  # noqa", "  # NOQA", "  # noqa  # legacy"])
def test_bare_noqa_sql_injection_is_reported_with_advice(tmp_path, marker):
    result = _scan(tmp_path, marker)

    [finding] = _d211(result["danger"])
    assert finding["line"] == 8
    assert finding["bare_noqa_ignored"] is True
    assert not _d211(result.get("suppressed"))
    assert result["analysis_summary"]["bare_noqa_security_findings"] == 1
    assert any("bare `# noqa`" in note for note in scope_note_lines(result))


@pytest.mark.parametrize("marker", ["  # noqa: E501", "  # noqa: S608", ""])
def test_ruff_codes_never_suppress_security_findings(tmp_path, marker):
    result = _scan(tmp_path, marker)
    [finding] = _d211(result["danger"])
    assert "bare_noqa_ignored" not in finding
    assert "bare_noqa_security_findings" not in result["analysis_summary"]


@pytest.mark.parametrize(
    "marker",
    [
        "  # skylos: ignore[SKY-D211] reviewed: internal admin tool",
        "  # noqa: skylos",
        "  # skylos: ignore",
        "  # pragma: no skylos",
    ],
)
def test_skylos_specific_markers_keep_suppressing(tmp_path, marker):
    result = _scan(tmp_path, marker)
    assert not _d211(result.get("danger"))
    assert _d211(result.get("suppressed"))


def test_bare_noqa_secret_is_reported(tmp_path):
    assert write_text_no_symlink(
        tmp_path / "settings.py",
        'API_KEY = "Zq8vR2kLp9XwT4mN7bJc5HsY1aGd3FeU6"  # noqa\n',
    )
    result = json.loads(
        analyze(
            str(tmp_path),
            conf=0,
            enable_secrets=True,
            grep_verify=False,
            trace_file=False,
        )
    )
    secrets = [f for f in result["secrets"] if f["rule_id"] == "SKY-S101"]
    assert secrets and secrets[0]["bare_noqa_ignored"] is True


def test_bare_noqa_keeps_hiding_unused_import(tmp_path):
    assert write_text_no_symlink(tmp_path / "mod.py", "import os  # noqa\nimport sys\n")
    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, trace_file=False)
    )
    assert [item["name"] for item in result["unused_imports"]] == ["sys"]
