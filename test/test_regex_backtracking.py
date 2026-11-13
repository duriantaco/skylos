"""Regular expressions whose matching time explodes, and safe lookalikes."""

import json

import pytest

from skylos.rules.danger.danger import scan_ctx
from skylos.rules.danger.regex_dos import analyze_pattern

RULE = "SKY-D379"


def scan(tmp_path, code):
    path = tmp_path / "server.py"
    path.write_text(code)
    return [f for f in scan_ctx(tmp_path, [path]) if f["rule_id"] == RULE]


@pytest.mark.parametrize(
    "pattern",
    [
        r"(a+)+$",
        r"(\w+\s?)+$",
        r"^(a|a)*$",
        r"([a-zA-Z]+)*@",
        r"(.*a){12}$",
        r"^(\d+|\d+\.)+x",
        r"(a*)*b",
    ],
)
def test_exponential_patterns_are_found(pattern):
    verdict = analyze_pattern(pattern, 0, "match")

    assert verdict is not None
    assert verdict["growth"] == "exponential"
    assert verdict["pump"]


@pytest.mark.parametrize(
    ("pattern", "mode"),
    [
        (r"\s*\s*\s*x", "match"),
        (r"^\d*\d*\d*$", "match"),
        (r"\s*\s*=", "search"),
        (r"\w*\w*,", "search"),
    ],
)
def test_cubic_patterns_are_found(pattern, mode):
    verdict = analyze_pattern(pattern, 0, mode)

    assert verdict is not None
    assert verdict["growth"] == "polynomial"


@pytest.mark.parametrize(
    ("pattern", "mode"),
    [
        (r"(\d+\.)+\d+$", "match"),
        (r"^[\w.+-]+@[\w-]+\.[\w.-]+$", "match"),
        (r"(\d{1,3}\.){3}\d{1,3}", "search"),
        (r"\s*,\s*", "search"),
        (r"\s*=\s*", "search"),
        (r"^\s*(\w+)\s*=\s*(\S+)$", "match"),
        (r"(ab|cd)+e", "search"),
        (r"(a+)++$", "match"),
        (r"(?>a+)+$", "match"),
        (r"[a-z]+[0-9]+", "search"),
        (r"(a|b|c)*d", "match"),
        (r"<[^>]*>", "search"),
        (r"\d+", "search"),
        (r"hello world", "search"),
    ],
)
def test_linear_and_quadratic_patterns_stay_quiet(pattern, mode):
    assert analyze_pattern(pattern, 0, mode) is None


@pytest.mark.parametrize(
    "pattern",
    [r"(a+)+\1$", r"(?<=x)(a+)+$", r"(a+", r"(?i:(a+))+$"],
)
def test_unsupported_or_invalid_patterns_give_no_verdict(pattern):
    assert analyze_pattern(pattern, 0, "match") is None


def test_attack_string_is_reported_and_reproduces():
    verdict = analyze_pattern(r"(a+)+$", 0, "match")

    assert verdict["prefix"] == ""
    assert verdict["pump"] == "a"
    assert verdict["suffix"] != ""


@pytest.mark.parametrize(
    "code",
    [
        "import re\nre.compile(r'(a+)+$')\n",
        "import re\nre.match(r'(\\w+\\s?)+$', text)\n",
        "import re as regex\nregex.search(r'(a+)+$', text)\n",
        "from re import compile\ncompile(r'(a+)+$')\n",
        "import re\nPATTERN = r'(a+)+$'\nre.compile(PATTERN)\n",
        "import re\nre.compile('(a+)' '+$')\n",
        "import re\nre.sub(r'(a+)+$', '', text)\n",
        "import re\nre.compile(r'''\n  (a+)+   # words\n  $\n''', re.VERBOSE)\n",
    ],
)
def test_regex_calls_are_reported(tmp_path, code):
    findings = scan(tmp_path, code)

    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert "backtracking" in findings[0]["message"]
    assert findings[0]["metadata"]["regex_attack"]["pump"] == "a"
    assert json.dumps(findings)


@pytest.mark.parametrize(
    "code",
    [
        "import re\nre.compile(r'(\\d+\\.)+\\d+$')\n",
        "import re\nre.compile(pattern)\n",
        "import re\nre.compile(f'({name}+)+$')\n",
        "import re\nre.compile(r'(a+)+$', flags)\n",
        "class re:\n    @staticmethod\n    def compile(value): pass\nre.compile(r'(a+)+$')\n",
        "import regex\nregex.compile(r'(a+)+$')\n",
        "import re\ndef build(re):\n    return re.compile(r'(a+)+$')\n",
        "import re\nre.escape(r'(a+)+$')\n",
        "import re\nPATTERN = r'(a+)+$'\nPATTERN = load()\nre.compile(PATTERN)\n",
        "text = '(a+)+$'\n",
    ],
)
def test_safe_unknown_and_lookalike_calls_stay_quiet(tmp_path, code):
    assert scan(tmp_path, code) == []


def test_one_finding_per_call_with_the_line_of_the_call(tmp_path):
    code = "import re\n\nA = re.compile(r'(a+)+$')\nB = re.compile(r'\\d+')\nC = re.compile(r'(b+)+$')\n"

    assert [f["line"] for f in scan(tmp_path, code)] == [3, 5]


def test_analysis_is_bounded_on_a_file_full_of_patterns(tmp_path):
    lines = ["import re"]
    for index in range(400):
        lines.append(f"P{index} = re.compile(r'(a+)+(b+)+(c+)+k{index}$')")

    findings = scan(tmp_path, "\n".join(lines) + "\n")

    assert 0 < len(findings) <= 400


def test_patterns_in_test_files_stay_quiet(tmp_path):
    folder = tmp_path / "tests"
    folder.mkdir()
    path = folder / "test_patterns.py"
    path.write_text(
        "import re\n\n\ndef test_slow():\n    assert re.compile(r'(a+)+$')\n"
    )

    assert [f for f in scan_ctx(tmp_path, [path]) if f["rule_id"] == RULE] == []
