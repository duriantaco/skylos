"""Literal-only folding never trusts a name: an alias, a module constant, a
wrapper call in the test, or a wrapper that returns request data on the live
branch keeps eval listed. Runs the production analyzer path."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.reporting.listing import is_listed

HEADER = "from flask import request\n"

LISTED = {
    "wrapper_alias": (
        "def same(value):\n"
        "    return value\n"
        "def run(flag):\n"
        "    alias = same(flag)\n"
        "    code = '1'\n"
        "    if alias:\n"
        "        code = request.args['q']\n"
        "    return eval(code)\n"
    ),
    "constant_looking_local": (
        "def run():\n"
        "    off = 0\n"
        "    code = '1'\n"
        "    if off:\n"
        "        code = request.args['q']\n"
        "    return eval(code)\n"
    ),
    "module_constant_test": (
        "DEBUG = False\n"
        "def run():\n"
        "    code = '1'\n"
        "    if DEBUG:\n"
        "        code = request.args['q']\n"
        "    return eval(code)\n"
    ),
    "wrapper_call_in_test": (
        "def same(value):\n"
        "    return value\n"
        "def run():\n"
        "    code = '1'\n"
        "    if same(False):\n"
        "        code = request.args['q']\n"
        "    return eval(code)\n"
    ),
    "wrapper_returns_request_on_live_branch": (
        "def fetch():\n"
        "    return request.args['q']\n"
        "def run():\n"
        "    code = '1'\n"
        "    if 1 < 2:\n"
        "        code = fetch()\n"
        "    return eval(code)\n"
    ),
    "alias_in_conditional_expression": (
        "def run():\n"
        "    on = 1\n"
        "    code = '1' if on else request.args['q']\n"
        "    return eval(code)\n"
    ),
    "alias_match_subject": (
        "def run():\n"
        "    mode = 'a'\n"
        "    match mode:\n"
        "        case 'a':\n"
        "            code = '1'\n"
        "        case _:\n"
        "            code = request.args['q']\n"
        "    return eval(code)\n"
    ),
    "literal_or_name": (
        "def run(flag):\n"
        "    code = '1'\n"
        "    if 1 > 2 or flag:\n"
        "        code = request.args['q']\n"
        "    return eval(code)\n"
    ),
}


@pytest.fixture(scope="module")
def eval_rows(tmp_path_factory):
    root = tmp_path_factory.mktemp("fold_controls")
    (root / "pyproject.toml").write_text("[project]\nname = 'demo'\n")
    package = root / "app"
    package.mkdir()
    for name, code in LISTED.items():
        (package / f"{name}.py").write_text(HEADER + code)
    result = json.loads(
        analyze(str(root), enable_danger=True, grep_verify=False, all_advice=False)
    )
    rows = {}
    for row in result.get("danger", []):
        if row.get("rule_id") == "SKY-D201":
            stem = row["file"].replace("\\", "/").rsplit("/", 1)[-1][:-3]
            rows.setdefault(stem, []).append(row)
    return rows


@pytest.mark.parametrize("case", sorted(LISTED))
def test_names_and_wrappers_never_fold_away_a_tainted_branch(eval_rows, case):
    [row] = eval_rows[case]
    assert row["severity"] == "HIGH"
    assert "low_risk_context" not in row
    assert is_listed(row, "danger")
