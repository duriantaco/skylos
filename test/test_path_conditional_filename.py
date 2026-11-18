"""A finite filename choice constrains the checked HTTP value only."""

import ast

import pytest

from skylos.reporting.advice_policy import apply_advice_policy
from skylos.reporting.listing import is_path_review
from skylos.rules.danger.danger_fs.path_flow import scan
from skylos.rules.danger.danger_fs.path_provenance import (
    resolve_helper_parameter_findings,
)


def _findings(tmp_path, choice, *, next_line="", setup="", suffix="", dependency=""):
    source = (
        "from pathlib import Path\nfrom flask import Flask, request\n"
        + ("import helpers\n" if dependency else "")
        + "app = Flask(__name__)\n"
        + setup
        + "@app.get('/document')\ndef document():\n"
        + "    value = request.args['name']\n    other = request.args['other']\n"
        + "    name = "
        + choice
        + "\n"
        + next_line
        + "    return open(Path('/srv/reports') / name).read(16)\n"
        + suffix
    )
    (tmp_path / "pyproject.toml").write_text('[project]\nname="filename-choices"\n')
    if dependency:
        (tmp_path / "helpers.py").write_text(dependency)
    path = tmp_path / "app.py"
    path.write_text(source)
    findings = []
    scan(ast.parse(source), path, findings)
    kept = resolve_helper_parameter_findings(
        findings, scan_path=tmp_path, project_root=tmp_path, suppressed=[]
    )
    result = {"danger": kept}
    result = apply_advice_policy(result)
    by_rule = {row["rule_id"]: row for row in result["danger"]}
    assert by_rule["SKY-D325"]["listing"]["listed"]
    return by_rule["SKY-D215"]


CHOICE = "value if value in ('public.txt', 'manual.txt') else 'manual.txt'"


@pytest.mark.parametrize(
    "choice",
    [
        CHOICE,
        "'manual.txt' if value not in {'public.txt', 'manual.txt'} else value",
    ],
)
def test_finite_choice_leaves_a_reviewable_http_guard(tmp_path, choice):
    row = _findings(tmp_path, choice)
    assert is_path_review(row)
    proof = row["metadata"]["path_provenance"]
    assert proof["status"] == "conditional_http_guard"
    assert any(
        "finite set of literal filenames" in step
        for chain in proof["guarded_http"]
        for step in chain
    )


@pytest.mark.parametrize(
    ("choice", "after", "setup", "suffix", "dependency"),
    [
        (CHOICE.replace("value if value", "other if value"), "", "", "", ""),
        (CHOICE.replace(" in ", " not in "), "", "", "", ""),
        (CHOICE.replace("'public.txt'", "'directory/index'"), "", "", "", ""),
        (CHOICE.replace("else 'manual.txt'", "else other"), "", "", "", ""),
        (CHOICE, "    name = other\n", "", "", ""),
        (CHOICE, "    name = name.replace('manual.txt', other)\n", "", "", ""),
        (CHOICE, "", "app.request_class = AlternateRequest\n", "", ""),
        (CHOICE, "", "", "", "import flask\nflask.request = alternate\n"),
        (CHOICE, "", "", "mutate_app(app)\n", ""),
        (CHOICE, "", "", "mutate_request(request)\n", ""),
        (CHOICE, "", "", "", "from flask import Request as R\nmutate_class(R)\n"),
    ],
    ids=[
        "sibling",
        "inverted",
        "non-filename",
        "untrusted-fallback",
        "reassigned",
        "rewritten",
        "custom-request",
        "replaced-import",
        "escaped-app",
        "escaped-request",
        "escaped-imported-request-class",
    ],
)
def test_unsafe_or_unproven_choice_remains_primary(
    tmp_path, choice, after, setup, suffix, dependency
):
    row = _findings(
        tmp_path,
        choice,
        next_line=after,
        setup=setup,
        suffix=suffix,
        dependency=dependency,
    )
    assert row["listing"]["listed"]
    assert row["metadata"]["path_provenance"]["status"] == "untrusted"
