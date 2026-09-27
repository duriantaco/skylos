"""Weak hashes stay visible unless the call explicitly opts out of security use."""

import ast

import pytest

from skylos.core.linter import LinterVisitor
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.danger import scan_ctx


HASH_RULES = {"SKY-D207", "SKY-D208"}


def _hash_findings_from_both_paths(tmp_path, code):
    path = tmp_path / "hash_case.py"
    path.write_text(  # skylos: ignore[SKY-D324] fixed fixture path under pytest tmp_path
        code, encoding="utf-8"
    )
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    linter.visit(ast.parse(code))
    return (
        [item for item in scan_ctx(tmp_path, [path]) if item["rule_id"] in HASH_RULES],
        [item for item in linter.findings if item["rule_id"] in HASH_RULES],
    )


@pytest.mark.parametrize(
    ("algorithm", "rule_id"),
    [("md5", "SKY-D207"), ("sha1", "SKY-D208")],
)
def test_neutral_names_do_not_hide_authentication_comparison(
    tmp_path, algorithm, rule_id
):
    code = (
        "import hashlib\n"
        '@app.post("/login")\n'
        "def check(body, row):\n"
        f"    return hashlib.{algorithm}(body).hexdigest() == row.digest\n"
    )
    for findings in _hash_findings_from_both_paths(tmp_path, code):
        assert {item["rule_id"] for item in findings} == {rule_id}


def test_names_alone_do_not_prove_nonsecurity_use(tmp_path):
    code = (
        "import hashlib\n"
        "def cache_key(data):\n"
        "    return hashlib.md5(data).hexdigest()\n"
        "content_id = hashlib.sha1(b'blob').hexdigest()\n"
    )
    for findings in _hash_findings_from_both_paths(tmp_path, code):
        assert {item["rule_id"] for item in findings} == HASH_RULES


def test_explicit_nonsecurity_optout_is_preserved(tmp_path):
    code = (
        "import hashlib\n"
        "def check(body, row):\n"
        "    return hashlib.md5(body, usedforsecurity=False).hexdigest() == row.digest\n"
        "value = hashlib.sha1(b'blob', usedforsecurity=False).hexdigest()\n"
    )
    for findings in _hash_findings_from_both_paths(tmp_path, code):
        assert findings == []
