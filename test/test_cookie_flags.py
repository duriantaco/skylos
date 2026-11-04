"""SKY-D252: a Python response cookie written with secure turned off by a
literal False, through the production analyzer. An explicit httponly=False
alone is a deliberate script-readable cookie and is not reported."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from test.fixture_paths import write_fixture


def _analyze(tmp_path, monkeypatch, source, name="app.py", *, all_advice=True):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    write_fixture(tmp_path, name, source)
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="cookies"\n')
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_verify=False,
            grep_cache=False,
            all_advice=all_advice,
        )
    )
    assert not result.get("analysis_errors")
    return result


def _cookie_findings(result):
    return [f for f in result.get("danger", []) if f["rule_id"] == "SKY-D252"]


FLASK = "from flask import Flask, make_response\napp = Flask(__name__)\n"
DJANGO = "from django.http import HttpResponse\n"


@pytest.mark.parametrize(
    "prefix, body, options",
    [
        (
            FLASK,
            'def login():\n    resp = make_response("ok")\n'
            '    resp.set_cookie("sid", "v", secure=False)\n    return resp\n',
            {"httpOnly": "absent", "secure": "false"},
        ),
        (
            FLASK,
            'def login():\n    resp = make_response("ok")\n'
            '    resp.set_cookie("sid", "v", 60, None, "/", None, False, True)\n'
            "    return resp\n",
            {"httpOnly": "true", "secure": "false"},
        ),
        (
            DJANGO,
            'def login(request):\n    response = HttpResponse("ok")\n'
            '    response.set_cookie(key="sid", value="v", httponly=False, secure=False)\n'
            "    return response\n",
            {"httpOnly": "false", "secure": "false"},
        ),
        (
            DJANGO,
            'def login(request):\n    response = HttpResponse("ok")\n'
            '    response.set_signed_cookie("sid", "v", salt="s", secure=False, **{})\n'
            "    return response\n",
            {"httpOnly": "unknown", "secure": "false"},
        ),
        (
            FLASK,
            'def login():\n    resp = make_response("ok")\n    other = resp\n'
            '    other.set_cookie("sid", "v", secure=False)\n    return resp\n',
            {"httpOnly": "absent", "secure": "false"},
        ),
        (
            FLASK,
            "def remember(resp, value):\n"
            '    resp.set_cookie("sid", value, secure=False)\n'
            "def login():\n"
            '    resp = make_response("ok")\n    remember(resp, "v")\n    return resp\n',
            {"httpOnly": "absent", "secure": "false"},
        ),
    ],
)
def test_literal_false_cookie_flag_is_reported_with_complete_evidence(
    tmp_path, monkeypatch, prefix, body, options
):
    source = prefix + body
    line = next(
        number
        for number, text in enumerate(source.splitlines(), start=1)
        if "_cookie(" in text
    )
    findings = _cookie_findings(_analyze(tmp_path, monkeypatch, source))
    assert [(f["line"], f["severity"]) for f in findings] == [(line, "MEDIUM")]
    finding = findings[0]
    assert finding["listing"]["listed"] is True
    evidence = finding["metadata"]["security_evidence"]
    assert evidence["evidence_kind"] == "cookie_security_options"
    assert evidence["options"] == options
    assert finding["evidence_contract"]["proof_state"] == "verified"


@pytest.mark.parametrize(
    "prefix, factory, writer",
    [
        (FLASK, 'make_response("ok")', "set_cookie"),
        (DJANGO, 'HttpResponse("ok")', "set_signed_cookie"),
    ],
)
@pytest.mark.parametrize(
    "call",
    [
        'resp.{writer}("sid", token, {flag})',
        'resp.{writer} ("sid", token, {flag})',
        'resp.{writer}\t("sid", token, {flag})',
        "resp.{writer} " + chr(92) + '\n        ("sid", token, {flag})',
        '(resp.{writer}\n    )("sid", token, {flag})',
        '(resp.{writer}  # cookie writer\n    )("sid", token, {flag})',
    ],
    ids=["normal", "space", "tab", "continuation", "parenthesized", "comment"],
)
@pytest.mark.parametrize(
    "flag, reported",
    [("secure=False", True), ("secure=True", False), ("httponly=False", False)],
)
def test_cookie_call_formatting_preserves_findings_and_gate(
    tmp_path, monkeypatch, prefix, factory, writer, call, flag, reported
):
    source = (
        prefix
        + "def login(token):\n"
        + f"    resp = {factory}\n"
        + "    "
        + call.format(writer=writer, flag=flag)
        + "\n    return resp\n"
    )
    findings = _cookie_findings(
        _analyze(tmp_path, monkeypatch, source, all_advice=False)
    )
    expected = []
    if reported:
        expected = [(len(prefix.splitlines()) + 3, "MEDIUM", "login")]
    assert [(f["line"], f["severity"], f["symbol"]) for f in findings] == expected
    assert all(f["listing"]["listed"] is True for f in findings)
    assert check_gate({"danger": findings}, {"gate": {"max_security": 0}})[0] is (
        not reported
    )


@pytest.mark.parametrize(
    "body",
    [
        'resp.set_cookie("sid", "v", secure=True, httponly=True)',
        'resp.set_cookie("sid", "v", secure=True, httponly=False)',
        'resp.set_cookie("logged_user", "true", httponly=False)',
        'resp.set_cookie("sid", "v", 60, None, "/", None, True, False)',
        'resp.set_cookie("sid", "v", 60, None, "/", None, None, False)',
        'resp.set_cookie("sid", "v")',
        'resp.set_cookie("sid", "v", max_age=60, samesite="Lax")',
        'resp.set_cookie("sid", "v", secure=use_https, httponly=False if 0 else True)',
        'resp.set_cookie("sid", "v", secure=SECURE_COOKIES)',
        'resp.set_cookie("sid", "v", **options)',
        'resp.set_cookie("sid", "v", None, None, "/", None, use_https)',
        'resp.set_cookie("sid", "v", *extra, False)',
        "jar.set_cookie(cookie)",
        "set_cookie_header = resp.set_cookie",
    ],
)
def test_cookie_flags_that_are_true_absent_or_computed_stay_quiet(
    tmp_path, monkeypatch, body
):
    source = (
        FLASK
        + "SECURE_COOKIES = False\n"
        + "def login(use_https, options, extra, jar, cookie):\n"
        + '    resp = make_response("ok")\n'
        + f"    {body}\n"
        + "    return resp\n"
    )
    assert _cookie_findings(_analyze(tmp_path, monkeypatch, source)) == []


def test_cookie_writer_definition_with_false_defaults_is_not_a_cookie_write(
    tmp_path, monkeypatch
):
    source = (
        "class Response:\n"
        "    def set_cookie(self, key, value='', secure=False, httponly=False):\n"
        "        self.cookie = (key, value, secure, httponly)\n"
    )
    assert _cookie_findings(_analyze(tmp_path, monkeypatch, source)) == []


@pytest.mark.parametrize(
    "name, reported",
    [
        ("tests/test_login.py", False),
        ("login_test.py", False),
        ("latest_cookies.py", True),
        ("contest/views.py", True),
    ],
)
def test_test_modules_are_not_reported_but_lookalike_paths_are(
    tmp_path, monkeypatch, name, reported
):
    source = (
        FLASK
        + 'def login():\n    resp = make_response("ok")\n'
        + '    resp.set_cookie("sid", "v", secure=False)\n    return resp\n'
    )
    findings = _cookie_findings(_analyze(tmp_path, monkeypatch, source, name=name))
    assert bool(findings) is reported
