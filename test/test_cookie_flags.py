"""SKY-D252: a response cookie written with secure or httponly turned off by a
literal False, through the production analyzer."""

import json

import pytest

from skylos.analyzer import analyze
from test.fixture_paths import write_fixture


def _analyze(tmp_path, monkeypatch, source, name="app.py"):
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
            all_advice=False,
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
            'def login(token):\n    resp = make_response("ok")\n'
            '    resp.set_cookie("sid", token, secure=False)\n    return resp\n',
            {"httpOnly": "absent", "secure": "false"},
        ),
        (
            FLASK,
            'def login(token):\n    resp = make_response("ok")\n'
            '    resp.set_cookie("sid", token, secure=True, httponly=False)\n    return resp\n',
            {"httpOnly": "false", "secure": "true"},
        ),
        (
            FLASK,
            'def login(token):\n    resp = make_response("ok")\n'
            '    resp.set_cookie("sid", token, 60, None, "/", None, False, True)\n'
            "    return resp\n",
            {"httpOnly": "true", "secure": "false"},
        ),
        (
            DJANGO,
            'def login(request, token):\n    response = HttpResponse("ok")\n'
            '    response.set_cookie(key="sid", value=token, httponly=False, secure=False)\n'
            "    return response\n",
            {"httpOnly": "false", "secure": "false"},
        ),
        (
            DJANGO,
            'def login(request, token):\n    response = HttpResponse("ok")\n'
            '    response.set_signed_cookie("sid", token, salt="s", secure=False, **{})\n'
            "    return response\n",
            {"httpOnly": "unknown", "secure": "false"},
        ),
        (
            FLASK,
            'def login(token):\n    resp = make_response("ok")\n    other = resp\n'
            '    other.set_cookie("sid", token, secure=False)\n    return resp\n',
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
    "call, listed",
    [
        ('resp.set_cookie("logged_user", "true", httponly=False)', False),
        ('resp.set_cookie(key="banner", value="Off", secure=False)', False),
        ('resp.set_cookie("seen", 1, max_age=None, path="/", secure=False)', False),
        ('resp.set_cookie("seen", 1, None, None, "/", None, False)', True),
        ('resp.set_cookie("staff", "yes", 32, secure=False)', True),
        ('resp.set_cookie("flag", b"1", httponly=False)', False),
        ('resp.set_cookie("seen", "1", 60, None, "/", None, False)', True),
        ('resp.set_signed_cookie("staff", "yes", salt="s", secure=False)', True),
        ('resp.set_signed_cookie("flag", b"1", salt="s", httponly=False)', True),
        ('resp.set_cookie("staff", "yes", secret=KEY, secure=False)', True),
        ('resp.set_cookie("staff", "yes", KEY, secure=False)', True),
        ('resp.set_cookie("staff", "yes", "k3y", secure=False)', True),
        ('resp.set_cookie("staff", "yes", None, KEY, secure=False)', True),
        ('resp.set_cookie("staff", "yes", httponly=False, digestmod=KEY)', True),
        ('resp.set_cookie("staff", "yes", httponly=False, **options)', True),
        ('resp.set_cookie("sid", "", max_age=0, secure=False)', False),
        ('resp.set_cookie("staff", "9f1b6e43d842a7c5", secure=False)', True),
        ('resp.set_cookie("admin", "letmein", httponly=False)', True),
        ('resp.set_cookie(key="lang", value="en", secure=False)', True),
        ('resp.set_cookie("pin", 4821, secure=False)', True),
        ('resp.set_cookie("key", b"\\xff", secure=False)', True),
        ('resp.set_cookie("sid", token, httponly=False)', True),
        ('resp.set_cookie("sid", value=token, secure=False)', True),
        ('resp.set_cookie("sid", f"{token}", secure=False)', True),
        ('resp.set_cookie("sid", "v" + token, secure=False)', True),
        ('resp.set_cookie("sid", TOKEN, secure=False)', True),
        ("resp.set_cookie(*parts, secure=False)", True),
        ('resp.set_cookie("sid", *parts, secure=False)', True),
        ('resp.set_cookie("sid", secure=False, **options)', True),
    ],
)
def test_on_off_flag_cookie_value_is_kept_but_hidden(
    tmp_path, monkeypatch, call, listed
):
    source = (
        FLASK
        + 'TOKEN = "abc"\n'
        + "KEY = TOKEN\n"
        + "def login(token, parts, options):\n"
        + '    resp = make_response("ok")\n'
        + f"    {call}\n"
        + "    return resp\n"
    )
    findings = _cookie_findings(_analyze(tmp_path, monkeypatch, source))
    assert [f["line"] for f in findings] == [7]
    finding = findings[0]
    assert finding["listing"]["listed"] is listed
    context = finding.get("low_risk_context")
    if listed:
        assert context is None
    else:
        assert context["reason"] == "on-off-cookie-value"


@pytest.mark.parametrize(
    "name, helper",
    [
        (
            "app.py",
            "class SignedResponse:\n"
            "    def set_cookie(self, key, value, **kw):\n"
            "        return (key, value, kw)\n",
        ),
        ("signing.py", "def install(cls, signer):\n    cls.set_cookie = signer\n"),
        (
            "signing.py",
            "def install(cls, signer):\n    setattr(cls, 'set_cookie', signer)\n",
        ),
        (
            "signing.py",
            "class Signed:\n    async def set_cookie(self, key, value):\n        return value\n",
        ),
    ],
)
def test_project_that_defines_or_patches_set_cookie_keeps_flag_cookies_listed(
    tmp_path, monkeypatch, name, helper
):
    view = (
        FLASK
        + "def login():\n"
        + '    resp = make_response("ok")\n'
        + '    resp.set_cookie("staff", "yes", secure=False)\n'
        + "    return resp\n"
    )
    if name == "app.py":
        view = view + helper
    else:
        write_fixture(tmp_path, name, helper)
    findings = _cookie_findings(_analyze(tmp_path, monkeypatch, view))
    assert [f["line"] for f in findings] == [5]
    assert findings[0]["listing"]["listed"] is True
    assert findings[0].get("low_risk_context") is None


def test_guarded_signed_flag_cookie_through_alias_and_wrapper_stays_listed(
    tmp_path, monkeypatch
):
    source = (
        DJANGO
        + "def emit(response):\n"
        + '    response.set_signed_cookie("staff", "yes", salt="s", secure=False)\n'
        + "def issue(request):\n"
        + "    if not request.user.is_staff:\n"
        + "        return HttpResponse(status=403)\n"
        + '    response = HttpResponse("ok")\n'
        + "    alias = response\n"
        + "    emit(alias)\n"
        + "    return response\n"
        + "def staff_area(request):\n"
        + '    if request.get_signed_cookie("staff", default="", salt="s") != "yes":\n'
        + "        return HttpResponse(status=403)\n"
        + '    return HttpResponse("private")\n'
    )
    findings = _cookie_findings(_analyze(tmp_path, monkeypatch, source))
    assert [f["line"] for f in findings] == [3]
    finding = findings[0]
    assert finding["listing"]["listed"] is True
    assert finding.get("low_risk_context") is None
    evidence = finding["metadata"]["security_evidence"]
    assert evidence["options"] == {"httpOnly": "absent", "secure": "false"}
    assert finding["evidence_contract"]["proof_state"] == "verified"


@pytest.mark.parametrize(
    "body",
    [
        'resp.set_cookie("sid", "v", secure=True, httponly=True)',
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
