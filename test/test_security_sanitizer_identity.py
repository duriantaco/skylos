"""Sanitizer proof follows the native API and the destination context."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from test.fixture_paths import write_fixture


def _analyze(tmp_path, monkeypatch, source, providers=()):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    write_fixture(tmp_path, "app.py", source)
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="proof"\n')
    for name, text in providers:
        write_fixture(tmp_path, name, text)
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_verify=False,
            grep_cache=False,
        )
    )
    assert not result.get("analysis_errors")
    assert result.get("analysis_summary", {}).get("analysis_error_count", 0) == 0
    return result


@pytest.mark.parametrize(
    "setup, expression, vulnerable",
    [
        ("", 'request.args.get("next")', True),
        ("", 'url_for("home", next=request.args.get("next"))', False),
        (
            "from flask import url_for as build\n",
            'build("home", next=request.args.get("next"))',
            False,
        ),
        (
            "def url_for(value):\n    return value\n",
            'url_for(request.args.get("next"))',
            True,
        ),
        (
            "class Helper:\n    def url_for(self, value):\n        return value\nhelper=Helper()\n",
            'helper.url_for(request.args.get("next"))',
            True,
        ),
        (
            "import flask\nflask.url_for=lambda value: value\n",
            'flask.url_for(request.args.get("next"))',
            True,
        ),
    ],
)
def test_redirect_builder_requires_native_identity(
    tmp_path, monkeypatch, setup, expression, vulnerable
):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "from flask import request, redirect, url_for\n"
        + setup
        + "def run():\n    return redirect("
        + expression
        + ")\n",
    )
    rows = [f for f in result.get("danger", []) if f["rule_id"] == "SKY-D230"]
    assert bool(rows) is vulnerable
    if rows:
        assert rows[0]["listing"]["listed"] is True
    passed, reasons = check_gate(result, {"gate": {"max_high": 0, "max_critical": 0}})
    assert passed is not vulnerable, reasons


@pytest.mark.parametrize(
    "setup, expression, vulnerable",
    [
        ("", "value", True),
        ("", '"/srv/uploads/" + os.path.basename(value)', False),
        (
            "from os.path import basename as filename\n",
            '"/srv/uploads/" + filename(value)',
            False,
        ),
        (
            "def _resolve_policy_path(value):\n    return value\n",
            "_resolve_policy_path(value)",
            True,
        ),
        (
            "def safe_join(base, value):\n    return value\n",
            'safe_join("/srv/uploads", value)',
            True,
        ),
        (
            "os.path.basename=lambda value: value\n",
            '"/srv/uploads/" + os.path.basename(value)',
            True,
        ),
        ("import html\n", "html.escape(value)", True),
        ("from html import escape as encode\n", "encode(value)", True),
    ],
)
def test_path_sanitizer_requires_native_identity_and_path_context(
    tmp_path, monkeypatch, setup, expression, vulnerable
):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import os\nfrom flask import Flask, request\napp=Flask(__name__)\n"
        + setup
        + '@app.get("/download")\ndef run():\n'
        + '    value=request.args.get("file")\n'
        + "    return open("
        + expression
        + ").read()\n",
    )
    rows = [f for f in result.get("danger", []) if f["rule_id"] == "SKY-D215"]
    assert bool(rows) is vulnerable
    if rows:
        assert rows[0]["listing"]["listed"] is True
        assert rows[0]["severity"] == "HIGH"
    passed, reasons = check_gate(result, {"gate": {"max_high": 0, "max_critical": 0}})
    assert passed is not vulnerable, reasons


@pytest.mark.parametrize(
    "setup, expression, providers, vulnerable",
    [
        (
            "def _resolve_policy_path(value):\n    return os.path.basename(value)\n",
            '"/srv/uploads/" + _resolve_policy_path(value)',
            (),
            False,
        ),
        (
            "from werkzeug.security import safe_join\n",
            'safe_join("/srv/uploads", value)',
            (),
            False,
        ),
        (
            "from werkzeug.security import safe_join\n",
            'safe_join(value, "file.txt")',
            (),
            True,
        ),
        (
            "from werkzeug.security import safe_join\n",
            'safe_join("/srv/uploads", value)',
            (
                ("werkzeug/__init__.py", ""),
                (
                    "werkzeug/security.py",
                    "def safe_join(base, value):\n    return value\n",
                ),
            ),
            True,
        ),
    ],
)
def test_path_helpers_follow_arguments_and_project_provider(
    tmp_path, monkeypatch, setup, expression, providers, vulnerable
):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import os\nfrom flask import request\n"
        + setup
        + 'def run():\n    value=request.args.get("file")\n    return open('
        + expression
        + ").read()\n",
        providers,
    )
    assert (
        any(f["rule_id"] == "SKY-D215" for f in result.get("danger", [])) is vulnerable
    )


@pytest.mark.parametrize(
    "setup, expression, providers, vulnerable",
    [
        ("", "shlex.quote(value)", (), False),
        ("from shlex import quote as encode\n", "encode(value)", (), False),
        ("shlex.quote=lambda value:value\n", "shlex.quote(value)", (), True),
        (
            "",
            "shlex.quote(value)",
            (("shlex.py", "def quote(value):\n    return value\n"),),
            True,
        ),
    ],
)
def test_command_quote_requires_native_provider(
    tmp_path, monkeypatch, setup, expression, providers, vulnerable
):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import os, shlex\n"
        + setup
        + 'def run(value):\n    os.system("echo " + '
        + expression
        + ")\n",
        providers,
    )
    assert (
        any(f["rule_id"] == "SKY-D212" for f in result.get("danger", [])) is vulnerable
    )


def test_redirect_builder_from_local_provider_is_not_native(tmp_path, monkeypatch):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "from werkzeug.utils import redirect\nimport flask\n"
        "from fastapi import FastAPI, Request\napi=FastAPI()\n"
        "def run(value):\n    return redirect(flask.url_for(value))\n"
        "@api.get('/go')\ndef route(request: Request):\n"
        "    return run(request.query_params['next'])\n",
        (("flask.py", "def url_for(value):\n    return value\n"),),
    )
    assert any(f["rule_id"] == "SKY-D230" for f in result.get("danger", []))


@pytest.mark.parametrize(
    "setup, command, vulnerable",
    [
        ("", '"echo " + shlex.quote(value)', False),
        ("", "'echo \"' + shlex.quote(value) + '\"'", True),
        ("", '"echo \'" + shlex.quote(value) + "\'"', True),
        ("", '"echo \\\\" + shlex.quote(value)', True),
        ("    safe=shlex.quote(value)\n", "'echo \"' + safe + '\"'", True),
        ("", "f'echo \"{shlex.quote(value)}\"'", True),
        ("", '"echo " + shlex.join([value])', False),
        ("", "'echo \"' + shlex.join([value]) + '\"'", True),
        ("", '"echo hello # " + shlex.quote(value)', True),
        ("", '"echo pre#" + shlex.quote(value)', False),
        ("", '"echo # comment\\n echo " + shlex.quote(value)', False),
        ("", '"echo " + shlex.quote("fixed") + " " + shlex.quote(value)', False),
        ("", '"echo " + shlex.quote(shlex.quote(value))', False),
        ("", "'echo \"' + shlex.quote(shlex.quote(value)) + '\"'", True),
    ],
)
def test_command_quote_must_be_a_shell_word(
    tmp_path, monkeypatch, setup, command, vulnerable
):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import subprocess, shlex\ndef run(value):\n"
        + setup
        + "    subprocess.run("
        + command
        + ", shell=True)\n",
    )
    assert (
        any(f["rule_id"] == "SKY-D212" for f in result.get("danger", [])) is vulnerable
    )


def test_command_taint_tracks_command_operand_and_import_alias(tmp_path, monkeypatch):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import subprocess as process\nimport os as posix\n"
        "value='constant'\ndef run(value):\n"
        "    process.run('echo hello', shell=True, cwd=value)\n"
        "    process.run(value, shell=True)\n"
        "    posix.system(value)\n",
    )
    rows = [f for f in result.get("danger", []) if f["rule_id"] == "SKY-D212"]
    assert [f["line"] for f in rows] == [6, 7]


def test_isolated_aliased_system_call_reaches_command_checker(tmp_path, monkeypatch):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import os as posix\ndef run(value):\n    posix.system(value)\n",
    )
    assert any(f["rule_id"] == "SKY-D212" for f in result.get("danger", []))


@pytest.mark.parametrize(
    "body, vulnerable",
    [
        ("    if flag:\n        value=shlex.quote(value)\n", True),
        ("    for item in items:\n        value=shlex.quote(value)\n", True),
        (
            "    if flag:\n        value=shlex.quote(value)\n    else:\n        value=shlex.quote(other)\n",
            False,
        ),
        ('    value=""\n    value += other\n', True),
    ],
)
def test_command_quote_preserves_other_paths(tmp_path, monkeypatch, body, vulnerable):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import subprocess, shlex\ndef run(value,other,flag,items):\n"
        + body
        + '    subprocess.run("echo " + value, shell=True)\n',
    )
    assert (
        any(f["rule_id"] == "SKY-D212" for f in result.get("danger", [])) is vulnerable
    )
