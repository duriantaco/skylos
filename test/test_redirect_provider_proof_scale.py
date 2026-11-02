"""SKY-D230 trusts Flask's ``url_for`` only after the project-wide provider
proof passes. The proof must survive ordinary large projects and in-place
literal ``__import__`` reads, and must still fail on real provider tampering."""

import json

import pytest

from skylos.analyzer import analyze
from test.fixture_paths import write_fixture

VIEW = (
    "from flask import Flask, redirect, request, url_for\n"
    "app = Flask(__name__)\n"
    "@app.route('/private')\n"
    "def private():\n"
    "    return redirect(url_for('login', next=request.full_path))\n"
)
VIEW_LINE = 5


def _redirect_lines(root, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    write_fixture(root, "pyproject.toml", '[project]\nname="shop"\n')
    result = json.loads(
        analyze(
            str(root),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_verify=False,
            grep_cache=False,
            all_advice=False,
        )
    )
    assert not result.get("analysis_errors")
    return sorted(
        (f["file"].replace(str(root), "").lstrip("/"), f["line"])
        for f in result.get("danger", [])
        if f["rule_id"] == "SKY-D230"
    )


def _write(root, name, source):
    write_fixture(root, name, source)


@pytest.mark.parametrize(
    "helper, reported",
    [
        (
            "def context():\n"
            "    ctx = __import__('ssl').create_default_context()\n"
            "    ctx.verify_mode = __import__('ssl').CERT_REQUIRED\n"
            "    return ctx\n",
            False,
        ),
        ("def tamper(evil):\n    __import__('flask').url_for = evil\n", True),
        (
            "def tamper(fake):\n    __import__('sys').modules['flask'] = fake\n",
            True,
        ),
        (
            "def tamper(fake):\n    __import__('os').sys.modules['flask'] = fake\n",
            True,
        ),
        ("def load(name):\n    return __import__(name).thing\n", True),
        ("def load():\n    module = __import__('ssl')\n    return module\n", True),
        ("def load(hook):\n    return hook(__import__('ssl'))\n", True),
        (
            "def load():\n    return __import__('importlib').import_module('x')\n",
            True,
        ),
        ("def load():\n    return __import__('ssl', globals()).CERT_NONE\n", True),
    ],
)
def test_literal_import_reads_keep_url_for_trusted_but_tampering_does_not(
    tmp_path, monkeypatch, helper, reported
):
    _write(tmp_path, "shop/__init__.py", "")
    _write(tmp_path, "shop/views.py", "from shop import helpers\n" + VIEW)
    _write(tmp_path, "shop/helpers.py", helper)
    expected = [("shop/views.py", VIEW_LINE + 1)] if reported else []
    assert _redirect_lines(tmp_path, monkeypatch) == expected


def _large_project(root, size, tail):
    _write(root, "shop/__init__.py", "")
    _write(
        root,
        "shop/views.py",
        "from shop import m0\nfrom shop.common import settings\n" + VIEW,
    )
    _write(root, "shop/common.py", "settings = {}\n")
    for index in range(size):
        following = f"from shop import m{index + 1}\n" if index + 1 < size else tail
        _write(
            root,
            f"shop/m{index}.py",
            "import json\nimport os.path\nfrom shop.common import settings\n"
            + following
            + f"VALUE_{index} = json.dumps(settings)\n",
        )


def test_url_for_stays_trusted_across_a_project_larger_than_the_old_walk_limit(
    tmp_path, monkeypatch
):
    _large_project(tmp_path, 180, "")
    assert _redirect_lines(tmp_path, monkeypatch) == []


def test_tampering_deep_in_a_large_project_still_breaks_url_for_trust(
    tmp_path, monkeypatch
):
    _large_project(
        tmp_path,
        180,
        "import flask\ndef install(evil):\n    flask.url_for = evil\n",
    )
    assert _redirect_lines(tmp_path, monkeypatch) == [
        ("shop/views.py", VIEW_LINE + 2)
    ]
