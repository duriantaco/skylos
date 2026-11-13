"""A prefix check proves containment only when the prefix ends at a separator.

``"/srv/files2/x".startswith("/srv/files")`` is true, so a resolved path
checked against a base without a trailing separator can still reach a
sibling directory such as ``/srv/files2``.
"""

import pytest

from skylos.rules.danger.danger import scan_ctx

HEADER = """import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

app = FastAPI()
BASE = "/srv/files"
"""


def traversal_lines(tmp_path, code):
    path = tmp_path / "server.py"
    path.write_text(code)
    return [f["line"] for f in scan_ctx(tmp_path, [path]) if f["rule_id"] == "SKY-D215"]


def route(check, body=None, prefix_lines=""):
    if body is None:
        body = "    target = os.path.normpath(os.path.join(BASE, name))\n"
    return (
        HEADER
        + prefix_lines
        + "\n\n@app.get('/files/{name}')\ndef download(name: str):\n"
        + body
        + f"    if not {check}:\n"
        + "        raise HTTPException(404)\n"
        + "    return FileResponse(target)\n"
    )


def sink_line(code):
    return code.splitlines().index("    return FileResponse(target)") + 1


@pytest.mark.parametrize(
    ("check", "body", "prefix_lines"),
    [
        ("target.startswith(BASE)", None, ""),
        (
            "target.startswith(os.path.realpath(BASE))",
            "    target = os.path.realpath(os.path.join(BASE, name))\n",
            "",
        ),
        (
            "target.startswith(base)",
            "    base = os.path.abspath(load_setting())\n    target = os.path.normpath(os.path.join(base, name))\n",
            "",
        ),
        (
            "str(target).startswith(str(Path(BASE).resolve()))",
            "    target = (Path(BASE) / name).resolve()\n",
            "",
        ),
        ("target.startswith((BASE + os.sep, OTHER))", None, "OTHER = '/srv/other'\n"),
        ("target.startswith(PREFIX)", None, "PREFIX = BASE + os.sep\nPREFIX = BASE\n"),
        (
            "target.startswith(PREFIX)",
            "    PREFIX = BASE\n    target = os.path.normpath(os.path.join(BASE, name))\n",
            "PREFIX = '/srv/files/'\n",
        ),
        (
            "target.startswith(prefix)",
            "    prefix = load_prefix()\n    target = os.path.normpath(os.path.join(BASE, name))\n",
            "",
        ),
        (
            "target.startswith(BASE + suffix)",
            "    suffix = load_suffix()\n    target = os.path.normpath(os.path.join(BASE, name))\n",
            "",
        ),
        ("target.startswith(os.path.join(BASE, 'public'))", None, ""),
        ("target.startswith(os.sep)", None, ""),
        ("target.startswith('/')", None, ""),
        ("target.startswith(f'{os.sep}')", None, ""),
        ("target.startswith(SEP)", None, "SEP = os.path.sep\n"),
        ("target.startswith(os.path.join(BASE, '/'))", None, ""),
    ],
)
def test_prefix_without_a_separator_does_not_prove_containment(
    tmp_path, check, body, prefix_lines
):
    code = route(check, body, prefix_lines)

    assert traversal_lines(tmp_path, code) == [sink_line(code)]


@pytest.mark.parametrize(
    ("check", "body", "prefix_lines"),
    [
        ("target.startswith(BASE + os.sep)", None, ""),
        ("target.startswith(BASE + os.path.sep)", None, ""),
        ("target.startswith(BASE + '/')", None, ""),
        ("target.startswith(f'{BASE}/')", None, ""),
        ("target.startswith(os.path.join(BASE, ''))", None, ""),
        ("target.startswith('/srv/files/')", None, ""),
        (
            "target.startswith(PREFIX)",
            None,
            "PREFIX = os.path.realpath(BASE) + os.sep\n",
        ),
        ("target.startswith(PREFIX)", None, "PREFIX = '/srv/files/'\n"),
        (
            "target.startswith(prefix)",
            "    prefix = BASE + os.sep\n    target = os.path.normpath(os.path.join(BASE, name))\n",
            "",
        ),
        (
            "target.startswith((BASE + os.sep, OTHER + '/'))",
            None,
            "OTHER = '/srv/other'\n",
        ),
        (
            "str(target).startswith(str(Path(BASE).resolve()) + os.sep)",
            "    target = (Path(BASE) / name).resolve()\n",
            "",
        ),
        ("target.startswith(os.path.join(BASE, 'public/'))", None, ""),
    ],
)
def test_prefix_ending_at_a_separator_still_proves_containment(
    tmp_path, check, body, prefix_lines
):
    assert traversal_lines(tmp_path, route(check, body, prefix_lines)) == []


def test_sibling_prefix_in_a_positive_branch_is_reported(tmp_path):
    code = (
        HEADER
        + "\n\n@app.get('/files/{name}')\ndef download(name: str):\n"
        + "    target = os.path.normpath(os.path.join(BASE, name))\n"
        + "    if target.startswith(BASE):\n"
        + "        return FileResponse(target)\n"
        + "    raise HTTPException(404)\n"
    )

    line = code.splitlines().index("        return FileResponse(target)") + 1

    assert traversal_lines(tmp_path, code) == [line]


def test_separator_prefix_in_a_positive_branch_stays_quiet(tmp_path):
    code = (
        HEADER
        + "\n\n@app.get('/files/{name}')\ndef download(name: str):\n"
        + "    target = os.path.normpath(os.path.join(BASE, name))\n"
        + "    if target.startswith(BASE + os.sep):\n"
        + "        return FileResponse(target)\n"
        + "    raise HTTPException(404)\n"
    )

    assert traversal_lines(tmp_path, code) == []


def test_fake_os_module_separator_does_not_prove_containment(tmp_path):
    code = route("target.startswith(BASE + os.sep)").replace(
        'BASE = "/srv/files"\n',
        "BASE = \"/srv/files\"\n\n\nclass os:\n    sep = ''\n    path = __import__('os').path\n",
    )

    assert traversal_lines(tmp_path, code) == [sink_line(code)]


def test_flask_open_with_sibling_prefix_check_is_reported(tmp_path):
    code = """import os
from flask import Flask, abort, request

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/read")
def read():
    path = os.path.realpath(os.path.join(BASE, request.args["f"]))
    if not path.startswith(BASE):
        abort(403)
    with open(path) as handle:
        return handle.read()
"""

    assert traversal_lines(tmp_path, code) == [13]


def test_flask_open_with_separator_prefix_check_stays_quiet(tmp_path):
    code = """import os
from flask import Flask, abort, request

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/read")
def read():
    path = os.path.realpath(os.path.join(BASE, request.args["f"]))
    if not path.startswith(BASE + os.sep):
        abort(403)
    with open(path) as handle:
        return handle.read()
"""

    assert traversal_lines(tmp_path, code) == []
