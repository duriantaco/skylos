"""An allowlist or containment check proves only what the logic of the whole
test guarantees: ``or`` with another condition proves nothing on its own."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze

ROUTE = """
import os
from fastapi import FastAPI, HTTPException
from storage import load

app = FastAPI()
ALLOWED = {{"a.txt", "b.txt"}}
BASE = "/srv/files"

@app.get("/files/{{name}}")
def view(name: str, strict: bool = True):
{body}
"""

STORAGE = (
    "def load(path):\n    with open(path) as stream:\n        return stream.read()\n"
)


def _d215(tmp_path, body):
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n")
    (tmp_path / "storage.py").write_text(STORAGE)
    source = ROUTE.format(body=textwrap.indent(textwrap.dedent(body).strip(), "    "))
    (tmp_path / "app.py").write_text(source)
    result = json.loads(
        analyze(
            str(tmp_path),
            conf=60,
            enable_danger=True,
            grep_cache=False,
            grep_verify=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors")
    return [
        row["file"].rsplit("/", 1)[-1]
        for row in result.get("danger", [])
        if row["rule_id"] == "SKY-D215"
    ]


@pytest.mark.parametrize(
    "body",
    [
        """
        if name not in ALLOWED or not strict:
            raise HTTPException(status_code=400)
        return load(name)
        """,
        """
        if not (name in ALLOWED and strict):
            raise HTTPException(status_code=400)
        return load(name)
        """,
        """
        if name in ALLOWED and strict:
            return load(name)
        raise HTTPException(status_code=404)
        """,
        """
        if name in ALLOWED and strict:
            return open(name).read()
        raise HTTPException(status_code=404)
        """,
        """
        target = os.path.realpath(os.path.join(BASE, name))
        if os.path.commonpath([target, BASE]) != BASE or not strict:
            raise HTTPException(status_code=404)
        return open(target).read()
        """,
    ],
    ids=[
        "reject-either",
        "reject-not-both",
        "use-when-both",
        "local-use-when-both",
        "containment-reject-either",
    ],
)
def test_checks_the_whole_test_guarantees_are_kept(tmp_path, body):
    assert _d215(tmp_path, body) == []


@pytest.mark.parametrize(
    "body",
    [
        """
        if not (name in ALLOWED or len(name) > 0):
            raise HTTPException(status_code=400)
        return load(name)
        """,
        """
        if name not in ALLOWED and strict:
            raise HTTPException(status_code=400)
        return load(name)
        """,
        """
        if name in ALLOWED or not strict:
            return load(name)
        raise HTTPException(status_code=404)
        """,
        """
        if name in ALLOWED or not strict:
            return open(name).read()
        raise HTTPException(status_code=404)
        """,
        """
        target = os.path.realpath(os.path.join(BASE, name))
        if os.path.commonpath([target, BASE]) != BASE and strict:
            raise HTTPException(status_code=404)
        return open(target).read()
        """,
    ],
    ids=[
        "reject-unless-either",
        "reject-only-when-strict",
        "use-when-either",
        "local-use-when-either",
        "containment-reject-only-when-strict",
    ],
)
def test_checks_an_or_makes_optional_still_report(tmp_path, body):
    assert _d215(tmp_path, body)
