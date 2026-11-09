"""An actual native route builder keeps a proven fixed path prefix."""

import pytest

from skylos.core.gatekeeper import check_gate
from test.test_security_sanitizer_identity import _analyze


BASE = (
    "from flask import Flask, request\n"
    "web=Flask(__name__)\n"
    "from starlette.applications import Starlette\n"
    "from starlette.routing import Route\n"
    "from starlette.responses import RedirectResponse as redirect\n"
    "def endpoint(request):\n    return None\n"
    "app=Starlette(routes=[Route('/item/{slug}',endpoint=endpoint,name='item')])\n"
)


@pytest.mark.parametrize(
    "setup, receiver, body, vulnerable",
    [
        ("", "app", "", False),
        ("application=app\n", "application", "", False),
        ("app.url_path_for=lambda name,slug:slug\n", "app", "", True),
        (
            "application=app\napplication.url_path_for=lambda name,slug:slug\n",
            "app",
            "",
            True,
        ),
        ("configure(app)\n", "app", "", True),
        ("configure(app.router)\n", "app", "", True),
        (
            "class Helper:\n    def url_path_for(self,name,slug):\n        return slug\napp=Helper()\n",
            "app",
            "",
            True,
        ),
        ("", "app", "    app=Helper()\n", True),
    ],
)
def test_native_instance_builder_is_bounded_to_stable_receiver(
    tmp_path, monkeypatch, setup, receiver, body, vulnerable
):
    source = BASE + setup + "def run(value):\n" + body
    source += f"    return redirect({receiver}.url_path_for('item',slug=value))\n"
    source += "@web.get('/go')\ndef caller():\n    return run(request.args['next'])\n"
    result = _analyze(tmp_path, monkeypatch, source)
    rows = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D230"]
    assert bool(rows) is vulnerable
    if rows:
        assert rows[0]["severity"] == "HIGH"
        assert rows[0]["listing"]["listed"] is True
    passed, reasons = check_gate(result, {"gate": {"max_high": 0}})
    assert passed is not vulnerable, reasons


@pytest.mark.parametrize(
    "path, vulnerable", [("/item/{slug}", False), ("/{slug:path}", True)]
)
def test_native_builder_requires_fixed_origin_path_segment(
    tmp_path, monkeypatch, path, vulnerable
):
    result = _analyze(
        tmp_path,
        monkeypatch,
        BASE.replace("/item/{slug}", path)
        + "def run(value):\n    return redirect(app.url_path_for('item',slug=value))\n"
        + "@web.get('/go')\ndef caller():\n    return run(request.args['next'])\n",
    )
    assert (
        any(row["rule_id"] == "SKY-D230" for row in result.get("danger", []))
        is vulnerable
    )


def test_native_constructor_and_receiver_aliases_remain_safe(tmp_path, monkeypatch):
    source = (
        BASE.replace("import Starlette", "import Starlette as Site")
        .replace("import Route", "import Route as Entry")
        .replace("Starlette(routes=[Route(", "Site(routes=[Entry(")
    )
    result = _analyze(
        tmp_path,
        monkeypatch,
        source
        + "application=app\ndef run(value):\n    return redirect(application.url_path_for('item',slug=value))\n",
    )
    assert not any(row["rule_id"] == "SKY-D230" for row in result.get("danger", []))
