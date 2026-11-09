"""Expanded redirect sinks preserve the URL builder's provider identity."""

import pytest

from skylos.core.gatekeeper import check_gate
from test.test_security_sanitizer_identity import _analyze


@pytest.mark.parametrize(
    "sink_import, sink",
    [
        (
            "from starlette.responses import RedirectResponse\n",
            "return RedirectResponse(url={target})",
        ),
        (
            "from aiohttp import web\n",
            "raise web.HTTPFound(location={target})",
        ),
        (
            "from starlette.responses import Response\n",
            "return Response(status_code=302, headers={{'Location': {target}}})",
        ),
    ],
)
@pytest.mark.parametrize("builder", ["native", "local", "request"])
def test_expanded_redirect_sinks_keep_provider_identity_and_request_evidence(
    tmp_path, monkeypatch, sink_import, sink, builder
):
    setup = ""
    target = "request.args.get('next')"
    if builder != "request":
        target = "url_for('home', next=request.args.get('next'))"
    if builder == "local":
        setup = "def url_for(endpoint, **values):\n    return values['next']\n"
    result = _analyze(
        tmp_path,
        monkeypatch,
        "from flask import request, url_for\n"
        + sink_import
        + setup
        + "def run():\n    "
        + sink.format(target=target)
        + "\n",
    )
    rows = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D230"]
    vulnerable = builder != "native"
    assert len(rows) == int(vulnerable)
    if rows:
        assert rows[0]["severity"] == "HIGH"
        assert rows[0]["listing"]["listed"] is True
    passed, reasons = check_gate(result, {"gate": {"max_high": 0}})
    assert passed is not vulnerable, reasons
