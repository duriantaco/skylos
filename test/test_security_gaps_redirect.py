"""Redirect claims require a source, including sources passed through helpers."""

import ast

from skylos.rules.danger.danger_redirect.redirect_flow import scan


def _findings(code):
    findings = []
    scan(ast.parse(code), "app.py", findings)
    return findings


def test_library_authorization_result_is_not_claimed_to_be_request_input():
    findings = _findings("""
from flask import redirect
def authorize(client, redirect_uri):
    rv = client.create_authorization_url(redirect_uri)
    return redirect(rv["url"])
""")
    assert len(findings) == 1
    assert "user-controlled" not in findings[0]["message"]
    assert findings[0]["metadata"]["source_status"] == "unresolved"
    assert findings[0]["metadata"]["audit_only"] is True
    assert findings[0]["metadata"]["redirect_operand"]
    assert findings[0]["metadata"]["redirect_source_ast_sha256"]


def test_request_redirect_through_helper_retains_source_evidence():
    findings = _findings("""
from flask import redirect, request
def destination(value):
    return redirect(value)
def route():
    return destination(request.args["next"])
""")
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D230", 4)]
    assert "request" in findings[0]["metadata"]["security_evidence"]["source"]


def test_route_argument_remains_untrusted():
    findings = _findings("""
from flask import Flask, redirect
app = Flask(__name__)
@app.get("/<target>")
def route(target):
    return redirect(target)
""")
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D230", 6)]
