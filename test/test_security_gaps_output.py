"""New detectors must survive the analyzer's listing and gate boundaries."""

import json

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.reporting.listing import is_listed


def test_new_python_checks_survive_full_analyzer_and_gate(tmp_path):
    (tmp_path / "server.py").write_text("""
from functools import cache
from flask import request, url_for
from importlib import import_module
from jinja2 import Environment
import requests
import gradio as gr

environment = Environment()
requests.get("http://api.example.com/data")
import_module(request.args["plugin"])
demo = gr.Interface(fn=print, inputs=[], outputs=[])
demo.launch(server_name="0.0.0.0")

@cache
def content():
    return url_for("index", _external=True)
""")
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            grep_verify=False,
        )
    )
    assert not result.get("analysis_errors")
    expected = {f"SKY-D{number}" for number in range(355, 360)}
    rows = [row for row in result.get("danger", []) if row["rule_id"] in expected]
    assert {row["rule_id"] for row in rows} == expected
    assert all(
        row["finding_type"] == "review" and is_listed(row, "security") for row in rows
    )
    assert check_gate(result, {"gate": {"max_security": 0}})[0] is False
