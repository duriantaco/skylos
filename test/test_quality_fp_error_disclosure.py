"""SKY-L017 reports exception text that reaches an HTTP response.

A plain ``return`` only reaches an HTTP response when the enclosing function
is a web route or view. Exception text passed to an HTTP response
constructor is reported wherever it appears.

Each case marks the lines it expects to be reported with ``# L017``.
"""

from __future__ import annotations

import ast
import textwrap

import pytest

from skylos.rules.quality.logic_security import ErrorDisclosureRule


def _expected_lines(source: str) -> list[int]:
    return [
        number
        for number, line in enumerate(source.splitlines(), start=1)
        if "# L017" in line
    ]


def _reported_lines(source: str, filename: str = "app.py") -> list[int]:
    # The analyzer hands the rule ExceptHandler nodes with the module source.
    tree = ast.parse(source)
    context = {"filename": filename, "source": source}
    rule = ErrorDisclosureRule()
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            findings.extend(rule.visit_node(node, context) or [])
    assert all(f["rule_id"] == "SKY-L017" for f in findings)
    return sorted(f["line"] for f in findings)


HTTP = {
    "flask-route-dict": """
        from flask import Flask

        app = Flask(__name__)

        @app.route("/items", methods=["POST"])
        def add_item():
            try:
                return save_item()
            except Exception as e:
                return {"error": str(e)}  # L017
        """,
    "fastapi-route-under-auth-decorator": """
        from fastapi import APIRouter

        router = APIRouter()

        @router.post("/jobs")
        @requires_login
        async def start_job():
            try:
                return await queue_job()
            except Exception as e:
                return {"detail": str(e)}  # L017
        """,
    "fastapi-route-traceback": """
        import traceback
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/health")
        def health():
            try:
                return check()
            except Exception as e:
                return traceback.format_exc()  # L017
        """,
    "view-taking-request": """
        def item_detail(request, item_id):
            try:
                return render_item(item_id)
            except Exception as e:
                return f"lookup failed: {e}"  # L017
        """,
    "view-with-request-annotation": """
        from starlette.requests import Request

        async def homepage(req: Request):
            try:
                return await render(req)
            except Exception as e:
                return repr(e)  # L017
        """,
    "response-constructor-in-helper": """
        from flask import jsonify

        def failure_payload():
            try:
                return jsonify(ok=True)
            except Exception as e:
                return jsonify(error=str(e))  # L017
        """,
    "response-constructor-in-socket-method": """
        class Handler:
            def reply(self):
                try:
                    return ok()
                except Exception as e:
                    return JSONResponse({"error": str(e)})  # L017
        """,
}


@pytest.mark.parametrize("code", HTTP.values(), ids=HTTP.keys())
def test_exception_text_reaching_an_http_response_is_reported(code):
    source = textwrap.dedent(code)
    assert _expected_lines(source)
    assert _reported_lines(source) == _expected_lines(source)


def test_test_files_stay_excluded():
    source = textwrap.dedent(HTTP["flask-route-dict"])
    assert _reported_lines(source, filename="test_api.py") == []


