"""Wildcard CORS matters when the app has open state-changing routes, and an
echoed request Origin is a wildcard unless an allowlist check guards it."""

import ast
import textwrap

import pytest

from skylos.rules.danger.danger_cors.cors_flow import scan


def _findings(source):
    findings = []
    scan(ast.parse(textwrap.dedent(source)), "app.py", findings)
    return sorted(
        (f["line"], f["severity"]) for f in findings if f["rule_id"] == "SKY-D231"
    )


def _lines(source):
    return [line for line, _severity in _findings(source)]


MIDDLEWARE = """
    from fastapi import FastAPI, Depends
    from fastapi.middleware.cors import CORSMiddleware

    app = FastAPI()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
    )
"""


@pytest.mark.parametrize(
    "route,severity",
    [
        (
            """
    @app.post("/control/arm")
    def control_arm():
        return bridge.arm()
    """,
            "HIGH",
        ),
        (
            """
    @app.post("/notes")
    def add_note(note: dict):
        db.insert(note)
    """,
            "MEDIUM",
        ),
    ],
    ids=["privileged-route", "ordinary-write"],
)
def test_wildcard_middleware_with_open_writes_is_reported_at_the_origin(
    route, severity
):
    assert _findings(MIDDLEWARE + route) == [(8, severity)]


@pytest.mark.parametrize(
    "routes",
    [
        "",
        """
    @app.get("/status")
    def status():
        return {"ok": True}
    """,
        """
    @app.post("/control/arm")
    def control_arm(user=Depends(get_current_user)):
        return bridge.arm()
    """,
        """
    CurrentUser = Annotated[User, Depends(get_current_user)]

    @app.post("/items")
    def create_item(item: dict, user: CurrentUser):
        db.insert(item)
    """,
        """
    app.add_middleware(AuthenticationMiddleware, backend=BearerBackend())

    @app.post("/items")
    def create_item(item: dict):
        db.insert(item)
    """,
    ],
    ids=[
        "no-routes",
        "reads-only",
        "guarded-write",
        "annotated-dependency",
        "auth-middleware",
    ],
)
def test_wildcard_middleware_without_open_writes_is_not_reported(routes):
    assert _lines(MIDDLEWARE + routes) == []


def test_flask_cors_wildcard_with_an_open_write_is_reported():
    source = """
        from flask import Flask
        from flask_cors import CORS
        app = Flask(__name__)
        CORS(app, origins="*")

        @app.route("/items/delete", methods=["POST"])
        def delete_item():
            db.delete(request.json["id"])
    """
    assert _findings(source) == [(5, "HIGH")]


REFLECTED = """
    from fastapi import Request
    from fastapi.responses import JSONResponse

    ALLOWED = {{"https://dashboard.example.org"}}
    ORIGIN_PATTERN = re.compile(r"https://dashboard\\.example\\.org")
    LOOSE_PATTERN = re.compile(r"https://.*example\\.org")

    def is_allowed(value):
        return value in ALLOWED

    def always_ok(value):
        return True

    async def deny(request: Request, call_next):
        origin = request.headers.get("origin", "")
{body}
"""


def _reflected(body):
    body = textwrap.indent(textwrap.dedent(body).strip("\n"), " " * 8)
    return _lines(REFLECTED.format(body=body))


@pytest.mark.parametrize(
    "body",
    [
        'return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})',
        'return JSONResponse({}, headers={"access-control-allow-origin": request.headers["Origin"]})',
        """
        response = await call_next(request)
        response.headers["Access-Control-Allow-Origin"] = origin
        return response
        """,
        """
        response = await call_next(request)
        response.headers.setdefault("Access-Control-Allow-Origin", origin or "*")
        return response
        """,
    ],
    ids=["dict", "subscript-read", "header-assignment", "header-setter"],
)
def test_echoed_origin_without_a_check_is_reported(body):
    assert len(_reflected(body)) == 1


@pytest.mark.parametrize(
    "body",
    [
        """
        if origin in ALLOWED:
            return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        return JSONResponse({})
        """,
        """
        if origin not in ALLOWED:
            return JSONResponse({}, status_code=403)
        return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        """,
        """
        return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin if origin in ALLOWED else ""})
        """,
        """
        if origin not in ALLOWED:
            origin = "https://dashboard.example.org"
        return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        """,
        """
        if is_allowed(origin):
            return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        """,
        """
        if ORIGIN_PATTERN.fullmatch(origin):
            return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        """,
        """
        if any(origin == allowed for allowed in ALLOWED):
            return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        """,
        """
        if origin in (None, ""):
            return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        """,
    ],
    ids=[
        "inside-check",
        "early-reject",
        "conditional-value",
        "reassigned-default",
        "helper",
        "anchored-pattern",
        "any-equality",
        "empty-origin",
    ],
)
def test_echoed_origin_after_an_allowlist_check_is_not_reported(body):
    assert _reflected(body) == []


@pytest.mark.parametrize(
    "body",
    [
        """
        allowed = origin in ALLOWED
        return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        """,
        """
        other = request.headers.get("referer", "")
        if other in ALLOWED:
            return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        """,
        """
        if origin.startswith("https://dashboard.example.org"):
            return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        """,
        """
        if origin in {"*", "https://dashboard.example.org"}:
            return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        """,
        """
        if origin in ALLOWED:
            pass
        else:
            return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        """,
        """
        if origin not in ALLOWED:
            log(origin)
        return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        """,
        """
        if origin in "https://dashboard.example.org,https://admin.example.org":
            return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        """,
        """
        if re.fullmatch(r".*", origin):
            return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        """,
        """
        if LOOSE_PATTERN.fullmatch(origin):
            return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        """,
        """
        if origin in {"null", "https://dashboard.example.org"}:
            return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        """,
        'return JSONResponse({}, headers={"Access-Control-Allow-Origin": f"{origin}"})',
        """
        if always_ok(origin):
            return JSONResponse({}, headers={"Access-Control-Allow-Origin": origin})
        """,
    ],
    ids=[
        "ignored-result",
        "different-value",
        "prefix-check",
        "wildcard-allowlist",
        "wrong-branch",
        "check-without-reject",
        "substring-test",
        "wildcard-regex",
        "loose-compiled-regex",
        "null-allowed",
        "f-string-echo",
        "helper-proves-nothing",
    ],
)
def test_checks_that_prove_nothing_still_report(body):
    assert len(_reflected(body)) == 1


def test_fixed_wildcard_header_on_a_single_response_keeps_its_old_scope():
    source = """
        async def discovery(request):
            response = JSONResponse(content=DOCUMENT)
            response.headers["Access-Control-Allow-Origin"] = "*"
            return response
    """
    assert _lines(source) == []
