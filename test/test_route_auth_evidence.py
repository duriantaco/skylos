"""Inbound route authentication needs framework and request evidence."""

import ast
import json
import textwrap

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.rules.danger.danger_web.route_auth import scan
from test.fixture_paths import write_fixture


ROUTE = """from fastapi import FastAPI
app = FastAPI()
{module}
@app.delete("/admin/users/{{user_id}}")
def admin_delete_user(user_id: int):
    {body}
    return db.delete(user_id)
"""


def _source(module="", body="pass"):
    return ROUTE.format(module=module, body=body)


def _raw(source):
    findings = []
    scan(ast.parse(textwrap.dedent(source)), "app.py", findings)
    return [(row["name"], row["severity"]) for row in findings]


@pytest.mark.parametrize(
    "body",
    [
        'print("author requested deletion")',
        'print("authentication is handled upstream")',
        '"""Requires authentication before deletion."""',
        "author_id = user_id",
        'log.info("authorization token accepted")',
    ],
    ids=["author-log", "auth-prose", "docstring", "author-variable", "auth-log"],
)
def test_authentication_prose_and_author_names_do_not_guard_a_route(body):
    assert _raw(_source(body=body)) == [("admin_delete_user", "HIGH")]


@pytest.mark.parametrize(
    "module",
    [
        'def telemetry():\n    return requests.get("https://api.example", auth=None)\n',
        'def telemetry():\n    return requests.get("https://api.example", auth=("user", "secret"))\n',
        "configure_export(auth=load_export_credentials())\n",
        "other.add_middleware(AuthenticationMiddleware)\n",
        "other.before_request(check_session)\n",
        "other.wsgi_app = LoginMiddleware(other.wsgi_app)\n",
        "app = FastAPI(dependencies=[])\n",
    ],
    ids=[
        "outbound-none",
        "outbound-auth",
        "unrelated-options",
        "other-middleware",
        "other-hook",
        "other-wrapper",
        "empty-dependencies",
    ],
)
def test_unrelated_or_inert_options_do_not_authenticate_inbound_requests(module):
    source = _source(module=module)
    if module.startswith("app ="):
        source = source.replace("app = FastAPI()\n", "")
    assert _raw(source) == [("admin_delete_user", "HIGH")]


@pytest.mark.parametrize(
    "imports,constructor",
    [
        ("from fastapi import FastAPI as API", "API()"),
        ("from fastapi.applications import FastAPI as API", "API()"),
        ("import fastapi as api", "api.FastAPI()"),
        ("import fastapi.applications as api", "api.FastAPI()"),
        ("from flask import Flask as Application", "Application(__name__)"),
        ("from flask.app import Flask as Application", "Application(__name__)"),
        ("from fastapi import FastAPI as API\nFactory = API", "Factory()"),
        (
            "from fastapi import FastAPI as API\nclass NativeApp(API):\n    pass",
            "NativeApp()",
        ),
    ],
)
def test_native_framework_constructor_import_aliases_keep_the_route(
    imports, constructor
):
    source = _source().replace("from fastapi import FastAPI", imports)
    source = source.replace("FastAPI()", constructor)
    assert _raw(source) == [("admin_delete_user", "HIGH")]


@pytest.mark.parametrize(
    "provider,expected",
    [
        (
            "class FastAPI:\n    def delete(self, path):\n        return lambda fn: fn\n",
            [],
        ),
        ("from unrelated import FastAPI\n", [("admin_delete_user", "HIGH")]),
        (
            "from fastapi import FastAPI\nFastAPI = make_decorator_holder\n",
            [("admin_delete_user", "HIGH")],
        ),
    ],
    ids=["local-class", "foreign-import", "rebound-native-import"],
)
def test_only_proved_inert_constructor_disproves_a_route_candidate(provider, expected):
    source = _source().replace("from fastapi import FastAPI\n", provider)
    assert _raw(source) == expected


@pytest.mark.parametrize(
    "module,body",
    [
        ("app.add_middleware(AuthenticationMiddleware)", "pass"),
        ("app.before_request(check_session)", "pass"),
        ("app.wsgi_app = LoginMiddleware(app.wsgi_app)", "pass"),
        ("", "if not request.headers.get('Authorization'):\n        abort(401)"),
        ("", "if not g.user:\n        return redirect(url_for('login'))"),
        ("", "if not logged_in:\n        return redirect('/login')"),
        ("", "check_authorization(user_id)"),
        ("", "verify(request.json['token'])"),
        ("", "verify(request.form.get('password'))"),
        (
            "GUARDS = []\ndef configure(GUARDS):\n    app.include_router(other, dependencies=GUARDS)\n",
            "pass",
        ),
    ],
)
def test_actual_possible_request_guards_still_keep_the_security_finding_quiet(
    module, body
):
    assert _raw(_source(module=module, body=body)) == []


@pytest.mark.parametrize(
    "variant", ["author-log", "outbound-none", "native-alias", "local-class"]
)
def test_route_evidence_reaches_native_listing_and_gate(tmp_path, monkeypatch, variant):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    source = _source()
    if variant == "author-log":
        source = _source(body='print("author requested deletion")')
    elif variant == "outbound-none":
        source = _source(
            module='def telemetry():\n    return requests.get("https://api.example", auth=None)\n'
        )
    elif variant == "native-alias":
        source = source.replace(
            "from fastapi import FastAPI", "from fastapi import FastAPI as API"
        ).replace("FastAPI()", "API()")
    else:
        source = source.replace(
            "from fastapi import FastAPI\n",
            "class FastAPI:\n    def delete(self, path):\n        return lambda fn: fn\n",
        )
    write_fixture(tmp_path, "app.py", source)
    report = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_quality=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_cache=False,
            grep_verify=False,
        )
    )
    assert not report.get("analysis_errors")
    assert report.get("analysis_summary", {}).get("analysis_error_count", 0) == 0
    security = [row for row in report.get("danger", []) if row["rule_id"] == "SKY-D283"]
    quality = [row for row in report.get("quality", []) if row["rule_id"] == "SKY-F102"]
    expected = variant != "local-class"
    assert len(security) == int(expected)
    assert len(quality) == int(not expected)
    if security:
        row = security[0]
        assert row["name"] == "admin_delete_user"
        assert row["severity"] == "HIGH"
        assert row["listing"]["listed"]
        assert row["metadata"]["security_trace"]
    passed, reasons = check_gate(report, {"gate": {"max_security": 0, "max_high": 0}})
    assert passed is (not expected), reasons


@pytest.mark.parametrize(
    "module",
    [
        "def telemetry(app):\n    app.add_middleware(AuthenticationMiddleware)\n",
        "def telemetry(app):\n    app.before_request(check_session)\n",
        "def telemetry(app):\n    app.wsgi_app = LoginMiddleware(app.wsgi_app)\n",
    ],
)
def test_local_app_parameter_cannot_guard_the_module_app(module):
    assert _raw(_source(module=module)) == [("admin_delete_user", "HIGH")]


def test_local_receiver_shadow_does_not_establish_an_owned_route():
    source = (
        _source()
        + """
def describe(app):
    @app.delete("/admin/local")
    def admin_local():
        return {}
"""
    )
    assert _raw(source) == [("admin_delete_user", "HIGH")]


def test_local_include_receiver_cannot_mount_a_router_on_the_module_app():
    source = (
        _source()
        + """
from fastapi import APIRouter
router = APIRouter()
def describe(app):
    app.include_router(router)
@router.delete("/admin/local")
def admin_local():
    return {}
"""
    )
    assert _raw(source) == [("admin_delete_user", "HIGH")]


@pytest.mark.parametrize("nested", [False, True])
def test_project_provider_shadow_is_not_a_native_http_app(
    tmp_path, monkeypatch, nested
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    path = "package/app.py" if nested else "app.py"
    write_fixture(tmp_path, path, _source())
    write_fixture(
        tmp_path,
        "fastapi.py",
        "class FastAPI:\n    def delete(self, path):\n        return lambda fn: fn\n",
    )
    report = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_quality=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_cache=False,
            grep_verify=False,
        )
    )
    assert not report.get("analysis_errors")
    assert not [row for row in report.get("danger", []) if row["rule_id"] == "SKY-D283"]
    assert [
        row["name"] for row in report.get("quality", []) if row["rule_id"] == "SKY-F102"
    ] == ["admin_delete_user"]


@pytest.mark.parametrize(
    "module",
    [
        'globals().update({"DEBUG": True})',
        'def metadata():\n    globals().update({"DEBUG": True})\n',
        'FastAPI.openapi_version = "3.1.0"',
    ],
)
def test_provider_uncertainty_is_not_proof_that_a_native_route_is_safe(module):
    assert _raw(_source(module=module)) == [("admin_delete_user", "HIGH")]


@pytest.mark.parametrize(
    "imports",
    [
        "try:\n    from fastapi import FastAPI\nexcept ImportError:\n    raise",
        "if __name__ == '__main__':\n    from fastapi import FastAPI",
        "from fastapi import FastAPI\nFastAPI = FastAPI",
    ],
)
def test_uncertain_native_import_control_flow_does_not_erase_a_route(imports):
    source = _source().replace("from fastapi import FastAPI", imports)
    assert _raw(source) == [("admin_delete_user", "HIGH")]


def test_local_provider_reexport_is_not_an_inert_constructor(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    write_fixture(
        tmp_path, "app.py", _source().replace("FastAPI()", "FastAPI(__name__)")
    )
    write_fixture(tmp_path, "fastapi.py", "from flask import Flask as FastAPI\n")
    report = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_quality=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_cache=False,
            grep_verify=False,
        )
    )
    assert not report.get("analysis_errors")
    findings = [row for row in report.get("danger", []) if row["rule_id"] == "SKY-D283"]
    assert [(row["name"], row["severity"]) for row in findings] == [
        ("admin_delete_user", "HIGH")
    ]
    passed, reasons = check_gate(report, {"gate": {"max_security": 0}})
    assert passed is False, reasons


def test_later_inert_constructor_does_not_erase_an_already_created_native_app():
    source = _source(
        module="class FastAPI:\n    def delete(self, path):\n        return lambda fn: fn\n"
    )
    assert _raw(source) == [("admin_delete_user", "HIGH")]
