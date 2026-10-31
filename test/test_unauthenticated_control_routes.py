"""SKY-D283: unauthenticated routes that control, destroy, administer or run
commands are security findings; other open mutating routes stay SKY-F102."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze


def _scan(tmp_path, source, *, danger=True, quality=True, name="app.py"):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(source))
    result = json.loads(
        analyze(
            str(tmp_path),
            conf=60,
            enable_danger=danger,
            enable_quality=quality,
            grep_cache=False,
            grep_verify=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors")
    return {
        "D283": sorted(
            (row["name"], row["severity"])
            for row in result.get("danger") or []
            if row.get("rule_id") == "SKY-D283"
        ),
        "F102": sorted(
            row["name"]
            for row in result.get("quality") or []
            if row.get("rule_id") == "SKY-F102"
        ),
    }


APP = """
    import os
    import uvicorn
    from fastapi import FastAPI

    app = FastAPI()
    HOST = {host}

    @app.post("/control/arm")
    def control_arm():
        return bridge.arm()

    @app.post("/system/reboot")
    def reboot():
        return bridge.reboot()

    @app.post("/notes")
    def add_note(note: dict):
        db.insert(note)

    @app.get("/reboot/status")
    def reboot_status():
        return {{"ok": True}}

    if __name__ == "__main__":
        uvicorn.run(app, host=HOST)
"""


def _app(host='os.environ.get("APP_HOST", "0.0.0.0")'):
    return textwrap.dedent(APP.format(host=host))


def test_privileged_routes_on_an_open_all_interface_app_are_critical(tmp_path):
    found = _scan(tmp_path, _app())
    assert found == {
        "D283": [("control_arm", "CRITICAL"), ("reboot", "CRITICAL")],
        "F102": ["add_note"],
    }


@pytest.mark.parametrize(
    "host",
    [
        'os.environ.get("APP_HOST", "127.0.0.1")',
        'os.environ["APP_HOST"]',
        "load_host()",
    ],
)
def test_without_an_all_interface_bind_privileged_routes_are_high(tmp_path, host):
    found = _scan(tmp_path, _app(host))
    assert found["D283"] == [("control_arm", "HIGH"), ("reboot", "HIGH")]


def test_rebound_host_or_auth_elsewhere_keeps_high(tmp_path):
    rebound = _app('"0.0.0.0"').replace(
        "app = FastAPI()", 'app = FastAPI()\nHOST = "127.0.0.1"'
    )
    assert _scan(tmp_path / "a", rebound)["D283"] == [
        ("control_arm", "HIGH"),
        ("reboot", "HIGH"),
    ]
    guarded = _app('"0.0.0.0"') + textwrap.dedent(
        """
        @app.post("/settings")
        def save_settings(settings: dict, current_user=Depends(get_current_user)):
            db.save(settings)
        """
    )
    assert _scan(tmp_path / "b", guarded)["D283"] == [
        ("control_arm", "HIGH"),
        ("reboot", "HIGH"),
    ]


def test_critical_needs_the_handler_to_perform_the_action(tmp_path):
    source = _app('"0.0.0.0"').replace(
        "return bridge.reboot()", 'PENDING["reboot"] = True'
    )
    assert _scan(tmp_path, source)["D283"] == [
        ("control_arm", "CRITICAL"),
        ("reboot", "HIGH"),
    ]


def test_delete_method_is_destructive_and_path_parameters_are_not_words(tmp_path):
    source = """
        from fastapi import FastAPI
        app = FastAPI()

        @app.delete("/items/{item_id}")
        def remove_item(item_id: int):
            db.remove(item_id)

        @app.post("/jobs/{cmd_id}/retry")
        def retry_job(cmd_id: int):
            queue.push(cmd_id)

        @app.post("/farm/harvest")
        def farm_harvest(crop: dict):
            db.insert(crop)
    """
    assert _scan(tmp_path, source) == {
        "D283": [("remove_item", "HIGH")],
        "F102": ["farm_harvest", "retry_job"],
    }


ROUTE = """
from fastapi import FastAPI, Depends, Header, Request, HTTPException
from typing import Annotated
app = FastAPI()
Operator = Annotated[str, Depends(load_operator)]
{module}

@app.post("/admin/users/delete")
{decorator}
def admin_delete_user({parameters}):
    {body}
    db.delete(user_id)
"""


@pytest.mark.parametrize(
    "module,decorator,parameters,body",
    [
        ("", "@admins_only", "user_id: int", "pass"),
        ("", "", "user_id: int, account=Depends(check_super_user)", "pass"),
        ("", "", "user_id: int, operator: Operator", "pass"),
        ("", "", "user_id: int, key: str = Header(...)", "pass"),
        (
            "",
            "",
            "user_id: int, request: Request",
            "if request.headers.get('x-ops-key') != OPS_KEY:\n"
            "        raise HTTPException(status_code=401)",
        ),
        ("", "", "user_id: int, request: Request", "verifier.check(request)"),
        ("app.add_middleware(OperatorKeyMiddleware)", "", "user_id: int", "pass"),
        (
            "app = FastAPI(dependencies=[Depends(check_key)])",
            "",
            "user_id: int",
            "pass",
        ),
    ],
    ids=[
        "unmarked-decorator",
        "dependency",
        "annotated-alias",
        "header-parameter",
        "body-rejects-401",
        "body-passes-request",
        "unknown-middleware",
        "app-dependencies",
    ],
)
def test_possible_guards_keep_the_review_not_a_security_finding(
    tmp_path, module, decorator, parameters, body
):
    source = ROUTE.format(
        module=module, decorator=decorator, parameters=parameters, body=body
    )
    assert _scan(tmp_path, source)["D283"] == []


def test_routes_on_routers_mounted_elsewhere_are_not_judged_here(tmp_path):
    source = """
        from fastapi import APIRouter
        router = APIRouter()

        @router.post("/system/reboot")
        def reboot():
            host.reboot()
    """
    found = _scan(tmp_path, source, name="routers/system.py")
    assert found == {"D283": [], "F102": ["reboot"]}


def test_request_hook_that_reads_no_credentials_does_not_hide_the_risk(tmp_path):
    source = """
        from flask import Flask, request, abort
        app = Flask(__name__)

        @app.before_request
        def policy():
            if request.method == "POST" and request.path.startswith("/maintenance"):
                abort(409)

        @app.route("/admin/users/delete", methods=["POST"])
        def admin_delete_user():
            db.delete(request.form["id"])
    """
    assert _scan(tmp_path, source)["D283"] == [("admin_delete_user", "HIGH")]


def test_scan_selection_keeps_one_finding_per_route(tmp_path):
    assert _scan(tmp_path / "q", _app(), danger=False) == {
        "D283": [],
        "F102": ["add_note", "control_arm", "reboot"],
    }
    assert _scan(tmp_path / "d", _app(), quality=False)["D283"] == [
        ("control_arm", "CRITICAL"),
        ("reboot", "CRITICAL"),
    ]


@pytest.mark.parametrize(
    "comment,expected",
    [
        (
            "# skylos: ignore[SKY-D283] bench rig on an isolated LAN",
            [("reboot", "CRITICAL")],
        ),
        (
            "# skylos: ignore[SKY-F102] advice reviewed",
            [("control_arm", "CRITICAL"), ("reboot", "CRITICAL")],
        ),
        ("# noqa", [("control_arm", "CRITICAL"), ("reboot", "CRITICAL")]),
    ],
    ids=["own-rule", "advice-rule", "bare-noqa"],
)
def test_only_the_security_rule_suppresses_it(tmp_path, comment, expected):
    source = _app().replace("def control_arm():", f"def control_arm():  {comment}")
    assert _scan(tmp_path, source)["D283"] == expected


def test_test_code_is_not_a_served_route(tmp_path):
    assert _scan(tmp_path, _app(), name="tests/test_app.py")["D283"] == []


def test_middleware_decorator_is_not_a_hook_registered_by_call(tmp_path):
    source = """
        from fastapi import FastAPI
        app = FastAPI()

        @app.middleware("http")
        async def timing(request, call_next):
            response = await call_next(request)
            response.headers["X-Process-Time"] = "1"
            return response

        @app.post("/system/reboot")
        def reboot():
            host.reboot()
    """
    assert _scan(tmp_path, source)["D283"] == [("reboot", "HIGH")]


OPEN_APP = """
import os
import uvicorn
from flask import Flask, g, redirect, request, url_for
from fastapi import APIRouter, Depends, FastAPI

app = FastAPI()
{body}

uvicorn.run(app, host="0.0.0.0")
"""


@pytest.mark.parametrize(
    "body",
    [
        '@app.post("/campaigns/{cid}/launch")\ndef launch_campaign(cid: int):\n    campaigns.launch(cid)\n',
        '@app.post("/builds/arm64")\ndef build_arm64(spec: dict):\n    builder.arm64(spec)\n',
        '@app.post("/models/{name}/eval")\ndef eval_model(name: str):\n    jobs.submit(name)\n',
    ],
    ids=["launch-homonym", "arm64-token", "model-eval"],
)
def test_homonyms_are_not_privileged_actions(tmp_path, body):
    found = _scan(tmp_path, OPEN_APP.format(body=body))
    assert found["D283"] == []
    assert len(found["F102"]) == 1


@pytest.mark.parametrize(
    "body",
    [
        '@app.post("/system/reboot")\ndef reboot():\n    if g.user is None:\n        return {"error": "unauthorized"}, 401\n    host.reboot()\n',
        '@app.post("/data/purge")\ndef purge():\n    if not g.user:\n        return redirect(url_for("login"))\n    store.purge()\n',
        'app.wsgi_app = BasicAuthMiddleware(app.wsgi_app)\n\n@app.post("/system/reboot")\ndef reboot():\n    host.reboot()\n',
    ],
    ids=["tuple-401", "login-redirect", "wsgi-wrapper"],
)
def test_more_authentication_forms_keep_the_review(tmp_path, body):
    assert _scan(tmp_path, OPEN_APP.format(body=body))["D283"] == []


@pytest.mark.parametrize(
    "include,expected",
    [
        ("app.include_router(router)", [("reboot", "CRITICAL")]),
        ('app.include_router(router, prefix="/ops")', [("reboot", "CRITICAL")]),
        ("app.include_router(router, dependencies=[Depends(check_key)])", []),
    ],
    ids=["mounted", "mounted-with-prefix", "mounted-with-guard"],
)
def test_routers_mounted_on_the_app_in_this_module_are_judged(
    tmp_path, include, expected
):
    body = (
        'router = APIRouter()\n\n@router.post("/system/reboot")\n'
        f"def reboot():\n    host.reboot()\n\n{include}\n"
    )
    assert _scan(tmp_path, OPEN_APP.format(body=body))["D283"] == expected


def test_namespace_word_alone_does_not_make_it_critical(tmp_path):
    body = '@app.post("/control/yaw")\ndef control_yaw(angle: float):\n    bridge.set_yaw(angle)\n'
    assert _scan(tmp_path, OPEN_APP.format(body=body))["D283"] == [
        ("control_yaw", "HIGH")
    ]


def test_function_parameters_named_like_the_app_do_not_hide_it(tmp_path):
    body = (
        "async def lifespan(app: FastAPI):\n    yield\n\n"
        '@app.delete("/files/{filename}")\ndef delete_file(filename: str):\n'
        "    storage.delete(filename)\n"
    )
    source = OPEN_APP.format(body=body).replace("uvicorn.run(app", "run_server(app")
    assert _scan(tmp_path, source)["D283"] == [("delete_file", "HIGH")]


def test_app_a_function_may_rebind_is_not_judged(tmp_path):
    body = (
        "def configure():\n    global app\n    app = build_app()\n\n"
        '@app.delete("/files/{filename}")\ndef delete_file(filename: str):\n'
        "    storage.delete(filename)\n"
    )
    assert _scan(tmp_path, OPEN_APP.format(body=body))["D283"] == []
