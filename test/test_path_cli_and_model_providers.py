"""Source-backed CLI streams and framework-provided model UUID values."""

from pathlib import Path

import pytest

from skylos.rules.danger.danger import scan_ctx
from skylos.rules.danger.danger_fs.path_provenance import (
    resolve_helper_parameter_findings,
)

RULES = {"SKY-D215", "SKY-D324", "SKY-D325"}


def _scan(tmp_path, files):
    (tmp_path / ".git").mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nname="provider"\n')
    paths = []
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_text(source)
        paths.append(path)
    suppressed = []
    raw = scan_ctx(tmp_path, paths)
    visible = resolve_helper_parameter_findings(
        raw, scan_path=tmp_path, project_root=tmp_path, suppressed=suppressed
    )
    return [row for row in visible if row["rule_id"] in RULES], suppressed


CLI_HELPER = """import sys
from pathlib import Path

def read_ids(path):
    if path == '-':
        text = sys.stdin.read()
    else:
        text = Path(path).read_text()
    return text.splitlines()

def save(name):
    return open(name, 'w').write('report')
"""
CLI_CALLER = """import argparse
from helper import read_ids, save

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--input-file')
    args=parser.parse_args()
    for username in read_ids(args.input_file):
        username=username.replace('/', '_')
        save('report_{}.txt'.format(username))

if __name__ == '__main__':
    main()
"""


def test_cli_selected_stdin_in_mixed_project_does_not_become_http_input(tmp_path):
    visible, suppressed = _scan(
        tmp_path,
        {
            "helper.py": CLI_HELPER,
            "cli.py": CLI_CALLER,
            "web.py": "from flask import Flask\napp=Flask(__name__)\n",
        },
    )
    assert not [row for row in visible if row.get("symbol") == "save"]
    assert any(row.get("symbol") == "save" for row in suppressed)


@pytest.mark.parametrize(
    "caller",
    [
        "read_ids(request.args['file'])",
        "read_ids(request.args['file'] if request.args.get('file') else '-')",
    ],
)
def test_http_selected_stdin_retains_the_path_finding(tmp_path, caller):
    visible, _ = _scan(
        tmp_path,
        {
            "helper.py": CLI_HELPER,
            "cli.py": CLI_CALLER,
            "web.py": "from flask import Flask,request\nfrom helper import read_ids,save\napp=Flask(__name__)\n@app.get('/report')\ndef report():\n    for name in "
            + caller
            + ":\n        save(name)\n",
        },
    )
    assert any(
        row["rule_id"] == "SKY-D215" and row.get("symbol") == "save" for row in visible
    )


MODEL = """import uuid
from django.db import models
class Account(models.Model):
    uuid=models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    username=models.CharField(max_length=100)
"""
AUTH = """from starlette.authentication import AuthenticationBackend, AuthCredentials, SimpleUser, UnauthenticatedUser
from starlette.middleware.authentication import AuthenticationMiddleware
from fastapi import FastAPI
from route import api
from models import Account
app=FastAPI()
app.include_router(api)
class AuthUser(SimpleUser):
    def __init__(self, user):
        self.object=user
        super().__init__(user.username)
class Backend(AuthenticationBackend):
    async def authenticate(self, request):
        user=await Account.objects.filter(id=request.session['id']).afirst()
        if user:
            return AuthCredentials(['authenticated']), AuthUser(user)
        return AuthCredentials(), UnauthenticatedUser()
app.add_middleware(AuthenticationMiddleware, backend=Backend())
"""
ROUTE = """import uuid
from fastapi import APIRouter
from starlette.requests import Request
from starlette.authentication import requires
from models import Account
api=APIRouter()
@api.post('/record')
@requires(['authenticated'])
def record(request:Request):
    user:Account=request.user.object
    filename=f'{user.uuid}-{uuid.uuid4()}.webm'
    with open(filename,'wb') as stream:
        stream.write(b'audio')
    stream=open(filename,'rb')
    return stream.read()
"""


def test_authenticated_django_uuid_field_is_identifier_not_request_path(tmp_path):
    visible, suppressed = _scan(
        tmp_path, {"models.py": MODEL, "auth.py": AUTH, "route.py": ROUTE}
    )
    assert not [row for row in visible if Path(row["file"]).name == "route.py"]
    assert any(row.get("symbol") == "record" for row in suppressed)


@pytest.mark.parametrize(
    "model,auth,route",
    [
        (
            MODEL.replace(
                "UUIDField(default=uuid.uuid4, editable=False, unique=True)",
                "CharField(max_length=100)",
            ),
            AUTH,
            ROUTE,
        ),
        (
            MODEL,
            AUTH.replace(
                "app.add_middleware(AuthenticationMiddleware, backend=Backend())", ""
            ),
            ROUTE,
        ),
        (
            MODEL,
            AUTH.replace(
                "user=await Account.objects.filter(id=request.session['id']).afirst()",
                "user=request.query_params",
            ),
            ROUTE,
        ),
        (MODEL, AUTH, ROUTE.replace("user.uuid", "user.username")),
        (
            MODEL,
            AUTH,
            ROUTE.replace(
                "    filename=",
                "    user.uuid=request.query_params['name']\n    filename=",
            ),
        ),
        (MODEL, AUTH.replace("self.object=user", "self.object=request_data"), ROUTE),
        (
            MODEL,
            AUTH,
            ROUTE.replace("@requires(['authenticated'])", "@custom_requires()"),
        ),
        (
            MODEL,
            AUTH,
            ROUTE.replace(
                "    user:Account=request.user.object",
                "    user:Account=request.query_params",
            ),
        ),
    ],
)
def test_uuid_lookalikes_and_modified_provider_retain_http_paths(
    tmp_path, model, auth, route
):
    visible, _ = _scan(
        tmp_path, {"models.py": model, "auth.py": auth, "route.py": route}
    )
    assert any(
        row["rule_id"] == "SKY-D215" and row.get("symbol") == "record"
        for row in visible
    )


@pytest.mark.parametrize(
    "template",
    [
        "'report_{}.txt'.format(str.replace(request.query_params['name'], '/', '_'))",
        "f\"report_{str.replace(request.query_params['name'], '/', '_')}.txt\"",
    ],
)
def test_slash_cleanup_needs_actual_posix_guard_and_fixed_filename_affix(
    tmp_path, template
):
    source = (
        "import os\nfrom starlette.requests import Request\n@api.get('/report')\ndef report(request:Request):\n    if os.name == 'posix':\n        return open("
        + template
        + ", 'w').write('report')\n"
    )
    visible, _ = _scan(tmp_path, {"route.py": source})
    assert not [row for row in visible if row["rule_id"] == "SKY-D215"]
    assert any(row["rule_id"] == "SKY-D324" for row in visible)


@pytest.mark.parametrize(
    "guard,expression,extra",
    [
        (
            "os.name == 'nt'",
            "'report_{}.txt'.format(str.replace(request.query_params['name'], '/', '_'))",
            "",
        ),
        (
            "True",
            "'report_{}.txt'.format(str.replace(request.query_params['name'], '/', '_'))",
            "",
        ),
        (
            "os.name == 'posix'",
            "'{}'.format(str.replace(request.query_params['name'], '/', '_'))",
            "",
        ),
        (
            "os.name == 'posix'",
            "'report_{}.txt'.format(str.replace(request.query_params['name'], '../', ''))",
            "",
        ),
        (
            "os.name == 'posix'",
            "unquote('report_{}.txt'.format(str.replace(request.query_params['name'], '/', '_')))",
            "from urllib.parse import unquote\n",
        ),
        (
            "os.name == 'posix'",
            "'report_{}.txt'.format(str.replace(request.query_params['name'], '/', '_'))",
            "os.name='posix'\n",
        ),
    ],
)
def test_posix_filename_lookalikes_keep_real_traversal(
    tmp_path, guard, expression, extra
):
    source = (
        "import os\nfrom starlette.requests import Request\n"
        + extra
        + "@api.get('/report')\ndef report(request:Request):\n    if "
        + guard
        + ":\n        return open("
        + expression
        + ", 'w').write('report')\n"
    )
    visible, _ = _scan(tmp_path, {"route.py": source})
    assert any(row["rule_id"] == "SKY-D215" for row in visible)


@pytest.mark.parametrize(
    "target,mutation",
    [
        ("model", "\nsetattr(models, 'UUIDField', fake_field)\n"),
        ("model", "\nsetattr(models, field_name, fake_field)\n"),
        ("model", "\nAccount.objects = fake_manager\n"),
        ("auth", "\nBackend.authenticate = replaced_authenticate\n"),
        ("auth", "\napp.add_middleware = fake_install\n"),
        ("auth", "\napp.include_router = fake_install\n"),
        ("route", "\nrequest.user.object = attacker\n"),
    ],
)
def test_mutated_framework_providers_cannot_prove_uuid_safety(
    tmp_path, target, mutation
):
    sources = {"model": MODEL, "auth": AUTH, "route": ROUTE}
    sources[target] += mutation
    visible, _ = _scan(
        tmp_path,
        {
            "models.py": sources["model"],
            "auth.py": sources["auth"],
            "route.py": sources["route"],
        },
    )
    assert any(
        row["rule_id"] == "SKY-D215" and row.get("symbol") == "record"
        for row in visible
    )


@pytest.mark.parametrize(
    "replacement",
    [
        "return request.query_params['authentication']",
        "return unknown_auth_result",
    ],
)
def test_unknown_backend_return_is_not_a_model_provider(tmp_path, replacement):
    auth = AUTH.replace("return AuthCredentials(), UnauthenticatedUser()", replacement)
    visible, _ = _scan(
        tmp_path, {"models.py": MODEL, "auth.py": auth, "route.py": ROUTE}
    )
    assert any(
        row["rule_id"] == "SKY-D215" and row.get("symbol") == "record"
        for row in visible
    )


def test_router_on_a_different_application_does_not_borrow_uuid_provider(tmp_path):
    auth = AUTH.replace(
        "app.include_router(api)", "other=FastAPI()\nother.include_router(api)"
    )
    visible, _ = _scan(
        tmp_path, {"models.py": MODEL, "auth.py": auth, "route.py": ROUTE}
    )
    assert any(
        row["rule_id"] == "SKY-D215" and row.get("symbol") == "record"
        for row in visible
    )


@pytest.mark.parametrize("bad_helper", [False, True])
def test_uuid_provider_follows_orm_tuple_helpers_and_foreign_keys(tmp_path, bad_helper):
    model = (
        MODEL
        + "\nclass Credential(models.Model):\n    user=models.ForeignKey(Account,on_delete=models.CASCADE)\n"
    )
    helper = "from models import Account\nasync def fetch_user():\n    user,created=await Account.objects.aupdate_or_create(username='operator')\n    return user,created\n"
    if bad_helper:
        helper = helper.replace("return user,created", "return unknown_user,created")
    auth = AUTH.replace(
        "from models import Account",
        "from models import Account,Credential\nfrom service import fetch_user",
    )
    auth = auth.replace(
        "user=await Account.objects.filter(id=request.session['id']).afirst()",
        "user,created=await fetch_user()\n        token=await Credential.objects.filter(token=request.headers['token']).afirst()\n        if token:\n            return AuthCredentials(['authenticated']),AuthUser(token.user)",
    )
    visible, _ = _scan(
        tmp_path,
        {"models.py": model, "service.py": helper, "auth.py": auth, "route.py": ROUTE},
    )
    assert (
        bool(
            [
                row
                for row in visible
                if row["rule_id"] == "SKY-D215" and row.get("symbol") == "record"
            ]
        )
        == bad_helper
    )


@pytest.mark.parametrize(
    "target,mutation",
    [
        ("models.py", "globals()['Account']=fake_model\n"),
        ("models.py", "vars()['Account']=fake_model\n"),
        ("auth.py", "globals()['Backend']=fake_backend\n"),
        ("route.py", "globals()['api']=fake_router\n"),
        ("route.py", "globals()['requires']=fake_requires\n"),
    ],
)
def test_dynamic_namespaces_do_not_prove_model_or_app_identity(
    tmp_path, target, mutation
):
    sources = {"models.py": MODEL, "auth.py": AUTH, "route.py": ROUTE}
    sources[target] += mutation
    visible, _ = _scan(tmp_path, sources)
    assert any(
        row["rule_id"] == "SKY-D215" and row.get("symbol") == "record"
        for row in visible
    )


def test_copied_object_keywords_do_not_mutate_provider_namespace(tmp_path):
    route = ROUTE.replace("    filename=", "    log(**user.__dict__)\n    filename=")
    visible, _ = _scan(
        tmp_path, {"models.py": MODEL, "auth.py": AUTH, "route.py": route}
    )
    assert not [row for row in visible if row.get("symbol") == "record"]
