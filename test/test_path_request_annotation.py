"""A parameter named ``request`` is web request data only by convention.

An explicit annotation with a type that is not a framework request (a
project dataclass, ``str``, an external non-web type) turns the convention
off, and the parameter's callers decide what it holds. No annotation, ``Any``,
framework request types, project subclasses of them, aliases, string forms and
optional forms keep the convention.
"""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink

PATH_RULES = {"SKY-D215", "SKY-D324", "SKY-D325"}

KERNEL = """\
import os
{imports}

BASE = "/srv/out"


@dataclass
class TranslateRequest:
    files: list
    output: str

{classes}

def translate(request{annotation}):
    with open(os.path.join(BASE, request.output), "w") as handle:
        handle.write("x")
    return request.files
"""


def _project(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "proj"
    (root / ".git").mkdir(parents=True)
    assert write_text_no_symlink(root / "pyproject.toml", '[project]\nname = "proj"\n')
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, text)
    return root


def _scan(tmp_path, files):
    result = json.loads(analyze(str(_project(tmp_path, files)), enable_danger=True))
    reported = {
        finding["rule_id"]
        for finding in result.get("danger") or []
        if finding.get("rule_id") in PATH_RULES and finding.get("symbol") == "translate"
    }
    suppressed = {
        finding["rule_id"]: finding
        for finding in result.get("suppressed") or []
        if finding.get("rule_id") in PATH_RULES and finding.get("symbol") == "translate"
    }
    return reported, suppressed


def _kernel(annotation, imports="", classes=""):
    return KERNEL.format(
        imports="from dataclasses import dataclass\n" + imports,
        classes=classes,
        annotation=annotation,
    )


NON_REQUEST = {
    "project_dataclass": (": TranslateRequest", "", ""),
    "string_project_dataclass": (': "TranslateRequest"', "", ""),
    "optional_project_dataclass": (
        ": Optional[TranslateRequest]",
        "from typing import Optional\n",
        "",
    ),
    "union_with_none": (": TranslateRequest | None", "", ""),
    "builtin_str": (": str", "", ""),
    "external_non_web_type": (
        ": PreparedRequest",
        "from requests import PreparedRequest\n",
        "",
    ),
    "project_model_on_a_non_web_base": (
        ": Job",
        "from pydantic import BaseModel\n",
        "class Job(BaseModel):\n    output: str\n    files: list\n\n",
    ),
}


@pytest.mark.parametrize("form", sorted(NON_REQUEST))
def test_non_request_annotation_turns_off_the_request_name_convention(tmp_path, form):
    annotation, imports, classes = NON_REQUEST[form]
    reported, suppressed = _scan(
        tmp_path,
        {"app/__init__.py": "", "app/kernel.py": _kernel(annotation, imports, classes)},
    )
    assert reported == set()
    assert suppressed["SKY-D215"]["metadata"]["path_provenance"]["status"] == "unknown"


def test_non_request_annotation_in_a_flask_module_turns_off_the_convention(tmp_path):
    kernel = _kernel(
        ": TranslateRequest", "from flask import Flask\n\napp = Flask(__name__)\n"
    )
    reported, _ = _scan(tmp_path, {"app/__init__.py": "", "app/kernel.py": kernel})
    assert reported == set()


REQUEST_FORMS = {
    "no_annotation": ("", "", ""),
    "any": (": Any", "from typing import Any\n", ""),
    "object": (": object", "", ""),
    "django_http_request": (
        ": HttpRequest",
        "from django.http import HttpRequest\n",
        "",
    ),
    "flask_request_attribute": (": flask.Request", "import flask\n", ""),
    "aliased_flask_request": (": Req", "from flask import Request as Req\n", ""),
    "module_alias_of_a_request_type": (
        ": Job",
        "import flask\n\nJob = flask.Request\n",
        "",
    ),
    "project_subclass_of_flask_request": (
        ": R",
        "import flask\n",
        "class R(flask.Request):\n    pass\n\n",
    ),
    "project_subclass_two_levels_down": (
        ": ApiRequest",
        "from starlette.requests import Request\n",
        "class BaseApiRequest(Request):\n    pass\n\n\nclass ApiRequest(BaseApiRequest):\n    pass\n\n",
    ),
    "request_named_class_on_werkzeug": (
        ": TranslateJob",
        "from werkzeug.wrappers import Request as WerkzeugRequest\n",
        "class TranslateJob(WerkzeugRequest):\n    pass\n\n",
    ),
    "string_http_request": (
        ': "HttpRequest"',
        "from django.http import HttpRequest\n",
        "",
    ),
    "string_flask_request": (': "flask.Request"', "import flask\n", ""),
    "string_project_subclass": (
        ': "R"',
        "import flask\n",
        "class R(flask.Request):\n    pass\n\n",
    ),
    "optional_http_request": (
        ": Optional[HttpRequest]",
        "from typing import Optional\nfrom django.http import HttpRequest\n",
        "",
    ),
    "http_request_or_none": (
        ": HttpRequest | None",
        "from django.http import HttpRequest\n",
        "",
    ),
    "union_with_a_request_type": (
        ": Union[TranslateRequest, HttpRequest]",
        "from typing import Union\nfrom django.http import HttpRequest\n",
        "",
    ),
    "optional_project_subclass": (
        ": Optional[R]",
        "import flask\nfrom typing import Optional\n",
        "class R(flask.Request):\n    pass\n\n",
    ),
    "annotated_project_subclass": (
        ": Annotated[R, 'web']",
        "import flask\nfrom typing import Annotated\n",
        "class R(flask.Request):\n    pass\n\n",
    ),
    "unresolved_name": (": Mystery", "", ""),
    "unparseable_string": (': "not valid ]["', "", ""),
}


@pytest.mark.parametrize("form", sorted(REQUEST_FORMS))
def test_request_name_convention_still_reports_for_request_like_annotations(
    tmp_path, form
):
    annotation, imports, classes = REQUEST_FORMS[form]
    reported, _ = _scan(
        tmp_path,
        {"app/__init__.py": "", "app/kernel.py": _kernel(annotation, imports, classes)},
    )
    assert "SKY-D215" in reported


def test_annotated_parameter_still_reports_when_a_route_passes_request_data(tmp_path):
    kernel = (
        "import os\n\n"
        "from pydantic import BaseModel\n\n\n"
        "class TranslateRequest(BaseModel):\n"
        "    output: str\n"
        "    files: list\n\n\n"
        "def translate(request: TranslateRequest):\n"
        "    with open(os.path.join('/srv/out', request.output), 'w') as handle:\n"
        "        handle.write('x')\n"
        "    return request.files\n"
    )
    api = (
        "from fastapi import FastAPI\n\n"
        "from app.kernel import TranslateRequest, translate\n\n"
        "api = FastAPI()\n\n\n"
        "@api.post('/translate')\n"
        "def run(body: TranslateRequest):\n"
        "    return translate(body)\n"
    )
    reported, _ = _scan(
        tmp_path, {"app/__init__.py": "", "app/kernel.py": kernel, "app/api.py": api}
    )
    assert {"SKY-D215", "SKY-D324"} <= reported


GUARDS_THAT_DO_NOT_GUARD = {
    "useless_checks_on_a_request_type": (
        "import os\n"
        "from django.http import HttpRequest\n\n\n"
        "def translate(request: HttpRequest):\n"
        "    if not isinstance(request, HttpRequest):\n"
        "        print('unexpected request type')\n"
        "    if request:\n"
        "        pass\n"
        "    return open(os.path.join('/srv/out', request.GET['name'])).read()\n"
    ),
    "non_request_annotation_on_another_parameter": (
        "import os\n"
        "from dataclasses import dataclass\n\n\n"
        "@dataclass\n"
        "class TranslateRequest:\n"
        "    output: str\n\n\n"
        "def translate(job: TranslateRequest, request):\n"
        "    if isinstance(job, TranslateRequest):\n"
        "        return open(os.path.join('/srv/out', request.args['name'])).read()\n"
        "    return ''\n"
    ),
    "non_request_type_check_without_an_annotation": (
        "import os\n"
        "from dataclasses import dataclass\n\n\n"
        "@dataclass\n"
        "class TranslateRequest:\n"
        "    output: str\n\n\n"
        "def translate(request):\n"
        "    if isinstance(request, TranslateRequest):\n"
        "        pass\n"
        "    return open(os.path.join('/srv/out', request.args['name'])).read()\n"
    ),
}


@pytest.mark.parametrize("form", sorted(GUARDS_THAT_DO_NOT_GUARD))
def test_checks_that_do_not_change_the_request_type_still_report(tmp_path, form):
    reported, _ = _scan(
        tmp_path,
        {"app/__init__.py": "", "app/kernel.py": GUARDS_THAT_DO_NOT_GUARD[form]},
    )
    assert "SKY-D215" in reported
