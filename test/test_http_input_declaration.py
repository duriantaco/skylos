"""Source-only declarations for conditional filename guard evidence."""

import ast

import pytest

from skylos.security.http_input_declaration import (
    declared_http_string_input,
    declared_model_string_field,
)
from test.fixture_paths import write_fixture

BODY = """
from typing import Optional
from fastapi import FastAPI, Body
from pydantic import BaseModel, Field, ConfigDict
app = FastAPI(title="example")
class Payload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = Field(default=None, max_length=100)
    count: int = 4
@app.post("/items")
def route(payload: Payload | None = Body(default=None)):
    return payload
"""


def _declared(source, field="name", **kwargs):
    tree = ast.parse(source)
    route = next(fn for fn in tree.body if getattr(fn, "name", "") == "route")
    return declared_http_string_input(tree, route, route.args.args[0], field, **kwargs)


def test_native_declarations_bind_exact_parameter_and_model_field():
    tree = ast.parse(BODY)
    route = tree.body[-1]
    model = tree.body[-2]
    assert declared_http_string_input(tree, route, "payload", "name")
    assert declared_model_string_field(tree, model, "name")
    assert not declared_http_string_input(tree, route, "other", "name")
    assert not declared_model_string_field(tree, model, "count")
    assert not declared_http_string_input(tree, route, "payload", "missing")
    assert not declared_http_string_input(tree, route, "payload")


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("class Payload(BaseModel)", "class Payload(CustomModel)"),
        ("class Payload(BaseModel)", "@decorated\nclass Payload(BaseModel)"),
        ("name: Optional[str]", "name: CustomType"),
        (
            "class Payload(BaseModel):",
            "class Payload(BaseModel):\n    def model_post_init(self, context): pass",
        ),
        ("Field(default=None,", "Field(default_factory=foreign,"),
        ('extra="forbid"', "arbitrary_types_allowed=True"),
        ('@app.post("/items")', '@app.post("/items", dependencies=[foreign])'),
        ('title="example"', "route_class=CustomRoute"),
        ("Body(default=None)", "foreign(default=None)"),
        (
            "from typing import Optional",
            "from local import str\nfrom typing import Optional",
        ),
        ("from fastapi import FastAPI, Body", "from other import FastAPI, Body"),
    ],
)
def test_custom_model_and_route_dispatch_remain_unresolved(before, after):
    assert not _declared(BODY.replace(before, after))


@pytest.mark.parametrize(
    "extra",
    [
        "foreign.configure(app)",
        "alias = app\nforeign.configure(package={'server': alias})",
        "app.router.route_class = MyRoute",
        "app.add_middleware(ForeignMiddleware)",
        "ModelAlias = Payload\nModelAlias.model_fields = replacement",
        "payload.name = make_value()",
        "setattr(payload, 'name', replacement)",
        "import fastapi.routing as routing\nother = routing\nother.serialize_response = replacement",
        "import json\nsetattr(json, 'loads', replacement)",
        "globals()['Payload'] = replacement",
        "Payload = alternate",
        "from foreign import *",
    ],
)
def test_visible_binding_mutation_or_escape_remains_unresolved(extra):
    assert not _declared(BODY + extra)


def test_route_string_and_unrelated_dataclass_are_ordinary_declarations():
    source = """
from fastapi import FastAPI
from dataclasses import dataclass
app = FastAPI()
@dataclass(frozen=True)
class Descriptor:
    size: int
@app.get("/read/{name}")
def route(name: str):
    return name
"""
    assert _declared(source, None)
    assert not _declared(source, "other")
    assert not _declared(source.replace("name: str", "name: bytes"), None)
    assert not _declared(source + "app.get = foreign.register", None)


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("pydantic.py", "class BaseModel: pass"),
        ("patcher.py", "import json\njson.loads = replacement"),
        ("patcher.py", "import main\nmain.Payload.name = replacement"),
        ("patcher.py", "from main import app\nforeign.configure(app)"),
    ],
)
def test_project_shadow_or_imported_write_is_adverse(tmp_path, name, code):
    source = BODY + "import patcher\n"
    path = write_fixture(tmp_path, "main.py", source)
    write_fixture(tmp_path, name, code)
    assert not _declared(source, filename=path, project_root=tmp_path)


def test_ordinary_declaration_works_in_real_source_context(tmp_path):
    path = write_fixture(tmp_path, "main.py", BODY)
    assert _declared(BODY, filename=path, project_root=tmp_path)
