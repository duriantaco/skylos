"""HTTP dependency audits parse fixtures; framework/target code is never run."""

import ast

import pytest

from skylos.security.framework_contracts import native_http_pipeline_is_intact
from test.fixture_paths import write_fixture


def _intact(tmp_path, source, **kwargs):
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="fixture"\n')
    path = write_fixture(tmp_path, "app.py", source)
    tree = ast.parse(source, filename=str(path))
    return native_http_pipeline_is_intact(tree, path, tmp_path, **kwargs)


def test_inert_ast_size_does_not_spend_dependency_operation_budget(tmp_path):
    source = "from fastapi import FastAPI\n" + "value=1\n" * 2000
    assert _intact(tmp_path, source, max_work=1)


def test_deep_literal_arithmetic_has_no_provider_capability(tmp_path):
    expression = "(" * 40 + "320" + " + 1)" * 40
    assert _intact(tmp_path, "WIDTH=" + expression + "\n")


def test_literal_global_scalar_projection_does_not_escape_namespace(tmp_path):
    assert _intact(tmp_path, "WIDTH=320\ndef width():\n    return globals()['WIDTH']\n")


@pytest.mark.parametrize(
    "definition",
    [
        "from fastapi import routing\nWIDTH=routing",
        "def WIDTH():\n    return None",
        "class WIDTH:\n    pass",
    ],
)
def test_literal_namespace_key_cannot_project_provider_or_python_namespace(
    tmp_path, definition
):
    assert not _intact(
        tmp_path, definition + "\ndef width():\n    return globals()['WIDTH']\n"
    )


def test_native_model_class_instance_check_is_not_an_opaque_escape(tmp_path):
    assert _intact(
        tmp_path,
        "from pydantic import BaseModel\n"
        "class Parent(BaseModel):\n    name: str\n"
        "class Payload(Parent):\n    pass\n"
        "def inspect(payload):\n    return isinstance(payload, Payload)\n",
    )


def test_unknown_model_metaclass_is_not_a_native_instance_reader(tmp_path):
    assert not _intact(
        tmp_path,
        "from pydantic import BaseModel\nimport foreign\n"
        "class Payload(BaseModel, metaclass=foreign.Meta):\n    name: str\n"
        "def inspect(payload):\n    return isinstance(payload, Payload)\n",
    )


@pytest.mark.parametrize(
    "read",
    [
        "getattr(other, 'name', None)",
        "setattr(other, 'name', 'value')",
        "delattr(other, 'name')",
        "globals().get('other')",
        "locals().get('other', None)",
        "builtins.getattr(other, 'name', None)",
    ],
)
def test_unrelated_reflection_does_not_expose_http_provider(tmp_path, read):
    assert _intact(
        tmp_path, "import builtins, foreign\nother=foreign.factory()\n" + read + "\n"
    )


@pytest.mark.parametrize(
    "change",
    [
        "getattr(routing, 'APIRoute').get_route_handler=foreign.handler",
        "setattr(routing, 'get_request_handler', foreign.handler)",
        "delattr(TypeAdapter, 'validate_python')",
        "foreign.configure(json._default_decoder)",
        "globals().get('routing').get_request_handler=foreign.handler",
        "globals().get('TypeAdapter').validate_python=foreign.validate",
        "namespace=globals\nnamespace()['routing']=foreign.router",
        "from builtins import globals as namespace\nnamespace()['routing']=foreign.router",
        "globals().get(foreign.key)",
        "exec(foreign.source)",
    ],
)
def test_provider_reflection_mutation_and_namespace_escape_remain_unproven(
    tmp_path, change
):
    assert not _intact(
        tmp_path,
        "import foreign, json\nfrom fastapi import routing\n"
        "from pydantic import TypeAdapter\n" + change + "\n",
    )


def test_dependency_audit_retains_a_finite_operation_budget(tmp_path):
    assert not _intact(tmp_path, "getattr(other,'a')\ngetattr(other,'b')\n", max_work=1)


def test_cached_contract_reattests_imported_source_snapshot(tmp_path):
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="fixture"\n')
    source = "import patcher\nfrom fastapi import FastAPI\n"
    path = write_fixture(tmp_path, "app.py", source)
    write_fixture(tmp_path, "patcher.py", "value=1\n")
    tree = ast.parse(source, filename=str(path))
    assert native_http_pipeline_is_intact(tree, path, tmp_path)
    write_fixture(
        tmp_path,
        "patcher.py",
        "import json, foreign\njson._default_decoder=foreign.decoder\n",
        overwrite=True,
    )
    assert not native_http_pipeline_is_intact(tree, path, tmp_path)


REGISTRATION = (
    "from fastapi import FastAPI\n"
    "from fastapi.middleware.cors import CORSMiddleware\n"
    "from pydantic import BaseModel\n"
    "app=FastAPI()\nclass Result(BaseModel):\n    value: str\n"
    "app.add_middleware(CORSMiddleware,allow_origins=['*'])\n"
    "@app.get('/preview',response_model=Result)\n"
    "def preview():\n    return {'value':'native'}\n"
)


def test_native_framework_class_registration_is_not_opaque_provider_escape(tmp_path):
    assert _intact(tmp_path, REGISTRATION)


def test_native_http_exception_instance_check_does_not_escape_its_class(tmp_path):
    assert _intact(
        tmp_path,
        "from fastapi import HTTPException\n"
        "def classify(exc):\n    return isinstance(exc, HTTPException)\n",
    )


def test_replaced_instance_check_cannot_consume_http_exception_class(tmp_path):
    assert not _intact(
        tmp_path,
        "import builtins, foreign\nfrom fastapi import HTTPException\n"
        "builtins.isinstance=foreign.check\n"
        "def classify(exc):\n    return isinstance(exc, HTTPException)\n",
    )


@pytest.mark.parametrize(
    "change",
    [
        "app.add_middleware=foreign.register",
        "alias=app\nalias.add_middleware=foreign.register",
        "setattr(app,'add_middleware',foreign.register)",
        "app.get=foreign.register",
        "CORSMiddleware.__call__=foreign.middleware",
        "foreign.register(CORSMiddleware)",
        "foreign.register(Result)",
    ],
)
def test_modified_or_opaque_registration_does_not_consume_provider_safely(
    tmp_path, change
):
    assert not _intact(tmp_path, REGISTRATION + "\nimport foreign\n" + change + "\n")
