"""Model storage capabilities must not masquerade as validated native strings."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.reporting.listing import is_listed


_HEADER = """import os
from fastapi import FastAPI
from pydantic import BaseModel
from storage import load

app = FastAPI()
ROOT = '/srv/files'

def clean(raw):
    cleaned = ''.join(c if c.isalnum() or c in ('-', '_') else '_' for c in raw)
    return cleaned or 'empty'

class Parent(BaseModel):
    name: str

class Request(Parent):
    pass

class Raw(str):
    def __iter__(self):
        yield self
    def isalnum(self):
        return True
"""
_ROUTE = """
@app.post('/files')
def view(payload: Request):
{mutation}
    return load(os.path.join(ROOT, clean(payload.name), 'record.json'))
"""
_STORAGE = "def load(path):\n    with open(path, 'r') as stream:\n        return stream.read()\n"


def _scan(
    tmp_path, monkeypatch, mutation="pass", prelude="", extra=None, header=_HEADER
):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="route-model-boundary"\n')
    source = (
        header
        + prelude
        + _ROUTE.format(
            mutation="\n".join("    " + line for line in mutation.splitlines())
        )
    )
    for name, code in {
        "app.py": source,
        "storage.py": _STORAGE,
        **(extra or {}),
    }.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code)
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            grep_verify=False,
            grep_cache=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors")
    rows = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D215"]
    return result, rows


def _assert_unsafe(result, rows):
    assert len(rows) == 1
    [finding] = rows
    assert (Path(finding["file"]).name, finding["line"]) == ("storage.py", 2)
    assert finding["severity"] == "HIGH"
    assert is_listed(finding, "danger") is True
    assert finding["metadata"]["path_provenance"]["status"] == "untrusted"
    assert check_gate(result, {"gate": {"max_high": 0}})[0] is False
    assert (
        check_gate({"danger": rows}, {"gate": {"max_high": 0, "max_security": 0}})[0]
        is False
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "object.__setattr__(payload, 'name', Raw(payload.name))",
        "writer = object.__setattr__\nwriter(payload, 'name', Raw(payload.name))",
        "from builtins import object as Root\nRoot.__setattr__(payload, 'name', Raw(payload.name))",
        "type(payload).__setattr__(payload, 'name', Raw(payload.name))",
        "writer = payload.__setattr__\nwriter('name', Raw(payload.name))",
        "from functools import partial\nwriter=partial(object.__setattr__, payload, 'name')\nwriter(Raw(payload.name))",
        "from functools import partial\nwriter=partial(setattr, payload, 'name')\nwriter(Raw(payload.name))",
        "state=object.__getattribute__(payload, '__dict__')\nstate['name']=Raw(payload.name)",
        "from operator import attrgetter\nstate=attrgetter('__dict__')(payload)\nstate['name']=Raw(payload.name)",
        "state=payload.__dict__\nstate.update({'name':Raw(payload.name)})",
        "vars(payload)['name']=Raw(payload.name)",
        "import external_plugin\nexternal_plugin.mutate(payload)",
        "key=input()\nwriter=getattr(payload,key)\nwriter('name',Raw(payload.name))",
        "mutate(payload)",
    ],
    ids=[
        "object-protocol",
        "object-alias",
        "imported-object",
        "type-protocol",
        "bound-protocol",
        "partial-object",
        "partial-builtin",
        "namespace-protocol",
        "namespace-attrgetter",
        "dict-alias",
        "vars",
        "opaque-external",
        "computed-capability",
        "local-helper",
    ],
)
def test_mutated_validated_field_remains_reported(tmp_path, monkeypatch, mutation):
    prelude = ""
    if mutation == "mutate(payload)":
        prelude = "\ndef mutate(value):\n    object.__setattr__(value,'name',Raw(value.name))\n"
    result, rows = _scan(tmp_path, monkeypatch, mutation, prelude)
    _assert_unsafe(result, rows)


def test_unknown_effect_through_a_resolved_helper_remains_reported(
    tmp_path, monkeypatch
):
    prelude = "\nimport external_plugin\ndef mutate(value):\n    external_plugin.mutate(value)\n"
    result, rows = _scan(tmp_path, monkeypatch, "mutate(payload)", prelude)
    _assert_unsafe(result, rows)


@pytest.mark.parametrize(
    "mutation,prelude",
    [
        ("pass", ""),
        ("other=Other()\nother.name='fixed'", "\nclass Other:\n    pass\n"),
        (
            "other=Other()\nobject.__setattr__(other,'name','fixed')",
            "\nclass Other:\n    pass\n",
        ),
        ("isinstance(payload, Request)\nprint(payload)\nrepr(payload)", ""),
    ],
    ids=[
        "plain-inherited-model",
        "unrelated-field-store",
        "unrelated-protocol",
        "readonly-builtins",
    ],
)
def test_proven_native_fields_keep_filename_precision(
    tmp_path, monkeypatch, mutation, prelude
):
    result, rows = _scan(tmp_path, monkeypatch, mutation, prelude)
    assert rows == []
    suppressed = [
        row for row in result.get("suppressed", []) if row["rule_id"] == "SKY-D215"
    ]
    assert len(suppressed) == 1
    assert suppressed[0]["metadata"]["path_provenance"]["status"] == "safe"
    assert check_gate(result, {"gate": {"max_high": 0}})[0] is True


@pytest.mark.parametrize(
    "field,prelude",
    [
        ("    other: Custom\n", "\nfrom external_types import Custom\n"),
        ("    other: list[Custom]\n", "\nfrom external_types import Custom\n"),
        (
            "    other: int = unknown_default\n",
            "\nfrom external_types import unknown_default\n",
        ),
        (
            "    other: int = Field(default=unknown_default)\n",
            "\nfrom pydantic import Field\nfrom external_types import unknown_default\n",
        ),
        (
            "    other: Custom\n",
            "\nfrom pydantic_core import core_schema\nclass Custom:\n    @classmethod\n    def __get_pydantic_core_schema__(cls, source, handler):\n        def rewrite(value, info):\n            info.data['name']=Raw(info.data['name'])\n            return value\n        return core_schema.with_info_after_validator_function(rewrite, core_schema.str_schema())\n",
        ),
    ],
    ids=[
        "opaque-type",
        "nested-opaque-type",
        "opaque-default",
        "opaque-field-default",
        "custom-validator-overwrites-prior-field",
    ],
)
def test_other_field_validation_cannot_change_the_native_string(
    tmp_path, monkeypatch, field, prelude
):
    source = _HEADER.replace(
        "class Request(Parent):\n    pass\n", "class Request(Parent):\n" + field
    )
    (tmp_path / "pyproject.toml").write_text('[project]\nname="whole-model-boundary"\n')
    (tmp_path / "storage.py").write_text(_STORAGE)
    (tmp_path / "app.py").write_text(
        prelude + source + _ROUTE.format(mutation="    pass")
    )
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            grep_verify=False,
            grep_cache=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors")
    rows = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D215"]
    _assert_unsafe(result, rows)


@pytest.mark.parametrize(
    "field", ["    count: int = 0\n", "    tags: list[str] = []\n"]
)
def test_inert_secondary_fields_preserve_native_string_proof(
    tmp_path, monkeypatch, field
):
    source = _HEADER.replace(
        "class Request(Parent):\n    pass\n", "class Request(Parent):\n" + field
    )
    (tmp_path / "pyproject.toml").write_text('[project]\nname="inert-model-boundary"\n')
    (tmp_path / "storage.py").write_text(_STORAGE)
    (tmp_path / "app.py").write_text(source + _ROUTE.format(mutation="    pass"))
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            grep_verify=False,
            grep_cache=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors")
    assert not [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D215"]
    assert check_gate(result, {"gate": {"max_high": 0}})[0] is True


def test_local_identity_does_not_erase_an_escaped_model(tmp_path, monkeypatch):
    prelude = "\nimport external_plugin\ndef identity(value):\n    return value\n"
    result, rows = _scan(
        tmp_path,
        monkeypatch,
        "alias=identity(payload)\nexternal_plugin.mutate(alias)",
        prelude,
    )
    _assert_unsafe(result, rows)


@pytest.mark.parametrize("operation", ["model_dump", "dict", "json", "model_dump_json"])
def test_inert_model_read_methods_preserve_native_field(
    tmp_path, monkeypatch, operation
):
    result, rows = _scan(tmp_path, monkeypatch, "payload." + operation + "()")
    assert rows == []
    assert check_gate(result, {"gate": {"max_high": 0}})[0] is True


def test_a_custom_constructor_cannot_exclude_a_model_receiver(tmp_path, monkeypatch):
    prelude = "\nclass Other:\n    def __new__(cls, value):\n        return value\n"
    result, rows = _scan(
        tmp_path,
        monkeypatch,
        "alias=Other(payload)\nobject.__setattr__(alias,'name',Raw(payload.name))",
        prelude,
    )
    _assert_unsafe(result, rows)


@pytest.mark.parametrize(
    "mutation,prelude",
    [
        (
            "alias=await identity(payload)\nexternal_plugin.mutate(alias)",
            "\nimport external_plugin\nasync def identity(value):\n    return value\n",
        ),
        ("external_plugin.mutate(alias := payload)", "\nimport external_plugin\n"),
    ],
    ids=["await-local-result", "named-expression"],
)
def test_expression_wrappers_preserve_model_capability(
    tmp_path, monkeypatch, mutation, prelude
):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="wrapped-model"\n')
    (tmp_path / "storage.py").write_text(_STORAGE)
    route = _ROUTE.replace("def view(", "async def view(")
    (tmp_path / "app.py").write_text(
        _HEADER
        + prelude
        + route.format(
            mutation="\n".join("    " + line for line in mutation.splitlines())
        )
    )
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            grep_verify=False,
            grep_cache=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors")
    rows = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D215"]
    _assert_unsafe(result, rows)


@pytest.mark.parametrize(
    "mutation",
    [
        "token + payload",
        "token == payload",
        "token[payload]",
        "holder=Holder()\nholder.current=payload\nexternal_plugin.mutate(holder)",
        "cache={}\ncache['current']=payload\nexternal_plugin.mutate(cache)",
        "class Box:\n    current=payload\nexternal_plugin.mutate(Box)",
        "global saved\nsaved=payload\nexternal_plugin.mutate_global()",
        "if True:\n    global saved\n(saved := payload)\nexternal_plugin.mutate_global()",
        "callback=lambda:payload\nexternal_plugin.register(callback)",
        "def callback():\n    return payload\nexternal_plugin.register(callback)",
    ],
    ids=[
        "opaque-add",
        "opaque-equality",
        "opaque-index",
        "attribute-store",
        "mapping-store",
        "class-store",
        "global-store",
        "nested-global-walrus",
        "lambda-capture",
        "function-capture",
    ],
)
def test_unsupported_model_ownership_keeps_native_field_unproved(
    tmp_path, monkeypatch, mutation
):
    prelude = "\nimport external_plugin\nfrom opaque_plugin import token\nclass Holder:\n    pass\n"
    result, rows = _scan(tmp_path, monkeypatch, mutation, prelude)
    _assert_unsafe(result, rows)


def test_a_frozen_model_dictionary_key_still_carries_mutable_storage(
    tmp_path, monkeypatch
):
    header = _HEADER.replace(
        "from pydantic import BaseModel", "from pydantic import BaseModel, ConfigDict"
    ).replace(
        "class Request(Parent):\n    pass",
        "class Request(Parent):\n    model_config=ConfigDict(frozen=True)",
    )
    result, rows = _scan(
        tmp_path,
        monkeypatch,
        "external_plugin.mutate({payload:1})",
        "\nimport external_plugin\n",
        header=header,
    )
    _assert_unsafe(result, rows)


def test_external_base_hook_authority_survives_partial_binding(tmp_path, monkeypatch):
    prelude = "\nfrom functools import partial\ndef intercept(instance,key):\n    value=object.__getattribute__(instance,key)\n    if key=='name':\n        return Raw(value)\n    return value\n"
    result, rows = _scan(
        tmp_path,
        monkeypatch,
        "writer=partial(setattr,BaseModel,'__getattribute__')\nwriter(intercept)",
        prelude,
    )
    _assert_unsafe(result, rows)


def test_native_annotation_namespace_is_not_an_opaque_plugin_argument(
    tmp_path, monkeypatch
):
    result, rows = _scan(
        tmp_path,
        monkeypatch,
        "external_plugin.install(builtins)",
        "\nimport builtins,external_plugin\n",
    )
    _assert_unsafe(result, rows)


@pytest.mark.parametrize("length", [2, 30])
def test_long_local_forwarding_never_forgets_model_authority(
    tmp_path, monkeypatch, length
):
    functions = "\nimport external_plugin\n"
    for index in range(length):
        returned = (
            "value" if index == length - 1 else "step" + str(index + 1) + "(value)"
        )
        functions += "def step" + str(index) + "(value):\n    return " + returned + "\n"
    result, rows = _scan(
        tmp_path, monkeypatch, "external_plugin.mutate(step0(payload))", functions
    )
    _assert_unsafe(result, rows)


def test_unpacked_attribute_protocol_arguments_retain_model_authority(
    tmp_path, monkeypatch
):
    mutation = "writer=object.__setattr__\narguments=[payload,'name',Raw(payload.name)]\nwriter(*arguments)"
    result, rows = _scan(tmp_path, monkeypatch, mutation)
    _assert_unsafe(result, rows)


@pytest.mark.parametrize("decorator", ["staticmethod", "classmethod"])
def test_native_method_decorators_keep_local_calls_local(
    tmp_path, monkeypatch, decorator
):
    first = "" if decorator == "staticmethod" else "cls, "
    prelude = f"\nclass Helper:\n    @{decorator}\n    def echo({first}value):\n        return value\n"
    result, rows = _scan(tmp_path, monkeypatch, "Helper.echo('plain')", prelude)
    assert rows == []
    assert check_gate(result, {"gate": {"max_high": 0}})[0] is True


def test_opaque_method_decorator_does_not_hide_model_effects(tmp_path, monkeypatch):
    prelude = "\nfrom external_plugin import decorate\nclass Helper:\n    @decorate\n    def echo(value):\n        return value\n"
    result, rows = _scan(tmp_path, monkeypatch, "Helper.echo(payload)", prelude)
    _assert_unsafe(result, rows)


@pytest.mark.parametrize("imported", [False, True])
def test_model_effects_follow_runtime_import_domain(tmp_path, monkeypatch, imported):
    plugin = (
        "import pytest\nfrom app import Request\nRequest.__getattribute__ = input()\n"
    )
    prelude = "\nimport tests.test_plugin\n" if imported else ""
    result, rows = _scan(
        tmp_path,
        monkeypatch,
        prelude=prelude,
        extra={"tests/__init__.py": "", "tests/test_plugin.py": plugin},
    )
    if imported:
        _assert_unsafe(result, rows)
    else:
        assert rows == []
        assert check_gate(result, {"gate": {"max_high": 0}})[0] is True
