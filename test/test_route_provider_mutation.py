"""A source-local inert provider is not inert after visible replacement."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.rules.danger.danger import scan_ctx
from test.fixture_paths import write_fixture


CASES = [
    pytest.param(
        'import sys,types\nfrom flask import Flask\nsys.modules["fastapi"]=types.SimpleNamespace(FastAPI=Flask)\nfrom fastapi import FastAPI\napp=FastAPI(__name__)\n@app.post("/control/poweroff")\ndef poweroff():\n    return {"ok":True}\napp.run(host="0.0.0.0")\n',
        (
            (
                "fastapi.py",
                "class FastAPI:\n    def __init__(self,*args,**kwargs):\n        pass\n    def post(self,*args,**kwargs):\n        return lambda handler:handler\n",
            ),
        ),
        True,
        id="native-flask-via-sysmodules",
    ),
    pytest.param(
        'from fastapi import FastAPI\napp=FastAPI(__name__)\n@app.post("/control/poweroff")\ndef poweroff():\n    return {"ok":True}\napp.run(host="0.0.0.0")\n',
        (
            (
                "fastapi.py",
                "class FastAPI:\n    def __init__(self,*args,**kwargs):\n        pass\n    def post(self,*args,**kwargs):\n        return lambda handler:handler\n",
            ),
        ),
        False,
        id="inert-provider-control",
    ),
    pytest.param(
        'from flask import Flask as FastAPI\napp=FastAPI(__name__)\n@app.post("/control/poweroff")\ndef poweroff():\n    return {"ok":True}\napp.run(host="0.0.0.0")\n',
        (),
        True,
        id="native-flask-control",
    ),
    pytest.param(
        'from fastapi import FastAPI\nfrom flask import Flask\nFastAPI.__new__=staticmethod(lambda cls,*args,**kwargs: Flask(__name__))\napp=FastAPI(__name__)\n@app.post("/control/poweroff")\ndef poweroff():\n    return {"ok":True}\napp.run(host="0.0.0.0")\n',
        (
            (
                "fastapi.py",
                "class FastAPI:\n    def __init__(self,*args,**kwargs):\n        pass\n    def post(self,*args,**kwargs):\n        return lambda handler:handler\n",
            ),
        ),
        True,
        id="native-flask-via-patched-localprovider",
    ),
    pytest.param(
        'class FastAPI:\n    def __init__(self,*args,**kwargs):\n        pass\n    def post(self,*args,**kwargs):\n        return lambda handler:handler\nfrom flask import Flask\nFastAPI.__new__=staticmethod(lambda cls,*args,**kwargs: Flask(__name__))\n\napp=FastAPI(__name__)\n@app.post("/control/poweroff")\ndef poweroff():\n    return {"ok":True}\napp.run(host="0.0.0.0")\n',
        (),
        True,
        id="native-flask-via-patched-localclass",
    ),
]


@pytest.mark.parametrize("source,providers,vulnerable", CASES)
def test_route_provider_negative_proof_survives_source_effect_checks(
    tmp_path, monkeypatch, source, providers, vulnerable
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    root = tmp_path.resolve()
    path = write_fixture(root, "app.py", source)
    for name, content in providers:
        write_fixture(root, name, content)
    raw = [row for row in scan_ctx(root, [path]) if row["rule_id"] == "SKY-D283"]
    result = json.loads(
        analyze(
            str(root),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_verify=False,
            grep_cache=False,
        )
    )
    assert not result.get("analysis_errors")
    listed = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D283"]
    assert bool(raw) is bool(listed) is vulnerable
    if vulnerable:
        assert [(row["line"], row["severity"]) for row in raw] == [
            (row["line"], row["severity"]) for row in listed
        ]
        assert all(
            row["severity"] in {"HIGH", "CRITICAL"} and row["listing"]["listed"]
            for row in listed
        )
    assert check_gate(result, {"gate": {"max_high": 0, "max_security": 0}})[0] is (
        not vulnerable
    )


def test_opaque_extension_provider_does_not_inherit_inert_source_proof(
    tmp_path, monkeypatch
):
    from importlib.machinery import EXTENSION_SUFFIXES

    source, providers, _vulnerable = CASES[1].values
    providers = (*providers, ("fastapi" + EXTENSION_SUFFIXES[0], "opaque extension"))
    test_route_provider_negative_proof_survives_source_effect_checks(
        tmp_path, monkeypatch, source, providers, True
    )


@pytest.mark.parametrize(
    "source,providers",
    [
        pytest.param(
            'import mutator\nfrom fastapi import FastAPI\napp=FastAPI(__name__)\n@app.post("/control/poweroff")\ndef poweroff():\n    return {"ok":True}\napp.run(host="0.0.0.0")\n',
            (
                (
                    "fastapi.py",
                    "class FastAPI:\n    def __init__(self,*args,**kwargs):\n        pass\n    def post(self,*args,**kwargs):\n        return lambda handler:handler\n",
                ),
                (
                    "mutator.py",
                    "from fastapi import FastAPI\nfrom flask import Flask\nFastAPI.__new__=staticmethod(lambda cls,*args,**kwargs: Flask(__name__))\n",
                ),
            ),
            id="imported-provider-replacement",
        ),
        pytest.param(
            'class FastAPI:\n    def __init__(self,*args,**kwargs):\n        pass\n    def post(self,*args,**kwargs):\n        return lambda handler:handler\n\nimport mutator\napp=FastAPI(__name__)\n@app.post("/control/poweroff")\ndef poweroff():\n    return {"ok": True}\napp.run(host="0.0.0.0")\n',
            (
                (
                    "mutator.py",
                    "import app\nfrom flask import Flask\napp.FastAPI.__new__=staticmethod(lambda cls,*args,**kwargs: Flask(__name__))\n",
                ),
            ),
            id="imported-inline-class-replacement",
        ),
    ],
)
def test_imported_project_effects_refute_inert_route_holder(
    tmp_path, monkeypatch, source, providers
):
    test_route_provider_negative_proof_survives_source_effect_checks(
        tmp_path, monkeypatch, source, providers, True
    )


def test_inert_root_class_does_not_prove_another_submodule_inert(tmp_path, monkeypatch):
    source, providers, _vulnerable = CASES[1].values
    source = source.replace("from fastapi import", "from fastapi.applications import")
    providers = (
        ("fastapi/__init__.py", providers[0][1]),
        ("fastapi/applications.py", "from flask import Flask as FastAPI\n"),
    )
    test_route_provider_negative_proof_survives_source_effect_checks(
        tmp_path, monkeypatch, source, providers, True
    )


def test_competing_compiled_package_refutes_inert_module_proof(tmp_path, monkeypatch):
    from importlib.machinery import EXTENSION_SUFFIXES

    source, providers, _vulnerable = CASES[1].values
    providers = (
        *providers,
        ("fastapi/__init__" + EXTENSION_SUFFIXES[0], "opaque extension"),
    )
    test_route_provider_negative_proof_survives_source_effect_checks(
        tmp_path, monkeypatch, source, providers, True
    )
