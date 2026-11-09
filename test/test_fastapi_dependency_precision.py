"""Dependency contracts follow real FastAPI providers and selected consumers."""

import json

import pytest

from skylos.analyzer import analyze


def _scan(root, sources, conf=0, grep_verify=False):
    for name, source in sources.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    result = json.loads(analyze(str(root), conf=conf, grep_verify=grep_verify))
    assert not result.get("analysis_errors")
    return result


def _parameters(result):
    return {finding["full_name"] for finding in result.get("unused_parameters", [])}


def _symbol(result, name):
    return next(
        item
        for item in result["dead_code_evidence"]["symbols"]
        if item["qualified_name"] == name
    )


ROUTE = """from fastapi import FastAPI
{imports}
app = FastAPI()
@app.get('/')
def endpoint(
    *,
    credential: {annotation},
    ignored_flag: bool = False,
):
    return {{}}
def unrelated_neighbor(): return 2
"""
DEPS = """from typing import Annotated
from fastapi import Depends
def guard(): return guard_helper()
def guard_helper(): return 1
CurrentUser = Annotated[int, Depends(guard)]
"""


@pytest.mark.parametrize(
    "imports,annotation,extra",
    [
        ("from app.deps import CurrentUser", "CurrentUser", {}),
        ("from app.deps import CurrentUser as UserAlias", "UserAlias", {}),
        ("import app.deps as deps", "deps.CurrentUser", {}),
        (
            "from app.bridge import Authenticated",
            "Authenticated",
            {"app/bridge.py": "from app.deps import CurrentUser as Authenticated\n"},
        ),
    ],
    ids=["named", "renamed", "qualified", "reexported"],
)
def test_dependency_annotation_aliases_keep_only_injected_parameter(
    tmp_path, imports, annotation, extra
):
    sources = {
        "app/__init__.py": "",
        "app/deps.py": DEPS,
        "app/routes.py": ROUTE.format(imports=imports, annotation=annotation),
        **extra,
    }
    result = _scan(tmp_path, sources)
    unused = _parameters(result)
    assert "app.routes.endpoint.credential" not in unused
    assert "app.routes.endpoint.ignored_flag" in unused


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "setup,marker",
    [
        ("def Depends(dependency): return 0\n", "Depends"),
        (
            "from fastapi import Depends\n"
            "def ordinary_marker(dependency): return 0\n"
            "Depends = ordinary_marker\n",
            "Depends",
        ),
        (
            "class Markers:\n"
            "    @staticmethod\n"
            "    def Security(dependency): return 0\n",
            "Markers.Security",
        ),
    ],
    ids=["local-name", "replaced-import", "attribute-lookalike"],
)
def test_lookalike_dependency_marker_does_not_hide_ordinary_route_parameter(
    tmp_path, setup, marker, grep_verify
):
    source = (
        "from typing import Annotated\nfrom fastapi import FastAPI\n"
        + setup
        + "def guard(): return 1\napp = FastAPI()\n"
        "@app.get('/')\n"
        "def endpoint(\n    *,\n    credential: Annotated[int, "
        + marker
        + "(guard)],\n):\n    return {}\n"
    )
    result = _scan(tmp_path, {"main.py": source}, grep_verify=grep_verify)
    assert "main.endpoint.credential" in _parameters(result)
    assert not any(
        item["kind"] == "framework_root"
        for item in _symbol(result, "main.guard")["evidence"]
    )


@pytest.mark.parametrize("grep_verify", [False, True])
def test_an_unrelated_same_named_annotation_is_not_an_injected_parameter(
    tmp_path, grep_verify
):
    result = _scan(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/deps.py": DEPS,
            "app/plain_types.py": "CurrentUser = int\n",
            "app/routes.py": ROUTE.format(
                imports="from app.plain_types import CurrentUser",
                annotation="CurrentUser",
            ),
        },
        grep_verify=grep_verify,
    )
    assert "app.routes.endpoint.credential" in _parameters(result)


@pytest.mark.parametrize("grep_verify", [False, True])
def test_depends_in_an_ordinary_called_function_does_not_inject(tmp_path, grep_verify):
    result = _scan(
        tmp_path,
        {
            "main.py": "from typing import Annotated\nfrom fastapi import Depends\n"
            "def guard(): return 1\n"
            "def ordinary(\n    *,\n    credential: Annotated[int, Depends(guard)],\n):\n"
            "    return 1\nordinary(credential=1)\n"
        },
        grep_verify=grep_verify,
    )
    assert "main.ordinary.credential" in _parameters(result)


@pytest.mark.parametrize("conf", [0, 80])
def test_callable_instance_dependency_reaches_its_selected_call_body(tmp_path, conf):
    result = _scan(
        tmp_path,
        {
            "main.py": "from typing import Annotated\nfrom fastapi import FastAPI, Depends\n"
            "class Checker:\n"
            "    def __call__(self): return guard_helper()\n"
            "def guard_helper(): return 1\n"
            "def unrelated_neighbor(): return 2\n"
            "checker = Checker()\napp = FastAPI()\n"
            "@app.get('/')\n"
            "def endpoint(\n    credential: Annotated[int, Depends(checker)],\n):\n"
            "    return {}\n"
        },
        conf=conf,
    )
    assert _symbol(result, "main.guard_helper")["classification"] == "alive"
    assert "main.endpoint.credential" not in _parameters(result)
    assert any(
        item["full_name"] == "main.unrelated_neighbor"
        for item in result.get("unused_functions", [])
    )


def test_class_shortcut_processes_dependencies_in_its_constructor(tmp_path):
    result = _scan(
        tmp_path,
        {
            "main.py": "from typing import Annotated\nfrom fastapi import FastAPI, Depends\n"
            "def inner(): return 1\n"
            "class Provider:\n"
            "    def __init__(\n        self,\n        credential: Annotated[int, Depends(inner)],\n    ):\n"
            "        pass\n"
            "app = FastAPI()\n@app.get('/')\n"
            "def endpoint(\n    service: Annotated[Provider, Depends()],\n):\n    return {}\n"
        },
    )
    unused = _parameters(result)
    assert "main.endpoint.service" not in unused
    assert "main.Provider.__init__.credential" not in unused


def test_imported_provider_aliases_on_a_standalone_router_keep_parameter_contracts(
    tmp_path,
):
    result = _scan(
        tmp_path,
        {
            "main.py": "from typing_extensions import Annotated as Metadata\n"
            "from fastapi import APIRouter as Router, Security as Auth\n"
            "def guard(): return 1\nrouter = Router()\n@router.get('/')\n"
            "def endpoint(\n    credential: Metadata[int, Auth(guard, scopes=['read'])],\n"
            "    ignored_flag: bool = False,\n):\n    return {}\n"
        },
    )
    assert "main.endpoint.credential" not in _parameters(result)
    assert "main.endpoint.ignored_flag" in _parameters(result)
    assert not any(
        item["kind"] in {"framework_root", "top_level_execution"}
        for item in _symbol(result, "main.guard")["evidence"]
    )


@pytest.mark.parametrize(
    "setup,annotation",
    [
        (
            "class Annotated:\n"
            "    @classmethod\n"
            "    def __class_getitem__(cls, metadata): return int\n",
            "Annotated[int, Depends(guard)]",
        ),
        (
            "from typing import Annotated\n",
            "Annotated[int, {'ordinary': Depends(guard)}]",
        ),
        (
            "from typing import Annotated\nfrom fastapi import Query\n",
            "Annotated[int, Depends(guard), Query()]",
        ),
    ],
    ids=["local-annotated", "nested-ordinary-metadata", "query-selected-last"],
)
def test_only_actual_selected_annotated_metadata_injects(tmp_path, setup, annotation):
    source = "from fastapi import FastAPI, Depends\n" + setup
    source += "def guard(): return 1\napp = FastAPI()\n@app.get('/')\n"
    source += "def endpoint(\n    credential: " + annotation + ",\n):\n    return {}\n"
    result = _scan(tmp_path, {"main.py": source})
    assert "main.endpoint.credential" in _parameters(result)


def test_transformed_dependency_does_not_prove_the_original_body_runs(tmp_path):
    result = _scan(
        tmp_path,
        {
            "main.py": "from fastapi import FastAPI, Depends\n"
            "def erase(callback):\n"
            "    def replacement(): return 1\n"
            "    return replacement\n"
            "@erase\ndef guard(): return guard_helper()\n"
            "def guard_helper(): return 1\n"
            "app = FastAPI()\n@app.get('/')\n"
            "def endpoint(\n    credential=Depends(guard),\n):\n    return {}\n"
        },
    )
    kinds = {item["kind"] for item in _symbol(result, "main.guard")["evidence"]}
    assert "framework_root" not in kinds
    assert "top_level_execution" not in kinds


@pytest.mark.parametrize("called_owner", [True, False])
def test_possible_route_registration_keeps_only_possible_dependency_contracts(
    tmp_path, called_owner
):
    source = "from fastapi import FastAPI, Depends\napp = FastAPI()\n"
    source += "def dependency(): return 1\n"
    source += "def endpoint(\n    value=Depends(dependency),\n):\n    return 1\n"
    if called_owner:
        source += "for path in ('/a', '/b'):\n    app.add_api_route(path, endpoint)\n"
    else:
        source += "def unused_setup():\n    for path in ('/a', '/b'):\n        app.add_api_route(path, endpoint)\n"
    result = _scan(tmp_path, {"main.py": source})
    if called_owner:
        assert "main.endpoint.value" not in _parameters(result)
    else:
        assert any(
            item["full_name"] == "main.endpoint"
            for item in result.get("unused_functions", [])
        )
    assert not any(
        item["kind"] == "framework_root"
        for item in _symbol(result, "main.dependency")["evidence"]
    )


@pytest.mark.parametrize("conf", [0, 80])
def test_unused_dependency_alias_does_not_prove_its_callback_executed(tmp_path, conf):
    result = _scan(tmp_path, {"main.py": DEPS}, conf=conf)
    kinds = {item["kind"] for item in _symbol(result, "main.guard")["evidence"]}
    assert "top_level_execution" not in kinds
    assert "framework_root" not in kinds


@pytest.mark.parametrize("scope", ["app", "router", "route", "include"])
def test_explicit_dependency_lists_keep_actual_callbacks(tmp_path, scope):
    source = "from fastapi import FastAPI, APIRouter, Depends\n"
    source += "def guard(): return guard_helper()\ndef guard_helper(): return 1\n"
    source += "def unrelated_neighbor(): return 2\n"
    arguments = "dependencies=[Depends(guard)]"
    source += "app = FastAPI(" + (arguments if scope == "app" else "") + ")\n"
    source += "router = APIRouter(" + (arguments if scope == "router" else "") + ")\n"
    source += "@router.get('/'" + (", " + arguments if scope == "route" else "") + ")\n"
    source += "def endpoint(): return {}\n"
    source += (
        "app.include_router(router"
        + (", " + arguments if scope == "include" else "")
        + ")\n"
    )
    result = _scan(tmp_path, {"main.py": source})
    assert _symbol(result, "main.guard_helper")["classification"] == "alive"


def test_empty_router_diamonds_and_cycles_do_not_invent_dependency_execution(tmp_path):
    source = "from fastapi import FastAPI, APIRouter, Depends\n"
    source += "def guard(): return 1\napp = FastAPI(dependencies=[Depends(guard)])\n"
    for layer in range(12):
        for side in ("left", "right"):
            source += side + str(layer) + " = APIRouter()\n"
    for layer in range(11):
        for side in ("left", "right"):
            for child in ("left", "right"):
                source += (
                    side
                    + str(layer)
                    + ".include_router("
                    + child
                    + str(layer + 1)
                    + ")\n"
                )
    source += "left11.include_router(right11)\nright11.include_router(left11)\n"
    source += "app.include_router(left0)\napp.include_router(right0)\n"
    result = _scan(tmp_path, {"main.py": source})
    assert not any(
        item["kind"] == "framework_root"
        for item in _symbol(result, "main.guard")["evidence"]
    )


@pytest.mark.parametrize(
    ("imports", "parameter"),
    [
        ("from fastapi import *", "credential=Depends(guard)"),
        (
            "from typing import *\nfrom fastapi import FastAPI, Depends",
            "credential: Annotated[int, Depends(guard)]",
        ),
    ],
)
def test_existing_wildcard_imports_keep_dependency_parameters(
    tmp_path, imports, parameter
):
    from skylos.analyzer import Skylos

    (tmp_path / "app.py").write_text(
        imports + "\napp=FastAPI()\ndef guard(): return True\n"
        "@app.get('/')\ndef endpoint(\n    " + parameter + ",\n): return 1\n",
        encoding="utf-8",
    )
    analyzer = Skylos()
    result = json.loads(analyzer.analyze(str(tmp_path), thr=0, grep_verify=False))
    assert not result.get("analysis_errors")
    assert "app.endpoint.credential" not in {
        item["full_name"] for item in result.get("unused_parameters", [])
    }
    assert analyzer.defs["app.guard"].heuristic_refs.get("framework_root") == 1.0
