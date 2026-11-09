"""FastAPI execution roots require actual providers and active app connections."""

import ast
import json
from types import SimpleNamespace

import pytest

from skylos.analyzer import Skylos

HELPS = "def helper():\n    return 1\ndef dead_neighbor():\n    return 2\n"
CASES = {
    "real_app_decorator": (
        {
            "app.py": "from fastapi import FastAPI\napp = FastAPI()\n"
            + HELPS
            + "@app.get('/')\ndef endpoint():\n    return helper()\n"
        },
        True,
    ),
    "included_router": (
        {
            "app.py": "from fastapi import FastAPI, APIRouter\napp = FastAPI()\nrouter = APIRouter()\n"
            + HELPS
            + "@router.get('/')\ndef endpoint():\n    return helper()\napp.include_router(router)\n"
        },
        True,
    ),
    "unincluded_router": (
        {
            "app.py": "from fastapi import FastAPI, APIRouter\napp = FastAPI()\nrouter = APIRouter()\n"
            + HELPS
            + "@router.get('/')\ndef endpoint():\n    return helper()\n"
        },
        False,
    ),
    "dead_app_factory": (
        {
            "app.py": "from fastapi import FastAPI\n"
            + HELPS
            + "def unused_factory():\n    app = FastAPI()\n    @app.get('/')\n    def endpoint():\n        return helper()\n    return app\n"
        },
        False,
    ),
    "called_app_factory": (
        {
            "app.py": "from fastapi import FastAPI\n"
            + HELPS
            + "def create_app():\n    app = FastAPI()\n    @app.get('/')\n    def endpoint():\n        return helper()\n    return app\napp = create_app()\n"
        },
        True,
    ),
    "fake_decorator_provider": (
        {
            "app.py": "from fastapi import FastAPI\nclass Fake:\n    def get(self, path):\n        return lambda f:f\napp = Fake()\n"
            + HELPS
            + "@app.get('/')\ndef endpoint():\n    return helper()\n"
        },
        False,
    ),
    "rebound_constructor": (
        {
            "app.py": "from fastapi import FastAPI\nclass Fake:\n    def get(self, path):\n        return lambda f:f\nFastAPI = Fake\napp = FastAPI()\n"
            + HELPS
            + "@app.get('/')\ndef endpoint():\n    return helper()\n"
        },
        False,
    ),
    "rebound_app": (
        {
            "app.py": "from fastapi import FastAPI\nclass Fake:\n    def get(self, path):\n        return lambda f:f\napp = FastAPI()\napp = Fake()\n"
            + HELPS
            + "@app.get('/')\ndef endpoint():\n    return helper()\n"
        },
        False,
    ),
    "real_imperative_route": (
        {
            "app.py": "from fastapi import FastAPI\napp = FastAPI()\n"
            + HELPS
            + "def endpoint():\n    return helper()\napp.add_api_route('/', endpoint, methods=['GET'])\n"
        },
        True,
    ),
    "dead_imperative_route_owner": (
        {
            "app.py": "from fastapi import FastAPI\napp = FastAPI()\n"
            + HELPS
            + "def endpoint():\n    return helper()\ndef unused_setup():\n    app.add_api_route('/', endpoint, methods=['GET'])\n"
        },
        False,
    ),
    "fake_imperative_route": (
        {
            "app.py": "from fastapi import FastAPI\nclass Fake:\n    def add_api_route(self, *args, **kwargs):\n        return None\napp = Fake()\n"
            + HELPS
            + "def endpoint():\n    return helper()\napp.add_api_route('/', endpoint, methods=['GET'])\n"
        },
        False,
    ),
    "included_websocket_router": (
        {
            "app.py": "from fastapi import FastAPI, APIRouter\napp = FastAPI()\nrouter = APIRouter()\n"
            + HELPS
            + "@router.websocket('/ws')\nasync def endpoint(socket):\n    return helper()\napp.include_router(router)\n"
        },
        True,
    ),
    "unincluded_websocket_router": (
        {
            "app.py": "from fastapi import FastAPI, APIRouter\napp = FastAPI()\nrouter = APIRouter()\n"
            + HELPS
            + "@router.websocket('/ws')\nasync def endpoint(socket):\n    return helper()\n"
        },
        False,
    ),
    "router_added_after_include": (
        {
            "app.py": "from fastapi import FastAPI, APIRouter\napp = FastAPI()\nrouter = APIRouter()\napp.include_router(router)\n"
            + HELPS
            + "@router.get('/')\ndef endpoint():\n    return helper()\n"
        },
        True,
    ),
    "imported_router_alias": (
        {
            "app.py": "from fastapi import FastAPI as Application\nfrom routes import api as resource_router\napp = Application()\napp.include_router(resource_router)\n",
            "routes.py": "from fastapi import APIRouter as Router\napi = Router()\n"
            + HELPS
            + "@api.get('/')\ndef endpoint():\n    return helper()\n",
        },
        True,
    ),
    "mounted_asgi_callback": (
        {
            "app.py": "from fastapi import FastAPI\napp = FastAPI()\n"
            + HELPS
            + "async def endpoint(scope, receive, send):\n    helper()\napp.mount('/sub', endpoint)\n"
        },
        True,
    ),
}


CASES.update(
    {
        "module_provider_alias": (
            {
                "app.py": "import fastapi as framework\napp = framework.FastAPI()\n"
                + HELPS
                + "@app.get('/')\ndef endpoint():\n    return helper()\n"
            },
            True,
        ),
        "nested_router_included_late": (
            {
                "app.py": "from fastapi import FastAPI, APIRouter\napp = FastAPI()\nouter = APIRouter()\ninner = APIRouter()\napp.include_router(outer)\n"
                + HELPS
                + "@inner.get('/')\ndef endpoint():\n    return helper()\nouter.include_router(inner)\n"
            },
            True,
        ),
        "called_registration_argument_wrapper": (
            {
                "app.py": "from fastapi import FastAPI, APIRouter\napp = FastAPI()\nrouter = APIRouter()\n"
                + HELPS
                + "def attach(target):\n    @target.get('/')\n    def endpoint():\n        return helper()\nattach(router)\napp.include_router(router)\n"
            },
            True,
        ),
        "subclass_classmethod_factory": (
            {
                "app.py": "from fastapi import FastAPI\nclass Application(FastAPI):\n    @classmethod\n    def build(cls):\n        return cls()\napp = Application.build()\n"
                + HELPS
                + "@app.get('/')\ndef endpoint():\n    return helper()\n"
            },
            True,
        ),
        "replaced_route_method": (
            {
                "app.py": "from fastapi import FastAPI\napp = FastAPI()\napp.get = lambda path: lambda callback: callback\n"
                + HELPS
                + "@app.get('/')\ndef endpoint():\n    return helper()\n"
            },
            False,
        ),
        "subclass_route_method_override": (
            {
                "app.py": "from fastapi import FastAPI\nclass Application(FastAPI):\n    def get(self, path):\n        return lambda callback: callback\napp = Application()\n"
                + HELPS
                + "@app.get('/')\ndef endpoint():\n    return helper()\n"
            },
            False,
        ),
    }
)


_IMPERATIVE_BASE = (
    "from fastapi import FastAPI\napp = FastAPI()\n"
    + HELPS
    + "def endpoint():\n    return helper()\n"
)
for _name, _expression, _active in (
    ("uncalled_lambda", "unused = lambda: app.add_api_route('/', endpoint)", False),
    ("false_and_registration", "False and app.add_api_route('/', endpoint)", False),
    ("true_or_registration", "True or app.add_api_route('/', endpoint)", False),
    (
        "false_conditional_expression",
        "app.add_api_route('/', endpoint) if False else None",
        False,
    ),
    (
        "unconsumed_generator",
        "unused = (app.add_api_route('/', endpoint) for _ in [1])",
        False,
    ),
    (
        "empty_list_comprehension",
        "unused = [app.add_api_route('/', endpoint) for _ in []]",
        False,
    ),
    ("called_lambda", "(lambda: app.add_api_route('/', endpoint))()", True),
    ("true_and_registration", "True and app.add_api_route('/', endpoint)", True),
):
    CASES[_name] = ({"app.py": _IMPERATIVE_BASE + _expression + "\n"}, _active)

_ERASER_BASE = (
    "from fastapi import FastAPI\napp = FastAPI()\n"
    "def erase(callback):\n    return lambda: None\n" + HELPS
)
CASES["conventional_deployment_factory"] = (
    {
        "app.py": "from fastapi import FastAPI\n"
        + HELPS
        + "def create_app():\n    app = FastAPI()\n    @app.get('/')\n    def endpoint():\n        return helper()\n    return app\n"
    },
    False,
)
CASES["erasing_inner_decorator"] = (
    {
        "app.py": _ERASER_BASE
        + "@app.get('/')\n@erase\ndef endpoint():\n    return helper()\n"
    },
    False,
)
CASES["erasing_outer_decorator"] = (
    {
        "app.py": _ERASER_BASE
        + "@erase\n@app.get('/')\ndef endpoint():\n    return helper()\n"
    },
    True,
)


@pytest.mark.parametrize("case", sorted(CASES))
@pytest.mark.parametrize("conf", [0, 80])
@pytest.mark.parametrize("grep", [False, True])
def test_fastapi_routes_need_real_executing_registration(tmp_path, case, conf, grep):
    sources, active = CASES[case]
    for name, source in sources.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    analyzer = Skylos()
    result = json.loads(analyzer.analyze(str(tmp_path), thr=conf, grep_verify=grep))
    assert not result.get("analysis_errors")
    endpoints = [
        definition
        for definition in analyzer.defs.values()
        if definition.type == "function" and definition.simple_name == "endpoint"
    ]
    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert bool(endpoint.heuristic_refs.get("framework_root")) is active
    unused = {item["full_name"] for item in result.get("unused_functions", [])}
    assert any(name.endswith(".dead_neighbor") for name in unused)
    if active:
        assert endpoint.name not in unused
        assert not any(name.endswith(".helper") for name in unused)
    elif case == "conventional_deployment_factory":
        assert not any(name.endswith(".helper") for name in unused)
    elif case in {
        "unincluded_router",
        "unincluded_websocket_router",
        "dead_app_factory",
        "dead_imperative_route_owner",
    }:
        assert any(name.endswith(".helper") for name in unused)


def _bounded_wrapper_source(depth):
    source = (
        "from fastapi import FastAPI, APIRouter\nfrom flask import Flask\n"
        "app = FastAPI()\nrouter = APIRouter()\nforeign = Flask(__name__)\n"
        "@app.get('/live')\ndef real_route(): return 1\n"
        "@router.get('/orphan')\ndef orphan_route(): return 2\n"
        "@foreign.get('/foreign')\ndef foreign_route(): return 3\n"
        "def step0(): return None\n"
    )
    for level in range(1, depth + 1):
        source += f"def step{level}():\n    step{level - 1}()\n    step{level - 1}()\n"
    return source + f"step{depth}()\n"


def test_abstract_call_budget_bounds_acyclic_source_expansion(tmp_path, monkeypatch):
    from skylos.deadcode import fastapi_liveness as fastapi
    from skylos.deadcode.python_ast import ParsedPythonFile

    monkeypatch.setattr(fastapi, "_MAX_ANALYSIS_STEPS", 100_000)
    monkeypatch.setattr(fastapi, "_MAX_CALL_EVENTS", 40)
    path = tmp_path / "app.py"
    source = _bounded_wrapper_source(12)
    path.write_text(source)
    tree = ast.parse(source)
    definitions = {
        node.name: SimpleNamespace(
            filename=path,
            line=node.lineno,
            name="app." + node.name,
            type="function",
            node=node,
        )
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }

    report = fastapi.collect_fastapi_liveness(
        definitions, [ParsedPythonFile(path, tree)], tmp_path
    )

    assert not report.complete
    assert report.incomplete_reason == "call_event_budget"
    assert len(report.project.calls) <= 40
    assert not report.roots
    assert not report.callback_parameters
    assert not report.injected_parameters


def test_incomplete_fastapi_proofs_preserve_all_legacy_hints(tmp_path, monkeypatch):
    from skylos.deadcode import fastapi_liveness as fastapi

    monkeypatch.setattr(fastapi, "_MAX_ANALYSIS_STEPS", 200)
    (tmp_path / "app.py").write_text(_bounded_wrapper_source(10))
    analyzer = Skylos()

    result = json.loads(analyzer.analyze(str(tmp_path), thr=80, grep_verify=False))

    assert not result.get("analysis_errors")
    report = analyzer._fastapi_liveness_report
    assert not report.complete
    assert report.incomplete_reason
    assert not report.roots
    unused = {item["full_name"] for item in result.get("unused_functions", [])}
    definitions = {item.name: item for item in analyzer.defs.values()}
    for name in ("app.real_route", "app.orphan_route", "app.foreign_route"):
        assert definitions[name].heuristic_refs.get("framework_root") == 1.0
        assert not getattr(definitions[name], "_fastapi_inactive", False)
        assert name not in unused
