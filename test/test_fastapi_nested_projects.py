"""FastAPI routes in nested projects resolve imports from the project's own root."""

import json

import pytest

from skylos.analyzer import Skylos
from skylos.deadcode.python_import_roots import PythonImportRoots

WORKSPACE = '[tool.uv.workspace]\nmembers = ["backend"]\n'
MEMBER = '[project]\nname = "app"\nversion = "0.1.0"\n'
ROUTER = "from fastapi import APIRouter\n\nrouter = APIRouter()\n\n\n"
APP = "from fastapi import FastAPI\n\n"


def _route(name):
    return ROUTER + f"@router.get('/{name}')\ndef {name}():\n    return 1\n"


CASES = {
    "uv_member_included": (
        {
            "pyproject.toml": WORKSPACE,
            "backend/pyproject.toml": MEMBER,
            "backend/app/__init__.py": "",
            "backend/app/main.py": APP
            + "from app.api.main import api_router\n\napp = FastAPI()\n"
            "app.include_router(api_router)\n",
            "backend/app/api/__init__.py": "",
            "backend/app/api/main.py": "from fastapi import APIRouter\n\n"
            "from app.api.routes import items\n\napi_router = APIRouter()\n"
            "api_router.include_router(items.router)\n",
            "backend/app/api/routes/__init__.py": "",
            "backend/app/api/routes/items.py": _route("read_items")
            + "\n\ndef stale_helper():\n    return 2\n",
        },
        {"stale_helper"},
        {"read_items"},
    ),
    "requirements_service_package": (
        {
            "services/api/requirements.txt": "fastapi\n",
            "services/api/app/__init__.py": "",
            "services/api/app/main.py": APP
            + "from app.routes import router\n\napp = FastAPI()\n"
            "app.include_router(router)\n",
            "services/api/app/routes.py": _route("create_order"),
        },
        set(),
        {"create_order"},
    ),
    "src_layout_member": (
        {
            "pyproject.toml": WORKSPACE.replace("backend", "packages/api"),
            "packages/api/pyproject.toml": MEMBER,
            "packages/api/src/api_app/__init__.py": "",
            "packages/api/src/api_app/main.py": APP
            + "from api_app.routes import router\n\napp = FastAPI()\n"
            "app.include_router(router)\n",
            "packages/api/src/api_app/routes.py": _route("list_orders"),
        },
        set(),
        {"list_orders"},
    ),
    "nested_router_never_included": (
        {
            "pyproject.toml": WORKSPACE,
            "backend/pyproject.toml": MEMBER,
            "backend/app/__init__.py": "",
            "backend/app/main.py": APP
            + "from app.api import router\n\napp = FastAPI()\n",
            "backend/app/api.py": _route("orphan_route"),
        },
        {"orphan_route"},
        set(),
    ),
    "same_package_in_two_projects": (
        {
            "svc_a/pyproject.toml": MEMBER,
            "svc_a/app/__init__.py": "",
            "svc_a/app/main.py": APP
            + "from app.routes import router\n\napp = FastAPI()\n"
            "app.include_router(router)\n",
            "svc_a/app/routes.py": _route("route_a"),
            "svc_b/pyproject.toml": MEMBER,
            "svc_b/app/__init__.py": "",
            "svc_b/app/main.py": APP
            + "from app.routes import router\n\napp = FastAPI()\n",
            "svc_b/app/routes.py": _route("route_b"),
        },
        {"route_b"},
        {"route_a"},
    ),
    "nested_package_shadows_root_package": (
        {
            "app/__init__.py": "",
            "app/routes.py": _route("root_route"),
            "backend/pyproject.toml": MEMBER,
            "backend/app/__init__.py": "",
            "backend/app/main.py": APP
            + "from app.routes import router\n\napp = FastAPI()\n"
            "app.include_router(router)\n",
            "backend/app/routes.py": _route("backend_route"),
        },
        {"root_route"},
        {"backend_route"},
    ),
    "tool_config_only_namespace_dir": (
        {
            "pyproject.toml": "[tool.ruff]\nline-length = 100\n",
            "backend/pyproject.toml": "[tool.ruff]\nline-length = 100\n",
            "backend/app/main.py": APP
            + "from app.routes import router\n\napp = FastAPI()\n"
            "app.include_router(router)\n",
            "backend/app/routes.py": _route("namespace_route"),
        },
        {"namespace_route"},
        set(),
    ),
    "project_without_its_own_package_import": (
        {
            "backend/pyproject.toml": MEMBER,
            "backend/app/__init__.py": "",
            "backend/app/main.py": APP
            + "from other.routes import router\n\napp = FastAPI()\n"
            "app.include_router(router)\n",
            "backend/app/routes.py": _route("unimported_route"),
            "worker/pyproject.toml": MEMBER,
            "worker/other/__init__.py": "",
            "worker/other/routes.py": "router = None\n",
        },
        {"unimported_route"},
        set(),
    ),
    "conditional_and_constant_false_includes": (
        {
            "pyproject.toml": WORKSPACE,
            "backend/pyproject.toml": MEMBER,
            "backend/app/__init__.py": "",
            "backend/app/settings.py": "import os\n\nENV = os.environ.get('ENV')\n",
            "backend/app/main.py": APP
            + "from app import settings\nfrom app.routes import dev, never\n\n"
            "app = FastAPI()\n"
            "if settings.ENV == 'development':\n"
            "    app.include_router(dev.router)\n"
            "if False:\n"
            "    app.include_router(never.router)\n",
            "backend/app/routes/__init__.py": "",
            "backend/app/routes/dev.py": _route("create_dev_user"),
            "backend/app/routes/never.py": _route("never_route"),
        },
        {"never_route"},
        {"create_dev_user"},
    ),
    "conditional_include_in_uncalled_factory": (
        {
            "app.py": "import os\n"
            + APP
            + "from fastapi import APIRouter\n\nrouter = APIRouter()\nserved = FastAPI()\n\n\n"
            "@served.get('/ok')\ndef served_route():\n    return 0\n\n\n"
            "@router.get('/x')\ndef factory_route():\n    return 1\n\n\n"
            "def unused_factory():\n"
            "    app = FastAPI()\n"
            "    if os.environ.get('X'):\n"
            "        app.include_router(router)\n"
            "    return app\n",
        },
        {"factory_route", "unused_factory"},
        {"served_route"},
    ),
}


@pytest.mark.parametrize("case", sorted(CASES))
@pytest.mark.parametrize("conf", [0, 80])
@pytest.mark.parametrize("grep", [False, True])
def test_nested_project_routes_follow_their_own_imports(tmp_path, case, conf, grep):
    sources, reported, live = CASES[case]
    for name, source in sources.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    analyzer = Skylos()
    result = json.loads(analyzer.analyze(str(tmp_path), thr=conf, grep_verify=grep))
    assert not result.get("analysis_errors")
    unused = {item["simple_name"] for item in result.get("unused_functions", [])}
    assert reported <= unused
    assert not (live & unused)


def test_import_roots_name_package_and_project_roots(tmp_path):
    files = {
        "backend/pyproject.toml": MEMBER,
        "backend/app/__init__.py": "",
        "backend/app/api.py": "",
        "packages/lib/pyproject.toml": "[build-system]\nrequires = []\n",
        "packages/lib/src/lib_pkg/__init__.py": "",
        "packages/lib/src/lib_pkg/core.py": "",
        "tools/pyproject.toml": "[tool.black]\nline-length = 88\n",
        "tools/scripts/run.py": "",
        "top.py": "",
    }
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    roots = PythonImportRoots(tmp_path)

    assert roots.aliases(tmp_path / "backend/app/api.py") == (
        ((tmp_path / "backend").resolve(), "app.api"),
    )
    assert {
        name
        for _root, name in roots.aliases(tmp_path / "packages/lib/src/lib_pkg/core.py")
    } == {"lib_pkg.core"}
    assert roots.aliases(tmp_path / "tools/scripts/run.py") == ()
    assert roots.aliases(tmp_path / "top.py") == ()
