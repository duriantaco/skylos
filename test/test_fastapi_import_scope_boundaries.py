"""Nested imports must not create roots in a shadowed sibling package."""

import ast
import json
from types import SimpleNamespace

import pytest

from skylos.analyzer import Skylos
from skylos.deadcode import fastapi_liveness
from skylos.deadcode.fastapi_liveness import FastAPIAnalysisLimit, FastAPIProject


def _project(root, sources):
    parsed = []
    for name, source in sources.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        if path.suffix == ".py":
            parsed.append(SimpleNamespace(path=path, tree=ast.parse(source)))
    return FastAPIProject({}, parsed, root)


@pytest.mark.parametrize(
    "import_route",
    [
        "from app.routes import router\napp.include_router(router)\n",
        "import app.routes as api\napp.include_router(api.router)\n",
    ],
)
@pytest.mark.parametrize("conf", [0, 80])
@pytest.mark.parametrize("grep", [False, True])
def test_missing_nested_submodule_does_not_resolve_from_root_package(
    tmp_path, import_route, conf, grep
):
    project = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/routes.py": "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/')\ndef unrelated_route(): return 1\n",
            "backend/app/__init__.py": "",
            "backend/app/main.py": "from fastapi import FastAPI\n"
            "app = FastAPI()\n" + import_route,
        },
    )
    report = project.collect()
    route = (str((tmp_path / "app/routes.py").resolve()), 4)
    assert report.complete
    assert route in report.candidates
    assert route not in report.roots
    assert route not in report.uncertain
    result = json.loads(Skylos().analyze(str(tmp_path), thr=conf, grep_verify=grep))
    assert not result.get("analysis_errors")
    assert any(
        item["simple_name"] == "unrelated_route"
        for item in result.get("unused_functions", [])
    )


def test_possible_include_graph_honors_abstract_step_budget(tmp_path, monkeypatch):
    project = FastAPIProject({}, [], tmp_path)
    project.active_objects.add("app")
    project.possible_includes = [
        SimpleNamespace(
            receiver="app" if index == 0 else f"router_{index - 1}",
            child=f"router_{index}",
            owner=None,
            owner_key=None,
        )
        for index in reversed(range(20))
    ]
    monkeypatch.setattr(fastapi_liveness, "_MAX_ANALYSIS_STEPS", 10)
    with pytest.raises(FastAPIAnalysisLimit):
        project._possibly_included()
    assert not project.report.complete
    assert project.report.incomplete_reason == "abstract_step_budget"


def test_possible_include_graph_retains_cycles_and_rejects_uncalled_owner(tmp_path):
    project = FastAPIProject({}, [], tmp_path)
    project.active_objects.add("app")
    project.possible_includes = [
        SimpleNamespace(receiver=parent, child=child, owner=owner, owner_key=owner)
        for parent, child, owner in [
            ("second", "first", None),
            ("first", "second", None),
            ("app", "first", None),
            ("app", "orphan", "uncalled_factory"),
        ]
    ]
    project.includes["second"].add("unconditional_child")
    assert project._possibly_included() == {
        "first",
        "second",
        "unconditional_child",
    }
