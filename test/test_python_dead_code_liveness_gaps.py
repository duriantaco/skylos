"""Python dead-code liveness: registrations, forward references and documented
framework contracts must stay quiet; the lookalikes beside them must be reported."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import Skylos

ROUTES = (
    "from fastapi import APIRouter\n\nrouter = APIRouter()\n\n\n"
    "@router.get('/items')\nasync def list_items():\n    return []\n\n\n"
    "@router.websocket('/ws')\nasync def item_socket(websocket):\n"
    "    await websocket.accept()\n\n\n"
    "def orphan_helper():\n    return 2\n"
)


def _app(import_line):
    return (
        "from fastapi import FastAPI\n"
        + import_line
        + "\n\napplication = FastAPI()\napplication.include_router(items.router)\n"
    )


UNMOUNTED = (
    "from fastapi import APIRouter\n\nrouter = APIRouter()\n\n\n"
    "@router.get('/stale')\nasync def never_mounted():\n    return 1\n"
)

CASES = {
    "route_in_package_named_src": (
        {
            "src/__init__.py": "",
            "src/main.py": _app("from src.api import items"),
            "src/api/__init__.py": "",
            "src/api/items.py": ROUTES,
            "src/api/stale.py": UNMOUNTED,
        },
        {"unused_functions": {"orphan_helper", "never_mounted"}},
        {"list_items", "item_socket"},
    ),
    "route_in_package_named_lib": (
        {
            "lib/__init__.py": "",
            "lib/main.py": _app("from lib.api import items"),
            "lib/api/__init__.py": "",
            "lib/api/items.py": ROUTES,
        },
        {"unused_functions": {"orphan_helper"}},
        {"list_items", "item_socket"},
    ),
    "route_in_src_package_imported_without_prefix": (
        {
            "src/__init__.py": "",
            "src/pkg/__init__.py": "",
            "src/pkg/main.py": _app("from pkg.api import items"),
            "src/pkg/api/__init__.py": "",
            "src/pkg/api/items.py": ROUTES,
        },
        {"unused_functions": {"orphan_helper"}},
        {"list_items", "item_socket"},
    ),
    "route_in_src_namespace_directory": (
        {
            "src/main.py": _app("from src.api import items"),
            "src/api/items.py": ROUTES,
        },
        {"unused_functions": {"orphan_helper"}},
        {"list_items", "item_socket"},
    ),
    "src_import_does_not_resolve_to_unrelated_root_package": (
        {
            "src/__init__.py": "",
            "src/main.py": _app("from src.api import items"),
            "src/api/__init__.py": "",
            "api/__init__.py": "",
            "api/items.py": ROUTES,
        },
        {"unused_functions": {"orphan_helper", "list_items", "item_socket"}},
        set(),
    ),
    "project_decorator_applies_a_registration": (
        {
            "toolpkg/__init__.py": "",
            "toolpkg/server.py": "import functools\n\n"
            "from mcp.server.fastmcp import FastMCP\n\n"
            "mcp = FastMCP('demo')\n\n\n"
            "def _expose(fn):\n"
            "    @functools.wraps(fn)\n"
            "    def wrapper(*args, **kwargs):\n"
            "        return str(fn(*args, **kwargs))\n\n"
            "    return mcp.tool(name=fn.__name__)(wrapper)\n\n\n"
            "def _expose_inline(fn):\n"
            "    @mcp.tool(name=fn.__name__)\n"
            "    def wrapper(*args, **kwargs):\n"
            "        return str(fn(*args, **kwargs))\n\n"
            "    return wrapper\n\n\n"
            "def expose_as(label):\n"
            "    def decorate(fn):\n"
            "        return mcp.tool(name=label)(fn)\n\n"
            "    return decorate\n\n\n"
            "def _logged(fn):\n"
            "    @functools.wraps(fn)\n"
            "    def wrapper(*args, **kwargs):\n"
            "        return fn(*args, **kwargs)\n\n"
            "    return wrapper\n\n\n"
            "def _cached(fn):\n"
            "    return functools.lru_cache(maxsize=None)(fn)\n\n\n"
            "def _late(fn):\n"
            "    def wrapper(*args, **kwargs):\n"
            "        return mcp.tool(name='late')(fn)(*args, **kwargs)\n\n"
            "    return wrapper\n\n\n"
            "@_expose\ndef open_tab(url):\n    return url\n\n\n"
            "@_expose_inline\ndef close_tab(tab):\n    return tab\n\n\n"
            "@expose_as('reload')\ndef reload_tab(tab):\n    return tab\n\n\n"
            "@_logged\ndef unused_logged():\n    return 1\n\n\n"
            "@_cached\ndef unused_cached():\n    return 2\n\n\n"
            "@_late\ndef unused_late():\n    return 3\n\n\n"
            "@functools.lru_cache(maxsize=8)\ndef unused_lru():\n    return 4\n",
            "toolpkg/handlers.py": "from toolpkg.server import _logged, _expose\n\n\n"
            "@_expose\ndef remote_click(x, y):\n    return x + y\n\n\n"
            "@_logged\ndef unused_remote_logged():\n    return 0\n",
        },
        {
            "unused_functions": {
                "unused_logged",
                "unused_cached",
                "unused_late",
                "unused_lru",
                "unused_remote_logged",
            }
        },
        {"open_tab", "close_tab", "reload_tab", "remote_click"},
    ),
    "third_party_decorator_factory_with_a_key": (
        {
            "cfgpkg/__init__.py": "",
            "cfgpkg/wrappers.py": "import functools\n\n\n"
            "def labelled(label):\n"
            "    def decorate(fn):\n"
            "        @functools.wraps(fn)\n"
            "        def wrapper(*args, **kwargs):\n"
            "            return fn(*args, **kwargs)\n\n"
            "        return wrapper\n\n"
            "    return decorate\n",
            "cfgpkg/settings.py": "import functools\n\n"
            "import labkit\n"
            "from labkit.registry import GroupBase, provider\n"
            "from tenacity import retry, stop_after_attempt\n\n"
            "from cfgpkg.wrappers import labelled\n\n\n"
            "class Group(GroupBase):\n    model: str\n    loader: str\n\n\n"
            "@provider(Group.model)\ndef small_model(c):\n    return 'small'\n\n\n"
            "@labkit.registry.provider(Group.loader, 'fast')\n"
            "def _fast_loader(c):\n    return 'fast'\n\n\n"
            "@Group.derive(Group.loader)\ndef computed_loader(c):\n    return 1\n\n\n"
            "@retry(stop=stop_after_attempt(3))\ndef unused_retried():\n    return 1\n\n\n"
            "@functools.lru_cache(maxsize=4)\ndef unused_cached():\n    return 2\n\n\n"
            "@labelled('x')\ndef unused_labelled():\n    return 3\n\n\n"
            "@labkit.traced\ndef unused_bare_external():\n    return 4\n\n\n"
            "@labkit.timer()\ndef unused_empty_call():\n    return 5\n",
        },
        {
            "unused_functions": {
                "unused_retried",
                "unused_cached",
                "unused_labelled",
                "unused_bare_external",
                "unused_empty_call",
            }
        },
        {"small_model", "_fast_loader", "computed_loader"},
    ),
    "string_forward_references": (
        {
            "shapes/__init__.py": "",
            "shapes/types.py": "from typing import TYPE_CHECKING, TypedDict, TypeVar, Union\n\n"
            "if TYPE_CHECKING:\n"
            "    from _typeshed import DataclassInstance\n"
            "    from decimal import Decimal\n"
            "    from fractions import Fraction\n\n"
            "T = TypeVar('T', bound='DataclassInstance')\n"
            "ItemData = Union['StandardData', 'RadioData']\n\n\n"
            "class Item(TypedDict):\n    data: 'ItemData'\n\n\n"
            "class StandardData(TypedDict):\n    name: str\n\n\n"
            "class RadioData(TypedDict):\n    options: list\n\n\n"
            "class OrphanData(TypedDict):\n    unused: int\n\n\n"
            "class LegacyData(TypedDict):\n    old: int\n\n\n"
            "def describe(item: Item) -> str:\n"
            "    print('LegacyData was removed in 2.0')\n"
            "    print('Fraction of items shown')\n"
            "    return str(item)\n\n\n"
            "def clone(instance: T) -> T:\n    return instance\n",
            "shapes/main.py": "from shapes.types import clone, describe\n\n"
            "print(describe({}), clone(2))\n",
        },
        {
            "unused_classes": {"OrphanData", "LegacyData"},
            "unused_imports": {"Decimal", "Fraction"},
        },
        {"StandardData", "RadioData", "DataclassInstance", "ItemData"},
    ),
    "class_named_by_dotted_path_in_a_used_registry": (
        {
            "plugpkg/__init__.py": "",
            "plugpkg/models/__init__.py": "import importlib\n\n"
            "MODEL_CLASSES = {\n"
            "    'alpha': 'plugpkg.models.alpha_model.AlphaModel',\n"
            "    'gone': 'retired.models.gamma_model.GammaModel',\n"
            "}\n"
            "UNUSED_CLASSES = {'delta': 'plugpkg.models.delta_model.DeltaModel'}\n\n\n"
            "def get_model_class(spec):\n"
            "    full_path = MODEL_CLASSES.get(spec, spec)\n"
            "    module_name, class_name = full_path.rsplit('.', 1)\n"
            "    module = importlib.import_module(module_name)\n"
            "    return getattr(module, class_name)\n",
            "plugpkg/models/alpha_model.py": "class AlphaModel:\n    pass\n\n\n"
            "class AlphaLeftover:\n    pass\n",
            "plugpkg/models/gamma_model.py": "class GammaModel:\n    pass\n",
            "plugpkg/models/delta_model.py": "class DeltaModel:\n    pass\n",
            "plugpkg/__main__.py": "from plugpkg.models import get_model_class\n\n"
            "print(get_model_class('alpha')())\n",
        },
        {"unused_classes": {"AlphaLeftover", "GammaModel", "DeltaModel"}},
        {"AlphaModel"},
    ),
    "local_import_rebinding_a_parameter": (
        {
            "netpkg/__init__.py": "",
            "netpkg/skills.py": "def recommend(task):\n    return task\n\n\n"
            "def pick_unused(task):\n    return task\n\n\n"
            "def pick_shadowed(task):\n    return task\n",
            "netpkg/transit.py": "import bisect\nimport readline\n\n\n"
            "class Transit:\n"
            "    def __init__(self, reactor=None):\n"
            "        if reactor is None:\n"
            "            from twisted.internet import reactor\n"
            "        self._reactor = reactor\n\n\n"
            "def route(task, recommend_fn=None):\n"
            "    if recommend_fn is None:\n"
            "        from netpkg.skills import recommend as recommend_fn\n"
            "    return recommend_fn(task)\n\n\n"
            "def stale(task, picker=None):\n"
            "    if picker is None:\n"
            "        from netpkg.skills import pick_unused\n"
            "    return input(task)\n\n\n"
            "def shadowed(task, chooser=None):\n"
            "    if chooser is None:\n"
            "        from netpkg.skills import pick_shadowed as chooser\n"
            "    chooser = len\n"
            "    return chooser(task)\n",
            "netpkg/__main__.py": "from netpkg.transit import Transit, route, shadowed, stale\n\n"
            "print(Transit(), route('a'), stale('b'), shadowed('c'))\n",
        },
        {"unused_imports": {"pick_unused", "pick_shadowed", "bisect"}},
        {"reactor", "recommend", "readline"},
    ),
    "members_read_by_a_documented_base_class": (
        {
            "webpkg/__init__.py": "",
            "webpkg/site.py": "from twisted.web import resource\n\n\n"
            "class Status(resource.Resource):\n"
            "    def render_GET(self, request):\n        return b'ok'\n\n"
            "    def render_page(self, request):\n        return b'never'\n\n\n"
            "print(Status())\n",
            "webpkg/commands.py": "def build_cmdclass():\n"
            "    from setuptools import Command\n\n"
            "    class cmd_report(Command):\n"
            "        description = 'report'\n"
            "        boolean_options: list[str] = []\n"
            "        scratch_values: list[str] = []\n\n"
            "        def initialize_options(self):\n            pass\n\n"
            "        def finalize_options(self):\n            pass\n\n"
            "        def run(self):\n            print('report')\n\n"
            "    return {'report': cmd_report}\n\n\n"
            "print(build_cmdclass())\n",
            "webpkg/settings.py": "from pydantic_settings import BaseSettings\n\n\n"
            "class Settings(BaseSettings):\n"
            "    debug: bool = False\n\n"
            "    class Config:\n        env_file = '.env'\n\n"
            "    class Options:\n        verbose = True\n\n\n"
            "print(Settings())\n",
            "webpkg/plain.py": "class NotACommand:\n"
            "    negative_opt: dict = {}\n\n\n"
            "class Holder:\n"
            "    class Config:\n        env_file = '.env'\n\n\n"
            "print(NotACommand(), Holder())\n",
        },
        {
            "unused_functions": {"render_page"},
            "unused_variables": {"scratch_values", "negative_opt"},
            "unused_classes": {"Options", "plain.py:Config"},
        },
        {"render_GET", "description", "boolean_options", "settings.py:Config"},
    ),
    "namespace_handed_to_exec": (
        {
            "runpkg/__init__.py": "",
            "runpkg/admin.py": "def list_profiles():\n    return []\n\n\n"
            "def stop_daemon():\n    return True\n",
            "runpkg/recorder.py": "def recording_dir():\n    return 'rec'\n",
            "runpkg/helpers.py": "from .recorder import recording_dir\n",
            "runpkg/run.py": "import sys\n\n"
            "from .admin import list_profiles\n"
            "from .helpers import *\n\n\n"
            "def main():\n    exec(sys.stdin.read(), globals())\n",
            "runpkg/sandbox.py": "import bisect\nimport sys\n\n"
            "from .admin import stop_daemon\n\n\n"
            "def main():\n"
            "    exec(sys.stdin.read(), {})\n"
            "    return eval(sys.stdin.read(), {'__builtins__': {}})\n",
            "runpkg/__main__.py": "from runpkg import run, sandbox\n\n"
            "run.main()\nsandbox.main()\n",
        },
        {"unused_imports": {"stop_daemon", "bisect"}},
        {"list_profiles", "recording_dir"},
    ),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_live_shapes_stay_quiet_and_lookalikes_are_reported(tmp_path, case):
    sources, reported, live = CASES[case]
    for name, source in sources.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    result = json.loads(Skylos().analyze(str(tmp_path), thr=0, grep_verify=False))
    assert not result.get("analysis_errors")
    listed = set()
    for section in (
        "unused_functions",
        "unused_classes",
        "unused_imports",
        "unused_variables",
    ):
        names = set()
        for item in result.get(section, []):
            names.add(item["simple_name"])
            names.add(f"{Path(item['file']).name}:{item['simple_name']}")
        assert reported.get(section, set()) <= names
        listed |= names
    assert not (live & listed)
