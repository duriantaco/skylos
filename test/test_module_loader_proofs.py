"""Source-only loader contracts and finite discovery; fixture code never runs."""

import ast
import json
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from skylos.analyzer import analyze
from skylos.deadcode._reachability_bindings import ModuleInfo
from skylos.deadcode.module_loader_proofs import (
    ModuleExecutionProof,
    _loader_contract,
    _supplied_arguments,
)
from skylos.deadcode.python_project_sources import Function, ProjectSourceIndex, alternatives
from test.fixture_paths import write_fixture


_LOADER = """
import importlib.util
def load(path):
    spec = importlib.util.spec_from_file_location("extension", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
"""


def _contract(source):
    tree = ast.parse(textwrap.dedent(source))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
    return _loader_contract(
        Function(Path("/private/tmp/proof/loader.py"), function), tree
    )


def test_actual_file_loader_joins_path_spec_and_module():
    assert _contract(_LOADER) == ("path", True)


@pytest.mark.parametrize(
    "mutation",
    [
        "opaque(spec=spec)",
        "opaque(module=module)",
        'opaque(payload={"spec": spec})',
        "spec.loader = external_loader",
    ],
)
def test_escaped_or_replaced_spec_is_not_a_contract(mutation):
    source = _LOADER.replace(
        "    spec.loader.exec_module(module)",
        "    " + mutation + "\n    spec.loader.exec_module(module)",
    )
    assert _contract(source) is None


def test_metadata_without_execution_is_not_a_load():
    assert (
        _contract(_LOADER.replace("    spec.loader.exec_module(module)\n", "")) is None
    )


def test_execution_uses_the_module_created_from_that_spec():
    assert (
        _contract(_LOADER.replace("exec_module(module)", "exec_module(other_module)"))
        is None
    )


def test_first_return_controls_the_returned_module_proof():
    source = _LOADER.replace("    return module", "    return None\n    return module")
    assert _contract(source) == ("path", False)


def test_early_conditional_return_is_not_unconditional_execution():
    source = _LOADER.replace(
        "def load(path):", "def load(path):\n    if True:\n        return None"
    )
    assert _contract(source) is None


def test_provider_escape_before_execution_invalidates_contract():
    source = _LOADER.replace(
        "def load(path):", "def load(path):\n    opaque(provider=importlib)"
    )
    assert _contract(source) is None


def test_missing_required_argument_is_not_a_source_invocation():
    node = ast.parse("def load(path, required):\n    return path\n").body[0]
    function = Function(Path("/private/tmp/proof/loader.py"), node)
    assert _supplied_arguments(function, ["plugin.py"], {}) is None
    assert _supplied_arguments(function, ["plugin.py", "present"], {}) == {
        "path": "plugin.py",
        "required": "present",
    }


def test_parameter_shadowing_a_closure_variable_is_not_a_bound_receiver():
    node = ast.parse("def load(path):\n    return path\n").body[0]
    function = Function(
        Path("/private/tmp/proof/loader.py"), node, {"path": "outer.py"}
    )
    assert _supplied_arguments(function, ["plugin.py"], {}) == {"path": "plugin.py"}


def test_targeted_loader_query_is_not_starved_by_previous_startup_work(
    tmp_path, monkeypatch
):
    sources = {
        "loader.py": _LOADER,
        "app.py": """
            from pathlib import Path
            from loader import load
            def discover():
                load(Path(__file__).parent / "plugins" / "active.py")
        """,
        "plugins/active.py": "class Active:\n    pass\n",
    }
    modules = {}
    locations = {}
    candidates = {}
    for relative, source in sources.items():
        content = textwrap.dedent(source).lstrip()
        path = write_fixture(tmp_path, relative, content, overwrite=True)
        tree = ast.parse(content)
        name = relative.removesuffix(".py").replace("/", ".")
        modules[path] = ModuleInfo(path, tree, names={name})
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                key = name + "." + node.name
                locations[path, node.lineno] = key
                candidates[key] = SimpleNamespace(
                    node=node, filename=path, line=node.lineno
                )
    report = SimpleNamespace(
        index=SimpleNamespace(
            modules=modules, by_location=locations, candidates=candidates
        ),
        project_root=tmp_path,
        proven_reachable_keys={"app.discover"},
    )
    proof = ModuleExecutionProof(report)
    proof.index.total_steps = 1_000_001
    monkeypatch.setattr(proof.index, "contexts", lambda: iter(()))
    proof.collect({"app.discover"})
    assert tmp_path / "plugins" / "active.py" in proof.loaded


@pytest.mark.parametrize("enabled", [None, False, True])
def test_html_augmented_addition_keeps_finite_branch_values(tmp_path, enabled):
    source = '''
def render(enabled):
    html = "<ul>"
    checked = " checked" if enabled else ""
    html += '<li onclick="toggle_entry()"' + checked + "></li>"
    return html
'''
    path = write_fixture(tmp_path, "renderer.py", source, overwrite=True)
    index = ProjectSourceIndex(tmp_path, [path])
    value = index.call(index.global_value(path, "render"), [enabled], {})
    expected = set()
    if enabled is not True:
        expected.add('<ul><li onclick="toggle_entry()"></li>')
    if enabled is not False:
        expected.add('<ul><li onclick="toggle_entry()" checked></li>')
    assert set(alternatives(value)) == expected


def test_html_augmented_addition_does_not_coerce_an_unknown_operand(tmp_path):
    source = '''
def render(value):
    html = "<ul>"
    html += value
    return html
'''
    path = write_fixture(tmp_path, "renderer.py", source, overwrite=True)
    index = ProjectSourceIndex(tmp_path, [path])
    assert index.call(index.global_value(path, "render"), [None], {}) is None


@pytest.mark.parametrize("execute", [False, True])
def test_imported_source_loader_reaches_only_its_enumerated_folder(tmp_path, execute):
    loader = _LOADER
    if not execute:
        loader = loader.replace("    spec.loader.exec_module(module)\n", "")
    sources = {
        "base.py": "class Base:\n    pass\n",
        "loader.py": loader,
        "app.py": """
            from pathlib import Path
            from base import Base
            from loader import load
            def discover():
                for path in (Path(__file__).parent / "plugins").glob("*.py"):
                    load(path)
                return Base.__subclasses__()
            discover()
        """,
        "plugins/active.py": "from base import Base\nclass Active(Base):\n    pass\n",
        "elsewhere/unused.py": "from base import Base\nclass Unused(Base):\n    pass\n",
    }
    for relative, source in sources.items():
        write_fixture(
            tmp_path, relative, textwrap.dedent(source).lstrip(), overwrite=True
        )
    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, grep_cache=False)
    )
    names = {item["full_name"] for item in result.get("unused_classes", ())}
    assert ("plugins.active.Active" not in names) == execute
    assert "elsewhere.unused.Unused" in names


@pytest.mark.parametrize("returned", ["module", "None"])
def test_nested_registrar_gets_only_the_module_the_loader_returns(tmp_path, returned):
    sources = {
        "base.py": "class Base:\n    pass\n",
        "loader.py": _LOADER.replace("return module", f"return {returned}"),
        "app.py": """
            import inspect
            from pathlib import Path
            from base import Base
            from loader import load
            def bootstrap():
                def register(module):
                    for value in module.__dict__.values():
                        if inspect.isclass(value) and issubclass(value, Base):
                            print(value)
                register(load(Path(__file__).parent / "plugins" / "active.py"))
            bootstrap()
        """,
        "plugins/active.py": "from base import Base\nclass Active(Base):\n    pass\n",
        "elsewhere/unused.py": "from base import Base\nclass Unused(Base):\n    pass\n",
    }
    for relative, source in sources.items():
        write_fixture(
            tmp_path, relative, textwrap.dedent(source).lstrip(), overwrite=True
        )
    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, grep_cache=False)
    )
    names = {item["full_name"] for item in result.get("unused_classes", ())}
    assert ("plugins.active.Active" not in names) == (returned == "module")
    assert "elsewhere.unused.Unused" in names


@pytest.mark.parametrize("load_first", [False, True])
def test_discovery_requires_the_loader_call_before_it(tmp_path, load_first):
    calls = "load_plugins()\ndiscover()\n"
    if not load_first:
        calls = "discover()\nload_plugins()\n"
    sources = {
        "base.py": "class Base:\n    pass\n",
        "loader.py": _LOADER,
        "app.py": """
            from pathlib import Path
            from base import Base
            from loader import load
            def load_plugins():
                load(Path(__file__).parent / "plugins" / "active.py")
            def discover():
                return Base.__subclasses__()
        """,
        "plugins/active.py": "from base import Base\nclass Active(Base):\n    pass\n",
    }
    for relative, source in sources.items():
        content = textwrap.dedent(source).lstrip()
        if relative == "app.py":
            content += calls
        write_fixture(tmp_path, relative, content, overwrite=True)
    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, grep_cache=False)
    )
    names = {item["full_name"] for item in result.get("unused_classes", ())}
    assert ("plugins.active.Active" not in names) == load_first


def test_an_unrelated_reachable_loader_does_not_supply_discovery(tmp_path):
    sources = {
        "base.py": "class Base:\n    pass\n",
        "loader.py": _LOADER,
        "app.py": """
            from base import Base
            def discover():
                return Base.__subclasses__()
            discover()
        """,
        "other.py": """
            from pathlib import Path
            from loader import load
            def startup():
                load(Path(__file__).parent / "plugins" / "active.py")
            startup()
        """,
        "plugins/active.py": "from base import Base\nclass Active(Base):\n    pass\n",
    }
    for relative, source in sources.items():
        write_fixture(
            tmp_path, relative, textwrap.dedent(source).lstrip(), overwrite=True
        )
    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, grep_cache=False)
    )
    names = {item["full_name"] for item in result.get("unused_classes", ())}
    assert "plugins.active.Active" in names


@pytest.mark.parametrize(
    ("binding", "real_provider"),
    [
        ("import tqdm\nprogress = tqdm.tqdm", True),
        ("from tqdm import tqdm as progress", True),
        ("from tqdm.auto import tqdm as progress", True),
        ("from tqdm import tqdm as progress\n# local module", False),
        (
            "import tqdm\n"
            "def replaced(items):\n    return []\n"
            "tqdm.tqdm = replaced\nprogress = tqdm.tqdm",
            False,
        ),
        ("from other_provider import progress", False),
        (
            "from tqdm import tqdm as real_progress\n"
            "def progress(items):\n"
            "    return real_progress(items, unsupported_option=True)",
            False,
        ),
    ],
)
def test_progress_iterator_preserves_only_the_real_provider(
    tmp_path, binding, real_provider
):
    sources = {
        "base.py": "class Base:\n    pass\n",
        "loader.py": _LOADER,
        "app.py": """
            from pathlib import Path
            from base import Base
            from loader import load
            class Entry:
                def __init__(self, path):
                    self.path = path
            entries = []
            def populate():
                for path in (Path(__file__).parent / "plugins").glob("*.py"):
                    entries.append(Entry(path))
            def discover():
                for entry in progress(entries):
                    load(entry.path)
                return Base.__subclasses__()
            populate()
            discover()
        """,
        "plugins/active.py": "from base import Base\nclass Active(Base):\n    pass\n",
        "elsewhere/unused.py": "from base import Base\nclass Unused(Base):\n    pass\n",
    }
    if "# local module" in binding:
        sources["tqdm.py"] = "def tqdm(items):\n    return []\n"
    for relative, source in sources.items():
        content = textwrap.dedent(source).lstrip()
        if relative == "app.py":
            content = binding + "\n" + content
        write_fixture(tmp_path, relative, content, overwrite=True)
    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, grep_cache=False)
    )
    names = {item["full_name"] for item in result.get("unused_classes", ())}
    assert ("plugins.active.Active" not in names) == real_provider
    assert "elsewhere.unused.Unused" in names
