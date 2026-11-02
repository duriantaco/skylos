"""Lazy API declarations require an actual, source-bound export path."""

import ast
import json
import textwrap
from types import SimpleNamespace

import pytest

from skylos.analyzer import analyze
from skylos.deadcode.public_api import find_declared_public_api_targets
from skylos.deadcode.python_ast import ParsedPythonFile


BODY = "def candidate(path):\n    with open(path) as handle:\n        return handle.read().splitlines()\n"
GETTER = """
def __getattr__(name):
    if name in _EXPORTS:
        return getattr(importlib.import_module(_EXPORTS[name], __name__), name)
    raise AttributeError(name)
"""
HEADER = 'import importlib\n_EXPORTS = {"candidate": ".impl"}\n'


def _project(tmp_path, source, *, extra=None):
    files = {
        "lib/__init__.py": source,
        "lib/impl.py": BODY,
        "lib/real.py": "def kept(path):\n    return path.read_text()\n",
        "pyproject.toml": '[project]\nname="lib"\nversion="1"\n',
        **(extra or {}),
    }
    definitions = {}
    parsed = []
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text).lstrip())
        if path.suffix != ".py":
            continue
        tree = ast.parse(path.read_text())
        parsed.append(ParsedPythonFile(path=path, tree=tree))
        module = ".".join(path.relative_to(tmp_path).with_suffix("").parts)
        module = module.removesuffix(".__init__")
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                full_name = f"{module}.{node.name}"
                definitions[full_name] = SimpleNamespace(
                    name=full_name,
                    simple_name=node.name,
                    filename=path,
                    type="function",
                    line=node.lineno,
                )
    return definitions, parsed


def _kept(tmp_path, source, *, extra=None):
    definitions, parsed = _project(tmp_path, source, extra=extra)
    return {
        definition.name
        for definition, _ in find_declared_public_api_targets(
            definitions, parsed, tmp_path
        )
    }


@pytest.mark.parametrize(
    "source",
    [
        HEADER + GETTER,
        HEADER
        + GETTER.replace(
            "return getattr(importlib.import_module(_EXPORTS[name], __name__), name)",
            "module = importlib.import_module(_EXPORTS[name], __name__)\n        return getattr(module, name)",
        ),
        HEADER.replace(
            "import importlib", "from importlib import import_module as load"
        )
        + GETTER.replace("importlib.import_module", "load"),
        HEADER.replace('".impl"', '(".impl", "candidate")')
        + GETTER.replace(
            "return getattr(importlib.import_module(_EXPORTS[name], __name__), name)",
            "owner, attr = _EXPORTS[name]\n        return getattr(importlib.import_module(owner, __name__), attr)",
        ),
        "import importlib\ndef __getattr__(name):\n    if name == 'candidate':\n        return importlib.import_module('.impl', __name__).candidate\n    raise AttributeError(name)\n",
        "def __getattr__(name):\n    if name == 'candidate':\n        return getattr(__import__('lib.impl', fromlist=[name]), name)\n    raise AttributeError(name)\n",
        "import lazy_loader as lazy\n__getattr__, __dir__, __all__ = lazy.attach(__name__, submod_attrs={'impl': ['candidate']})\n",
        "from lazy_loader import attach as expose\n__getattr__, __dir__, _ = expose(__name__, [], {'impl': ['candidate']})\n",
        "import lazy_loader as lazy\n__getattr__, __dir__, __all__ = lazy.attach('lib', submod_attrs={'impl': ['candidate']})\n",
        "import lazy_loader as lazy\n__getattr__, _, __all__ = lazy.attach(__name__, submod_attrs={'impl': ['candidate']})\n",
        HEADER + GETTER.replace("_EXPORTS[name]", "_EXPORTS.get(name)"),
        HEADER
        + GETTER.replace(
            "_EXPORTS[name], __name__", "name=_EXPORTS[name], package=__name__"
        ),
        HEADER.replace(
            "import importlib",
            "import importlib\nfrom builtins import getattr as fetch",
        )
        + GETTER.replace("return getattr(", "return fetch("),
        "import importlib\ndef __getattr__(name):\n    if name == 'external':\n        return getattr(importlib.import_module('.impl', __name__), 'candidate')\n    raise AttributeError(name)\n",
    ],
)
def test_proven_lazy_export_forms_keep_only_the_actual_target(tmp_path, source):
    assert "lib.impl.candidate" in _kept(tmp_path, source)


@pytest.mark.parametrize(
    "source",
    [
        "_REMOVED = {'candidate': '.impl'}\ndef __getattr__(name):\n    import importlib\n    raise AttributeError(name)\n",
        "import importlib\n_EXPORTS = {'kept': '.real'}\n_STATUS = {'candidate': '.impl'}\n"
        + GETTER,
        HEADER.replace('".impl"', '".missing"') + GETTER,
        HEADER + GETTER.replace("_EXPORTS[name]", "'.real'"),
        HEADER + GETTER.replace("if name in _EXPORTS:", "if False:"),
        HEADER
        + GETTER.replace(
            "if name in _EXPORTS:", "return None\n    if name in _EXPORTS:"
        ),
        HEADER + GETTER.replace("if name in _EXPORTS:", "if name == 'different':"),
        HEADER + GETTER.replace(", name)", ", 'kept')"),
        HEADER.replace("import importlib", "import fake_importer as importlib")
        + GETTER,
        HEADER + "importlib = object()\n" + GETTER,
        HEADER + "importlib.import_module = lambda *args: None\n" + GETTER,
        HEADER + "def getattr(*args):\n    return None\n" + GETTER,
        HEADER + GETTER + "__getattr__ = lambda name: None\n",
        HEADER + "_ALIAS = _EXPORTS\nmutate(_ALIAS)\n" + GETTER,
        HEADER + "_EXPORTS['candidate'] = '.real'\n" + GETTER,
        HEADER + GETTER.replace("if name in _EXPORTS:", "if unknown_guard():"),
        "import fake_loader as lazy\n__getattr__, __dir__, __all__ = lazy.attach(__name__, submod_attrs={'impl': ['candidate']})\n",
        "import lazy_loader as lazy\n__dir__, __getattr__, __all__ = lazy.attach(__name__, submod_attrs={'impl': ['candidate']})\n",
        "import lazy_loader as lazy\n__getattr__, __dir__, __all__ = lazy.attach(__name__, submod_attrs={'impl': ['candidate']})\n__getattr__ = lambda name: None\n",
        HEADER + "_ALIAS = (_EXPORTS,)\nmutate(_ALIAS)\n" + GETTER,
        HEADER + "_ALIAS = _EXPORTS\nmutate(_ALIAS)\n_ALIAS = []\n" + GETTER,
        HEADER + "candidate = None\n" + GETTER,
        HEADER
        + GETTER.replace("_EXPORTS[name], __name__", "_EXPORTS[name], __name__, None"),
        HEADER
        + GETTER.replace(
            "_EXPORTS[name], __name__", "_EXPORTS[name], __name__, bogus=True"
        ),
        HEADER + GETTER.replace(", name)", ", name, unknown_default)"),
        "def __getattr__(name):\n    if name == 'candidate':\n        return getattr(__import__('lib.impl', fromlist=unknown), name)\n    raise AttributeError(name)\n",
        "import lazy_loader as lazy\n__getattr__, __dir__, __all__ = lazy.attach(__name__, submod_attrs={'impl': ['candidate']}, bogus=True)\n",
        "import lazy_loader as lazy\n__getattr__, __dir__, __all__ = lazy.attach(__name__, submod_attrs={'impl': ['candidate']})\n__all__.clear()\n",
        "import lazy_loader as lazy\n__getattr__, __dir__, __all__ = lazy.attach(__name__, submod_attrs={'impl': ['candidate']})\n_ALIAS = __all__\nmutate(_ALIAS)\n",
        HEADER + "from other import *\n" + GETTER,
        HEADER + GETTER + "import sys\nsys.modules[__name__] = object()\n",
        HEADER + GETTER + "__getattr__.__code__ = replacement\n",
        "import lazy_loader as lazy\n__getattr__, __dir__, __all__ = lazy.attach(__name__, submod_attrs={'impl': ['candidate']})\n_ALIAS = __getattr__\n_ALIAS.__code__ = replacement\n",
    ],
)
def test_lookalike_lazy_patterns_do_not_declare_a_target_public(tmp_path, source):
    assert "lib.impl.candidate" not in _kept(tmp_path, source)


def test_lazy_provider_in_project_is_not_the_external_lazy_loader(tmp_path):
    source = "import lazy_loader as lazy\n__getattr__, __dir__, __all__ = lazy.attach(__name__, submod_attrs={'impl': ['candidate']})\n"
    assert "lib.impl.candidate" not in _kept(
        tmp_path,
        source,
        extra={
            "lazy_loader.py": "def attach(*args, **kwargs):\n    return None, None, []\n",
        },
    )


def test_project_loader_cannot_attest_stub_reexports(tmp_path):
    source = "import lazy_loader as lazy\n__getattr__, __dir__, __all__ = lazy.attach_stub(__name__, __file__)\n"
    assert "lib.impl.candidate" not in _kept(
        tmp_path,
        source,
        extra={
            "lib/__init__.pyi": "from .impl import candidate\n",
            "lazy_loader.py": "def attach_stub(*args):\n    return None, None, []\n",
        },
    )


def test_project_loader_cannot_attest_unknown_all_for_docs(tmp_path):
    source = (
        "import lazy_loader as lazy\n"
        + BODY
        + "\n__getattr__, __dir__, __all__ = lazy.attach(__name__, submod_attrs={'impl': ['candidate']})\n"
    )
    assert "lib.candidate" not in _kept(
        tmp_path,
        source,
        extra={
            "docs/api.rst": ".. autofunction:: lib.candidate\n",
            "lazy_loader.py": "def attach(*args, **kwargs):\n    return None, None, []\n",
        },
    )


@pytest.mark.parametrize(
    "third,tail,expected",
    [
        ("__all__", "", True),
        ("_", "", True),
        ("__all__", "__all__.clear()\n", False),
        ("__all__", "_ALIAS = __all__\nmutate(_ALIAS)\n", False),
        ("_", "__all__ = uncertain()\n", False),
    ],
)
def test_stub_factory_cannot_override_later_or_unrelated_all(
    tmp_path, third, tail, expected
):
    source = (
        "import lazy_loader as lazy\n"
        + f"__getattr__, __dir__, {third} = lazy.attach_stub(__name__, __file__)\n"
        + tail
    )
    kept = _kept(
        tmp_path, source, extra={"lib/__init__.pyi": "from .impl import candidate\n"}
    )
    assert ("lib.impl.candidate" in kept) is expected


def test_private_exporter_does_not_rescue_its_implementation(tmp_path):
    definitions, parsed = _project(
        tmp_path,
        "",
        extra={
            "lib/_internal/__init__.py": HEADER + GETTER,
            "lib/_internal/impl.py": BODY,
        },
    )
    kept = {
        definition.name
        for definition, _ in find_declared_public_api_targets(
            definitions, parsed, tmp_path
        )
    }
    assert "lib._internal.impl.candidate" not in kept


@pytest.mark.parametrize(
    "metadata", ["submod_attrs={'impl': ['candidate']}", "submodules=['candidate']"]
)
def test_attach_all_keeps_existing_local_binding_without_reaching_lazy_target(
    tmp_path, metadata
):
    source = (
        "import lazy_loader as lazy\n"
        + BODY
        + f"\n__getattr__, __dir__, __all__ = lazy.attach(__name__, {metadata})\n"
    )
    kept = _kept(tmp_path, source)
    assert "lib.candidate" in kept
    assert "lib.impl.candidate" not in kept


@pytest.mark.parametrize(
    "condition",
    [
        "importlib.import_module('.flags', __name__).enabled",
        "importlib.import_module('.flags', __name__).enabled != False",
    ],
)
def test_imported_attribute_is_not_a_concrete_truth_value(tmp_path, condition):
    source = HEADER + GETTER.replace("if name in _EXPORTS:", f"if {condition}:")
    assert "lib.impl.candidate" not in _kept(
        tmp_path, source, extra={"lib/flags.py": "enabled = False\n"}
    )


def test_set_indexing_does_not_prove_a_lazy_export(tmp_path):
    source = """
    import importlib
    _EXPORTS = {"candidate"}
    def __getattr__(name):
        if name == "candidate":
            module = importlib.import_module(".impl", __name__)
            return getattr(module, _EXPORTS[0])
        raise AttributeError(name)
    """
    assert "lib.impl.candidate" not in _kept(tmp_path, source)


def test_set_indexing_keeps_the_actual_analyzer_finding(tmp_path):
    source = """
    import importlib
    _EXPORTS = {"candidate"}
    def __getattr__(name):
        if name == "candidate":
            module = importlib.import_module(".impl", __name__)
            return getattr(module, _EXPORTS[0])
        raise AttributeError(name)
    """
    _project(tmp_path, source)
    result = json.loads(analyze(str(tmp_path), conf=0))
    assert not result.get("analysis_errors")
    assert any(
        row["full_name"] == "lib.impl.candidate" and row["listing"]["listed"]
        for row in result.get("unused_functions", [])
    )


@pytest.mark.parametrize(
    "source",
    [
        "import importlib\n_EXPORTS = {'candidate'}\ndef __getattr__(name):\n    if name in _EXPORTS:\n        return getattr(importlib.import_module('.impl', __name__), name)\n    raise AttributeError(name)\n",
        "import lazy_loader as lazy\n__getattr__, __dir__, __all__ = lazy.attach(__name__, submodules={'submodule'}, submod_attrs={'impl': {'candidate'}})\n",
    ],
)
def test_valid_set_membership_and_loader_metadata_still_export(tmp_path, source):
    assert "lib.impl.candidate" in _kept(tmp_path, source)


def test_mutated_set_alias_does_not_prove_a_lazy_export(tmp_path):
    source = "import importlib\n_EXPORTS = {'candidate'}\n_ALIAS = _EXPORTS\n_ALIAS.clear()\ndef __getattr__(name):\n    if name in _EXPORTS:\n        return getattr(importlib.import_module('.impl', __name__), name)\n    raise AttributeError(name)\n"
    assert "lib.impl.candidate" not in _kept(tmp_path, source)


@pytest.mark.parametrize(
    "source",
    [
        "_REMOVED = {'candidate': '.impl'}\ndef __getattr__(name):\n    import importlib\n    raise AttributeError(name)\n",
        "import importlib\n_EXPORTS = {'kept': '.real'}\n_STATUS = {'candidate': '.impl'}\n"
        + GETTER,
        HEADER.replace('".impl"', '".missing"') + GETTER,
    ],
)
def test_false_lazy_rescues_do_not_remove_real_analyzer_findings(tmp_path, source):
    _project(tmp_path, source)
    result = json.loads(analyze(str(tmp_path), conf=0))
    assert not result.get("analysis_errors")
    assert any(
        row["full_name"] == "lib.impl.candidate" and row["listing"]["listed"]
        for row in result.get("unused_functions", [])
    )
