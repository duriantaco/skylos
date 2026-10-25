"""Registry retention must follow executing, source-bound config lookups."""

import ast
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from skylos.deadcode.plugin_registry import find_nested_dict_getattr_targets
from skylos.deadcode.python_ast import ParsedPythonFile


HANDLERS = "def active(): return 1\ndef obsolete(): return 2\n"
TABLE = 'TABLE = {"row": {"create_method": "obsolete"}}\n'


def _inputs(root, sources):
    parsed, definitions = [], {}
    for filename, source in sources.items():
        path = root / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        tree = ast.parse(source)
        parsed.append(ParsedPythonFile(path=path, tree=tree))
        module = str(Path(filename).with_suffix("")).replace("/", ".")
        module = module.removesuffix(".__init__")
        pending = [(tree, module, False)]
        while pending:
            node, prefix, in_class = pending.pop()
            for child in ast.iter_child_nodes(node):
                if isinstance(
                    child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    name = prefix + "." + child.name
                    kind = (
                        "class"
                        if isinstance(child, ast.ClassDef)
                        else "method"
                        if in_class
                        else "function"
                    )
                    definitions[name] = SimpleNamespace(
                        name=name,
                        simple_name=child.name,
                        filename=str(path),
                        line=child.lineno,
                        node=child,
                        type=kind,
                        heuristic_refs={},
                    )
                    pending.append((child, name, kind == "class"))
                else:
                    pending.append((child, prefix, in_class))
    return definitions, parsed


def _targets(root, sources):
    definitions, parsed = _inputs(root, sources)
    return {item.name for item in find_nested_dict_getattr_targets(definitions, parsed)}


@pytest.mark.parametrize(
    "program",
    [
        'def inspect():\n    name = TABLE["row"].get("create_method")\n    return getattr(handlers, name)\n',
        'for config in []:\n    name = config.get("create_method")\n    getattr(handlers, name)\n',
        'def inspect():\n    name = TABLE["row"].get("create_method")\n    if False:\n        getattr(handlers, name)\ninspect()\n',
        'def inspect(handlers):\n    name = TABLE["row"].get("create_method")\n    return hasattr(handlers, name)\ninspect(object())\n',
        'handlers = object()\ndef inspect():\n    name = TABLE["row"].get("create_method")\n    return hasattr(handlers, name)\ninspect()\n',
        'def getattr(module, name): return None\ndef inspect():\n    name = TABLE["row"].get("create_method")\n    return getattr(handlers, name)\ninspect()\n',
        'def inspect():\n    name = TABLE["row"].get("create_method")\n    name = "active"\n    return hasattr(handlers, name)\ninspect()\n',
        'def inspect():\n    def dead():\n        name = TABLE["row"].get("create_method")\n        return getattr(handlers, name)\n    return None\ninspect()\n',
        'def inspect():\n    name = TABLE["row"].get("create_method")\n    yield getattr(handlers, name)\ninspect()\n',
        'def inspect(config):\n    name = config.get("create_method")\n    return getattr(handlers, name)\ninspect(TABLE["row"], unexpected=True)\n',
        'from external import mutate\nconfig = TABLE["row"]\nmutate(TABLE)\ndef inspect():\n    name = config.get("create_method")\n    return getattr(handlers, name)\ninspect()\n',
    ],
)
def test_inactive_or_rebound_lookup_does_not_retain_handler(tmp_path, program):
    assert "handlers.obsolete" not in _targets(
        tmp_path,
        {
            "handlers.py": HANDLERS,
            "dispatch.py": "import handlers\n" + TABLE + program,
        },
    )


def test_unrelated_table_is_not_the_source_of_the_lookup(tmp_path):
    sources = {
        "handlers.py": HANDLERS,
        "unloaded.py": TABLE,
        "dispatch.py": 'import handlers\nACTIVE = {"row": {"create_method": "active"}}\n'
        'def inspect():\n    name = ACTIVE["row"].get("create_method")\n    return hasattr(handlers, name)\ninspect()\n',
    }
    assert _targets(tmp_path, sources) == {"handlers.active"}


@pytest.mark.parametrize(
    "program",
    [
        'def inspect():\n    name = TABLE["row"].get("create_method")\n    return getattr(handlers, name)()\ninspect()\n',
        'def inspect(config):\n    name = config.get("create_method")\n    return getattr(handlers, name)()\ninspect(TABLE["row"])\n',
        'def factory(config):\n    name = config.get("create_method")\n    def callback():\n        return getattr(handlers, name)()\n    return callback\ncallback = factory(TABLE["row"])\ncallback()\n',
        'def factory(config):\n    name = config.get("create_method")\n    def method(self):\n        return getattr(handlers, self._create_method_name)()\n    return type("Dynamic", (object,), {"_create_method_name": name, "run": method})\nBuilt = factory(TABLE["row"])\nBuilt().run()\n',
    ],
)
def test_actual_table_flow_and_called_factory_callbacks_are_retained(tmp_path, program):
    assert _targets(
        tmp_path,
        {
            "handlers.py": HANDLERS,
            "dispatch.py": "import handlers\n" + TABLE + program,
        },
    ) == {"handlers.obsolete"}


def test_imported_list_tuple_registry_and_nested_config_values(tmp_path):
    assert _targets(
        tmp_path,
        {
            "handlers.py": HANDLERS,
            "registry.py": 'ROWS = [(object, {"related": {"row": {"create_method": "obsolete"}}})]\n',
            "dispatch.py": "import handlers\nfrom registry import ROWS as configs\n"
            'def inspect(config):\n    name = config.get("create_method")\n    return getattr(handlers, name)()\n'
            'for model, config in configs:\n    for relation in config["related"].values():\n        inspect(relation)\n',
        },
    ) == {"handlers.obsolete"}


@pytest.mark.parametrize(
    "provider, lookup",
    [
        ("from builtins import getattr as lookup", "lookup"),
        ("from builtins import *", "getattr"),
    ],
)
def test_bound_builtin_alias_keeps_its_capture_before_reassignment(
    tmp_path, provider, lookup
):
    assert _targets(
        tmp_path,
        {
            "handlers.py": HANDLERS,
            "dispatch.py": "import handlers\n"
            + provider
            + "\n"
            + TABLE
            + 'def inspect():\n    name = TABLE["row"]["create_method"]\n'
            + f"    return {lookup}(handlers, name)\ninspect()\n",
        },
    ) == {"handlers.obsolete"}


@pytest.mark.parametrize(
    "replacement",
    [
        "handlers.obsolete = None",
        "setattr(handlers, 'obsolete', None)",
        "import builtins\nbuiltins.getattr = lambda *args: None",
        "import builtins\nsetattr(builtins, 'getattr', lambda *args: None)",
    ],
)
def test_current_receiver_and_builtin_attributes_are_not_stale_proofs(
    tmp_path, replacement
):
    assert not _targets(
        tmp_path,
        {
            "handlers.py": HANDLERS,
            "dispatch.py": "import handlers\n"
            + TABLE
            + replacement
            + "\n"
            + 'def inspect():\n    name = TABLE["row"]["create_method"]\n    return getattr(handlers, name)\ninspect()\n',
        },
    )


def test_builtin_alias_captured_before_provider_replacement_remains_real(tmp_path):
    assert _targets(
        tmp_path,
        {
            "handlers.py": HANDLERS,
            "dispatch.py": "import handlers\nimport builtins\nlookup = builtins.getattr\n"
            + TABLE
            + "builtins.getattr = lambda *args: None\n"
            + 'def inspect():\n    name = TABLE["row"]["create_method"]\n    return lookup(handlers, name)\ninspect()\n',
        },
    ) == {"handlers.obsolete"}


@pytest.mark.parametrize(
    "import_line, receiver, expected",
    [
        ("import pkg", "pkg.handlers", set()),
        ("import pkg.handlers", "pkg.handlers", {"pkg.handlers.obsolete"}),
        ("from pkg import handlers", "handlers", {"pkg.handlers.obsolete"}),
    ],
)
def test_package_attribute_needs_its_actual_submodule_import(
    tmp_path, import_line, receiver, expected
):
    assert (
        _targets(
            tmp_path,
            {
                "pkg/__init__.py": "",
                "pkg/handlers.py": HANDLERS,
                "dispatch.py": import_line
                + "\n"
                + TABLE
                + 'def inspect():\n    name = TABLE["row"]["create_method"]\n'
                + f"    return getattr({receiver}, name)\ninspect()\n",
            },
        )
        == expected
    )


def test_relative_import_preserves_real_module_and_table_binding(tmp_path):
    assert _targets(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/handlers.py": HANDLERS,
            "pkg/registry.py": TABLE,
            "pkg/dispatch.py": "from . import handlers\nfrom .registry import TABLE as CONFIG\n"
            'def inspect():\n    name = CONFIG["row"]["create_method"]\n    return getattr(handlers, name)\ninspect()\n',
        },
    ) == {"pkg.handlers.obsolete"}


@pytest.mark.parametrize(
    "initializer, construction",
    [
        ("def __init__(self, required): pass", "Carrier()"),
        ("", "Carrier(1)"),
        ("", "Carrier(unexpected=1)"),
        ("def __init__(self, required): pass", "Carrier(1, required=2)"),
        ("def __init__(self, required): pass", "Carrier(required=1, unexpected=2)"),
        ("def __init__(self): return 1", "Carrier()"),
        ("def __init__(self): return unknown()", "Carrier()"),
        ("def __init__(self): raise ValueError()", "Carrier()"),
        ("def __init__(self):\n        if unknown:\n            return 1", "Carrier()"),
    ],
)
def test_invalid_constructor_cannot_supply_an_executing_method(
    tmp_path, initializer, construction
):
    source = "import handlers\n" + TABLE + "class Carrier:\n"
    if initializer:
        source += "    " + initializer + "\n"
    source += '    def load(self):\n        name = TABLE["row"]["create_method"]\n        return getattr(handlers, name)\n'
    source += construction + ".load()\n"
    assert not _targets(tmp_path, {"handlers.py": HANDLERS, "dispatch.py": source})


@pytest.mark.parametrize(
    "initializer, construction",
    [
        ("", "Carrier()"),
        ("def __init__(self): pass", "Carrier()"),
        ("def __init__(self): return None", "Carrier()"),
        ("def __init__(self):\n        if False:\n            return 1", "Carrier()"),
        ("def __init__(self, required): self.required = required", "Carrier(1)"),
        ("def __init__(self, required=1): self.required = required", "Carrier()"),
        (
            "def __init__(self, required): self.required = required",
            "Carrier(required=1)",
        ),
    ],
)
def test_valid_constructor_preserves_executing_method_lookup(
    tmp_path, initializer, construction
):
    source = "import handlers\n" + TABLE + "class Carrier:\n"
    if initializer:
        source += "    " + initializer + "\n"
    source += '    def load(self):\n        name = TABLE["row"]["create_method"]\n        return getattr(handlers, name)\n'
    source += construction + ".load()\n"
    assert _targets(tmp_path, {"handlers.py": HANDLERS, "dispatch.py": source}) == {
        "handlers.obsolete"
    }


@pytest.mark.parametrize(
    "expression",
    [
        "getattr(handlers, name, None, 1)",
        "hasattr(handlers, name, 1)",
        "getattr(handlers, name, unexpected=True)",
        'getattr(handlers, TABLE["row"].get("create_method", None, 1))',
        'getattr(handlers, TABLE["row"].get("create_method", unexpected=True))',
    ],
)
def test_invalid_builtin_or_table_get_arity_cannot_retain_target(tmp_path, expression):
    source = "import handlers\n" + TABLE
    source += 'def inspect():\n    name = TABLE["row"]["create_method"]\n'
    source += f"    return {expression}\ninspect()\n"
    assert not _targets(tmp_path, {"handlers.py": HANDLERS, "dispatch.py": source})


@pytest.mark.parametrize("method", ["values", "items", "keys"])
def test_invalid_table_iteration_keywords_cannot_execute_body(tmp_path, method):
    source = "import handlers\n" + TABLE
    if method == "values":
        source += 'for config in TABLE.values(unexpected=True):\n    name = config["create_method"]\n    getattr(handlers, name)\n'
    elif method == "items":
        source += 'for key, config in TABLE.items(unexpected=True):\n    name = config["create_method"]\n    getattr(handlers, name)\n'
    else:
        source += 'for key in TABLE.keys(unexpected=True):\n    name = TABLE[key]["create_method"]\n    getattr(handlers, name)\n'
    assert not _targets(tmp_path, {"handlers.py": HANDLERS, "dispatch.py": source})


def test_invalid_table_update_does_not_apply_a_partial_mutation(tmp_path):
    source = 'import handlers\nTABLE = {"row": {"create_method": "active"}}\n'
    source += 'TABLE["row"].update({"create_method": "obsolete"}, {})\n'
    source += 'def inspect():\n    name = TABLE["row"]["create_method"]\n    return getattr(handlers, name)\ninspect()\n'
    assert "handlers.obsolete" not in _targets(
        tmp_path, {"handlers.py": HANDLERS, "dispatch.py": source}
    )


@pytest.mark.parametrize(
    "expression",
    [
        "getattr(handlers, name)",
        "getattr(handlers, name, None)",
        "hasattr(handlers, name)",
    ],
)
def test_valid_builtin_lookup_arity_keeps_registry_target(tmp_path, expression):
    source = "import handlers\n" + TABLE
    source += 'def inspect():\n    name = TABLE["row"].get("create_method", None)\n'
    source += f"    return {expression}\ninspect()\n"
    assert _targets(tmp_path, {"handlers.py": HANDLERS, "dispatch.py": source}) == {
        "handlers.obsolete"
    }


@pytest.mark.parametrize("statement", ["break", "continue"])
def test_loop_completion_does_not_execute_the_remaining_body(tmp_path, statement):
    source = "import handlers\n" + TABLE
    source += f'for config in [TABLE["row"]]:\n    {statement}\n    name = config["create_method"]\n    getattr(handlers, name)\n'
    assert not _targets(tmp_path, {"handlers.py": HANDLERS, "dispatch.py": source})


@pytest.mark.parametrize(
    "left, right",
    [
        ("return None", "return None"),
        ("raise ValueError()", "raise ValueError()"),
        ("return None", "raise ValueError()"),
    ],
)
def test_all_terminal_unknown_branches_do_not_execute_following_lookup(
    tmp_path, left, right
):
    source = "import handlers\n" + TABLE
    source += f'def load(flag):\n    if flag:\n        {left}\n    else:\n        {right}\n    return getattr(handlers, TABLE["row"]["create_method"])\nload(object())\n'
    # A guaranteed raise also stops its importing module; the independent
    # positive belongs in another module that can complete normally.
    other = 'import handlers\nACTIVE = {"create_method": "active"}\nname = ACTIVE["create_method"]\ngetattr(handlers, name)\n'
    assert _targets(
        tmp_path, {"handlers.py": HANDLERS, "dispatch.py": source, "other.py": other}
    ) == {"handlers.active"}


@pytest.mark.parametrize("statement", ["break", "continue"])
def test_loop_completion_keeps_the_following_outer_lookup(tmp_path, statement):
    source = "import handlers\n" + TABLE
    source += f'for config in [TABLE["row"]]:\n    {statement}\nname = TABLE["row"]["create_method"]\ngetattr(handlers, name)\n'
    assert _targets(tmp_path, {"handlers.py": HANDLERS, "dispatch.py": source}) == {
        "handlers.obsolete"
    }


def test_budget_exhaustion_discards_all_partial_retention(tmp_path, monkeypatch):
    from skylos.deadcode import nested_registry_proofs as proof

    definitions, parsed = _inputs(
        tmp_path,
        {
            "handlers.py": HANDLERS,
            "dispatch.py": "import handlers\n"
            + TABLE
            + 'def inspect():\n    name = TABLE["row"]["create_method"]\n    return getattr(handlers, name)\ninspect()\n'
            + "unused = 1\n" * 100,
        },
    )
    monkeypatch.setattr(proof, "_MAX_STEPS", 100)
    report = proof.collect_nested_registry_targets(definitions, parsed)
    assert not report.complete
    assert report.incomplete_reason == "step_budget"
    assert report.targets == []


def test_nested_uncalled_scopes_are_visited_once(tmp_path):
    from skylos.deadcode.nested_registry_proofs import collect_nested_registry_targets

    nested = "".join("    " * index + f"def nested_{index}():\n" for index in range(24))
    nested += "    " * 24 + 'name = TABLE["row"]["create_method"]\n'
    nested += "    " * 24 + "getattr(handlers, name)\n"
    definitions, parsed = _inputs(
        tmp_path,
        {
            "handlers.py": HANDLERS,
            "dispatch.py": "import handlers\n" + TABLE + nested,
        },
    )
    report = collect_nested_registry_targets(definitions, parsed)
    assert report.complete
    assert report.targets == []
    assert report.steps < 100


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep", [False, True])
def test_unrelated_table_does_not_hide_raw_unused_handler(tmp_path, confidence, grep):
    from skylos.analyzer import Skylos

    _inputs(
        tmp_path,
        {
            "handlers.py": HANDLERS,
            "unloaded.py": TABLE,
            "dispatch.py": 'import handlers\nACTIVE = {"row": {"create_method": "active"}}\n'
            'def inspect():\n    name = ACTIVE["row"].get("create_method")\n    return hasattr(handlers, name)\ninspect()\n',
        },
    )
    analyzer = Skylos()
    result = json.loads(
        analyzer.analyze(str(tmp_path), thr=confidence, grep_verify=grep)
    )
    assert not result.get("analysis_errors")
    assert "handlers.obsolete" in {
        item["full_name"] for item in result.get("unused_functions", [])
    }
    definition = next(
        item for item in analyzer.defs.values() if item.name == "handlers.obsolete"
    )
    assert (
        "dead_code_liveness:nested_dict_getattr_registry"
        not in definition.heuristic_refs
    )


@pytest.mark.parametrize(
    "body, expected",
    [
        ("raise ValueError()", set()),
        ("return None", {"handlers.obsolete"}),
        ("return 1", {"handlers.obsolete"}),
    ],
)
def test_source_callee_completion_controls_following_lookup(tmp_path, body, expected):
    source = "import handlers\n" + TABLE
    source += "def stop():\n    " + body + "\nstop()\n"
    source += 'getattr(handlers, TABLE["row"]["create_method"])\n'
    assert _targets(tmp_path, {"handlers.py": HANDLERS, "app.py": source}) == expected


def test_nested_guaranteed_raise_stops_callers_without_stopping_other_modules(tmp_path):
    source = "import handlers\n" + TABLE
    source += (
        "def stop():\n    raise ValueError()\ndef wrapper():\n    stop()\nwrapper()\n"
    )
    source += 'getattr(handlers, TABLE["row"]["create_method"])\n'
    other = 'import handlers\nACTIVE = {"method": "active"}\ngetattr(handlers, ACTIVE["method"])\n'
    assert _targets(
        tmp_path, {"handlers.py": HANDLERS, "app.py": source, "other.py": other}
    ) == {"handlers.active"}


def test_both_raising_unknown_branches_stop_the_source_caller(tmp_path):
    source = "import handlers\n" + TABLE
    source += "def stop(flag):\n    if flag:\n        raise ValueError()\n    else:\n        raise RuntimeError()\nstop(unknown)\n"
    source += 'getattr(handlers, TABLE["row"]["create_method"])\n'
    assert not _targets(tmp_path, {"handlers.py": HANDLERS, "app.py": source})


def test_unknown_early_normal_return_is_not_a_guaranteed_raise(tmp_path):
    source = "import handlers\n" + TABLE
    source += "def stop(flag):\n    if flag:\n        return None\n    raise ValueError()\nstop(unknown)\n"
    source += 'getattr(handlers, TABLE["row"]["create_method"])\n'
    assert _targets(tmp_path, {"handlers.py": HANDLERS, "app.py": source}) == {
        "handlers.obsolete"
    }


def test_failed_source_import_cannot_complete_a_later_importer(tmp_path):
    source = "import handlers\nimport failing\n" + TABLE
    source += 'getattr(handlers, TABLE["row"]["create_method"])\n'
    assert not _targets(
        tmp_path,
        {
            "handlers.py": HANDLERS,
            "failing.py": "raise ValueError()\n",
            "app.py": source,
        },
    )
