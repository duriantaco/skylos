"""Repeated Robot expressions share one immutable provider/mutation index."""

import ast
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

from skylos.deadcode.robot_framework_liveness import (
    _Providers,
    _object_method_targets,
)


def _parsed(root, name, source):
    path = root / f"{name}.py"
    path.write_text(source)
    return SimpleNamespace(path=path, tree=ast.parse(source))


def test_provider_normalization_is_bounded_by_distinct_names(tmp_path, monkeypatch):
    values = _parsed(tmp_path, "values", "class Item: pass\n")
    providers = _Providers({}, [values], tmp_path)
    original = Path.resolve
    calls = []

    def counted(path, *args, **kwargs):
        calls.append(str(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", counted)
    for _ in range(400):
        assert providers.module("values", tmp_path) is not None
        assert providers.module("missing", tmp_path) is None
        assert providers.resolve("values.Item", tmp_path)[1].name == "Item"
        assert providers.resolve("missing.Item", tmp_path) == (None, None)
    assert len(calls) <= 50


def test_mutation_owners_are_resolved_once_for_all_methods(tmp_path, monkeypatch):
    methods = "".join(f"    def method_{i}(self): return {i}\n" for i in range(25))
    values = _parsed(tmp_path, "values", "class Item:\n" + methods + "OBJ = Item()\n")
    other = _parsed(tmp_path, "other", "class Other: pass\n")
    noise = _parsed(
        tmp_path,
        "noise",
        "import other\n"
        + "consume(other.Other)\n" * 80
        + "".join(f"import absent_{i}\nconsume(absent_{i}.Thing)\n" for i in range(80)),
    )
    definitions = {
        f"values.Item.method_{i}": SimpleNamespace(
            name=f"values.Item.method_{i}",
            filename=str(values.path),
            line=i + 2,
            simple_name=f"method_{i}",
            type="method",
        )
        for i in range(25)
    }
    providers = _Providers(definitions, [values, other, noise], tmp_path)
    scope = providers.modules[values.path]
    instance = scope.instances["OBJ"]
    original = providers.resolve
    resolved = Counter()

    def counted(name, parent):
        resolved[name] += 1
        return original(name, parent)

    monkeypatch.setattr(providers, "resolve", counted)
    for _ in range(3):
        for i in range(25):
            assert [
                row.name
                for row in _object_method_targets(
                    providers, scope, instance, f"method_{i}"
                )
            ] == [f"values.Item.method_{i}"]
    assert resolved["other.Other"] <= 1
    assert not any(name.startswith("absent_") for name in resolved)


def test_provider_misses_do_not_leak_into_a_later_index(tmp_path):
    first = _Providers({}, [], tmp_path)
    assert first.resolve("values.Item", tmp_path) == (None, None)
    parsed = _parsed(tmp_path, "values", "class Item: pass\n")
    second = _Providers({}, [parsed], tmp_path)
    assert second.resolve("values.Item", tmp_path)[1].name == "Item"
