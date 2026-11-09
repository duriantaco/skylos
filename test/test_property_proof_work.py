import ast
from types import SimpleNamespace

import pytest

from skylos.deadcode import property_descriptor_liveness as descriptors


def _parsed(root, name, source):
    path = root / f"{name}.py"
    path.write_text(source)
    return SimpleNamespace(path=path, tree=ast.parse(source))


def _definition(path):
    return SimpleNamespace(
        filename=str(path),
        name="app.Model.setting",
        simple_name="setting",
        line=2,
        type="variable",
        is_descriptor=False,
        confidence=90,
        skip_reason=None,
        suppression_code=None,
        references=0,
        called_by=set(),
    )


def test_classless_files_need_no_property_mutation_proof(tmp_path, monkeypatch):
    parsed = _parsed(
        tmp_path,
        "app",
        "import yaml\ndata = input()\n"
        + "".join(f"yaml.load(data, Loader=missing_{i})\n" for i in range(400)),
    )
    original = descriptors._mutations
    calls = []

    def counted(modules):
        calls.append(len(modules))
        return original(modules)

    monkeypatch.setattr(descriptors, "_mutations", counted)
    assert (
        descriptors.classify_property_descriptors(
            {}, iter([parsed]), {parsed.path: "app"}
        )
        == []
    )
    assert calls == []


@pytest.mark.parametrize("tampered", [False, True])
def test_any_class_preserves_mutations_in_classless_files(tmp_path, tampered):
    other = _parsed(
        tmp_path,
        "other",
        "import builtins\n"
        + ("builtins.property = lambda *args: 7\n" if tampered else "unused = 7\n"),
    )
    app = _parsed(
        tmp_path, "app", "class Model:\n    setting = property(lambda self: 1)\n"
    )
    definition = _definition(app.path)
    result = descriptors.classify_property_descriptors(
        {definition.name: definition},
        iter([other, app]),
        {other.path: "other", app.path: "app"},
    )
    assert result == ([] if tampered else [definition])
    assert definition.is_descriptor is (not tampered)
    assert definition.confidence == (90 if tampered else 0)
    assert definition.references == 0
    assert definition.called_by == set()
    assert definition.skip_reason == (
        None if tampered else "source-proven property descriptor declaration"
    )
