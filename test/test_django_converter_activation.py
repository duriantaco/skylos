"""Only source code that can reference a converter provider activates its pass."""

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from skylos.deadcode import django_converter_liveness as converters
from skylos.visitors.base import Definition


@pytest.mark.parametrize(
    "marker",
    [
        "# register_converter is documentation only\n",
        'DESCRIPTION = "register_converter"\n',
        '"""Example: register_converter(Converter, name)"""\n',
    ],
)
def test_documentation_marker_does_not_walk_an_unrelated_call_graph(
    tmp_path, monkeypatch, marker
):
    source = marker + "def f0():\n    return None\n"
    for index in range(1, 10):
        source += f"def f{index}():\n    f{index - 1}()\n    f{index - 1}()\n"
    source += "f9()\n"
    path = tmp_path / "app.py"
    path.write_text(source)
    tree = ast.parse(source)
    definitions = {
        "app." + node.name: Definition(
            "app." + node.name, "function", path, node.lineno, node
        )
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }

    def unnecessary_pass(*args, **kwargs):
        pytest.fail("Documentation must not activate project-wide converter analysis")

    monkeypatch.setattr(converters, "parse_python_files", unnecessary_pass)
    assert (
        converters.find_django_converter_classes(definitions, [path], tmp_path)
        == frozenset()
    )


def test_converter_scanner_source_is_not_itself_a_registration_candidate():
    assert not converters._project_may_register_converters(
        {}, [Path(converters.__file__)]
    )


@pytest.mark.parametrize(
    "source",
    [
        "from adapter import register_converter as register\nregister(Converter, 'custom')\n",
        "import adapter\nadapter.register_converter(Converter, 'custom')\n",
        "from adapter import registry\nregister = registry['register_converter']\nregister(Converter, 'custom')\n",
        "from adapter import registry\nregister = registry['nested.register_converter']\nregister(Converter, 'custom')\n",
        "# register_converter\nfrom adapter import ｒｅｇｉｓｔｅｒ_converter as register\nregister(Converter, 'custom')\n",
        "# register_converter\nimport adapter\nadapter.ｒｅｇｉｓｔｅｒ_converter(Converter, 'custom')\n",
        'f"{provider.register_converter(Converter, name)}"\n',
    ],
)
def test_code_level_provider_forms_remain_eligible(tmp_path, source):
    path = tmp_path / "app.py"
    path.write_text(source)
    assert converters._project_may_register_converters({}, [path])


def test_actual_django_import_does_not_require_a_named_registration(tmp_path):
    definitions = {"django": SimpleNamespace(type="import", name="django.urls")}
    assert converters._project_may_register_converters(definitions, [])


@pytest.mark.parametrize(
    "source",
    [
        "# register_converter\nx = (\n",
        "# register_converter\n    unexpected_indent = 1\n",
    ],
)
def test_ambiguous_source_does_not_prove_converter_pass_unnecessary(tmp_path, source):
    path = tmp_path / "app.py"
    path.write_text(source)
    assert converters._project_may_register_converters({}, [path])


def test_unreadable_source_keeps_converter_pass_eligible(tmp_path, monkeypatch):
    path = tmp_path / "app.py"
    path.write_text("# register_converter\n")

    def denied(*args, **kwargs):
        raise PermissionError("source cannot be inspected")

    monkeypatch.setattr(Path, "read_text", denied)
    assert converters._project_may_register_converters({}, [path])
