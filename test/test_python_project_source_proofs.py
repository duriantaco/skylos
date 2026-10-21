"""Source path effects are based on returned values and real providers."""

import ast
import textwrap

import pytest

from skylos.deadcode.python_project_sources import Choice, ProjectSourceIndex
from skylos.deadcode.python_browser_effects import project_script_entry_files
from test.fixture_paths import write_fixture


def _write(root, name, source):
    write_fixture(root, name, textwrap.dedent(source).lstrip())


def _listing(root, source):
    _write(root, "main.py", source)
    _write(root, "live.js", "var active = 1;\n")
    _write(root, "other.js", "var unrelated = 1;\n")
    index = ProjectSourceIndex(root, root.rglob("*.py"))
    result = index.listing_files(
        ast.parse("listing()", mode="eval").body, root / "main.py"
    )
    return {path.name for path in result or ()}


@pytest.mark.parametrize(
    "record",
    [
        "from dataclasses import dataclass\n@dataclass\nclass Entry:\n    path: str\n",
        'from collections import namedtuple\nEntry = namedtuple("Entry", "path")\n',
        "class Entry:\n    def __init__(self, value):\n        self.path = value\n",
    ],
)
def test_returned_source_records_have_only_their_actual_paths(tmp_path, record):
    assert _listing(
        tmp_path, record + 'def listing():\n    return [Entry("live.js").path]\n'
    ) == {"live.js"}


@pytest.mark.parametrize(
    "source",
    [
        'class Entry:\n    path: str\n    def __init__(self, value):\n        pass\ndef listing():\n    return [Entry("live.js").path]\n',
        'from dataclasses import dataclass\n@dataclass(init=False)\nclass Entry:\n    path: str\ndef listing():\n    return [Entry("live.js").path]\n',
        'import os\nos = None\ndef listing():\n    return os.listdir(".")\n',
        'import os\nalias = os\nalias.listdir = lambda value: []\ndef listing():\n    return os.listdir(".")\n',
        'from pathlib import Path\nPath.iterdir = lambda value: []\ndef listing():\n    return [str(value) for value in Path(".").iterdir()]\n',
        'import os\nsorted = None\ndef listing():\n    return sorted(os.listdir("."))\n',
        'import os\ndef listing():\n    os.listdir(".")\n    return []\n',
        'def real(value):\n    return ["live.js"]\ndef listing():\n    return real()\n',
        'def replace(function):\n    return lambda: []\n@replace\ndef values():\n    return ["live.js"]\ndef listing():\n    return values()\n',
    ],
)
def test_lookalikes_do_not_fabricate_returned_paths(tmp_path, source):
    assert _listing(tmp_path, source) == set()


@pytest.mark.parametrize(
    "call", ["mutate(item)", "mutate(item=item)", "mutate([item])"]
)
def test_unknown_record_escapes_cannot_prove_path_identity(tmp_path, call):
    source = (
        'from dataclasses import dataclass\nfrom remote import mutate\n@dataclass\nclass Entry:\n    path: str\ndef listing():\n    item = Entry("live.js")\n    '
        + call
        + "\n    return [item.path]\n"
    )
    assert _listing(tmp_path, source) == set()


def test_package_relative_reexport_resolves_the_actual_record(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "from .records import Entry\n")
    _write(
        tmp_path,
        "pkg/records.py",
        "from dataclasses import dataclass\n@dataclass\nclass Entry:\n    path: str\n",
    )
    assert _listing(
        tmp_path,
        'from pkg import Entry\ndef listing():\n    return [Entry("live.js").path]\n',
    ) == {"live.js"}


@pytest.mark.parametrize(
    "expression,expected",
    [
        ('value or "dead.js"', {"live.js", "other.js"}),
        ('value and "dead.js"', {"dead.js"}),
        ('"live.js" or "dead.js"', {"live.js"}),
        ('"live.js" and "other.js"', {"other.js"}),
    ],
)
def test_boolean_path_operands_preserve_python_value_flow(
    tmp_path, expression, expected
):
    _write(tmp_path, "main.py", "value = None\n")
    index = ProjectSourceIndex(tmp_path, [tmp_path / "main.py"])
    value = Choice(["live.js", "other.js"])
    assert (
        index.resolve_text(
            ast.parse(expression, mode="eval").body,
            tmp_path / "main.py",
            {"value": value},
        )
        == expected
    )


def test_cross_module_records_directory_effects_and_url_wrappers(tmp_path):
    _write(tmp_path, "client/one.js", "var active = 1;\n")
    _write(tmp_path, "other/client/orphan.js", "var orphan = 1;\n")
    _write(
        tmp_path,
        "pkg/locations.py",
        "from pathlib import Path\nBASE = Path(__file__).resolve().parent.parent\n",
    )
    _write(
        tmp_path,
        "pkg/assets.py",
        """
        import os
        from collections import namedtuple
        from dataclasses import dataclass
        from pkg.locations import BASE
        Asset = namedtuple("Asset", "name path")
        @dataclass
        class Wrapped:
            file: Asset
        def packaged(directory, suffix):
            entries = {}
            location = os.path.join(BASE, directory)
            for name in os.listdir(location):
                if not name.endswith(suffix):
                    continue
                entries[name] = Wrapped(Asset(name, os.path.join(location, name)))
            return [entry.file for entry in entries.values()]
    """,
    )
    _write(
        tmp_path,
        "pkg/page.py",
        """
        from pkg.assets import packaged
        def address(value):
            return f"file={value}?version={unknown_timestamp()}"
        def render():
            head = ""
            for entry in packaged("client", ".js"):
                head += f'<script src="{address(entry.path)}"></script>'
            return head
    """,
    )
    _write(tmp_path, "app.py", "from pkg.page import render\nprint(render())\n")
    index = ProjectSourceIndex(tmp_path, tmp_path.rglob("*.py"))

    assert project_script_entry_files(index) == {tmp_path / "client/one.js"}


def test_dormant_registry_writer_does_not_invalidate_unrelated_listing(tmp_path):
    source = 'import os\nimport sys\ndef unused(name):\n    sys.modules[name] = None\ndef listing():\n    return [name for name in os.listdir(".") if name.endswith(".js")]\n'
    assert _listing(tmp_path, source) == {"live.js", "other.js"}


def test_module_replacement_before_provider_import_is_unproven(tmp_path):
    source = 'import sys\nsys.modules["dataclasses"] = None\nfrom dataclasses import dataclass\n@dataclass\nclass Entry:\n    path: str\ndef listing():\n    return [Entry("live.js").path]\n'
    assert _listing(tmp_path, source) == set()


@pytest.mark.parametrize(
    "record,call,expected",
    [
        (
            'from dataclasses import dataclass, field\n@dataclass\nclass Entry:\n    path: str = field(init=False, default="other.js")\n    name: str\n',
            'Entry("live.js")',
            set(),
        ),
        (
            'from dataclasses import dataclass\nfrom typing import ClassVar\n@dataclass\nclass Entry:\n    path: ClassVar[str] = "other.js"\n    name: str\n',
            'Entry("live.js")',
            set(),
        ),
        (
            'from dataclasses import dataclass\n@dataclass\nclass Entry:\n    path: str = "live.js"\n',
            "Entry()",
            {"live.js"},
        ),
        (
            "from dataclasses import dataclass\n@dataclass(frozen=True)\nclass Entry:\n    path: str\n",
            'Entry("live.js")',
            {"live.js"},
        ),
    ],
)
def test_dataclass_constructor_fields_follow_owned_metadata(
    tmp_path, record, call, expected
):
    assert (
        _listing(tmp_path, record + f"def listing():\n    return [{call}.path]\n")
        == expected
    )


def test_positional_only_parameter_cannot_be_supplied_as_keyword(tmp_path):
    source = 'def files(value, /):\n    return [value]\ndef listing():\n    return files(value="live.js")\n'
    assert _listing(tmp_path, source) == set()


def test_dormant_provider_assignment_does_not_invalidate_live_listing(tmp_path):
    source = 'import os\ndef dormant():\n    os.listdir = lambda value: []\ndef listing():\n    return [value for value in os.listdir(".") if value.endswith(".js")]\n'
    assert _listing(tmp_path, source) == {"live.js", "other.js"}


def test_reachable_provider_assignment_invalidates_live_listing(tmp_path):
    source = 'import os\ndef change():\n    os.listdir = lambda value: []\ndef listing():\n    change()\n    return os.listdir(".")\n'
    assert _listing(tmp_path, source) == set()
