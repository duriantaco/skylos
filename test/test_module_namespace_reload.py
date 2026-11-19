"""A method named ``reload`` with nothing to reload is not a module reload."""

import ast

import pytest

from skylos.rules.danger.module_namespace import module_rebinding


def _dynamic(source):
    return module_rebinding(ast.parse(source), "app")[0]


@pytest.mark.parametrize(
    "source",
    [
        # Docker SDK, ORM documents and config objects refresh themselves.
        "def refresh(container):\n    container.reload()\n",
        "def refresh(doc):\n    doc.reload()\n    return doc\n",
    ],
    ids=["docker-container", "orm-document"],
)
def test_argumentless_reload_method_does_not_make_globals_dynamic(source):
    assert _dynamic(source) is False


@pytest.mark.parametrize(
    "source",
    [
        "import importlib\nimport app\nimportlib.reload(app)\n",
        "from importlib import reload\nimport app\nreload(app)\n",
        "import importlib as il\nimport app\nil.reload(module=app)\n",
        "from importlib import reload as again\nimport app\nagain(app)\n",
    ],
    ids=["importlib", "from-import", "keyword", "alias"],
)
def test_module_reload_still_makes_globals_dynamic(source):
    assert _dynamic(source) is True
