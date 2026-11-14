"""A package that re-exports an object under its submodule's name.

haystack: ``haystack/core/component/__init__.py`` runs
``from haystack.core.component.component import component``, which replaces
the submodule attribute with the ``_Component()`` decorator object. Code that
imports ``component`` from the package calls ``component.output_types(...)``
on that object, so a member missing from the submodule is not a phantom.
"""

import shutil
import tempfile
import textwrap
from pathlib import Path

import pytest

from skylos.rules.ai_defect.phantom_refs import scan_repo_phantom_security_references

PHANTOM_RULES = {"SKY-L012", "SKY-L023"}

SUBMODULE = """
    class _Component:
        def output_types(self, **types):
            def wrap(cls):
                return cls
            return wrap

    component = _Component()

    def helper():
        return 1
"""


def _scan(files):
    tmpdir = tempfile.mkdtemp()
    try:
        root = Path(tmpdir).resolve()
        (root / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        for rel_path, content in files.items():
            target = root / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(textwrap.dedent(content), encoding="utf-8")
        findings = scan_repo_phantom_security_references(root, sorted(root.rglob("*.py")))
        return sorted(
            (f["rule_id"], f["name"])
            for f in findings
            if f["rule_id"] in PHANTOM_RULES
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _project(init, user):
    return {
        "pkg/__init__.py": "",
        "pkg/core/__init__.py": init,
        "pkg/core/component.py": SUBMODULE,
        "pkg/user.py": user,
    }


OBJECT_REEXPORT = "from pkg.core.component import component\n"

USES = """
    from pkg.core import component

    @component.output_types(answer=str)
    class Answer:
        pass

    def build():
        return component.output_types(answer=str)
"""


def test_object_reexported_over_its_submodule_is_not_a_phantom():
    assert _scan(_project(OBJECT_REEXPORT, USES)) == []


def test_relative_object_reexport_is_not_a_phantom():
    assert _scan(_project("from .component import component\n", USES)) == []


def test_object_reexport_reached_through_an_attribute_chain_is_not_a_phantom():
    user = """
        import pkg.core

        def build():
            return pkg.core.component.output_types(answer=str)
    """
    assert _scan(_project(OBJECT_REEXPORT, user)) == []


def test_conditional_reexport_leaves_the_name_unproven():
    init = """
        try:
            from .component import component
        except ImportError:
            pass
    """
    assert _scan(_project(init, USES)) == []


@pytest.mark.parametrize(
    "init",
    [
        "",
        "from . import component\n",
        "from .component import helper\n",
        "import pkg.core.component as component\n",
    ],
)
def test_name_that_is_the_submodule_still_reports_a_missing_member(init):
    user = """
        from pkg.core import component

        @component.missing_decorator
        def view():
            return component.missing_call()
    """
    assert _scan(_project(init, user)) == [
        ("SKY-L012", "component.missing_call"),
        ("SKY-L023", "component.missing_decorator"),
    ]


def test_submodule_reached_through_a_chain_still_reports_a_missing_member():
    user = """
        import pkg.core.component

        def build():
            return pkg.core.component.missing_call()
    """
    assert _scan(_project("from .component import helper\n", user)) == [
        ("SKY-L012", "pkg.core.component.missing_call"),
    ]


def test_other_names_in_the_same_package_still_report():
    init = OBJECT_REEXPORT
    files = _project(init, USES)
    files["pkg/core/tools.py"] = "def run():\n    return 1\n"
    files["pkg/other.py"] = """
        from pkg.core import tools

        def go():
            return tools.missing_tool()
    """
    assert _scan(files) == [("SKY-L012", "tools.missing_tool")]


def test_comprehension_variable_shadows_a_module_import():
    files = _project("", "")
    files["pkg/user.py"] = """
        from pkg.core import component

        def names(items):
            return [component.name for component in items]

        def pairs(items):
            return {component.key: component.value for component in items}

        def lazy(items):
            return list(component.label for component in items)
    """
    assert _scan(files) == []


def test_first_iterable_of_a_comprehension_still_reads_the_outer_name():
    files = _project("", "")
    files["pkg/user.py"] = """
        from pkg.core import component

        def names():
            return [component for component in component.missing_items()]
    """
    assert _scan(files) == [("SKY-L012", "component.missing_items")]


def test_comprehension_variable_does_not_leak_after_the_comprehension():
    files = _project("", "")
    files["pkg/user.py"] = """
        from pkg.core import component

        def names(items):
            found = [component for component in items]
            return found, component.missing_after()
    """
    assert _scan(files) == [("SKY-L012", "component.missing_after")]


LAZY_SUBMODULE = """
    from contextlib import suppress

    with suppress(ImportError):
        import json as encoder

        class Optional:
            pass
"""


def test_names_bound_inside_a_module_level_with_block_may_exist():
    files = {
        "pkg/__init__.py": "",
        "pkg/lazy.py": LAZY_SUBMODULE,
        "pkg/user.py": """
            from pkg import lazy

            def use():
                return lazy.encoder, lazy.Optional
        """,
    }
    assert _scan(files) == []


def test_names_never_bound_by_a_with_block_still_report():
    files = {
        "pkg/__init__.py": "",
        "pkg/lazy.py": LAZY_SUBMODULE,
        "pkg/user.py": """
            from pkg import lazy

            def use():
                return lazy.missing_name
        """,
    }
    assert _scan(files) == [("SKY-L012", "lazy.missing_name")]


@pytest.mark.parametrize(
    "module",
    [
        "import os\n\nif os.environ.get('X'):\n    class Optional:\n        pass\n",
        "for _name in ('a',):\n    Optional = _name\n",
        "import sys\n\nmatch sys.platform:\n    case 'linux':\n        Optional = 1\n",
        "if False:\n    Optional = 1\n",
        "import os\n\nif os.environ.get('X'):\n    Other = 1\n",
    ],
)
def test_names_bound_only_on_skippable_paths_still_report(module):
    files = {
        "pkg/__init__.py": "",
        "pkg/mod.py": module,
        "pkg/use.py": "from pkg.mod import Optional\n",
    }
    assert [rule for rule, _name in _scan(files)] == ["SKY-L012"]


PLAIN_OBJECT = "class Obj:\n    pass\n\ncomponent = Obj()\n"
OTHER_MODULE = "def real():\n    return 1\n"
EXPLICIT_USE = """
    import pkg.core.component

    def build():
        return pkg.core.component.missing_call()
"""
FROM_USE = """
    from pkg.core import component

    def build():
        return component.missing_call()
"""


@pytest.mark.parametrize(
    "init",
    [PLAIN_OBJECT, "from pkg.other import component\n"],
    ids=["assigned_object", "object_from_another_module"],
)
def test_loading_the_submodule_replaces_an_object_bound_before_it(init):
    files = _project(init, EXPLICIT_USE)
    files["pkg/other.py"] = OTHER_MODULE + "component = object()\n"
    assert _scan(files) == [("SKY-L012", "pkg.core.component.missing_call")]


def test_object_bound_after_its_submodule_loaded_survives_a_later_import():
    user = """
        import pkg.core.component

        def build():
            return pkg.core.component.output_types(answer=str)
    """
    assert _scan(_project(OBJECT_REEXPORT, user)) == []


def test_package_alias_to_another_module_is_followed():
    files = _project("from pkg import other as component\n", FROM_USE)
    files["pkg/other.py"] = OTHER_MODULE
    assert _scan(files) == [("SKY-L012", "component.missing_call")]
    files["pkg/user.py"] = "from pkg.core import component\n\ndef build():\n    return component.real()\n"
    assert _scan(files) == []


def test_bare_annotation_creates_no_binding():
    assert _scan(_project("component: object\n", FROM_USE)) == [
        ("SKY-L012", "component.missing_call")
    ]


def test_object_reexported_through_another_package_is_not_a_phantom():
    files = _project(OBJECT_REEXPORT, "")
    files["pkg/api/__init__.py"] = "from pkg.core import component\n"
    files["pkg/user.py"] = """
        import pkg.api

        def build():
            return pkg.api.component.output_types(answer=str)
    """
    assert _scan(files) == []


@pytest.mark.parametrize(
    ("init", "user"),
    [
        ("from pkg import other as component\n", EXPLICIT_USE),
        (
            "import os\nif os.environ.get('OPTIONAL'):\n    component = object()\n"
            "from pkg import other as component\n",
            FROM_USE,
        ),
        ("from pkg import other\ncomponent = other\n", FROM_USE),
        ("from pkg import other\ncomponent: object = other\n", FROM_USE),
        ("from pkg.other import *\n", FROM_USE),
    ],
    ids=["fresh-child-over-alias", "final-binding-over-branch", "assigned-module", "annotated-module", "unrelated-star"],
)
def test_proven_module_bindings_keep_missing_member_findings(init, user):
    files = _project(init, user)
    files["pkg/other.py"] = OTHER_MODULE
    findings = _scan(files)
    assert len(findings) == 1
    assert findings[0][0] == "SKY-L012"
    assert findings[0][1].endswith("component.missing_call")


@pytest.mark.parametrize(
    "user",
    [
        "import pkg.core\npkg.core.component.output_types()\nimport pkg.core.component\n",
        "import pkg.core\nif False:\n    import pkg.core.component\n"
        "pkg.core.component.output_types()\n",
        "import pkg.core\ndef unused():\n    import pkg.core.component\n"
        "pkg.core.component.output_types()\n",
        "from typing import TYPE_CHECKING\nimport pkg.core\nif TYPE_CHECKING:\n"
        "    import pkg.core.component\npkg.core.component.output_types()\n",
    ],
    ids=["later", "dead-branch", "uncalled-function", "type-checking-only"],
)
def test_unexecuted_child_import_does_not_replace_package_object(user):
    init = SUBMODULE
    assert _scan(_project(init, user)) == []


def test_separate_child_load_and_object_rebinding_survives_cached_import():
    init = "from . import component\n" + textwrap.dedent(SUBMODULE)
    user = "import pkg.core.component\npkg.core.component.output_types()\n"
    assert _scan(_project(init, user)) == []


def test_star_import_respects_explicit_exports_and_real_object_exports():
    files = _project("from pkg.other import *\n", FROM_USE)
    files["pkg/other.py"] = textwrap.dedent(SUBMODULE) + "\n__all__ = ['helper']\n"
    assert _scan(files) == [("SKY-L012", "component.missing_call")]
    files["pkg/other.py"] = SUBMODULE
    files["pkg/user.py"] = USES
    assert _scan(files) == []
