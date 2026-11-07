"""Native Robot configuration keeps exact objects, never similarly named code."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze


def _scan(tmp_path, sources):
    for name, source in sources.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    result = json.loads(
        analyze(
            str(tmp_path),
            conf=0,
            grep_verify=False,
            grep_cache=False,
            trace_file=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert result.get("analysis_errors", []) == []
    return result


def _unused(result):
    return {row["full_name"] for row in result.get("unused_functions", [])}


def _roots(result):
    return {
        row["name"]
        for row in result["analysis_summary"]["dead_code_liveness"]["rescued"]
        if row["reason"].startswith("robot_")
    }


@pytest.mark.parametrize(
    "prefix,application",
    [
        (
            "from robot.api.deco import library\n",
            "Library = library(auto_keywords=True)(Library)",
        ),
        (
            "from robot.api.deco import library as native_library\n",
            "Library = native_library(auto_keywords=True)(Library)",
        ),
        (
            "import robot.api.deco as deco\n",
            "Library = deco.library(auto_keywords=True)(Library)",
        ),
        (
            "from robot.api.deco import library\n"
            "decorate = library(auto_keywords=True)\n",
            "Library = decorate(Library)",
        ),
    ],
)
def test_programmatic_native_library_retains_the_original_class(
    tmp_path, prefix, application
):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    actions.py\n",
            "actions.py": prefix + "class Library:\n"
            "    def live_keyword(self): return self._implementation()\n"
            "    def _implementation(self): return 42\n"
            "    def _dead_helper(self): return 0\n" + application,
        },
    )
    assert "actions.Library.live_keyword" not in _unused(result)
    assert "actions.Library._implementation" not in _unused(result)
    assert "actions.Library._dead_helper" in _unused(result)
    assert "actions.Library.live_keyword" in _roots(result)


@pytest.mark.parametrize("application", ["library(Library)", "library()(Library)"])
def test_programmatic_native_library_keeps_auto_keywords_off_by_default(
    tmp_path, application
):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    actions.py\n",
            "actions.py": "from robot.api.deco import keyword, library\n"
            "class Library:\n"
            "    @keyword\n"
            "    def _explicit_keyword(self): pass\n"
            "    def unused_helper(self): pass\n"
            f"Library = {application}\n",
        },
    )
    assert "actions.Library._explicit_keyword" in _roots(result)
    assert "actions.Library.unused_helper" in _unused(result)
    assert "actions.Library.unused_helper" not in _roots(result)


@pytest.mark.parametrize(
    "prefix,application",
    [
        (
            "def library(**kwargs): return lambda cls: None\n",
            "Library = library(auto_keywords=True)(Library)",
        ),
        (
            "from robot.api.deco import library\n"
            "library = lambda **kwargs: lambda cls: None\n",
            "Library = library(auto_keywords=True)(Library)",
        ),
        (
            "import robot.api.deco as deco\n"
            "deco.library = lambda **kwargs: lambda cls: None\n",
            "Library = deco.library(auto_keywords=True)(Library)",
        ),
        (
            "from robot.api.deco import library\n"
            "decorate = library(auto_keywords=True)\n"
            "decorate = lambda cls: None\n",
            "Library = decorate(Library)",
        ),
        (
            "from robot.api.deco import library\n",
            "Library = library(auto_keywords=False)(Library)",
        ),
    ],
)
def test_programmatic_library_lookalikes_do_not_retain_helpers(
    tmp_path, prefix, application
):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    actions.py\n",
            "actions.py": prefix
            + "class Library:\n    def dead_helper(self): pass\n"
            + application,
        },
    )
    assert "actions.Library.dead_helper" in _unused(result)
    assert "actions.Library.dead_helper" not in _roots(result)


_VALUES = """\
class ExampleObject:
    def used(self, *args, **kwargs): return self._implementation()
    def _implementation(self): return 42
    def unused_helper(self): return 0
class Other:
    def used(self): return -1
OBJ = ExampleObject()
OTHER = Other()
"""


@pytest.mark.parametrize(
    "expression",
    [
        "${OBJ.used()}",
        "${ o_b J .used()}",
        "&{OBJ.used()}",
        "@{OBJ.used(1, label='value')}",
        r"\\${OBJ.used()}",
    ],
)
def test_extended_variables_retain_only_the_called_objects_method(tmp_path, expression):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    values.py\n"
            "*** Test Cases ***\nExercise\n    Log    " + expression,
            "values.py": _VALUES,
        },
    )
    assert "values.ExampleObject.used" not in _unused(result)
    assert "values.ExampleObject._implementation" not in _unused(result)
    assert "values.ExampleObject.unused_helper" in _unused(result)
    assert "values.Other.used" in _unused(result)
    assert "values.ExampleObject.used" in _roots(result)
    assert "values.Other.used" not in _roots(result)


@pytest.mark.parametrize(
    "robot",
    [
        "*** Test Cases ***\nExercise\n    # ${OBJ.used()}",
        "*** Test Cases ***\nExercise\n    Log    \\${OBJ.used()}",
        "*** Comments ***\n${OBJ.used()}",
        "*** Test Cases ***\nExercise\n    Log    ${MISSING.used()}",
        "*** Variables ***\n${OBJ}    replacement\n"
        "*** Test Cases ***\nExercise\n    Log    ${OBJ.used()}",
        "*** Test Cases ***\nExercise\n    ${OBJ}=    Set Variable    replacement\n"
        "    Log    ${OBJ.used()}",
    ],
)
def test_extended_variable_mentions_or_rebindings_do_not_prove_object_use(
    tmp_path, robot
):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    values.py\n" + robot,
            "values.py": _VALUES,
        },
    )
    assert "values.ExampleObject.used" in _unused(result)
    assert "values.ExampleObject.unused_helper" in _unused(result)
    assert "values.Other.used" in _unused(result)
    assert "values.ExampleObject.used" not in _roots(result)


@pytest.mark.parametrize(
    "suffix",
    [
        "OBJ = OTHER\n",
        "OBJ = unknown_factory()\n",
        "OBJ.used = lambda: 7\n",
        "ALIAS = OBJ\nALIAS.used = lambda: 7\n",
        "ExampleObject.used = lambda self: 7\n",
    ],
)
def test_extended_variables_do_not_trust_replaced_instances_or_methods(
    tmp_path, suffix
):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    values.py\n"
            "*** Test Cases ***\nExercise\n    Log    ${OBJ.used()}",
            "values.py": _VALUES + suffix,
        },
    )
    assert "values.ExampleObject.used" not in _roots(result)
    # Existing receiver uncertainty can already hide this helper after writes.
    # The new Robot proof must not upgrade it into proven framework liveness.
    assert "values.ExampleObject.unused_helper" not in _roots(result)


def test_extended_variables_follow_only_imported_resources(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\n"
            "Resource    resources/common.resource\n"
            "*** Test Cases ***\nExercise\n    Log    ${OBJ.used()}\n",
            "resources/common.resource": "*** Settings ***\n"
            "Variables    ../values.py\n",
            "unimported.resource": "*** Keywords ***\nUncalled\n"
            "    Log    ${OTHER.used()}\n",
            "values.py": _VALUES,
        },
    )
    assert "values.ExampleObject.used" in _roots(result)
    assert "values.Other.used" in _unused(result)


def test_variable_getter_does_not_export_module_objects_as_well(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    values.py\n"
            "*** Test Cases ***\nExercise\n    Log    ${OBJ.used()}",
            "values.py": _VALUES + "def get_variables(): return {'OBJ': 7}\n",
        },
    )
    assert "values.ExampleObject.used" not in _roots(result)


@pytest.mark.parametrize(
    "expression",
    ["${OBJ.Used()}", "${OBJ.child.used()}", "${OBJ.used}", "${OBJ.used() extra}"],
)
def test_unresolved_extended_expressions_do_not_match_method_spellings(
    tmp_path, expression
):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    values.py\n"
            "*** Test Cases ***\nExercise\n    Log    " + expression,
            "values.py": _VALUES,
        },
    )
    assert "values.ExampleObject.used" in _unused(result)
    assert "values.Other.used" in _unused(result)
    assert "values.ExampleObject.used" not in _roots(result)


@pytest.mark.parametrize(
    "member",
    [
        "def __new__(cls): return unknown_object\n",
        "def __getattr__(self, name): return unknown_value\n",
        "def __init__(self): self.used = lambda: 0\n",
        "def __init__(self):\n    alias = self\n    alias.used = lambda: 0\n",
        "def __init__(self): setattr(self, unknown_name, lambda: 0)\n",
        "def __init__(self): install_methods(self)\n",
    ],
)
def test_dynamic_construction_and_receiver_rewrites_do_not_prove_methods(
    tmp_path, member
):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    values.py\n"
            "*** Test Cases ***\nExercise\n    Log    ${OBJ.used()}",
            "values.py": "class ExampleObject:\n"
            + textwrap.indent(member, "    ")
            + "    def used(self): pass\nOBJ = ExampleObject()\n",
        },
    )
    assert "values.ExampleObject.used" not in _roots(result)


@pytest.mark.parametrize(
    "suffix", ["Library.ROBOT_AUTO_KEYWORDS = False", "Library = None"]
)
def test_later_library_policy_or_binding_changes_are_not_ignored(tmp_path, suffix):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    actions.py\n",
            "actions.py": "from robot.api.deco import library\n"
            "class Library:\n    def unused_helper(self): pass\n"
            "Library = library(auto_keywords=True)(Library)\n" + suffix,
        },
    )
    assert "actions.Library.unused_helper" not in _roots(result)


def test_object_constructor_alias_keeps_the_class_binding_at_construction(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    values.py\n"
            "*** Test Cases ***\nExercise\n    Log    ${OBJ.used()}",
            "values.py": "class ExampleObject:\n    def used(self): pass\n"
            "class Other:\n    def used(self): pass\n"
            "Alias = ExampleObject\nOBJ = Alias()\nAlias = Other\n",
        },
    )
    assert "values.ExampleObject.used" in _roots(result)
    assert "values.Other.used" not in _roots(result)


def test_resource_keyword_bodies_are_not_treated_as_executed_expressions(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    values.py\n"
            "Resource    common.resource\n*** Test Cases ***\nExercise\n    No Operation",
            "common.resource": "*** Keywords ***\nUncalled\n    Log    ${OBJ.used()}",
            "values.py": _VALUES,
        },
    )
    assert "values.ExampleObject.used" in _unused(result)
    assert "values.ExampleObject.used" not in _roots(result)


@pytest.mark.parametrize(
    "patch",
    [
        "if True:\n    ExampleObject.used = lambda self: 0\n",
        "if True:\n    OBJ.used = lambda: 0\n",
        "if True:\n    alias = OBJ\n    alias.used = lambda: 0\n",
        "if True:\n    Alias = ExampleObject\n    Alias.used = lambda self: 0\n",
        "def patch():\n    OBJ.used = lambda: 0\npatch()\n",
        "def patch():\n    Alias = ExampleObject\n    Alias.used = lambda self: 0\npatch()\n",
    ],
)
def test_visible_nested_or_called_patches_do_not_prove_the_original_method(
    tmp_path, patch
):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    values.py\n"
            "*** Test Cases ***\nExercise\n    Log    ${OBJ.used()}",
            "values.py": _VALUES + patch,
        },
    )
    assert "values.ExampleObject.used" not in _roots(result)


@pytest.mark.parametrize(
    "options",
    ["OtherClass, auto_keywords=True", "scope=OtherClass, auto_keywords=True"],
)
def test_library_class_argument_is_not_a_decorator_factory(tmp_path, options):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    actions.py\n",
            "actions.py": "from robot.api.deco import library\n"
            "class OtherClass:\n    def __init__(self, value): pass\n"
            "class Library:\n    def unused_helper(self): pass\n"
            f"Library = library({options})(Library)\n",
        },
    )
    assert "actions.Library.unused_helper" not in _roots(result)


def test_native_positional_scope_remains_a_real_library_factory(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    actions.py\n",
            "actions.py": "from robot.api.deco import library\n"
            "class Library:\n    def live_keyword(self): pass\n"
            "Library = library('GLOBAL', auto_keywords=True)(Library)\n",
        },
    )
    assert "actions.Library.live_keyword" in _roots(result)


def test_foreign_receiver_parameter_patch_does_not_replace_the_exported_object(
    tmp_path,
):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    values.py\n"
            "*** Test Cases ***\nExercise\n    Log    ${OBJ.used()}",
            "values.py": _VALUES + "def patch(OBJ):\n    OBJ.used = lambda: 0\n",
        },
    )
    assert "values.ExampleObject.used" in _roots(result)


def test_conditional_imported_class_alias_patch_is_not_ignored(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    values.py\n"
            "*** Test Cases ***\nExercise\n    Log    ${OBJ.used()}",
            "values.py": _VALUES + "import patcher\n",
            "patcher.py": "import values\nif True:\n"
            "    Alias = values.ExampleObject\n    Alias.used = lambda self: 0\n",
        },
    )
    assert "values.ExampleObject.used" not in _roots(result)


@pytest.mark.parametrize("argument", ["OBJ", "ExampleObject", "value=OBJ"])
def test_passing_the_instance_or_class_to_a_patcher_does_not_prove_methods(
    tmp_path, argument
):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    values.py\n"
            "*** Test Cases ***\nExercise\n    Log    ${OBJ.used()}",
            "values.py": _VALUES
            + "def rewrite(value):\n    value.used = lambda *args: 0\n"
            + f"rewrite({argument})\n",
        },
    )
    assert "values.ExampleObject.used" not in _roots(result)


def test_passing_an_imported_instance_to_a_patcher_is_not_ignored(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    values.py\n"
            "*** Test Cases ***\nExercise\n    Log    ${OBJ.used()}",
            "values.py": _VALUES + "import patcher\n",
            "patcher.py": "from values import OBJ\n"
            "def rewrite(value):\n    value.used = lambda: 0\nrewrite(OBJ)\n",
        },
    )
    assert "values.ExampleObject.used" not in _roots(result)


def test_passing_a_different_object_to_a_patcher_preserves_the_exact_receiver(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    values.py\n"
            "*** Test Cases ***\nExercise\n    Log    ${OBJ.used()}",
            "values.py": _VALUES
            + "def rewrite(value):\n    value.used = lambda: 0\nrewrite(OTHER)\n",
        },
    )
    assert "values.ExampleObject.used" in _roots(result)
