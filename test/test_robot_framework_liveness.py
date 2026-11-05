"""Robot providers are read statically; fixtures are never imported."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze


def _scan(tmp_path, sources, **options):
    for name, source in sources.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    return json.loads(analyze(str(tmp_path), conf=0, grep_verify=False, **options))


def _names(result, bucket="unused_functions"):
    return {item["full_name"] for item in result.get(bucket, [])}


@pytest.mark.parametrize(
    "setting",
    [
        "Library    Actions.py    AS    My Actions",
        "Library\tActions.py",
        "| Library | Actions.py | WITH NAME | My Actions |",
        "Library\n...    ${CURDIR}${/}Actions.py",
    ],
)
def test_named_class_library_exposes_keywords_and_their_helpers(tmp_path, setting):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\n" + setting,
            "Actions.py": """
                class Actions:
                    def public_keyword(self): return self._implementation()
                    def _implementation(self): return 42
                    def _unused_helper(self): return 0
                class Unrelated:
                    def unrelated_method(self): return 0
            """,
            "elsewhere.py": "class Actions:\n    def unrelated_keyword(self): pass",
        },
    )
    unused = _names(result)
    assert "Actions.Actions.public_keyword" not in unused
    assert "Actions.Actions._implementation" not in unused
    assert "Actions.Actions._unused_helper" in unused
    assert "Actions.Actions" not in _names(result, "unused_classes")
    assert "Actions.Unrelated" in _names(result, "unused_classes")
    assert "elsewhere.Actions" in _names(result, "unused_classes")


def test_module_library_uses_final_bindings_and_literal_all(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    keywords.py",
            "keywords.py": """
                __all__ = ['exposed', 'replaced']
                def exposed(): return _helper()
                def _helper(): return 42
                def excluded(): pass
                def replaced(): pass
                replaced = None
            """,
        },
    )
    assert "keywords.exposed" not in _names(result)
    assert "keywords._helper" not in _names(result)
    assert "keywords.excluded" in _names(result)
    rescued = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert not any(item["name"] == "keywords.replaced" for item in rescued)


def test_keyword_discovery_respects_robot_decorators_and_auto_keywords(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    Keywords.py\nLibrary    module.py",
            "Keywords.py": """
                from robot.api.deco import keyword as kw, library, not_keyword
                @library
                class Keywords:
                    @kw('Explicit name')
                    def _explicit_keyword(self): pass
                    def public_helper(self): pass
                    @not_keyword
                    def disabled_keyword(self): pass
            """,
            "module.py": """
                from robot.api.deco import keyword
                ROBOT_AUTO_KEYWORDS = False
                @keyword
                def explicit_keyword(): pass
                def public_helper(): pass
            """,
        },
    )
    unused = _names(result)
    assert "Keywords.Keywords._explicit_keyword" not in unused
    assert "module.explicit_keyword" not in unused
    assert "Keywords.Keywords.public_helper" in unused
    assert "Keywords.Keywords.disabled_keyword" in unused
    assert "module.public_helper" in unused


def test_dotted_class_import_preserves_inherited_keywords(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    pkg.tools.Child",
            "pkg/__init__.py": "",
            "pkg/tools.py": """
                from .base import Parent
                class Child(Parent):
                    def own_keyword(self): pass
            """,
            "pkg/base.py": """
                class Parent:
                    def inherited_keyword(self): pass
                    def _unused_helper(self): pass
            """,
        },
    )
    assert "pkg.tools.Child.own_keyword" not in _names(result)
    assert "pkg.base.Parent.inherited_keyword" not in _names(result)
    assert "pkg.base.Parent._unused_helper" in _names(result)


def test_static_variable_files_are_scoped_to_the_named_provider(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    data/vars.py",
            "data/vars.py": "EXPORTED_VALUE = 42\n_private_value = 1\n",
            "other/vars.py": "UNRELATED_VALUE = 1\n",
        },
    )
    unused = _names(result, "unused_variables")
    assert "data.vars.EXPORTED_VALUE" not in unused
    assert "other.vars.UNRELATED_VALUE" in unused


def test_public_imports_in_a_variable_file_are_exported_values(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    data.py",
            "data.py": "import math\nfrom decimal import Decimal",
            "other.py": "import statistics",
        },
    )
    unused = _names(result, "unused_imports")
    assert "math" not in unused
    assert "Decimal" not in unused
    assert "statistics" in unused


def test_variable_file_all_and_dynamic_getter_do_not_export_every_value(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": (
                "*** Settings ***\nVariables    selected.py\nVariables    dynamic.py"
            ),
            "selected.py": "__all__ = ['EXPORTED']\nEXPORTED = 1\nUNEXPORTED = 2",
            "dynamic.py": """
                def get_variables(): return _values()
                def _values(): return {'VALUE': 42}
                UNUSED_VALUE = 10
            """,
        },
    )
    unused = _names(result, "unused_variables")
    assert "selected.EXPORTED" not in unused
    assert "selected.UNEXPORTED" in unused
    assert "dynamic.UNUSED_VALUE" in unused
    assert "dynamic.get_variables" not in _names(result)
    assert "dynamic._values" not in _names(result)


def test_resource_imports_resolve_literal_variables_and_relative_paths(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nResource    resources/common.resource",
            "resources/common.resource": """
                *** Settings ***
                Library    ${LIBRARY}
                Variables    ${CURDIR}/../data.py
                *** Variables ***
                ${LIBRARY}    ${CURDIR}/../keywords.py
            """,
            "keywords.py": "def exposed_keyword(): pass",
            "data.py": "VALUE = 42",
        },
    )
    assert "keywords.exposed_keyword" not in _names(result)
    assert "data.VALUE" not in _names(result, "unused_variables")


@pytest.mark.parametrize(
    "robot_source",
    [
        "*** Test Cases ***\nLibrary    keywords.py\nVariables    data.py",
        "*** Settings ***\n# Library    keywords.py\n# Variables    data.py",
        "*** Settings ***\nDocumentation    Library    keywords.py\n...    Variables    data.py",
        "*** Settings ***\nLibrary    ${UNKNOWN}/keywords.py\nVariables    ${UNKNOWN}/data.py",
        "*** Settings ***\nLibrary    absent/keywords.py\nVariables    absent/data.py",
    ],
)
def test_mentions_and_unresolved_imports_do_not_rescue_providers(
    tmp_path, robot_source
):
    result = _scan(
        tmp_path,
        {
            "suite.robot": robot_source,
            "keywords.py": "def dead_keyword(): pass",
            "data.py": "DEAD_VALUE = 42",
        },
    )
    assert "keywords.dead_keyword" in _names(result)
    assert "data.DEAD_VALUE" in _names(result, "unused_variables")


def test_excluded_robot_files_do_not_supply_entrypoints(tmp_path):
    result = _scan(
        tmp_path,
        {
            "excluded/suite.robot": "*** Settings ***\nLibrary    ../keywords.py",
            "keywords.py": "def dead_keyword(): pass",
        },
        exclude_folders=["excluded"],
    )
    assert "keywords.dead_keyword" in _names(result)


def test_builtin_library_is_implicit_only_in_a_robot_project(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Test Cases ***\nExample\n    Log    hello",
            "src/robot/__init__.py": "",
            "src/robot/libraries/__init__.py": "",
            "src/robot/libraries/BuiltIn.py": """
                class BuiltIn:
                    def log(self, message): return _format(message)
                    def _unused_helper(self): pass
                def _format(message): return str(message)
            """,
        },
    )
    assert "robot.libraries.BuiltIn.BuiltIn.log" not in _names(result)
    assert "robot.libraries.BuiltIn._format" not in _names(result)
    assert "robot.libraries.BuiltIn.BuiltIn._unused_helper" in _names(result)
    (tmp_path / "suite.robot").unlink()
    without_robot = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    assert "robot.libraries.BuiltIn.BuiltIn" in _names(without_robot, "unused_classes")
    assert "robot.libraries.BuiltIn._format" in _names(without_robot)


def test_unrelated_import_roots_and_ambiguous_modules_stay_dead(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": (
                "*** Settings ***\nLibrary    keywords\nVariables    data\n"
                "Library    ambiguous"
            ),
            "unrelated/keywords.py": "def dead_keyword(): pass",
            "unrelated/data.py": "DEAD_VALUE = 42",
            "ambiguous.py": "def first_dead_keyword(): pass",
            "src/ambiguous.py": "def second_dead_keyword(): pass",
        },
    )
    assert _names(result) == {
        "unrelated.keywords.dead_keyword",
        "ambiguous.first_dead_keyword",
        "ambiguous.second_dead_keyword",
    }
    assert "unrelated.data.DEAD_VALUE" in _names(result, "unused_variables")


def test_hybrid_library_only_exposes_the_returned_keyword_names(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    Hybrid.py",
            "Hybrid.py": """
                class Hybrid:
                    def get_keyword_names(self): return ['selected_keyword']
                    def selected_keyword(self): return _implementation()
                    def unlisted_helper(self): pass
                def _implementation(): return 42
            """,
        },
    )
    assert "Hybrid.Hybrid.get_keyword_names" not in _names(result)
    assert "Hybrid.Hybrid.selected_keyword" not in _names(result)
    assert "Hybrid._implementation" not in _names(result)
    assert "Hybrid.Hybrid.unlisted_helper" in _names(result)


def test_auto_keywords_policy_is_inherited_from_the_selected_base(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    Child.py",
            "Child.py": """
                from robot.api.deco import library, keyword
                @library
                class Parent:
                    def unused_helper(self): pass
                class Child(Parent):
                    @keyword
                    def exposed_keyword(self): pass
                    def another_unused_helper(self): pass
            """,
        },
    )
    assert "Child.Parent.unused_helper" in _names(result)
    assert "Child.Child.another_unused_helper" in _names(result)


def test_replaced_library_and_variable_classes_do_not_get_roots(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    replaced.Live\nVariables    replaced.Data",
            "replaced.py": """
                class Live:
                    def dead_keyword(self): pass
                class Data:
                    DEAD_VALUE = 42
                Live = None
                Data = None
            """,
        },
    )
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert not any(item["reason"].startswith("robot_") for item in rescues)


def test_variable_class_getter_keeps_its_initializer_and_helpers(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    values.Data",
            "values.py": """
                class Data:
                    def __init__(self): self.value = _initial_value()
                    def getVariables(self): return {'VALUE': self.value}
                    def unused_helper(self): pass
                def _initial_value(): return 42
            """,
        },
    )
    assert "values.Data.getVariables" not in _names(result)
    assert "values._initial_value" not in _names(result)
    assert "values.Data.unused_helper" in _names(result)


def test_ordinary_data_and_robot_filenames_do_not_activate_builtin(tmp_path):
    result = _scan(
        tmp_path,
        {
            "notes.robot": "Library    src/robot/libraries/BuiltIn.py",
            "src/robot/__init__.py": "",
            "src/robot/libraries/__init__.py": "",
            "src/robot/libraries/BuiltIn.py": "class BuiltIn:\n    def log(self): pass",
        },
    )
    assert "robot.libraries.BuiltIn.BuiltIn" in _names(result, "unused_classes")


@pytest.mark.parametrize("prefix", ["./", "../project/"])
def test_explicit_relative_paths_keep_every_parent_component(tmp_path, prefix):
    project = tmp_path / "project"
    result = _scan(
        project,
        {
            "suite.robot": (
                f"*** Settings ***\nLibrary    {prefix}keywords.py\n"
                f"Variables    {prefix}data.py"
            ),
            "keywords.py": "def keyword_from_relative_path(): pass",
            "data.py": "VALUE_FROM_RELATIVE_PATH = 42",
        },
    )
    assert "keywords.keyword_from_relative_path" not in _names(result)
    assert "data.VALUE_FROM_RELATIVE_PATH" not in _names(result, "unused_variables")


def test_manual_not_keyword_flags_and_calls_do_not_supply_robot_roots(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    keywords.py",
            "keywords.py": """
                from robot.api.deco import not_keyword
                def excluded_by_flag(): pass
                excluded_by_flag.robot_not_keyword = True
                def excluded_by_call(): pass
                not_keyword(excluded_by_call)
                def real_keyword(): pass
            """,
        },
    )
    # Ordinary Python top-level references already retain these two functions.
    # The Robot model must not promote either excluded function to an entrypoint.
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert {item["name"] for item in rescues if item["reason"] == "robot_library"} == {
        "keywords.real_keyword"
    }
    assert "keywords.real_keyword" not in _names(result)


def test_unimported_resource_files_do_not_supply_library_roots(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Test Cases ***\nExample\n    No Operation",
            "unused.resource": "*** Settings ***\nLibrary    keywords.py",
            "keywords.py": "def unused_keyword(): pass",
        },
    )
    assert "keywords.unused_keyword" in _names(result)


def test_variable_export_filters_keep_same_line_names_separate(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nVariables    data.py",
            "data.py": "__all__ = ['PUBLIC']\nPUBLIC = 1; UNEXPORTED = 2",
        },
    )
    unused = _names(result, "unused_variables")
    assert "data.PUBLIC" not in unused
    assert "data.UNEXPORTED" in unused


def test_multiple_inheritance_uses_the_python_method_resolution_order(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    hierarchy.Child",
            "hierarchy.py": """
                class Ancestor:
                    ROBOT_AUTO_KEYWORDS = True
                    def inherited_keyword(self): pass
                class Left(Ancestor): pass
                class Right(Ancestor):
                    ROBOT_AUTO_KEYWORDS = False
                    def inherited_keyword(self): pass
                class Child(Left, Right): pass
            """,
        },
    )
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    robot_names = {
        item["name"] for item in rescues if item["reason"] == "robot_library"
    }
    assert robot_names == {"hierarchy.Child"}


def test_base_class_binding_is_captured_when_the_child_is_defined(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    hierarchy.Child",
            "hierarchy.py": """
                class Parent:
                    def original_keyword(self): pass
                class Child(Parent): pass
                class Parent:
                    def unrelated_keyword(self): pass
            """,
        },
    )
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    robot_names = {
        item["name"] for item in rescues if item["reason"] == "robot_library"
    }
    assert "hierarchy.Parent.original_keyword" in robot_names
    assert "hierarchy.Parent.unrelated_keyword" not in robot_names


def test_diamond_inheritance_selects_the_effective_keyword_method(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    hierarchy.Child",
            "hierarchy.py": """
                class Ancestor:
                    def inherited_keyword(self): pass
                class Left(Ancestor): pass
                class Right(Ancestor):
                    def inherited_keyword(self): pass
                class Child(Left, Right): pass
            """,
        },
    )
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    robot_names = {
        item["name"] for item in rescues if item["reason"] == "robot_library"
    }
    assert "hierarchy.Right.inherited_keyword" in robot_names
    assert "hierarchy.Ancestor.inherited_keyword" not in robot_names


def test_dynamic_keyword_prefix_is_limited_to_the_selected_class(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    Dynamic.py",
            "Dynamic.py": """
                class Dynamic:
                    def get_keyword_names(self):
                        return [name for name in dir(self) if name.startswith('do_')]
                    def run_keyword(self, name, args): return getattr(self, name)(*args)
                    def do_selected_work(self): pass
                    def unrelated_helper(self): pass
                def do_unrelated_work(): pass
            """,
        },
    )
    unused = _names(result)
    assert "Dynamic.Dynamic.do_selected_work" not in unused
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert any(item["name"] == "Dynamic.Dynamic.do_selected_work" for item in rescues)
    assert not any(
        item["name"] == "Dynamic.Dynamic.unrelated_helper" for item in rescues
    )
    # The generic dir(self) analysis retains other methods as uncertain. The
    # bounded Robot contract must not upgrade them to proven framework roots.
    assert (
        result["definitions"]["Dynamic.Dynamic.unrelated_helper"][
            "dead_code_classification"
        ]
        == "uncertain"
    )
    assert "Dynamic.do_unrelated_work" in unused


@pytest.mark.parametrize("listener", ["self", "SELF"])
def test_selected_library_can_install_itself_as_a_listener(tmp_path, listener):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    Events.py",
            "Events.py": f"""
                from robot.api.deco import library
                @library(listener={listener!r})
                class Events:
                    def start_suite(self, data, result): return _handle_event()
                    def close(self): pass
                    def unused_helper(self): pass
                def _handle_event(): return 42
            """,
        },
    )
    unused = _names(result)
    assert "Events.Events.start_suite" not in unused
    assert "Events.Events.close" not in unused
    assert "Events._handle_event" not in unused
    assert "Events.Events.unused_helper" in unused


def test_another_listener_does_not_activate_the_librarys_listener_methods(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    Events.py",
            "Events.py": """
                from robot.api.deco import library
                @library(listener='somewhere.Else')
                class Events:
                    def start_suite(self, data, result): pass
                    def close(self): pass
            """,
        },
    )
    unused = _names(result)
    assert "Events.Events.start_suite" in unused
    assert "Events.Events.close" in unused


@pytest.mark.parametrize(
    "getter",
    [
        "return [name for name in dir(unknown) if name.startswith('do_')]",
        "dir = lambda obj: ['do_dead_work']\n"
        "        return [name for name in dir(self) if name.startswith('do_')]",
    ],
)
def test_a_prefix_on_an_unknown_object_or_shadowed_dir_is_not_a_contract(
    tmp_path, getter
):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    Dynamic.py",
            "Dynamic.py": (
                "class Dynamic:\n    def get_keyword_names(self):\n        "
                + getter
                + "\n    def do_dead_work(self): pass\n"
            ),
        },
    )
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert not any(item["name"] == "Dynamic.Dynamic.do_dead_work" for item in rescues)


@pytest.mark.parametrize(
    "assignment",
    [
        "ROBOT_AUTO_KEYWORDS, OTHER = False, True",
        "(ROBOT_AUTO_KEYWORDS, OTHER) = (False, True)",
        "[ROBOT_AUTO_KEYWORDS, OTHER] = [False, True]",
    ],
)
def test_destructured_auto_keyword_flag_keeps_its_individual_value(
    tmp_path, assignment
):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    Lib.py",
            "Lib.py": (
                "class Lib:\n    " + assignment + "\n"
                "    def excluded_keyword(self): return _dead_helper()\n"
                "def _dead_helper(): return 42\n"
            ),
        },
    )
    assert "Lib._dead_helper" in _names(result)
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert not any(item["name"] == "Lib.Lib.excluded_keyword" for item in rescues)


def test_later_native_import_does_not_legitimize_an_earlier_fake_method_decorator(
    tmp_path,
):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    Lib.py",
            "Lib.py": """
                def keyword(fn): return None
                class Lib:
                    ROBOT_AUTO_KEYWORDS = False
                    @keyword
                    def excluded_keyword(self): return _dead_helper()
                from robot.api.deco import keyword
                def _dead_helper(): return 42
            """,
        },
    )
    assert "Lib._dead_helper" in _names(result)
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert not any(item["name"] == "Lib.Lib.excluded_keyword" for item in rescues)


def test_later_shadow_does_not_erase_a_native_method_decorator(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    Lib.py",
            "Lib.py": """
                from robot.api.deco import keyword
                class Lib:
                    ROBOT_AUTO_KEYWORDS = False
                    @keyword
                    def _explicit_keyword(self): return _live_helper()
                keyword = None
                def _live_helper(): return 42
            """,
        },
    )
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert any(item["name"] == "Lib.Lib._explicit_keyword" for item in rescues)
    assert "Lib._live_helper" not in _names(result)


@pytest.mark.parametrize(
    "header, setting",
    [
        ("*** Settings ***", "L_ib_rary"),
        ("*** Settings ***", "L i b r a r y"),
        ("*** S_ettings ***", "Library"),
    ],
)
def test_robot_setting_and_header_names_preserve_significant_characters(
    tmp_path, header, setting
):
    result = _scan(
        tmp_path,
        {
            "suite.robot": f"{header}\n{setting}    Lib.py",
            "Lib.py": (
                "class Lib:\n"
                "    def excluded_keyword(self): return _dead_helper()\n"
                "def _dead_helper(): return 42\n"
            ),
        },
    )
    assert "Lib._dead_helper" in _names(result)
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert not any(item["reason"].startswith("robot_") for item in rescues)


@pytest.mark.parametrize("first_value", ["real.py", "real.py    other"])
def test_first_robot_variable_definition_keeps_priority(tmp_path, first_value):
    result = _scan(
        tmp_path,
        {
            "suite.robot": (
                "*** Settings ***\nLibrary    ${LIBRARY NAME}\n"
                f"*** Variables ***\n${{LIBRARY NAME}}    {first_value}\n"
                "${library_name}    dead.py"
            ),
            "real.py": "def real_keyword(): pass",
            "dead.py": "def dead_keyword(): pass",
        },
    )
    assert "dead.dead_keyword" in _names(result)
    if first_value == "real.py":
        assert "real.real_keyword" not in _names(result)


def test_reassigned_dynamic_keyword_receiver_is_not_the_selected_class(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    Dynamic.py",
            "Dynamic.py": """
                class Dynamic:
                    def get_keyword_names(self):
                        self = unknown_object
                        return [name for name in dir(self) if name.startswith('do_')]
                    def do_dead_work(self): pass
            """,
        },
    )
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert not any(item["name"] == "Dynamic.Dynamic.do_dead_work" for item in rescues)


def test_runtime_global_dir_shadow_does_not_supply_a_keyword_contract(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    Dynamic.py",
            "Dynamic.py": """
                class Dynamic:
                    def get_keyword_names(self):
                        return [name for name in dir(self) if name.startswith('do_')]
                    def do_dead_work(self): pass
                def dir(obj): return []
            """,
        },
    )
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert not any(item["name"] == "Dynamic.Dynamic.do_dead_work" for item in rescues)


@pytest.mark.parametrize("extension", ["yaml", "yml", "json"])
def test_non_python_variable_file_does_not_resolve_a_python_class(tmp_path, extension):
    result = _scan(
        tmp_path,
        {
            "suite.robot": f"*** Settings ***\nVariables    data.{extension}",
            f"data.{extension}": (
                json.dumps({"ACTUAL_VALUE": 1})
                if extension == "json"
                else "ACTUAL_VALUE: 1\n"
            ),
            "data.py": f"class {extension}:\n    DEAD_VAR = 42\n",
        },
    )
    assert result.get("analysis_errors", []) == []
    assert f"data.{extension}" in _names(result, "unused_classes")
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert not any(item["reason"] == "robot_variables" for item in rescues)


def test_library_dotted_class_name_can_match_a_variable_file_extension(tmp_path):
    result = _scan(
        tmp_path,
        {
            "suite.robot": "*** Settings ***\nLibrary    data.yaml",
            "data.yaml": "ACTUAL_VALUE: 1\n",
            "data.py": """
                class yaml:
                    def exposed_keyword(self): return _live_helper()
                def _live_helper(): return 42
            """,
        },
    )
    assert result.get("analysis_errors", []) == []
    assert "data.yaml" not in _names(result, "unused_classes")
    assert "data._live_helper" not in _names(result)
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert any(
        item["name"] == "data.yaml.exposed_keyword"
        and item["reason"] == "robot_library"
        for item in rescues
    )
