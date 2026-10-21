"""Configured collection scopes advice without changing security or helpers."""

import ast
import json
from pathlib import Path

import pytest

from skylos.analysis.file_processing import set_linter_node_types
from skylos.core.linter import LinterVisitor
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.quality.class_size import GodClassRule, GodFileRule


NATIVE = """[tool.pytest]
python_files = ["checks/*.py"]
python_classes = ["Acceptance"]
python_functions = ["check_"]
testpaths = ["checks"]
"""


def _write(root, name, text):
    root = root.resolve()
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("fixture path leaves project")
    target = root / relative
    target.resolve().relative_to(root)
    target.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(target, text)
    return target


def _class(name="AcceptanceCases", prefix="check_case", extra=""):
    return (
        f"class {name}:\n"
        + extra
        + "".join(
            f"    def {prefix}_{index}(self):\n        assert {index} >= 0\n"
            for index in range(3)
        )
    )


def _metrics(root, source, filename="checks/cases.py"):
    path = _write(root, filename, source)
    rules = [
        GodClassRule(max_methods=2, max_attributes=99),
        GodFileRule(
            max_lines=99999, max_definitions=2, max_top_level_definitions=99999
        ),
    ]
    set_linter_node_types(rules)
    visitor = LinterVisitor(rules, str(path))
    visitor.context.update(source=source, project_root=root)
    visitor.visit(ast.parse(source))
    return visitor.findings


def _ids(findings):
    return {row["rule_id"] for row in findings}


@pytest.mark.parametrize(
    "filename,config",
    [
        ("pyproject.toml", NATIVE),
        (
            "pyproject.toml",
            "[tool.pytest.ini_options]\n"
            'python_files = "checks/*.py"\n'
            'python_classes = "Acceptance"\n'
            'python_functions = "check_"\n'
            'testpaths = "checks"\n',
        ),
        (
            "pyproject.toml",
            NATIVE.replace("[tool.pytest]", "[tool.pytest.ini_options]"),
        ),
        ("pytest.toml", NATIVE.replace("[tool.pytest]", "[pytest]")),
        (".pytest.toml", NATIVE.replace("[tool.pytest]", "[pytest]")),
        (
            "pytest.ini",
            "[pytest]\npython_files = checks/*.py\n"
            "python_classes = Acceptance\npython_functions = check_\ntestpaths = checks\n",
        ),
        (
            ".pytest.ini",
            "[pytest]\npython_files = checks/*.py\n"
            "python_classes = Acceptance\npython_functions = check_\ntestpaths = checks\n",
        ),
        (
            "tox.ini",
            "[pytest]\npython_files = checks/*.py\n"
            "python_classes = Acceptance\npython_functions = check_\ntestpaths = checks\n",
        ),
        (
            "setup.cfg",
            "[tool:pytest]\npython_files = checks/*.py\n"
            "python_classes = Acceptance\npython_functions = check_\ntestpaths = checks\n",
        ),
    ],
)
def test_native_and_legacy_collection_settings_scope_real_metrics(
    tmp_path, filename, config
):
    _write(tmp_path, filename, config)
    assert _metrics(tmp_path, _class()) == []


@pytest.mark.parametrize(
    "class_pattern,function_pattern,class_name,function_prefix",
    [
        ("Acceptance", "check_", "AcceptanceCases", "check_case"),
        ("*Cases", "check_*", "AcceptanceCases", "check_case"),
        ("Suite?", "verify[12]*", "SuiteA", "verify1"),
    ],
)
def test_class_and_function_patterns_support_prefixes_and_globs(
    tmp_path, class_pattern, function_pattern, class_name, function_prefix
):
    config = (
        '[tool.pytest]\npython_files = ["checks/*.py"]\n'
        f'python_classes = ["{class_pattern}"]\n'
        f'python_functions = ["{function_pattern}"]\n'
    )
    _write(tmp_path, "pyproject.toml", config)
    assert _metrics(tmp_path, _class(class_name, function_prefix)) == []


def test_configured_top_level_functions_are_collected_without_a_test_class(tmp_path):
    _write(tmp_path, "pyproject.toml", NATIVE)
    source = "".join(
        f"def check_case_{index}():\n    assert {index} >= 0\n" for index in range(3)
    )
    assert _metrics(tmp_path, source) == []


@pytest.mark.parametrize("filename", ["test_cases.py", "cases_test.py"])
def test_default_collection_conventions_remain_supported(tmp_path, filename):
    _write(tmp_path, "pyproject.toml", "[project]\nname = 'sample'\n")
    assert _metrics(tmp_path, _class("TestCases", "test_case"), filename) == []


def test_configured_file_pattern_preserves_directory_scope(tmp_path):
    _write(tmp_path, "pyproject.toml", NATIVE)
    assert _metrics(tmp_path, _class()) == []
    assert _ids(_metrics(tmp_path, _class(), "package/cases.py")) == {
        "SKY-Q501",
        "SKY-Q502",
    }


def test_file_pattern_without_directory_matches_basename(tmp_path):
    _write(
        tmp_path,
        "pyproject.toml",
        NATIVE.replace('"checks/*.py"', '"*_checks.py"').replace(
            'testpaths = ["checks"]\n', ""
        ),
    )
    assert _metrics(tmp_path, _class(), "other/worker_checks.py") == []
    assert _ids(_metrics(tmp_path, _class(), "checks/worker.py")) == {
        "SKY-Q501",
        "SKY-Q502",
    }


@pytest.mark.parametrize(
    "source",
    [
        _class("Worker", "process"),
        _class("AcceptanceCases", "process"),
        _class("Worker", "check_case"),
        _class("AcceptanceCases", "check_case", "    __test__ = False\n"),
        _class(
            "AcceptanceCases",
            "check_case",
            "    def __init__(self):\n        pass\n",
        ),
        _class(
            "AcceptanceCases",
            "check_case",
            "    def __new__(cls):\n        return object.__new__(cls)\n",
        ),
    ],
)
def test_configuration_needs_actual_collectable_classes(tmp_path, source):
    _write(tmp_path, "pyproject.toml", NATIVE)
    assert _ids(_metrics(tmp_path, source)) == {"SKY-Q501", "SKY-Q502"}


@pytest.mark.parametrize("false_value", ["False", "0", "None"])
def test_false_collection_metadata_keeps_uncollected_class_advice(
    tmp_path, false_value
):
    _write(tmp_path, "pyproject.toml", NATIVE)
    source = _class(extra=f"    __test__ = {false_value}\n")
    assert _ids(_metrics(tmp_path, source)) == {"SKY-Q501", "SKY-Q502"}


@pytest.mark.parametrize("false_value", ["False", "0", "None"])
def test_false_module_collection_metadata_does_not_scope_advice(tmp_path, false_value):
    _write(tmp_path, "pyproject.toml", NATIVE)
    source = f"__test__ = {false_value}\n" + _class()
    assert _ids(_metrics(tmp_path, source)) == {"SKY-Q501", "SKY-Q502"}


@pytest.mark.parametrize("class_methods", [False, True])
def test_fixture_functions_with_matching_names_are_not_collection_proof(
    tmp_path, class_methods
):
    _write(tmp_path, "pyproject.toml", NATIVE)
    if class_methods:
        source = "import pytest\n" + _class().replace(
            "    def ", "    @pytest.fixture\n    def "
        )
        expected = {"SKY-Q501", "SKY-Q502"}
    else:
        source = "import pytest\n" + "".join(
            f"@pytest.fixture\ndef check_case_{index}():\n    return {index}\n"
            for index in range(3)
        )
        expected = {"SKY-Q502"}
    assert _ids(_metrics(tmp_path, source)) == expected


@pytest.mark.parametrize("class_methods", [False, True])
def test_functions_opted_out_by_static_assignment_are_not_collection_proof(
    tmp_path, class_methods
):
    _write(tmp_path, "pyproject.toml", NATIVE)
    if class_methods:
        source = _class() + "".join(
            f"    check_case_{index}.__test__ = False\n" for index in range(3)
        )
        expected = {"SKY-Q501", "SKY-Q502"}
    else:
        source = "".join(
            f"def check_case_{index}():\n    return {index}\n"
            f"check_case_{index}.__test__ = False\n"
            for index in range(3)
        )
        expected = {"SKY-Q502"}
    assert _ids(_metrics(tmp_path, source)) == expected


@pytest.mark.parametrize(
    "base_source,base_expression",
    [
        ("class Base:\n    def __init__(self):\n        pass\n", "Base"),
        (
            "class Base:\n    def __new__(cls):\n        return object.__new__(cls)\n",
            "Base",
        ),
        ("class Base:\n    __test__ = False\n", "Base"),
        (
            "class Root:\n    def __init__(self):\n        pass\n"
            "class Base(Root):\n    pass\n",
            "Base",
        ),
        ("from custom_framework import Base\n", "Base"),
        ("import custom_framework\n", "custom_framework.Base"),
        ("", "build_base()"),
    ],
)
def test_inherited_or_unresolved_collection_controls_keep_class_advice(
    tmp_path, base_source, base_expression
):
    _write(tmp_path, "pyproject.toml", NATIVE)
    source = base_source + _class(f"AcceptanceCases({base_expression})")
    assert _ids(_metrics(tmp_path, source)) == {"SKY-Q501", "SKY-Q502"}


def test_known_local_base_without_collection_controls_is_supported(tmp_path):
    _write(tmp_path, "pyproject.toml", NATIVE)
    source = (
        "class Base:\n    def setup_method(self):\n        self.ready = True\n"
        + _class("AcceptanceCases(Base)")
    )
    assert _metrics(tmp_path, source) == []


def test_custom_metaclass_is_not_collection_proof(tmp_path):
    _write(tmp_path, "pyproject.toml", NATIVE)
    assert _ids(_metrics(tmp_path, _class("AcceptanceCases(metaclass=Factory)"))) == {
        "SKY-Q501",
        "SKY-Q502",
    }


def test_rebound_local_base_is_not_collection_proof(tmp_path):
    _write(tmp_path, "pyproject.toml", NATIVE)
    source = "class Base:\n    pass\nBase = external_base\n" + _class(
        "AcceptanceCases(Base)"
    )
    assert _ids(_metrics(tmp_path, source)) == {"SKY-Q501", "SKY-Q502"}


@pytest.mark.parametrize("replacement", ["None", "external_class"])
def test_rebound_class_is_not_collection_proof(tmp_path, replacement):
    _write(tmp_path, "pyproject.toml", NATIVE)
    source = _class() + f"AcceptanceCases = {replacement}\n"
    assert _ids(_metrics(tmp_path, source)) == {"SKY-Q501", "SKY-Q502"}


@pytest.mark.parametrize("class_methods", [False, True])
def test_rebound_matching_functions_are_not_collection_proof(tmp_path, class_methods):
    _write(tmp_path, "pyproject.toml", NATIVE)
    if class_methods:
        source = _class() + "".join(
            f"    check_case_{index} = None\n" for index in range(3)
        )
        expected = {"SKY-Q501", "SKY-Q502"}
    else:
        source = "".join(
            f"def check_case_{index}():\n    return {index}\n"
            f"check_case_{index} = None\n"
            for index in range(3)
        )
        expected = {"SKY-Q502"}
    assert _ids(_metrics(tmp_path, source)) == expected


@pytest.mark.parametrize("constructor", ["__init__", "__new__"])
@pytest.mark.parametrize("inherited", [False, True])
def test_assigned_constructors_are_not_collection_proof(
    tmp_path, constructor, inherited
):
    _write(tmp_path, "pyproject.toml", NATIVE)
    assignment = f"    {constructor} = constructor\n"
    source = (
        "class Base:\n" + assignment + _class("AcceptanceCases(Base)")
        if inherited
        else _class(extra=assignment)
    )
    assert _ids(_metrics(tmp_path, source)) == {"SKY-Q501", "SKY-Q502"}


@pytest.mark.parametrize("attribute", ["__init__", "__new__", "__test__"])
@pytest.mark.parametrize("inherited", [False, True])
def test_patched_class_collection_controls_are_not_proof(
    tmp_path, attribute, inherited
):
    _write(tmp_path, "pyproject.toml", NATIVE)
    value = "False" if attribute == "__test__" else "constructor"
    source = (
        f"class Base:\n    pass\nBase.{attribute} = {value}\n"
        + _class("AcceptanceCases(Base)")
        if inherited
        else _class() + f"AcceptanceCases.{attribute} = {value}\n"
    )
    assert _ids(_metrics(tmp_path, source)) == {"SKY-Q501", "SKY-Q502"}


def test_class_decorator_may_generate_a_constructor(tmp_path):
    _write(tmp_path, "pyproject.toml", NATIVE)
    source = "from dataclasses import dataclass\n@dataclass\n" + _class(
        extra="    value: int\n"
    )
    assert _ids(_metrics(tmp_path, source)) == {"SKY-Q501", "SKY-Q502"}


@pytest.mark.parametrize(
    "imports,decorator",
    [
        ("import pytest\n", '@pytest.mark.usefixtures("ready")'),
        ("from pytest import mark as marks\n", '@marks.usefixtures("ready")'),
    ],
)
def test_import_proven_pytest_marks_preserve_configured_collection(
    tmp_path, imports, decorator
):
    _write(tmp_path, "pyproject.toml", NATIVE)
    source = (
        imports
        + decorator
        + "\n"
        + _class().replace("    def ", "    " + decorator + "\n    def ")
    )
    assert _metrics(tmp_path, source) == []


def test_unknown_class_decorator_does_not_prove_collection(tmp_path):
    _write(tmp_path, "pyproject.toml", NATIVE)
    assert _ids(_metrics(tmp_path, "@transform_class\n" + _class())) == {
        "SKY-Q501",
        "SKY-Q502",
    }


@pytest.mark.parametrize("decorator", ["property", "cached_property"])
def test_property_names_are_not_collectable_test_methods(tmp_path, decorator):
    _write(tmp_path, "pyproject.toml", NATIVE)
    source = "from functools import cached_property\n" + _class().replace(
        "    def ", f"    @{decorator}\n    def "
    )
    assert _ids(_metrics(tmp_path, source)) == {"SKY-Q501", "SKY-Q502"}


def test_testpaths_does_not_exempt_uncollected_files(tmp_path):
    _write(tmp_path, "pyproject.toml", '[tool.pytest]\ntestpaths = ["checks"]\n')
    assert _ids(_metrics(tmp_path, _class("Worker", "process"))) == {
        "SKY-Q501",
        "SKY-Q502",
    }


@pytest.mark.parametrize("collected", [False, True])
def test_boolean_and_literal_advice_need_collection_proof(tmp_path, collected):
    from skylos.rules.quality.logic_maintainability import (
        BooleanTrapRule,
        DuplicateStringLiteralRule,
    )

    _write(tmp_path, "pyproject.toml", NATIVE)
    source = (
        "def publish(notify: bool):\n"
        '    first = "display-value"\n'
        '    second = "display-value"\n'
        '    third = "display-value"\n'
        "    return first, second, third\n"
    )
    if collected:
        source += "\ndef check_ready():\n    assert True\n"
    path = _write(tmp_path, "checks/cases.py", source)
    rules = [BooleanTrapRule(), DuplicateStringLiteralRule()]
    set_linter_node_types(rules)
    visitor = LinterVisitor(rules, str(path))
    visitor.context.update(source=source, project_root=tmp_path)
    visitor.visit(ast.parse(source))
    assert _ids(visitor.findings) == (set() if collected else {"SKY-L027", "SKY-L029"})


def test_collected_subclass_does_not_exempt_its_setup_helper(tmp_path):
    _write(tmp_path, "pyproject.toml", NATIVE)
    source = _class("WorkerCase", "setup_part") + (
        "class AcceptanceCases(WorkerCase):\n"
        "    def check_ready(self):\n        assert True\n"
    )
    rows = _metrics(tmp_path, source)
    assert [(row["name"], row["rule_id"]) for row in rows] == [
        ("WorkerCase", "SKY-Q501")
    ]


@pytest.mark.parametrize(
    "setting", ["python_files", "python_classes", "python_functions"]
)
def test_explicit_empty_collection_patterns_are_not_replaced_by_defaults(
    tmp_path, setting
):
    config = NATIVE.replace(
        next(line for line in NATIVE.splitlines() if line.startswith(setting + " =")),
        f"{setting} = []",
    )
    _write(tmp_path, "pyproject.toml", config)
    assert _ids(_metrics(tmp_path, _class())) == {"SKY-Q501", "SKY-Q502"}


@pytest.mark.parametrize(
    "config",
    [
        '[tool.pytest]\npython_files = "checks/*.py"\n',
        NATIVE.replace('["check_"]', '["check_", 1]'),
        NATIVE.replace('["Acceptance"]', "true"),
        NATIVE + '[tool.pytest.ini_options]\npython_classes = "Acceptance"\n',
        '[tool.pytest]\npython_files = ["checks/*.py"\n',
    ],
)
def test_invalid_collection_config_cannot_create_a_scope_exemption(tmp_path, config):
    _write(tmp_path, "pyproject.toml", config)
    assert _ids(_metrics(tmp_path, _class())) == {"SKY-Q501", "SKY-Q502"}


def test_empty_higher_precedence_config_blocks_lower_precedence_settings(tmp_path):
    _write(tmp_path, "pytest.ini", "")
    _write(tmp_path, "pyproject.toml", NATIVE)
    assert _ids(_metrics(tmp_path, _class())) == {"SKY-Q501", "SKY-Q502"}


def test_configs_are_selected_without_merging(tmp_path):
    _write(
        tmp_path,
        "pytest.ini",
        "[pytest]\npython_files = checks/*.py\npython_classes = Acceptance\n",
    )
    _write(tmp_path, "pyproject.toml", NATIVE)
    # The selected INI file uses default test* functions, not pyproject's check_.
    assert _ids(_metrics(tmp_path, _class())) == {"SKY-Q501", "SKY-Q502"}


def test_ini_default_section_is_not_inherited_as_pytest_settings(tmp_path):
    _write(
        tmp_path,
        "pytest.ini",
        "[DEFAULT]\npython_files = checks/*.py\npython_classes = Acceptance\n"
        "python_functions = check_\n[pytest]\n",
    )
    assert _ids(_metrics(tmp_path, _class())) == {"SKY-Q501", "SKY-Q502"}


def test_ini_option_names_remain_case_sensitive_like_pytest(tmp_path):
    _write(
        tmp_path,
        "pytest.ini",
        "[pytest]\nPYTHON_FILES = checks/*.py\nPYTHON_CLASSES = Acceptance\n"
        "PYTHON_FUNCTIONS = check_\n",
    )
    assert _ids(_metrics(tmp_path, _class())) == {"SKY-Q501", "SKY-Q502"}


def test_nested_config_does_not_relabel_files_for_a_root_scan(tmp_path):
    _write(tmp_path, "pyproject.toml", "[project]\nname = 'sample'\n")
    _write(
        tmp_path,
        "checks/pytest.ini",
        "[pytest]\npython_files = *.py\n"
        "python_classes = Acceptance\npython_functions = check_\n",
    )
    assert _ids(_metrics(tmp_path, _class())) == {"SKY-Q501", "SKY-Q502"}


def test_config_rewrites_are_visible_within_one_process(tmp_path):
    _write(tmp_path, "pyproject.toml", NATIVE)
    assert _metrics(tmp_path, _class()) == []
    _write(tmp_path, "pyproject.toml", NATIVE.replace('"Acceptance"', '"OtherClass"'))
    assert _ids(_metrics(tmp_path, _class())) == {"SKY-Q501", "SKY-Q502"}
    _write(tmp_path, "pyproject.toml", NATIVE)
    assert _metrics(tmp_path, _class()) == []


def test_symlinked_config_cannot_create_a_scope_exemption(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    external = _write(tmp_path, "external.toml", NATIVE)
    try:
        (root / "pyproject.toml").symlink_to(external)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    assert _ids(_metrics(root, _class())) == {"SKY-Q501", "SKY-Q502"}


def test_configured_glob_cannot_classify_a_file_outside_the_project(tmp_path):
    from skylos.rules.quality._pytest_collection import is_collected_pytest_file

    root = tmp_path / "project"
    root.mkdir()
    _write(root, "pyproject.toml", NATIVE.replace('"checks/*.py"', '"*.py"'))
    external = _write(tmp_path, "cases.py", _class())
    assert not is_collected_pytest_file(external, root, _class())
    assert not is_collected_pytest_file("../cases.py", root, _class())


def test_quality_collection_config_does_not_change_security_classification(
    tmp_path, monkeypatch
):
    """``check_write`` has no caller, so path_provenance records it as unknown
    instead of reporting it (it used to be reported). The quality config
    must not change that classification or treat the file as test code.
    """
    from skylos.analyzer import analyze
    from skylos.rules.quality._test_code import is_python_test_file

    monkeypatch.setenv("SKYLOS_JOBS", "1")
    (tmp_path / ".git").mkdir()
    _write(tmp_path, "pyproject.toml", "[project]\nname = 'sample'\n")
    source = (
        "from pathlib import Path\n\n"
        "def check_write(path, text):\n    Path(path).write_text(text)\n"
    )
    path = _write(tmp_path, "checks/cases.py", source)
    before = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    _write(tmp_path, "pyproject.toml", NATIVE)
    after = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))

    def path_findings(result, key="danger"):
        return {
            (row["rule_id"], row["line"], row.get("symbol"))
            for row in result.get(key, [])
            if row["rule_id"] in {"SKY-D215", "SKY-D324", "SKY-D325"}
        }

    def provenance(result):
        return {
            (row["rule_id"], row["line"], row.get("symbol"), row.get("reason"),
             row["metadata"]["path_provenance"]["status"])
            for row in result.get("suppressed", [])
            if row["rule_id"] in {"SKY-D215", "SKY-D324", "SKY-D325"}
        }

    assert not is_python_test_file(path, tmp_path, source)
    assert any(row[0] == "SKY-D324" and row[4] == "unknown" for row in provenance(before))
    assert path_findings(after) == path_findings(before)
    assert provenance(after) == provenance(before)
    assert not any("test code" in str(row[3]) for row in provenance(after))
