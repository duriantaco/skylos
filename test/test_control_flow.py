import ast
import tempfile
from pathlib import Path
import pytest

from skylos.control_flow import (
    evaluate_static_condition,
    extract_constant_string,
    _is_sys_version_info_node,
    _extract_version_tuple,
    _find_pyproject_toml,
    _parse_requires_python,
    _version_check_is_within_supported_range,
)


class TestEvaluateStaticCondition:
    def test_constant_true(self):
        node = ast.parse("True", mode="eval").body
        assert evaluate_static_condition(node) is True

    def test_constant_false(self):
        node = ast.parse("False", mode="eval").body
        assert evaluate_static_condition(node) is False

    def test_constant_number(self):
        node = ast.parse("42", mode="eval").body
        assert evaluate_static_condition(node) == 42

    def test_constant_string(self):
        node = ast.parse("'hello'", mode="eval").body
        assert evaluate_static_condition(node) == "hello"

    def test_not_true(self):
        node = ast.parse("not True", mode="eval").body
        assert evaluate_static_condition(node) is False

    def test_not_false(self):
        node = ast.parse("not False", mode="eval").body
        assert evaluate_static_condition(node) is True

    def test_and_all_true(self):
        node = ast.parse("True and True", mode="eval").body
        assert evaluate_static_condition(node) is True

    def test_and_with_false(self):
        node = ast.parse("True and False", mode="eval").body
        assert evaluate_static_condition(node) is False

    def test_and_with_unknown(self):
        node = ast.parse("True and unknown_var", mode="eval").body
        assert evaluate_static_condition(node) is None

    def test_or_with_true(self):
        node = ast.parse("False or True", mode="eval").body
        assert evaluate_static_condition(node) is True

    def test_or_all_false(self):
        node = ast.parse("False or False", mode="eval").body
        assert evaluate_static_condition(node) is False

    def test_or_with_unknown(self):
        node = ast.parse("False or unknown_var", mode="eval").body
        assert evaluate_static_condition(node) is None

    def test_comparison_equal(self):
        node = ast.parse("5 == 5", mode="eval").body
        assert evaluate_static_condition(node) is True

        node = ast.parse("5 == 6", mode="eval").body
        assert evaluate_static_condition(node) is False

    def test_comparison_not_equal(self):
        node = ast.parse("5 != 6", mode="eval").body
        assert evaluate_static_condition(node) is True

        node = ast.parse("5 != 5", mode="eval").body
        assert evaluate_static_condition(node) is False

    def test_comparison_less_than(self):
        node = ast.parse("3 < 5", mode="eval").body
        assert evaluate_static_condition(node) is True

        node = ast.parse("5 < 3", mode="eval").body
        assert evaluate_static_condition(node) is False

    def test_comparison_greater_than(self):
        node = ast.parse("5 > 3", mode="eval").body
        assert evaluate_static_condition(node) is True

        node = ast.parse("3 > 5", mode="eval").body
        assert evaluate_static_condition(node) is False

    def test_comparison_less_or_equal(self):
        node = ast.parse("3 <= 5", mode="eval").body
        assert evaluate_static_condition(node) is True

        node = ast.parse("5 <= 5", mode="eval").body
        assert evaluate_static_condition(node) is True

    def test_comparison_greater_or_equal(self):
        node = ast.parse("5 >= 3", mode="eval").body
        assert evaluate_static_condition(node) is True

        node = ast.parse("5 >= 5", mode="eval").body
        assert evaluate_static_condition(node) is True

    def test_comparison_is(self):
        node = ast.parse("None is None", mode="eval").body
        result = evaluate_static_condition(node)
        assert result is True or result is None

    def test_comparison_is_not(self):
        node = ast.parse("5 is not None", mode="eval").body
        result = evaluate_static_condition(node)
        assert result is True or result is None

    def test_unknown_variable(self):
        node = ast.parse("some_var", mode="eval").body
        assert evaluate_static_condition(node) is None

    def test_unknown_comparison(self):
        node = ast.parse("some_var > 5", mode="eval").body
        assert evaluate_static_condition(node) is None

    def test_complex_expression(self):
        node = ast.parse("(True and False) or (not False)", mode="eval").body
        assert evaluate_static_condition(node) is True


class TestExtractConstantString:
    def test_string_constant(self):
        node = ast.parse("'hello'", mode="eval").body
        assert extract_constant_string(node) == "hello"

    def test_double_quoted_string(self):
        node = ast.parse('"world"', mode="eval").body
        assert extract_constant_string(node) == "world"

    def test_non_string_constant(self):
        node = ast.parse("42", mode="eval").body
        assert extract_constant_string(node) is None

    def test_non_constant(self):
        node = ast.parse("some_var", mode="eval").body
        assert extract_constant_string(node) is None


class TestIsSysVersionInfoNode:
    def test_sys_version_info(self):
        node = ast.parse("sys.version_info", mode="eval").body
        assert _is_sys_version_info_node(node) is True

    def test_sys_platform(self):
        node = ast.parse("sys.platform", mode="eval").body
        assert _is_sys_version_info_node(node) is False

    def test_random_attribute(self):
        node = ast.parse("obj.version_info", mode="eval").body
        assert _is_sys_version_info_node(node) is False

    def test_simple_name(self):
        node = ast.parse("version_info", mode="eval").body
        assert _is_sys_version_info_node(node) is False

    def test_constant(self):
        node = ast.parse("42", mode="eval").body
        assert _is_sys_version_info_node(node) is False


class TestExtractVersionTuple:
    def test_simple_version_tuple(self):
        node = ast.parse("(3, 12)", mode="eval").body
        assert _extract_version_tuple(node) == (3, 12)

    def test_three_part_version(self):
        node = ast.parse("(3, 11, 5)", mode="eval").body
        assert _extract_version_tuple(node) == (3, 11, 5)

    def test_single_element(self):
        node = ast.parse("(3,)", mode="eval").body
        assert _extract_version_tuple(node) == (3,)

    def test_not_a_tuple(self):
        node = ast.parse("3", mode="eval").body
        assert _extract_version_tuple(node) is None

    def test_tuple_with_non_ints(self):
        node = ast.parse("(3, 'foo')", mode="eval").body
        assert _extract_version_tuple(node) is None

    def test_empty_tuple(self):
        node = ast.parse("()", mode="eval").body
        assert _extract_version_tuple(node) == ()


class TestFindPyprojectToml:
    def test_finds_in_same_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            pyproject = project_dir / "pyproject.toml"
            pyproject.write_text("[project]\nname = 'test'")

            test_file = project_dir / "test.py"
            test_file.write_text("# test")

            result = _find_pyproject_toml(test_file)
            assert result.resolve() == pyproject.resolve()

    def test_finds_in_parent_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            pyproject = project_dir / "pyproject.toml"
            pyproject.write_text("[project]\nname = 'test'")

            subdir = project_dir / "src"
            subdir.mkdir()
            test_file = subdir / "test.py"
            test_file.write_text("# test")

            result = _find_pyproject_toml(test_file)
            assert result.resolve() == pyproject.resolve()

    def test_finds_multiple_levels_up(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            pyproject = project_dir / "pyproject.toml"
            pyproject.write_text("[project]\nname = 'test'")

            deep_dir = project_dir / "src" / "package" / "module"
            deep_dir.mkdir(parents=True)
            test_file = deep_dir / "test.py"
            test_file.write_text("# test")

            result = _find_pyproject_toml(test_file)
            assert result.resolve() == pyproject.resolve()

    def test_returns_none_when_not_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("# test")

            result = _find_pyproject_toml(test_file)
            assert result is None

    def test_handles_none_input(self):
        result = _find_pyproject_toml(None)
        assert result is None

    def test_accepts_directory_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            pyproject = project_dir / "pyproject.toml"
            pyproject.write_text("[project]\nname = 'test'")

            result = _find_pyproject_toml(project_dir)
            assert result.resolve() == pyproject.resolve()


class TestParseRequiresPython:
    def test_parse_minimum_version_only(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            pyproject = project_dir / "pyproject.toml"
            pyproject.write_text('[project]\nrequires-python = ">=3.11"')

            test_file = project_dir / "test.py"
            test_file.write_text("# test")

            min_ver, max_ver = _parse_requires_python(test_file)
            assert min_ver == (3, 11)
            assert max_ver is None

    def test_parse_version_range(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            pyproject = project_dir / "pyproject.toml"
            pyproject.write_text('[project]\nrequires-python = ">=3.10,<3.13"')

            test_file = project_dir / "test.py"
            test_file.write_text("# test")

            min_ver, max_ver = _parse_requires_python(test_file)
            assert min_ver == (3, 10)
            assert max_ver == (3, 13)

    def test_parse_maximum_version_only(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            pyproject = project_dir / "pyproject.toml"
            pyproject.write_text('[project]\nrequires-python = "<3.13"')

            test_file = project_dir / "test.py"
            test_file.write_text("# test")

            min_ver, max_ver = _parse_requires_python(test_file)
            assert min_ver is None
            assert max_ver == (3, 13)

    def test_parse_with_spaces(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            pyproject = project_dir / "pyproject.toml"
            pyproject.write_text('[project]\nrequires-python = ">= 3.11 , < 3.14"')

            test_file = project_dir / "test.py"
            test_file.write_text("# test")

            min_ver, max_ver = _parse_requires_python(test_file)
            assert min_ver == (3, 11)
            assert max_ver == (3, 14)

    def test_returns_none_when_no_pyproject(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("# test")

            min_ver, max_ver = _parse_requires_python(test_file)
            assert min_ver is None
            assert max_ver is None

    def test_returns_none_when_no_requires_python(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            pyproject = project_dir / "pyproject.toml"
            pyproject.write_text('[project]\nname = "test"')

            test_file = project_dir / "test.py"
            test_file.write_text("# test")

            min_ver, max_ver = _parse_requires_python(test_file)
            assert min_ver is None
            assert max_ver is None

    def test_handles_invalid_toml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            pyproject = project_dir / "pyproject.toml"
            pyproject.write_text('invalid toml {{')

            test_file = project_dir / "test.py"
            test_file.write_text("# test")

            min_ver, max_ver = _parse_requires_python(test_file)
            assert min_ver is None
            assert max_ver is None


class TestVersionCheckIsWithinSupportedRange:
    def test_gte_check_overlaps_range(self):
        result = _version_check_is_within_supported_range(
            (3, 12), ast.GtE, (3, 11), None
        )
        assert result is True

    def test_gte_check_at_minimum(self):
        result = _version_check_is_within_supported_range(
            (3, 11), ast.GtE, (3, 11), None
        )
        assert result is False

    def test_gte_check_below_minimum(self):
        result = _version_check_is_within_supported_range(
            (3, 10), ast.GtE, (3, 11), None
        )
        assert result is False

    def test_lt_check_overlaps_range(self):
        result = _version_check_is_within_supported_range(
            (3, 13), ast.Lt, (3, 11), None
        )
        assert result is True

    def test_eq_check_in_range(self):
        result = _version_check_is_within_supported_range(
            (3, 12), ast.Eq, (3, 11), (3, 14)
        )
        assert result is True

    def test_neq_check_always_dynamic(self):
        result = _version_check_is_within_supported_range(
            (3, 12), ast.NotEq, (3, 11), None
        )
        assert result is True

    def test_no_version_constraint(self):
        result = _version_check_is_within_supported_range(
            (3, 12), ast.GtE, None, None
        )
        assert result is True


class TestVersionCheckIntegration:
    def test_version_check_treated_as_dynamic(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            pyproject = project_dir / "pyproject.toml"
            pyproject.write_text('[project]\nrequires-python = ">=3.11"')

            test_file = project_dir / "test.py"
            test_file.write_text("# test")

            node = ast.parse("sys.version_info >= (3, 12)", mode="eval").body
            result = evaluate_static_condition(node, file_path=test_file)

            assert result is None

    def test_version_check_without_pyproject(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("# test")

            node = ast.parse("sys.version_info >= (3, 12)", mode="eval").body
            result = evaluate_static_condition(node, file_path=test_file)

            assert result is None

    def test_non_version_check_still_works(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            pyproject = project_dir / "pyproject.toml"
            pyproject.write_text('[project]\nrequires-python = ">=3.11"')

            test_file = project_dir / "test.py"
            test_file.write_text("# test")

            node = ast.parse("5 > 3", mode="eval").body
            result = evaluate_static_condition(node, file_path=test_file)

            assert result is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
