"""Static-only fixtures for the narrow literal pytest path-parameter proof."""

import ast
import textwrap

import pytest

from skylos.rules.danger.danger_fs import path_flow


PATH_RULES = {"SKY-D215", "SKY-D324", "SKY-D325"}
WRITE_RULES = {"SKY-D215", "SKY-D324"}


def _fixture(
    decorator='@pytest.mark.parametrize("filename", ["one.txt", "two.txt"])',
    *,
    imports="import pytest",
    parameters="tmp_path, filename",
    name="test_write",
    body='(tmp_path / filename).write_text("fixture")',
):
    body = textwrap.indent(textwrap.dedent(body).strip(), "    ")
    return f"{imports}\n{decorator}\ndef {name}({parameters}):\n{body}\n"


def _scan(source, filename="tests/test_paths.py"):
    findings = []
    path_flow.scan(ast.parse(source), filename, findings)
    return [finding for finding in findings if finding["rule_id"] in PATH_RULES]


def _assert_write_flagged(
    source, *, filename="tests/test_paths.py", symbol="test_write"
):
    findings = _scan(source, filename)
    relevant = [finding for finding in findings if finding["symbol"] == symbol]
    assert WRITE_RULES <= {finding["rule_id"] for finding in relevant}, findings
    assert all(finding["file"] == filename for finding in relevant)
    assert all(finding["line"] > 0 for finding in relevant)


@pytest.mark.parametrize(
    "imports, decorator",
    [
        ("import pytest", '@pytest.mark.parametrize("filename", ["one.txt"])'),
        ("import pytest", '@pytest.mark.parametrize("filename", ("one.txt",))'),
        ("import pytest", '@pytest.mark.parametrize(["filename"], [("one.txt",)])'),
        ("import pytest", '@pytest.mark.parametrize(("filename",), [["one.txt"]])'),
        ("import pytest as pt", '@pt.mark.parametrize("filename", ["one.txt"])'),
        ("from pytest import mark", '@mark.parametrize("filename", ["one.txt"])'),
        ("from pytest import mark as m", '@m.parametrize("filename", ["one.txt"])'),
        (
            "import pytest",
            '@pytest.mark.parametrize("filename", [pytest.param("one.txt", id="one")])',
        ),
        (
            "import pytest as pt",
            '@pt.mark.parametrize("filename", [pt.param("one.txt", id="one")])',
        ),
        (
            "from pytest import mark, param",
            '@mark.parametrize("filename", [param("one.txt", id="one")])',
        ),
        (
            "from pytest import mark as m, param as p",
            '@m.parametrize("filename", [p("one.txt", id="one")])',
        ),
        (
            "import pytest",
            '@pytest.mark.parametrize(argnames="filename", argvalues=["one.txt"])',
        ),
    ],
)
def test_proven_pytest_literal_filename_forms_are_safe(imports, decorator):
    assert _scan(_fixture(decorator, imports=imports)) == []


@pytest.mark.parametrize(
    "filename", ["one.txt", "nested/one.txt", "file with spaces.txt"]
)
def test_safe_relative_literal_names_are_accepted(filename):
    assert (
        _scan(_fixture(f'@pytest.mark.parametrize("filename", [{filename!r}])')) == []
    )


@pytest.mark.parametrize(
    "body",
    [
        '(tmp_path / filename).write_text("fixture")',
        '(tmp_path / filename).write_bytes(b"fixture")',
        "(tmp_path / filename).read_text()",
        "(tmp_path / filename).read_bytes()",
        'open(tmp_path / filename, "w")',
        'open(file=tmp_path / filename, mode="r")',
        'path = tmp_path / filename\npath.write_text("fixture")',
        'alias = filename\npath = tmp_path / alias\npath.write_text("fixture")',
        'with pytest.raises(ValueError):\n    (tmp_path / filename).write_text("fixture")',
    ],
)
def test_literal_path_proof_reaches_existing_path_sinks(body):
    assert _scan(_fixture(body=body)) == []


@pytest.mark.parametrize(
    "argnames", ['"filename, contents"', '["filename", "contents"]']
)
def test_multicolumn_rows_only_prove_literal_path_columns(argnames):
    source = _fixture(
        f'@pytest.mark.parametrize({argnames}, [("one.txt", 1), ("two.txt", 2)])',
        parameters="tmp_path, filename, contents",
        body="(tmp_path / filename).write_text(str(contents))",
    )
    assert _scan(source) == []


def test_unknown_column_does_not_taint_independently_proven_filename():
    source = _fixture(
        '@pytest.mark.parametrize("filename, other", [("one.txt", dynamic_value)])',
        parameters="tmp_path, filename, other",
        body='(tmp_path / filename).write_text("fixture")\n'
        '(tmp_path / other).write_text("fixture")',
    )
    findings = _scan(source)
    assert {finding["rule_id"] for finding in findings} == WRITE_RULES
    assert {finding["line"] for finding in findings} == {5}
    assert {finding["symbol"] for finding in findings} == {"test_write"}


def test_stacked_literal_decorators_prove_each_parameter():
    source = _fixture(
        '@pytest.mark.parametrize("filename", ["one.txt"])\n'
        '@pytest.mark.parametrize("second", ["two.txt"])',
        parameters="tmp_path, filename, second",
        body='(tmp_path / filename).write_text("fixture")\n'
        '(tmp_path / second).write_text("fixture")',
    )
    assert _scan(source) == []


@pytest.mark.parametrize("indirect", ['["other"]', '("other",)'])
def test_indirect_parameter_list_only_invalidates_affected_columns(indirect):
    source = _fixture(
        '@pytest.mark.parametrize("filename, other", [("one.txt", "two.txt")], '
        f"indirect={indirect})",
        parameters="tmp_path, filename, other",
        body='(tmp_path / filename).write_text("fixture")\n'
        '(tmp_path / other).write_text("fixture")',
    )
    findings = _scan(source)
    assert {finding["rule_id"] for finding in findings} == WRITE_RULES
    assert {finding["line"] for finding in findings} == {5}


def test_explicit_false_indirect_keeps_direct_literal_proof():
    source = _fixture(
        '@pytest.mark.parametrize("filename", ["one.txt"], indirect=False)'
    )
    assert _scan(source) == []


@pytest.mark.parametrize(
    "argvalues",
    [
        "[]",
        "()",
        '["one.txt", dynamic_value]',
        '["one.txt", None]',
        '["one.txt", 1]',
        '["one.txt", b"two.txt"]',
        '["one.txt", ["two.txt"]]',
        '["one.txt", ("two.txt", "extra")]',
        '"one.txt"',
        '{"one.txt"}',
        'iter(["one.txt"])',
        '[name for name in ["one.txt"]]',
        "FILENAMES",
        "get_filenames()",
        '[pytest.param("one.txt", marks=pytest.mark.skip)]',
        '[pytest.param("one.txt", id=dynamic_id)]',
        '[pytest.param("one.txt", unknown=True)]',
        "[pytest.param()]",
    ],
)
def test_dynamic_empty_mixed_or_unsupported_values_remain_flagged(argvalues):
    source = _fixture(
        f'@pytest.mark.parametrize("filename", {argvalues})',
        imports='import pytest\nFILENAMES = ["one.txt"]',
    )
    _assert_write_flagged(source)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "/outside.txt",
        "../outside.txt",
        "nested/../outside.txt",
        "..",
        "C:/outside.txt",
        "C:outside.txt",
        "\\outside.txt",
        "nested\\..\\outside.txt",
        "\\\\server\\share\\outside.txt",
        "nul\x00.txt",
    ],
)
def test_unsafe_literal_path_components_do_not_gain_proof(value):
    _assert_write_flagged(
        _fixture(f'@pytest.mark.parametrize("filename", [{value!r}])')
    )


@pytest.mark.parametrize(
    "decorator",
    [
        '@pytest.mark.parametrize("filename", ["one.txt"], indirect=True)',
        '@pytest.mark.parametrize("filename", ["one.txt"], indirect=dynamic)',
        '@pytest.mark.parametrize("filename", ["one.txt"], indirect=["filename"])',
        '@pytest.mark.parametrize("filename", ["one.txt"], indirect="filename")',
        '@pytest.mark.parametrize("filename,", ["one.txt"])',
        '@pytest.mark.parametrize("filename, filename", [("one.txt", "two.txt")])',
        '@pytest.mark.parametrize(["filename", 1], [("one.txt", "two.txt")])',
        '@pytest.mark.parametrize(NAMES, ["one.txt"])',
        '@pytest.mark.parametrize("filename", ["one.txt"], **options)',
        '@pytest.mark.parametrize("filename", ["one.txt"])\n@custom',
        '@custom\n@pytest.mark.parametrize("filename", ["one.txt"])',
        '@pytest.mark.parametrize("filename", ["one.txt"])\n'
        '@pytest.mark.parametrize("filename", ["two.txt"])',
        '@pytest.mark.parametrize("filename, other", [("one.txt", 1), ("two.txt",)])',
    ],
)
def test_unsupported_or_malformed_decorators_remain_flagged(decorator):
    _assert_write_flagged(_fixture(decorator, parameters="tmp_path, filename, other"))


@pytest.mark.parametrize(
    "imports, decorator",
    [
        ("", '@pytest.mark.parametrize("filename", ["one.txt"])'),
        ("import fake as pytest", '@pytest.mark.parametrize("filename", ["one.txt"])'),
        ("from . import pytest", '@pytest.mark.parametrize("filename", ["one.txt"])'),
        ("from .pytest import mark", '@mark.parametrize("filename", ["one.txt"])'),
        ("from fake import mark", '@mark.parametrize("filename", ["one.txt"])'),
        (
            "if enabled:\n    import pytest",
            '@pytest.mark.parametrize("filename", ["one.txt"])',
        ),
        (
            "import pytest\npytest = replacement",
            '@pytest.mark.parametrize("filename", ["one.txt"])',
        ),
        (
            "import pytest\npytest.mark = replacement",
            '@pytest.mark.parametrize("filename", ["one.txt"])',
        ),
        (
            "import pytest\npytest.mark.parametrize = replacement",
            '@pytest.mark.parametrize("filename", ["one.txt"])',
        ),
        (
            "from pytest import mark\nmark = replacement",
            '@mark.parametrize("filename", ["one.txt"])',
        ),
        (
            "import pytest, fake as pytest",
            '@pytest.mark.parametrize("filename", ["one.txt"])',
        ),
        (
            "from pytest import mark as m, param as m",
            '@m.parametrize("filename", ["one.txt"])',
        ),
        (
            "import pytest\ndel pytest",
            '@pytest.mark.parametrize("filename", ["one.txt"])',
        ),
        (
            "import pytest\nalias = pytest",
            '@pytest.mark.parametrize("filename", ["one.txt"])',
        ),
        (
            "import pytest\nmutate(pytest)",
            '@pytest.mark.parametrize("filename", ["one.txt"])',
        ),
        (
            "import pytest\npytest.__dict__.update(overrides)",
            '@pytest.mark.parametrize("filename", ["one.txt"])',
        ),
        (
            "import pytest\npytest.mark.__setattr__('parametrize', replacement)",
            '@pytest.mark.parametrize("filename", ["one.txt"])',
        ),
    ],
)
def test_unproven_shadowed_or_escaped_pytest_apis_remain_flagged(imports, decorator):
    _assert_write_flagged(_fixture(decorator, imports=imports))


def test_mutation_through_one_pytest_alias_invalidates_other_alias():
    source = _fixture(
        '@m.parametrize("filename", ["one.txt"])',
        imports="import pytest\nfrom pytest import mark as m\npytest.mark = replacement",
    )
    _assert_write_flagged(source)


def test_bare_fixture_decorator_elsewhere_does_not_invalidate_literal_test():
    source = _fixture(
        imports="import pytest\n@pytest.fixture\ndef fixture_data():\n    return 1",
    )
    assert _scan(source) == []


@pytest.mark.parametrize("filename", ["app.py", "src/storage.py"])
def test_literal_parametrize_in_production_file_is_not_a_test_proof(filename):
    _assert_write_flagged(
        _fixture(body='open(tmp_path / filename, "w")'), filename=filename
    )


def test_nontest_function_name_does_not_gain_literal_parameter_proof():
    _assert_write_flagged(
        _fixture(name="write_file", body='open(tmp_path / filename, "w")'),
        symbol="write_file",
    )


@pytest.mark.parametrize("scope", ["class TestFiles:", "def outer():"])
def test_class_and_nested_test_functions_are_outside_supported_proof(scope):
    function = _fixture(imports="").lstrip()
    source = "import pytest\n" + scope + "\n" + textwrap.indent(function, "    ")
    _assert_write_flagged(source)


def test_module_mark_does_not_prove_function_parameters():
    source = _fixture(
        "",
        imports='import pytest\npytestmark = pytest.mark.parametrize("filename", ["one.txt"])',
    )
    _assert_write_flagged(source)


@pytest.mark.parametrize(
    "reference",
    ["test_write(root, input())", "alias = test_write", "register(test_write)"],
)
def test_explicit_function_references_outside_pytest_invalidate_proof(reference):
    _assert_write_flagged(_fixture() + reference + "\n")


@pytest.mark.parametrize(
    "statement",
    [
        "other += 1",
        "(other := 1)",
        "for other in []:\n    pass",
        "while False:\n    pass",
        "if True:\n    pass",
        "try:\n    pass\nexcept ValueError:\n    pass",
        "match other:\n    case 1:\n        pass",
        "values = [value for value in []]",
        "values = {value for value in []}",
        "values = {value: value for value in []}",
        "values = (value for value in [])",
        "callback = lambda: 1",
        "import pytest",
        "from other import replacement",
        'with open("fixed.txt") as handle:\n    pass',
    ],
)
def test_unsupported_function_body_shapes_keep_parameter_taint(statement):
    _assert_write_flagged(
        _fixture(body=statement + '\n(tmp_path / filename).write_text("fixture")')
    )


@pytest.mark.parametrize(
    "statement",
    [
        'filename = "other.txt"',
        'filename: str = "other.txt"',
        "del filename",
    ],
)
def test_candidate_binding_changes_anywhere_decline_entry_proof(statement):
    source = _fixture(body='(tmp_path / filename).write_text("fixture")\n' + statement)
    _assert_write_flagged(source)


@pytest.mark.parametrize(
    "body",
    [
        'filename = input()\n(tmp_path / filename).write_text("fixture")',
        'filename = request.args["name"]\n(tmp_path / filename).write_text("fixture")',
        'alias = filename\nalias = input()\n(tmp_path / alias).write_text("fixture")',
        'alias = filename\nalias = request.args["name"]\n(tmp_path / alias).write_text("fixture")',
        'tmp_path = request.args["root"]\nopen(tmp_path / filename, "w")',
        'alias = filename\nwith open("fixed") as alias:\n    (tmp_path / alias).write_text("fixture")',
    ],
)
def test_literal_metadata_never_hides_request_input_or_alias_reassignment(body):
    _assert_write_flagged(_fixture(body=body))


def test_unknown_root_parameter_remains_tainted_with_literal_filename():
    source = _fixture(
        parameters="root, filename", body='(root / filename).write_text("fixture")'
    )
    findings = _scan(source)
    assert "SKY-D324" in {finding["rule_id"] for finding in findings}


@pytest.mark.parametrize(
    "path_expression",
    [
        'f"{filename}"',
        '"{}".format(filename)',
        '"%s" % filename',
        '"prefix-" + filename',
    ],
)
def test_independent_interpolation_rule_still_reports_literal_parameters(
    path_expression,
):
    _assert_write_flagged(_fixture(body=f'open({path_expression}, "w")'))


def test_filename_length_limit_fails_closed():
    _assert_write_flagged(
        _fixture(f'@pytest.mark.parametrize("filename", [{("x" * 4097)!r}])')
    )


def test_parametrize_row_limit_fails_closed():
    rows = ", ".join(repr(f"file{index}.txt") for index in range(257))
    _assert_write_flagged(_fixture(f'@pytest.mark.parametrize("filename", [{rows}])'))


def test_parametrize_name_limit_fails_closed():
    names = ["filename", *(f"other{index}" for index in range(32))]
    row = ", ".join(repr("one.txt") for _ in names)
    source = _fixture(
        f"@pytest.mark.parametrize({names!r}, [({row})])",
        parameters=", ".join(["tmp_path", *names]),
    )
    _assert_write_flagged(source)


@pytest.mark.parametrize(
    "arguments",
    [
        '"filename", ["one.txt"], False, None, None, None',
        "",
        '"filename"',
        'argvalues=["one.txt"]',
        '"filename", ["one.txt"], unexpected=True',
        '"filename", ["one.txt"], argvalues=["other.txt"]',
        '"filename", ["one.txt"], ids=None, ids=None',
        "*arguments",
        '"filename", ["one.txt"], *arguments',
        '"filename", [pytest.param("one.txt", "two.txt")]',
        '"filename", [pytest.param(*values)]',
        '"filename", [pytest.param("one.txt", id="one", id="two")]',
        '["filename"], ["one.txt"]',
        '"filename", [("one.txt",)]',
        '"filename", [["one.txt"]]',
        '"filename", ["one.txt"], ids=dynamic_ids',
        '"filename", ["one.txt"], ids=[dynamic_id]',
        '"filename", ["one.txt"], ids=lambda value: value',
        '"filename", ["one.txt"], scope=get_scope()',
    ],
)
def test_malformed_call_shapes_and_dynamic_metadata_fail_closed(arguments):
    _assert_write_flagged(_fixture(f"@pytest.mark.parametrize({arguments})"))


@pytest.mark.parametrize(
    "arguments",
    [
        '"filename", ["one.txt"], False, ["one"], "function"',
        '"filename", ["one.txt"], ids=None, scope="function"',
    ],
)
def test_literal_metadata_and_supported_positional_arguments_preserve_proof(arguments):
    assert _scan(_fixture(f"@pytest.mark.parametrize({arguments})")) == []


def test_async_test_function_supports_direct_literal_proof_without_execution():
    source = _fixture().replace("\ndef test_write(", "\nasync def test_write(")
    assert _scan(source) == []


@pytest.mark.parametrize(
    "statement", ["import unknown as alias", "from unknown import replacement as alias"]
)
def test_function_import_cannot_rebind_a_derived_literal_alias(statement):
    source = _fixture(
        body=f'alias = filename\n{statement}\n(tmp_path / alias).write_text("fixture")'
    )
    _assert_write_flagged(source)
