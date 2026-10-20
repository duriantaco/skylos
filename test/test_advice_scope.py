"""Presentation context is positive, bounded evidence, independent of raw checks."""

import ast
from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.core.test_paths import is_test_code_path
from skylos.reporting.advice_scope import advice_source_context
from skylos.rules.quality._typing import is_typing_test_path
from skylos.rules.quality.practices import TypeAnnotationPracticeRule


PYTEST = """[tool.pytest]
python_files = ["checks/*.py"]
python_classes = ["Acceptance"]
python_functions = ["check_"]
testpaths = ["checks"]
[tool.mypy]
files = ["checks"]
disallow_untyped_defs = true
"""
PACKAGING = """[tool.hatch.build.targets.sdist]
exclude = ["/profiling"]
[tool.hatch.build.targets.wheel]
only-include = ["src"]
sources = ["src"]
"""


def _write(root, relative, source):
    root = root.resolve()
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("fixture path leaves root")
    path = root / relative
    path.resolve().relative_to(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, source)
    return path


def _row(file, **kwargs):
    return {"rule_id": "SKY-Q301", "file": str(file), "line": 1, **kwargs}


@pytest.mark.parametrize(
    "relative,source,expected",
    [
        ("tests/helpers.py", "def helper(): pass\n", "test"),
        ("package/tests/helpers.py", "def helper(): pass\n", "test"),
        ("src/package/tests/helpers.py", "def helper(): pass\n", "test"),
        ("test_unit.py", "import pytest\ndef test_case(): pass\n", "test"),
        ("test_unit.py", "def test_service(): return 'production'\n", None),
        ("package/test/client.py", "def client(): pass\n", None),
        ("app/pages/tests/view.ts", "export const route = 1;\n", None),
        ("unit_test.go", "package unit\n", "test"),
        ("tests/service.go", "package service\n", None),
        ("examples/demo.py", "def run(): pass\n", "example"),
        ("src/package/examples/demo.py", "def run(): pass\n", "example"),
        ("docs_src/demo.py", "def run(): pass\n", "example"),
        ("package/api/examples/view.py", "def run(): pass\n", None),
        ("benchmarks/measure.py", "def run(): pass\n", "profiling"),
        ("src/package/core.py", "def run(): pass\n", None),
        ("vendor/core.py", "def run(): pass\n", None),
        ("src/blib2to3/core.py", "def run(): pass\n", None),
    ],
)
def test_only_relative_project_conventions_prove_context(
    tmp_path, relative, source, expected
):
    path = _write(tmp_path, relative, source)
    assert advice_source_context(_row(path), tmp_path) == expected
    assert advice_source_context(_row(relative), tmp_path) == expected


def test_unknown_root_missing_file_and_ancestor_names_preserve_advice(tmp_path):
    root = tmp_path / "tests" / "checkout"
    root.mkdir(parents=True)
    path = _write(root, "src/service.py", "def run(): pass\n")
    assert advice_source_context(_row(path), root) is None
    assert advice_source_context(_row(path)) is None
    assert advice_source_context(_row(root / "tests/missing.py"), root) is None
    assert advice_source_context(_row("../tests/service.py"), root) is None
    assert advice_source_context(_row(path), root / "src") is None


def test_outside_and_symlink_evidence_cannot_relabel_advice(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    outside = _write(tmp_path, "outside/tests/case.py", "import pytest\n")
    assert advice_source_context(_row(outside), root) is None
    (root / "tests").symlink_to(outside.parent, target_is_directory=True)
    assert advice_source_context(_row(root / "tests/case.py"), root) is None
    source = _write(root, "real.py", "import pytest\n")
    (root / "test_alias.py").symlink_to(source)
    assert advice_source_context(_row(root / "test_alias.py"), root) is None


@pytest.mark.parametrize(
    "rule", ["SKY-D324", "SKY-S101", "SKY-L001", "SKY-L011", "SKY-UNKNOWN"]
)
def test_context_never_classifies_risk_or_unknown_rules(tmp_path, rule):
    path = _write(tmp_path, "tests/case.py", "import pytest\n")
    finding = _row(path, rule_id=rule, finding_type="advice")
    assert advice_source_context(finding, tmp_path) is None


def test_context_never_classifies_custom_rules_or_mutates_findings(tmp_path):
    path = _write(tmp_path, "tests/case.py", "import pytest\n")
    finding = _row(path)
    original = dict(finding)
    assert advice_source_context(finding, tmp_path) == "test"
    assert finding == original
    assert advice_source_context({**finding, "custom_rule": True}, tmp_path) is None


def test_guarded_native_collection_is_used_without_relabeling_security_paths(tmp_path):
    _write(tmp_path, "pyproject.toml", PYTEST)
    source = "def check_case(value, enabled: bool) -> str:\n    return str(value)\n"
    path = _write(tmp_path, "checks/cases.py", source)
    assert advice_source_context(_row(path), tmp_path) == "test"
    assert is_typing_test_path(path, tmp_path)
    assert not is_test_code_path(path, tmp_path)


@pytest.mark.parametrize(
    "source",
    [
        "def check_case(value, enabled: bool) -> str:\n    return str(value)\n",
        "def check_case(value: str):\n    return value\n",
        "class AcceptanceCases:\n    def check_case(self, value, enabled: bool) -> str:\n        return str(value)\n",
        # Collection is module policy: this helper is not itself a test.
        "def check_case():\n    assert True\ndef helper(value, enabled: bool) -> str:\n    return str(value)\n",
    ],
)
@pytest.mark.parametrize("legacy", [False, True])
def test_typing_rules_skip_proven_configured_test_modules(tmp_path, source, legacy):
    config = (
        PYTEST.replace("[tool.pytest]", "[tool.pytest.ini_options]")
        if legacy
        else PYTEST
    )
    _write(tmp_path, "pyproject.toml", config)
    path = _write(tmp_path, "checks/cases.py", source)
    rule = TypeAnnotationPracticeRule()
    assert not rule.visit_node(
        ast.parse(source),
        {"filename": str(path), "source": source, "project_root": tmp_path},
    )
    assert advice_source_context(_row(path), tmp_path) == "test"


@pytest.mark.parametrize(
    "source",
    [
        "def process(value, enabled: bool) -> str:\n    return str(value)\n",
        "__test__ = False\ndef check_case(value, enabled: bool) -> str:\n    return str(value)\n",
        "def check_case(value, enabled: bool) -> str:\n    return str(value)\ncheck_case = None\n",
        "class AcceptanceCases:\n    def __init__(self): pass\n    def check_case(self, value, enabled: bool) -> str:\n        return str(value)\n",
        "import pytest\n@pytest.fixture\ndef check_case(value, enabled: bool) -> str:\n    return str(value)\ndef public(value, enabled: bool) -> str:\n    return str(value)\n",
    ],
)
def test_typing_advice_remains_without_collection_proof(tmp_path, source):
    _write(tmp_path, "pyproject.toml", PYTEST)
    path = _write(tmp_path, "checks/cases.py", source)
    findings = TypeAnnotationPracticeRule().visit_node(
        ast.parse(source),
        {"filename": str(path), "source": source, "project_root": tmp_path},
    )
    assert findings and any(row["rule_id"] == "SKY-T101" for row in findings)
    assert advice_source_context(_row(path), tmp_path) is None


def test_bad_rewritten_config_never_reuses_old_typing_scope(tmp_path):
    config = _write(tmp_path, "pyproject.toml", PYTEST)
    source = "def check_case(value, enabled: bool) -> str:\n    return str(value)\n"
    path = _write(tmp_path, "checks/cases.py", source)
    assert is_typing_test_path(path, tmp_path)
    assert write_text_no_symlink(
        config, PYTEST.replace('["checks/*.py"]', '"checks/*.py"')
    )
    assert not is_typing_test_path(path, tmp_path)
    assert advice_source_context(_row(path), tmp_path) is None


def test_symlinked_and_higher_precedence_invalid_pytest_config_preserve_advice(
    tmp_path,
):
    config = _write(tmp_path, "pyproject.toml", PYTEST)
    source = "def check_case(value, enabled: bool) -> str:\n    return str(value)\n"
    path = _write(tmp_path, "checks/cases.py", source)
    assert advice_source_context(_row(path), tmp_path) == "test"
    higher = _write(tmp_path, "pytest.toml", "[pytest]\npython_files = 'checks/*.py'\n")
    assert advice_source_context(_row(path), tmp_path) is None
    higher.unlink()
    config.unlink()
    outside = _write(tmp_path, "other/config.toml", PYTEST)
    config.symlink_to(outside)
    assert advice_source_context(_row(path), tmp_path) is None
    assert not is_typing_test_path(path, tmp_path, source=source)


def test_source_rewrite_invalidates_configured_collection_context(tmp_path):
    _write(tmp_path, "pyproject.toml", PYTEST)
    path = _write(tmp_path, "checks/cases.py", "def check_case():\n    assert True\n")
    assert advice_source_context(_row(path), tmp_path) == "test"
    assert write_text_no_symlink(path, "def process():\n    return 'production'\n")
    assert advice_source_context(_row(path), tmp_path) is None


@pytest.mark.parametrize("method", [False, True])
@pytest.mark.parametrize(
    "imports,decorator,expected",
    [
        ("import pytest\n", "pytest.mark.parametrize('value', [1])", "test"),
        ("import pytest as pt\n", "pt.mark.slow", "test"),
        ("from pytest import mark as marker\n", "marker.slow", "test"),
        ("import pytest\npytest = other\n", "pytest.mark.slow", None),
        ("import pytest\npytest.mark = replacement\n", "pytest.mark.slow", None),
        ("from helpers import wrapper\n", "wrapper", None),
        ("from helpers import wrapper\n", "wrapper()", None),
        ("def wrapper(function):\n    return None\n", "wrapper", None),
    ],
)
def test_only_proven_mark_decorators_establish_configured_collection(
    tmp_path, method, imports, decorator, expected
):
    _write(tmp_path, "pyproject.toml", PYTEST)
    definition = (
        f"@{decorator}\n"
        "def check_case(value, enabled: bool) -> str:\n    return str(value)\n"
    )
    if method:
        definition = definition.replace("check_case(value", "check_case(self, value")
        definition = "class AcceptanceCases:\n" + "".join(
            "    " + line for line in definition.splitlines(keepends=True)
        )
    source = imports + definition
    path = _write(tmp_path, "checks/cases.py", source)
    assert advice_source_context(_row(path), tmp_path) == expected
    findings = TypeAnnotationPracticeRule().visit_node(
        ast.parse(source),
        {"filename": str(path), "source": source, "project_root": tmp_path},
    )
    assert bool(findings) == (expected is None)


@pytest.mark.parametrize(
    "imports,shadow,decorator",
    [
        ("import pytest\n", "pytest = custom", "pytest.mark.slow"),
        ("from pytest import mark as marker\n", "marker = custom", "marker.slow"),
    ],
)
def test_class_scope_shadowing_does_not_reuse_global_pytest_mark_evidence(
    tmp_path, imports, shadow, decorator
):
    _write(tmp_path, "pyproject.toml", PYTEST)
    source = (
        imports
        + "class AcceptanceCases:\n"
        + f"    {shadow}\n    @{decorator}\n"
        + "    def check_case(self, value, enabled: bool) -> str:\n"
        + "        return str(value)\n"
    )
    path = _write(tmp_path, "checks/cases.py", source)
    assert advice_source_context(_row(path), tmp_path) is None
    assert not is_typing_test_path(path, tmp_path, source=source)


def _vendor(root):
    path = _write(root, "src/parser/core.py", "def parse(): pass\n")
    readme = _write(
        root,
        "src/parser/README",
        "A subset taken from Python 3.7.\nReasons for forking:\nUpstream https://github.com/python/cpython\n",
    )
    license_path = _write(
        root,
        "src/parser/LICENSE",
        "Copyright upstream authors. Permission to copy this software.\n",
    )
    return path, readme, license_path


def test_vendored_context_requires_local_provenance_and_license(tmp_path):
    path, readme, license_path = _vendor(tmp_path)
    assert advice_source_context(_row(path), tmp_path) == "vendored"
    nested = _write(tmp_path, "src/parser/nested/core.py", "def parse(): pass\n")
    assert advice_source_context(_row(nested), tmp_path) == "vendored"
    license_path.unlink()
    assert advice_source_context(_row(path), tmp_path) is None
    assert write_text_no_symlink(license_path, "Copyright and license.\n")
    assert write_text_no_symlink(
        readme, "This is not vendored code. Upstream https://example.com\n"
    )
    assert advice_source_context(_row(path), tmp_path) is None


def test_root_readme_and_sibling_provenance_do_not_relabel_first_party_code(tmp_path):
    _write(
        tmp_path,
        "README.md",
        "Vendored code taken from Python 3.7 https://example.com\n",
    )
    _write(tmp_path, "LICENSE", "Copyright and license.\n")
    path = _write(tmp_path, "src/core.py", "def run(): pass\n")
    _vendor(tmp_path)
    assert advice_source_context(_row(path), tmp_path) is None


def test_symlinked_vendor_metadata_is_not_evidence(tmp_path):
    path, readme, _ = _vendor(tmp_path)
    readme.unlink()
    outside = _write(
        tmp_path, "other/README", "Taken from Python 3.7 https://example.com\n"
    )
    readme.symlink_to(outside)
    assert advice_source_context(_row(path), tmp_path) is None


def _dataset():
    return "config = some.Structure(values=set(" + repr(list(range(160))) + "))\n"


def test_profile_data_requires_both_packaging_and_static_data_evidence(tmp_path):
    path = _write(tmp_path, "profiling/sample.py", _dataset())
    assert advice_source_context(_row(path), tmp_path) is None
    config = _write(tmp_path, "pyproject.toml", PACKAGING)
    assert advice_source_context(_row(path), tmp_path) == "profiling"
    assert write_text_no_symlink(config, PACKAGING.replace('["src"]', '["profiling"]'))
    assert advice_source_context(_row(path), tmp_path) is None


@pytest.mark.parametrize(
    "source",
    [
        "import some\n" + _dataset(),
        "def generate():\n    return " + repr(list(range(160))) + "\n",
        "for item in range(160):\n    print(item)\n",
        "some = factory()\n" + _dataset(),
        "values = " + repr(list(range(160))) + "\nrun(values)\n",
        "config = some.Structure(values=load())\n",
        "config = str.format(" + repr(list(range(160))) + ")\n",
        "config = __builtins__.eval(" + repr(list(range(160))) + ")\n",
        "config = some.Structure(values=[1, 2])\n",
        "not valid python!!!\n",
    ],
)
def test_real_or_unknown_profile_programs_keep_advice(tmp_path, source):
    _write(tmp_path, "pyproject.toml", PACKAGING)
    path = _write(tmp_path, "profiling/sample.py", source)
    assert advice_source_context(_row(path), tmp_path) is None


def _clones(first, second, count=2):
    return _row(
        first,
        rule_id="SKY-C401",
        message=f"Clone group detected (type1, sim=0.982, members={count}) examples: {first}:1-2 (function a), {second}:1-2 (function b)",
    )


def test_clone_context_requires_every_exported_member_to_share_proven_context(tmp_path):
    first = _write(tmp_path, "examples/a.py", "def a():\n    pass\n")
    second = _write(tmp_path, "examples/b.py", "def b():\n    pass\n")
    assert advice_source_context(_clones(first, second), tmp_path) == "example"
    assert advice_source_context(_clones(first, second, count=5), tmp_path) is None
    production = _write(tmp_path, "src/core.py", "def b():\n    pass\n")
    assert advice_source_context(_clones(first, production), tmp_path) is None
    test_file = _write(tmp_path, "tests/case.py", "def b():\n    pass\n")
    assert advice_source_context(_clones(first, test_file), tmp_path) is None
    assert advice_source_context(_row(first, rule_id="SKY-C401"), tmp_path) is None


def test_clone_preview_count_ranges_and_representative_must_be_consistent(tmp_path):
    first = _write(tmp_path, "examples/a.py", "def a():\n    pass\n")
    second = _write(tmp_path, "examples/b.py", "def b():\n    pass\n")
    finding = _clones(first, second)
    for changed in [
        {"message": finding["message"].replace("members=2", "members=3")},
        {"message": finding["message"].replace(":1-2", ":3-2")},
        {"file": str(second)},
        {"line": 2},
        {"message": finding["message"].replace(str(second), str(first))},
    ]:
        assert advice_source_context({**finding, **changed}, tmp_path) is None
