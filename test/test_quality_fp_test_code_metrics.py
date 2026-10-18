"""Size and duplication metrics do not apply to test code.

SKY-Q501 skips test classes in test files: a test class groups many cases by
design. SKY-C401 skips clone groups whose members are all in test files:
near-identical test bodies are normal. Production classes, helper classes in
test files, and clone groups that reach production code are still reported.

Test classes are the ones a runner collects (pytest ``Test*`` names, unittest
``TestCase`` subclasses). Test files are judged from the project root, so the
folders a checkout happens to sit in do not count, and a ``*_test.py`` name
alone (``ab_test.py``) is not enough without tests in it.
"""

from __future__ import annotations

import ast
import json
import textwrap

import pytest

from skylos.rules.quality.class_size import GodClassRule


def _q501(
    code: str, filename: str, project_root: str | None = "/repo"
) -> list[tuple[str, int]]:
    source = textwrap.dedent(code)
    tree = ast.parse(source)
    context = {"filename": filename, "source": source, "project_root": project_root}
    rule = GodClassRule()
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            findings.extend(rule.visit_node(node, context) or [])
    return [(finding["name"], finding["value"]) for finding in findings]


def _methods(count: int, prefix: str = "test_case") -> str:
    return "".join(
        f"    def {prefix}_{index}(self):\n        assert run({index})\n"
        for index in range(count)
    )


def _attributes(count: int) -> str:
    assignments = "".join(f"        self.value_{index} = {index}\n" for index in range(count))
    return f"    def setUp(self):\n{assignments}"


TEST_CLASSES = {
    "pytest-class-in-tests-dir": (
        "class TestShapeChecks:\n" + _methods(23),
        "/repo/tests/python/evaluator_checks.py",
    ),
    "unittest-case-in-suffix-file": (
        "import unittest\n\nclass ShapeChecks(unittest.TestCase):\n" + _methods(23),
        "/repo/pkg/evaluator_test.py",
    ),
    "many-fixture-attributes": (
        "class TestFixtures:\n" + _attributes(16) + _methods(2),
        "/repo/tests/test_fixtures.py",
    ),
}


@pytest.mark.parametrize(
    "code,filename", TEST_CLASSES.values(), ids=TEST_CLASSES.keys()
)
def test_q501_skips_test_classes_in_test_files(code, filename):
    assert _q501(code, filename) == []


STILL_REPORTED = {
    "production-class": (
        "class Evaluator:\n" + _methods(23, prefix="handle"),
        "/repo/pkg/evaluator.py",
        [("Evaluator", 23)],
    ),
    "test-named-class-in-production-file": (
        "class TestRunner:\n" + _methods(23),
        "/repo/pkg/runner.py",
        [("TestRunner", 23)],
    ),
    "helper-class-in-test-file": (
        "class FakeStorage:\n" + _methods(23, prefix="read"),
        "/repo/tests/fakes.py",
        [("FakeStorage", 23)],
    ),
    # pytest only collects ``Test*`` classes; test-named methods alone do
    # not make a class a test class.
    "class-with-test-methods-in-prefix-file": (
        "class EvaluatorBehaviour:\n" + _methods(23),
        "/repo/pkg/test_evaluator.py",
        [("EvaluatorBehaviour", 23)],
    ),
    "production-class-with-a-test-method": (
        "class DatabaseClient:\n" + _methods(22, prefix="run") + _methods(1, prefix="test_connection"),
        "/repo/app/db.py",
        [("DatabaseClient", 23)],
    ),
    "ab-test-class-in-production": (
        "class ABTest:\n" + _methods(23, prefix="assign"),
        "/repo/src/experiments/ab_test.py",
        [("ABTest", 23)],
    ),
    "test-named-class-in-suffix-file-without-tests": (
        "class TestRunner:\n" + _methods(23, prefix="run"),
        "/repo/src/tools/load_test.py",
        [("TestRunner", 23)],
    ),
}


@pytest.mark.parametrize(
    "code,filename,expected", STILL_REPORTED.values(), ids=STILL_REPORTED.keys()
)
def test_q501_still_reports_non_test_classes(code, filename, expected):
    assert _q501(code, filename) == expected


ARITHMETIC = """
def NAME(value):
    total = value + 1
    total = total * 2
    total = total - 3
    total = total / 4
    total = total + 5
    total = total * 6
    total = total - 7
    total = total / 8
    return total
"""

TEXT = """
def NAME(text):
    parts = text.split(",")
    parts = [part.strip() for part in parts]
    parts = [part for part in parts if part]
    joined = "-".join(parts)
    joined = joined.upper()
    joined = joined.replace("A", "B")
    size = len(joined)
    flag = size > 10
    return joined, flag
"""

COUNTING = """
def NAME(items):
    seen = {}
    for item in items:
        key = item["id"]
        if key in seen:
            seen[key]["count"] += 1
        else:
            seen[key] = {"count": 1}
    ordered = sorted(seen.items())
    return dict(ordered)
"""


def test_c401_skips_groups_made_only_of_test_files(tmp_path, monkeypatch):
    from skylos.analyzer import analyze

    monkeypatch.setenv("SKYLOS_JOBS", "1")
    (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
    files = {
        # production clone pair: reported
        "pkg/first.py": ARITHMETIC.replace("NAME", "first"),
        "pkg/second.py": ARITHMETIC.replace("NAME", "second"),
        # test-only clone pair (a *_test.py file and a file under tests/):
        # not reported. test_*.py files never enter clone detection.
        "pkg/alpha_test.py": "import pytest\n" + TEXT.replace("NAME", "check_alpha"),
        "tests/python/beta_checks.py": "import pytest\n" + TEXT.replace("NAME", "check_beta"),
        # production code copied into a test: still reported
        "pkg/counting.py": COUNTING.replace("NAME", "count_items"),
        "tests/counting_test.py": COUNTING.replace("NAME", "check_count_items"),
    }
    for relative, body in files.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")

    result = json.loads(
        analyze(str(tmp_path), conf=0, enable_quality=True, grep_verify=False)
    )

    groups = sorted(
        finding["name"]
        for finding in result.get("quality", [])
        if finding.get("rule_id") == "SKY-C401"
    )
    assert groups == ["count_items", "first"]


def test_q501_ignores_folders_above_the_project_root():
    # The repository is checked out under a folder named ``tests``.
    code = "class TestShapeChecks:\n" + _methods(23)
    assert _q501(code, "/work/tests/proj/app/checks.py", "/work/tests/proj") == [
        ("TestShapeChecks", 23)
    ]


def test_q501_without_a_project_root_uses_the_file_name_only():
    code = "class TestShapeChecks:\n" + _methods(23)
    assert _q501(code, "/work/tests/proj/app/checks.py", None) == [("TestShapeChecks", 23)]
    assert _q501(code, "/work/proj/tests/test_checks.py", None) == []


def test_c401_reports_clones_in_production_files_named_like_tests(tmp_path, monkeypatch):
    from skylos.analyzer import analyze

    monkeypatch.setenv("SKYLOS_JOBS", "1")
    (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
    files = {
        "src/experiments/ab_test.py": ARITHMETIC.replace("NAME", "assign_variant"),
        "src/experiments/split_test.py": ARITHMETIC.replace("NAME", "split_traffic"),
    }
    for relative, body in files.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")

    result = json.loads(
        analyze(str(tmp_path), conf=0, enable_quality=True, grep_verify=False)
    )

    assert [
        finding["name"]
        for finding in result.get("quality", [])
        if finding.get("rule_id") == "SKY-C401"
    ] == ["assign_variant"]


def test_q501_reports_a_test_named_class_that_opts_out_of_collection():
    code = "class TestService:\n    __test__ = False\n\n" + _methods(23, prefix="operation")
    assert _q501(code, "/repo/tests/test_services.py") == [("TestService", 23)]


def test_c401_keeps_test_folder_clones_that_production_code_imports(tmp_path, monkeypatch):
    from skylos.analyzer import analyze

    monkeypatch.setenv("SKYLOS_JOBS", "1")
    (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
    files = {
        "tests/__init__.py": "",
        "tests/helpers_a.py": TEXT.replace("NAME", "clean_a"),
        "tests/helpers_b.py": TEXT.replace("NAME", "clean_b"),
        "app.py": "from tests.helpers_a import clean_a\n"
        "from tests import helpers_b\n\n\n"
        "def run(text):\n    return clean_a(text), helpers_b.clean_b(text)\n",
    }
    for relative, body in files.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")

    result = json.loads(
        analyze(str(tmp_path), conf=0, enable_quality=True, grep_verify=False)
    )

    assert [
        finding["name"]
        for finding in result.get("quality", [])
        if finding.get("rule_id") == "SKY-C401"
    ] == ["clean_a"]


STILL_REPORTED_ROUND5 = {
    # A test-management product's model in a ``test_*.py`` module.
    "model-in-test-named-module": (
        "class TestRun(Base):\n" + _methods(23, prefix="record"),
        "/repo/app/models/test_run.py",
        [("TestRun", 23)],
    ),
    # A lab system's ``tests`` package: no test runs from it.
    "domain-tests-package": (
        "class TestOrder:\n" + _methods(23, prefix="schedule"),
        "/repo/lims/tests/models.py",
        [("TestOrder", 23)],
    ),
    # pytest does not collect a ``Test*`` class with ``__init__``.
    "test-class-with-init": (
        "import pytest\n\nclass TestHarness:\n    def __init__(self):\n        self.x = 1\n"
        + _methods(23),
        "/repo/tests/test_harness.py",
        [("TestHarness", 23)],  # __init__ is a protocol method, outside the count.
    ),
}


@pytest.mark.parametrize(
    "code,filename,expected",
    STILL_REPORTED_ROUND5.values(),
    ids=STILL_REPORTED_ROUND5.keys(),
)
def test_q501_reports_classes_no_test_runner_collects(code, filename, expected):
    assert _q501(code, filename) == expected


def test_c401_reports_production_modules_named_like_tests(tmp_path, monkeypatch):
    # ``def test_connection(host)`` is a production health check here; the
    # admin module imports both copies.
    from skylos.analyzer import analyze

    monkeypatch.setenv("SKYLOS_JOBS", "1")
    (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
    body = COUNTING.replace("NAME", "summarize") + "\n\ndef test_connection(host):\n    return bool(host)\n"
    files = {
        "diagnostics/__init__.py": "",
        "diagnostics/smtp_test.py": body,
        "diagnostics/db_test.py": body.replace("summarize", "summarize_db"),
        "app/admin.py": "from diagnostics import smtp_test, db_test\n\n\n"
        "def check():\n    return smtp_test.test_connection('a'), db_test.test_connection('b')\n",
    }
    for relative, text in files.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    result = json.loads(
        analyze(str(tmp_path), conf=0, enable_quality=True, grep_verify=False)
    )

    assert [
        finding["name"]
        for finding in result.get("quality", [])
        if finding.get("rule_id") == "SKY-C401"
    ] == ["summarize_db"]  # the group is named after its first file
