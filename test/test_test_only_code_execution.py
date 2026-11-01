"""exec/eval weigh less only in modules proved to be test-only."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze

HARNESS = """
    import unittest

    def test_harness():
        namespace = {}
        exec(compile("x = 1", "harness", "exec"), namespace)
        assert eval("namespace['x']") == 1
"""


def _danger(tmp_path, files):
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(source))
    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, enable_danger=True)
    )
    assert not result.get("analysis_errors")
    return sorted(
        (
            str(row["file"]).split(str(tmp_path) + "/", 1)[1],
            row["rule_id"],
            row["severity"],
            row.get("original_severity"),
        )
        for row in result.get("danger", [])
    )


def test_exec_in_a_test_only_module_is_medium_and_production_stays_high(tmp_path):
    found = _danger(
        tmp_path,
        {
            "tests/test_harness.py": HARNESS,
            "app.py": "def run(code):\n    exec(code)\n",
        },
    )
    assert found == [
        ("app.py", "SKY-D202", "HIGH", None),
        ("tests/test_harness.py", "SKY-D201", "MEDIUM", "HIGH"),
        ("tests/test_harness.py", "SKY-D202", "MEDIUM", "HIGH"),
    ]


def test_test_module_imported_by_production_keeps_high(tmp_path):
    found = _danger(
        tmp_path,
        {
            "tests/__init__.py": "",
            "tests/test_harness.py": HARNESS,
            "app.py": "from tests.test_harness import test_harness\n",
        },
    )
    assert found == [
        ("tests/test_harness.py", "SKY-D201", "HIGH", None),
        ("tests/test_harness.py", "SKY-D202", "HIGH", None),
    ]


def test_test_named_production_module_without_tests_keeps_high(tmp_path):
    found = _danger(
        tmp_path,
        {"service/test_runner.py": "def run(code):\n    exec(code)\n"},
    )
    assert found == [("service/test_runner.py", "SKY-D202", "HIGH", None)]


def test_other_security_rules_in_test_only_modules_keep_their_severity(tmp_path):
    source = (
        HARNESS
        + "\n    import os\n    def test_shell(name):\n        os.system(name)\n"
    )
    found = _danger(tmp_path, {"tests/test_harness.py": source})
    assert ("tests/test_harness.py", "SKY-D202", "MEDIUM", "HIGH") in found
    others = [row for row in found if row[1] not in {"SKY-D201", "SKY-D202"}]
    assert others
    assert all(row[2] in {"HIGH", "CRITICAL"} for row in others)


@pytest.mark.parametrize(
    "importer",
    [
        "def run():\n    from tests.test_harness import test_harness\n    test_harness()\n",
        "import importlib\nharness = importlib.import_module('tests.' + NAME)\n",
        "try:\n    from tests import test_harness\nexcept ImportError:\n    test_harness = None\n",
    ],
    ids=["function-level-import", "dynamic-import", "try-import"],
)
def test_any_production_mention_of_the_module_keeps_high(tmp_path, importer):
    found = _danger(
        tmp_path,
        {"tests/test_harness.py": HARNESS, "app.py": importer},
    )
    harness = [row for row in found if row[0] == "tests/test_harness.py"]
    assert harness == [
        ("tests/test_harness.py", "SKY-D201", "HIGH", None),
        ("tests/test_harness.py", "SKY-D202", "HIGH", None),
    ]


def test_test_helpers_inside_a_shipped_package_keep_high(tmp_path):
    found = _danger(
        tmp_path,
        {"mylib/__init__.py": "", "mylib/test/test_sandbox.py": HARNESS},
    )
    assert [row[2] for row in found] == ["HIGH", "HIGH"]


def test_scanning_only_the_test_folder_keeps_high(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n")
    (tmp_path / "app.py").write_text("from tests.test_harness import test_harness\n")
    suite = tmp_path / "tests"
    suite.mkdir()
    (suite / "test_harness.py").write_text(textwrap.dedent(HARNESS))
    result = json.loads(
        analyze(str(suite), conf=0, grep_verify=False, enable_danger=True)
    )
    assert sorted(row["severity"] for row in result.get("danger", [])) == [
        "HIGH",
        "HIGH",
    ]


@pytest.mark.parametrize(
    "harness",
    [
        "import urllib.request\n\ndef test_plugin():\n    exec(urllib.request.urlopen(URL).read(), {})\n",
        "import requests\n\ndef test_plugin():\n    code = requests.get(URL).text\n    exec(code, {})\n",
    ],
    ids=["network-argument", "network-local"],
)
def test_test_code_running_network_input_keeps_high(tmp_path, harness):
    found = _danger(tmp_path, {"tests/test_plugin.py": harness})
    assert [row[2] for row in found if row[1] == "SKY-D202"] == ["HIGH"]
