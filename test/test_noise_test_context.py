"""Real test-context evidence removes advice while production lookalikes stay."""

import ast
import json
import os

import pytest

from skylos.rules.quality.class_size import GodClassRule


def _write(root, files):
    root = root.resolve()
    for name, source in files.items():
        path = (root / name).resolve()
        path.relative_to(root)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(source)


def test_fixture_writer_rejects_paths_outside_its_root(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    with pytest.raises(ValueError):
        _write(root, {"../outside.py": "unexpected"})
    assert not (tmp_path / "outside.py").exists()


def test_fixture_writer_does_not_overwrite_existing_files(tmp_path):
    _write(tmp_path, {"case.py": "original"})
    with pytest.raises(FileExistsError):
        _write(tmp_path, {"case.py": "replacement"})
    assert (tmp_path / "case.py").read_text(encoding="utf-8") == "original"


def test_fixture_writer_rejects_symlinks_outside_its_root(tmp_path):
    _write(tmp_path, {"outside.py": "original"})
    root = tmp_path / "project"
    root.mkdir()
    try:
        (root / "case.py").symlink_to(tmp_path / "outside.py")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    with pytest.raises(ValueError):
        _write(root, {"case.py": "replacement"})
    assert (tmp_path / "outside.py").read_text(encoding="utf-8") == "original"


def _methods(prefix="test_case", count=23):
    return "".join(
        f"    def {prefix}_{index}(self):\n        assert {index} >= 0\n"
        for index in range(count)
    )


def _q501(root, code, filename="tests/test_cases.py"):
    rule = GodClassRule()
    tree = ast.parse(code)
    context = {"filename": str(root / filename), "source": code, "project_root": root}
    return [
        finding
        for node in ast.walk(tree)
        for finding in rule.visit_node(node, context) or []
    ]


@pytest.mark.parametrize(
    "filename,config",
    [
        ("pyproject.toml", '[tool.pytest.ini_options]\npython_classes = "test_*"\n'),
        ("pyproject.toml", '[tool.pytest.ini_options]\npython_classes = ["test_*"]\n'),
        ("pytest.ini", "[pytest]\npython_classes = test_*\n"),
        ("tox.ini", "[pytest]\npython_classes = test_*\n"),
        ("setup.cfg", "[tool:pytest]\npython_classes = test_*\n"),
    ],
)
def test_configured_pytest_class_names_are_not_god_classes(tmp_path, filename, config):
    _write(tmp_path, {filename: config})
    code = "class test_Worker:\n" + _methods()
    assert _q501(tmp_path, code) == []
    # Collection config says nothing about classes in shipped modules.
    findings = _q501(tmp_path, code, "package/worker.py")
    assert [(item["rule_id"], item["name"]) for item in findings] == [
        ("SKY-Q501", "test_Worker")
    ]


@pytest.mark.parametrize(
    "class_body",
    ["", "    __test__ = False\n", "    def __init__(self):\n        pass\n"],
)
def test_lowercase_class_needs_actual_collection_proof(tmp_path, class_body):
    code = "class test_Worker:\n" + class_body + _methods()
    assert _q501(tmp_path, code)[0]["name"] == "test_Worker"
    if class_body:
        _write(tmp_path, {"pytest.ini": "[pytest]\npython_classes = test_*\n"})
        assert _q501(tmp_path, code)[0]["name"] == "test_Worker"


def _fixture_setup():
    return "    def setup_method(self):\n" + "".join(
        f"        self.item_{index} = {index}\n" for index in range(18)
    )


def test_setup_helpers_remain_measured_even_when_collected_tests_inherit_them(tmp_path):
    base = "class WorkerCase:\n" + _fixture_setup()
    tests = "\nclass TestWorker(WorkerCase):\n" + _methods(count=1)
    assert _q501(tmp_path, base + tests)[0]["name"] == "WorkerCase"
    assert _q501(tmp_path, base)[0]["name"] == "WorkerCase"
    # A setup-named method alone cannot hide an ordinary helper class.
    ordinary = base + "    def process(self):\n        return self.item_0\n"
    assert _q501(tmp_path, ordinary + tests)[0]["name"] == "WorkerCase"
    assert _q501(tmp_path, base + tests, "package/worker.py")[0]["name"] == "WorkerCase"


BODY = """def normalize(value):
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


def _clones(root, monkeypatch):
    from skylos.analyzer import analyze

    monkeypatch.setenv("SKYLOS_JOBS", "1")
    result = json.loads(
        analyze(str(root), conf=0, enable_quality=True, grep_verify=False)
    )
    return [
        item for item in result.get("quality", []) if item.get("rule_id") == "SKY-C401"
    ]


@pytest.mark.parametrize("production_import", [False, True])
def test_suite_helpers_do_not_keep_all_test_clones_unless_production_reaches_them(
    tmp_path, monkeypatch, production_import
):
    files = {
        "pyproject.toml": "[tool.skylos]\n",
        "tests/__init__.py": "tests_datadir = 'sample_data'\n",
        "tests/test_first.py": "import pytest\n" + BODY,
        "tests/test_second.py": "import pytest\n"
        + BODY.replace("normalize", "normalize_second"),
        # A helper importing its own test package used to retain every group.
        "tests/mockserver/http.py": "from tests import tests_datadir\n",
        "tests/server.py": "from tests.mockserver import http\n",
    }
    if production_import:
        # Follow more than one helper edge; a real shared implementation must
        # remain visible even if it lives in an otherwise genuine test suite.
        files["app.py"] = "from tests import server\n"
    _write(tmp_path, files)
    findings = _clones(tmp_path, monkeypatch)
    assert bool(findings) is production_import
    if findings:
        assert findings[0]["rule_id"] == "SKY-C401"


def test_production_submodule_import_also_reaches_test_package_initializer(
    tmp_path, monkeypatch
):
    _write(
        tmp_path,
        {
            "tests/__init__.py": "from tests.test_first import normalize\n",
            "tests/test_first.py": "import pytest\n" + BODY,
            "tests/test_second.py": "import pytest\n"
            + BODY.replace("normalize", "normalize_second"),
            "tests/config.py": "VALUE = 1\n",
            "app.py": "from tests.config import VALUE\n",
        },
    )
    assert _clones(tmp_path, monkeypatch)[0]["rule_id"] == "SKY-C401"


READER = """def read_case(path):
    lines = path.read_text().splitlines()
    before, after = [], []
    result = before
    for line in lines:
        if line == "# output":
            result = after
        else:
            result.append(line)
    return before, after
"""


@pytest.mark.parametrize(
    "reader,production_import,expected",
    [(True, False, False), (False, False, True), (True, True, True)],
)
def test_golden_clone_pairs_need_a_text_reader_and_no_production_import(
    tmp_path, monkeypatch, reader, production_import, expected
):
    files = {
        "pyproject.toml": "[tool.skylos]\n",
        "tests/data/case.py": BODY + "\n# output\n" + BODY,
    }
    if reader:
        files["tests/util.py"] = READER
    if production_import:
        files["app.py"] = "from tests.data import case\n"
    _write(tmp_path, files)
    findings = _clones(tmp_path, monkeypatch)
    assert bool(findings) is expected


def test_golden_marker_cannot_hide_shipped_duplicates(tmp_path, monkeypatch):
    _write(
        tmp_path,
        {"package/case.py": BODY + "\n# output\n" + BODY, "tests/util.py": READER},
    )
    assert _clones(tmp_path, monkeypatch)[0]["rule_id"] == "SKY-C401"


def test_unrelated_text_reader_does_not_prove_a_golden_fixture_protocol(
    tmp_path, monkeypatch
):
    _write(
        tmp_path,
        {
            "tests/data/case.py": BODY + "\n# output\n" + BODY,
            "tests/util.py": "def read(path):\n    print('# output')\n    return path.read_text()\n",
        },
    )
    assert _clones(tmp_path, monkeypatch)[0]["rule_id"] == "SKY-C401"


@pytest.mark.parametrize(
    "import_text,decorator",
    [
        ("from typing import overload", "overload"),
        ("from typing_extensions import overload as signature", "signature"),
        ("import typing as t", "t.overload"),
    ],
)
def test_typing_overload_signatures_do_not_inflate_implemented_method_count(
    tmp_path, import_text, decorator
):
    code = import_text + "\nclass Worker:\n" + _methods("work", count=19)
    code += f"    @{decorator}\n    def process(self, value: str): ...\n"
    code += f"    @{decorator}\n    def process(self, value: int): ...\n"
    code += "    def process(self, value):\n        return value\n"
    assert _q501(tmp_path, code, "package/worker.py") == []
    # The next real method still crosses the existing limit of twenty.
    findings = _q501(tmp_path, code + _methods("more", count=1), "package/worker.py")
    assert [(item["rule_id"], item["value"]) for item in findings] == [("SKY-Q501", 21)]


@pytest.mark.parametrize(
    "prefix,class_binding",
    [
        ("def overload(fn):\n    return fn\n", ""),
        ("from typing import overload\noverload = custom_decorator\n", ""),
        ("from typing import overload\n", "    overload = custom_decorator\n"),
        # A local import cannot prove an unrelated module decorator binding.
        (
            "overload = custom_decorator\ndef factory():\n    from typing import overload\n",
            "",
        ),
    ],
)
def test_overload_lookalikes_and_shadowed_imports_still_count(
    tmp_path, prefix, class_binding
):
    code = prefix + "class Worker:\n" + class_binding + _methods("work", count=19)
    code += "    @overload\n    def process(self, value: str): ...\n"
    code += "    @overload\n    def process(self, value: int): ...\n"
    code += "    def process(self, value):\n        return value\n"
    assert _q501(tmp_path, code, "package/worker.py")[0]["value"] == 22


def test_property_accessors_keep_the_existing_method_count(tmp_path):
    code = "from typing import overload\nclass Worker:\n" + _methods("work", count=19)
    code += "    @property\n    def value(self):\n        return self._value\n"
    code += (
        "    @value.setter\n    def value(self, value):\n        self._value = value\n"
    )
    assert _q501(tmp_path, code, "package/worker.py")[0]["value"] == 21


def test_mutating_the_typing_module_cannot_hide_method_declarations(tmp_path):
    code = (
        "import typing as t\nt.overload = custom_decorator\nclass Worker:\n"
        + _methods("work", count=19)
    )
    code += "    @t.overload\n    def process(self, value: str): ...\n"
    code += "    @t.overload\n    def process(self, value: int): ...\n"
    code += "    def process(self, value):\n        return value\n"
    assert _q501(tmp_path, code, "package/worker.py")[0]["value"] == 22
