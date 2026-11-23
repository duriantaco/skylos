"""Done must not count a run as passing when the change could have forged it.

Each case mirrors a red-team reproduction: a broken ``add()`` plus a file,
hook, fixture or setting that makes the tests look green.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import pytest

from skylos.done.base import open_comparison
from skylos.done.config import DoneConfig
from skylos.done.runner import _probe_problem, run_tests
from skylos.done.test_config import detect_loosened_test_config

BROKEN = "def add(a, b):\n    return a - b\n"
FORGED_JUNIT = """\
import os, sys
junit = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--junitxml="))
cases = [("tests/test_calc.py", "test_add"), ("tests/test_other.py", "test_truth")]
body = "".join(
    f'<testcase classname="x" file="{f}" line="0" name="{n}" time="0"/>'
    for f, n in cases
)
with open(junit, "w") as handle:
    handle.write(
        '<testsuites><testsuite name="pytest" errors="0" failures="0" '
        f'skipped="0" tests="{len(cases)}">{body}</testsuite></testsuites>'
    )
sys.exit(0)
"""
REWRITE_AT_EXIT = """\
def add(a, b):
    return a - b


def _finish():
    import os, re, sys
    junit = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--junitxml="))
    xml = open(junit).read()
    xml = re.sub(r"<failure\\b.*?</failure>", "", xml, flags=re.S)
    open(junit, "w").write(re.sub(r'failures="\\d+"', 'failures="0"', xml))
    os._exit(0)


import atexit
atexit.register(_finish)
"""
REPORT_REWRITER = """\
import pytest


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.failed:
        report.outcome = "passed"
        report.longrepr = None
"""


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _apply(root: Path, files: dict[str, str | None]) -> None:
    for rel, text in files.items():
        path = root / rel
        if text is None:
            path.unlink()
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(  # skylos: ignore[SKY-D324] fixture files inside pytest's own tmp_path
            dedent(text), encoding="utf-8"
        )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _apply(
        root,
        {
            "src/calc.py": "def add(a, b):\n    return a + b\n",
            "tests/test_calc.py": (
                "from calc import add\n\n\n"
                "def test_add():\n    assert add(1, 2) == 3\n\n\n"
                "def test_add_zero():\n    assert add(0, 5) == 5\n"
            ),
            "tests/test_other.py": "def test_truth():\n    assert 1 + 1 == 2\n",
            "pyproject.toml": (
                '[tool.pytest.ini_options]\naddopts = "--strict-markers -W error"\n'
            ),
        },
    )
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    _git(root, "switch", "-qc", "feature")
    return root


def _findings(root: Path, files: dict[str, str | None]) -> list[str]:
    _apply(root, files)
    return [
        f"{item.file}: {item.message}"
        for item in detect_loosened_test_config(open_comparison(root, "main"))
    ]


# ---------------------------------------------------------------------------
# Files that stand in for pytest, the probe or Python's startup
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "pytest.py",
        "src/pytest.py",
        "_pytest/__init__.py",
        "pluggy.py",
        "skylos_done_pytest_plugin.py",
        "src/sitecustomize.py",
        "usercustomize.py",
        ".venv/lib/python3.13/site-packages/pytest/__init__.py",
        "tools/startup.pth",
    ],
)
def test_a_file_that_would_shadow_the_runner_is_tampering(repo: Path, path: str):
    findings = _findings(repo, {"src/calc.py": BROKEN, path: "x = 1\n"})
    assert any(f.startswith(f"{path}: ") and "Python would load" in f for f in findings)


@pytest.mark.parametrize(
    "path", ["docs/examples/pytest.py", "src/app/pluggy_adapter.py", "pytest.md"]
)
def test_lookalike_names_outside_import_roots_are_ordinary(repo: Path, path: str):
    assert _findings(repo, {path: "x = 1\n"}) == []


# ---------------------------------------------------------------------------
# conftest hooks and fixtures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("hook", "conftest"),
    [
        (
            "pytest_pyfunc_call",
            "def pytest_pyfunc_call(pyfuncitem):\n    return True\n",
        ),
        (
            "pytest_configure",
            (
                "class _Reporter:\n    pass\n\n\n"
                "def pytest_configure(config):\n"
                "    config.pluginmanager.register(_Reporter(), 'helpers-reporter')\n"
            ),
        ),
        (
            "pytest_runtestloop",
            "def pytest_runtestloop(session):\n    return True\n",
        ),
        (
            "pytest_runtest_makereport",
            "from tests.helpers import pytest_runtest_makereport\n",
        ),
    ],
)
def test_hooks_that_skip_calls_or_register_plugins_are_found(
    repo: Path, hook: str, conftest: str
):
    findings = _findings(repo, {"tests/conftest.py": conftest})
    assert any(f"adds the pytest hook {hook}" in f for f in findings), findings


def test_a_hook_added_to_an_existing_local_plugin_is_found(repo: Path):
    _apply(
        repo,
        {
            "tests/conftest.py": 'pytest_plugins = ["tests.helpers"]\n',
            "tests/__init__.py": "",
            "tests/helpers.py": "VALUE = 1\n",
        },
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "local plugin at the base")
    _git(repo, "branch", "-f", "main")
    findings = _findings(repo, {"tests/helpers.py": "VALUE = 1\n\n" + REPORT_REWRITER})
    assert any(
        f.startswith("tests/helpers.py: adds the pytest hook pytest_runtest_makereport")
        for f in findings
    ), findings


def test_marker_and_option_declarations_are_not_reported(repo: Path):
    conftest = """\
        def pytest_configure(config):
            \"\"\"Markers.\"\"\"
            config.addinivalue_line("markers", "slow: slow tests")


        def pytest_addoption(parser):
            group = parser.getgroup("demo")
            group.addoption("--runslow", action="store_true")
        """
    assert _findings(repo, {"tests/conftest.py": conftest}) == []


def test_a_fixture_that_skips_tests_at_run_time_is_found(repo: Path):
    conftest = """\
        import pytest


        @pytest.fixture(autouse=True)
        def _platform_guard(request):
            if request.node.module.__name__.endswith("test_calc"):
                pytest.skip("calc backend unavailable in this environment")


        @pytest.fixture
        def docker():
            pytest.skip("docker is not installed")
        """
    findings = _findings(repo, {"tests/conftest.py": conftest})
    assert any("fixture _platform_guard can now skip" in f for f in findings)
    # A brand-new fixture only reaches tests written to use it.
    assert not any("fixture docker" in f for f in findings)


# ---------------------------------------------------------------------------
# pytest settings: pytest.toml, precedence and removed strictness
# ---------------------------------------------------------------------------


def test_a_dot_pytest_toml_that_replaces_the_base_settings_is_found(repo: Path):
    findings = _findings(
        repo, {".pytest.toml": '[pytest]\nminversion = "8.0"\n', "src/calc.py": BROKEN}
    )
    assert any(
        f.startswith(".pytest.toml: ") and "warnings into errors" in f for f in findings
    )
    assert any("--strict-markers" in f for f in findings)


def test_a_pytest_toml_that_loads_a_local_plugin_is_found(repo: Path):
    findings = _findings(
        repo,
        {
            "pytest.toml": '[pytest]\naddopts = ["-p", "qa_report"]\n',
            "qa_report.py": REPORT_REWRITER,
        },
    )
    assert any("own pytest plugin 'qa_report'" in f for f in findings), findings


def test_removing_strict_options_from_the_same_file_is_found(repo: Path):
    findings = _findings(
        repo, {"pyproject.toml": '[tool.pytest.ini_options]\naddopts = "-q"\n'}
    )
    assert any("--strict-markers" in f for f in findings)
    assert any("warnings into errors (error)" in f for f in findings)


def test_deleting_the_config_pytest_reads_is_found(repo: Path):
    # pytest.ini wins over pyproject.toml; deleting it makes pyproject.toml's
    # settings apply, which lack this filter.
    _apply(repo, {"pytest.ini": "[pytest]\naddopts = -W error::UserWarning\n"})
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "pytest.ini at the base")
    _git(repo, "branch", "-f", "main")
    findings = _findings(repo, {"pytest.ini": None})
    assert any("warnings into errors (error::UserWarning)" in f for f in findings)


# ---------------------------------------------------------------------------
# Runtime evidence from the probe
# ---------------------------------------------------------------------------


def _run(root: Path, files: dict[str, str | None]):
    _apply(root, files)
    env = dict(os.environ, PYTHONPATH=str(root / "src"))
    return run_tests(
        open_comparison(root, "main"),
        DoneConfig(test_command=(sys.executable, "-m", "pytest")),
        changed_tests=[],
        environment=env,
    )


posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX test runner")


@posix_only
def test_an_honest_run_still_passes(repo: Path):
    result = _run(repo, {"tests/test_more.py": "def test_more():\n    pass\n"})
    assert result.status == "pass", result.reason


@posix_only
def test_a_replaced_pytest_leaves_no_evidence_and_is_unfinished(repo: Path):
    result = _run(repo, {"src/calc.py": BROKEN, "pytest.py": FORGED_JUNIT})
    assert result.status == "incomplete"
    assert result.error == "probe_evidence"
    assert "without evidence from Skylos's probe" in result.reason


@posix_only
def test_a_junit_report_rewritten_at_exit_is_unfinished(repo: Path):
    result = _run(repo, {"src/calc.py": REWRITE_AT_EXIT})
    assert result.status == "incomplete"
    assert result.reason == "the JUnit report changed after pytest wrote it"


@posix_only
def test_a_repository_file_cannot_stand_in_for_the_probe(repo: Path):
    result = _run(
        repo, {"src/calc.py": BROKEN, "skylos_done_pytest_plugin.py": REPORT_REWRITER}
    )
    assert result.status == "fail"
    assert {case.name for case in result.failures} == {"test_add", "test_add_zero"}


def test_evidence_must_match_the_run(tmp_path: Path):
    probe = tmp_path / "probe.py"
    probe.write_text("", encoding="utf-8")
    good = {
        "version": 1,
        "probe": os.path.realpath(probe),
        "exitstatus": 0,
        "junit_sha256": "abc",
        "modules": {
            name: os.path.realpath(f"/usr/lib/site-packages/{name}/__init__.py")
            for name in ("pytest", "_pytest", "pluggy")
        },
        "prefix": [],
        "injected": [],
    }

    def problem(data, exit_code=0, junit="abc"):
        return _probe_problem(
            data,
            root=tmp_path,
            probe=probe,
            exit_code=exit_code,
            junit_sha256=junit,
            strict=False,
        )

    assert problem(good) is None
    assert "without evidence" in problem(None)
    assert "changed after pytest wrote it" in problem(good, junit="def")
    assert "exit status 1" in problem({**good, "exitstatus": 1})
    assert "PYTEST_ADDOPTS" in problem({**good, "injected": ["PYTEST_ADDOPTS"]})
    shadow = {
        **good,
        "modules": {**good["modules"], "pytest": str(tmp_path / "pytest.py")},
    }
    assert "installed pytest" in problem(shadow)
    venv = {
        **shadow,
        "modules": {
            **good["modules"],
            "pytest": str(tmp_path / ".venv/lib/site-packages/pytest/__init__.py"),
        },
        "prefix": [str(tmp_path / ".venv")],
    }
    assert problem(venv) is None
