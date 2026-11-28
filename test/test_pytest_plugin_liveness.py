"""Pytest hook liveness follows the plugin loader's explicit module choices."""

import json
from textwrap import dedent

import pytest

from skylos.analyzer import Skylos

REGISTRATIONS = {
    "conftest-list": {
        "conftest.py": 'pytest_plugins = ["checks.integration"]\n',
    },
    "collected-test-tuple": {
        "test_loader.py": """
            PLUGINS = ("checks.integration",)
            pytest_plugins: tuple[str, ...] = PLUGINS

            def test_collection():
                assert True
        """,
    },
    "transitive-plugin": {
        "conftest.py": 'pytest_plugins = "checks.loader"\n',
        "checks/loader.py": 'pytest_plugins = "checks.integration,unavailable"\n',
    },
    "pyproject": {
        "pyproject.toml": '[project.entry-points.pytest11]\nchecks = "checks.integration"\n',
    },
    "poetry": {
        "pyproject.toml": '[tool.poetry.plugins.pytest11]\nchecks = "checks.integration"\n',
    },
    "setup-cfg": {
        "setup.cfg": "[options.entry_points]\npytest11 =\n    checks = checks.integration\n",
    },
    "setup-py-dict": {
        "setup.py": """
            from setuptools import setup

            PLUGINS = {"pytest11": ["checks = checks.integration"]}
            setup(entry_points=PLUGINS)
        """,
    },
    "setup-py-string": {
        "setup.py": '''
            from setuptools import setup

            setup(entry_points="""
                [pytest11]
                checks = checks.integration
            """)
        ''',
    },
}


def _write(root, files):
    for name, source in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(source).lstrip(), encoding="utf-8")


def _scan(root, *, confidence=60, grep_verify=True):
    scanner = Skylos()
    result = json.loads(
        scanner.analyze(
            str(root), thr=confidence, grep_verify=grep_verify, grep_cache=False
        )
    )
    assert not result.get("analysis_errors")
    return scanner, result


@pytest.mark.parametrize("registration", REGISTRATIONS)
def test_loaded_plugin_hooks_keep_only_dispatched_helpers(tmp_path, registration):
    _write(
        tmp_path,
        {
            "checks/__init__.py": "",
            "checks/integration.py": """
                def active_setup():
                    return "configuration"

                def active_format():
                    return "description"

                def pytest_configure(config):
                    active_setup()

                def pytest_make_parametrize_id(config, val, argname):
                    return active_format()

                def pytest_unrelated_helper():
                    return "unused"
            """,
            "checks/detached.py": """
                def detached_format():
                    return "unused"

                def pytest_make_parametrize_id(config, val, argname):
                    return detached_format()
            """,
            **REGISTRATIONS[registration],
        },
    )

    scanner, result = _scan(tmp_path)
    unused = {row["full_name"] for row in result["unused_functions"]}
    assert unused == {
        "checks.integration.pytest_unrelated_helper",
        "checks.detached.pytest_make_parametrize_id",
        "checks.detached.detached_format",
    }
    for hook in ("pytest_configure", "pytest_make_parametrize_id"):
        assert (
            "test_entrypoint"
            in scanner.defs[f"checks.integration.{hook}"].heuristic_refs
        )


@pytest.mark.parametrize(
    "registration",
    [
        {"ordinary.py": 'pytest_plugins = ["checks.integration"]\n'},
        {
            "conftest.py": 'def bootstrap():\n    pytest_plugins = ["checks.integration"]\n'
        },
        {
            "conftest.py": 'pytest_plugins = ["checks.integration"]\npytest_plugins = []\n'
        },
        {
            "conftest.py": """
                pytest_plugins = ["checks.integration"]
                alias = pytest_plugins
                alias.clear()
            """,
        },
        {
            "pyproject.toml": '[project.entry-points.example]\nchecks = "checks.integration"\n'
        },
    ],
)
def test_unloaded_or_replaced_plugin_declarations_do_not_prove_hooks(
    tmp_path, registration
):
    _write(
        tmp_path,
        {
            "checks/__init__.py": "",
            "checks/integration.py": """
                def unused_format():
                    return "description"

                def pytest_make_parametrize_id(config, val, argname):
                    return unused_format()
            """,
            **registration,
        },
    )

    scanner, result = _scan(tmp_path, grep_verify=False)
    assert {
        "checks.integration.pytest_make_parametrize_id",
        "checks.integration.unused_format",
    }.issubset({row["full_name"] for row in result["unused_functions"]})
    assert (
        "test_entrypoint"
        not in scanner.defs[
            "checks.integration.pytest_make_parametrize_id"
        ].heuristic_refs
    )


def test_registered_hook_parameters_and_local_conftest_hook(tmp_path):
    _write(
        tmp_path,
        {
            "conftest.py": """
                pytest_plugins = "checks"

                def pytest_make_parametrize_id(config, val, argname):
                    return "case"
            """,
            "checks.py": """
                def configure_checks(
                    config,
                    optional_setting=None,
                ):
                    return None

                pytest_configure = configure_checks

                def unrelated(unused_arg):
                    return None
            """,
        },
    )
    _, result = _scan(tmp_path, confidence=0, grep_verify=False)
    assert {row["full_name"] for row in result["unused_parameters"]} == {
        "checks.configure_checks.optional_setting",
        "checks.unrelated.unused_arg",
    }
    assert "checks.configure_checks" not in {
        row["full_name"] for row in result.get("unused_functions", [])
    }


def test_pytest_import_alone_does_not_prove_hook_invocation(tmp_path):
    _write(
        tmp_path,
        {
            "utility.py": """
                import pytest

                def pytest_configure(config):
                    return "unattached"
            """,
        },
    )
    scanner, _ = _scan(tmp_path, grep_verify=False)
    assert "utility.pytest_configure" not in (
        scanner._python_reachability_report.proven_reachable_keys
    )


def test_collected_test_module_loads_plugins_only(tmp_path):
    _write(
        tmp_path,
        {
            "test_loader.py": """
                pytest_plugins = "checks"

                def pytest_configure(config):
                    unused_setup()

                def unused_setup():
                    return None

                def test_collection():
                    assert True
            """,
            "checks.py": """
                def pytest_configure(config):
                    registered_setup()

                def registered_setup():
                    return None
            """,
        },
    )
    scanner, _ = _scan(tmp_path, grep_verify=False)
    assert set(scanner._python_reachability_report.proven_reachable_keys) >= {
        "checks.pytest_configure",
        "checks.registered_setup",
    }
    assert "test_loader.pytest_configure" not in (
        scanner._python_reachability_report.proven_reachable_keys
    )
    assert scanner._python_reachability_report.unreachable_keys >= {
        "test_loader.pytest_configure",
        "test_loader.unused_setup",
    }


def test_plugin_reexports_hook_from_another_module(tmp_path):
    _write(
        tmp_path,
        {
            "conftest.py": 'pytest_plugins = ["checks.plugin"]\n',
            "checks/__init__.py": "",
            "checks/plugin.py": """
                from .callbacks import describe as pytest_report_teststatus
            """,
            "checks/callbacks.py": """
                def describe(report, config):
                    return format_status()

                def format_status():
                    return "passed", ".", "PASSED"

                def stale_status():
                    return None
            """,
        },
    )
    scanner, result = _scan(tmp_path, confidence=0, grep_verify=False)
    assert {row["full_name"] for row in result.get("unused_functions", [])} == {
        "checks.callbacks.stale_status",
    }
    assert not result.get("unused_imports")
    assert not result.get("unused_parameters")
    assert "test_entrypoint" in scanner.defs["checks.callbacks.describe"].heuristic_refs
