"""Resolve dependency hooks from one deterministic project environment."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from skylos.analysis.external_bases import ExternalClassIndex, default_search_dirs
from skylos.analyzer import analyze


def _site(root: Path, env_name: str, layout: str = "lib/python3.11/site-packages"):
    site = root / env_name / layout
    site.mkdir(parents=True, exist_ok=True)
    return site


def _write(site: Path, relative: str, source: str):
    path = site / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


@pytest.mark.parametrize(
    ("environments", "chosen"),
    [
        ((".env", "env", "venv", ".venv"), ".venv"),
        ((".env", "env", "venv"), "venv"),
        ((".env", "env"), "env"),
        ((".env",), ".env"),
    ],
)
def test_project_environment_priority_uses_only_one_environment(
    tmp_path, environments, chosen
):
    sites = {name: _site(tmp_path, name) for name in environments}

    directories = default_search_dirs([tmp_path])

    assert sites[chosen].resolve() in directories
    for name, site in sites.items():
        if name != chosen:
            assert site.resolve() not in directories


@pytest.mark.parametrize(
    "layout",
    ["lib/python3.11/site-packages", "lib/site-packages", "Lib/site-packages"],
)
def test_project_environment_supports_posix_and_windows_layouts(tmp_path, layout):
    site = _site(tmp_path, ".venv", layout)

    assert site.resolve() in default_search_dirs([tmp_path])


def test_empty_preferred_environment_falls_back_to_installed_environment(tmp_path):
    (tmp_path / ".venv").mkdir()
    site = _site(tmp_path, "venv")

    assert site.resolve() in default_search_dirs([tmp_path])


def test_environment_sites_have_stable_order(tmp_path):
    newer = _site(tmp_path, ".venv", "lib/python3.12/site-packages")
    older = _site(tmp_path, ".venv", "lib/python3.11/site-packages")

    selected = [
        path for path in default_search_dirs([tmp_path]) if path in {older, newer}
    ]

    assert selected == [older, newer]


def test_project_environment_is_authoritative_over_scanner_and_stale_environments(
    tmp_path, monkeypatch
):
    root = tmp_path / "project"
    project_site = _site(root, ".venv")
    stale_site = _site(root, "venv")
    host_site = tmp_path / "scanner" / "site-packages"
    host_site.mkdir(parents=True)
    package = "skylos_venv_contract_lib"
    for site in (project_site, stale_site, host_site):
        _write(site, f"{package}/__init__.py", "raise RuntimeError('never import')\n")
    _write(
        project_site,
        f"{package}/hooks.py",
        "class Hooks:\n    expected_hook = None\n",
    )
    for site in (stale_site, host_site):
        _write(
            site,
            f"{package}/hooks.py",
            "class Hooks:\n    removed_hook = None\n",
        )
        _write(
            site,
            f"{package}/missing.py",
            "class Missing:\n    nonexistent_hook = None\n",
        )
    monkeypatch.syspath_prepend(str(host_site))
    monkeypatch.syspath_prepend(str(stale_site))

    directories = default_search_dirs([root])
    index = ExternalClassIndex(directories)

    assert project_site.resolve() in directories
    assert stale_site.resolve() not in directories
    assert host_site.resolve() not in directories
    assert index.defining_class(f"{package}.hooks.Hooks", "expected_hook")
    assert index.defining_class(f"{package}.hooks.Hooks", "removed_hook") is None
    assert (
        index.defining_class(f"{package}.missing.Missing", "nonexistent_hook") is None
    )
    assert package not in sys.modules


def test_project_root_environment_precedes_nested_module_environment(tmp_path):
    root_site = _site(tmp_path, ".venv")
    module_root = tmp_path / "src"
    nested_site = _site(module_root, ".venv")

    directories = default_search_dirs([tmp_path, module_root])

    assert root_site.resolve() in directories
    assert nested_site.resolve() not in directories


def test_project_environment_symlink_keeps_dependency_sources(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    external_site = _site(tmp_path / "external", "actual")
    try:
        (root / ".venv").symlink_to(external_site.parents[2], target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    _write(
        external_site,
        "symlink_contract.py",
        "class Hooks:\n    expected_hook = None\n",
    )

    index = ExternalClassIndex(default_search_dirs([root]))

    assert index.defining_class("symlink_contract.Hooks", "expected_hook")
    assert "symlink_contract" not in sys.modules


def test_arbitrary_site_packages_under_environment_name_stays_vendored(
    tmp_path, monkeypatch
):
    site = tmp_path / "env" / "vendor" / "site-packages"
    site.mkdir(parents=True)
    monkeypatch.syspath_prepend(str(site))

    assert site.resolve() not in default_search_dirs([tmp_path])


def test_virtualenv_selection_preserves_hooks_and_reports_stale_members(
    tmp_path, monkeypatch
):
    project_site = _site(tmp_path, ".venv")
    stale_site = _site(tmp_path, "venv")
    package = "skylos_venv_contract_hooks"
    for site in (project_site, stale_site):
        _write(site, f"{package}/__init__.py", "raise RuntimeError('never import')\n")
    _write(
        project_site,
        f"{package}/core.py",
        "class FrameworkBase:\n    def expected_hook(self):\n        return None\n",
    )
    _write(
        stale_site,
        f"{package}/core.py",
        "class FrameworkBase:\n    def removed_hook(self):\n        return None\n",
    )
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'fixture'\n")
    (tmp_path / "app.py").write_text(
        f"from {package}.core import FrameworkBase\n\n"
        "class Handler(FrameworkBase):\n"
        "    def expected_hook(self):\n        return None\n\n"
        "    def removed_hook(self):\n        return None\n\n"
        "    def orphan(self):\n        return None\n\n"
        "HANDLER = Handler()\n"
    )
    monkeypatch.setenv("SKYLOS_JOBS", "1")

    result = json.loads(
        analyze(
            str(tmp_path),
            conf=60,
            grep_verify=False,
            grep_cache=False,
            exclude_folders=[".venv", "venv"],
        )
    )
    reported = {item["full_name"] for item in result.get("unused_functions") or []}

    assert reported == {"app.Handler.removed_hook", "app.Handler.orphan"}
    assert package not in sys.modules
