"""A made-up import is proved made up by the project's own environment.

With a range requirement (``flask>=3.0``) no single release can prove that
no allowed release ships a module. When nothing installed provides the
module and every declared distribution is installed in the project's
environment, at an allowed version, with a complete file list that does not
ship it, the import fails there: SKY-D222, not a "possible" SKY-D223.
Partial, editable, out-of-range, missing or foreign-environment installs
keep the old "possible" answer, and a provider with another name still
provides its module.
"""

from __future__ import annotations

import pytest

from skylos.rules.ai_defect import dependency_hallucination as dep
from test.test_dependency_provider_regressions import (
    _isolate_with_installed_record,
    _project,
    _scan,
)


def _rules(findings):
    return [(f["rule_id"], f["severity"], f["symbol"]) for f in findings]


@pytest.mark.parametrize("mode", ["full", "diff"])
@pytest.mark.parametrize("requirement", ["safe-lib>=1.0", "safe-lib", "safe-lib~=1.0"])
def test_range_declared_install_proves_a_made_up_import(
    monkeypatch, tmp_path, mode, requirement
):
    repo, path = _project(tmp_path, "import ghost_required\n", requirement)
    _isolate_with_installed_record(
        monkeypatch, tmp_path, files=("safe_lib/__init__.py",)
    )
    findings = _scan(mode, repo, path)
    assert _rules(findings) == [
        (dep.RULE_ID_HALLUCINATION, dep.SEV_CRITICAL, "ghost_required")
    ]


@pytest.mark.parametrize("mode", ["full", "diff"])
def test_a_provider_with_another_name_still_provides_its_module(
    monkeypatch, tmp_path, mode
):
    repo, path = _project(tmp_path, "import yaml\n", "safe-lib>=1.0")
    _isolate_with_installed_record(monkeypatch, tmp_path, files=("yaml/__init__.py",))
    assert _scan(mode, repo, path, root="yaml") == []


def _possible(findings):
    assert _rules(findings) == [
        (dep.RULE_ID_UNDECLARED, dep.SEV_MEDIUM, "ghost_required")
    ]
    assert findings[0]["message"].startswith("Possible hallucinated import")


def test_an_editable_install_cannot_prove_absence(monkeypatch, tmp_path):
    repo, path = _project(tmp_path, "import ghost_required\n", "safe-lib>=1.0")
    _isolate_with_installed_record(
        monkeypatch, tmp_path, files=("safe_lib/__init__.py",), editable_metadata=True
    )
    _possible(dep.scan_python_dependency_hallucinations(repo, [path]))


def test_an_install_outside_the_allowed_range_cannot_prove_absence(
    monkeypatch, tmp_path
):
    repo, path = _project(tmp_path, "import ghost_required\n", "safe-lib>=2.0")
    _isolate_with_installed_record(
        monkeypatch, tmp_path, files=("safe_lib/__init__.py",)
    )
    _possible(dep.scan_python_dependency_hallucinations(repo, [path]))


def test_a_declared_distribution_that_is_not_installed_keeps_it_possible(
    monkeypatch, tmp_path
):
    repo, path = _project(
        tmp_path, "import ghost_required\n", "safe-lib>=1.0\nother-lib>=1.0"
    )
    _isolate_with_installed_record(
        monkeypatch, tmp_path, files=("safe_lib/__init__.py",)
    )
    _possible(dep.scan_python_dependency_hallucinations(repo, [path]))


def test_an_install_outside_the_project_environment_keeps_it_possible(
    monkeypatch, tmp_path
):
    repo, path = _project(tmp_path, "import ghost_required\n", "safe-lib>=1.0")
    _isolate_with_installed_record(
        monkeypatch, tmp_path, files=("safe_lib/__init__.py",)
    )
    site_packages = str(tmp_path / "site-packages")
    monkeypatch.setattr(dep, "virtual_env_site_packages", list)
    monkeypatch.setattr(dep.site, "getsitepackages", lambda: [site_packages])
    _possible(dep.scan_python_dependency_hallucinations(repo, [path]))


def test_a_module_installed_in_the_environment_is_never_proved_made_up(
    monkeypatch, tmp_path
):
    repo, path = _project(tmp_path, "import ghost_required\n", "safe-lib>=1.0")
    _isolate_with_installed_record(
        monkeypatch, tmp_path, files=("safe_lib/__init__.py",)
    )
    monkeypatch.setattr(
        dep,
        "_build_installed_module_mapping",
        lambda: {"ghost_required": {"private-sdk"}},
    )
    findings = dep.scan_python_dependency_hallucinations(repo, [path])
    assert all(f["rule_id"] != dep.RULE_ID_HALLUCINATION for f in findings)
