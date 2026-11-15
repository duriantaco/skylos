"""SKY-D223: PEP 723 inline script dependencies and build-time imports of
setup.py helpers, each beside an import that stays undeclared."""

import skylos.rules.ai_defect.dependency_hallucination as dep


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path fixture
        text, encoding="utf-8"
    )
    return path


def _stub(monkeypatch):
    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: {"sys", "pathlib"})
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(
        dep, "_build_installed_module_mapping", lambda: {"requests": {"requests"}}
    )
    monkeypatch.setattr(dep, "_load_import_to_dist_mapping", lambda: {})
    monkeypatch.setattr(dep, "_check_pypi_status", lambda name, _cache: "exists")


def _undeclared(findings):
    return sorted(
        (f["file"].rsplit("/", 1)[-1], f["symbol"])
        for f in findings
        if f["rule_id"] == dep.RULE_ID_UNDECLARED
    )


PYPROJECT = '[project]\nname = "probe"\nversion = "0.1.0"\ndependencies = ["requests"]\n'
INLINE = '# /// script\n# dependencies = [\n#   "rich",\n# ]\n# ///\n\n'


def test_inline_script_block_declares_only_what_it_lists(monkeypatch, tmp_path):
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", PYPROJECT)
    listed = _write(repo / "train.py", INLINE + "import requests\nimport rich\n")
    partial = _write(repo / "train_more.py", INLINE + "import httpx\nimport rich\n")
    plain = _write(repo / "plain.py", "import rich\n")
    findings = dep.scan_python_dependency_hallucinations(repo, [listed, partial, plain])
    assert _undeclared(findings) == [("plain.py", "rich"), ("train_more.py", "httpx")]


def test_build_requirements_cover_setup_helpers_only(monkeypatch, tmp_path):
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(
        repo / "pyproject.toml",
        '[build-system]\nrequires = ["setuptools>=64", "cython"]\n\n' + PYPROJECT,
    )
    setup = _write(
        repo / "setup.py",
        "from setuptools import setup\n\nimport buildtools\n\nsetup(cmdclass=buildtools.commands())\n",
    )
    helper = _write(
        repo / "buildtools.py",
        "import cython\nimport httpx\nfrom setuptools import Command\n",
    )
    script = _write(repo / "tools.py", "import setuptools\n")
    package = _write(repo / "src" / "probe" / "core.py", "import cython\nimport setuptools\n")
    _write(repo / "src" / "probe" / "__init__.py", "")
    findings = dep.scan_python_dependency_hallucinations(
        repo, [setup, helper, script, package]
    )
    assert _undeclared(findings) == [
        ("buildtools.py", "httpx"),
        ("core.py", "cython"),
        ("core.py", "setuptools"),
        ("tools.py", "setuptools"),
    ]
