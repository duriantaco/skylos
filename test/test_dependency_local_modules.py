"""SKY-D222/D223 false positives from agent-pr-bench (plan 3.8b).

* real-03 / real-18: a test adds a sibling directory to ``sys.path`` and
  imports a repository module; that is not a hallucinated PyPI package.
* real-10: ``import examples.x`` is the repository's own namespace package,
  not the ``tweepy`` distribution that also ships an ``examples`` module.
* real-05: ``backend/requirements-mlx.txt`` declares ``mlx``.
"""

import skylos.rules.ai_defect.dependency_hallucination as dep


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest tmp_path fixture
    return path


def _stub(monkeypatch, installed=None, statuses=None):
    statuses = statuses or {}
    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: {"sys", "pathlib"})
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(dep, "_build_installed_module_mapping", lambda: installed or {})
    monkeypatch.setattr(dep, "_load_import_to_dist_mapping", lambda: {})
    monkeypatch.setattr(
        dep, "_check_pypi_status", lambda name, _cache: statuses.get(name, "missing")
    )


def _rules(findings):
    return sorted((f["rule_id"], f["symbol"]) for f in findings)


def test_sys_path_insert_repository_module_is_not_hallucinated(monkeypatch, tmp_path):
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "requirements.txt", "requests\n")
    tool = _write(repo / "tools" / "job_key.py", "def key():\n    return 1\n")
    test = _write(
        repo / "tests" / "test_job_key.py",
        "import sys\nfrom pathlib import Path\n"
        "sys.path.insert(0, str(Path(__file__).parent.parent / 'tools'))\n"
        "import job_key\nimport totally_made_up_pkg\n",
    )
    findings = dep.scan_python_dependency_hallucinations(repo, [tool, test])
    # The genuinely unknown package is still reported.
    assert _rules(findings) == [(dep.RULE_ID_HALLUCINATION, "totally_made_up_pkg")]


def test_root_namespace_package_is_local_not_a_distribution(monkeypatch, tmp_path):
    _stub(monkeypatch, installed={"examples": {"tweepy"}, "faiss": {"faiss-cpu"}})
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", '[project]\nname = "agentlightning"\ndependencies = []\n')
    agent = _write(repo / "examples" / "search_r1" / "agent.py", "import faiss\n")
    test = _write(
        repo / "tests" / "examples" / "test_agent.py",
        "from examples.search_r1 import agent\n",
    )
    findings = dep.scan_python_dependency_hallucinations(repo, [agent, test])
    assert _rules(findings) == [(dep.RULE_ID_UNDECLARED, "faiss")]


def test_requirements_variant_files_declare_dependencies(monkeypatch, tmp_path):
    _stub(monkeypatch, installed={"mlx": {"mlx"}, "mlx_lm": {"mlx-lm"}})
    repo = tmp_path / "repo"
    _write(repo / "backend" / "requirements.txt", "fastapi\n")
    _write(repo / "backend" / "requirements-mlx.txt", "mlx>=0.20\n")
    test = _write(
        repo / "backend" / "tests" / "test_mlx.py", "import mlx\nimport mlx_lm\n"
    )
    findings = dep.scan_python_dependency_hallucinations(repo, [test])
    assert _rules(findings) == [(dep.RULE_ID_UNDECLARED, "mlx_lm")]


def test_root_requirements_variant_files_declare_dependencies(monkeypatch, tmp_path):
    _stub(monkeypatch, installed={"pytest": {"pytest"}})
    repo = tmp_path / "repo"
    _write(repo / "requirements.txt", "requests\n")
    _write(repo / "requirements-dev.txt", "pytest\n")
    test = _write(repo / "test_x.py", "import pytest\n")
    assert dep.scan_python_dependency_hallucinations(repo, [test]) == []
