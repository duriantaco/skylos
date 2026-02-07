import json
import pytest

import skylos.rules.danger.danger_hallucination.dependency_hallucination as dep


def _write_py(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _extract_single(finds, rule_id):
    out = []
    for f in finds:
        if f.get("rule_id") == rule_id:
            out.append(f)
    return out


def test_normalize_name_basic():
    assert dep._normalize_name(None) == ""
    assert dep._normalize_name("Requests") == "requests"
    assert dep._normalize_name("google_genai") == "google-genai"
    assert dep._normalize_name("a..b__c---d") == "a-b-c-d"


def test_extract_imports_import_and_from():
    src = "import os\nimport a.b.c\nfrom foo.bar import baz\n"
    mods = dep._extract_imports(src)
    assert "os" in mods
    assert "a" in mods
    assert "foo" in mods


def test_find_import_line_finds_first_match():
    src = "\n\nimport os\nfrom abc import x\nimport requests\n"
    assert dep._find_import_line(src, "os") == 3
    assert dep._find_import_line(src, "abc") == 4
    assert dep._find_import_line(src, "requests") == 5


def test_parse_requirements_txt_basic(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "\n".join(
            [
                "# comment",
                "",
                "requests>=2.0",
                "numpy==1.26.0",
                "-e .",
                "git+https://example.com/repo.git",
                "https://example.com/pkg.whl",
            ]
        ),
        encoding="utf-8",
    )
    deps = dep._parse_requirements_txt(req)
    assert "requests" in deps
    assert "numpy" in deps


def test_parse_pyproject_toml_dependencies_array(tmp_path):
    py = tmp_path / "pyproject.toml"
    py.write_text(
        """
[project]
dependencies = [
  "requests>=2",
  "google_genai==0.1.0",
]
""".strip(),
        encoding="utf-8",
    )
    deps, _name = dep._parse_pyproject_toml(py)
    assert "requests" in deps
    assert "google-genai" in deps


def test_parse_pyproject_toml_poetry_block(tmp_path):
    py = tmp_path / "pyproject.toml"
    py.write_text(
        """
[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.0"
pydantic = "^2.0"
""".strip(),
        encoding="utf-8",
    )
    deps, _name = dep._parse_pyproject_toml(py)
    assert "requests" in deps
    assert "pydantic" in deps
    assert "python" not in deps


def test_parse_setup_py_install_requires(tmp_path):
    sp = tmp_path / "setup.py"
    sp.write_text(
        """
from setuptools import setup
setup(
  name="x",
  install_requires=[
    "requests>=2",
    "google_genai==0.1.0",
  ],
)
""".strip(),
        encoding="utf-8",
    )
    deps, _name = dep._parse_setup_py(sp)
    assert "requests" in deps
    assert "google-genai" in deps


def test_scan_returns_empty_when_repo_root_none():
    assert dep.scan_python_dependency_hallucinations(None, []) == []


def test_scan_ignores_stdlib_local_declared_private(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    f = _write_py(
        repo / "app.py",
        "\n".join(
            [
                "import os",
                "import localpkg",
                "import declaredpkg",
                "import privpkg",
                "import unknownpkg",
            ]
        )
        + "\n",
    )

    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: {"os"})
    monkeypatch.setattr(dep, "_collect_local_modules", lambda root: {"localpkg"})
    monkeypatch.setattr(dep, "_collect_declared_deps", lambda root: {"declaredpkg"})
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: {"privpkg"})
    monkeypatch.setattr(dep, "_build_installed_module_mapping", lambda: {})

    def fake_check(name, cache):
        cache[dep._normalize_name(name)] = "exists"
        return "exists"

    monkeypatch.setattr(dep, "_check_pypi_status", fake_check)

    finds = dep.scan_python_dependency_hallucinations(repo, [f])

    assert len(finds) == 1
    assert finds[0]["symbol"] == "unknownpkg"
    assert finds[0]["rule_id"] == dep.RULE_ID_UNDECLARED
    assert finds[0]["file"].endswith("app.py")
    assert finds[0]["line"] == 5


def test_scan_installed_but_undeclared_emits_dist_hint(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    f = _write_py(
        repo / "a.py",
        "\n".join(
            [
                "import installedmod",
            ]
        )
        + "\n",
    )

    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: set())
    monkeypatch.setattr(dep, "_collect_local_modules", lambda root: set())
    monkeypatch.setattr(dep, "_collect_declared_deps", lambda root: set())
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())

    monkeypatch.setattr(
        dep,
        "_build_installed_module_mapping",
        lambda: {"installedmod": {"Some-Dist", "other_dist"}},
    )

    finds = dep.scan_python_dependency_hallucinations(repo, [f])

    assert len(finds) == 1
    one = finds[0]
    assert one["rule_id"] == dep.RULE_ID_UNDECLARED
    assert one["severity"] == dep.SEV_MEDIUM
    assert one["symbol"] == "installedmod"
    assert one["line"] == 1
    assert "provided by:" in one["message"]
    assert "some-dist" in one["message"] or "Some-Dist" in one["message"]
    assert "other" in one["message"]


@pytest.mark.xfail(
    reason="Current code treats PyPI status as truthy string; 'missing' won't trigger hallucination until fixed."
)
def test_scan_pypi_missing_should_emit_hallucination(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    f = _write_py(repo / "x.py", "import nonexistentpkg\n")

    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: set())
    monkeypatch.setattr(dep, "_collect_local_modules", lambda root: set())
    monkeypatch.setattr(dep, "_collect_declared_deps", lambda root: set())
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(dep, "_build_installed_module_mapping", lambda: {})

    def fake_check(name, cache):
        cache[dep._normalize_name(name)] = "missing"
        return "missing"

    monkeypatch.setattr(dep, "_check_pypi_status", fake_check)

    finds = dep.scan_python_dependency_hallucinations(repo, [f])

    halluc = _extract_single(finds, dep.RULE_ID_HALLUCINATION)
    assert len(halluc) == 1
    assert halluc[0]["severity"] == dep.SEV_CRITICAL
    assert halluc[0]["symbol"] == "nonexistentpkg"


def test_scan_cache_is_written_when_modified(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    f = _write_py(repo / "x.py", "import somepkg\n")

    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: set())
    monkeypatch.setattr(dep, "_collect_local_modules", lambda root: set())
    monkeypatch.setattr(dep, "_collect_declared_deps", lambda root: set())
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(dep, "_build_installed_module_mapping", lambda: {})

    def fake_check(name, cache):
        cache[dep._normalize_name(name)] = "exists"
        return "exists"

    monkeypatch.setattr(dep, "_check_pypi_status", fake_check)

    cache_path = repo / ".skylos" / "cache" / "pypi_exists.json"
    assert not cache_path.exists()

    _ = dep.scan_python_dependency_hallucinations(repo, [f])

    assert cache_path.exists()
    data = json.loads(cache_path.read_text(encoding="utf-8"))
    assert "somepkg" in data
    assert data["somepkg"] == "exists"


def test_scan_does_not_write_cache_when_not_modified(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    f = _write_py(repo / "x.py", "import somepkg\n")

    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: set())
    monkeypatch.setattr(dep, "_collect_local_modules", lambda root: set())
    monkeypatch.setattr(dep, "_collect_declared_deps", lambda root: set())
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(dep, "_build_installed_module_mapping", lambda: {})

    def fake_check(name, cache):
        return "exists"

    monkeypatch.setattr(dep, "_check_pypi_status", fake_check)

    cache_path = repo / ".skylos" / "cache" / "pypi_exists.json"
    _ = dep.scan_python_dependency_hallucinations(repo, [f])
    assert not cache_path.exists()

def test_pyproject_extras_brackets(tmp_path):
    py = tmp_path / "pyproject.toml"
    py.write_text(
        '[project]\nname = "skylos-demo"\n'
        'dependencies = [\n'
        '  "fastapi>=0.110",\n'
        '  "uvicorn[standard]>=0.27",\n'
        '  "sqlalchemy>=2.0",\n'
        '  "pydantic>=2.5",\n'
        '  "pydantic-settings>=2.0",\n'
        '  "httpx>=0.27",\n'
        ']\n',
        encoding="utf-8",
    )
    deps, name = dep._parse_pyproject_toml(py)
    assert name == "skylos-demo"
    for expected in ("fastapi", "uvicorn", "sqlalchemy", "pydantic", "pydantic-settings", "httpx"):
        assert expected in deps, f"{expected} missing from {deps}"


def test_pyproject_multiple_extras(tmp_path):
    py = tmp_path / "pyproject.toml"
    py.write_text(
        '[project]\ndependencies = ["boto3[crt,s3]>=1.26", "click>=8.0"]',
        encoding="utf-8",
    )
    deps, _ = dep._parse_pyproject_toml(py)
    assert "boto3" in deps
    assert "click" in deps


def test_pyproject_inline_array(tmp_path):
    py = tmp_path / "pyproject.toml"
    py.write_text(
        '[project]\ndependencies = ["requests>=2", "flask>=3"]',
        encoding="utf-8",
    )
    deps, _ = dep._parse_pyproject_toml(py)
    assert "requests" in deps
    assert "flask" in deps


def test_pyproject_empty_deps(tmp_path):
    py = tmp_path / "pyproject.toml"
    py.write_text('[project]\nname = "x"\ndependencies = []', encoding="utf-8")
    deps, name = dep._parse_pyproject_toml(py)
    assert len(deps) == 0
    assert name == "x"


def test_pyproject_optional_deps_with_extras(tmp_path):
    py = tmp_path / "pyproject.toml"
    py.write_text(
        '[project]\ndependencies = ["requests>=2"]\n\n'
        "[project.optional-dependencies]\n"
        'dev = [\n  "pytest>=8.0",\n  "coverage[toml]>=7.0",\n]\n',
        encoding="utf-8",
    )
    deps, _ = dep._parse_pyproject_toml(py)
    assert "requests" in deps
    assert "pytest" in deps
    assert "coverage" in deps


def test_setup_py_extras_brackets(tmp_path):
    sp = tmp_path / "setup.py"
    sp.write_text(
        "from setuptools import setup\nsetup(\n"
        "  name='myapp',\n"
        "  install_requires=[\n"
        "    'uvicorn[standard]>=0.27',\n"
        "    'sqlalchemy>=2.0',\n"
        "  ],\n)\n",
        encoding="utf-8",
    )
    deps, name = dep._parse_setup_py(sp)
    assert name == "myapp"
    assert "uvicorn" in deps
    assert "sqlalchemy" in deps


def test_self_package_in_declared_deps(tmp_path):
    py = tmp_path / "pyproject.toml"
    py.write_text(
        '[project]\nname = "skylos-demo"\ndependencies = ["requests>=2"]',
        encoding="utf-8",
    )
    deps = dep._collect_declared_deps(tmp_path)
    assert "skylos-demo" in deps
    assert "requests" in deps


def test_self_package_not_flagged_end_to_end(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app").mkdir()
    (repo / "app" / "__init__.py").write_text("")
    f = _write_py(repo / "app" / "main.py", "from app.config import Settings\n")

    finds = dep.scan_python_dependency_hallucinations(repo, [f])
    app_findings = [f for f in finds if f["symbol"] == "app"]
    assert len(app_findings) == 0, f"Self-import 'app' should not be flagged: {app_findings}"


def test_pypi_missing_no_env_metadata(monkeypatch, tmp_path):
    """Hallucination detected even without installed env metadata."""
    repo = tmp_path / "repo"
    repo.mkdir()
    f = _write_py(repo / "x.py", "import fakepkg123\n")

    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: set())
    monkeypatch.setattr(dep, "_collect_local_modules", lambda root: set())
    monkeypatch.setattr(dep, "_collect_declared_deps", lambda root: set())
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(dep, "_build_installed_module_mapping", lambda: {})

    def fake_check(name, cache):
        cache[dep._normalize_name(name)] = "missing"
        return "missing"

    monkeypatch.setattr(dep, "_check_pypi_status", fake_check)

    finds = dep.scan_python_dependency_hallucinations(repo, [f])
    halluc = _extract_single(finds, dep.RULE_ID_HALLUCINATION)
    assert len(halluc) == 1
    assert halluc[0]["severity"] == dep.SEV_CRITICAL