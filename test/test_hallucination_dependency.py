import json
import subprocess
import time

import skylos.rules.ai_defect.dependency_hallucination as dep


def _write_py(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path fixture
        text, encoding="utf-8"
    )
    return path


def _extract_single(finds, rule_id):
    out = []
    for f in finds:
        if f.get("rule_id") == rule_id:
            out.append(f)
    return out


def _stub_dependency_registry(monkeypatch, statuses):
    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: set())
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(dep, "_build_installed_module_mapping", lambda: {})
    monkeypatch.setattr(
        dep,
        "_check_pypi_status",
        lambda name, _cache: statuses.get(name, "missing"),
    )


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


def test_parse_requirements_txt_rejects_symlink(tmp_path):
    target = tmp_path / "outside-requirements.txt"
    target.write_text("notarealpackage==1.0.0\n", encoding="utf-8")
    link = tmp_path / "requirements.txt"
    try:
        link.symlink_to(target)
    except OSError:
        return

    assert dep._parse_requirements_txt(link) == set()


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


def test_parse_pyproject_toml_pep735_dependency_groups(tmp_path):
    py = _write_py(
        tmp_path / "pyproject.toml",
        """
[dependency-groups]
test = ["pytest>=8", "coverage[toml]; python_version >= '3.11'"]
lint = ["ruff", {include-group = "test"}]
""".strip(),
    )

    deps, project_name = dep._parse_pyproject_toml(py)

    assert deps == {"coverage", "pytest", "ruff"}
    assert project_name is None


def test_pep735_malformed_objects_do_not_create_dependencies(tmp_path):
    py = _write_py(
        tmp_path / "pyproject.toml",
        """
[dependency-groups]
valid = ["requests", {include-group = "cycle"}]
cycle = [{include-group = "cycle"}]
not-a-list = {include-group = "valid"}
future = [{new-object = "fabricated-package"}]
""".strip(),
    )

    deps, _ = dep._parse_pyproject_toml(py)

    assert deps == {"requests"}


def test_pep735_dependency_group_prevents_d223(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        """
[project]
name = "pep735-reproducer"
version = "0.0.0"
dependencies = []

[dependency-groups]
dev = ["pytest"]
""".strip(),
    )
    source = _write_py(repo / "reproduce.py", "import pytest\n")

    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: set())
    monkeypatch.setattr(dep, "_collect_local_modules", lambda root: set())
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(
        dep,
        "_build_installed_module_mapping",
        lambda: {"pytest": {"pytest"}},
    )

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert _extract_single(findings, dep.RULE_ID_UNDECLARED) == []


def test_nested_pyproject_dependencies_do_not_leak_to_siblings(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "parent"\ndependencies = []\n\n'
        '[dependency-groups]\ndev = ["pytest"]\n',
    )
    nested = repo / "pydantic-core"
    nested.mkdir()
    _write_py(
        nested / "pyproject.toml",
        '[project]\nname = "pydantic-core"\ndependencies = []\n\n'
        '[dependency-groups]\nbuild = ["maturin"]\n',
    )
    nested_source = _write_py(nested / "build.py", "import maturin\nimport pytest\n")
    sibling_source = _write_py(repo / "tools" / "build.py", "import maturin\n")

    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: set())
    monkeypatch.setattr(dep, "_collect_local_modules", lambda root: set())
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(
        dep,
        "_build_installed_module_mapping",
        lambda: {"maturin": {"maturin"}, "pytest": {"pytest"}},
    )

    findings = dep.scan_python_dependency_hallucinations(
        repo, [nested_source, sibling_source]
    )

    undeclared = _extract_single(findings, dep.RULE_ID_UNDECLARED)
    assert [(finding["file"], finding["symbol"]) for finding in undeclared] == [
        (str(sibling_source), "maturin")
    ]


def test_nested_pyproject_scope_rejects_symlinked_directory(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    _write_py(
        outside / "pyproject.toml",
        '[project]\ndependencies = ["outside-dependency"]\n',
    )
    nested_link = repo / "child"
    try:
        nested_link.symlink_to(outside, target_is_directory=True)
    except OSError:
        return

    scope_cache = {repo: (frozenset({"root-dependency"}), True)}
    declared, manifest_context = dep._dependency_scope_for_file(
        repo,
        nested_link / "module.py",
        scope_cache,
    )

    assert declared == {"root-dependency"}
    assert manifest_context is True


def test_dependency_scope_rejects_excessive_path_depth(monkeypatch, tmp_path):
    root_scope = (frozenset({"root-dependency"}), True)
    scope_cache = {tmp_path: root_scope}
    calls = []
    monkeypatch.setattr(
        dep,
        "_nested_pyproject_metadata",
        lambda *args: calls.append(args),
    )
    deep_file = "/".join(
        ["child"] * (dep.MAX_DEPENDENCY_SCOPE_COMPONENTS + 1) + ["module.py"]
    )

    scope = dep._dependency_scope_for_file(tmp_path, deep_file, scope_cache)

    assert scope == root_scope
    assert scope_cache == {tmp_path: root_scope}
    assert calls == []


def test_hostile_nested_pyproject_does_not_abort_sibling_scan(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(repo / "requirements.txt", "click\n")
    nested = repo / "child"
    nested.mkdir()
    _write_py(nested / "pyproject.toml", "hostile = true\n")
    nested_source = _write_py(nested / "app.py", "import maturin\n")
    sibling_source = _write_py(repo / "sibling.py", "import maturin\n")

    def raise_recursion_error(_text):
        raise RecursionError

    monkeypatch.setattr(dep.tomllib, "loads", raise_recursion_error)
    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: set())
    monkeypatch.setattr(dep, "_collect_local_modules", lambda root: set())
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(
        dep,
        "_build_installed_module_mapping",
        lambda: {"maturin": {"maturin"}},
    )

    findings = dep.scan_python_dependency_hallucinations(
        repo, [nested_source, sibling_source]
    )

    assert [
        (finding["file"], finding["symbol"])
        for finding in _extract_single(findings, dep.RULE_ID_UNDECLARED)
    ] == [(str(nested_source), "maturin"), (str(sibling_source), "maturin")]


def test_pyproject_parser_value_error_is_ignored(monkeypatch, tmp_path):
    pyproject = _write_py(tmp_path / "pyproject.toml", "hostile = true\n")

    def raise_value_error(_text):
        raise ValueError

    monkeypatch.setattr(dep.tomllib, "loads", raise_value_error)

    assert dep._parse_pyproject_toml(pyproject) == (set(), None)


def test_pyproject_comment_apostrophe_does_not_hide_declared_dependency(
    monkeypatch, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        """
[project]
name = "issue-682-repro"
version = "0.0.0"
dependencies = [
    # The project's dependency is declared on the next line.
    "rich>=13",
]
requires-python = ">=3.10"
""".strip(),
        encoding="utf-8",
    )
    source = _write_py(repo / "reproduce.py", "from rich.console import Console\n")

    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: set())
    monkeypatch.setattr(dep, "_collect_local_modules", lambda root: set())
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(
        dep,
        "_build_installed_module_mapping",
        lambda: {"rich": {"rich"}},
    )

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert _extract_single(findings, dep.RULE_ID_UNDECLARED) == []


def test_uv_source_dependency_counts_as_declared_for_d223(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        """
[project]
dependencies = [
  "private-pkg>=1.0.0",
]

[tool.uv.sources]
private-pkg = { git = "https://github.com/example/private-pkg" }
""".strip(),
        encoding="utf-8",
    )
    source = _write_py(repo / "app.py", "import private_pkg\n")

    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: set())
    monkeypatch.setattr(dep, "_collect_local_modules", lambda root: set())
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(dep, "_build_installed_module_mapping", lambda: {})
    monkeypatch.setattr(dep, "_load_import_to_dist_mapping", lambda: {})

    def fail_pypi_check(name, cache):
        raise AssertionError(f"{name} should be treated as declared")

    monkeypatch.setattr(dep, "_check_pypi_status", fail_pypi_check)

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert _extract_single(findings, dep.RULE_ID_UNDECLARED) == []


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


def test_nested_local_imports_are_resolved_without_hiding_external_findings(
    monkeypatch, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "nested-local-mre"\ndependencies = []\n'
        '[tool.setuptools.packages.find]\nwhere = ["src"]\n',
    )
    _write_py(repo / "docs" / "generate_default_bsedict.py", "VALUE = 1\n")
    docs = _write_py(
        repo / "docs" / "conf.py",
        "import generate_default_bsedict\nimport missing_docs_dependency\n",
    )
    _write_py(repo / "src" / "cosmic" / "__init__.py", "VALUE = 2\n")
    consumer = _write_py(
        repo / "src" / "cosmic" / "consumer.py",
        "import cosmic\nimport undeclared_remote_dependency\n",
    )
    _stub_dependency_registry(
        monkeypatch,
        {
            "generate_default_bsedict": "missing",
            "missing_docs_dependency": "missing",
            "cosmic": "exists",
            "undeclared_remote_dependency": "exists",
        },
    )

    findings = dep.scan_python_dependency_hallucinations(repo, [docs, consumer])

    assert [
        (finding["rule_id"], finding["symbol"], finding["line"]) for finding in findings
    ] == [
        (dep.RULE_ID_HALLUCINATION, "missing_docs_dependency", 2),
        (dep.RULE_ID_UNDECLARED, "undeclared_remote_dependency", 2),
    ]


def test_nested_local_imports_use_discovered_files_without_directory_fds(
    monkeypatch, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "nested-local-mre"\ndependencies = []\n'
        '[tool.setuptools.packages.find]\nwhere = ["src"]\n',
    )
    _write_py(repo / "docs" / "generate_default_bsedict.py", "VALUE = 1\n")
    docs = _write_py(
        repo / "docs" / "conf.py",
        "import generate_default_bsedict\nimport missing_docs_dependency\n",
    )
    _write_py(repo / "src" / "cosmic" / "__init__.py", "VALUE = 2\n")
    consumer = _write_py(
        repo / "src" / "cosmic" / "consumer.py",
        "import cosmic\nimport undeclared_remote_dependency\n",
    )
    _stub_dependency_registry(
        monkeypatch,
        {
            "generate_default_bsedict": "missing",
            "missing_docs_dependency": "missing",
            "cosmic": "exists",
            "undeclared_remote_dependency": "exists",
        },
    )
    monkeypatch.setattr(dep, "_supports_directory_fd_access", lambda **_kwargs: False)

    findings = dep.scan_python_dependency_hallucinations(repo, [docs, consumer])
    diff_findings, _ = dep.scan_diff_added_imports(
        repo,
        [
            ("docs/conf.py", 1, "generate_default_bsedict"),
            ("docs/conf.py", 2, "missing_docs_dependency"),
            ("src/cosmic/consumer.py", 1, "cosmic"),
            ("src/cosmic/consumer.py", 2, "undeclared_remote_dependency"),
        ],
    )

    expected = [
        (finding["rule_id"], finding["symbol"], finding["line"]) for finding in findings
    ]
    assert expected == [
        (dep.RULE_ID_HALLUCINATION, "missing_docs_dependency", 2),
        (dep.RULE_ID_UNDECLARED, "undeclared_remote_dependency", 2),
    ]
    assert [
        (finding["rule_id"], finding["symbol"], finding["line"])
        for finding in diff_findings
    ] == expected


def test_known_source_root_lookup_is_linear_in_file_depth():
    roots = {dep.Path(f"root_{index}") for index in range(256)}
    known_files = frozenset(
        dep.Path(f"root_{root_index}/package_{file_index}/module.py")
        for root_index in range(256)
        for file_index in range(79)
    )

    started = time.perf_counter()
    modules = dep._collect_known_source_root_modules(known_files, roots)
    elapsed = time.perf_counter() - started

    assert len(known_files) > 20_000
    assert modules == {f"package_{index}" for index in range(79)}
    assert elapsed < 2.0


def test_secure_directory_access_skips_fallback_inventory(monkeypatch, tmp_path):
    monkeypatch.setattr(dep, "_supports_directory_fd_access", lambda **_kwargs: True)

    def fail_discovery(*_args, **_kwargs):
        raise AssertionError("secure directory access must not build a fallback index")

    monkeypatch.setattr(dep, "discover_source_files", fail_discovery)

    assert dep._dependency_context_python_files(tmp_path, [tmp_path / "app.py"]) == ()


def test_no_directory_fd_fallback_does_not_trust_gitignored_local_files(
    monkeypatch, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
    _write_py(repo / ".gitignore", "docs/ignored_helper.py\n")
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "ignored-local"\ndependencies = []\n',
    )
    _write_py(repo / "docs" / "ignored_helper.py", "VALUE = 1\n")
    source = _write_py(repo / "docs" / "conf.py", "import ignored_helper\n")
    _stub_dependency_registry(monkeypatch, {"ignored_helper": "missing"})
    monkeypatch.setattr(dep, "_supports_directory_fd_access", lambda **_kwargs: False)

    findings = dep.scan_python_dependency_hallucinations(repo, [source])
    diff_findings, _ = dep.scan_diff_added_imports(
        repo, [("docs/conf.py", 1, "ignored_helper")]
    )

    assert [(finding["rule_id"], finding["symbol"]) for finding in findings] == [
        (dep.RULE_ID_HALLUCINATION, "ignored_helper")
    ]
    assert [(finding["rule_id"], finding["symbol"]) for finding in diff_findings] == [
        (dep.RULE_ID_HALLUCINATION, "ignored_helper")
    ]


def test_source_root_package_is_local_outside_its_own_directory(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "source-layout"\ndependencies = []\n'
        '[tool.setuptools.packages.find]\nwhere = ["src"]\n',
    )
    _write_py(repo / "src" / "cosmic" / "models.py", "VALUE = 1\n")
    source = _write_py(repo / "tools" / "build_docs.py", "import cosmic\n")
    _stub_dependency_registry(monkeypatch, {"cosmic": "missing"})

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert findings == []


def test_conventional_src_package_is_local_with_meson(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "meson-layout"\ndependencies = []\n'
        '[build-system]\nbuild-backend = "mesonpy"\n',
    )
    _write_py(repo / "src" / "cosmic" / "__init__.py", "VALUE = 1\n")
    source = _write_py(repo / "src" / "cosmic" / "consumer.py", "import cosmic\n")
    _stub_dependency_registry(monkeypatch, {"cosmic": "exists"})

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert findings == []


def test_source_root_script_with_main_guard_can_import_sibling(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "source-script"\ndependencies = []\n'
        '[tool.setuptools.packages.find]\nwhere = ["src"]\n',
    )
    _write_py(repo / "src" / "tools" / "helper.py", "VALUE = 1\n")
    source = _write_py(
        repo / "src" / "tools" / "run.py",
        'import helper\n\nif __name__ == "__main__":\n    print(helper.VALUE)\n',
    )
    _stub_dependency_registry(monkeypatch, {"helper": "missing"})

    findings = dep.scan_python_dependency_hallucinations(repo, [source])
    diff_findings, _ = dep.scan_diff_added_imports(
        repo,
        [("src/tools/run.py", 1, "helper")],
    )

    assert findings == []
    assert diff_findings == []


def test_main_guard_text_in_docstring_does_not_make_package_module_a_script(
    monkeypatch, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "documented-package"\ndependencies = []\n',
    )
    package = repo / "package"
    _write_py(package / "__init__.py", "")
    _write_py(package / "helper.py", "VALUE = 1\n")
    source = _write_py(
        package / "consumer.py",
        '"""Example::\n\n    if __name__ == "__main__":\n'
        "        run()\n"
        '"""\n'
        "import helper\n",
    )
    _stub_dependency_registry(monkeypatch, {"helper": "missing"})

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert [(finding["rule_id"], finding["symbol"]) for finding in findings] == [
        (dep.RULE_ID_HALLUCINATION, "helper")
    ]


def test_main_guard_does_not_override_regular_package_context(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "guarded-package"\ndependencies = []\n',
    )
    package = repo / "package"
    _write_py(package / "__init__.py", "")
    _write_py(package / "helper.py", "VALUE = 1\n")
    source = _write_py(
        package / "consumer.py",
        'import helper\n\nif __name__ == "__main__":\n    print(helper.VALUE)\n',
    )
    _stub_dependency_registry(monkeypatch, {"helper": "missing"})

    findings = dep.scan_python_dependency_hallucinations(repo, [source])
    diff_findings, _ = dep.scan_diff_added_imports(
        repo,
        [("package/consumer.py", 1, "helper")],
    )

    expected = [(dep.RULE_ID_HALLUCINATION, "helper")]
    assert [(finding["rule_id"], finding["symbol"]) for finding in findings] == expected
    assert [
        (finding["rule_id"], finding["symbol"]) for finding in diff_findings
    ] == expected


def test_repository_source_root_preserves_script_sibling_imports(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "flat-layout"\ndependencies = []\n'
        '[tool.setuptools.packages.find]\nwhere = ["."]\n',
    )
    _write_py(repo / "docs" / "helper.py", "VALUE = 1\n")
    source = _write_py(
        repo / "docs" / "conf.py",
        'import helper\n\nif __name__ == "__main__":\n    print(helper.VALUE)\n',
    )
    _stub_dependency_registry(monkeypatch, {"helper": "missing"})

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert findings == []


def test_repository_source_root_treats_namespace_module_as_package(
    monkeypatch, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "flat-namespace"\ndependencies = []\n'
        '[tool.setuptools.packages.find]\nwhere = ["."]\n',
    )
    _write_py(repo / "namespace_pkg" / "subpkg" / "helper.py", "VALUE = 1\n")
    source = _write_py(
        repo / "namespace_pkg" / "subpkg" / "consumer.py", "import helper\n"
    )
    _stub_dependency_registry(monkeypatch, {"helper": "missing"})

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert [(finding["rule_id"], finding["symbol"]) for finding in findings] == [
        (dep.RULE_ID_HALLUCINATION, "helper")
    ]


def test_named_setuptools_package_directory_is_local(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "mapped-layout"\ndependencies = []\n'
        '[tool.setuptools]\npackages = ["cosmic"]\n'
        'package-dir = {cosmic = "src/cosmic"}\n',
    )
    _write_py(repo / "src" / "cosmic" / "__init__.py", "VALUE = 1\n")
    source = _write_py(repo / "src" / "cosmic" / "consumer.py", "import cosmic\n")
    _stub_dependency_registry(monkeypatch, {"cosmic": "exists"})

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert findings == []


def test_setuptools_namespaces_false_requires_package_initializer(
    monkeypatch, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "regular-packages-only"\ndependencies = []\n'
        '[tool.setuptools.packages.find]\nwhere = ["src"]\n'
        "namespaces = false\n",
    )
    _write_py(repo / "src" / "requests" / "data.py", "VALUE = 1\n")
    source = _write_py(repo / "app.py", "import requests\n")
    _stub_dependency_registry(monkeypatch, {"requests": "exists"})

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert [(finding["rule_id"], finding["symbol"]) for finding in findings] == [
        (dep.RULE_ID_UNDECLARED, "requests")
    ]


def test_named_namespace_package_does_not_hide_bare_sibling_import(
    monkeypatch, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "mapped-namespace"\ndependencies = []\n'
        '[tool.setuptools]\npackages = ["cosmic"]\n'
        'package-dir = {cosmic = "src/cosmic"}\n',
    )
    _write_py(repo / "src" / "cosmic" / "helper.py", "VALUE = 1\n")
    source = _write_py(repo / "src" / "cosmic" / "consumer.py", "import helper\n")
    _stub_dependency_registry(monkeypatch, {"helper": "missing"})

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert [(finding["rule_id"], finding["symbol"]) for finding in findings] == [
        (dep.RULE_ID_HALLUCINATION, "helper")
    ]


def test_malformed_find_where_does_not_abort_package_dir_resolution(
    monkeypatch, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "typed-config"\ndependencies = []\n'
        "[tool.setuptools.packages.find]\nwhere = 1\n"
        '[tool.setuptools.package-dir]\n"" = "src"\n',
    )
    _write_py(repo / "src" / "local_package" / "module.py", "VALUE = 1\n")
    source = _write_py(
        repo / "tools" / "consumer.py",
        "import local_package\nimport missing_dependency\n",
    )
    _stub_dependency_registry(
        monkeypatch,
        {"local_package": "missing", "missing_dependency": "missing"},
    )

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert [(finding["rule_id"], finding["symbol"]) for finding in findings] == [
        (dep.RULE_ID_HALLUCINATION, "missing_dependency")
    ]


def test_malformed_find_table_does_not_abort_dependency_scan(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "malformed-find"\ndependencies = []\n'
        "[tool.setuptools]\npackages = {find = 1}\n",
    )
    source = _write_py(repo / "app.py", "import missing_dependency\n")
    _stub_dependency_registry(monkeypatch, {"missing_dependency": "missing"})

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert [(finding["rule_id"], finding["symbol"]) for finding in findings] == [
        (dep.RULE_ID_HALLUCINATION, "missing_dependency")
    ]


def test_invalid_find_roots_do_not_starve_default_package_directory(
    monkeypatch, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "bounded-config"\ndependencies = []\n'
        "[tool.setuptools.packages.find]\n"
        f"where = {json.dumps([1] * dep.MAX_PYTHON_SOURCE_ROOTS)}\n"
        '[tool.setuptools.package-dir]\n"" = "src"\n',
    )
    _write_py(repo / "src" / "cosmic" / "module.py", "VALUE = 1\n")
    source = _write_py(repo / "tools" / "consumer.py", "import cosmic\n")
    _stub_dependency_registry(monkeypatch, {"cosmic": "missing"})

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert findings == []


def test_invalid_find_roots_do_not_starve_later_valid_root(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    configured = [1] * dep.MAX_PYTHON_SOURCE_ROOTS + ["lib"]
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "late-valid-root"\ndependencies = []\n'
        "[tool.setuptools.packages.find]\n"
        f"where = {json.dumps(configured)}\n",
    )
    _write_py(repo / "lib" / "cosmic" / "module.py", "VALUE = 1\n")
    source = _write_py(repo / "app.py", "import cosmic\n")
    _stub_dependency_registry(monkeypatch, {"cosmic": "missing"})

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert findings == []


def test_source_root_configuration_is_bounded(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    configured = [f"roots/root_{index}" for index in range(300)]
    _write_py(
        repo / "pyproject.toml",
        f"[tool.setuptools.packages.find]\nwhere = {json.dumps(configured)}\n",
    )

    roots = dep._configured_python_source_roots(repo)

    assert len(roots) == dep.MAX_PYTHON_SOURCE_ROOTS
    assert dep.Path("roots/root_255") in roots
    assert dep.Path("roots/root_256") not in roots


def test_source_root_candidate_inspection_is_bounded(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        "[tool.setuptools.packages.find]\n"
        f"where = {json.dumps(['duplicate'] * 2_000)}\n",
    )
    original = dep._configured_python_path
    calls = 0

    def count_candidate(candidate):
        nonlocal calls
        calls += 1
        return original(candidate)

    monkeypatch.setattr(dep, "_configured_python_path", count_candidate)

    roots, _marker_roots, _modules, _directories = dep._configured_python_layout(repo)

    assert roots == {dep.Path("duplicate")}
    assert calls <= dep.MAX_PYTHON_LAYOUT_CANDIDATES + 1


def test_contained_directory_rejects_resolution_loops(monkeypatch, tmp_path):
    def fail_to_resolve(_path, *, strict):
        raise RuntimeError("filesystem link loop")

    monkeypatch.setattr(type(tmp_path), "resolve", fail_to_resolve)

    assert dep._contained_directory(tmp_path, dep.Path(".")) is None


def test_local_python_file_check_holds_parent_directory_open(monkeypatch, tmp_path):
    if not dep._supports_directory_fd_access():
        return
    repo = tmp_path / "repo"
    docs = repo / "docs"
    docs.mkdir(parents=True)
    outside = tmp_path / "outside"
    _write_py(outside / "requests.py", "VALUE = 1\n")
    original_docs = repo / "original_docs"
    real_open = dep.os.open
    swapped = False

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if dir_fd is None:
            descriptor = real_open(path, flags, mode)
        else:
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == "docs" and dir_fd is not None and not swapped:
            docs.rename(original_docs)
            docs.symlink_to(outside, target_is_directory=True)
            swapped = True
        return descriptor

    monkeypatch.setattr(dep.os, "open", swapping_open)
    monkeypatch.setattr(dep, "_supports_directory_fd_access", lambda **_kwargs: True)

    assert not dep._is_local_python_file(repo, dep.Path("docs/requests.py"))
    assert swapped is True


def test_source_root_scan_holds_directory_open(monkeypatch, tmp_path):
    if not dep._supports_directory_fd_access(require_scandir=True):
        return
    repo = tmp_path / "repo"
    source_root = repo / "src"
    source_root.mkdir(parents=True)
    outside = tmp_path / "outside"
    _write_py(outside / "requests.py", "VALUE = 1\n")
    original_source_root = repo / "original_src"
    real_open = dep.os.open
    swapped = False

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if dir_fd is None:
            descriptor = real_open(path, flags, mode)
        else:
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == "src" and dir_fd is not None and not swapped:
            source_root.rename(original_source_root)
            source_root.symlink_to(outside, target_is_directory=True)
            swapped = True
        return descriptor

    monkeypatch.setattr(dep.os, "open", swapping_open)
    monkeypatch.setattr(dep, "_supports_directory_fd_access", lambda **_kwargs: True)

    modules = dep._collect_source_root_modules(repo, {dep.Path("src")})

    assert "requests" not in modules
    assert swapped is True


def test_unrelated_nested_module_does_not_hide_missing_dependency(
    monkeypatch, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "scoped-local"\ndependencies = []\n',
    )
    _write_py(repo / "docs" / "shared_helper.py", "VALUE = 1\n")
    source = _write_py(repo / "tools" / "consumer.py", "import shared_helper\n")
    _stub_dependency_registry(monkeypatch, {"shared_helper": "missing"})

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert [(finding["rule_id"], finding["symbol"]) for finding in findings] == [
        (dep.RULE_ID_HALLUCINATION, "shared_helper")
    ]


def test_unconfigured_non_python_source_directory_does_not_hide_dependency(
    monkeypatch, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "mixed-layout"\ndependencies = []\n',
    )
    (repo / "lib" / "requests").mkdir(parents=True)
    _write_py(repo / "lib" / "requests" / "README.md", "support files\n")
    source = _write_py(repo / "app.py", "import requests\n")
    _stub_dependency_registry(monkeypatch, {"requests": "missing"})

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert [(finding["rule_id"], finding["symbol"]) for finding in findings] == [
        (dep.RULE_ID_HALLUCINATION, "requests")
    ]


def test_package_sibling_decoys_do_not_hide_absolute_imports(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "package-decoys"\ndependencies = []\n',
    )
    package = repo / "src" / "app_package"
    _write_py(package / "__init__.py", "")
    _write_py(package / "package_decoy.py", "VALUE = 1\n")
    direct = _write_py(package / "consumer.py", "import package_decoy\n")
    _write_py(package / "tools" / "namespace_decoy.py", "VALUE = 2\n")
    nested = _write_py(package / "tools" / "consumer.py", "import namespace_decoy\n")
    _stub_dependency_registry(
        monkeypatch,
        {"package_decoy": "missing", "namespace_decoy": "missing"},
    )

    findings = dep.scan_python_dependency_hallucinations(repo, [direct, nested])

    assert [(finding["rule_id"], finding["symbol"]) for finding in findings] == [
        (dep.RULE_ID_HALLUCINATION, "package_decoy"),
        (dep.RULE_ID_HALLUCINATION, "namespace_decoy"),
    ]


def test_non_runtime_and_symlink_siblings_do_not_hide_imports(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "invalid-siblings"\ndependencies = []\n',
    )
    docs = repo / "docs"
    _write_py(docs / "stub_dependency.pyi", "VALUE: int\n")
    _write_py(docs / "windows_script_dependency.pyw", "VALUE = 1\n")
    outside = _write_py(tmp_path / "linked_dependency.py", "VALUE = 2\n")
    link = docs / "linked_dependency.py"
    try:
        link.symlink_to(outside)
    except OSError:
        return
    source = _write_py(
        docs / "conf.py",
        "import stub_dependency\n"
        "import windows_script_dependency\n"
        "import linked_dependency\n",
    )
    _stub_dependency_registry(
        monkeypatch,
        {
            "stub_dependency": "missing",
            "windows_script_dependency": "missing",
            "linked_dependency": "missing",
        },
    )

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert [finding["symbol"] for finding in findings] == [
        "linked_dependency",
        "stub_dependency",
        "windows_script_dependency",
    ]


def test_symlinked_packages_and_importers_do_not_claim_local_modules(
    monkeypatch, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "contained-modules"\ndependencies = []\n'
        '[tool.setuptools.packages.find]\nwhere = ["src"]\n',
    )
    _write_py(repo / "local_helper.py", "VALUE = 1\n")
    _write_py(tmp_path / "root_package" / "__init__.py", "VALUE = 2\n")
    _write_py(tmp_path / "source_package" / "module.py", "VALUE = 3\n")
    outside_importer = _write_py(
        tmp_path / "outside_docs" / "consumer.py", "import local_helper\n"
    )
    (repo / "src").mkdir()
    try:
        (repo / "root_package").symlink_to(
            tmp_path / "root_package", target_is_directory=True
        )
        (repo / "src" / "source_package").symlink_to(
            tmp_path / "source_package", target_is_directory=True
        )
        (repo / "linked_docs").symlink_to(
            tmp_path / "outside_docs", target_is_directory=True
        )
    except OSError:
        return
    source = _write_py(repo / "app.py", "import root_package\nimport source_package\n")
    _stub_dependency_registry(
        monkeypatch,
        {
            "local_helper": "missing",
            "root_package": "missing",
            "source_package": "missing",
        },
    )

    findings = dep.scan_python_dependency_hallucinations(
        repo, [source, repo / "linked_docs" / outside_importer.name]
    )

    assert [finding["symbol"] for finding in findings] == [
        "root_package",
        "source_package",
        "local_helper",
    ]


def test_diff_import_resolution_uses_the_importing_file(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "diff-local"\ndependencies = []\n'
        '[tool.setuptools.packages.find]\nwhere = ["src"]\n',
    )
    _write_py(repo / "docs" / "local_helper.py", "VALUE = 1\n")
    _write_py(repo / "src" / "cosmic" / "__init__.py", "VALUE = 2\n")
    _stub_dependency_registry(
        monkeypatch,
        {"local_helper": "missing", "cosmic": "exists", "missing_dep": "missing"},
    )

    findings, unreachable = dep.scan_diff_added_imports(
        repo,
        [
            ("docs/conf.py", 2, "local_helper"),
            ("src/cosmic/consumer.py", 3, "cosmic"),
            ("docs/conf.py", 4, "missing_dep"),
        ],
    )

    assert unreachable is False
    assert [(finding["rule_id"], finding["symbol"]) for finding in findings] == [
        (dep.RULE_ID_HALLUCINATION, "missing_dep")
    ]


def test_diff_importer_outside_repository_cannot_claim_local_module(
    monkeypatch, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "contained-diff"\ndependencies = []\n',
    )
    _write_py(repo / "local_helper.py", "VALUE = 1\n")
    _stub_dependency_registry(monkeypatch, {"local_helper": "missing"})

    findings, _ = dep.scan_diff_added_imports(
        repo,
        [("../outside/consumer.py", 1, "local_helper")],
    )

    assert [(finding["rule_id"], finding["symbol"]) for finding in findings] == [
        (dep.RULE_ID_HALLUCINATION, "local_helper")
    ]


def test_diff_importer_in_new_directory_can_use_root_module(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "new-diff-directory"\ndependencies = []\n',
    )
    _write_py(repo / "local_helper.py", "VALUE = 1\n")
    _stub_dependency_registry(monkeypatch, {"local_helper": "missing"})

    findings, _ = dep.scan_diff_added_imports(
        repo,
        [("new/nested/consumer.py", 1, "local_helper")],
    )

    assert findings == []


def test_diff_importer_under_symlink_cannot_claim_local_module(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(
        repo / "pyproject.toml",
        '[project]\nname = "linked-diff-directory"\ndependencies = []\n',
    )
    _write_py(repo / "local_helper.py", "VALUE = 1\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (repo / "linked").symlink_to(outside, target_is_directory=True)
    except OSError:
        return
    _stub_dependency_registry(monkeypatch, {"local_helper": "missing"})

    findings, _ = dep.scan_diff_added_imports(
        repo,
        [("linked/consumer.py", 1, "local_helper")],
    )

    assert [(finding["rule_id"], finding["symbol"]) for finding in findings] == [
        (dep.RULE_ID_HALLUCINATION, "local_helper")
    ]


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
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = []\n',
        encoding="utf-8",
    )

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


def test_scan_without_dependency_manifest_suppresses_undeclared_import(
    monkeypatch, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    f = _write_py(repo / "a.py", "import installedmod\n")

    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: set())
    monkeypatch.setattr(dep, "_collect_local_modules", lambda root: set())
    monkeypatch.setattr(dep, "_collect_declared_deps", lambda root: set())
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(
        dep,
        "_build_installed_module_mapping",
        lambda: {"installedmod": {"installed-dist"}},
    )

    finds = dep.scan_python_dependency_hallucinations(repo, [f])

    assert _extract_single(finds, dep.RULE_ID_UNDECLARED) == []


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
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = []\n',
        encoding="utf-8",
    )

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


def test_scan_rejects_symlinked_pypi_cache_file(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = []\n',
        encoding="utf-8",
    )

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

    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "pypi_exists.json"
    target.write_text('{"somepkg": "missing"}', encoding="utf-8")
    cache_path = repo / ".skylos" / "cache" / "pypi_exists.json"
    cache_path.parent.mkdir(parents=True)
    try:
        cache_path.symlink_to(target)
    except OSError:
        import pytest

        pytest.skip("filesystem does not allow symlink creation")

    _ = dep.scan_python_dependency_hallucinations(repo, [f])

    assert target.read_text(encoding="utf-8") == '{"somepkg": "missing"}'
    assert cache_path.is_symlink()


def test_scan_does_not_write_cache_when_not_modified(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = []\n',
        encoding="utf-8",
    )

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
        "dependencies = [\n"
        '  "fastapi>=0.110",\n'
        '  "uvicorn[standard]>=0.27",\n'
        '  "sqlalchemy>=2.0",\n'
        '  "pydantic>=2.5",\n'
        '  "pydantic-settings>=2.0",\n'
        '  "httpx>=0.27",\n'
        "]\n",
        encoding="utf-8",
    )
    deps, name = dep._parse_pyproject_toml(py)
    assert name == "skylos-demo"
    for expected in (
        "fastapi",
        "uvicorn",
        "sqlalchemy",
        "pydantic",
        "pydantic-settings",
        "httpx",
    ):
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
    assert len(app_findings) == 0, (
        f"Self-import 'app' should not be flagged: {app_findings}"
    )


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
