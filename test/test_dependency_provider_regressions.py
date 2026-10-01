"""Provider evidence must survive unsafe lookalikes without trusting repo caches."""

import json

import pytest

from skylos.rules.ai_defect import dependency_hallucination as dep
from skylos.rules.ai_defect import pypi_wheel_modules
from test.test_dependency_providers import _write


def _inventory(*files, complete=True, version="1.0"):
    return {
        **pypi_wheel_modules.module_inventory(files),
        "version": version,
        "complete_for_requirement": complete,
    }


def _project(tmp_path, source, requirement="safe-lib==1.0"):
    repo = tmp_path / "repo"
    _write(repo / "requirements.txt", requirement + "\n")
    return repo, _write(repo / "main.py", source)


def _isolate(monkeypatch, answers=None):
    answers = answers or {}
    fetched, names = [], []
    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: {"os", "sys", "json"})
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(dep, "_load_import_to_dist_mapping", lambda: {})
    monkeypatch.setattr(dep, "_build_installed_module_mapping", lambda: {})
    monkeypatch.setattr(dep, "_installed_provider_inventory", lambda _dist, _ctx: None)

    def status(name, cache):
        names.append(name)
        return cache.setdefault(name, "missing")

    def fetch(dist, *, specifier=""):
        fetched.append((dist, specifier))
        return answers.get((dist, specifier), answers.get(dist, {"status": "no_wheel"}))

    monkeypatch.setattr(dep, "_check_pypi_status", status)
    monkeypatch.setattr(dep, "_fetch_dist_modules", fetch)
    return fetched, names


def _scan(mode, repo, path, root="ghost_required"):
    if mode == "diff":
        return dep.scan_diff_added_imports(
            repo, [(path.relative_to(repo).as_posix(), 1, root)]
        )[0]
    return dep.scan_python_dependency_hallucinations(repo, [path])


@pytest.mark.parametrize("mode", ["full", "diff"])
@pytest.mark.parametrize(
    "source",
    [
        "try:\n    import ghost_required\nexcept ImportError:\n    raise\n",
        "try:\n    import ghost_required\nexcept ImportError:\n    raise RuntimeError('required')\n",
        "try:\n    import safe_lib\nexcept ImportError:\n    import ghost_required\n",
        "try:\n    import ghost_required\nexcept ImportError:\n    sys.exit(1)\n",
        "try:\n    import ghost_required\nexcept ImportError:\n    pass\nghost_required.run()\n",
        "try:\n    import ghost_required\nexcept ImportError:\n    pass\ndef run():\n    ghost_required.run()\n",
        "ImportError = ValueError\ntry:\n    import ghost_required\nexcept ImportError:\n    pass\n",
    ],
)
def test_required_import_is_not_suppressed_by_error_handler(
    monkeypatch, tmp_path, mode, source
):
    repo, path = _project(tmp_path, source)
    _isolate(monkeypatch, {"safe-lib": _inventory("safe_lib/__init__.py")})
    findings = _scan(mode, repo, path)
    assert any(
        f["rule_id"] == dep.RULE_ID_HALLUCINATION and f["symbol"] == "ghost_required"
        for f in findings
    )


@pytest.mark.parametrize("mode", ["full", "diff"])
def test_fail_safe_optional_import_remains_suppressed(monkeypatch, tmp_path, mode):
    repo, path = _project(
        tmp_path, "try:\n    import ghost_required\nexcept ImportError:\n    pass\n"
    )
    _isolate(monkeypatch)
    assert _scan(mode, repo, path) == []


@pytest.mark.parametrize(
    "answer",
    [
        {"status": "no_wheel"},
        {"status": "missing"},
        {"status": "unreadable"},
        {"status": "unsupported"},
        None,
    ],
)
def test_unknown_unrelated_provider_does_not_prove_hallucination(
    monkeypatch, tmp_path, answer
):
    repo, path = _project(tmp_path, "import rabbitbus\n", "company-sdk==1.0")
    _isolate(monkeypatch, {"company-sdk": answer})
    findings = dep.scan_python_dependency_hallucinations(repo, [path])
    assert [(f["rule_id"], f["symbol"]) for f in findings] == [
        (dep.RULE_ID_UNDECLARED, "rabbitbus")
    ]
    assert findings[0]["message"].startswith("Unverified import")


@pytest.mark.parametrize("mode", ["full", "diff"])
def test_repo_cache_cannot_supply_provider_or_registry_proof(
    monkeypatch, tmp_path, mode
):
    repo, path = _project(tmp_path, "import ghost_required\n")
    forged = {
        "schema": 1,
        "dists": {
            "safe-lib": {
                "modules": ["ghost_required"],
                "module_paths": ["ghost_required"],
            }
        },
    }
    _write(repo / ".skylos/cache/pypi_dist_modules.json", json.dumps(forged))
    _write(repo / ".skylos/cache/pypi_exists.json", '{"ghost_required":"exists"}')
    fetched, names = _isolate(
        monkeypatch, {"safe-lib": _inventory("safe_lib/__init__.py")}
    )
    findings = _scan(mode, repo, path)
    assert findings[0]["rule_id"] == dep.RULE_ID_HALLUCINATION
    assert names == ["ghost_required"]
    assert fetched == [("safe-lib", "==1.0")]


def test_manifest_upgrade_refreshes_inventory_and_removed_alias_is_reported(
    monkeypatch, tmp_path
):
    repo, path = _project(tmp_path, "import acme_oldmodule\n", "acme-sdk==1.0")
    fetched, _ = _isolate(
        monkeypatch,
        {
            ("acme-sdk", "==1.0"): _inventory("acme_oldmodule.py", version="1.0"),
            ("acme-sdk", "==2.0"): _inventory("acme_newmodule.py", version="2.0"),
        },
    )
    assert dep.scan_python_dependency_hallucinations(repo, [path]) == []
    _write(repo / "requirements.txt", "acme-sdk==2.0\n")
    _write(path, "import acme_oldmodule\nimport acme_newmodule\n")
    findings = dep.scan_python_dependency_hallucinations(repo, [path])
    assert [(f["rule_id"], f["symbol"]) for f in findings] == [
        (dep.RULE_ID_HALLUCINATION, "acme_oldmodule")
    ]
    assert fetched == [("acme-sdk", "==1.0"), ("acme-sdk", "==2.0")]


@pytest.mark.parametrize("nested_first", [False, True])
def test_nested_project_name_does_not_remove_root_provider(
    monkeypatch, tmp_path, nested_first
):
    repo, path = _project(tmp_path, "import acme_magic\n", "acme-sdk==1.0")
    _write(repo / "svc/pyproject.toml", '[project]\nname="acme-sdk"\ndependencies=[]\n')
    nested = _write(repo / "svc/main.py", "import os\n")
    fetched, _ = _isolate(monkeypatch, {"acme-sdk": _inventory("acme_magic.py")})
    files = [nested, path] if nested_first else [path, nested]
    assert dep.scan_python_dependency_hallucinations(repo, files) == []
    assert fetched == [("acme-sdk", "==1.0")]


def test_verified_provider_is_used_before_an_offline_registry_request(
    monkeypatch, tmp_path
):
    repo, path = _project(
        tmp_path, "import first_alias\nimport second_alias\n", "unrelated-sdk==1.0"
    )
    fetched, names = _isolate(
        monkeypatch, {"unrelated-sdk": _inventory("first_alias.py", "second_alias.py")}
    )

    def status(name, _cache):
        names.append(name)
        return "missing" if name == "first_alias" else "unknown"

    monkeypatch.setattr(dep, "_check_pypi_status", status)
    findings, unreachable = dep.scan_diff_added_imports(
        repo, [("main.py", 1, "first_alias"), ("main.py", 2, "second_alias")]
    )
    assert findings == [] and unreachable is False
    assert names == ["first_alias"]
    assert fetched == [("unrelated-sdk", "==1.0")]


@pytest.mark.parametrize(
    "source",
    [
        "import shared.missing\n",
        "from shared import missing\n",
        "from shared.missing import Widget\n",
    ],
)
def test_namespace_portion_cannot_prove_a_different_portion(
    monkeypatch, tmp_path, source
):
    repo, path = _project(tmp_path, source, "shared-one==1.0")
    _isolate(monkeypatch, {"shared-one": _inventory("shared/one/__init__.py")})
    findings = dep.scan_python_dependency_hallucinations(repo, [path])
    assert [(f["rule_id"], f["symbol"]) for f in findings] == [
        (dep.RULE_ID_HALLUCINATION, "shared")
    ]


def test_namespace_portions_can_be_satisfied_by_separate_distributions(
    monkeypatch, tmp_path
):
    repo, path = _project(
        tmp_path,
        "from shared.one import Widget\nfrom shared.two import Other\n",
        "shared-one==1.0\nshared-two==1.0",
    )
    _isolate(
        monkeypatch,
        {
            "shared-one": _inventory("shared/one/__init__.py"),
            "shared-two": _inventory("shared/two/__init__.py"),
        },
    )
    assert dep.scan_python_dependency_hallucinations(repo, [path]) == []


@pytest.mark.parametrize("mode", ["full", "diff"])
def test_optional_namespace_portion_does_not_make_required_portion_missing(
    monkeypatch, tmp_path, mode
):
    source = "try:\n    import shared.optional\nexcept ImportError:\n    pass\nimport shared.required\n"
    repo, path = _project(tmp_path, source, "shared-core==1.0")
    _isolate(monkeypatch, {"shared-core": _inventory("shared/required/__init__.py")})
    assert _scan(mode, repo, path, "shared") == []


@pytest.mark.parametrize("requirement", ["safe-lib", "safe-lib>=1,<3", "safe-lib==1.*"])
def test_selected_release_does_not_prove_absence_in_other_allowed_versions(
    monkeypatch, tmp_path, requirement
):
    repo, path = _project(tmp_path, "import ghost_required\n", requirement)
    _isolate(
        monkeypatch, {"safe-lib": _inventory("safe_lib/__init__.py", complete=False)}
    )
    findings = dep.scan_python_dependency_hallucinations(repo, [path])
    assert findings[0]["rule_id"] == dep.RULE_ID_UNDECLARED


@pytest.mark.parametrize(
    "manifest, text, expected",
    [
        ("requirements.txt", "acme-sdk>=1.0,<2.0\n", "<2.0,>=1.0"),
        (
            "pyproject.toml",
            '[project]\nname="demo"\ndependencies=["acme-sdk==1.0"]\n',
            "==1.0",
        ),
        (
            "pyproject.toml",
            '[tool.poetry]\nname="demo"\n[tool.poetry.dependencies]\nacme-sdk="^1.2.3"\n',
            "<2,>=1.2.3",
        ),
        (
            "setup.py",
            'from setuptools import setup\nsetup(name="demo", install_requires=["acme-sdk==1.0"])\n',
            "==1.0",
        ),
    ],
)
def test_declared_specifier_is_forwarded_to_inventory_lookup(
    monkeypatch, tmp_path, manifest, text, expected
):
    repo = tmp_path / "repo"
    _write(repo / manifest, text)
    path = _write(repo / "main.py", "import acme_magic\n")
    fetched, _ = _isolate(monkeypatch, {"acme-sdk": _inventory("acme_magic.py")})
    assert dep.scan_python_dependency_hallucinations(repo, [path]) == []
    assert fetched == [("acme-sdk", expected)]


@pytest.mark.parametrize(
    "manifest, text",
    [
        ("requirements.txt", "acme-sdk @ https://private.example/acme.whl\n"),
        ("requirements.txt", "-i https://private.example/simple\nacme-sdk==1.0\n"),
        (
            "requirements.txt",
            "--index-url=https://private.example/simple\nacme-sdk==1.0\n",
        ),
        ("pyproject.toml", '[project]\nname="demo"\ndynamic=["dependencies"]\n'),
        ("pyproject.toml", '[project]\nname="demo"\ndynamic=12\n'),
        (
            "pyproject.toml",
            '[tool.poetry]\nname="demo"\n[tool.poetry.dependencies]\nacme-sdk={version="1.0",source="internal"}\n',
        ),
        (
            "setup.py",
            'from setuptools import setup\nsetup(name="demo", install_requires=dynamic_requirements)\n',
        ),
    ],
)
def test_unsupported_or_private_declarations_cannot_use_public_inventory(
    monkeypatch, tmp_path, manifest, text
):
    repo = tmp_path / "repo"
    _write(repo / manifest, text)
    path = _write(repo / "main.py", "import acme_magic\n")
    fetched, _ = _isolate(monkeypatch, {"acme-sdk": _inventory("acme_magic.py")})
    findings = dep.scan_python_dependency_hallucinations(repo, [path])
    assert findings[0]["rule_id"] == dep.RULE_ID_UNDECLARED
    assert findings[0]["message"].startswith("Unverified import")
    assert fetched == []


def test_lookup_budget_is_shared_across_many_scopes_and_files(monkeypatch, tmp_path):
    repo, root_path = _project(
        tmp_path,
        "import first_ghost\n",
        "\n".join(f"provider-{i}==1.0" for i in range(80)),
    )
    files = [root_path]
    for i in range(5):
        _write(
            repo / f"svc{i}/pyproject.toml",
            f'[project]\nname="svc{i}"\ndependencies=["extra-{i}==1.0"]\n',
        )
        files.append(_write(repo / f"svc{i}/main.py", f"import other_ghost_{i}\n"))
    fetched, _ = _isolate(monkeypatch)
    findings = dep.scan_python_dependency_hallucinations(repo, files)
    assert len(fetched) == dep.MAX_DIST_MODULE_LOOKUPS
    assert len(findings) == len(files)
    assert all(f["rule_id"] == dep.RULE_ID_UNDECLARED for f in findings)


def test_offline_failure_does_not_wait_for_every_declared_provider(
    monkeypatch, tmp_path
):
    repo, path = _project(
        tmp_path,
        "import first_ghost\nimport second_ghost\n",
        "\n".join(f"provider-{i}==1.0" for i in range(80)),
    )
    fetched, _ = _isolate(monkeypatch, {f"provider-{i}": None for i in range(80)})
    findings, unreachable = dep.scan_diff_added_imports(
        repo, [("main.py", 1, "first_ghost"), ("main.py", 2, "second_ghost")]
    )
    assert len(fetched) == dep.DIST_MODULE_LOOKUP_WORKERS
    assert len(findings) == 2 and unreachable is True


def test_exact_installed_record_is_checked_before_registry(monkeypatch, tmp_path):
    actual_lookup = dep._installed_provider_inventory
    repo, _ = _project(tmp_path, "from real_alias import Widget\n")
    fetched, names = _isolate(monkeypatch)
    monkeypatch.setattr(dep, "_installed_provider_inventory", actual_lookup)
    site_packages = tmp_path / "venv/lib/python3.12/site-packages"
    dist_info = site_packages / "safe_lib-1.0.dist-info"
    _write(
        dist_info / "METADATA", "Metadata-Version: 2.1\nName: safe-lib\nVersion: 1.0\n"
    )
    _write(dist_info / "RECORD", "real_alias/__init__.py,,\n")
    monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / "venv"))
    findings, unreachable = dep.scan_diff_added_imports(
        repo, [("main.py", 1, "real_alias")]
    )
    assert findings == [] and unreachable is False
    assert fetched == [] and names == []


def test_installed_record_with_wrong_version_does_not_supply_provider(
    monkeypatch, tmp_path
):
    actual_lookup = dep._installed_provider_inventory
    repo, path = _project(tmp_path, "import real_alias\n")
    fetched, _ = _isolate(monkeypatch, {"safe-lib": _inventory("safe_lib/__init__.py")})
    monkeypatch.setattr(dep, "_installed_provider_inventory", actual_lookup)
    site_packages = tmp_path / "venv/lib/python3.12/site-packages"
    dist_info = site_packages / "safe_lib-2.0.dist-info"
    _write(
        dist_info / "METADATA", "Metadata-Version: 2.1\nName: safe-lib\nVersion: 2.0\n"
    )
    _write(dist_info / "RECORD", "real_alias.py,,\n")
    monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / "venv"))
    findings = dep.scan_python_dependency_hallucinations(repo, [path])
    assert findings[0]["rule_id"] == dep.RULE_ID_HALLUCINATION
    assert fetched == [("safe-lib", "==1.0")]


def test_symlinked_dist_info_cannot_supply_installed_proof(monkeypatch, tmp_path):
    actual_lookup = dep._installed_provider_inventory
    repo, path = _project(tmp_path, "import real_alias\n")
    _isolate(monkeypatch)
    monkeypatch.setattr(dep, "_installed_provider_inventory", actual_lookup)
    outside = tmp_path / "outside"
    _write(outside / "METADATA", "Name: safe-lib\nVersion: 1.0\n")
    _write(outside / "RECORD", "real_alias.py,,\n")
    site_packages = tmp_path / "venv/lib/python3.12/site-packages"
    site_packages.mkdir(parents=True)
    try:
        (site_packages / "safe_lib-1.0.dist-info").symlink_to(
            outside, target_is_directory=True
        )
    except OSError:
        pytest.skip("directory symlinks unavailable")
    monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / "venv"))
    findings = dep.scan_python_dependency_hallucinations(repo, [path])
    assert findings[0]["rule_id"] == dep.RULE_ID_UNDECLARED


@pytest.mark.parametrize("mode", ["full", "diff"])
def test_logging_handler_leaves_uncertainty_instead_of_proving_required_import(
    monkeypatch, tmp_path, mode
):
    source = "try:\n    import ghost_required\nexcept ImportError:\n    logging.warning('optional integration unavailable')\n"
    repo, path = _project(tmp_path, source)
    _isolate(monkeypatch, {"safe-lib": _inventory("safe_lib/__init__.py")})
    findings = _scan(mode, repo, path)
    assert findings[0]["rule_id"] == dep.RULE_ID_UNDECLARED
    assert findings[0]["message"].startswith("Unverified import")
    assert "fallback cannot be proven" in findings[0]["message"]


@pytest.mark.parametrize("mode", ["full", "diff"])
def test_earlier_fatal_catcher_does_not_make_later_handler_a_safe_fallback(
    monkeypatch, tmp_path, mode
):
    source = "try:\n    import ghost_required\nexcept Exception:\n    raise\nexcept ImportError:\n    pass\n"
    repo, path = _project(tmp_path, source)
    _isolate(monkeypatch, {"safe-lib": _inventory("safe_lib/__init__.py")})
    assert _scan(mode, repo, path)[0]["rule_id"] == dep.RULE_ID_HALLUCINATION


@pytest.mark.parametrize("mode", ["full", "diff"])
def test_aliased_earlier_fatal_catcher_does_not_make_later_handler_safe(
    monkeypatch, tmp_path, mode
):
    source = "OtherError = ImportError\ntry:\n    import ghost_required\nexcept OtherError:\n    raise\nexcept ImportError:\n    pass\n"
    repo, path = _project(tmp_path, source)
    _isolate(monkeypatch, {"safe-lib": _inventory("safe_lib/__init__.py")})
    assert _scan(mode, repo, path)[0]["rule_id"] == dep.RULE_ID_HALLUCINATION


def test_plain_module_from_one_provider_shadows_namespace_from_another(
    monkeypatch, tmp_path
):
    repo, path = _project(
        tmp_path, "import shared.child\n", "provider-one==1.0\nprovider-two==1.0"
    )
    _isolate(
        monkeypatch,
        {
            "provider-one": _inventory("shared.py"),
            "provider-two": _inventory("shared/child.py"),
        },
    )
    findings = dep.scan_python_dependency_hallucinations(repo, [path])
    assert findings and findings[0]["rule_id"] == dep.RULE_ID_HALLUCINATION


def test_plain_module_and_regular_package_collision_is_unverified(
    monkeypatch, tmp_path
):
    repo, path = _project(
        tmp_path, "import shared.child\n", "provider-one==1.0\nprovider-two==1.0"
    )
    _isolate(
        monkeypatch,
        {
            "provider-one": _inventory("shared.py"),
            "provider-two": _inventory("shared/__init__.py", "shared/child.py"),
        },
    )
    findings = dep.scan_python_dependency_hallucinations(repo, [path])
    assert findings[0]["rule_id"] == dep.RULE_ID_UNDECLARED
    assert findings[0]["message"].startswith("Unverified import")


@pytest.mark.parametrize("variants_directory", [False, True])
def test_manifest_file_limit_does_not_prove_provider_absent(
    monkeypatch, tmp_path, variants_directory
):
    repo = tmp_path / "repo"
    parent = repo / "requirements" if variants_directory else repo
    for index in range(dep.MAX_REQUIREMENTS_FILES_PER_DIRECTORY):
        name = (
            f"{index:03}.txt" if variants_directory else f"requirements-{index:03}.txt"
        )
        _write(parent / name, "safe-lib==1.0\n")
    last_name = "999.txt" if variants_directory else "requirements-999.txt"
    _write(parent / last_name, "alias-provider==1.0\n")
    path = _write(repo / "main.py", "import actual_alias\n")
    _isolate(monkeypatch, {"safe-lib": _inventory("safe_lib/__init__.py")})
    assert dep._provider_directory_metadata(repo)[2] is True
    findings = dep.scan_python_dependency_hallucinations(repo, [path])
    assert findings[0]["rule_id"] == dep.RULE_ID_UNDECLARED
