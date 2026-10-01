"""SKY-D222/D223: decide from what declared distributions actually ship.

The false CRITICALs on djangoproject.com came from treating a PyPI 404 for an
import name as proof: ``djmoney`` (django-money), ``debug_toolbar``
(django-debug-toolbar), ``registration`` (django-registration-redux) and the
``sphinxcontrib`` namespace are all real and declared.
"""

import io
import logging
import urllib.error
import zipfile

import pytest

import skylos.rules.ai_defect.dependency_hallucination as dep
from skylos.rules.ai_defect import installed_modules_cache, pypi_wheel_modules


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path fixture
        text, encoding="utf-8"
    )
    return path


def _stub_registry(monkeypatch, *, pypi=None, wheels=None, installed=None):
    """PyPI name lookups, wheel module lists, and installed metadata."""
    pypi = pypi or {}
    wheels = wheels or {}
    fetched = []

    def fetch(dist, **_kwargs):
        fetched.append(dist)
        answer = wheels.get(dist, {"status": "no_wheel"})
        if answer is None:
            return None
        answer = dict(answer)
        if "modules" in answer:
            roots = answer["modules"]
            inventory = pypi_wheel_modules.module_inventory(
                f"{root}/__init__.py" for root in roots
            )
            inventory.update(answer)
            # Synthetic fixtures explicitly describe complete provider files.
            inventory.setdefault("complete_for_requirement", True)
            return inventory
        return answer

    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: {"os", "sys"})
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(dep, "_build_installed_module_mapping", lambda: installed or {})
    monkeypatch.setattr(dep, "_installed_provider_inventory", lambda _dist, _ctx: None)
    monkeypatch.setattr(dep, "_load_import_to_dist_mapping", lambda: {})
    monkeypatch.setattr(
        dep, "_check_pypi_status", lambda name, _cache: pypi.get(name, "missing")
    )
    monkeypatch.setattr(dep, "_fetch_dist_modules", fetch)
    return fetched


def _findings(findings):
    return sorted((f["rule_id"], f["severity"], f["symbol"]) for f in findings)


def _project(tmp_path, dependencies, source, name="site"):
    repo = tmp_path / "repo"
    deps = ", ".join(f'"{d}"' for d in dependencies)
    _write(
        repo / "pyproject.toml",
        f'[project]\nname = "{name}"\ndependencies = [{deps}]\n',
    )
    return repo, _write(repo / "app" / "views.py", source)


def test_declared_distributions_with_other_import_names_are_not_reported(
    monkeypatch, tmp_path
):
    repo, source = _project(
        tmp_path,
        ["django-money", "django-debug-toolbar", "django-registration-redux"],
        "import djmoney\nimport debug_toolbar\nfrom registration import forms\n",
    )
    _stub_registry(
        monkeypatch,
        # "registration" is an unrelated PyPI project, the others are not.
        pypi={"registration": "exists"},
        wheels={
            "django-money": {"modules": ["djmoney"]},
            "django-debug-toolbar": {"modules": ["debug_toolbar"]},
            "django-registration-redux": {"modules": ["registration", "test_app"]},
        },
    )

    assert dep.scan_python_dependency_hallucinations(repo, [source]) == []


def test_hallucination_is_critical_once_every_declared_distribution_is_checked(
    monkeypatch, tmp_path
):
    repo, source = _project(
        tmp_path,
        ["django-money", "requests"],
        "import djmoney\nimport requests\nimport fastapi_magic_auth\n",
    )
    _stub_registry(
        monkeypatch,
        pypi={"requests": "exists"},
        wheels={
            "django-money": {"modules": ["djmoney"]},
            "requests": {"modules": ["requests"]},
        },
    )

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert _findings(findings) == [
        (dep.RULE_ID_HALLUCINATION, dep.SEV_CRITICAL, "fastapi_magic_auth")
    ]


@pytest.mark.parametrize(
    "answer",
    [{"status": "no_wheel"}, {"status": "missing"}, {"status": "unreadable"}],
)
def test_unknown_declared_modules_make_a_hallucination_unverified(
    monkeypatch, tmp_path, answer
):
    repo, source = _project(
        tmp_path, ["requests", "acme-internal"], "import acme_magic\n"
    )
    _stub_registry(
        monkeypatch,
        wheels={"requests": {"modules": ["requests"]}, "acme-internal": answer},
    )

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert _findings(findings) == [
        (dep.RULE_ID_UNDECLARED, dep.SEV_MEDIUM, "acme_magic")
    ]
    assert findings[0]["message"].startswith("Unverified import 'acme_magic'")
    assert "dependency 'acme-internal' could not be checked" in findings[0]["message"]


def test_unreadable_distribution_with_an_unrelated_name_leaves_uncertainty(
    monkeypatch, tmp_path
):
    # djangoproject.com declares psycopg-c, which only ships a source archive.
    repo, source = _project(
        tmp_path, ["psycopg-c", "requests"], "import fastapi_magic_auth\n"
    )
    _stub_registry(
        monkeypatch,
        wheels={
            "psycopg-c": {"status": "no_wheel"},
            "requests": {"modules": ["requests"]},
        },
    )

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert _findings(findings) == [
        (dep.RULE_ID_UNDECLARED, dep.SEV_MEDIUM, "fastapi_magic_auth")
    ]


def test_installed_root_metadata_does_not_prove_other_modules_absent(
    monkeypatch, tmp_path
):
    repo, source = _project(
        tmp_path, ["django-money", "requests"], "import djmoney\nimport made_up\n"
    )
    fetched = _stub_registry(
        monkeypatch,
        installed={"djmoney": {"django-money"}, "requests": {"requests"}},
    )

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert _findings(findings) == [(dep.RULE_ID_UNDECLARED, dep.SEV_MEDIUM, "made_up")]
    assert set(fetched) == {"django-money", "requests"}


def test_registry_failure_stops_lookups_and_marks_the_scan_incomplete(
    monkeypatch, tmp_path
):
    plugins = [f"ghost-plugin-{index}" for index in range(40)]
    repo, _ = _project(tmp_path, plugins, "import ghost_one\nimport ghost_two\n")
    fetched = _stub_registry(monkeypatch, wheels=dict.fromkeys(plugins))

    findings, unreachable = dep.scan_diff_added_imports(
        repo, [("app/views.py", 1, "ghost_one"), ("app/views.py", 2, "ghost_two")]
    )

    # Any of the related "ghost-plugin-*" packages could ship these modules.
    assert {(f["rule_id"], f["symbol"]) for f in findings} == {
        (dep.RULE_ID_UNDECLARED, "ghost_one"),
        (dep.RULE_ID_UNDECLARED, "ghost_two"),
    }
    assert "'ghost-plugin-0', 'ghost-plugin-1'" in findings[0]["message"]
    assert "and 37 more" in findings[0]["message"]
    assert unreachable is True
    # One failed round; the second import does not wait out more timeouts.
    assert len(fetched) == dep.DIST_MODULE_LOOKUP_WORKERS


def test_undeclared_check_only_looks_up_similarly_named_distributions(
    monkeypatch, tmp_path
):
    repo, source = _project(
        tmp_path,
        ["django-registration-redux", "stripe", "feedparser"],
        "import registration\nimport yaml\n",
    )
    fetched = _stub_registry(
        monkeypatch,
        pypi={"registration": "exists", "yaml": "exists"},
        wheels={"django-registration-redux": {"modules": ["registration"]}},
    )

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    # An undeclared import is MEDIUM and claims no proof, so unrelated
    # distributions are not looked up for it.
    assert _findings(findings) == [(dep.RULE_ID_UNDECLARED, dep.SEV_MEDIUM, "yaml")]
    assert fetched == ["django-registration-redux"]


def test_namespace_portion_is_not_a_hallucination(monkeypatch, tmp_path):
    repo, source = _project(
        tmp_path,
        ["sphinx"],
        "from sphinxcontrib.serializinghtml import jsonimpl\n",
    )
    _stub_registry(
        monkeypatch,
        pypi={"sphinxcontrib-serializinghtml": "exists"},
        wheels={"sphinx": {"modules": ["sphinx"]}},
    )

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert _findings(findings) == [
        (dep.RULE_ID_UNDECLARED, dep.SEV_MEDIUM, "sphinxcontrib")
    ]
    assert "sphinxcontrib-serializinghtml" in findings[0]["message"]


def test_declared_namespace_portion_does_not_provide_other_portions(
    monkeypatch, tmp_path
):
    repo, source = _project(
        tmp_path,
        ["sphinxcontrib-applehelp", "stripe"],
        "import sphinxcontrib.serializinghtml\n",
    )
    _stub_registry(
        monkeypatch,
        wheels={
            "sphinxcontrib-applehelp": {
                "modules": ["sphinxcontrib"],
                "module_paths": ["sphinxcontrib", "sphinxcontrib.applehelp"],
                "concrete_module_paths": ["sphinxcontrib.applehelp"],
            }
        },
    )

    assert _findings(dep.scan_python_dependency_hallucinations(repo, [source])) == [
        (dep.RULE_ID_UNDECLARED, dep.SEV_MEDIUM, "sphinxcontrib")
    ]


def test_own_project_name_is_not_a_provider_to_look_up(monkeypatch, tmp_path):
    repo, source = _project(tmp_path, [], "import invented_pkg\n", name="my-app")
    fetched = _stub_registry(monkeypatch)

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert _findings(findings) == [
        (dep.RULE_ID_HALLUCINATION, dep.SEV_CRITICAL, "invented_pkg")
    ]
    assert fetched == []


def test_nested_project_name_is_not_a_provider_to_look_up(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    _write(repo / "requirements.txt", "requests\n")
    _write(
        repo / "svc" / "pyproject.toml",
        '[project]\nname = "svc-internal"\ndependencies = []\n',
    )
    source = _write(repo / "svc" / "main.py", "import invented_pkg\n")
    fetched = _stub_registry(
        monkeypatch, wheels={"requests": {"modules": ["requests"]}}
    )

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert _findings(findings) == [
        (dep.RULE_ID_HALLUCINATION, dep.SEV_CRITICAL, "invented_pkg")
    ]
    assert "svc-internal" not in fetched


def test_wheel_answers_are_fresh_between_scans(monkeypatch, tmp_path):
    repo, source = _project(tmp_path, ["django-money"], "import djmoney\n")
    fetched = _stub_registry(
        monkeypatch, wheels={"django-money": {"modules": ["djmoney"]}}
    )

    assert dep.scan_python_dependency_hallucinations(repo, [source]) == []
    assert dep.scan_python_dependency_hallucinations(repo, [source]) == []
    assert fetched == ["django-money", "django-money"]


def test_failed_lookups_are_not_cached(monkeypatch, tmp_path):
    repo, source = _project(tmp_path, ["django-money"], "import djmoney\n")
    fetched = _stub_registry(monkeypatch, wheels={"django-money": None})

    first = dep.scan_python_dependency_hallucinations(repo, [source])
    second = dep.scan_python_dependency_hallucinations(repo, [source])

    assert (
        _findings(first)
        == _findings(second)
        == [(dep.RULE_ID_UNDECLARED, dep.SEV_MEDIUM, "djmoney")]
    )
    assert fetched == ["django-money", "django-money"]


def test_repository_module_inventory_cache_is_not_used(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    dep.save_project_json_cache(
        repo,
        ".skylos/cache/pypi_dist_modules.json",
        {
            "schema": 1,
            "dists": {
                "good": {"modules": ["good"]},
                "bad-modules": {"modules": "good"},
                "bad-status": {"status": "exists"},
                "missing": {"status": "missing"},
            },
        },
    )

    _stub_registry(monkeypatch)
    assert dep._build_dependency_context(repo)["dist_modules"] == {}


def test_virtualenv_metadata_is_read(monkeypatch, tmp_path):
    site_packages = tmp_path / "venv" / "lib" / "python3.12" / "site-packages"
    dist_info = site_packages / "django_money-3.6.1.dist-info"
    _write(dist_info / "METADATA", "Metadata-Version: 2.1\nName: django-money\n")
    _write(dist_info / "top_level.txt", "djmoney\n")
    monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / "venv"))

    assert str(site_packages) in installed_modules_cache.virtual_env_site_packages()
    assert "django-money" in dep._build_installed_module_mapping()["djmoney"]


def test_missing_mapping_file_is_reported(monkeypatch, caplog):
    monkeypatch.setattr(dep, "_IMPORT_TO_DIST_MAPPING", None)
    monkeypatch.setattr(dep, "_MAPPING_FILENAME", "no-such-mapping.txt")

    with caplog.at_level(logging.WARNING, logger=dep.logger.name):
        mapping = dep._load_import_to_dist_mapping()

    assert "no-such-mapping.txt" in caplog.text
    assert mapping["cv2"] == "opencv-python"


def test_shipped_mapping_file_is_loaded(monkeypatch):
    monkeypatch.setattr(dep, "_IMPORT_TO_DIST_MAPPING", None)

    mapping = dep._load_import_to_dist_mapping()

    assert mapping["sorl"] == "sorl_thumbnail"
    assert len(mapping) > 500


@pytest.mark.parametrize(
    "source",
    [
        # requests' tests/compat.py and tests/conftest.py (Python 2 fallbacks).
        "try:\n    import StringIO\nexcept ImportError:\n    import io as StringIO\n",
        "try:\n    from cStringIO import StringIO\nexcept ImportError:\n    StringIO = None\n",
        "try:\n    import ujsonx as json\nexcept (ImportError, AttributeError):\n"
        "    import json\n",
        "try:\n    if True:\n        import StringIO\nexcept Exception:\n    pass\n",
    ],
)
def test_import_the_code_can_run_without_is_not_a_hallucination(
    monkeypatch, tmp_path, source
):
    repo, path = _project(tmp_path, ["requests"], source)
    _stub_registry(
        monkeypatch,
        pypi={"io": "exists"},
        wheels={"requests": {"modules": ["requests"]}},
        installed={},
    )
    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: {"io", "http", "json"})

    assert dep.scan_python_dependency_hallucinations(repo, [path]) == []
    findings, _ = dep.scan_diff_added_imports(
        repo, [("app/views.py", 2, mod) for mod in sorted(dep._extract_imports(source))]
    )
    assert findings == []


@pytest.mark.parametrize(
    "source",
    [
        # Also imported without a guard elsewhere in the file.
        "try:\n    import ghostlib\nexcept ImportError:\n    pass\nimport ghostlib\n",
        "try:\n    import ghostlib\nexcept ImportError:\n    pass\n"
        "def run():\n    import ghostlib\n",
        # The handler does not catch a failed import.
        "try:\n    import ghostlib\nexcept ValueError:\n    pass\n",
        # Only runs later, outside the try.
        "try:\n    def load():\n        import ghostlib\nexcept ImportError:\n    pass\n",
        # else/finally blocks are not guarded.
        "try:\n    pass\nexcept ImportError:\n    pass\nelse:\n    import ghostlib\n",
    ],
)
def test_unguarded_import_is_still_a_hallucination(monkeypatch, tmp_path, source):
    repo, path = _project(tmp_path, ["requests"], source)
    _stub_registry(monkeypatch, wheels={"requests": {"modules": ["requests"]}})

    findings = dep.scan_python_dependency_hallucinations(repo, [path])

    assert _findings(findings) == [
        (dep.RULE_ID_HALLUCINATION, dep.SEV_CRITICAL, "ghostlib")
    ]


# --- reading a wheel's file list -------------------------------------------


def test_top_level_modules_from_wheel_file_names():
    names = [
        "djmoney/__init__.py",
        "djmoney/models/fields.py",
        "sphinxcontrib/serializinghtml/__init__.py",
        "six.py",
        "_cffi_backend.cpython-312-darwin.so",
        "winmod.cp312-win_amd64.pyd",
        "pkg-1.0.data/purelib/vendored/__init__.py",
        "pkg-1.0.data/scripts/tool",
        "pkg-1.0.dist-info/RECORD",
        "foo-stubs/__init__.pyi",
        "distutils-precedence.pth",
        "README.md",
        "emptydir/",
    ]

    assert pypi_wheel_modules.top_level_modules(names) == {
        "djmoney",
        "sphinxcontrib",
        "six",
        "_cffi_backend",
        "winmod",
        "vendored",
    }


def _wheel_bytes(names, comment=b""):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in names:
            archive.writestr(name, b"x = 1\n")
        archive.comment = comment
    return buffer.getvalue()


def _serve(monkeypatch, *, wheel, json_body=None, filename="pkg-1.0-py3-none-any.whl"):
    """Fake PyPI JSON plus range reads of one wheel; returns the request log."""
    import json

    wheel_url = f"https://{pypi_wheel_modules.WHEEL_HOST}/packages/{filename}"
    if json_body is None:
        json_body = {
            "info": {"version": "1.0"},
            "urls": [
                {
                    "packagetype": "bdist_wheel",
                    "filename": filename,
                    "url": wheel_url,
                    "size": len(wheel),
                }
            ],
        }
    requests = []

    def fake_get(url, *, max_bytes, byte_range=None, **_kwargs):
        requests.append((url, byte_range))
        if url.startswith("https://pypi.org/pypi/"):
            return json.dumps(json_body).encode()
        assert url == wheel_url and byte_range is not None
        start, end = byte_range
        body = wheel[start : end + 1]
        assert len(body) <= max_bytes
        return body

    monkeypatch.setattr(pypi_wheel_modules, "_http_get", fake_get)
    return requests


def test_wheel_modules_are_read_from_the_zip_index_only(monkeypatch):
    wheel = _wheel_bytes(
        [
            "djmoney/__init__.py",
            "djmoney/money.py",
            "django_money-3.6.dist-info/RECORD",
        ],
        comment=b"c" * 1000,
    )
    requests = _serve(monkeypatch, wheel=wheel)

    result = pypi_wheel_modules.fetch_distribution_modules("django-money")

    assert result["modules"] == ["djmoney"]
    assert result["module_paths"] == ["djmoney", "djmoney.money"]
    wheel_reads = [byte_range for _url, byte_range in requests[1:]]
    assert wheel_reads == [(0, len(wheel) - 1)]  # a small wheel fits the tail read


def test_large_zip_index_is_fetched_with_a_second_range(monkeypatch):
    names = [f"bigpkg/module_{index:05d}_{'x' * 40}.py" for index in range(2000)]
    wheel = _wheel_bytes(names)
    requests = _serve(monkeypatch, wheel=wheel)

    result = pypi_wheel_modules.fetch_distribution_modules("bigpkg")

    assert result["modules"] == ["bigpkg"]
    assert len(requests) == 3  # JSON, tail, then the rest of the index
    assert all(
        byte_range[1] - byte_range[0] < len(wheel) for _, byte_range in requests[1:]
    )


def test_project_missing_from_pypi(monkeypatch):
    monkeypatch.setattr(pypi_wheel_modules, "_http_get", lambda url, **_kw: None)

    assert pypi_wheel_modules.fetch_distribution_modules("nope") == {
        "status": "missing"
    }


@pytest.mark.parametrize(
    "files",
    [
        [],
        [
            {
                "packagetype": "sdist",
                "url": "https://files.pythonhosted.org/a.tar.gz",
                "size": 9,
            }
        ],
        [
            {
                "packagetype": "bdist_wheel",
                "url": "https://evil.example/a.whl",
                "size": 9,
            }
        ],
        [
            {
                "packagetype": "bdist_wheel",
                "url": "http://files.pythonhosted.org/a.whl",
                "size": 9,
            }
        ],
        [
            {
                "packagetype": "bdist_wheel",
                "url": "https://files.pythonhosted.org/a.whl",
                "size": 9,
                "yanked": True,
            }
        ],
    ],
)
def test_releases_without_a_usable_wheel(monkeypatch, files):
    requests = _serve(monkeypatch, wheel=b"", json_body={"urls": files})

    expected = (
        "unsupported"
        if any(
            item.get("packagetype") == "bdist_wheel" and not item.get("yanked")
            for item in files
        )
        else "no_wheel"
    )
    assert pypi_wheel_modules.fetch_distribution_modules("pkg") == {"status": expected}
    assert len(requests) == 1


def test_bad_zip_index_is_unreadable(monkeypatch):
    _serve(monkeypatch, wheel=b"PK\x03\x04" + b"\x00" * 200)

    assert pypi_wheel_modules.fetch_distribution_modules("pkg") == {
        "status": "unreadable"
    }


def test_zip_index_entry_count_beyond_data_is_unreadable(monkeypatch):
    wheel = bytearray(_wheel_bytes(["pkg/__init__.py"]))
    end = wheel.rfind(b"PK\x05\x06")
    wheel[end + 10 : end + 12] = (500).to_bytes(2, "little")  # claim 500 entries
    _serve(monkeypatch, wheel=bytes(wheel))

    assert pypi_wheel_modules.fetch_distribution_modules("pkg") == {
        "status": "unreadable"
    }


class _Response:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    def read(self, size):
        return self._body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_range_request_answered_with_the_whole_file_is_refused(monkeypatch):
    monkeypatch.setattr(
        pypi_wheel_modules,
        "_urlopen",
        lambda request, timeout: _Response(200, b"x" * 100),
    )

    with pytest.raises(pypi_wheel_modules.LookupUnavailable):
        pypi_wheel_modules._http_get(
            "https://files.pythonhosted.org/a.whl", max_bytes=10, byte_range=(0, 9)
        )


def test_oversized_reply_is_refused(monkeypatch):
    monkeypatch.setattr(
        pypi_wheel_modules,
        "_urlopen",
        lambda request, timeout: _Response(200, b"x" * 100),
    )

    with pytest.raises(pypi_wheel_modules.LookupUnavailable):
        pypi_wheel_modules._http_get("https://pypi.org/pypi/a/json", max_bytes=10)


def test_network_errors_are_unavailable_not_missing(monkeypatch):
    def fail(request, timeout):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(pypi_wheel_modules, "_urlopen", fail)

    with pytest.raises(pypi_wheel_modules.LookupUnavailable):
        pypi_wheel_modules.fetch_distribution_modules("requests")
