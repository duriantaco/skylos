from skylos.rules.sca import vulnerability_scanner as sca


def test_parse_requirements_txt_rejects_symlink(tmp_path):
    target = tmp_path / "outside-requirements.txt"
    target.write_text("requests==2.31.0\n", encoding="utf-8")
    link = tmp_path / "requirements.txt"
    try:
        link.symlink_to(target)
    except OSError:
        return

    assert sca.parse_requirements_txt(link) == []


def test_scan_dependencies_rejects_symlinked_osv_cache_file(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

    monkeypatch.setattr(sca, "_requests", object())

    def fake_query(deps, cache):
        cache["PyPI:requests:2.31.0"] = []
        return []

    monkeypatch.setattr(sca, "_query_osv_batch", fake_query)

    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "osv_cache.json"
    target.write_text(
        '{"_ts": 9999999999, "PyPI:requests:2.31.0": []}', encoding="utf-8"
    )
    cache_path = repo / ".skylos" / "cache" / "osv_cache.json"
    cache_path.parent.mkdir(parents=True)
    try:
        cache_path.symlink_to(target)
    except OSError:
        import pytest

        pytest.skip("filesystem does not allow symlink creation")

    findings = sca.scan_dependencies(repo)

    assert findings == []
    assert target.read_text(encoding="utf-8") == (
        '{"_ts": 9999999999, "PyPI:requests:2.31.0": []}'
    )
    assert cache_path.is_symlink()


def test_scan_dependencies_reports_unavailable_requests(monkeypatch, tmp_path):
    monkeypatch.setattr(sca, "_requests", None)

    result = sca.scan_dependencies(tmp_path)

    assert result == []
    assert result.receipt["status"] == "unavailable"
    assert result.receipt["complete"] is False
    assert result.receipt["category_complete"] is False
    assert result.receipt["scope"] == "supported_direct_manifest_entries"
    assert result.receipt["reason"] == "requests_dependency_unavailable"


def test_scan_dependencies_reports_invalid_manifest(monkeypatch, tmp_path):
    monkeypatch.setattr(sca, "_requests", object())
    (tmp_path / "package.json").write_text("{invalid", encoding="utf-8")

    result = sca.scan_dependencies(tmp_path)

    assert result == []
    assert result.receipt["status"] == "incomplete"
    assert result.receipt["complete"] is False
    assert result.receipt["parse_error_count"] == 1


def test_scan_dependencies_reports_invalid_utf8_pyproject(monkeypatch, tmp_path):
    monkeypatch.setattr(sca, "_requests", object())
    (tmp_path / "pyproject.toml").write_bytes(
        b'[project]\ndependencies = ["rich==13.0.0"]\n# \xff\n'
    )

    result = sca.scan_dependencies(tmp_path)

    assert result == []
    assert result.receipt["status"] == "incomplete"
    assert result.receipt["complete"] is False
    assert result.receipt["parse_error_count"] == 1
    assert result.receipt["queried_dependency_count"] == 0


def test_scan_dependencies_reports_osv_failure(monkeypatch, tmp_path):
    class FailingRequests:
        @staticmethod
        def post(*args, **kwargs):
            raise RuntimeError("offline")

    monkeypatch.setattr(sca, "_requests", FailingRequests())
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

    result = sca.scan_dependencies(tmp_path)

    assert result == []
    assert result.receipt["status"] == "incomplete"
    assert result.receipt["complete"] is False
    assert result.receipt["query"]["failed_batches"] == 1


def test_project_cache_cannot_suppress_osv_query(monkeypatch, tmp_path):
    monkeypatch.setattr(sca, "_requests", object())
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    cache_path = tmp_path / ".skylos" / "cache" / "osv_cache.json"
    cache_path.parent.mkdir(parents=True)
    cache_path.write_text(
        '{"_ts": 9999999999, "PyPI:requests:2.31.0": []}', encoding="utf-8"
    )
    queried = []

    def fake_query(deps, cache):
        queried.extend(deps)
        return sca.OsvQueryResult(
            [],
            receipt={
                "status": "complete",
                "complete": True,
                "requested_batches": 1,
                "successful_batches": 1,
                "failed_batches": 0,
            },
        )

    monkeypatch.setattr(sca, "_query_osv_batch", fake_query)

    result = sca.scan_dependencies(tmp_path)

    assert [item["name"] for item in queried] == ["requests"]
    assert result.receipt["cache_hit_count"] == 0
    assert result.receipt["queried_dependency_count"] == 1
    assert result.receipt["cache_policy"] == "project_cache_disabled"


def test_manifest_parsers_query_only_exact_versions(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "exact==1.2.3\nrange>=2.0\ncompatible~=3.0\nwildcard==4.*\n",
        encoding="utf-8",
    )
    package_json = tmp_path / "package.json"
    package_json.write_text(
        '{"dependencies":{"exact":"1.2.3","caret":"^2.0.0","tag":"latest"}}',
        encoding="utf-8",
    )
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.poetry.dependencies]\npython = "^3.12"\nexact = "1.2.3"\ncaret = "^2.0"\n',
        encoding="utf-8",
    )

    assert [
        (item["name"], item["version"])
        for item in sca.parse_requirements_txt(requirements)
    ] == [("exact", "1.2.3")]
    assert [
        (item["name"], item["version"]) for item in sca.parse_package_json(package_json)
    ] == [("exact", "1.2.3")]
    assert [
        (item["name"], item["version"]) for item in sca.parse_pyproject_toml(pyproject)
    ] == [("exact", "1.2.3")]


def test_poetry_multiple_constraint_versions_are_preserved(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.poetry.dependencies]
python = ">=3.7"
foo = [
    { version = "1.9.0", python = "<3.8" },
    { version = "2.0.0", python = ">=3.8" },
]
""".strip(),
        encoding="utf-8",
    )

    expected = [("foo", "1.9.0"), ("foo", "2.0.0")]
    assert [
        (item["name"], item["version"])
        for item in sca.parse_pyproject_toml(pyproject)
    ] == expected
    assert [
        (item["name"], item["version"])
        for item in sca.parse_pyproject_toml_candidates(pyproject)
    ] == expected


def test_pyproject_comment_apostrophe_preserves_dependency_candidates(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
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

    candidates = sca.parse_pyproject_toml_candidates(pyproject)

    assert [(item["name"], item["version"]) for item in candidates] == [
        ("rich", "13")
    ]


def test_malformed_pyproject_does_not_produce_poetry_dependencies(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.poetry.dependencies]\nghost = "9.9.9"\nnot valid toml\n',
        encoding="utf-8",
    )

    assert sca.parse_pyproject_toml(pyproject) == []
    assert sca.parse_pyproject_toml_candidates(pyproject) == []


def test_scan_receipt_counts_unresolved_ranges(monkeypatch, tmp_path):
    monkeypatch.setattr(sca, "_requests", object())
    (tmp_path / "requirements.txt").write_text(
        "exact==1.2.3\nrange>=2.0\n", encoding="utf-8"
    )
    queried = []

    def fake_query(deps, cache):
        queried.extend(deps)
        return sca.OsvQueryResult(
            [],
            receipt={
                "status": "complete",
                "complete": True,
                "requested_batches": 1,
                "successful_batches": 1,
                "failed_batches": 0,
            },
        )

    monkeypatch.setattr(sca, "_query_osv_batch", fake_query)

    result = sca.scan_dependencies(tmp_path)

    assert [(item["name"], item["version"]) for item in queried] == [("exact", "1.2.3")]
    assert result.receipt["unresolved_dependency_count"] == 1
    assert result.receipt["status"] == "complete_with_unresolved_versions"


def test_sca_inventory_limits_fail_closed_before_network(monkeypatch, tmp_path):
    monkeypatch.setattr(sca, "_requests", object())
    monkeypatch.setattr(sca, "MAX_UNIQUE_DEPENDENCIES", 1)
    (tmp_path / "requirements.txt").write_text(
        "one==1.0.0\ntwo==2.0.0\n", encoding="utf-8"
    )

    def unexpected_query(*args, **kwargs):
        raise AssertionError("bounded inventory must not be queried")

    monkeypatch.setattr(sca, "_query_osv_batch", unexpected_query)

    result = sca.scan_dependencies(tmp_path)

    assert result == []
    assert result.receipt["complete"] is False
    assert result.receipt["limit_reasons"] == ["dependency_limit_exceeded"]


def test_sca_discovers_deep_monorepo_manifest(monkeypatch, tmp_path):
    monkeypatch.setattr(sca, "_requests", object())
    nested = tmp_path / "services" / "group" / "team" / "api" / "worker"
    nested.mkdir(parents=True)
    (nested / "requirements.txt").write_text("deep==1.0.0\n", encoding="utf-8")
    queried = []

    def fake_query(deps, cache):
        queried.extend(deps)
        return sca.OsvQueryResult(
            [],
            receipt={
                "status": "complete",
                "complete": True,
                "requested_batches": 1,
                "successful_batches": 1,
                "failed_batches": 0,
            },
        )

    monkeypatch.setattr(sca, "_query_osv_batch", fake_query)

    result = sca.scan_dependencies(tmp_path)

    assert [item["name"] for item in queried] == ["deep"]
    assert result.receipt["supported_manifest_count"] == 1
