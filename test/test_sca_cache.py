import json

import pytest

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
        json.dumps(
            {
                "dependencies": {
                    "exact": "1.2.3",
                    "prerelease": "v2.0.0-rc.1+build.5",
                    "double-equals": "==7.6.3",
                    "leading-zero": "01.2.3",
                    "loose-prerelease": "1.2.3beta",
                    "numeric-prerelease": "1.2.3-01",
                    "unicode-digits": "١.٢.٣",
                    "caret": "^2.0.0",
                    "loose": "18.x",
                    "partial": "18",
                    "tag": "latest",
                }
            }
        ),
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
    ] == [
        ("exact", "1.2.3"),
        ("prerelease", "2.0.0-rc.1"),
        ("double-equals", "7.6.3"),
        ("leading-zero", "1.2.3"),
        ("loose-prerelease", "1.2.3-beta"),
        ("numeric-prerelease", "1.2.3-1"),
    ]
    assert sca.parse_package_json(package_json)[1]["version_spec"] == (
        "v2.0.0-rc.1+build.5"
    )
    unicode_candidate = next(
        item
        for item in sca.parse_package_json_candidates(package_json)
        if item["name"] == "unicode-digits"
    )
    assert unicode_candidate["version"] == "١.٢.٣"
    assert unicode_candidate["exact"] is False
    assert [
        (item["name"], item["version"]) for item in sca.parse_pyproject_toml(pyproject)
    ] == [("exact", "1.2.3")]


def test_npm_finding_line_anchors_to_dependency_entry_not_first_occurrence(tmp_path):
    package_json = tmp_path / "package.json"
    package_json.write_text(
        """
{
  "name": "line-anchor-mre",
  "keywords": [
    "through2"
  ],
  "dependencies": {
    "through2": "999999.0.0"
  }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    [item] = sca.parse_package_json_candidates(package_json)
    assert item["line"] == 7


def test_npm_finding_line_distinguishes_same_name_in_dependencies_and_devdependencies(
    tmp_path,
):
    package_json = tmp_path / "package.json"
    package_json.write_text(
        """
{
  "dependencies": {
    "react": "18.0.0"
  },
  "devDependencies": {
    "react": "17.0.0"
  }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    lines = [item["line"] for item in sca.parse_package_json_candidates(package_json)]
    assert lines == [3, 6]


def test_npm_finding_line_anchors_correctly_when_section_is_a_single_line(tmp_path):
    # A section object written entirely on one line closes its brace on the
    # same line it opens, so a line-scoped "am I still inside the section"
    # scan sees depth return to zero before it ever inspects that line's
    # content and falls back to the first textual occurrence of the name
    # anywhere in the file -- here, inside "keywords" one line above the
    # real declaring entry.
    package_json = tmp_path / "package.json"
    package_json.write_text(
        """
{
  "keywords": ["lodash"],
  "dependencies": { "lodash": "4.17.20" }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    [item] = sca.parse_package_json_candidates(package_json)
    assert item["line"] == 3


def test_npm_finding_line_ignores_same_name_nested_under_overrides(tmp_path):
    # This scanner only ever reads the top-level "dependencies" and
    # "devDependencies" objects (overrides are not scanned as candidates at
    # all), so a same-named key nested inside "overrides" must never hijack
    # the line reported for the real top-level entry, however deeply nested
    # or however many times the name repeats underneath it.
    package_json = tmp_path / "package.json"
    package_json.write_text(
        """
{
  "dependencies": { "foo": "1.0.0" },
  "overrides": {
    "bar": {
      "dependencies": {
        "foo": "2.0.0"
      }
    }
  }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    [item] = sca.parse_package_json_candidates(package_json)
    assert item["name"] == "foo"
    assert item["line"] == 2


def test_npm_scans_all_dependency_sections_with_context(tmp_path):
    package_json = tmp_path / "package.json"
    package_json.write_text(
        """
{
  "dependencies": { "runtime-dep": "1.0.0" },
  "devDependencies": { "dev-dep": "2.0.0" },
  "peerDependencies": {
    "peer-dep": "3.0.0",
    "optional-peer": "4.0.0"
  },
  "peerDependenciesMeta": {
    "optional-peer": { "optional": true }
  },
  "optionalDependencies": { "optional-dep": "5.0.0" }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    parsed = {item["name"]: item for item in sca.parse_package_json(package_json)}

    assert set(parsed) == {
        "runtime-dep",
        "dev-dep",
        "peer-dep",
        "optional-peer",
        "optional-dep",
    }
    assert parsed["runtime-dep"]["dependency_section"] == "dependencies"
    assert parsed["dev-dep"]["dependency_section"] == "devDependencies"
    assert parsed["peer-dep"]["dependency_section"] == "peerDependencies"
    assert parsed["peer-dep"]["dependency_optional"] is False
    assert parsed["optional-peer"]["peer_dependency_optional"] is True
    assert parsed["optional-peer"]["dependency_optional"] is True
    assert parsed["optional-peer"]["line"] == 6
    assert parsed["optional-dep"]["dependency_section"] == "optionalDependencies"
    assert parsed["optional-dep"]["dependency_optional"] is True


def test_npm_optional_dependency_overrides_dependency_before_parsing_and_counting(
    tmp_path,
):
    package_json = tmp_path / "package.json"
    manifest = {
        "dependencies": {"shared": "1.0.0", "runtime": "2.0.0"},
        "optionalDependencies": {"shared": "3.0.0"},
    }
    text = json.dumps(manifest, indent=2)
    package_json.write_text(text, encoding="utf-8")

    for parser in (sca.parse_package_json, sca.parse_package_json_candidates):
        parsed = parser(package_json)
        assert [(item["name"], item["version"]) for item in parsed] == [
            ("runtime", "2.0.0"),
            ("shared", "3.0.0"),
        ]
        shared = next(item for item in parsed if item["name"] == "shared")
        assert shared["dependency_section"] == "optionalDependencies"
        assert text.splitlines()[shared["line"] - 1].strip() == '"shared": "3.0.0"'

    assert sca._declared_dependency_count("package.json", text) == 2


@pytest.mark.parametrize(
    ("version_spec", "expected_version", "exact"),
    [
        ("1.2.3", "1.2.3", True),
        ("=v1.2.3", "1.2.3", True),
        ("^18", "^18", False),
        ("18.x", "18.x", False),
        (">=18 <20", ">=18 <20", False),
        ("^18 || ^19", "^18 || ^19", False),
        ("*", "*", False),
        ("", "", False),
        ("latest", "latest", False),
    ],
)
def test_npm_registry_specs_preserve_exactness(
    tmp_path,
    version_spec,
    expected_version,
    exact,
):
    package_json = tmp_path / "package.json"
    package_json.write_text(
        json.dumps({"peerDependencies": {"react": version_spec}}),
        encoding="utf-8",
    )

    [candidate] = sca.parse_package_json_candidates(package_json)
    assert candidate["version"] == expected_version
    assert candidate["version_spec"] == version_spec
    assert candidate["exact"] is exact
    assert sca.parse_package_json(package_json) == ([] if not exact else [candidate])


@pytest.mark.parametrize(
    "version_spec",
    [
        "workspace:*",
        "file:../react",
        "../react",
        "https://example.test/react.tgz",
        "git+https://example.test/react.git",
        "github:user/react",
        "user/react",
        "npm:react@^18",
        "react.tgz",
    ],
)
def test_npm_non_registry_specs_are_not_candidates(tmp_path, version_spec):
    package_json = tmp_path / "package.json"
    package_json.write_text(
        json.dumps({"peerDependencies": {"local-react": version_spec}}),
        encoding="utf-8",
    )

    assert sca.parse_package_json_candidates(package_json) == []
    assert sca.parse_package_json(package_json) == []


@pytest.mark.parametrize("version_spec", ["x" * 1025, " " * 1025 + "1.2.3"])
def test_npm_oversized_spec_is_not_copied_into_candidates(tmp_path, version_spec):
    package_json = tmp_path / "package.json"
    package_json.write_text(
        json.dumps({"peerDependencies": {"react": version_spec}}),
        encoding="utf-8",
    )

    assert sca.parse_package_json_candidates(package_json) == []
    assert sca.parse_package_json(package_json) == []


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


@pytest.mark.parametrize(
    ("dependency_spec", "optional_spec", "expected_query", "unresolved"),
    [
        ("1.0.0", "^2.0.0", [], 1),
        ("^1.0.0", "2.0.0", [("shared", "2.0.0")], 0),
    ],
)
def test_scan_receipt_uses_effective_optional_override(
    monkeypatch,
    tmp_path,
    dependency_spec,
    optional_spec,
    expected_query,
    unresolved,
):
    monkeypatch.setattr(sca, "_requests", object())
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"shared": dependency_spec},
                "optionalDependencies": {"shared": optional_spec},
            }
        ),
        encoding="utf-8",
    )
    queried = []

    def fake_query(deps, _cache):
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

    assert [(item["name"], item["version"]) for item in queried] == expected_query
    assert result.receipt["unresolved_dependency_count"] == unresolved
    assert result.receipt["dependency_count"] == len(expected_query)


def test_sca_finding_keeps_peer_dependency_context(monkeypatch, tmp_path):
    monkeypatch.setattr(sca, "_requests", object())
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "peerDependencies": {"react": "18.2.0"},
                "peerDependenciesMeta": {"react": {"optional": True}},
            }
        ),
        encoding="utf-8",
    )

    def fake_query(deps, _cache):
        [dependency] = deps
        finding = sca._make_finding(
            dependency,
            {
                "vuln_id": "GHSA-test",
                "summary": "test vulnerability",
                "aliases": [],
            },
        )
        return sca.OsvQueryResult(
            [finding],
            receipt={
                "status": "complete",
                "complete": True,
                "requested_batches": 1,
                "successful_batches": 1,
                "failed_batches": 0,
            },
        )

    monkeypatch.setattr(sca, "_query_osv_batch", fake_query)

    [finding] = sca.scan_dependencies(tmp_path)

    assert finding["metadata"]["dependency_section"] == "peerDependencies"
    assert finding["metadata"]["dependency_optional"] is True
    assert finding["metadata"]["peer_dependency_optional"] is True
    assert finding["metadata"]["version_spec"] == "18.2.0"
    assert finding["metadata"]["exact"] is True


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
