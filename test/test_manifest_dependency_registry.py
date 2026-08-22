from __future__ import annotations

import json
import urllib.error
from unittest.mock import MagicMock

import pytest

from skylos.rules.ai_defect import manifest_dependency_hallucination as manifest_rule
from skylos.rules.ai_defect.manifest_dependency_hallucination import (
    RULE_ID_VERSION_HALLUCINATION,
    STATUS_MISSING_PACKAGE,
    STATUS_MISSING_VERSION,
    STATUS_PRESENT,
    STATUS_UNKNOWN,
    VERSION_CACHE_PATH,
    VERSION_CACHE_SCHEMA_VERSION,
    check_dependency_version_status,
    scan_manifest_dependency_hallucinations,
)
from skylos.rules.sca.vulnerability_scanner import (
    ECOSYSTEM_GO,
    ECOSYSTEM_NPM,
    ECOSYSTEM_PYPI,
)

NPM_VERSION_URL = "https://registry.npmjs.org/react/999999.0.0"
NPM_PACKAGE_URL = "https://registry.npmjs.org/react"


def _oversized_registry_response():
    response = MagicMock()
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    response.read.return_value = b"x" * 1_000_001
    return response


def _not_found(url):
    return urllib.error.HTTPError(url, 404, "not found", {}, None)


def test_large_npm_response_flags_missing_version_and_caches(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"dependencies": {"react": "999999.0.0"}}),
        encoding="utf-8",
    )
    response = _oversized_registry_response()
    seen_requests = []

    def fake_urlopen(request, *, timeout):
        seen_requests.append((request.full_url, request.get_method(), timeout))
        if request.full_url == NPM_VERSION_URL:
            raise _not_found(NPM_VERSION_URL)
        if request.full_url == NPM_PACKAGE_URL:
            return response
        raise AssertionError(f"unexpected registry URL: {request.full_url}")

    monkeypatch.setattr(manifest_rule.urllib.request, "urlopen", fake_urlopen)
    findings = scan_manifest_dependency_hallucinations(repo)

    assert [finding["rule_id"] for finding in findings] == [
        RULE_ID_VERSION_HALLUCINATION
    ]
    assert findings[0]["metadata"]["package_name"] == "react"
    assert findings[0]["metadata"]["dependency_truth_state"] == (STATUS_MISSING_VERSION)
    assert seen_requests == [
        (NPM_VERSION_URL, "HEAD", 5),
        (NPM_PACKAGE_URL, "HEAD", 5),
    ]
    response.read.assert_not_called()
    cache = json.loads((repo / VERSION_CACHE_PATH).read_text(encoding="utf-8"))
    assert cache["statuses"] == {
        "npm:react:999999.0.0": STATUS_MISSING_VERSION,
    }

    monkeypatch.setattr(
        manifest_rule.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: pytest.fail("cached status performed a lookup"),
    )
    assert scan_manifest_dependency_hallucinations(repo) == findings


@pytest.mark.parametrize(
    "case",
    [
        (
            ECOSYSTEM_NPM,
            "@scope/widget",
            "999999.0.0",
            "https://registry.npmjs.org/@scope%2Fwidget/999999.0.0",
            "https://registry.npmjs.org/@scope%2Fwidget",
        ),
        (
            ECOSYSTEM_PYPI,
            "numpy",
            "999999.0.0",
            "https://pypi.org/pypi/numpy/999999.0.0/json",
            "https://pypi.org/pypi/numpy/json",
        ),
        (
            ECOSYSTEM_GO,
            "github.com/stretchr/testify",
            "999999.0.0",
            "https://proxy.golang.org/github.com/stretchr/testify/@v/v999999.0.0.info",
            "https://proxy.golang.org/github.com/stretchr/testify/@v/list",
        ),
    ],
    ids=["npm", "pypi", "go"],
)
def test_registry_checks_use_head_without_reading_response_bodies(
    monkeypatch,
    case,
):
    ecosystem, name, version, version_url, package_url = case
    response = _oversized_registry_response()
    seen_requests = []
    mode = "present"

    def fake_urlopen(request, *, timeout):
        seen_requests.append((request.full_url, request.get_method(), timeout))
        if request.full_url == version_url:
            if mode != "present":
                raise _not_found(version_url)
            return response
        if request.full_url == package_url:
            if mode == "missing_package":
                raise _not_found(package_url)
            return response
        raise AssertionError(f"unexpected registry URL: {request.full_url}")

    monkeypatch.setattr(manifest_rule.urllib.request, "urlopen", fake_urlopen)
    cases = [
        ("present", STATUS_PRESENT, [version_url]),
        ("missing_version", STATUS_MISSING_VERSION, [version_url, package_url]),
        ("missing_package", STATUS_MISSING_PACKAGE, [version_url, package_url]),
    ]

    for mode, expected_status, expected_urls in cases:
        seen_requests.clear()
        status = check_dependency_version_status(ecosystem, name, version, {})
        assert status == expected_status
        assert seen_requests == [(url, "HEAD", 5) for url in expected_urls]

    response.read.assert_not_called()


@pytest.mark.parametrize("version_spec", ["^18", "18.x", ">=18 <20", "*", "", "latest"])
def test_npm_non_exact_specs_only_check_package_endpoint(
    monkeypatch,
    version_spec,
):
    response = _oversized_registry_response()
    seen_requests = []

    def fake_urlopen(request, *, timeout):
        seen_requests.append((request.full_url, request.get_method(), timeout))
        if request.full_url != NPM_PACKAGE_URL:
            raise AssertionError(f"unexpected version lookup: {request.full_url}")
        return response

    monkeypatch.setattr(manifest_rule.urllib.request, "urlopen", fake_urlopen)

    status = check_dependency_version_status(
        ECOSYSTEM_NPM,
        "react",
        version_spec,
        {},
    )

    assert status == STATUS_PRESENT
    assert seen_requests == [(NPM_PACKAGE_URL, "HEAD", 5)]
    response.read.assert_not_called()


def test_npm_non_exact_spec_reports_missing_package_not_missing_version(monkeypatch):
    seen_requests = []

    def fake_urlopen(request, *, timeout):
        seen_requests.append((request.full_url, request.get_method(), timeout))
        raise _not_found(request.full_url)

    monkeypatch.setattr(manifest_rule.urllib.request, "urlopen", fake_urlopen)

    status = check_dependency_version_status(
        ECOSYSTEM_NPM,
        "missing-peer",
        "^18",
        {},
    )

    assert status == STATUS_MISSING_PACKAGE
    assert seen_requests == [("https://registry.npmjs.org/missing-peer", "HEAD", 5)]


@pytest.mark.parametrize(
    ("version_spec", "canonical_version"),
    [
        ("7.6.3+build.5", "7.6.3"),
        ("==7.6.3", "7.6.3"),
        ("01.2.3", "1.2.3"),
        ("1.2.3beta", "1.2.3-beta"),
        ("1.2.3-01", "1.2.3-1"),
    ],
)
def test_npm_exact_versions_use_canonical_registry_lookup(
    monkeypatch,
    version_spec,
    canonical_version,
):
    response = _oversized_registry_response()
    seen_requests = []

    def fake_urlopen(request, *, timeout):
        seen_requests.append((request.full_url, request.get_method(), timeout))
        return response

    monkeypatch.setattr(manifest_rule.urllib.request, "urlopen", fake_urlopen)

    status = check_dependency_version_status(
        ECOSYSTEM_NPM,
        "semver",
        version_spec,
        {},
    )

    assert status == STATUS_PRESENT
    assert seen_requests == [
        (f"https://registry.npmjs.org/semver/{canonical_version}", "HEAD", 5),
    ]
    response.read.assert_not_called()


@pytest.mark.parametrize(
    "version_spec",
    ["workspace:*", "file:../react", "npm:react@^18", "github:org/react"],
)
def test_npm_non_registry_specs_do_not_make_requests(monkeypatch, version_spec):
    monkeypatch.setattr(
        manifest_rule.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: pytest.fail("non-registry spec performed a lookup"),
    )

    assert (
        check_dependency_version_status(
            ECOSYSTEM_NPM,
            "react-alias",
            version_spec,
            {},
        )
        == STATUS_UNKNOWN
    )


def test_old_range_cache_is_invalidated_before_package_only_lookup(
    tmp_path,
    monkeypatch,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"peerDependencies": {"react": "18.x"}}),
        encoding="utf-8",
    )
    cache_path = repo / VERSION_CACHE_PATH
    cache_path.parent.mkdir(parents=True)
    cache_path.write_text(
        json.dumps(
            {
                "schema_version": VERSION_CACHE_SCHEMA_VERSION - 1,
                "statuses": {"npm:react:18.x": STATUS_MISSING_VERSION},
            }
        ),
        encoding="utf-8",
    )
    response = _oversized_registry_response()
    seen_requests = []

    def fake_urlopen(request, *, timeout):
        seen_requests.append((request.full_url, request.get_method(), timeout))
        return response

    monkeypatch.setattr(manifest_rule.urllib.request, "urlopen", fake_urlopen)

    assert scan_manifest_dependency_hallucinations(repo) == []
    assert seen_requests == [(NPM_PACKAGE_URL, "HEAD", 5)]
    refreshed = json.loads(cache_path.read_text(encoding="utf-8"))
    assert refreshed == {
        "schema_version": VERSION_CACHE_SCHEMA_VERSION,
        "statuses": {"npm:react:<package-only>": STATUS_PRESENT},
    }


@pytest.mark.parametrize(
    ("failure_point", "expected_urls"),
    [
        ("version", [NPM_VERSION_URL]),
        ("package", [NPM_VERSION_URL, NPM_PACKAGE_URL]),
    ],
)
def test_registry_checks_keep_non_404_failures_unknown(
    monkeypatch,
    failure_point,
    expected_urls,
):
    seen_requests = []

    def fake_urlopen(request, *, timeout):
        seen_requests.append((request.full_url, request.get_method(), timeout))
        if request.full_url == NPM_VERSION_URL:
            if failure_point == "version":
                raise urllib.error.HTTPError(
                    NPM_VERSION_URL,
                    500,
                    "registry failure",
                    {},
                    None,
                )
            raise _not_found(NPM_VERSION_URL)
        if request.full_url == NPM_PACKAGE_URL:
            raise TimeoutError("registry timeout")
        raise AssertionError(f"unexpected registry URL: {request.full_url}")

    monkeypatch.setattr(manifest_rule.urllib.request, "urlopen", fake_urlopen)
    status = check_dependency_version_status(
        ECOSYSTEM_NPM,
        "react",
        "999999.0.0",
        {},
    )

    assert status == STATUS_UNKNOWN
    assert seen_requests == [(url, "HEAD", 5) for url in expected_urls]
