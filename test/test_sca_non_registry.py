"""Valid non-registry UV sources are coverage gaps, not inventory failures."""

import json
from pathlib import Path

import pytest

from skylos.core.gatekeeper import check_gate
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.core.sca_coverage import valid_non_registry_sca_receipt
from skylos.rules.sca import vulnerability_scanner as sca
from skylos.rules.sca.uv_lockfile import parse_uv_lock
from test import test_sca_lockfiles

# Reuse the same offline transport as the existing lockfile integration suite.
osv = test_sca_lockfiles.osv

_COMMIT = "a" * 40
_SOURCES = [
    f'git = "https://example.test/private.git#{_COMMIT}"',
    f'git = "ssh://git@example.test/private.git#{_COMMIT}"',
    'url = "https://example.test/private.whl"',
    'url = "https://example.test/private.tar.gz", subdirectory = "packages/private"',
    'path = "../vendor/private.whl"',
    'registry = "https://private.example/simple"',
    'registry = "https://user:secret@private.example/simple?token=secret"',
    'registry = "../vendor/index"',
    'registry = "C:/vendor/index"',
]


def _project(root, source, *, public_version="1.2.3", count=1):
    text = (
        'version = 1\n[[package]]\nname = "local-app"\nversion = "0.1.0"\n'
        'source = { virtual = "." }\n'
        'dependencies = [{ name = "example" }, { name = "private-pkg" }]\n'
        '[[package]]\nname = "example"\n'
        f'version = "{public_version}"\nsource = {{ registry = "https://pypi.org/simple" }}\n'
    )
    for index in range(count):
        name = "private-pkg" if index == 0 else f"private-pkg-{index}"
        text += (
            f'[[package]]\nname = "{name}"\nversion = "1.0"\nsource = {{ {source} }}\n'
        )
    assert write_text_no_symlink(root / "uv.lock", text)
    return text


@pytest.mark.parametrize("source", _SOURCES)
@pytest.mark.parametrize("vulnerable", [False, True])
def test_valid_non_registry_sources_preserve_public_queries_and_cve_gate(
    tmp_path, osv, source, vulnerable
):
    _project(tmp_path, source)
    assert write_text_no_symlink(tmp_path / "requirements.txt", "private-pkg==1.0\n")
    osv.vulnerable = vulnerable
    result = sca.scan_dependencies(tmp_path)
    receipt = result.receipt
    assert receipt["status"] == "complete_with_non_registry_sources"
    assert receipt["complete"] is False
    assert receipt["category_complete"] is False
    assert receipt["parse_error_count"] == 0
    assert receipt["unresolved_lockfile_dependency_count"] == 0
    assert receipt["non_registry_lockfile_dependency_count"] == 1
    assert receipt["not_checked_lockfile_dependency_count"] == 1
    assert receipt["manifest_source_conflict_count"] == 1
    assert receipt["query"]["complete"] is True
    assert osv.queries == [
        {
            "package": {"name": "example", "ecosystem": "PyPI"},
            "version": "1.2.3",
        }
    ]
    assert len(receipt["lockfile_not_checked"]) == 1
    entry = receipt["lockfile_not_checked"][0]
    assert entry["name"] == "private-pkg"
    assert entry["source_type"] in {"git", "url", "path", "registry"}
    assert entry["reason"] in {"non_registry_source", "non_public_registry"}
    assert entry["file"] == str(tmp_path / "uv.lock")
    assert entry["line"] > 1
    assert "non_registry_lockfile_sources_not_checked" in receipt["limitations"]
    assert "local_lockfile_packages_not_checked" not in receipt["limitations"]
    assert "secret" not in json.dumps(receipt)
    assert "private.example" not in json.dumps(receipt)
    report = {
        "dependency_vulnerabilities": list(result),
        "analysis_summary": {"sca_coverage": receipt},
    }
    passed, reasons = check_gate(
        report, {"gate": {"max_dependency_vulnerabilities": 0}}
    )
    assert passed is not vulnerable
    assert any("dependency" in reason.lower() for reason in reasons) is vulnerable
    assert all(finding["metadata"]["package_name"] == "example" for finding in result)


@pytest.mark.parametrize(
    "source",
    [
        "git = 123",
        'git = "not a URL"',
        'git = "https://example.test/private.git"',
        'git = "https://example.test/private.git#invalid"',
        'url = "https:///private.whl"',
        'url = "https://example.test:invalid/private.whl"',
        'url = "https://example.test/private.whl", subdirectory = 123',
        'url = "https://example.test/private.whl", unknown = "value"',
        'path = ""',
        'registry = "https://"',
        'registry = "https://pypi.org/simple", git = "other"',
        'unknown = "https://example.test/private.whl"',
    ],
)
def test_malformed_or_unknown_sources_remain_operational_failure(tmp_path, osv, source):
    _project(tmp_path, source)
    result = sca.scan_dependencies(tmp_path)
    receipt = result.receipt
    assert receipt["status"] == "incomplete"
    assert receipt["complete"] is False
    assert receipt["query"]["complete"] is True
    assert receipt["unresolved_lockfile_dependency_count"] == 1
    assert receipt["non_registry_lockfile_dependency_count"] == 0
    assert receipt["not_checked_lockfile_dependency_count"] == 0
    assert receipt["lockfile_issues"][0]["reason"] in {
        "invalid_package_source",
        "unsupported_package_source",
    }
    assert len(result) == 1
    assert result[0]["metadata"]["package_name"] == "example"


def test_non_registry_source_does_not_waive_bad_public_version(tmp_path, osv):
    _project(tmp_path, _SOURCES[0], public_version=">=1.0")
    result = sca.scan_dependencies(tmp_path)
    assert result.receipt["status"] == "incomplete"
    assert result.receipt["non_registry_lockfile_dependency_count"] == 1
    assert result.receipt["unresolved_lockfile_dependency_count"] == 1
    assert result.receipt["lockfile_issues"][0]["reason"] == "invalid_locked_version"
    assert osv.queries == []


def test_non_registry_source_does_not_waive_osv_failure(tmp_path, osv):
    _project(tmp_path, _SOURCES[0])
    osv.fail = True
    result = sca.scan_dependencies(tmp_path)
    assert result.receipt["status"] == "incomplete"
    assert result.receipt["complete"] is False
    assert result.receipt["non_registry_lockfile_dependency_count"] == 1
    assert result.receipt["query"]["complete"] is False
    assert result.receipt["query"]["failed_batches"] == 1


@pytest.mark.parametrize("failure", ["advisory-details", "pagination"])
def test_non_registry_coverage_keeps_known_cve_when_query_is_incomplete(
    tmp_path, osv, monkeypatch, failure
):
    _project(tmp_path, _SOURCES[0])
    if failure == "advisory-details":

        def unavailable(*_args, **_kwargs):
            raise ConnectionError("local advisory fixture unavailable")

        monkeypatch.setattr(osv, "get", unavailable)
    else:
        original_post = osv.post

        def paginated(*args, **kwargs):
            response = original_post(*args, **kwargs)
            response.payload["results"][0]["next_page_token"] = "more"
            return response

        monkeypatch.setattr(osv, "post", paginated)
    result = sca.scan_dependencies(tmp_path)
    assert result.receipt["status"] == "incomplete"
    assert result.receipt["complete"] is False
    assert result.receipt["query"]["complete"] is False
    assert result.receipt["non_registry_lockfile_dependency_count"] == 1
    assert len(result) == 1
    assert result[0]["metadata"]["package_name"] == "example"
    assert result[0]["metadata"]["vuln_id"] == "GHSA-test-lockfile"
    if failure == "pagination":
        assert result.receipt["query"]["limit_reasons"] == [
            "query_pagination_not_completed"
        ]
    else:
        assert result[0]["metadata"]["advisory_status"] == "unavailable"


def test_non_registry_receipt_count_survives_example_truncation(tmp_path, osv):
    _project(tmp_path, _SOURCES[0], count=30)
    result = sca.scan_dependencies(tmp_path)
    assert result.receipt["status"] == "complete_with_non_registry_sources"
    assert result.receipt["non_registry_lockfile_dependency_count"] == 30
    assert result.receipt["not_checked_lockfile_dependency_count"] == 30
    assert len(result.receipt["lockfile_not_checked"]) == 25
    assert result.receipt["unresolved_lockfile_dependency_count"] == 0


def test_uv_non_registry_sample_survives_earlier_local_example_truncation(
    tmp_path, osv
):
    _project(tmp_path, _SOURCES[0])
    local = {
        f"local-{index}": {
            "specifier": f"link:./packages/local-{index}",
            "version": f"link:./packages/local-{index}",
        }
        for index in range(30)
    }
    assert write_text_no_symlink(
        tmp_path / "pnpm-lock.yaml",
        json.dumps(
            {
                "lockfileVersion": "9.0",
                "importers": {".": {"dependencies": local}},
                "packages": {},
                "snapshots": {},
            }
        ),
    )
    result = sca.scan_dependencies(tmp_path)
    receipt = result.receipt
    assert receipt["status"] == "complete_with_non_registry_sources"
    assert receipt["non_registry_lockfile_dependency_count"] == 1
    assert receipt["not_checked_lockfile_dependency_count"] == 31
    assert len(receipt["lockfile_not_checked"]) == 25
    assert (
        sum(
            entry["reason"] == "non_registry_source"
            for entry in receipt["lockfile_not_checked"]
        )
        == 1
    )
    assert receipt["lockfile_not_checked"][-1]["name"] == "private-pkg"
    assert valid_non_registry_sca_receipt(receipt) is True


def test_non_registry_source_does_not_waive_inventory_limit(tmp_path, osv, monkeypatch):
    _project(tmp_path, _SOURCES[0])
    monkeypatch.setattr(sca, "MAX_UNIQUE_DEPENDENCIES", 2)
    result = sca.scan_dependencies(tmp_path)
    assert result.receipt["status"] == "incomplete"
    assert result.receipt["complete"] is False
    assert result.receipt["limit_reasons"] == ["dependency_limit_exceeded"]
    assert osv.queries == []


def test_url_subdirectory_metadata_is_preserved_as_skipped_source_data():
    text = (
        'version = 1\n[[package]]\nname = "private-pkg"\nversion = "1.0"\n'
        'source = { url = "https://example.test/private.tar.gz", subdirectory = "packages/private" }\n'
    )
    inventory = parse_uv_lock(Path("uv.lock"), text=text)
    assert inventory.unresolved == []
    assert inventory.not_checked[0]["source_type"] == "url"
