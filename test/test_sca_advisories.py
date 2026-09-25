"""Batch matches survive full-advisory enrichment and partial failures."""

import json
from urllib.parse import urlsplit

import pytest

from skylos.rules.sca import vulnerability_scanner as sca


class Response:
    headers = {}

    def __init__(self, payload, status=200):
        self.payload = payload
        self.status_code = status
        self.closed = False

    def iter_content(self, chunk_size):
        yield json.dumps(self.payload).encode("utf-8")

    def close(self):
        self.closed = True


def dependency(version="1.0.0", name="example"):
    return {
        "name": name,
        "version": version,
        "ecosystem": "npm",
        "file": "/fixture/package-lock.json",
        "line": 7,
    }


def advisory(advisory_id="GHSA-test-one", name="example"):
    return {
        "id": advisory_id,
        "summary": "Example dependency advisory",
        "aliases": ["CVE-2026-00001"],
        "database_specific": {"severity": "HIGH"},
        "references": [
            {"type": "ADVISORY", "url": "https://osv.dev/vulnerability/" + advisory_id}
        ],
        "affected": [
            {
                "package": {"name": name, "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "3.0.0"}],
                    }
                ],
            }
        ],
    }


class Transport:
    def __init__(self, results, documents=None):
        self.results = results
        self.documents = documents or {"GHSA-test-one": advisory()}
        self.posts = []
        self.gets = []
        self.responses = []

    def post(self, url, **kwargs):
        assert url == sca.OSV_BATCH_URL
        assert kwargs["stream"] is True
        assert kwargs["allow_redirects"] is False
        self.posts.append(kwargs["json"])
        response = Response({"results": self.results})
        self.responses.append(response)
        return response

    def get(self, url, **kwargs):
        assert url.startswith("https://api.osv.dev/v1/vulns/")
        assert kwargs["stream"] is True
        assert kwargs["allow_redirects"] is False
        advisory_id = urlsplit(url).path.rsplit("/", 1)[-1]
        self.gets.append(advisory_id)
        document = self.documents.get(advisory_id)
        if isinstance(document, Exception):
            raise document
        response = Response(document, status=404 if document is None else 200)
        self.responses.append(response)
        return response


def scan(monkeypatch, transport, dependencies=None):
    monkeypatch.setattr(sca, "_requests", transport)
    return sca._query_osv_batch(dependencies or [dependency()], {})


def test_id_only_batch_is_enriched_with_severity_and_matching_fix(monkeypatch):
    transport = Transport([{"vulns": [{"id": "GHSA-test-one"}]}])
    result = scan(monkeypatch, transport)
    assert result.receipt["complete"] is True
    assert transport.gets == ["GHSA-test-one"]
    assert result[0]["severity"] == "HIGH"
    assert "Upgrade to 3.0.0" in result[0]["message"]
    assert result[0]["metadata"]["aliases"] == ["CVE-2026-00001"]
    assert result[0]["metadata"]["advisory_status"] == "complete"
    assert result[0]["metadata"]["cvss_score"] is None  # label is not a numeric score
    assert all(response.closed for response in transport.responses)


def test_nuget_advisory_matches_package_id_case_insensitively(monkeypatch):
    nuget_dependency = {
        "name": "Newtonsoft.Json",
        "version": "13.0.1",
        "ecosystem": "NuGet",
        "file": "/fixture/App.csproj",
        "line": 1,
        "exact": True,
    }
    document = {
        "id": "GHSA-test-one",
        "summary": "NuGet dependency advisory",
        "affected": [
            {
                "package": {"name": "newtonsoft.json", "ecosystem": "NuGet"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "13.0.2"}],
                    }
                ],
            }
        ],
    }
    transport = Transport(
        [{"vulns": [{"id": "GHSA-test-one"}]}],
        {"GHSA-test-one": document},
    )

    result = scan(monkeypatch, transport, [nuget_dependency])

    assert transport.posts[0]["queries"] == [
        {
            "package": {"name": "Newtonsoft.Json", "ecosystem": "NuGet"},
            "version": "13.0.1",
        }
    ]
    assert result.receipt["complete"] is True
    assert result[0]["metadata"]["advisory_status"] == "complete"
    assert result[0]["metadata"]["fixed_version"] == "13.0.2"


def test_advisory_fetch_deduplicates_across_versions_and_batches(monkeypatch):
    monkeypatch.setattr(sca, "OSV_BATCH_LIMIT", 1)
    transport = Transport(
        [{"vulns": [{"id": "GHSA-test-one"}, {"id": "GHSA-test-one"}]}]
    )
    result = scan(monkeypatch, transport, [dependency("1.0.0"), dependency("2.0.0")])
    assert len(result) == 2
    assert len(transport.posts) == 2
    assert transport.gets == ["GHSA-test-one"]
    assert {f["metadata"]["package_version"] for f in result} == {"1.0.0", "2.0.0"}
    assert result.receipt["advisory_details"]["requested_count"] == 1


@pytest.mark.parametrize("missing", [None, ConnectionError("offline")])
def test_failed_detail_keeps_match_and_makes_scan_incomplete(monkeypatch, missing):
    transport = Transport(
        [{"vulns": [{"id": "GHSA-test-one"}, {"id": "GHSA-test-two"}]}],
        {"GHSA-test-one": advisory(), "GHSA-test-two": missing},
    )
    result = scan(monkeypatch, transport)
    assert len(result) == 2
    assert result.receipt["complete"] is False
    assert result.receipt["failed_batches"] == 0
    assert result.receipt["advisory_details"]["failed_count"] == 1
    assert result[0]["metadata"]["advisory_status"] == "complete"
    assert result[1]["rule_id"] == "SKY-SCA-GHSA-test-two"
    assert result[1]["metadata"]["advisory_status"] == "unavailable"
    assert result[1]["metadata"]["fixed_version"] is None
    assert result[1]["severity"] == "UNKNOWN"


def test_advisory_for_other_package_does_not_supply_fix_or_severity(monkeypatch):
    transport = Transport(
        [{"vulns": [{"id": "GHSA-test-one"}]}],
        {"GHSA-test-one": advisory(name="different-package")},
    )
    result = scan(monkeypatch, transport)
    assert len(result) == 1
    assert result[0]["metadata"]["advisory_error"] == "package_mismatch"
    assert result[0]["metadata"]["fixed_version"] is None
    assert result[0]["severity"] == "UNKNOWN"
    assert result.receipt["advisory_context_error_count"] == 1
    assert result.receipt["complete"] is False


def test_absent_optional_advisory_details_do_not_fabricate_enrichment(monkeypatch):
    minimal = {
        "id": "GHSA-test-one",
        "affected": [{"package": {"name": "example", "ecosystem": "npm"}}],
    }
    transport = Transport(
        [{"vulns": [{"id": "GHSA-test-one"}]}], {"GHSA-test-one": minimal}
    )
    result = scan(monkeypatch, transport)
    assert result.receipt["complete"] is True
    assert result[0]["metadata"]["advisory_status"] == "complete"
    assert result[0]["severity"] == "UNKNOWN"
    assert result[0]["metadata"]["fixed_version"] is None


def test_withdrawn_detail_remains_explicit_instead_of_silently_erasing_match(
    monkeypatch,
):
    document = advisory()
    document["withdrawn"] = "2026-09-14T00:00:00Z"
    transport = Transport(
        [{"vulns": [{"id": "GHSA-test-one"}]}], {"GHSA-test-one": document}
    )
    result = scan(monkeypatch, transport)
    assert len(result) == 1
    assert result[0]["metadata"]["withdrawn"] == document["withdrawn"]


def test_no_matches_does_not_fetch_advisories(monkeypatch):
    transport = Transport([{}])
    result = scan(monkeypatch, transport)
    assert result == []
    assert transport.gets == []
    assert result.receipt["complete"] is True
    assert result.receipt["advisory_details"]["requested_count"] == 0


@pytest.mark.parametrize(
    "result_item",
    [None, {"vulns": None}, {"vulns": {}}, {"vulns": [None]}, {"vulns": [{"id": ""}]}],
)
def test_malformed_batch_result_cannot_look_clean(monkeypatch, result_item):
    result = scan(monkeypatch, Transport([result_item]))
    assert result.receipt["complete"] is False
    assert result.receipt["failed_batches"] == 1


def test_partial_batch_count_preserves_known_matches(monkeypatch):
    transport = Transport([{"vulns": [{"id": "GHSA-test-one"}]}])
    result = scan(monkeypatch, transport, [dependency(), dependency("2.0.0")])
    assert len(result) == 1
    assert result.receipt["complete"] is False
    assert result.receipt["failed_batches"] == 1


def test_unread_pagination_is_explicit_not_a_complete_inventory(monkeypatch):
    transport = Transport(
        [{"vulns": [{"id": "GHSA-test-one"}], "next_page_token": "next-page"}]
    )
    result = scan(monkeypatch, transport)
    assert len(result) == 1
    assert result.receipt["complete"] is False
    assert result.receipt["limit_reasons"] == ["query_pagination_not_completed"]


def test_match_count_limit_is_explicit(monkeypatch):
    monkeypatch.setattr(sca, "MAX_OSV_MATCHES", 1)
    transport = Transport(
        [{"vulns": [{"id": "GHSA-test-one"}, {"id": "GHSA-test-two"}]}]
    )
    result = scan(monkeypatch, transport)
    assert len(result) == 1
    assert transport.gets == ["GHSA-test-one"]
    assert result.receipt["complete"] is False
    assert result.receipt["limit_reasons"] == ["advisory_match_limit_exceeded"]
