import json
from pathlib import Path
import threading
import time
from urllib.parse import urlsplit

import pytest

from skylos.rules.sca import osv_client as osv


def advisory(advisory_id="GHSA-test-1234-abcd", **extra):
    return {
        "id": advisory_id,
        "affected": [
            {
                "package": {"name": "example", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                    }
                ],
            }
        ],
        **extra,
    }


class Response:
    def __init__(self, data=None, *, body=None, status=200, headers=None, chunks=None):
        self.body = json.dumps(data).encode() if body is None else body
        self.status_code = status
        self.headers = headers or {}
        self.chunks = chunks
        self.closed = False
        self.iterated = False

    def iter_content(self, chunk_size):
        self.iterated = True
        if self.chunks is not None:
            yield from self.chunks
            return
        for index in range(0, len(self.body), chunk_size):
            yield self.body[index : index + chunk_size]

    def close(self):
        self.closed = True


class Client:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []
        self.lock = threading.Lock()

    def get(self, url, **kwargs):
        with self.lock:
            self.calls.append((url, kwargs))
        response = self.responses[url.rsplit("/", 1)[1]]
        if isinstance(response, Exception):
            raise response
        return response


def test_fetches_full_documents_once_and_only_fixed_origin():
    first, second = "GHSA-test-1234-abcd", "PYSEC-2020-123"
    client = Client(
        {
            first: Response(advisory(first, summary="Details")),
            second: Response(advisory(second)),
        }
    )
    result = osv.fetch_advisories([first, second, first], client)

    assert list(result.advisories) == [first, second]
    assert result.advisories[first]["summary"] == "Details"
    assert "severity" not in result.advisories[second]
    assert result.errors == {}
    assert result.receipt["complete"] is True
    assert result.receipt["requested_count"] == 2
    assert result.receipt["unique_id_count"] == 2
    assert result.receipt["successful_count"] == 2
    assert result.receipt["failed_count"] == 0
    assert result.receipt["skipped_count"] == 0
    assert len(client.calls) == 2
    assert {url for url, _kwargs in client.calls} == {
        f"https://api.osv.dev/v1/vulns/{first}",
        f"https://api.osv.dev/v1/vulns/{second}",
    }
    for url, kwargs in client.calls:
        assert kwargs == {
            "timeout": (5.0, 15.0),
            "stream": True,
            "allow_redirects": False,
        }
    assert all(response.closed for response in client.responses.values())


@pytest.mark.parametrize(
    "advisory_id",
    ["A", "0", "GHSA-test_1234.abcd", "CVE-2024-12345", "X" * 200],
)
def test_prepared_advisory_url_keeps_exact_fixed_origin_and_single_segment(advisory_id):
    from requests import Request

    client = Client({advisory_id: Response(advisory(advisory_id))})
    result = osv.fetch_advisories([advisory_id], client)

    assert result.receipt["complete"] is True
    assert len(client.calls) == 1
    url, options = client.calls[0]
    assert url == f"https://api.osv.dev/v1/vulns/{advisory_id}"
    prepared_url = Request("GET", url).prepare().url
    assert prepared_url == url
    parsed = urlsplit(prepared_url)
    assert parsed.scheme == "https"
    assert parsed.netloc == "api.osv.dev"
    assert parsed.path == f"/v1/vulns/{advisory_id}"
    assert parsed.query == parsed.fragment == ""
    assert parsed.username is parsed.password is parsed.port is None
    assert options["allow_redirects"] is False


def test_worker_revalidates_id_before_transport(monkeypatch):
    validation_results = iter([True, False])
    monkeypatch.setattr(
        osv, "is_valid_advisory_id", lambda value: next(validation_results)
    )
    client = Client({})
    advisory_id = "GHSA-test-1234-abcd"

    result = osv.fetch_advisories([advisory_id], client)

    assert result.errors == {advisory_id: "invalid_advisory_id"}
    assert result.receipt["requested_count"] == 0
    assert client.calls == []


def test_static_scanner_recognizes_actual_client_fixed_origin():
    from skylos.rules.danger.danger import scan_ctx

    source_path = Path(osv.__file__)
    findings = scan_ctx(source_path.parent, [source_path])
    assert not [finding for finding in findings if finding["rule_id"] == "SKY-D216"]


@pytest.mark.parametrize(
    "unsafe_id",
    [
        "",
        "../GHSA-example",
        "GHSA-example/path",
        "GHSA-example?query=value",
        "GHSA-example#fragment",
        "GHSA-%2f-example",
        "https://example.invalid/path",
        "GHSA-back\\slash",
        "GHSA-control\n",
        "//example.invalid/path",
        "GHSA-user@example.invalid",
        "GHSA:8443",
        "GHSA-%252f-example",
        "GHSA-carriage\rreturn",
        "GHSA-tab\t",
        "GHSA-null\0",
        ".",
        "..",
        "GHSA-non-ascii-\u00e9",
        "X" * 201,
        123,
        None,
    ],
)
def test_rejects_unsafe_or_unbounded_ids_without_transport(unsafe_id):
    client = Client({})
    result = osv.fetch_advisories([unsafe_id], client)
    assert result.advisories == {}
    assert result.errors == {unsafe_id: "invalid_advisory_id"}
    assert result.receipt["complete"] is False
    assert result.receipt["requested_count"] == 0
    assert result.receipt["skipped_count"] == 1
    assert client.calls == []


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308, 400, 404, 429, 500, 503])
def test_http_errors_and_redirects_are_explicit_failures(status):
    advisory_id = "GHSA-test-1234-abcd"
    response = Response(advisory(), status=status)
    client = Client({advisory_id: response})
    result = osv.fetch_advisories([advisory_id, advisory_id], client)
    assert result.errors == {advisory_id: f"http_{status}"}
    assert result.receipt["requested_count"] == 1
    assert result.receipt["failed_count"] == 1
    assert not response.iterated
    assert response.closed
    assert len(client.calls) == 1


@pytest.mark.parametrize(
    "location", ["https://example.invalid/advisory", "/other/path"]
)
def test_redirect_location_never_triggers_another_request(location):
    advisory_id = "GHSA-test-1234-abcd"
    response = Response(advisory(), status=302, headers={"Location": location})
    client = Client({advisory_id: response})

    result = osv.fetch_advisories([advisory_id], client)

    assert result.errors == {advisory_id: "http_302"}
    assert len(client.calls) == 1
    assert client.calls[0][0] == f"https://api.osv.dev/v1/vulns/{advisory_id}"
    assert client.calls[0][1]["allow_redirects"] is False
    assert not response.iterated
    assert response.closed


@pytest.mark.parametrize(
    "document",
    [
        None,
        [],
        {},
        advisory("WRONG-ID"),
        {"id": "GHSA-test-1234-abcd"},
        advisory(affected=None),
        advisory(affected={}),
        advisory(affected=[None]),
        advisory(affected=[{"package": "example"}]),
        advisory(affected=[{"package": {"name": 123}}]),
        advisory(affected=[{"versions": "1.0.0"}]),
        advisory(affected=[{"versions": [12]}]),
        advisory(affected=[{"ranges": {}}]),
        advisory(affected=[{"ranges": [None]}]),
        advisory(affected=[{"ranges": [{"events": []}]}]),
        advisory(affected=[{"ranges": [{"type": "SEMVER", "events": {}}]}]),
        advisory(affected=[{"ranges": [{"type": "SEMVER", "events": [{"fixed": 2}]}]}]),
        advisory(
            affected=[{"ranges": [{"type": "SEMVER", "events": [{"unknown": "2"}]}]}]
        ),
        advisory(
            affected=[
                {
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "0", "fixed": "2"}],
                        }
                    ]
                }
            ]
        ),
        advisory(summary=[]),
        advisory(aliases="CVE-1234-1234"),
        advisory(aliases=[False]),
    ],
)
def test_rejects_wrong_or_malformed_advisory_documents(document):
    advisory_id = "GHSA-test-1234-abcd"
    response = Response(document)
    result = osv.fetch_advisories([advisory_id], Client({advisory_id: response}))
    assert result.errors == {advisory_id: "invalid_advisory_document"}
    assert result.receipt["complete"] is False
    assert response.closed


def test_empty_affected_and_missing_optional_fields_are_valid():
    advisory_id = "GHSA-test-1234-abcd"
    document = advisory(affected=[], withdrawn="2024-01-01T00:00:00Z")
    result = osv.fetch_advisories(
        [advisory_id], Client({advisory_id: Response(document)})
    )
    assert result.advisories == {advisory_id: document}
    assert result.receipt["complete"] is True


@pytest.mark.parametrize("scope", ["top_level", "affected"])
@pytest.mark.parametrize(
    "fields",
    [
        {"severity": None},
        {"severity": {}},
        {"severity": "HIGH"},
        {"severity": [None]},
        {"severity": [{}]},
        {"severity": [{"type": "CVSS_V3"}]},
        {"severity": [{"type": "CVSS_V3", "score": None}]},
        {"severity": [{"type": "CVSS_V3", "score": 9.8}]},
        {"severity": [{"type": "CVSS_V3", "score": ""}]},
        {"severity": [{"type": None, "score": "9.8"}]},
        {"references": None},
        {"references": {}},
        {"references": [None]},
        {"references": [{}]},
        {"references": [{"type": "ADVISORY"}]},
        {"references": [{"type": "ADVISORY", "url": []}]},
        {"references": [{"type": None, "url": "https://example.com/advisory"}]},
        {"references": [{"type": "ADVISORY", "url": ""}]},
        {"database_specific": None},
        {"database_specific": []},
        {"database_specific": "HIGH"},
        {"ecosystem_specific": None},
        {"ecosystem_specific": []},
        {"ecosystem_specific": "HIGH"},
    ],
)
def test_malformed_optional_metadata_is_explicitly_incomplete(scope, fields):
    advisory_id = "GHSA-test-1234-abcd"
    document = advisory()
    target = document if scope == "top_level" else document["affected"][0]
    target.update(fields)
    response = Response(document)
    result = osv.fetch_advisories([advisory_id], Client({advisory_id: response}))
    assert result.advisories == {}
    assert result.errors == {advisory_id: "invalid_advisory_document"}
    assert result.receipt["complete"] is False
    assert result.receipt["failed_count"] == 1
    assert response.closed


@pytest.mark.parametrize("scope", ["top_level", "affected"])
@pytest.mark.parametrize(
    "fields",
    [
        {
            "severity": [],
            "references": [],
            "database_specific": {},
            "ecosystem_specific": {},
        },
        {
            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            "references": [{"type": "ADVISORY", "url": "https://example.com/advisory"}],
            "database_specific": {"cvss_score": 9.8},
            "ecosystem_specific": {"severity": "HIGH"},
        },
        {
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            ]
        },
    ],
)
def test_optional_metadata_valid_shapes_are_preserved(scope, fields):
    advisory_id = "GHSA-test-1234-abcd"
    document = advisory()
    target = document if scope == "top_level" else document["affected"][0]
    target.update(fields)
    result = osv.fetch_advisories(
        [advisory_id], Client({advisory_id: Response(document)})
    )
    assert result.advisories == {advisory_id: document}
    assert result.receipt["complete"] is True


@pytest.mark.parametrize(
    "body",
    [b"", b"{bad", b'{"id": "\xff"}', b'{"key":1,"key":2}', b'{"x":NaN}'],
)
def test_invalid_json_is_explicit_and_closed(body):
    response = Response(body=body)
    with pytest.raises(osv.OsvResponseError, match="invalid_json"):
        osv.read_json_response(response)
    assert response.closed


def test_response_stream_exception_closes_response():
    def broken_chunks():
        yield b"{"
        raise OSError("connection broken")

    response = Response(chunks=broken_chunks())
    with pytest.raises(OSError, match="connection broken"):
        osv.read_json_response(response)
    assert response.closed


def test_per_document_size_limit_uses_actual_decoded_stream():
    response = Response(headers={"Content-Length": "1"}, chunks=[b"123456", b"789012"])
    with pytest.raises(osv.OsvResponseError, match="response_size_limit"):
        osv.read_json_response(response, max_bytes=10)
    assert response.closed


def test_content_length_limit_is_checked_before_reading():
    response = Response({}, headers={"Content-Length": "100"})
    with pytest.raises(osv.OsvResponseError, match="response_size_limit"):
        osv.read_json_response(response, max_bytes=10)
    assert not response.iterated
    assert response.closed


@pytest.mark.parametrize("declared", ["-1", "not-a-number"])
def test_invalid_content_length_is_rejected(declared):
    response = Response({}, headers={"Content-Length": declared})
    with pytest.raises(osv.OsvResponseError, match="invalid_content_length"):
        osv.read_json_response(response)
    assert response.closed


def test_empty_chunks_are_allowed():
    response = Response(chunks=[b"", b'{"complete":', b"", b"true}"])
    assert osv.read_json_response(response) == {"complete": True}
    assert response.closed


def test_transport_failure_does_not_hide_other_advisories_or_leak_exception():
    first, second = "GHSA-first", "GHSA-second"
    client = Client(
        {
            first: RuntimeError("proxy://secret-password@host"),
            second: Response(advisory(second)),
        }
    )
    result = osv.fetch_advisories([first, second, first], client)
    assert result.errors == {first: "advisory_transport_error"}
    assert list(result.advisories) == [second]
    assert result.receipt["requested_count"] == 2
    assert result.receipt["successful_count"] == 1
    assert result.receipt["failed_count"] == 1
    assert result.receipt["complete"] is False
    assert "secret-password" not in json.dumps(result.receipt)
    assert "secret-password" not in json.dumps(result.errors)


def test_advisory_limit_does_not_launch_excess_requests(monkeypatch):
    monkeypatch.setattr(osv, "MAX_ADVISORIES", 2)
    ids = ["GHSA-first", "GHSA-second", "GHSA-third"]
    client = Client({key: Response(advisory(key)) for key in ids})
    result = osv.fetch_advisories(ids + ids, client)
    assert list(result.advisories) == ids[:2]
    assert result.errors == {ids[2]: "advisory_count_limit"}
    assert result.receipt["requested_count"] == 2
    assert result.receipt["skipped_count"] == 1
    assert len(client.calls) == 2


def test_total_response_budget_stops_new_requests(monkeypatch):
    monkeypatch.setattr(osv, "MAX_TOTAL_ADVISORY_BYTES", 20)
    monkeypatch.setattr(osv, "MAX_WORKERS", 1)
    ids = ["GHSA-first", "GHSA-second", "GHSA-third"]
    client = Client({key: Response(advisory(key)) for key in ids})
    result = osv.fetch_advisories(ids, client)
    assert result.advisories == {}
    assert result.errors == {key: "total_response_size_limit" for key in ids}
    assert result.receipt["requested_count"] == 1
    assert result.receipt["skipped_count"] == 2
    assert result.receipt["total_size_exceeded"] is True
    assert result.receipt["accepted_response_bytes"] <= 20
    assert len(client.calls) == 1
    assert client.responses[ids[0]].closed


def test_deadline_before_work_skips_all_requests(monkeypatch):
    monkeypatch.setattr(osv, "DETAIL_DEADLINE_SECONDS", 0)
    result = osv.fetch_advisories(["GHSA-first", "GHSA-second"], Client({}))
    assert result.receipt["complete"] is False
    assert result.receipt["deadline_exceeded"] is True
    assert result.receipt["requested_count"] == 0
    assert result.receipt["skipped_count"] == 2
    assert set(result.errors.values()) == {"detail_deadline_exceeded"}


def test_deadline_during_stream_closes_response(monkeypatch):
    clock = [0]
    monkeypatch.setattr(osv.time, "monotonic", lambda: clock[0])

    def slow_chunks():
        yield b"{"
        clock[0] = 20
        yield b"}"

    response = Response(chunks=slow_chunks())
    with pytest.raises(osv.OsvResponseError, match="detail_deadline_exceeded"):
        osv.read_json_response(response, deadline=10)
    assert response.closed


def test_deadline_does_not_wait_for_blocked_transport_or_start_queued_ids(monkeypatch):
    monkeypatch.setattr(osv, "MAX_WORKERS", 1)
    monkeypatch.setattr(osv, "DETAIL_DEADLINE_SECONDS", 0.05)
    release = threading.Event()
    finished = threading.Event()
    response = Response(advisory("GHSA-first"))

    class BlockedClient:
        def __init__(self):
            self.calls = []

        def get(self, url, **kwargs):
            self.calls.append((url, kwargs))
            assert release.wait(timeout=2)
            finished.set()
            return response

    client = BlockedClient()
    start = time.monotonic()
    try:
        result = osv.fetch_advisories(["GHSA-first", "GHSA-second"], client)
        assert time.monotonic() - start < 1
        assert result.receipt["deadline_exceeded"] is True
        assert result.receipt["requested_count"] == 1
        assert result.receipt["skipped_count"] == 1
        assert result.errors == {
            "GHSA-first": "detail_deadline_exceeded",
            "GHSA-second": "detail_deadline_exceeded",
        }
        assert len(client.calls) == 1
        assert client.calls[0][1]["timeout"][1] <= 0.05
    finally:
        release.set()
        assert finished.wait(timeout=2)


def test_fetch_concurrency_is_bounded(monkeypatch):
    monkeypatch.setattr(osv, "MAX_WORKERS", 4)
    ids = [f"GHSA-{index}" for index in range(12)]
    barrier = threading.Barrier(4)
    lock = threading.Lock()
    active = 0
    high_water = 0

    class ConcurrentClient:
        def get(self, url, **_kwargs):
            nonlocal active, high_water
            with lock:
                active += 1
                high_water = max(high_water, active)
            try:
                barrier.wait(timeout=2)
                return Response(advisory(url.rsplit("/", 1)[1]))
            finally:
                with lock:
                    active -= 1

    result = osv.fetch_advisories(ids, ConcurrentClient())
    assert result.receipt["complete"] is True
    assert list(result.advisories) == ids
    assert high_water == 4


def test_cache_is_scan_local_not_persistent():
    advisory_id = "GHSA-first"
    client = Client({advisory_id: Response(advisory(advisory_id))})
    assert osv.fetch_advisories([advisory_id], client).receipt["complete"] is True
    assert osv.fetch_advisories([advisory_id], client).receipt["complete"] is True
    assert len(client.calls) == 2


def test_empty_inventory_is_complete_without_requests():
    client = Client({})
    result = osv.fetch_advisories([], client)
    assert result.advisories == {}
    assert result.errors == {}
    assert result.receipt["complete"] is True
    assert result.receipt["requested_count"] == 0
    assert result.receipt["unique_id_count"] == 0
    assert client.calls == []
