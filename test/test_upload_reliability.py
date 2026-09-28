"""Report uploads: contract pre-flight, retries, idempotency, saved uploads.

Everything here runs against mocks or a local HTTP server on 127.0.0.1; no
test talks to Skylos Cloud. ``conftest.py`` points saved uploads at a temp
folder and turns retry sleeps and the contract-version check off.
"""

from __future__ import annotations

import email.utils
import gzip
import json
import os
import stat
import subprocess
import sys
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from uuid import UUID

import pytest
import requests

import skylos.api as api
from skylos.api import _contract_check, _pending_uploads, _upload_transport
from skylos.api._upload_contract import (
    CONTRACT_PATH,
    contract_sha256,
    contract_version,
    retryable_statuses,
)
from skylos.api._upload_paths import (
    REASON_CONTROL_CHARACTER,
    REASON_DOT_SEGMENT,
    REASON_EMPTY,
    REASON_EMPTY_SEGMENT,
    REASON_MISSING,
    REASON_NOT_STRING,
    REASON_PLACEHOLDER,
    REASON_TOO_LONG,
    file_path_problem,
    normalize_contract_file_path,
)
from skylos.api._upload_preflight import apply_upload_contract
from skylos.api._upload_transport import (
    RetryPolicy,
    UploadFailure,
    backoff_delay,
    clean_text,
    describe_http_failure,
    parse_retry_after,
)

TOKEN = "skylos_test_token_do_not_store"


class Resp:
    def __init__(self, status, body=None, headers=None, text=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self.text = text if text is not None else (json.dumps(body) if body else "")

    def json(self):
        if self._body is None:
            raise ValueError("no JSON")
        return self._body


def _ok(scan_id="scan-1", **extra):
    return Resp(200, {"scanId": scan_id, "quality_gate": {"passed": True}, **extra})


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("def main():\n    return 1\n")
    monkeypatch.setattr(api, "get_project_token", lambda: TOKEN)
    monkeypatch.setattr(api, "get_git_root", lambda: str(root))
    monkeypatch.setattr(api, "get_git_info", lambda: ("0" * 40, "main", "tester", None))
    monkeypatch.setattr(api, "detect_ai_code", lambda *a, **k: {"detected": False})
    monkeypatch.setattr(api, "get_project_info", lambda token: None)
    monkeypatch.setenv("SKYLOS_PENDING_UPLOAD_DIR", str(tmp_path / "pending"))
    return root


def _result(root, **sections):
    result = {"provenance": None, "project_root": "", **sections}
    result.setdefault("analysis_summary", {})["project_root"] = ""
    return result


def _quality(root, rel="src/app.py", line=1, **extra):
    return {
        "rule_id": "SKY-Q301",
        "file": str(root / rel),
        "line": line,
        "severity": "MEDIUM",
        "message": "Too complex.",
        **extra,
    }


def _pending_files(tmp_path):
    # <queue root>/<repo-id>/<key>.json.gz; failed/ is one level deeper.
    return sorted((tmp_path / "pending").glob("*/*.json.gz"))


def _queue(repo):
    """This repository's folder in the (temporary) per-user queue."""
    return _pending_uploads.pending_uploads_dir(repo)


def _read_pending(path):
    """The record JSON of a saved upload (after its signature line)."""
    data = gzip.decompress(
        Path(path).read_bytes()  # skylos: ignore[SKY-D215] saved pytest queue fixture
    )
    header, _, body = data.partition(b"\n")
    assert header.startswith(b"SKYLOS-PENDING-UPLOAD 3 ")
    return json.loads(body)


class _Calls:
    """Scripted ``requests.post`` replacement that records every call."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append(SimpleNamespace(url=url, **kwargs))
        item = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(item, BaseException):
            raise item
        return item

    @property
    def keys(self):
        return [c.headers.get("Idempotency-Key") for c in self.calls]


# --------------------------------------------------------------------------
# Contract file
# --------------------------------------------------------------------------


def test_vendored_contract_is_v1_and_has_the_transport_rules():
    data = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    assert data["contract"] == "skylos-report-upload"
    assert contract_version() == 1
    assert retryable_statuses() == frozenset({408, 425, 429, 500, 502, 503, 504})
    assert len(contract_sha256()) == 64


def test_vendored_contract_matches_the_cloud_copy_when_present():
    cloud = os.getenv("SKYLOS_CLOUD_CONTRACT_PATH") or str(
        Path(__file__).resolve().parents[2]
        / "skylos-cloud"
        / "skylos-cloud"
        / "contracts"
        / "upload"
        / "v1.json"
    )
    if not Path(cloud).is_file():
        pytest.skip("Skylos Cloud checkout not available")
    assert Path(cloud).read_bytes() == CONTRACT_PATH.read_bytes()


def test_contract_ships_as_package_data():
    pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    assert '"skylos.api" = ["upload_contract/*.json"]' in pyproject


# --------------------------------------------------------------------------
# Pre-flight normalization
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("src/a.py", None),
        ("src//a.py", None),
        ("C:\\repo\\a.py", None),
        ("file:///srv/a.py", None),
        ("home/runner/work/org/repo/src/a.py", None),
        ("/__w/org/repo/src/a.py", None),
        ("src/a%20b.py", None),
        ("../outside.py", REASON_DOT_SEGMENT),
        ("%2E%2E/outside.py", REASON_DOT_SEGMENT),
        ("src/./a.py", REASON_DOT_SEGMENT),
        (".", REASON_DOT_SEGMENT),
        ("src/", REASON_EMPTY_SEGMENT),
        ("", REASON_MISSING),
        (None, REASON_MISSING),
        ("   ", REASON_EMPTY),
        ("src/a\x07.py", REASON_CONTROL_CHARACTER),
        ("src/a%07.py", REASON_CONTROL_CHARACTER),
        (42, REASON_NOT_STRING),
        ("a/" + "b" * 600, REASON_TOO_LONG),
        ("unknown", REASON_PLACEHOLDER),
        ("<UNKNOWN>", REASON_PLACEHOLDER),
        (" None ", REASON_PLACEHOLDER),
        ("?", REASON_PLACEHOLDER),
        ("-", REASON_PLACEHOLDER),
        ("undefined", REASON_PLACEHOLDER),
    ],
)
def test_file_path_problem_follows_contract(value, reason):
    assert file_path_problem(value) == reason


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("  src/a.py  ", "src/a.py"),
        ("src\\pkg\\a.py", "src/pkg/a.py"),
        ("file:///home/x/a.py", "home/x/a.py"),
        ("C:/work/a.py", "work/a.py"),
        ("//src///a.py", "src/a.py"),
        ("src/a%20b.py", "src/a b.py"),
        ("src/100%.py", "src/100%.py"),  # not valid percent-encoding: unchanged
        ("src/%E9.py", "src/%E9.py"),  # not UTF-8: unchanged
        ("src/caf%C3%A9.py", "src/caf\u00e9.py"),
        ("src/a%2520b.py", "src/a%20b.py"),  # decoded once only
        ("/home/runner/work/org/repo/src/a.py", "src/a.py"),
        ("__w/org/repo/src/a.py", "src/a.py"),
        ("github/workspace/src/a.py", "src/a.py"),
        ("github/workspace/github/workspace/a.py", "github/workspace/a.py"),
    ],
)
def test_normalize_contract_file_path_steps(raw, normalized):
    assert normalize_contract_file_path(raw) == normalized


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        (" \t\r\n\x0b\x0csrc/a.py \t", "src/a.py"),
        # Not ASCII whitespace: kept, as the contract says (Python's strip()
        # would have removed them).
        ("\x85src/a.py", "\x85src/a.py"),
        ("\u00a0src/a.py", "\u00a0src/a.py"),
        ("src/a.py\u3000", "src/a.py\u3000"),
    ],
)
def test_only_ascii_whitespace_is_trimmed_from_paths(raw, normalized):
    assert normalize_contract_file_path(raw) == normalized


def test_control_characters_at_the_edges_are_not_trimmed_away():
    # U+001C-U+001F would vanish with str.strip(); the contract keeps them,
    # so the path is a control-character path with no location.
    assert file_path_problem("\x1csrc/a.py") == REASON_CONTROL_CHARACTER
    findings = [{"rule_id": "A", "file_path": "\x1fsrc/a.py", "line_number": 1}]
    assert apply_upload_contract(findings, "").no_location == 1
    assert findings[0]["file_path"] == ""


def test_path_length_is_counted_in_code_points():
    emoji = "\U0001f600"
    assert file_path_problem("a/" + emoji * 498) is None  # 500 code points
    assert file_path_problem("a/" + emoji * 499) == REASON_TOO_LONG


def test_rule_id_trim_matches_the_server_check():
    from skylos.api._upload_preflight import _normalize_rule_id

    assert _normalize_rule_id("\u00a0SKY-A\ufeff", 120) == "SKY-A"
    assert _normalize_rule_id("SKY-B\x85", 120) == "SKY-B\x85"  # not JS whitespace
    assert _normalize_rule_id("\x1cSKY-C", 120) == "SKY-C"  # control character removed
    assert _normalize_rule_id("\U0001f600" * 130, 120) == "\U0001f600" * 120


@pytest.mark.parametrize(
    ("value", "line"),
    [
        (7, 7),
        ("12", 12),
        ("007", 7),
        (" 12", 0),
        ("+1", 0),
        ("1_000", 0),
        ("\u0661", 0),
        (True, 0),
        (-3, 0),
        (None, 0),
    ],
)
def test_line_number_accepts_integers_and_digit_strings_only(value, line):
    from skylos.api._upload_preflight import _normalize_line

    assert _normalize_line(value) == line


def test_repository_scope_findings_go_to_the_project_root_on_line_one():
    findings = [
        {
            "rule_id": "SKY-R104",
            "kind": "repo_policy",
            "file_path": ".",
            "file": "/abs/repo",
            "line_number": 1,
        },
        {
            "rule_id": "SKY-R101",
            "kind": "repo_policy",
            "file_path": "apps/web/pyproject.toml",
            "line_number": 3,
            "snippet": "[project]",
        },
    ]
    preflight = apply_upload_contract(findings, "apps/web")
    assert [f["file_path"] for f in findings] == ["apps/web", "apps/web"]
    assert [f["line_number"] for f in findings] == [1, 1]
    assert "snippet" not in findings[1]
    assert findings[0]["file"] == "apps/web"  # no absolute path is uploaded
    assert preflight.repository_scoped == 2
    assert preflight.no_location == 0


def test_repository_scope_at_repo_root_is_dot():
    findings = [
        {
            "rule_id": "SKY-R104",
            "kind": "repo_policy",
            "file_path": ".",
            "line_number": 1,
        }
    ]
    apply_upload_contract(findings, "")
    assert findings[0]["file_path"] == "."


def test_only_contract_rules_with_repo_policy_kind_are_repository_scoped():
    findings = [
        {"rule_id": "SKY-R104", "file_path": ".", "line_number": 1},
        {
            "rule_id": "SKY-R105",
            "kind": "repo_policy",
            "file_path": "web/package.json",
            "line_number": 4,
        },
    ]
    preflight = apply_upload_contract(findings, "")
    # R104 without the repo_policy kind has no file location: sent empty.
    assert findings[0]["file_path"] == ""
    assert findings[1]["file_path"] == "web/package.json"
    assert findings[1]["line_number"] == 4
    assert preflight.repository_scoped == 0
    assert preflight.no_location == 1


def test_unknown_project_root_keeps_repository_finding_path():
    findings = [
        {
            "rule_id": "SKY-R103",
            "kind": "repo_policy",
            "file_path": "pyproject.toml",
            "line_number": 7,
        }
    ]
    apply_upload_contract(findings, None)
    assert findings[0]["file_path"] == "pyproject.toml"
    assert findings[0]["line_number"] == 1


def test_no_location_findings_are_sent_with_an_empty_path_never_a_placeholder():
    findings = [
        {
            "rule_id": "SKY-Q1",
            "file_path": "../moved.py",
            "line_number": 3,
            "snippet": "x",
        },
        {"rule_id": "SKY-Q1", "file_path": "unknown", "line_number": 1},
        {"rule_id": "SKY-Q1", "file_path": "<unknown>", "line_number": 1},
        {"rule_id": "SKY-Q1", "file_path": "NULL", "line_number": 1},
        {"rule_id": "SKY-Q1", "file_path": "apps/web", "line_number": 1},
        {"rule_id": "SKY-Q1", "file_path": "src/../../x.py", "line_number": 5},
        {"rule_id": "SKY-Q1", "file_path": "apps/web/ok.py", "line_number": 2},
    ]
    preflight = apply_upload_contract(findings, "apps/web")
    assert len(findings) == 7  # never dropped
    assert [f["file_path"] for f in findings] == [
        "",
        "",
        "",
        "",
        "",
        "",
        "apps/web/ok.py",
    ]
    assert [f["line_number"] for f in findings] == [3, 1, 1, 1, 1, 5, 2]
    assert "snippet" not in findings[0]
    assert preflight.no_location == 6
    assert preflight.no_location_message() == (
        "6 findings have no file location; uploading them anyway."
    )


def test_paths_are_normalized_inside_the_project():
    findings = [
        {"rule_id": "A", "file_path": "src/./pkg/../a.py", "line_number": 1},
        {"rule_id": "A", "file_path": "src\\win\\b.py", "line_number": 1},
    ]
    apply_upload_contract(findings, "")
    assert [f["file_path"] for f in findings] == ["src/a.py", "src/win/b.py"]


def test_absolute_paths_become_relative_or_no_location(tmp_path):
    base = tmp_path / "repo"
    (base / "src").mkdir(parents=True)
    findings = [
        {"rule_id": "A", "file_path": str(base / "src" / "a.py"), "line_number": 1},
        {
            "rule_id": "A",
            "file_path": str(tmp_path / "other" / "b.py"),
            "line_number": 1,
        },
        {
            "rule_id": "A",
            "file_path": "file://" + str(base / "src" / "c.py"),
            "line_number": 1,
        },
        {"rule_id": "A", "file_path": "C:\\Users\\me\\d.py", "line_number": 1},
    ]
    preflight = apply_upload_contract(findings, "", base_dir=base)
    assert [f["file_path"] for f in findings] == ["src/a.py", "", "src/c.py", ""]
    assert preflight.no_location == 2

    without_base = [{"rule_id": "A", "file_path": "/etc/passwd", "line_number": 1}]
    apply_upload_contract(without_base, "")
    assert without_base[0]["file_path"] == ""


def test_dotdot_path_is_placed_by_the_absolute_file_when_it_is_inside(tmp_path):
    base = tmp_path / "repo"
    (base / "src").mkdir(parents=True)
    findings = [
        {
            "rule_id": "A",
            "file_path": "../repo-link/src/a.py",
            "file": str(base / "src" / "a.py"),
            "line_number": 1,
        }
    ]
    apply_upload_contract(findings, "", base_dir=base)
    assert findings[0]["file_path"] == "src/a.py"


def test_folder_paths_have_no_location(tmp_path):
    base = tmp_path / "repo"
    (base / "src" / "pkg").mkdir(parents=True)
    findings = [{"rule_id": "SKY-U005", "file_path": "src/pkg", "line_number": 0}]
    apply_upload_contract(findings, "", base_dir=base)
    assert findings[0]["file_path"] == ""


def test_percent_in_a_file_name_survives_the_server_decode():
    findings = [
        {"rule_id": "A", "file_path": "src/100%.py", "line_number": 1},
        {"rule_id": "A", "file_path": "src/a%20b.py", "line_number": 1},
    ]
    apply_upload_contract(findings, "")
    sent = [f["file_path"] for f in findings]
    assert sent == ["src/100%25.py", "src/a%2520b.py"]
    assert [normalize_contract_file_path(p) for p in sent] == [
        "src/100%.py",
        "src/a%20b.py",
    ]


def test_preflight_leaves_severity_and_category_alone():
    findings = [
        {
            "rule_id": " SKY-Q1\x01 ",
            "file_path": "a.py",
            "line_number": -4,
            "severity": "warn",
            "category": "custom",
        },
        {"rule_id": "", "file_path": "a.py", "line_number": 1},
        {"rule_id": "X" * 300, "file_path": "a.py", "line_number": 1},
    ]
    apply_upload_contract(findings, "")
    assert findings[0]["rule_id"] == "SKY-Q1"
    assert findings[0]["line_number"] == 0
    assert findings[0]["severity"] == "warn"
    assert findings[0]["category"] == "custom"
    assert findings[1]["rule_id"] == "UNKNOWN"
    assert len(findings[2]["rule_id"]) == 120


def test_no_location_message_is_singular_or_absent():
    one = apply_upload_contract(
        [{"rule_id": "A", "file_path": "..", "line_number": 1}], ""
    )
    none = apply_upload_contract(
        [{"rule_id": "A", "file_path": "a.py", "line_number": 1}], ""
    )
    assert (
        one.no_location_message()
        == "1 finding has no file location; uploading it anyway."
    )
    assert none.no_location_message() is None


def _uris(payload):
    return [
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in payload["runs"][0]["results"]
    ]


def test_prepared_payload_has_repo_relative_paths_only(repo):
    result = _result(
        repo,
        danger=[_quality(repo, rule_id="SKY-D211", severity="HIGH")],
        quality=[
            {
                "rule_id": "SKY-R104",
                "kind": "repo_policy",
                "file": str(repo),
                "line": 1,
                "severity": "LOW",
                "message": "Repository has no pre-commit policy file.",
            }
        ],
    )
    prepared = api._prepare_report_upload(result, analyzer_owned=True)
    text = json.dumps(prepared.legacy_payload)
    assert str(repo) not in text
    assert _uris(prepared.legacy_payload) == ["src/app.py", "."]
    assert [f["file_path"] for f in prepared.compatibility_payload["findings"]] == [
        "src/app.py",
        ".",
    ]


def test_repo_policy_at_repo_root_is_sent_as_dot_when_result_has_no_project_root(repo):
    # A real `skylos . -a` result carries no project_root key. The repository
    # root itself must still be sent as "." for repository-level findings;
    # sending "" made the server store "no location" (and, on pull-request
    # scans, count it as new). Found by running a real repository's upload
    # through the server's normalization.
    result = {
        "provenance": None,
        "danger": [_quality(repo, rule_id="SKY-D211", severity="HIGH")],
        "quality": [
            {
                "rule_id": "SKY-R104",
                "kind": "repo_policy",
                "file": str(repo),
                "line": 1,
                "severity": "LOW",
                "message": "Repository has no pre-commit policy file.",
            }
        ],
    }
    for analyzer_owned in (False, True):
        prepared = api._prepare_report_upload(
            json.loads(json.dumps(result)), analyzer_owned=analyzer_owned
        )
        assert _uris(prepared.legacy_payload) == ["src/app.py", "."], analyzer_owned
        assert prepared.preflight.no_location == 0


def test_missing_path_is_sent_empty_in_sarif_and_compact_payloads(repo):
    result = _result(repo, danger=[{"rule_id": "SKY-D211", "message": "no file"}])
    prepared = api._prepare_report_upload(result, analyzer_owned=True)
    assert _uris(prepared.legacy_payload) == [""]
    [compact] = prepared.compatibility_payload["findings"]
    assert compact["file_path"] == ""
    assert "unknown" not in json.dumps(prepared.legacy_payload["runs"][0]["results"])


def test_without_a_git_root_paths_are_relative_to_the_working_directory(
    repo, tmp_path, monkeypatch
):
    monkeypatch.setattr(api, "get_git_root", lambda: None)
    monkeypatch.chdir(repo)
    result = _result(repo, quality=[_quality(repo)])
    prepared = api._prepare_report_upload(result, analyzer_owned=True)
    assert _uris(prepared.legacy_payload) == ["src/app.py"]
    assert str(repo) not in json.dumps(prepared.legacy_payload)

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    prepared = api._prepare_report_upload(
        _result(repo, quality=[_quality(repo)]), analyzer_owned=True
    )
    assert _uris(prepared.legacy_payload) == [""]
    text = json.dumps(prepared.legacy_payload)
    assert str(repo) not in text and str(repo).lstrip("/") not in text


def test_related_locations_and_flow_steps_never_carry_machine_paths(repo, tmp_path):
    outside = str(tmp_path / "private" / "helper.py")
    finding = _quality(
        repo,
        rule_id="SKY-D211",
        severity="HIGH",
        related_locations=[
            {"file": str(repo / "src" / "app.py"), "line": 2, "message": "inside"},
            {"file": outside, "line": 3, "message": "outside"},
        ],
        metadata={
            "security_evidence": {
                "path": [
                    {"file": outside, "line": 4, "message": "source"},
                    {
                        "file": str(repo / "src" / "app.py"),
                        "line": 1,
                        "message": "sink",
                    },
                ]
            }
        },
    )
    prepared = api._prepare_report_upload(
        _result(repo, danger=[finding]), analyzer_owned=True
    )
    [result] = prepared.legacy_payload["runs"][0]["results"]
    related = [
        r["physicalLocation"]["artifactLocation"]["uri"]
        for r in result.get("relatedLocations", [])
    ]
    assert related == ["src/app.py"]
    steps = [
        step["location"]["physicalLocation"]["artifactLocation"]["uri"]
        for step in result["codeFlows"][0]["threadFlows"][0]["locations"]
    ]
    # The outside step is anchored at the finding instead of its machine path.
    assert steps == ["src/app.py", "src/app.py"]
    locations = json.dumps(
        {k: result.get(k) for k in ("locations", "relatedLocations", "codeFlows")}
    )
    assert str(tmp_path) not in locations
    assert str(tmp_path).lstrip("/") not in locations


def test_upload_prints_one_summary_line_for_missing_locations(
    repo, tmp_path, monkeypatch, capsys
):
    outside = tmp_path / "elsewhere" / "moved.py"
    post = _Calls(_ok())
    monkeypatch.setattr(api.requests, "post", post)
    result = _result(
        repo,
        quality=[
            _quality(repo),
            {**_quality(repo), "file": str(outside)},
            {**_quality(repo), "file": str(outside), "line": 9},
        ],
    )
    response = api.upload_report(result)
    out = capsys.readouterr().out
    assert response["success"] is True
    assert out.count("no file location") == 1
    assert "2 findings have no file location; uploading them anyway." in out
    sent = post.calls[0].json
    assert _uris(sent) == ["src/app.py", "", ""]  # nothing dropped, no '..'


def test_managed_gitlab_upload_skips_contract_rewrite(repo, monkeypatch):
    monkeypatch.setattr(api, "get_git_root", lambda: str(repo))
    monkeypatch.setattr(
        "skylos.cloud.gitlab.managed_checkout_root", lambda: repo, raising=False
    )
    result = _result(
        repo,
        quality=[
            {
                "rule_id": "SKY-R101",
                "kind": "repo_policy",
                "file": str(repo / "pyproject.toml"),
                "line": 1,
                "severity": "MEDIUM",
                "message": "m",
            }
        ],
    )
    prepared = api._prepare_report_upload(result, gitlab_managed=True)
    assert prepared.preflight is None
    [sent] = prepared.legacy_payload["runs"][0]["results"]
    assert (
        sent["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "pyproject.toml"
    )


# --------------------------------------------------------------------------
# Retry policy
# --------------------------------------------------------------------------


@pytest.mark.parametrize("status", [408, 425, 429, 500, 502, 503, 504])
def test_retryable_statuses_are_retried_up_to_four_attempts(status, monkeypatch):
    post = _Calls(Resp(status))
    monkeypatch.setattr(api.requests, "post", post)
    response, error = api._post_json_with_retries(api.REPORT_URL, {}, {}, quiet=True)
    assert response is None
    assert len(post.calls) == 4
    assert isinstance(error, UploadFailure) and error.retryable
    assert f"HTTP {status}" in error


@pytest.mark.parametrize("status", [400, 403, 404, 409, 410, 413, 422])
def test_other_client_errors_are_never_retried(status, monkeypatch):
    post = _Calls(Resp(status, {"error": "No.", "code": "X"}))
    monkeypatch.setattr(api.requests, "post", post)
    response, error = api._post_json_with_retries(
        api.REPORT_URL, {}, {}, quiet=True, accepted_statuses=(200,)
    )
    assert response is None
    assert len(post.calls) == 1
    assert error.status == status


@pytest.mark.parametrize(
    "exc",
    [
        requests.exceptions.ConnectionError("down"),
        requests.exceptions.ReadTimeout("slow"),
    ],
)
def test_connection_errors_and_timeouts_are_retried(exc, monkeypatch):
    post = _Calls(exc, exc, _ok())
    monkeypatch.setattr(api.requests, "post", post)
    response, error = api._post_json_with_retries(api.REPORT_URL, {}, {}, quiet=True)
    assert error is None and response.status_code == 200
    assert len(post.calls) == 3


def test_non_transport_request_errors_are_not_retried(monkeypatch):
    post = _Calls(requests.exceptions.InvalidHeader("bad"))
    monkeypatch.setattr(api.requests, "post", post)
    response, error = api._post_json_with_retries(api.REPORT_URL, {}, {}, quiet=True)
    assert response is None and len(post.calls) == 1
    assert not error.retryable


def test_attempt_count_is_configurable(monkeypatch):
    monkeypatch.setenv("SKYLOS_UPLOAD_MAX_ATTEMPTS", "2")
    post = _Calls(Resp(503))
    monkeypatch.setattr(api.requests, "post", post)
    api._post_json_with_retries(api.REPORT_URL, {}, {}, quiet=True)
    assert len(post.calls) == 2


def test_backoff_is_exponential_full_jitter_and_capped():
    policy = RetryPolicy(max_attempts=4, base_seconds=1.0, max_seconds=30.0)
    upper = [backoff_delay(n, policy, rand=lambda lo, hi: hi) for n in range(1, 8)]
    lower = [backoff_delay(n, policy, rand=lambda lo, hi: lo) for n in range(1, 8)]
    assert upper == [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0]
    assert lower == [0.0] * 7
    for n in range(1, 8):
        for _ in range(50):
            assert 0.0 <= backoff_delay(n, policy) <= min(30.0, 2 ** (n - 1))


def test_default_policy_is_four_attempts_one_second_base_thirty_second_cap(monkeypatch):
    for name in (
        "SKYLOS_UPLOAD_MAX_ATTEMPTS",
        "SKYLOS_UPLOAD_RETRY_BASE_SECONDS",
        "SKYLOS_UPLOAD_RETRY_MAX_SECONDS",
        "SKYLOS_UPLOAD_CONFLICT_BUDGET_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    assert RetryPolicy.from_env() == RetryPolicy(4, 1.0, 30.0, 300.0)


def test_retry_sleeps_follow_backoff_between_attempts(monkeypatch):
    monkeypatch.setenv("SKYLOS_UPLOAD_RETRY_BASE_SECONDS", "1")
    sleeps = []
    monkeypatch.setattr(api, "_upload_sleep", sleeps.append)
    monkeypatch.setattr(api.requests, "post", _Calls(Resp(502)))
    api._post_json_with_retries(api.REPORT_URL, {}, {}, quiet=True)
    assert len(sleeps) == 3
    for index, delay in enumerate(sleeps, start=1):
        assert 0 <= delay <= 2 ** (index - 1)


def test_retry_after_seconds_is_honoured(monkeypatch):
    sleeps = []
    monkeypatch.setattr(api, "_upload_sleep", sleeps.append)
    post = _Calls(Resp(429, headers={"Retry-After": "7"}), _ok())
    monkeypatch.setattr(api.requests, "post", post)
    response, _ = api._post_json_with_retries(api.REPORT_URL, {}, {}, quiet=True)
    assert response.status_code == 200
    assert sleeps == [7.0]


def test_retry_after_longer_than_the_cap_stops_and_stays_retryable(monkeypatch):
    post = _Calls(Resp(503, headers={"Retry-After": "3600"}))
    monkeypatch.setattr(api.requests, "post", post)
    response, error = api._post_json_with_retries(api.REPORT_URL, {}, {}, quiet=True)
    assert response is None and len(post.calls) == 1
    assert error.retryable and error.retry_after == 3600


def test_parse_retry_after_accepts_seconds_and_http_dates():
    now = 1_800_000_000.0
    date = email.utils.formatdate(now + 12, usegmt=True)
    assert parse_retry_after("5") == 5.0
    assert parse_retry_after(date, now=now) == pytest.approx(12, abs=1)
    assert (
        parse_retry_after(email.utils.formatdate(now - 60, usegmt=True), now=now) == 0.0
    )
    assert parse_retry_after("soon") is None
    assert parse_retry_after("") is None
    assert parse_retry_after(None) is None
    assert parse_retry_after(mock.MagicMock()) is None


def test_every_attempt_sends_one_idempotency_key_and_the_contract_header(monkeypatch):
    monkeypatch.setattr(api, "_cli_version", lambda: "4.40.0")
    post = _Calls(Resp(500), Resp(503), _ok())
    monkeypatch.setattr(api.requests, "post", post)
    api._post_json_with_retries(
        api.REPORT_URL, {"Authorization": "Bearer t"}, {}, quiet=True
    )
    assert len(set(post.keys)) == 1
    UUID(post.keys[0], version=4)
    assert all(c.headers["X-Skylos-Upload-Contract"] == "1" for c in post.calls)
    assert all(c.headers["Authorization"] == "Bearer t" for c in post.calls)
    assert all(c.headers["X-Skylos-Cli-Version"] == "4.40.0" for c in post.calls)
    assert all(c.headers["User-Agent"] == "skylos/4.40.0" for c in post.calls)


def test_odd_cli_version_is_not_sent(monkeypatch):
    monkeypatch.setattr(api, "_cli_version", lambda: "bad version\r\nX-Evil: 1")
    post = _Calls(_ok())
    monkeypatch.setattr(api.requests, "post", post)
    api._post_json_with_retries(api.REPORT_URL, {}, {}, quiet=True)
    assert "X-Skylos-Cli-Version" not in post.calls[0].headers
    assert "User-Agent" not in post.calls[0].headers


def test_given_idempotency_key_is_used(monkeypatch):
    post = _Calls(_ok())
    monkeypatch.setattr(api.requests, "post", post)
    key = "7d6f3f2a-1c2b-4d3e-8f90-123456789abc"
    api._post_json_with_retries(api.REPORT_URL, {}, {}, quiet=True, idempotency_key=key)
    assert post.keys == [key]


def test_managed_gitlab_post_is_unchanged(monkeypatch):
    post = _Calls(Resp(503))
    monkeypatch.setattr(api.requests, "post", post)
    response, error = api._post_json_with_retries(
        api.REPORT_URL, {"X-Skylos-Auth": "gitlab_oidc"}, {}, quiet=True
    )
    assert response is None and len(post.calls) == 1
    assert "Idempotency-Key" not in post.calls[0].headers
    assert "X-Skylos-Upload-Contract" not in post.calls[0].headers
    assert "No automatic re-upload" in error


# --------------------------------------------------------------------------
# Error messages
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("response", "code", "expected", "retryable"),
    [
        (
            Resp(401, text="Unauthorized"),
            "INVALID_TOKEN",
            "Invalid API token. Run 'skylos login' to reconnect or 'skylos sync connect' to set a token manually.",
            False,
        ),
        (
            Resp(
                403, {"error": "Invalid upload credentials.", "code": "INVALID_TOKEN"}
            ),
            "INVALID_TOKEN",
            "Invalid upload credentials. Run 'skylos login'",
            False,
        ),
        (
            Resp(
                402,
                {
                    "error": "No credits remaining. Buy more at skylos.dev/dashboard/billing"
                },
            ),
            "NO_CREDITS",
            "No credits remaining.",
            False,
        ),
        (
            Resp(
                422,
                {
                    "error": "Upload contains findings outside the selected project root. Run Skylos from the matching subproject or upload each monorepo project separately.",
                    "code": "PROJECT_ROOT_FINDING_MISMATCH",
                    "project_root": "apps/web",
                    "rejected_findings": [
                        {
                            "index": 3,
                            "file_path": "libs/x.py",
                            "project_root": "apps/web",
                        }
                    ],
                },
            ),
            "PROJECT_ROOT_FINDING_MISMATCH",
            "Rejected: #3 (libs/x.py).",
            False,
        ),
        (
            Resp(
                422,
                {
                    "error": "Upload contains invalid finding paths or labels. Run a current Skylos scan and upload the report again.",
                    "code": "INVALID_FINDING_INPUT",
                    "rejected_findings": [
                        {"index": 12, "field": "file_path"},
                        {"index": 40, "field": "file_path"},
                    ],
                },
            ),
            "INVALID_FINDING_INPUT",
            "Rejected: #12 (file_path), #40 (file_path). Update Skylos with 'pip install -U skylos' and scan again.",
            False,
        ),
        (
            Resp(409, {"code": "UPLOAD_IN_PROGRESS"}),
            "UPLOAD_IN_PROGRESS",
            "Skylos Cloud is still processing this upload. Wait a minute",
            True,
        ),
        (
            Resp(409, {"code": "IDEMPOTENCY_KEY_REUSED", "error": "Key reused."}),
            "IDEMPOTENCY_KEY_REUSED",
            "Key reused. Run the scan again to upload it with a new key.",
            False,
        ),
        (
            Resp(413, text="<html>Request Entity Too Large</html>"),
            "PAYLOAD_TOO_LARGE",
            "The scan is too large for Skylos Cloud to accept in one request. Update Skylos with 'pip install -U skylos' so large scans use artifact upload",
            False,
        ),
        (
            Resp(429, {"code": "RATE_LIMITED"}),
            "RATE_LIMITED",
            "Skylos Cloud is limiting uploads right now.",
            True,
        ),
        (
            Resp(502, text="<html><body>Bad gateway</body></html>"),
            None,
            "Skylos Cloud had a temporary problem (HTTP 502). Try again in a few minutes.",
            True,
        ),
        (
            Resp(418, {"unexpected": {"nested": [1, 2]}}),
            None,
            "Skylos Cloud rejected the upload (HTTP 418).",
            False,
        ),
    ],
)
def test_error_messages_are_plain_and_actionable(response, code, expected, retryable):
    failure = describe_http_failure(response)
    assert failure.code == code
    assert expected in failure
    assert failure.retryable is retryable
    assert "{" not in failure and "<html" not in failure


def test_new_error_shape_prints_error_hint_and_reference():
    failure = describe_http_failure(
        Resp(
            422,
            {
                "code": "SOMETHING_NEW",
                "error": "The scan could not be stored.",
                "hint": "Run skylos doctor.",
                "retryable": False,
                "request_id": "req_123",
            },
        )
    )
    assert failure == "The scan could not be stored. Run skylos doctor. (ref: req_123)"
    assert failure.request_id == "req_123"


def test_body_retryable_flag_wins_over_status():
    assert describe_http_failure(Resp(503, {"retryable": False})).retryable is False
    assert describe_http_failure(Resp(409, {"retryable": True})).retryable is True


def test_server_text_is_cleaned_for_the_terminal():
    failure = describe_http_failure(
        Resp(400, {"error": "Bad\x1b[31m [red]thing[/red]\n" + "x" * 500})
    )
    assert "\x1b" not in failure and "\n" not in failure
    assert len(failure.error) <= 300


def test_server_text_invisible_characters_are_cleaned_for_the_terminal():
    ranges = (
        (0x00, 0x1F),
        (0x7F, 0x9F),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2066, 0x2069),
    )
    for start, end in ranges:
        for codepoint in range(start, end + 1):
            assert clean_text(f"left{chr(codepoint)}right") == "left right"


def test_upload_transport_source_has_no_invisible_format_characters():
    source = Path(_upload_transport.__file__).read_text(encoding="utf-8")
    hidden = [
        f"U+{ord(char):04X}" for char in source if unicodedata.category(char) == "Cf"
    ]
    assert hidden == []


def test_render_upload_failure_escapes_markup(capsys):
    from rich.console import Console
    import skylos.cli as cli

    console = Console(record=True, width=200)
    cli._render_upload_failure(console, {"error": "[bold]injected[/bold] text"})
    assert "[bold]injected[/bold]" in console.export_text()


def test_real_422_invalid_finding_input_is_not_retried_or_saved(
    repo, tmp_path, monkeypatch
):
    body = {
        "error": "Upload contains invalid finding paths or labels. Run a current Skylos scan and upload the report again.",
        "code": "INVALID_FINDING_INPUT",
        "rejected_findings": [
            {"index": 1, "field": "file_path"},
            {"index": 2, "field": "file_path"},
        ],
    }
    post = _Calls(Resp(422, body))
    monkeypatch.setattr(api.requests, "post", post)
    result = api.upload_report(_result(repo, quality=[_quality(repo)]), quiet=True)
    assert len(post.calls) == 1
    assert result["success"] is False and result["code"] == "INVALID_FINDING_INPUT"
    assert "Server Error" not in result["error"] and "{" not in result["error"]
    assert _pending_files(tmp_path) == []


def test_idempotent_replay_says_the_scan_was_already_saved(repo, monkeypatch, capsys):
    monkeypatch.setattr(
        api.requests,
        "post",
        _Calls(
            Resp(
                200,
                {"scanId": "s1", "quality_gate": {"passed": True}},
                {"Idempotent-Replayed": "true"},
            )
        ),
    )
    result = api.upload_report(_result(repo, quality=[_quality(repo)]))
    assert result["success"] and result["replayed"] is True
    assert "already saved by an earlier attempt" in capsys.readouterr().out


def test_idempotent_replay_body_flag_is_recognised(repo, monkeypatch, capsys):
    monkeypatch.setattr(
        api.requests,
        "post",
        _Calls(
            Resp(
                200,
                {
                    "scanId": "s1",
                    "idempotent_replay": True,
                    "quality_gate": {"passed": True},
                },
            )
        ),
    )
    result = api.upload_report(_result(repo, quality=[_quality(repo)]))
    assert result["replayed"] is True
    assert "already saved by an earlier attempt" in capsys.readouterr().out


def _in_progress(retry_after="15", **extra):
    return Resp(
        409,
        {
            "code": "UPLOAD_IN_PROGRESS",
            "error": "This upload is still being processed.",
            "hint": "Wait a moment and retry.",
            "retryable": True,
            "request_id": "req_9",
            **extra,
        },
        {"Retry-After": retry_after},
    )


def _replay(scan_id="scan-late"):
    return Resp(
        200,
        {
            "scanId": scan_id,
            "idempotent_replay": True,
            "quality_gate": {"passed": True},
        },
        {"Idempotent-Replayed": "true"},
    )


def test_slow_upload_timeout_then_in_progress_then_replay_is_a_success(
    repo, tmp_path, monkeypatch, capsys
):
    # Attempt 1 times out while the server keeps working; the retry finds the
    # same upload still running, waits as asked, then gets the saved scan.
    monkeypatch.setenv("SKYLOS_UPLOAD_CONFLICT_BUDGET_SECONDS", "300")
    sleeps = []
    monkeypatch.setattr(api, "_upload_sleep", sleeps.append)
    post = _Calls(
        requests.exceptions.ReadTimeout("slow"),
        _in_progress(),
        _in_progress(),
        _replay(),
    )
    monkeypatch.setattr(api.requests, "post", post)
    result = api.upload_report(_result(repo, quality=[_quality(repo)]))
    assert result["success"] is True and result["replayed"] is True
    assert result["scan_id"] == "scan-late"
    assert len(set(post.keys)) == 1
    assert sleeps[1:] == [15.0, 15.0]  # Retry-After honoured for the 409s
    assert _pending_files(tmp_path) == []
    out = capsys.readouterr().out
    assert "still processing" in out
    assert "already saved by an earlier attempt" in out


def test_retryable_conflicts_do_not_use_up_normal_attempts(monkeypatch):
    monkeypatch.setenv("SKYLOS_UPLOAD_CONFLICT_BUDGET_SECONDS", "300")
    monkeypatch.setattr(api, "_upload_sleep", lambda s: None)
    post = _Calls(*([_in_progress("5")] * 6), _ok())
    monkeypatch.setattr(api.requests, "post", post)
    response, error = api._post_json_with_retries(api.REPORT_URL, {}, {}, quiet=True)
    assert error is None and response.status_code == 200
    assert len(post.calls) == 7


def test_conflict_waiting_stops_at_the_budget_and_saves_the_scan(
    repo, tmp_path, monkeypatch
):
    monkeypatch.setenv("SKYLOS_UPLOAD_CONFLICT_BUDGET_SECONDS", "300")
    sleeps = []
    monkeypatch.setattr(api, "_upload_sleep", sleeps.append)
    post = _Calls(_in_progress())
    monkeypatch.setattr(api.requests, "post", post)
    result = api.upload_report(_result(repo, quality=[_quality(repo)]), quiet=True)
    assert sum(sleeps) <= 300 and sum(sleeps) >= 285
    assert len(post.calls) == len(sleeps) + 1
    assert result["code"] == "UPLOAD_IN_PROGRESS" and result["retryable"] is True
    assert result["error"].endswith("(ref: req_9)")
    [saved] = _pending_files(tmp_path)
    assert _read_pending(saved)["idempotency_key"] == post.keys[0]


def test_conflict_delay_is_bounded():
    from skylos.api._upload_transport import conflict_delay

    assert conflict_delay(describe_http_failure(_in_progress("15"))) == 15.0
    assert conflict_delay(describe_http_failure(_in_progress("0"))) == 1.0
    assert conflict_delay(describe_http_failure(_in_progress("900"))) == 60.0
    missing = Resp(409, {"code": "UPLOAD_IN_PROGRESS", "retryable": True})
    assert conflict_delay(describe_http_failure(missing)) == 15.0


@pytest.mark.parametrize(
    "body",
    [
        {"code": "IDEMPOTENCY_KEY_REUSED", "retryable": False},
        {"code": "PR_DIFF_UNAVAILABLE", "retryable": False},
        {"code": "SOMETHING", "error": "Conflict."},
    ],
)
def test_non_retryable_conflicts_stop_at_once(body, monkeypatch):
    monkeypatch.setenv("SKYLOS_UPLOAD_CONFLICT_BUDGET_SECONDS", "300")
    post = _Calls(Resp(409, body, {"Retry-After": "1"}))
    monkeypatch.setattr(api.requests, "post", post)
    response, error = api._post_json_with_retries(api.REPORT_URL, {}, {}, quiet=True)
    assert response is None and len(post.calls) == 1


def test_retryable_pr_diff_conflict_is_retried(monkeypatch):
    monkeypatch.setenv("SKYLOS_UPLOAD_CONFLICT_BUDGET_SECONDS", "300")
    monkeypatch.setattr(api, "_upload_sleep", lambda s: None)
    post = _Calls(
        Resp(
            409,
            {"code": "PR_DIFF_UNAVAILABLE", "retryable": True},
            {"Retry-After": "10"},
        ),
        _ok(),
    )
    monkeypatch.setattr(api.requests, "post", post)
    response, error = api._post_json_with_retries(api.REPORT_URL, {}, {}, quiet=True)
    assert error is None and len(post.calls) == 2


def test_report_endpoints_use_the_contract_read_timeout(repo, monkeypatch):
    post = _Calls(_ok())
    monkeypatch.setattr(api.requests, "post", post)
    api.upload_report(_result(repo, quality=[_quality(repo)]), quiet=True)
    assert post.calls[0].timeout == (api.NETWORK_TIMEOUT_DEFAULT, 270.0)


def test_finding_warnings_in_the_response_are_summarised(repo, monkeypatch, capsys):
    monkeypatch.setattr(
        api.requests,
        "post",
        _Calls(
            _ok(
                finding_warnings=[
                    {"index": 0, "field": "file_path", "reason": "dot_segment"}
                ]
            )
        ),
    )
    api.upload_report(_result(repo, quality=[_quality(repo)]))
    assert "stored 1 finding with a warning" in capsys.readouterr().out


# --------------------------------------------------------------------------
# Saved (pending) uploads
# --------------------------------------------------------------------------


def _wire_bytes(payload):
    """What requests puts on the wire for ``requests.post(json=payload)``."""
    return requests.Request("POST", "http://x.invalid/", json=payload).prepare().body


def test_retryable_failure_saves_the_exact_request_privately(
    repo, tmp_path, monkeypatch
):
    post = _Calls(Resp(503))
    monkeypatch.setattr(api.requests, "post", post)
    result = api.upload_report(_result(repo, quality=[_quality(repo)]), quiet=True)

    [saved] = _pending_files(tmp_path)
    assert result["success"] is False and result["retryable"] is True
    assert result["pending_upload"] == str(saved)
    assert "skylos upload --retry" in result["error"]
    # The file is named after the key every attempt used.
    assert set(post.keys) == {saved.name[: -len(".json.gz")]}
    assert stat.S_IMODE(saved.stat().st_mode) == 0o600
    record = _read_pending(saved)
    assert record["mode"] == "inline"
    assert record["endpoint"] == api.REPORT_URL
    assert record["idempotency_key"] == post.keys[0]
    assert record["cli_version"] == api._cli_version()
    assert record["last_error"]["status"] == 503
    # Byte for byte what the first attempt sent.
    assert _pending_uploads.decode_request_body(record) == _wire_bytes(
        post.calls[0].json
    )


def test_non_retryable_failure_is_not_saved(repo, tmp_path, monkeypatch):
    monkeypatch.setattr(api.requests, "post", _Calls(Resp(403)))
    api.upload_report(_result(repo, quality=[_quality(repo)]), quiet=True)
    assert _pending_files(tmp_path) == []


def test_sent_and_saved_uploads_never_contain_the_token_or_secret_snippets(
    repo, tmp_path, monkeypatch
):
    keys_file = repo / "src" / "keys.py"
    keys_file.write_text(  # skylos: ignore[SKY-D324] fixed file under fresh pytest tmp_path
        "AWS = 'AKIAIOSFODNN7EXAMPLE'\n"
    )
    post = _Calls(requests.exceptions.ConnectionError("x"))
    monkeypatch.setattr(api.requests, "post", post)
    result = _result(
        repo,
        secrets=[
            {
                "rule_id": "SKY-S101",
                "file": str(repo / "src" / "keys.py"),
                "line": 1,
                "severity": "CRITICAL",
                "message": "AWS access key",
                "snippet": "AWS = 'AKIAIOSFODNN7EXAMPLE'",
            }
        ],
    )
    api.upload_report(result, quiet=True)
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(post.calls[0].json)
    [saved] = _pending_files(tmp_path)
    text = gzip.decompress(saved.read_bytes()).decode("utf-8")
    assert TOKEN not in text
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    assert "Bearer" not in text


def test_secret_snippets_are_stripped_before_the_first_send():
    from skylos.api._upload_preflight import strip_secret_snippets

    payload = {
        "runs": [
            {
                "results": [
                    {
                        "properties": {"category": "SECRET"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "region": {"snippet": {"text": "k=SECRET"}}
                                }
                            }
                        ],
                    },
                    {
                        "properties": {"category": "SECURITY"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "region": {"snippet": {"text": "keep"}}
                                }
                            }
                        ],
                    },
                ]
            }
        ],
        "findings": [{"category": "SECRET", "snippet": "k=SECRET"}],
    }
    strip_secret_snippets(payload)
    text = json.dumps(payload)
    assert "k=SECRET" not in text and "keep" in text


def test_saving_never_edits_the_request_bytes(tmp_path):
    body = b'{"findings":[{"category":"SECRET","snippet":"sent as is"}],"x":1.0e16}'
    path = _pending_uploads.save_pending_upload(
        tmp_path / "p",
        idempotency_key="7d6f3f2a-1c2b-4d3e-8f90-123456789abc",
        kind="report",
        mode="inline",
        endpoint="https://x/api/report",
        api_base="https://x",
        project_id=None,
        cli_version="1",
        request_body=body,
    )
    [item], _ = _pending_uploads.list_pending_uploads(tmp_path / "p")
    assert item.path == path
    assert _pending_uploads.decode_request_body(item.record) == body


def test_queue_lives_in_the_user_state_folder_not_the_checkout(
    repo, tmp_path, monkeypatch
):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("SKYLOS_PENDING_UPLOAD_DIR")
    # Use the real ~/.skylos layout, under the temporary HOME set above.
    monkeypatch.setattr(
        _pending_uploads, "default_pending_root", _pending_uploads.home_pending_root
    )
    assert _pending_uploads.pending_root() == home / ".skylos" / "pending-uploads"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    monkeypatch.setattr(api.requests, "post", _Calls(Resp(503)))
    result = api.upload_report(_result(repo, quality=[_quality(repo)]), quiet=True)

    saved = Path(result["pending_upload"])
    queue_root = home / ".skylos" / "pending-uploads"
    assert saved.parent.parent == queue_root
    assert saved.parent.name == _pending_uploads.repository_queue_id(repo)
    assert stat.S_IMODE(saved.stat().st_mode) == 0o600
    assert stat.S_IMODE(saved.parent.stat().st_mode) == 0o700
    key_file = queue_root / ".record-key"
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert key_file.stat().st_size == 32
    assert not (repo / ".skylos").exists()
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    assert ".skylos" not in status.stdout


def test_tests_can_never_reach_the_real_home_queue(monkeypatch):
    monkeypatch.delenv("SKYLOS_PENDING_UPLOAD_DIR")
    real = Path(os.path.expanduser("~")) / ".skylos" / "pending-uploads"
    assert _pending_uploads.pending_root() != real
    assert "no-real-home" in str(_pending_uploads.pending_root())


def test_each_repository_has_its_own_queue(tmp_path):
    first = _pending_uploads.pending_uploads_dir(tmp_path / "a")
    second = _pending_uploads.pending_uploads_dir(tmp_path / "b")
    assert first != second and first.parent == second.parent


def test_pending_folder_refuses_a_symlinked_repository_queue(tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    queue = tmp_path / "root" / "repo-id"
    queue.parent.mkdir()
    queue.symlink_to(target)
    path = _pending_uploads.save_pending_upload(
        queue,
        idempotency_key="7d6f3f2a-1c2b-4d3e-8f90-123456789abc",
        kind="report",
        mode="inline",
        endpoint="e",
        api_base="b",
        project_id=None,
        cli_version=None,
        request_body=b"{}",
    )
    assert path is None
    assert list(target.iterdir()) == []


def test_pending_folder_refuses_a_symlinked_queue_root(tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    root = tmp_path / "pending"
    root.symlink_to(target, target_is_directory=True)
    queue = root / "repo-id"

    path = _pending_uploads.save_pending_upload(
        queue,
        idempotency_key="7d6f3f2a-1c2b-4d3e-8f90-123456789abc",
        kind="report",
        mode="inline",
        endpoint="e",
        api_base="b",
        project_id=None,
        cli_version=None,
        request_body=b"{}",
    )

    assert path is None
    assert list(target.iterdir()) == []
    assert _pending_uploads.list_pending_uploads(queue) == ([], 0)


def test_pending_listing_refuses_a_symlinked_queue_root(tmp_path):
    actual = tmp_path / "actual"
    queue = actual / "repo-id"
    saved = _save(queue, KEYS[0])
    assert saved is not None
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)

    assert _pending_uploads.list_pending_uploads(linked / "repo-id") == ([], 0)
    assert _pending_uploads.count_pending_uploads(linked / "repo-id") == 0


@pytest.mark.skipif(os.name != "posix", reason="POSIX queue permissions")
def test_pending_folder_refuses_a_public_queue_root(tmp_path):
    root = tmp_path / "pending"
    root.mkdir()
    os.chmod(root, 0o755)
    queue = root / "repo-id"

    path = _pending_uploads.save_pending_upload(
        queue,
        idempotency_key="7d6f3f2a-1c2b-4d3e-8f90-123456789abc",
        kind="report",
        mode="inline",
        endpoint="e",
        api_base="b",
        project_id=None,
        cli_version=None,
        request_body=b"{}",
    )

    assert path is None
    assert list(root.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX queue permissions")
def test_pending_folder_refuses_a_public_repository_queue(tmp_path):
    root = tmp_path / "pending"
    root.mkdir(mode=0o700)
    queue = root / "repo-id"
    queue.mkdir(mode=0o700)
    os.chmod(queue, 0o755)

    path = _pending_uploads.save_pending_upload(
        queue,
        idempotency_key="7d6f3f2a-1c2b-4d3e-8f90-123456789abc",
        kind="report",
        mode="inline",
        endpoint="e",
        api_base="b",
        project_id=None,
        cli_version=None,
        request_body=b"{}",
    )

    assert path is None
    assert list(queue.iterdir()) == []
    assert _pending_uploads.list_pending_uploads(queue) == ([], 0)


def test_unsigned_or_tampered_records_are_never_sent(repo, tmp_path, monkeypatch):
    queue = _queue(repo)
    good = _save(queue, KEYS[0])
    # A record written by someone without the user's key.
    forged = queue / f"{KEYS[1]}.json.gz"
    record = _read_pending(good)
    record["idempotency_key"] = KEYS[1]
    forged.write_bytes(  # skylos: ignore[SKY-D324] fixed filename in pytest queue
        gzip.compress(
            b"SKYLOS-PENDING-UPLOAD 3 "
            + b"0" * 64
            + b"\n"
            + json.dumps(record).encode()
        )
    )
    os.chmod(forged, 0o600)
    # A signed record with its body changed afterwards.
    tampered = _save(queue, KEYS[2])
    original = gzip.decompress(tampered.read_bytes())
    raw = original.replace(b'"kind":"report"', b'"kind":"forged"')
    assert raw != original
    tampered.write_bytes(  # skylos: ignore[SKY-D324] existing pytest queue fixture
        gzip.compress(raw)
    )
    # A valid record moved in from another repository's queue.
    other = _save(_queue(tmp_path / "other-repo"), KEYS[3])
    moved = queue / other.name
    os.replace(other, moved)

    pending, unreadable = _pending_uploads.list_pending_uploads(queue)
    assert [item.path for item in pending] == [good]
    assert unreadable == 3
    post = _Calls(_ok())
    monkeypatch.setattr(api.requests, "post", post)
    summary = api.resend_pending_uploads(quiet=True)
    assert summary["sent"] == 1 and len(post.calls) == 1
    assert post.keys == [KEYS[0]]


def test_a_readable_key_with_loose_permissions_is_not_trusted(repo, tmp_path):
    queue = _queue(repo)
    _save(queue, KEYS[0])
    os.chmod(queue.parent / ".record-key", 0o644)
    pending, unreadable = _pending_uploads.list_pending_uploads(queue)
    assert pending == [] and unreadable == 1


def test_uploads_saved_in_the_repository_by_older_versions_are_never_sent(
    repo, tmp_path, monkeypatch, capsys
):
    legacy = repo / ".skylos" / "pending-uploads"
    legacy.mkdir(parents=True)
    planted = legacy / f"{KEYS[0]}.json.gz"
    planted.write_bytes(  # skylos: ignore[SKY-D324] fixed filename under pytest repo
        gzip.compress(b'{"format":"skylos-pending-upload","version":2}')
    )
    os.chmod(planted, 0o600)
    post = _Calls(_ok())
    monkeypatch.setattr(api.requests, "post", post)

    summary = api.resend_pending_uploads(quiet=True)
    assert post.calls == [] and summary["total"] == 0
    assert "not sent automatically" in summary["legacy_notice"]
    assert planted.exists()  # left for the user to inspect and delete

    api.upload_report(_result(repo, quality=[_quality(repo)]))
    out = capsys.readouterr().out
    assert out.count("saved by an older Skylos") == 1
    assert "not sent automatically" in out
    # The fresh upload itself went out; the old file was not.
    assert len(post.calls) == 1


def _save(directory, key, *, now=None, body=None, endpoint=None, project_id=None):
    return _pending_uploads.save_pending_upload(
        directory,
        idempotency_key=key,
        kind="report",
        mode="inline",
        endpoint=endpoint or api.REPORT_URL,
        api_base=api.BASE_URL,
        project_id=project_id,
        cli_version="t",
        request_body=body if body is not None else b'{"findings":[],"tool":"skylos"}',
        now=now,
    )


KEYS = [f"7d6f3f2a-1c2b-4d3e-8f90-12345678900{i}" for i in range(6)]
EIGHT_DAYS = 8 * 24 * 3600


def test_scans_older_than_the_resend_window_move_to_failed(tmp_path):
    directory = tmp_path / "p"
    old = _save(directory, KEYS[0])
    fresh = _save(directory, KEYS[1])
    past = time.time() - EIGHT_DAYS
    os.utime(old, (past, past))
    pending, _ = _pending_uploads.list_pending_uploads(directory)
    assert [item.path for item in pending] == [fresh]
    assert not old.exists()
    reason = json.loads((directory / "failed" / f"{KEYS[0]}.reason.json").read_text())
    assert reason["reason"] == "too old to resend safely; rerun the scan"
    assert (directory / "failed" / f"{KEYS[0]}.json.gz").exists()
    assert _pending_uploads.count_pending_uploads(directory) == 1


def test_a_scan_past_the_window_is_never_sent(repo, tmp_path, monkeypatch):
    # Created 8 days ago even though the file itself looks new.
    path = _save(_queue(repo), KEYS[0], now=time.time() - EIGHT_DAYS)
    os.utime(path, None)
    post = _Calls(_ok())
    monkeypatch.setattr(api.requests, "post", post)
    summary = api.resend_pending_uploads(quiet=True)
    assert post.calls == []
    assert summary["total"] == 0
    assert (_queue(repo) / "failed" / f"{KEYS[0]}.json.gz").exists()


def test_resend_window_comes_from_the_contract():
    from skylos.api._upload_contract import client_resend_window_days

    assert client_resend_window_days() == 7
    assert _pending_uploads.resend_window_seconds() == 7 * 24 * 3600


def test_saved_uploads_are_capped_by_count_and_size(tmp_path, monkeypatch):
    directory = tmp_path / "p"
    monkeypatch.setattr(_pending_uploads, "MAX_COUNT", 2)
    paths = []
    base = time.time() - 100
    for index, key in enumerate(KEYS[:3]):
        paths.append(_save(directory, key))
        os.utime(paths[-1], (base + index, base + index))
    remaining = sorted(p.name for p in directory.glob("*.json.gz"))
    assert remaining == sorted(p.name for p in paths[1:])

    monkeypatch.setattr(_pending_uploads, "MAX_TOTAL_BYTES", 400)
    big = os.urandom(2000).hex().encode()
    assert _save(directory, KEYS[4], body=big) is None


def test_unreadable_or_planted_files_are_skipped(tmp_path):
    directory = tmp_path / "p"
    good = _save(directory, KEYS[0])
    loose = _save(directory, KEYS[1])
    os.chmod(loose, 0o644)  # e.g. a copy committed to the repository
    (directory / f"{KEYS[2]}.json.gz").write_bytes(b"not gzip")
    os.chmod(directory / f"{KEYS[2]}.json.gz", 0o600)
    (directory / f"{KEYS[3]}.json.gz").symlink_to(good)
    pending, unreadable = _pending_uploads.list_pending_uploads(directory)
    assert [item.path for item in pending] == [good]
    assert unreadable == 3


def test_next_upload_offers_to_resend(repo, tmp_path, monkeypatch, capsys):
    _save(_queue(repo), KEYS[0])
    monkeypatch.setattr(api.requests, "post", _Calls(_ok()))
    api.upload_report(_result(repo, quality=[_quality(repo)]))
    out = capsys.readouterr().out
    assert (
        "1 earlier upload did not finish. Run 'skylos upload --retry' to send it."
        in out
    )


def test_resend_sends_the_same_bytes_with_the_same_key(repo, tmp_path, monkeypatch):
    first = _Calls(Resp(500))
    monkeypatch.setattr(api.requests, "post", first)
    api.upload_report(_result(repo, quality=[_quality(repo)]), quiet=True)
    [saved] = _pending_files(tmp_path)
    key = saved.name[: -len(".json.gz")]

    post = _Calls(_ok("scan-9"))
    monkeypatch.setattr(api.requests, "post", post)
    summary = api.resend_pending_uploads(quiet=True)
    assert summary["sent"] == 1
    assert post.keys == [key]
    assert post.calls[0].url == api.REPORT_URL
    assert post.calls[0].data == _wire_bytes(first.calls[0].json)
    assert post.calls[0].headers["Content-Type"] == "application/json"
    assert _pending_files(tmp_path) == []


def test_resend_of_already_saved_scan_is_reported(repo, tmp_path, monkeypatch):
    _save(_queue(repo), KEYS[0])
    monkeypatch.setattr(
        api.requests,
        "post",
        _Calls(
            Resp(
                200,
                {"scanId": "s", "quality_gate": {"passed": True}},
                {"Idempotent-Replayed": "true"},
            )
        ),
    )
    summary = api.resend_pending_uploads(quiet=True)
    assert summary["already_saved"] == 1
    assert _pending_files(tmp_path) == []


def test_resend_keeps_scan_on_temporary_failure(repo, tmp_path, monkeypatch):
    _save(_queue(repo), KEYS[0])
    monkeypatch.setattr(api.requests, "post", _Calls(Resp(503)))
    summary = api.resend_pending_uploads(quiet=True)
    assert summary["kept"] == 1
    assert len(_pending_files(tmp_path)) == 1


def test_resend_moves_rejected_scan_to_failed_with_reason(repo, tmp_path, monkeypatch):
    _save(_queue(repo), KEYS[0])
    monkeypatch.setattr(
        api.requests,
        "post",
        _Calls(
            Resp(
                409,
                {
                    "code": "IDEMPOTENCY_KEY_REUSED",
                    "error": "Key reused.",
                    "request_id": "r1",
                },
            )
        ),
    )
    summary = api.resend_pending_uploads(quiet=True)
    assert summary["failed"] == 1
    assert _pending_files(tmp_path) == []
    failed = _queue(repo) / "failed"
    assert (failed / f"{KEYS[0]}.json.gz").exists()
    reason = json.loads((failed / f"{KEYS[0]}.reason.json").read_text())
    assert reason["code"] == "IDEMPOTENCY_KEY_REUSED"
    assert reason["request_id"] == "r1"


def test_resend_never_sends_to_a_different_endpoint(repo, tmp_path, monkeypatch):
    _save(_queue(repo), KEYS[0], endpoint="https://attacker.example/api/report")
    post = _Calls(_ok())
    monkeypatch.setattr(api.requests, "post", post)
    summary = api.resend_pending_uploads(quiet=True)
    assert summary["skipped"] == 1 and post.calls == []
    assert len(_pending_files(tmp_path)) == 1


@pytest.mark.parametrize(
    ("saved", "linked"),
    [("project-a", "project-b"), (None, "project-b"), ("project-a", None)],
)
def test_resend_requires_the_same_linked_project(
    repo, tmp_path, monkeypatch, saved, linked
):
    _save(_queue(repo), KEYS[0], project_id=saved)
    monkeypatch.setattr(
        api, "_load_repo_link", lambda root: {"project_id": linked} if linked else {}
    )
    post = _Calls(_ok())
    monkeypatch.setattr(api.requests, "post", post)
    assert api.resend_pending_uploads(quiet=True)["skipped"] == 1
    assert post.calls == []
    assert len(_pending_files(tmp_path)) == 1


def test_resend_skips_scans_for_another_linked_project(repo, tmp_path, monkeypatch):
    _save(_queue(repo), KEYS[0], project_id="project-a")
    monkeypatch.setattr(
        api, "_load_repo_link", lambda root: {"project_id": "project-b"}
    )
    post = _Calls(_ok())
    monkeypatch.setattr(api.requests, "post", post)
    assert api.resend_pending_uploads(quiet=True)["skipped"] == 1
    assert post.calls == []


def test_resend_refuses_managed_gitlab_tokens(repo, tmp_path, monkeypatch):
    _save(_queue(repo), KEYS[0])
    monkeypatch.setattr(api, "get_project_token", lambda: "gitlab_oidc:jwt")
    summary = api.resend_pending_uploads(quiet=True)
    assert "never re-sent" in summary["error"]
    assert len(_pending_files(tmp_path)) == 1


def test_interrupted_upload_is_saved_and_the_interrupt_propagates(
    repo, tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(api.requests, "post", _Calls(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        api.upload_report(_result(repo, quality=[_quality(repo)]), quiet=True)
    [saved] = _pending_files(tmp_path)
    record = _read_pending(saved)
    assert record["last_error"]["code"] == "INTERRUPTED"
    assert json.loads(_pending_uploads.decode_request_body(record))["runs"]
    assert "Upload interrupted" in capsys.readouterr().err


def test_sigterm_during_upload_saves_the_scan(repo, tmp_path, monkeypatch):
    import signal

    def post(url, **kwargs):
        os.kill(os.getpid(), signal.SIGTERM)
        time.sleep(1)
        return _ok()

    monkeypatch.setattr(api.requests, "post", post)
    before = signal.getsignal(signal.SIGTERM)
    with pytest.raises(SystemExit) as exc:
        api.upload_report(_result(repo, quality=[_quality(repo)]), quiet=True)
    assert exc.value.code == 128 + signal.SIGTERM
    assert len(_pending_files(tmp_path)) == 1
    assert signal.getsignal(signal.SIGTERM) == before


def test_quality_gate_exit_is_not_treated_as_an_interruption(
    repo, tmp_path, monkeypatch
):
    monkeypatch.setattr(
        api.requests,
        "post",
        _Calls(
            Resp(
                200,
                {"scanId": "s", "quality_gate": {"passed": False, "new_violations": 1}},
            )
        ),
    )
    with pytest.raises(SystemExit):
        api.upload_report(
            _result(repo, quality=[_quality(repo)]), quiet=True, strict=True
        )
    assert _pending_files(tmp_path) == []


def test_quiet_upload_keeps_stdout_clean(repo, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(api.requests, "post", _Calls(Resp(502)))
    api.upload_report(_result(repo, quality=[_quality(repo)]), quiet=True)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "skylos upload --retry" in captured.err


def test_managed_gitlab_failure_is_never_saved(repo, tmp_path, monkeypatch):
    monkeypatch.setattr(api, "get_project_token", lambda: "gitlab_oidc:jwt")
    prepared = SimpleNamespace(
        metadata={"project_root": ""},
        grade_data=None,
        legacy_payload={},
        legacy_payload_size_bytes=10,
    )
    monkeypatch.setattr(api, "_prepare_report_upload", lambda *a, **k: prepared)
    monkeypatch.setattr(
        "skylos.cloud.gitlab.managed_project_root", lambda *a, **k: None
    )
    post = _Calls(Resp(503))
    monkeypatch.setattr(api.requests, "post", post)
    result = api.upload_report({}, quiet=True)
    assert result["code"] == "GITLAB_DELIVERY_UNKNOWN"
    assert len(post.calls) == 1
    assert _pending_files(tmp_path) == []


# --------------------------------------------------------------------------
# Artifact (large scan) path
# --------------------------------------------------------------------------


def _artifact_init(json_payload):
    return Resp(
        200,
        {
            "scan_id": "s1",
            "upload_id": "u1",
            "artifacts": {
                name: {
                    "upload": {
                        "method": "PUT",
                        "url": f"https://uploads.skylos.dev/{name}",
                    },
                    "artifact_id": name,
                }
                for name in json_payload["artifacts"]
            },
        },
    )


class _ArtifactServer:
    def __init__(self, complete_responses, put_statuses=(200,)):
        self.posts = []
        self.puts = []
        self.complete_responses = list(complete_responses)
        self.put_statuses = list(put_statuses)

    def post(self, url, **kwargs):
        self.posts.append(
            SimpleNamespace(url=url, **{"json": None, "data": None, **kwargs})
        )
        if url == api.REPORT_INIT_URL:
            body = kwargs.get("json")
            if body is None:
                body = json.loads(kwargs["data"])
            return _artifact_init(body)
        item = (
            self.complete_responses.pop(0)
            if len(self.complete_responses) > 1
            else self.complete_responses[0]
        )
        return item

    def put(self, url, data=None, headers=None, timeout=None, **kwargs):
        body = data.read()
        self.puts.append(SimpleNamespace(url=url, size=len(body), body=body))
        status = (
            self.put_statuses.pop(0)
            if len(self.put_statuses) > 1
            else self.put_statuses[0]
        )
        return Resp(status, headers={"ETag": "e"})


def _large_result(repo, count):
    return _result(
        repo,
        quality=[
            {
                "rule_id": f"SKY-Q{300 + i % 40}",
                "file": str(repo / f"pkg/m{i % 500}.py"),
                "line": i % 300 + 1,
                "severity": "MEDIUM",
                "message": f"Function f_{i} is too complex.",
            }
            for i in range(count)
        ],
    )


def test_large_scan_uses_artifact_upload_with_one_key(repo, monkeypatch):
    monkeypatch.setenv("SKYLOS_INLINE_UPLOAD_LIMIT_BYTES", "20000")
    server = _ArtifactServer([_ok("big")])
    monkeypatch.setattr(api.requests, "post", server.post)
    monkeypatch.setattr("skylos.api._artifacts.requests.put", server.put)
    result = api.upload_report(_large_result(repo, 300), quiet=True)
    assert result["success"] and result["scan_id"] == "big"
    assert [c.url for c in server.posts] == [
        api.REPORT_INIT_URL,
        api.REPORT_COMPLETE_URL,
    ]
    assert len({c.headers["Idempotency-Key"] for c in server.posts}) == 1
    assert server.puts and all(p.size > 0 for p in server.puts)


def test_complete_failure_saves_artifact_upload_for_resend(repo, tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_INLINE_UPLOAD_LIMIT_BYTES", "20000")
    server = _ArtifactServer([Resp(504)])
    monkeypatch.setattr(api.requests, "post", server.post)
    monkeypatch.setattr("skylos.api._artifacts.requests.put", server.put)
    result = api.upload_report(_large_result(repo, 300), quiet=True)
    assert result["retryable"] is True
    [saved] = _pending_files(tmp_path)
    record = _read_pending(saved)
    assert record["mode"] == "artifact"
    assert record["endpoint"] == api.REPORT_INIT_URL
    assert record["artifacts"]["scan_report"]["sha256"]
    key = record["idempotency_key"]
    assert {c.headers["Idempotency-Key"] for c in server.posts} == {key}

    resend = _ArtifactServer([_ok("big")])
    monkeypatch.setattr(api.requests, "post", resend.post)
    monkeypatch.setattr("skylos.api._artifacts.requests.put", resend.put)
    summary = api.resend_pending_uploads(quiet=True)
    assert summary["sent"] == 1
    assert {c.headers["Idempotency-Key"] for c in resend.posts} == {key}
    # The init request and the uploaded files are the bytes sent the first time.
    assert resend.posts[0].data == _wire_bytes(server.posts[0].json)
    assert [p.body for p in resend.puts] == [p.body for p in server.puts]


def test_storage_put_retries_only_retryable_statuses(repo, monkeypatch):
    monkeypatch.setenv("SKYLOS_INLINE_UPLOAD_LIMIT_BYTES", "20000")
    server = _ArtifactServer([_ok()], put_statuses=[503, 200])
    monkeypatch.setattr(api.requests, "post", server.post)
    monkeypatch.setattr("skylos.api._artifacts.requests.put", server.put)
    assert api.upload_report(_large_result(repo, 300), quiet=True)["success"]
    assert len(server.puts) >= 2

    denied = _ArtifactServer([_ok()], put_statuses=[403])
    monkeypatch.setattr(api.requests, "post", denied.post)
    monkeypatch.setattr("skylos.api._artifacts.requests.put", denied.put)
    result = api.upload_report(_large_result(repo, 300), quiet=True)
    assert result["success"] is False and result["retryable"] is False
    assert len(denied.puts) == 1
    assert "HTTP 403" in result["error"]


def test_dropping_an_optional_artifact_uses_a_new_key(repo, monkeypatch):
    monkeypatch.setenv("SKYLOS_INLINE_UPLOAD_LIMIT_BYTES", "20000")
    result = _large_result(repo, 300)
    result["definitions"] = {"pkg.f": {"type": "function"}}
    posts = []

    def post(url, **kwargs):
        posts.append(SimpleNamespace(url=url, **kwargs))
        if url == api.REPORT_INIT_URL and len(posts) == 1:
            return Resp(400, {"error": "Unsupported artifact 'definitions'"})
        if url == api.REPORT_INIT_URL:
            return _artifact_init(kwargs["json"])
        return _ok()

    monkeypatch.setattr(api.requests, "post", post)
    monkeypatch.setattr(
        "skylos.api._artifacts.requests.put", _ArtifactServer([_ok()]).put
    )
    assert api.upload_report(result, quiet=True)["success"]
    keys = [c.headers["Idempotency-Key"] for c in posts]
    assert keys[0] != keys[1]
    assert keys[1] == keys[2]


@pytest.mark.slow
@pytest.mark.skipif(
    os.getenv("SKYLOS_RUN_SLOW_UPLOAD_TESTS") != "1",
    reason="about a minute; set SKYLOS_RUN_SLOW_UPLOAD_TESTS=1",
)
def test_fifty_thousand_findings_take_the_artifact_path(repo, monkeypatch):
    server = _ArtifactServer([_ok("huge")])
    monkeypatch.setattr(api.requests, "post", server.post)
    monkeypatch.setattr("skylos.api._artifacts.requests.put", server.put)
    started = time.perf_counter()
    result = api.upload_report(_large_result(repo, 50_000), quiet=True)
    elapsed = time.perf_counter() - started
    assert result["success"] and result["scan_id"] == "huge"
    assert [c.url for c in server.posts] == [
        api.REPORT_INIT_URL,
        api.REPORT_COMPLETE_URL,
    ]
    init = server.posts[0].json
    assert init["summary"]["finding_count"] == 50_000
    assert (
        init["summary"]["legacy_payload_size_bytes"]
        > api._legacy_inline_upload_limit_bytes()
    )
    assert elapsed < 300


# --------------------------------------------------------------------------
# Contract version check
# --------------------------------------------------------------------------


@pytest.fixture
def contract_check(monkeypatch):
    monkeypatch.setenv("SKYLOS_UPLOAD_CONTRACT_CHECK", "1")
    _contract_check.reset_contract_check()
    yield
    _contract_check.reset_contract_check()


def test_contract_check_url_follows_the_api_base():
    assert (
        _contract_check.contract_check_url("https://skylos.dev")
        == "https://skylos.dev/api/report/contract"
    )
    assert (
        _contract_check.contract_check_url("https://x/api")
        == "https://x/api/report/contract"
    )


def _start(get):
    _contract_check.start_contract_version_check(
        "https://cloud.example/api/report/contract",
        get,
        validate=api._validate_api_request_url,
    )


def test_newer_contract_prints_one_upgrade_line(contract_check):
    calls = []

    def get(url, **kwargs):
        calls.append(kwargs)
        return Resp(200, {"version": 2, "sha256": "x"})

    _start(get)
    _start(get)
    notice = _contract_check.newer_contract_notice(join_timeout=2)
    assert notice == (
        "Skylos Cloud uses upload format v2; this CLI sends v1. "
        "Run 'pip install -U skylos' to update."
    )
    assert _contract_check.newer_contract_notice() is None  # once per process
    assert len(calls) == 1
    assert calls[0]["timeout"] == (1.5, 2.0)


@pytest.mark.parametrize(
    "get",
    [
        lambda url, **kw: Resp(200, {"version": 1, "sha256": "x"}),
        lambda url, **kw: Resp(404),
        lambda url, **kw: Resp(200, None, text="<html>"),
        lambda url, **kw: Resp(200, {"version": "2"}),
        lambda url, **kw: (_ for _ in ()).throw(
            requests.exceptions.ConnectTimeout("t")
        ),
        lambda url, **kw: (_ for _ in ()).throw(RuntimeError("boom")),
    ],
)
def test_contract_check_is_silent_when_same_or_unavailable(contract_check, get):
    _start(get)
    assert _contract_check.newer_contract_notice(join_timeout=2) is None


def test_contract_check_does_not_hold_up_an_upload(contract_check):
    release = threading.Event()

    def slow_get(url, **kwargs):
        release.wait(5)
        return Resp(200, {"version": 9})

    _start(slow_get)
    started = time.perf_counter()
    assert _contract_check.newer_contract_notice(join_timeout=0.2) is None
    assert time.perf_counter() - started < 1
    release.set()


def test_contract_check_can_be_disabled(monkeypatch):
    monkeypatch.setenv("SKYLOS_UPLOAD_CONTRACT_CHECK", "0")
    _contract_check.reset_contract_check()
    _start(lambda *a, **k: pytest.fail("network used"))
    assert _contract_check.newer_contract_notice() is None


# --------------------------------------------------------------------------
# End to end against a local HTTP server
# --------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self._respond(
            self.server.get_script.pop(0) if self.server.get_script else (404, {}, {})
        )

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        self.server.raw.append(raw)
        body = json.loads(raw or b"{}")
        self.server.seen.append((self.path, dict(self.headers), body))
        script = self.server.script
        self._respond(script.pop(0) if len(script) > 1 else script[0])

    def _respond(self, item):
        status, body, headers = item
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def local_cloud(monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.seen, server.script, server.get_script, server.raw = [], [], [], []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setattr(api, "BASE_URL", base)
    monkeypatch.setattr(api, "REPORT_URL", f"{base}/api/report")
    monkeypatch.setattr(api, "REPORT_INIT_URL", f"{base}/api/report/init")
    monkeypatch.setattr(api, "REPORT_COMPLETE_URL", f"{base}/api/report/complete")
    yield server
    server.shutdown()
    server.server_close()


def test_local_server_retries_then_succeeds_with_one_key(repo, local_cloud, capsys):
    local_cloud.script = [
        (503, {"code": "UNAVAILABLE", "error": "Down.", "retryable": True}, {}),
        (502, {}, {}),
        (200, {"scanId": "scan-e2e", "quality_gate": {"passed": True}}, {}),
    ]
    result = api.upload_report(_result(repo, quality=[_quality(repo)]))
    assert result["success"] and result["scan_id"] == "scan-e2e"
    assert len(local_cloud.seen) == 3
    keys = {headers["Idempotency-Key"] for _, headers, _ in local_cloud.seen}
    assert len(keys) == 1
    assert all(h["X-Skylos-Upload-Contract"] == "1" for _, h, _ in local_cloud.seen)
    assert "retrying (2/4)" in capsys.readouterr().out


def test_local_server_outage_then_resend_via_cli(
    repo, tmp_path, local_cloud, monkeypatch, capsys
):
    local_cloud.script = [(503, {"error": "Down."}, {})]
    result = api.upload_report(_result(repo, quality=[_quality(repo)]), quiet=True)
    assert result["retryable"] and len(local_cloud.seen) == 4
    first_key = local_cloud.seen[0][1]["Idempotency-Key"]
    first_bytes = local_cloud.raw[0]
    assert set(local_cloud.raw) == {first_bytes}  # every retry sent the same bytes

    local_cloud.seen.clear()
    local_cloud.raw.clear()
    local_cloud.script = [
        (200, {"scanId": "scan-late", "quality_gate": {"passed": True}}, {})
    ]
    from skylos.commands.upload_cmd import run_upload_command

    assert run_upload_command(["--retry"]) == 0
    assert [h["Idempotency-Key"] for _, h, _ in local_cloud.seen] == [first_key]
    # The resend is byte-identical to the original request.
    assert local_cloud.raw == [first_bytes]
    out = capsys.readouterr().out
    assert "Saved uploads: 1 sent." in out
    assert _pending_files(tmp_path) == []


def test_contract_check_against_local_server(repo, local_cloud, monkeypatch, capsys):
    monkeypatch.setenv("SKYLOS_UPLOAD_CONTRACT_CHECK", "1")
    _contract_check.reset_contract_check()
    try:
        local_cloud.get_script = [(200, {"version": 2, "sha256": "abc"}, {})]
        local_cloud.script = [
            (200, {"scanId": "s", "quality_gate": {"passed": True}}, {})
        ]
        api.upload_report(_result(repo, quality=[_quality(repo)]))
        assert "Run 'pip install -U skylos' to update." in capsys.readouterr().out
    finally:
        _contract_check.reset_contract_check()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def test_upload_command_is_registered_and_documented():
    from skylos.cli_core.dispatch import EARLY_COMMAND_HANDLERS
    from skylos.ui.help import COMMANDS

    assert EARLY_COMMAND_HANDLERS["upload"] == "_run_upload_command"
    assert any(item["name"] == "skylos upload --retry" for item in COMMANDS)


def test_upload_list_shows_saved_scans(repo, tmp_path, capsys):
    _save(_queue(repo), KEYS[0])
    from skylos.commands.upload_cmd import run_upload_command

    assert run_upload_command(["--list"]) == 0
    out = capsys.readouterr().out
    assert "1 scan is waiting to be sent" in out
    assert "skylos upload --retry" in out


def test_upload_retry_json_summary(repo, tmp_path, monkeypatch, capsys):
    _save(_queue(repo), KEYS[0])
    monkeypatch.setattr(api.requests, "post", _Calls(Resp(503)))
    from skylos.commands.upload_cmd import run_upload_command

    assert run_upload_command(["--retry", "--json"]) == 1
    summary = json.loads(capsys.readouterr().out)
    assert summary["kept"] == 1 and summary["total"] == 1


def test_upload_help_via_main(monkeypatch, capsys):
    import skylos.cli as cli

    monkeypatch.setattr(sys, "argv", ["skylos", "upload", "--help"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    assert "--retry" in capsys.readouterr().out
