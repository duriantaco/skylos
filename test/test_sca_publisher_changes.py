"""The npm publisher bridge must not trust scanned lockfile paths or metadata."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from skylos.rules.sca.publisher_changes import RULE_ID, scan_publisher_changes

npm_publisher = pytest.importorskip("ca9.npm_publisher")
NOW = datetime(2018, 11, 26, tzinfo=timezone.utc)


def _lock(
    *, resolved="https://registry.npmjs.org/event-stream/-/event-stream-3.3.5.tgz"
):
    return {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "app",
                "version": "1.0.0",
                "dependencies": {"event-stream": "^3.3.5"},
            },
            "node_modules/event-stream": {"version": "3.3.5", "resolved": resolved},
        },
    }


def _history():
    return {
        "name": "event-stream",
        "time": {
            "3.3.4": "2016-07-17T07:24:09.767Z",
            "3.3.5": "2018-09-05T02:00:00.000Z",
        },
        "versions": {
            "3.3.4": {"_npmUser": {"name": "dominictarr"}},
            "3.3.5": {"_npmUser": {"name": "right9ctrl"}},
        },
    }


def _write_lock(directory, data=None):
    path = directory / "package-lock.json"
    path.write_text(json.dumps(data if data is not None else _lock()))
    return path


def test_disabled_scan_does_not_read_or_fetch(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("disabled check must not access npm")

    monkeypatch.setattr(npm_publisher, "_fetch_json", forbidden)
    _write_lock(tmp_path)

    result = scan_publisher_changes(tmp_path)

    assert result.findings == []
    assert result.warnings == []
    assert result.receipt["status"] == "disabled"
    assert result.receipt["selected_lockfiles"] == 0


def test_historical_handover_is_a_separate_review_finding(tmp_path, monkeypatch):
    path = _write_lock(tmp_path)
    requests = []

    def fake_fetch(url, *, max_bytes):
        requests.append(url)
        return {"objects": []} if "/-/v1/search?" in url else _history()

    monkeypatch.setattr(npm_publisher, "_fetch_json", fake_fetch)

    result = scan_publisher_changes(tmp_path, enabled=True, now=NOW)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding["rule_id"] == RULE_ID
    assert finding["severity"] == "WARN"
    assert finding["file"] == str(path)
    assert finding["line"] >= 1
    assert finding["metadata"]["package_name"] == "event-stream"
    assert finding["metadata"]["package_version"] == "3.3.5"
    assert finding["metadata"]["previous_publisher"] == "dominictarr"
    assert finding["metadata"]["new_publisher"] == "right9ctrl"
    assert finding["metadata"]["dormancy_days"] >= 180
    assert finding["metadata"]["occurrences"] == [
        {
            "file": str(path),
            "line": finding["line"],
            "package_path": "node_modules/event-stream",
        }
    ]
    assert len(requests) == 2
    assert result.receipt["status"] == "complete"
    assert result.receipt["submitted_packages"] == 1


@pytest.mark.parametrize(
    "contents",
    [
        '{"lockfileVersion":3,"lockfileVersion":3,"packages":{}}',
        "X" * 10_000_001,
    ],
)
def test_invalid_or_oversized_lock_is_skipped_before_ca9(
    tmp_path, monkeypatch, contents
):
    (tmp_path / "package-lock.json").write_text(contents)

    def forbidden(*args, **kwargs):
        raise AssertionError("invalid source must not reach npm")

    monkeypatch.setattr(npm_publisher, "_fetch_json", forbidden)
    result = scan_publisher_changes(tmp_path, enabled=True, now=NOW)

    assert result.findings == []
    assert result.receipt["status"] == "partial"
    assert result.receipt["submitted_packages"] == 0
    assert result.warnings


def test_symlinked_lock_is_skipped_without_opening_target(tmp_path, monkeypatch):
    target = tmp_path / "outside.json"
    target.write_text(json.dumps(_lock()))
    (tmp_path / "package-lock.json").symlink_to(target)

    def forbidden(*args, **kwargs):
        raise AssertionError("symlinked source must not reach npm")

    monkeypatch.setattr(npm_publisher, "_fetch_json", forbidden)
    result = scan_publisher_changes(tmp_path, enabled=True, now=NOW)

    assert result.findings == []
    assert result.receipt["status"] == "partial"
    assert "symlinked" in result.warnings[0]


def test_private_or_alias_identity_is_not_queried_as_public_npm(tmp_path, monkeypatch):
    data = _lock(resolved="https://packages.example.test/event-stream-3.3.5.tgz")
    data["packages"][""]["dependencies"]["alias"] = "npm:actual@^1.0.0"
    data["packages"]["node_modules/alias"] = {
        "name": "actual",
        "version": "1.0.0",
        "resolved": "https://registry.npmjs.org/actual/-/actual-1.0.0.tgz",
    }
    data["packages"][""]["dependencies"]["same-alias"] = "npm:same-alias@^1.0.0"
    data["packages"]["node_modules/same-alias"] = {
        "version": "1.0.0",
        "resolved": "https://registry.npmjs.org/same-alias/-/same-alias-1.0.0.tgz",
    }
    _write_lock(tmp_path, data)

    def forbidden(*args, **kwargs):
        raise AssertionError("non-public or aliased identity must not reach npm")

    monkeypatch.setattr(npm_publisher, "_fetch_json", forbidden)
    result = scan_publisher_changes(tmp_path, enabled=True, now=NOW)

    assert result.findings == []
    assert result.receipt["status"] == "complete"
    assert result.receipt["submitted_packages"] == 0


def test_shrinkwrap_presence_overrides_package_lock(tmp_path, monkeypatch):
    _write_lock(tmp_path)
    (tmp_path / "npm-shrinkwrap.json").write_text("invalid")

    def forbidden(*args, **kwargs):
        raise AssertionError("shadowed lock must not reach npm")

    monkeypatch.setattr(npm_publisher, "_fetch_json", forbidden)
    result = scan_publisher_changes(tmp_path, enabled=True, now=NOW)

    assert result.findings == []
    assert result.receipt["ignored_package_locks"] == 1
    assert result.receipt["selected_lockfiles"] == 0
    assert result.receipt["status"] == "partial"
    assert "npm-shrinkwrap.json" in result.warnings[0]


def test_registry_fetch_warning_is_reported_as_partial_coverage(tmp_path, monkeypatch):
    _write_lock(tmp_path)

    def fail_fetch(url, *, max_bytes):
        raise npm_publisher.RegistryFetchError("registry unavailable")

    monkeypatch.setattr(npm_publisher, "_fetch_json", fail_fetch)
    result = scan_publisher_changes(tmp_path, enabled=True, now=NOW)

    assert result.findings == []
    assert result.receipt["status"] == "partial"
    assert result.receipt["submitted_packages"] == 1
    assert "registry fetch failed" in result.warnings[0]


def test_direct_package_limit_is_deterministic_and_reported(tmp_path, monkeypatch):
    names = [f"dep-{number:02}" for number in range(30)]
    data = {"name": "app", "lockfileVersion": 3, "packages": {"": {"dependencies": {}}}}
    for name in reversed(names):
        data["packages"][""]["dependencies"][name] = "^1.0.0"
        data["packages"][f"node_modules/{name}"] = {
            "version": "1.0.0",
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz",
        }
    _write_lock(tmp_path, data)
    fetched = []

    def fake_fetch(url, *, max_bytes):
        name = url.removeprefix("https://registry.npmjs.org/")
        fetched.append(name)
        return {
            "name": name,
            "time": {"1.0.0": "2018-01-01T00:00:00Z"},
            "versions": {"1.0.0": {"_npmUser": {"name": "owner"}}},
        }

    monkeypatch.setattr(npm_publisher, "_fetch_json", fake_fetch)
    result = scan_publisher_changes(tmp_path, enabled=True, now=NOW)

    assert fetched == names[:25]
    assert result.findings == []
    assert result.receipt["candidate_packages"] == 30
    assert result.receipt["submitted_packages"] == 25
    assert result.receipt["status"] == "partial"
    assert "publisher_candidate_limit_exceeded" in result.receipt["limit_reasons"]
    assert any("25-package limit" in warning for warning in result.warnings)
