"""Path alerts, review evidence and explicit listing through the normal policy."""

import json
from copy import deepcopy

import pytest

from skylos.analyzer import analyze
from skylos.reporting.advice_policy import apply_advice_policy
from skylos.reporting.issue_summary import issue_summary
from skylos.reporting.listing import is_listed, is_path_review


def _candidate(rule="SKY-D215"):
    return {
        "file": "storage.py",
        "rule_id": rule,
        "severity": "HIGH",
        "line": 5,
        "metadata": {
            "path_provenance": {
                "version": 1,
                "complete_project": True,
                "status": "unknown",
                "disposition": "needs_review",
                "unknown": [["callback unresolved", "file operation"]],
            }
        },
    }


def _policy(*rows, **options):
    return apply_advice_policy({"danger": list(rows)}, **options)


@pytest.mark.parametrize("rule", ["SKY-D215", "SKY-D324", "SKY-D325"])
def test_only_a_validated_unresolved_candidate_goes_to_review(rule):
    unknown = _candidate(rule)
    positive = deepcopy(unknown)
    positive["line"] += 1
    positive["metadata"]["path_provenance"]["untrusted"] = [
        ["request input", "file operation"]
    ]
    result = _policy(unknown, positive)
    assert [is_path_review(row) for row in result["danger"]] == [True, False]
    assert [is_listed(row, "security") for row in result["danger"]] == [False, True]
    assert issue_summary(result)["by_category"]["security"] == 1
    assert issue_summary(result)["path_review_count"] == 1
    for options in ({"all_advice": True}, {"explicit_rules": [rule]}):
        restored = _policy(unknown, **options)
        assert is_listed(restored["danger"][0], "security")
        assert issue_summary(restored)["path_review_count"] == 0


@pytest.mark.parametrize(
    "change",
    [
        {"complete_project": False},
        {"version": True},
        {"version": 2},
        {"status": "safe"},
        {"shared_temp_path": True},
        {"unknown": [[]]},
        {"unknown": [[" "]]},
        {"unknown": [[None]]},
        {"unknown": "unresolved"},
        {"disposition": None},
        {"status": "conditional_http_guard", "guarded_http": [["observed check"]]},
    ],
)
def test_incomplete_or_conflicting_contract_stays_primary(change):
    row = _candidate()
    row["metadata"]["path_provenance"].update(change)
    assert is_listed(_policy(row)["danger"][0], "security")


def test_independent_trace_other_languages_and_legacy_evidence_stay_primary():
    matched, legacy, js, unrelated = [_candidate() for _ in range(4)]
    matched["metadata"]["security_trace"] = {"status": "source_to_sink"}
    legacy.pop("metadata")
    js["file"] = "storage.js"
    unrelated["rule_id"] = "SKY-D211"
    result = _policy(matched, legacy, js, unrelated)
    assert issue_summary(result)["by_category"]["security"] == 4
    assert issue_summary(result)["path_review_count"] == 0


def test_predictable_shared_files_require_a_link_following_operation(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    # Input to the static scanner. None of the named files are opened by the test.
    code = """from pathlib import Path
import os
import tempfile

def operations():
    Path('/tmp/known').read_text()
    Path('/var/tmp/known').write_text('data')
    os.open('/dev/shm/known', os.O_WRONLY | os.O_CREAT, 0o600)
    os.open('/tmp/exclusive', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    (Path(tempfile.gettempdir()) / 'known').read_bytes()
    (Path('/tmp') / '/srv/app/fixed').read_text()
    with tempfile.TemporaryDirectory() as directory:
        (Path(directory) / 'owned').write_text('data')
    Path('/tmp-other/private').read_bytes()
    with open('/tmp/exclusive', 'x') as handle:
        handle.write('data')
    '/tmp/not-a-path-object'.read_text()

def custom_open():
    def open(label, mode):
        return label
    return open('/tmp/nonfile', 'w')
"""
    source = tmp_path / "storage.py"
    source.write_text(code)
    result = json.loads(
        analyze(str(tmp_path), enable_danger=True, trace_file=False, grep_verify=False)
    )
    assert not result.get("analysis_errors")
    rows = _policy(*result.get("danger", []))["danger"]
    paths = [
        (row["rule_id"], row["line"])
        for row in rows
        if row["rule_id"] in {"SKY-D324", "SKY-D325"}
    ]
    assert sorted(paths) == sorted(
        [("SKY-D325", 6), ("SKY-D324", 7), ("SKY-D324", 8), ("SKY-D325", 10)]
    )
    for row in rows:
        if (row["rule_id"], row["line"]) in paths:
            assert is_listed(row, "security")
            assert row["metadata"]["path_provenance"]["shared_temp_path"] is True


def test_read_capable_opens_and_observed_reads_have_distinct_messages(tmp_path):
    source = tmp_path / "storage.py"
    source.write_text(
        "import os\n"
        "from pathlib import Path\n"
        "def get_descriptor():\n"
        "    return os.open('/tmp/descriptor', os.O_RDONLY)\n"
        "def get_stream():\n"
        "    return open('/tmp/stream', 'rb')\n"
        "def get_contents():\n"
        "    return Path('/tmp/contents').read_bytes()\n"
        "def read_descriptor():\n"
        "    fd = os.open('/tmp/direct', os.O_RDONLY)\n"
        "    return os.read(fd, 8)\n"
        "def read_stream():\n"
        "    return open('/tmp/stream-read', 'rb').read()\n"
    )
    result = json.loads(
        analyze(str(tmp_path), enable_danger=True, trace_file=False, grep_verify=False)
    )
    assert not result.get("analysis_errors")
    rows = {r["symbol"]: r for r in result["danger"] if r["rule_id"] == "SKY-D325"}
    assert set(rows) == {
        "get_descriptor", "get_stream", "get_contents", "read_descriptor", "read_stream"
    }
    for symbol, row in rows.items():
        assert row["severity"] == "MEDIUM"
        assert is_listed(row, "security")
        assert row["metadata"]["path_provenance"]["shared_temp_path"] is True
        if symbol in {"get_descriptor", "get_stream"}:
            assert row["metadata"]["path_operation"] == "read_capable_open"
            assert row["message"].startswith("A read-capable open may follow a symlink")
        else:
            assert "symlink-following read" in row["message"]
