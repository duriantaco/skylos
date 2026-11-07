"""Mock JSON adapter contracts; these do not run or benchmark Bandit."""

import json
import subprocess

import pytest

from skylos.benchmarks import security as benchmark


_HASH_MESSAGES = {
    "MD5": "Use of weak MD5 hash for security. Consider usedforsecurity=False",
    "SHA1": "Use of weak SHA1 hash for security. Consider usedforsecurity=False",
}


def _scan_record(tmp_path, monkeypatch, **record):
    finding = {
        "test_id": "B324",
        "issue_text": "",
        "filename": "./app.py",
        "line_number": 3,
        "issue_severity": "HIGH",
    }
    finding.update(record)
    monkeypatch.setattr(benchmark.shutil, "which", lambda name: "/unused/bandit")

    def fake_run(cmd, **kwargs):
        assert cmd == ["/unused/bandit", "-r", ".", "-f", "json", "-q"]
        assert kwargs["cwd"] == str(tmp_path)
        return subprocess.CompletedProcess(
            cmd, 1, json.dumps({"results": [finding], "errors": []}), ""
        )

    monkeypatch.setattr(benchmark.subprocess, "run", fake_run)
    return benchmark._scan_bandit_case(tmp_path)["danger"][0]


@pytest.mark.parametrize(
    ("test_id", "issue_text", "expected"),
    [
        (
            "B501",
            "Call to requests with verify=False disabling SSL certificate checks, security issue.",
            "SKY-D210",
        ),
        (
            "B311",
            "Standard pseudo-random generators are not suitable for security/cryptographic purposes.",
            "SKY-D250",
        ),
        ("B324", _HASH_MESSAGES["MD5"], "SKY-D207"),
        ("B324", _HASH_MESSAGES["SHA1"], "SKY-D208"),
        ("B608", "Possible SQL injection vector.", "SKY-D211"),
    ],
)
def test_matching_bandit_findings_use_the_native_rule_identity(
    tmp_path, monkeypatch, test_id, issue_text, expected
):
    # Templates verified against PyCQA/bandit at
    # 48ef27bd1bbc32f4e585c92310f7a574e87f6b04, not fixture intent.
    finding = _scan_record(
        tmp_path, monkeypatch, test_id=test_id, issue_text=issue_text
    )
    assert finding["rule_id"] == expected
    assert finding["bandit_rule_id"] == test_id


@pytest.mark.parametrize(
    "message",
    [
        None,
        207,
        ["MD5"],
        {"algorithm": "MD5"},
        "",
        "MD5",
        "Use of weak MD4 hash for security. Consider usedforsecurity=False",
        "Use of weak SHA hash for security. Consider usedforsecurity=False",
        "Use of weak MD4, MD5, or SHA1 hash for security.",
        "Use of insecure crypt.METHOD_MD5 hash function.",
        "Use of weak MD5 hash for security. Consider usedforsecurity=False; or SHA1",
        "Example: Use of weak MD5 hash for security. Consider usedforsecurity=False",
        "Use of weak MD5 hash for security. Consider usedforsecurity=False\n",
        "Use of weak SHA256 hash for security. Consider usedforsecurity=False",
        "SKY-D207",
    ],
)
def test_ambiguous_or_malformed_b324_does_not_claim_a_native_algorithm(
    tmp_path, monkeypatch, message
):
    finding = _scan_record(tmp_path, monkeypatch, issue_text=message)
    assert finding["rule_id"] == finding["bandit_rule_id"] == "B324"


@pytest.mark.parametrize("test_id", ["B303", "B612", "B999"])
def test_a_hash_message_does_not_change_another_bandit_rule(
    tmp_path, monkeypatch, test_id
):
    finding = _scan_record(
        tmp_path,
        monkeypatch,
        test_id=test_id,
        issue_text=_HASH_MESSAGES["MD5"],
    )
    assert finding["rule_id"] == test_id


@pytest.mark.parametrize("field", ["filename", "code", "issue_text", "test_name"])
def test_other_bandit_fields_cannot_impersonate_a_native_rule(
    tmp_path, monkeypatch, field
):
    finding = _scan_record(tmp_path, monkeypatch, **{field: "SKY-D207"})
    assert finding["rule_id"] == "B324"
