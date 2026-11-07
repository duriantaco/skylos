"""Structured credentials reach output with exact spans and no extra alerts."""

from __future__ import annotations

import base64
import hashlib
import html
import json
from urllib.parse import quote

import pytest

from skylos.audit.redaction import REDACTION, redact_text, sanitize_for_audit
from skylos.cicd.evidence import sanitize_bounded_payload, sanitize_untrusted_text
from skylos.rules.secrets import scan_ctx


def _jwk(label=b"independent structured credential integration fixture"):
    key = base64.urlsafe_b64encode(hashlib.sha256(label).digest()).decode().rstrip("=")
    return {"kty": "oct", "k": key}


def _azure():
    key = base64.b64encode(
        hashlib.sha512(b"public synthetic Azure key fixture").digest()
    ).decode()
    return (
        "DefaultEndpointsProtocol=https;AccountName=depthfixture;AccountKey="
        + key
        + ";EndpointSuffix=core.windows.net"
    ), key


def _scan(text, path="README.md", **options):
    return scan_ctx(
        {"relpath": path, "lines": text.splitlines(True), "tree": None}, **options
    )


@pytest.mark.parametrize(
    "path", ["README.md", "credentials.json", "tests/test_keys.py", "src/settings.ts"]
)
def test_private_jwk_has_one_masked_exact_component_finding(path):
    record = _jwk()
    source = "\n" + json.dumps(record) + "\n"
    (finding,) = _scan(source, path)
    assert finding["provider"] == "jwk_symmetric_key"
    assert finding["rule_id"] == "SKY-S101"
    assert finding["line"] == 2
    assert source.splitlines()[1][finding["col"] : finding["end_col"]] == record["k"]
    assert finding["structured_credential"]["validation"] == "structural"
    assert record["k"] not in json.dumps(finding)


@pytest.mark.parametrize(
    "path", ["README.md", "connection.json", "tests/test_config.py", "src/settings.py"]
)
def test_azure_complete_connection_record_has_one_masked_component(path):
    source, key = _azure()
    (finding,) = _scan(source, path)
    assert finding["provider"] == "azure_storage_account_key"
    assert source[finding["col"] : finding["end_col"]] == key
    assert finding["structured_credential"]["verified"] is False
    assert key not in json.dumps(finding)


@pytest.mark.parametrize(
    "kind,encoding",
    [("jwk", encoding) for encoding in ("base64", "percent", "html", "utf16-base64")]
    + [("azure", encoding) for encoding in ("base64", "percent", "utf16-base64")],
)
def test_structured_records_survive_bounded_decoding(kind, encoding):
    source = json.dumps(_jwk()) if kind == "jwk" else _azure()[0]
    if encoding == "base64":
        encoded = base64.b64encode(source.encode()).decode()
        expected = ["base64"]
    elif encoding == "percent":
        encoded = quote(source, safe="")
        expected = ["percent"]
    elif encoding == "html":
        encoded = html.escape(source, quote=True)
        expected = ["html"]
    else:
        encoded = base64.b64encode(b"\xff\xfe" + source.encode("utf-16-le")).decode()
        expected = ["base64", "utf16le"]
    (finding,) = _scan('VALUE = "' + encoded + '"\n')
    assert finding["provider"] == (
        "jwk_symmetric_key" if kind == "jwk" else "azure_storage_account_key"
    )
    assert finding["decoding"]["encodings"] == expected
    assert finding["structured_credential"]["validation"] == "structural"


def test_two_private_keys_in_one_encoded_container_remain_two_occurrences():
    first, second = _jwk(), _jwk(b"second publicly derived fixture key")
    encoded = base64.b64encode(json.dumps([first, second]).encode()).decode()
    findings = _scan(encoded)
    assert [f["provider"] for f in findings] == ["jwk_symmetric_key"] * 2
    assert (
        findings[0]["decoding"]["source_path"] != findings[1]["decoding"]["source_path"]
    )


def test_public_jwk_and_unknown_sibling_do_not_widen_generic_suppression():
    public = {"kty": "OKP", "crv": "Ed25519", "x": _jwk()["k"]}
    assert _scan(json.dumps(public)) == []
    record = {
        **_jwk(),
        "API_SECRET": hashlib.sha256(b"another actual literal").hexdigest(),
    }
    findings = _scan(json.dumps(record), "settings.json")
    assert {f["provider"] for f in findings} == {"jwk_symmetric_key", "generic"}


def test_structured_records_honor_inline_ignore_and_allowlist():
    source = json.dumps(_jwk())
    assert _scan(source + " # skylos: ignore[SKY-S101]") == []
    assert _scan(source, allowlist_patterns=["kty"]) == []


def test_line_contexts_without_newlines_preserve_physical_locations():
    source = json.dumps(_jwk(), indent=2)
    findings = scan_ctx(
        {"relpath": "README.md", "lines": source.splitlines(), "tree": None}
    )
    (finding,) = findings
    assert finding["line"] == 3
    assert source.splitlines()[2][finding["col"] : finding["end_col"]] == _jwk()["k"]


def test_structured_source_budget_stays_visible_and_raw_provider_survives(monkeypatch):
    import skylos.rules.secret_credentials as credentials

    monkeypatch.setattr(credentials, "MAX_RECORD_TEXT", 32)
    token = "ghp_" + "K8mN2pQ6rS0tU4vW8xY1zA5bC9dE3fG7hJ2k"
    findings = _scan(json.dumps(_jwk()) + "\n" + token)
    assert any(f.get("provider") == "github" for f in findings)
    assert any(f["rule_id"] == "SKY-ANALYSIS-INCOMPLETE" for f in findings)


@pytest.mark.parametrize("kind", ["jwk", "azure"])
def test_structured_secrets_are_masked_in_audit_and_ci_text(kind):
    record = _jwk()
    source, key = (json.dumps(record), record["k"]) if kind == "jwk" else _azure()
    audit = redact_text("Review " + source)
    ci = sanitize_untrusted_text("Review " + source, preserve_newlines=True)
    assert key not in audit
    assert key not in ci
    assert REDACTION in audit
    assert "[redacted]" in ci


def test_nested_jwk_private_member_masking_preserves_public_context():
    record = _jwk()
    audit = sanitize_for_audit({"review": [record]})
    ci = sanitize_bounded_payload({"review": [record]})
    assert audit["review"][0] == {"kty": "oct", "k": REDACTION}
    assert ci["review"][0] == {"kty": "oct", "k": "[redacted]"}


def test_public_jwk_redaction_keeps_public_members():
    public = {"kty": "OKP", "crv": "Ed25519", "x": _jwk()["k"]}
    assert sanitize_for_audit(public) == public
    assert sanitize_bounded_payload(public) == public


@pytest.mark.parametrize("truncated", [False, True])
def test_jwk_private_fields_stay_masked_when_display_truncates_record(truncated):
    key = _jwk()["k"]
    source = json.dumps({"kty": "oct", "k": key, "padding": "a" * 5000})
    if truncated:
        source = source[:300]
    assert key not in redact_text(source)
    assert key not in sanitize_untrusted_text(source, max_length=250)


def test_jwk_redaction_uses_same_object_and_keeps_public_fields():
    key = _jwk()["k"]
    source = json.dumps([{"kty": "oct"}, {"k": key}])
    assert redact_text(source) == source
    public = json.dumps({"kty": "OKP", "crv": "Ed25519", "x": key})
    assert redact_text(public) == public


def test_private_member_before_key_type_and_nested_rsa_parts_are_masked():
    key = _jwk()["k"]
    source = json.dumps({"k": key, "kty": "oct"})
    assert key not in redact_text(source)
    other = json.dumps({"kty": "RSA", "oth": [{"r": key, "d": key, "t": key}]})
    assert key not in redact_text(other)


def _aws_profile():
    identifier = "AKIA" + "BCDEFGHJKLM23456"
    assert len(identifier) == 20
    secret = base64.b64encode(
        hashlib.sha256(b"synthetic AWS profile fixture").digest()
    ).decode()[:40]
    return (
        "[profile depthfixture]\n"
        f"aws_access_key_id={identifier}\n"
        f"aws_secret_access_key={secret}\n"
        "deploy_token=an-unrelated-non-provider-literal\n"
    )


@pytest.mark.parametrize("name", ["credentials", "config"])
@pytest.mark.parametrize("direct", [False, True])
def test_project_aws_profile_files_reach_native_scanner(
    tmp_path, monkeypatch, name, direct
):
    from skylos.analyzer import analyze
    from test.fixture_paths import write_fixture

    monkeypatch.setenv("SKYLOS_JOBS", "1")
    path = write_fixture(tmp_path, ".aws/" + name, _aws_profile())
    result = json.loads(
        analyze(
            str(path if direct else tmp_path), enable_secrets=True, grep_verify=False
        )
    )
    findings = result.get("secrets", [])
    assert {f["provider"] for f in findings} == {
        "aws_access_key_id",
        "aws_secret_access_key",
    }
    paired = next(f for f in findings if f["provider"] == "aws_secret_access_key")
    assert paired["structured_credential"]["credential_record"] == "aws_pair"
    assert paired["structured_credential"]["record_format"] == "ini_profile"
    assert result.get("analysis_errors", []) == []
    assert result["analysis_summary"]["secrets_files_scanned"] == 1


def test_arbitrary_extensionless_files_do_not_gain_generic_scanning(
    tmp_path, monkeypatch
):
    from skylos.analyzer import analyze
    from test.fixture_paths import write_fixture

    monkeypatch.setenv("SKYLOS_JOBS", "1")
    write_fixture(tmp_path, "docs/credentials", _aws_profile())
    result = json.loads(analyze(str(tmp_path), enable_secrets=True, grep_verify=False))
    assert result.get("secrets", []) == []
    assert result.get("analysis_errors", []) == []


def test_existing_shell_source_in_aws_path_keeps_generic_detection():
    secret = hashlib.sha256(b"existing shell credential fixture").hexdigest()
    source = '#!/bin/sh\nAPI_SECRET="' + secret + '"\n'
    findings = _scan(source, ".aws/config")
    assert any(f.get("provider") == "generic" for f in findings)


def test_aws_profile_selector_is_available_to_agent_hook():
    from pathlib import Path
    from skylos.commands.hook_cmd import _secret_scannable

    assert _secret_scannable(Path("repository/.aws/credentials"))
    assert _secret_scannable(Path("repository/.aws/config"))


def test_agent_hook_scans_profile_when_repository_root_is_aws_directory(tmp_path):
    from skylos.commands.hook_cmd import _secret_findings

    root = tmp_path / ".aws"
    path = root / "credentials"
    findings = _secret_findings(path, root, _aws_profile())
    assert len(findings) == 2


@pytest.mark.parametrize("quote_mark", ["", "'", '"'])
def test_aws_assignment_extraction_does_not_consume_field_name(quote_mark):
    source = _aws_profile()
    lines = source.splitlines()
    key = lines[2].split("=", 1)[1]
    lines[2] = "aws_secret_access_key=" + quote_mark + key + quote_mark
    findings = _scan("\n".join(lines), ".aws/credentials")
    secret_findings = [
        f for f in findings if f.get("provider") == "aws_secret_access_key"
    ]
    assert len(secret_findings) == 1
    finding = secret_findings[0]
    assert lines[2][finding["col"] : finding["end_col"]] == key


def test_aws_field_mention_does_not_classify_unrelated_token_as_aws_key():
    token = base64.b64encode(
        hashlib.sha256(b"unrelated token fixture").digest()
    ).decode()[:40]
    assert _scan("aws_secret_access_key is the field; other=" + token) == []


def test_short_aws_value_cannot_borrow_field_name_to_reach_credential_length():
    # Preserve the original malformed env fixture: KEY= is not secret material.
    source = "AWS_SECRET_ACCESS_K" r"E" "Y=AKIAIOSFODNN7EXAMPLE1234567890abcdef\n"
    findings = _scan(source, ".env")
    assert not any(f.get("provider") == "aws_secret_access_key" for f in findings)


def test_aws_profile_symlink_is_incomplete_and_never_followed(tmp_path, monkeypatch):
    from skylos.analyzer import analyze
    from test.fixture_paths import write_fixture

    monkeypatch.setenv("SKYLOS_JOBS", "1")
    root = tmp_path / "project"
    (root / ".aws").mkdir(parents=True)
    outside = write_fixture(tmp_path, "outside-credentials", _aws_profile())
    (root / ".aws/credentials").symlink_to(outside)
    result = json.loads(analyze(str(root), enable_secrets=True, grep_verify=False))
    assert result.get("secrets", []) == []
    assert result.get("analysis_errors", [])
    assert result["analysis_summary"]["secrets_files_scanned"] == 0
