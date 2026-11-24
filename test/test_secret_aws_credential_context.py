import base64
from hashlib import sha256
import json

import pytest

from skylos.analyzer import analyze
from skylos.cli import _apply_display_filters
from skylos.rules.secrets import scan_ctx


def _synthetic_identifier():
    material = base64.b32encode(sha256(b"skylos-aws-id-role-fixture").digest()).decode()
    return "AK" + "IA" + material[:16]


def _scan(path, line):
    return scan_ctx({"relpath": path, "lines": [line]})


def _material_view(findings):
    return _apply_display_filters(
        {"secrets": findings}, secrets_credential_material_only=True
    )


@pytest.mark.parametrize(
    "path,template,context",
    [
        ("app.py", 'SERVICE_PASSWORD = "{}"', "keyed_secret"),
        (".env", "SERVICE_PASSWORD={}", "config_credential"),
        ("incident.txt", "postgres://service:{}@db.internal/app", "url_password"),
        (
            "incident.md",
            "postgresql://db.internal/app?user=service&password={}",
            "url_password",
        ),
    ],
)
def test_exact_credential_role_keeps_the_aws_provider_finding(path, template, context):
    identifier = _synthetic_identifier()
    [finding] = findings = _scan(path, template.format(identifier))
    assert finding["provider"] == "aws_access_key_id"
    assert finding["credential_context"] == context
    assert identifier not in json.dumps(finding)
    assert _material_view(findings)["secrets"] == findings


def test_larger_database_password_keeps_its_own_full_location():
    identifier = _synthetic_identifier()
    password = f"{identifier}.suffix"
    text = f"postgres://service:{password}@db.internal/app"
    identifier_finding, credential = _scan("incident.txt", text)
    assert "credential_context" not in identifier_finding
    assert credential["provider"] == "url_credentials"
    assert text[credential["col"]:credential["end_col"]] == password
    assert password not in json.dumps(credential)
    assert _material_view([identifier_finding, credential])["secrets"] == [credential]


def test_full_scan_preserves_identifier_only_and_contextual_findings(tmp_path):
    identifier = _synthetic_identifier()
    (tmp_path / "incident.txt").write_text(
        f"Audit record aws_access_key_id={identifier}\n"
        f"postgres://service:{identifier}@db.internal/app\n",
        encoding="utf-8",
    )
    result = json.loads(analyze(str(tmp_path), enable_secrets=True, grep_verify=False))
    assert [finding["line"] for finding in result["secrets"]] == [1, 2]
    assert "credential_context" not in result["secrets"][0]
    display = _apply_display_filters(result, secrets_credential_material_only=True)
    assert [finding["line"] for finding in display["secrets"]] == [2]
    assert display["analysis_summary"]["aws_access_key_identifiers_hidden"] == 1
    assert [finding["line"] for finding in result["secrets"]] == [1, 2]
