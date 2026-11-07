"""Provider signatures stay visible in test, document and key file scopes."""

from __future__ import annotations

import base64
import json

import pytest

from skylos.rules import secrets


PROVIDER_TOKEN = "ghp_" + "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY2zA4"
GENERIC_TOKEN = "Z8k2Lm9Qp4Rs7Tv1Wx6Ya3Bc5De0Fg2H"
KEY_BODY = "MIIE" + "vgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRS0LmTwUT0iwP"


def _scan(path, source, *, provider_only=None, **options):
    context = {"relpath": path, "lines": source.splitlines(True), "tree": None}
    if provider_only is not None:
        context["provider_only"] = provider_only
    return list(secrets.scan_ctx(context, **options))


@pytest.mark.parametrize(
    "path",
    [
        "tests/test_settings.py",
        "test/test_settings.py",
        "tests/config.yaml",
        "tests/fixtures/settings.json",
        "README.md",
        "docs/setup.md",
        "notes.txt",
        "config/credentials.txt",
        "keys/service.key",
        "certs/service.pem",
        "id_rsa",
        "ssh/id_dsa",
        "ssh/id_ecdsa",
        "ssh/id_ed25519",
        "ssh/identity",
    ],
)
def test_provider_signature_survives_new_file_and_test_scopes(path):
    findings = _scan(path, f'API_TOKEN = "{PROVIDER_TOKEN}"\n')
    assert [finding.get("provider") for finding in findings] == ["github"]
    assert findings[0]["rule_id"] == "SKY-S101"
    assert findings[0]["severity"] == "CRITICAL"
    assert PROVIDER_TOKEN not in json.dumps(findings)


@pytest.mark.parametrize("path", ["README.MD", "notes.TXT", "service.KEY", "key.PEM"])
def test_new_literal_file_names_are_case_insensitive(path):
    assert secrets.is_secret_scan_name(path)


@pytest.mark.parametrize(
    "path",
    [
        "tests/test_settings.py",
        "tests/config.yaml",
        "README.md",
        "notes.txt",
        "service.key",
        "service.pem",
        "id_rsa",
        "examples/notes.txt",
    ],
)
def test_generic_entropy_does_not_expand_into_provider_only_scopes(path):
    source = (
        f'API_TOKEN = "{GENERIC_TOKEN}"\n'
        "DATABASE_URL=postgres://service:Zr8kLq2vW9xP4mT@db.internal/app\n"
    )
    assert _scan(path, source) == []


def test_explicit_test_opt_out_remains_explicit():
    source = f'API_TOKEN = "{PROVIDER_TOKEN}"\n'
    assert _scan("tests/test_settings.py", source, ignore_tests=True) == []


def test_existing_production_generic_detection_is_unchanged():
    source = f'API_TOKEN = "{GENERIC_TOKEN}"\n'
    assert any(f["provider"] == "generic" for f in _scan("src/settings.py", source))


def test_native_html_provider_only_mode_keeps_providers_without_generic_noise():
    source = f'<script>const apiToken = "{GENERIC_TOKEN}";</script>\n'
    assert _scan("standalone.html", source, provider_only=True) == []
    provider = f'<script>const apiToken = "{PROVIDER_TOKEN}";</script>\n'
    findings = _scan("standalone.html", provider, provider_only=True)
    assert [f["provider"] for f in findings] == ["github"]


def test_direct_html_existing_keyed_generic_contract_is_unchanged():
    source = f'<script>const apiToken = "{GENERIC_TOKEN}";</script>\n'
    assert any(f["provider"] == "generic" for f in _scan("index.html", source))


@pytest.mark.parametrize("path", ["keys/service.key", "id_ed25519", "README.md"])
def test_new_provider_only_scopes_keep_private_key_material(path):
    source = f"-----BEGIN PRIVATE KEY-----\n{KEY_BODY}\n-----END PRIVATE KEY-----\n"
    findings = _scan(path, source)
    assert [f["provider"] for f in findings] == ["private_key_block"]


@pytest.mark.parametrize("path", ["notes.txt", "README.md", "id_rsa"])
def test_private_key_documentation_stays_quiet_in_new_scopes(path):
    source = (
        f"-----BEGIN PRIVATE KEY-----\n{KEY_BODY}\n...\n-----END PRIVATE KEY-----\n"
    )
    assert _scan(path, source) == []


@pytest.mark.parametrize("path", ["tests/test_settings.py", "README.md", "notes.txt"])
def test_provider_decoding_is_retained_in_provider_only_scopes(path):
    encoded = base64.b64encode(PROVIDER_TOKEN.encode()).decode()
    findings = _scan(path, f'API_TOKEN = "{encoded}"\n')
    assert [f["provider"] for f in findings] == ["github"]
    assert findings[0]["decoding"]["encodings"] == ["base64"]


@pytest.mark.parametrize("path", ["tests/config.yaml", "README.md", "notes.txt"])
def test_provider_only_scope_does_not_require_generic_context_parsing(path):
    assert _scan(path, "not_a_mapping: [\n") == []
