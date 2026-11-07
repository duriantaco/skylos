"""Existing secret checks must include Swift production sources."""

import json

from skylos.analyzer import analyze
from skylos.rules.secrets import scan_ctx


_TAIL = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7R8"


def _provider_token():
    return "".join(("g", "h", "p", "_", _TAIL))


def test_swift_provider_secret_reaches_the_existing_detector():
    findings = list(
        scan_ctx(
            {
                "relpath": "Sources/Credentials.swift",
                "lines": [f'let credential = "{_provider_token()}"\n'],
                "tree": None,
            }
        )
    )
    assert any(
        item["rule_id"] == "SKY-S101" and item.get("provider") == "github"
        for item in findings
    )


def test_swift_generic_secret_reaches_the_existing_detector():
    findings = list(
        scan_ctx(
            {
                "relpath": "Sources/Credentials.swift",
                "lines": [f'let apiKey = "{_TAIL}"\n'],
                "tree": None,
            }
        )
    )
    assert any(
        item["rule_id"] == "SKY-S101" and item.get("provider") == "generic"
        for item in findings
    )


def test_swift_placeholder_stays_quiet():
    assert not list(
        scan_ctx(
            {
                "relpath": "Sources/Credentials.swift",
                "lines": ['let apiKey = "your_api_key_here"\n'],
                "tree": None,
            }
        )
    )


def test_swift_provider_secret_is_in_the_native_scan_output(tmp_path):
    source = tmp_path / "Credentials.swift"
    source.write_text(f'let credential = "{_provider_token()}"\n')
    result = json.loads(
        analyze(
            str(tmp_path),
            grep_verify=False,
            enable_secrets=True,
            enable_danger=False,
            enable_quality=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert any(
        item["rule_id"] == "SKY-S101" and item.get("provider") == "github"
        for item in result.get("secrets", [])
    )
