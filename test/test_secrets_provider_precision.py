"""Provider evidence replaces only an identical generic credential finding."""

from __future__ import annotations

import json
import base64

import pytest

from skylos.rules.secrets import scan_ctx
from skylos.rules import secrets


CLASSIC_TOKEN = "ghp_" + "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY2zA4"
FINE_GRAINED_BODY = (
    "aB3dE5fG7hJ9kL2mN4pQ6r"
    + "_"
    + ("S8tU0vW1xY2zA4bC6dE8fG0hJ2kL4mN6pQ8rS0tU2vW4xY6zA8bC0dE2fG3")
)
FINE_GRAINED_TOKEN = "github_pat_" + FINE_GRAINED_BODY
GENERIC_TOKEN = "Z8k2Lm9Qp4Rs7Tv1Wx6Ya3Bc5De0Fg2H"


def _scan(source, relpath="src/settings.py"):
    return list(
        scan_ctx({"relpath": relpath, "lines": source.splitlines(True), "tree": None})
    )


@pytest.mark.parametrize("key", ["VALUE", "API_TOKEN"])
def test_known_fine_grained_github_shape_has_one_provider_finding(key):
    assert len(FINE_GRAINED_BODY) == 82
    findings = _scan(f'{key} = "{FINE_GRAINED_TOKEN}"\n')
    assert len(findings) == 1
    assert findings[0]["provider"] == "github"
    assert findings[0]["rule_id"] == "SKY-S101"
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["col"] == len(key) + 4
    assert findings[0]["end_col"] == len(key) + 4 + len(FINE_GRAINED_TOKEN)
    assert FINE_GRAINED_TOKEN not in json.dumps(findings)


@pytest.mark.parametrize(
    "token",
    [
        "github_pat_" + FINE_GRAINED_BODY[:-1],
        "github_pat_" + FINE_GRAINED_BODY + "Z",
        "github_pat_" + FINE_GRAINED_BODY.replace("_", "-"),
        "github_pat_" + FINE_GRAINED_BODY.replace("_", ""),
        "github_pat_short_not_a_credential",
        "GITHUB_PAT_" + FINE_GRAINED_BODY,
        "x" + FINE_GRAINED_TOKEN,
        "_" + FINE_GRAINED_TOKEN,
        FINE_GRAINED_TOKEN + "_suffix",
    ],
)
def test_malformed_fine_grained_shapes_are_not_provider_findings(token):
    assert not [f for f in _scan(f'VALUE = "{token}"\n') if f["provider"] == "github"]


def test_provider_dedup_keeps_two_distinct_credentials_on_one_line():
    source = f'API_TOKEN = "{CLASSIC_TOKEN}"; OTHER_TOKEN = "{FINE_GRAINED_TOKEN}"\n'
    findings = _scan(source)
    assert [f["provider"] for f in findings] == ["github", "github"]
    assert len({(f["col"], f["end_col"]) for f in findings}) == 2


def test_provider_dedup_keeps_same_value_at_distinct_locations():
    source = f'API_TOKEN = "{CLASSIC_TOKEN}"; OTHER_TOKEN = "{CLASSIC_TOKEN}"\n'
    findings = _scan(source)
    assert [f["provider"] for f in findings] == ["github", "github"]
    assert len({(f["col"], f["end_col"]) for f in findings}) == 2


def test_provider_dedup_does_not_hide_a_distinct_generic_secret():
    source = f'API_TOKEN = "{CLASSIC_TOKEN}"; OTHER_TOKEN = "{GENERIC_TOKEN}"\n'
    findings = _scan(source)
    assert [f["provider"] for f in findings] == ["github", "generic"]
    assert findings[0]["end_col"] < findings[1]["col"]


def test_provider_dedup_keeps_a_larger_generic_value_with_other_bytes():
    source = f'API_TOKEN = "prefix.{CLASSIC_TOKEN}.suffix"\n'
    findings = _scan(source)
    assert {f["provider"] for f in findings} == {"github", "generic"}
    generic = next(f for f in findings if f["provider"] == "generic")
    provider = next(f for f in findings if f["provider"] == "github")
    assert generic["col"] < provider["col"]
    assert generic["end_col"] > provider["end_col"]


def test_exact_provider_duplicate_is_collapsed_in_decoded_yaml_context():
    escaped = "".join(f"\\u{ord(c):04x}" for c in CLASSIC_TOKEN)
    findings = _scan(f'checksum: "{escaped}"\n', "config.yaml")
    assert [f["provider"] for f in findings] == ["github"]


def test_fine_grained_provider_survives_client_exposure_classification():
    findings = _scan(f'const API_TOKEN = "{FINE_GRAINED_TOKEN}";\n', "public/app.js")
    assert len(findings) == 1
    assert findings[0]["provider"] == "github"
    assert findings[0]["rule_id"] == "SKY-S102"


def test_classic_github_pattern_retains_its_existing_long_token_behavior():
    findings = _scan(f'VALUE = "{CLASSIC_TOKEN}AdditionalLongSuffix"\n')
    assert any(f["provider"] == "github" for f in findings)


def _encoded(value):
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def test_encoded_single_provider_replaces_only_its_identical_generic_container():
    encoded = _encoded(CLASSIC_TOKEN)
    source = f'API_TOKEN = "{encoded}"\n'
    findings = _scan(source)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["provider"] == "github"
    assert finding["col"] == source.index(encoded)
    assert finding["end_col"] == source.index(encoded) + len(encoded)
    assert finding["decoding"] == {
        "encodings": ["base64"],
        "decoded_start": 0,
        "decoded_end": len(CLASSIC_TOKEN),
        "source_path": [
            [source.index(encoded), source.index(encoded) + len(encoded)],
            [0, len(CLASSIC_TOKEN)],
        ],
    }
    assert CLASSIC_TOKEN not in json.dumps(findings)
    assert encoded not in json.dumps(findings)


@pytest.mark.parametrize("same_value", [False, True])
def test_encoded_container_keeps_multiple_provider_occurrences(same_value):
    other = CLASSIC_TOKEN if same_value else FINE_GRAINED_TOKEN
    encoded = _encoded(f"{CLASSIC_TOKEN} {other}")
    findings = _scan(f'VALUE = "{encoded}"\n')
    assert [f["provider"] for f in findings] == ["github", "github"]
    assert len({f["decoding"]["decoded_start"] for f in findings}) == 2
    assert len({(f["col"], f["end_col"]) for f in findings}) == 1


@pytest.mark.parametrize("nested", [False, True])
def test_encoded_prefix_and_suffix_do_not_hide_larger_generic_value(nested):
    token = _encoded(CLASSIC_TOKEN) if nested else CLASSIC_TOKEN
    encoded = _encoded(f"prefix.{token}.suffix")
    findings = _scan(f'API_TOKEN = "{encoded}"\n')
    assert {f["provider"] for f in findings} == {"github", "generic"}


def test_decoding_surrounding_html_does_not_duplicate_visible_provider():
    source = f'VALUE = "https://api.invalid/?token={CLASSIC_TOKEN}&amp;view=1"\n'
    findings = _scan(source)
    assert [f["provider"] for f in findings] == ["github"]
    assert "decoding" not in findings[0]


def test_nested_encoding_keeps_its_full_encoding_trace():
    encoded = _encoded(_encoded(CLASSIC_TOKEN))
    findings = _scan(f'API_TOKEN = "{encoded}"\n')
    assert [f["provider"] for f in findings] == ["github"]
    assert findings[0]["decoding"]["encodings"] == ["base64", "base64"]


@pytest.mark.parametrize("letter", ["A", "a", "x"])
def test_long_benign_tokens_do_not_create_decoding_incompleteness(letter):
    assert not _scan(f'VALUE = "{letter * 100_000}"\n')


def test_encoded_public_prose_and_malformed_provider_are_quiet():
    encoded = _encoded("some readable public text: github_pat_short")
    assert not _scan(f'VALUE = "{encoded}"\n')


@pytest.mark.parametrize(
    "limit, value, diagnostic",
    [
        ("_MAX_SECRET_DECODE_CANDIDATES", 1, "secret_decode_candidate_count_limit"),
        ("_MAX_SECRET_DECODE_BYTES", len(CLASSIC_TOKEN), "secret_decode_byte_limit"),
    ],
)
def test_file_decoding_budget_preserves_raw_findings_and_reports_incomplete(
    monkeypatch, limit, value, diagnostic
):
    monkeypatch.setattr(secrets, limit, value)
    source = (
        f'VALUE = "{_encoded(CLASSIC_TOKEN)}"\n'
        f'VALUE = "{_encoded(FINE_GRAINED_TOKEN)}"\n'
        f'VALUE = "{CLASSIC_TOKEN}"\n'
    )
    findings = _scan(source)
    providers = [f for f in findings if f.get("provider") == "github"]
    assert [f["line"] for f in providers] == [1, 3]
    incomplete = [f for f in findings if f["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"]
    assert len(incomplete) == 1
    assert incomplete[0]["line"] == 2
    assert incomplete[0]["metadata"]["analysis_complete"] is False
    assert diagnostic in incomplete[0]["metadata"]["analysis_diagnostics"]
    assert CLASSIC_TOKEN not in json.dumps(incomplete)
    assert FINE_GRAINED_TOKEN not in json.dumps(incomplete)


@pytest.mark.parametrize("header", ["RSA PRIVATE KEY", "PRIVATE KEY", "PUBLIC KEY"])
def test_encoded_private_key_documentation_controls_are_preserved(header):
    body = "MIIE" + "vgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRS0LmTwUT0iwP"
    pem = f"-----BEGIN {header}-----\n{body}\n...\n-----END {header}-----\n"
    findings = _scan(f'VALUE = "{_encoded(pem)}"\n')
    assert not [f for f in findings if f.get("provider") == "private_key_block"]


def test_encoded_private_key_material_still_reports_provider():
    body = "MIIE" + "vgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRS0LmTwUT0iwP"
    pem = f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"
    findings = _scan(f'VALUE = "{_encoded(pem)}"\n')
    providers = [f for f in findings if f.get("provider") == "private_key_block"]
    assert len(providers) == 1
    assert "decoding" in providers[0]


@pytest.mark.parametrize("suffix", [r"\u0041", "&#65;"])
def test_decoded_extension_replaces_the_same_occurrence_raw_prefix(suffix):
    source = f'VALUE = "{CLASSIC_TOKEN}{suffix}"\n'
    findings = _scan(source)
    assert [f["provider"] for f in findings] == ["github"]
    assert findings[0]["decoding"]["decoded_end"] == len(CLASSIC_TOKEN) + 1
    assert findings[0]["preview"].endswith(CLASSIC_TOKEN[-3:] + "A")


def test_visible_and_escaped_same_value_preserve_exactly_two_occurrences():
    escaped = "".join(f"\\u{ord(c):04x}" for c in CLASSIC_TOKEN)
    source = f'VALUE = "{CLASSIC_TOKEN}\\u0020{escaped}"\n'
    findings = _scan(source)
    assert [f["provider"] for f in findings] == ["github", "github"]
    assert sum("decoding" in finding for finding in findings) == 1
    assert len({(f["col"], f["end_col"]) for f in findings}) == 2
    assert findings[0]["col"] == source.index(CLASSIC_TOKEN)
    assert source[findings[0]["col"] : findings[0]["end_col"]] == CLASSIC_TOKEN
    assert findings[1]["col"] == source.index(escaped)
    assert source[findings[1]["col"] : findings[1]["end_col"]] == escaped
    assert CLASSIC_TOKEN not in json.dumps(findings)
    assert escaped not in json.dumps(findings)


def test_nested_same_value_containers_have_distinct_source_paths():
    child = _encoded(CLASSIC_TOKEN)
    outer = _encoded(f'one="{child}";two="{child}"')
    findings = _scan(f'VALUE = "{outer}"\n')
    assert [f["provider"] for f in findings] == ["github", "github"]
    paths = [json.dumps(f["decoding"]["source_path"]) for f in findings]
    assert len(set(paths)) == 2
