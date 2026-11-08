"""Strict JSON literal views preserve private-component source coordinates."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from skylos.rules.secret_decoding import decode_provider_views
from skylos.rules.secrets import scan_ctx
from test.test_secret_credentials import AWS_ID, AWS_SECRET, _google


JWK_KEY = (
    base64.urlsafe_b64encode(
        hashlib.sha256(b"public JSON literal decoding fixture").digest()
    )
    .decode()
    .rstrip("=")
)
JWK_TEXT = json.dumps({"kty": "oct", "k": JWK_KEY})
AWS_TEXT = json.dumps({"accessKeyId": AWS_ID, "secretAccessKey": AWS_SECRET})
PREFIXES = ('"kty"', '"private_key"', '"secretAccessKey"', "ghp_")


def _decode(text, **limits):
    return decode_provider_views(
        text, provider_prefixes=PREFIXES, include_record_escapes=True, **limits
    )


def _base64(text):
    return base64.b64encode(text.encode()).decode()


def _native(text):
    return list(scan_ctx({"relpath": "README.md", "lines": [text], "tree": None}))


@pytest.mark.parametrize("wrapper", ["{}", "const VALUE = {};", "<entry value={} />"])
def test_complete_json_string_decodes_one_literal_without_executing_source(wrapper):
    source = wrapper.format(json.dumps(JWK_TEXT))
    result = _decode(source)
    views = [v for v in result.views if v.text == JWK_TEXT]
    assert result.complete
    assert len(views) == 1
    view = views[0]
    assert view.encodings == ("json",)
    assert view.frame == ()
    start = JWK_TEXT.index(JWK_KEY)
    first, last = view.source_range(start, start + len(JWK_KEY))
    assert source[first:last] == JWK_KEY
    assert JWK_KEY not in repr(view)
    assert JWK_KEY not in repr(result)


@pytest.mark.parametrize(
    "encoding,expected",
    [
        (lambda text: json.dumps(text), ("json",)),
        (lambda text: json.dumps(json.dumps(text)), ("json", "json")),
        (lambda text: _base64(json.dumps(text)), ("base64", "json")),
        (lambda text: json.dumps(_base64(text)), ("base64",)),
    ],
)
def test_record_literal_layers_share_existing_bounded_transformation_pipeline(
    encoding, expected
):
    result = _decode(encoding(JWK_TEXT))
    (view,) = [v for v in result.views if v.text == JWK_TEXT]
    assert result.complete
    assert view.encodings == expected


def test_two_json_layers_map_private_escaped_characters_to_original_source():
    record = '{"kty":"oct","k":"\\u0061' + JWK_KEY[1:] + '"}'
    source = "VALUE=" + json.dumps(record)
    result = _decode(source)
    normalized = '{"kty":"oct","k":"a' + JWK_KEY[1:] + '"}'
    (view,) = [v for v in result.views if v.text == normalized]
    first = view.text.index('"k":"') + len('"k":"')
    start, end = view.source_range(first, first + 1)
    assert source[start:end] == r"\\u0061"


def test_json_surrogate_pair_maps_one_unicode_column_to_all_twelve_source_bytes():
    text = "😀" + JWK_TEXT
    source = json.dumps(text)
    result = _decode(source)
    (view,) = [v for v in result.views if v.text == text]
    start, end = view.source_range(0, 1)
    assert source[start:end].lower() == r"\ud83d\ude00"
    assert view.source_range(1, 2)[0] == end


@pytest.mark.parametrize(
    "source",
    [
        r'"{\"kty\":\"oct\",\"k\":\"invalid\"}\q"',
        r'"{\"kty\":\"oct\",\"k\":\"invalid\"}\uZZZZ"',
        r'"{\"kty\":\"oct\",\"k\":\"invalid\"}\ud800"',
        r'"{\"kty\":\"oct\",\"k\":\"invalid\"}\udc00"',
        r'"{\"kty\":\"oct\",\"k\":\"invalid\"}\ud800\u0041"',
        r'"{\"kty\":\"oct\",\"k\":\"invalid\"}',
        '"{\\"kty\\":\\"oct\\"}\n"',
    ],
)
def test_malformed_or_truncated_json_literals_produce_no_json_view(source):
    result = _decode(source)
    assert not any("json" in v.encodings for v in result.views)


@pytest.mark.parametrize(
    "source",
    [
        '"ordinary text with \\"quoted words\\""',
        '"a normal \\n line break"',
        '"public metadata: \\"kty\\": \\"RSA\\""',
    ],
)
def test_complete_safe_literals_do_not_create_a_secret_finding(source):
    assert _native(source) == []


def test_unknown_escaped_quote_fragments_without_a_complete_literal_do_not_decode():
    source = r"{\"kty\":\"oct\",\"k\":\"" + JWK_KEY + r"\"}"
    assert not any(v.text == JWK_TEXT for v in _decode(source).views)


@pytest.mark.parametrize(
    "kind,record,provider",
    [
        ("jwk", JWK_TEXT, "jwk_symmetric_key"),
        ("aws", AWS_TEXT, "aws_secret_access_key"),
        ("google", json.dumps(_google()), "private_key_block"),
    ],
)
@pytest.mark.parametrize(
    "encode",
    [
        json.dumps,
        lambda text: json.dumps(json.dumps(text)),
        lambda text: _base64(json.dumps(text)),
    ],
)
def test_native_wrapped_record_keeps_one_private_finding_and_safe_metadata(
    kind, record, provider, encode
):
    findings = _native(encode(record))
    selected = [f for f in findings if f.get("provider") == provider]
    assert len(selected) == 1
    assert selected[0].get("structured_credential")
    if kind == "google":
        assert not any(f.get("provider") == "google_service_account" for f in findings)
    assert JWK_KEY not in json.dumps(findings)
    assert AWS_SECRET not in json.dumps(findings)


def test_json_source_offsets_distinguish_repeated_same_value_literals():
    source = "a=" + json.dumps(JWK_TEXT) + ";b=" + json.dumps(JWK_TEXT)
    selected = [f for f in _native(source) if f.get("provider") == "jwk_symmetric_key"]
    assert len(selected) == 2
    assert selected[0]["col"] != selected[1]["col"]
    assert all(source[f["col"] : f["end_col"]] == JWK_KEY for f in selected)


def test_json_candidate_count_limit_is_explicit():
    result = _decode(json.dumps(JWK_TEXT), max_candidates=0)
    assert not result.complete
    assert "secret_decode_candidate_count_limit" in result.diagnostics


def test_json_decoded_byte_limit_is_explicit():
    result = _decode(json.dumps(JWK_TEXT), max_decoded_bytes=1)
    assert not result.complete
    assert "secret_decode_byte_limit" in result.diagnostics


def test_json_candidate_character_limit_is_explicit():
    result = _decode(json.dumps(JWK_TEXT), max_candidate_chars=8)
    assert not result.complete
    assert "secret_decode_candidate_limit" in result.diagnostics


def test_json_third_layer_respects_existing_depth_limit():
    source = json.dumps(json.dumps(json.dumps(JWK_TEXT)))
    result = _decode(source)
    assert not result.complete
    assert "secret_decode_depth_limit" in result.diagnostics
    assert not any(v.text == JWK_TEXT for v in result.views)


def test_default_decoder_behavior_stays_opt_in_for_record_json_literals():
    result = decode_provider_views(json.dumps(JWK_TEXT), provider_prefixes=PREFIXES)
    assert not any("json" in v.encodings for v in result.views)


@pytest.mark.parametrize(
    "encoded_prefix",
    [
        r"\u0067\u0068\u0070&lowbar;",
        r"\u0067%68%70%5F",
    ],
)
def test_source_literal_prefix_concatenation_does_not_add_incomplete_noise(
    encoded_prefix,
):
    source = "container = " + json.dumps(encoded_prefix) + " + runtime_payload"
    assert _native(source) == []


@pytest.mark.parametrize("encode_entire_token", [False, True])
def test_backslash_only_json_layer_keeps_a_complete_unicode_encoded_provider(
    encode_entire_token,
):
    token = "ghp_" + hashlib.sha256(b"public escaped provider control").hexdigest()
    if encode_entire_token:
        escaped = "".join("\\u%04x" % ord(char) for char in token)
    else:
        escaped = r"\u0067\u0068\u0070_" + token[4:]
    source = json.dumps(escaped)
    findings = _native(source)
    assert [f.get("provider") for f in findings] == ["github"]
    assert findings[0]["decoding"]["encodings"] == ["json", "unicode"]
    assert token not in json.dumps(findings)


@pytest.mark.parametrize("layers", [1, 2])
def test_json_slash_escaped_webhook_keeps_the_same_one_or_two_layer_budget(layers):
    token = (
        "https://hooks.slack.com/services/T12345678/B12345678/"
        + hashlib.sha256(b"public JSON slash webhook").hexdigest()
    )
    source = json.dumps(token).replace("/", r"\/")
    if layers == 2:
        source = json.dumps(source)
    findings = _native(source)
    assert [f.get("provider") for f in findings] == ["slack_webhook"]
    assert findings[0]["decoding"]["encodings"] == ["json"] * layers
    assert token not in json.dumps(findings)


def test_complete_three_layer_credential_stays_incomplete_and_keeps_raw_checks():
    token = "ghp_" + hashlib.sha256(b"public full three layer control").hexdigest()
    escaped = r"\u0067\u0068\u0070&lowbar;" + token[4:]
    source = json.dumps(escaped)
    result = _decode(source)
    assert not result.complete
    assert "secret_decode_depth_limit" in result.diagnostics
    assert not any(view.text == token for view in result.views)
    deeper = _decode(source, max_depth=3)
    assert any(view.text == token for view in deeper.views)

    raw_token = "ghp_" + hashlib.sha256(b"public separate raw control").hexdigest()
    combined = source + "; raw=" + raw_token
    findings = _native(combined)
    private = [f for f in findings if f.get("rule_id") == "SKY-S101"]
    assert len(private) == 1
    assert combined[private[0]["col"] : private[0]["end_col"]] == raw_token
    incomplete = [f for f in findings if f.get("rule_id") == "SKY-ANALYSIS-INCOMPLETE"]
    assert len(incomplete) == 1
    assert (
        "secret_decode_depth_limit" in incomplete[0]["metadata"]["analysis_diagnostics"]
    )
