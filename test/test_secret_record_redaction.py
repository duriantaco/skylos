"""Record rendering protects recoverable private fields without hiding publics."""

from __future__ import annotations

import base64
import codecs
import hashlib
import html
import json
from urllib.parse import quote, unquote

import pytest

from skylos.audit.redaction import redact_text
from skylos.cicd.evidence import sanitize_untrusted_text
from skylos.rules import secret_record_redaction as redaction
from skylos.rules.secret_records import redact_secret_records


REPLACEMENT = "[PRIVATE]"
PRIVATE = (
    base64.urlsafe_b64encode(hashlib.sha256(b"display private fixture").digest())
    .decode()
    .rstrip("=")
)
PUBLIC = (
    base64.urlsafe_b64encode(hashlib.sha256(b"display public fixture").digest())
    .decode()
    .rstrip("=")
)


def _jwk():
    return {"kty": "OKP", "crv": "Ed25519", "x": PUBLIC, "d": PRIVATE}


def _quoted(value, layers=1):
    for _ in range(layers):
        value = json.dumps(value)
    return value


def _base64(value):
    return base64.b64encode(value.encode()).decode()


def _unicode_quotes(value):
    return json.dumps(value).replace('\\"', "\\u0022")


def _ci(value):
    return sanitize_untrusted_text(
        value, max_length=16_000, preserve_newlines=True, neutralize_mentions=False
    )


RENDERERS = [
    pytest.param(lambda text: redact_secret_records(text, REPLACEMENT), id="record"),
    pytest.param(redact_text, id="audit"),
    pytest.param(_ci, id="ci"),
]
TRANSPORTS = [
    pytest.param(lambda text: text, id="raw"),
    pytest.param(json.dumps, id="json-string"),
    pytest.param(_unicode_quotes, id="json-unicode-quotes"),
    pytest.param(lambda text: _quoted(text, 2), id="two-json-strings"),
    pytest.param(lambda text: quote(text, safe=""), id="percent"),
    pytest.param(lambda text: html.escape(text, quote=True), id="html"),
    pytest.param(_base64, id="base64"),
    pytest.param(
        lambda text: base64.b64encode(
            codecs.BOM_UTF16_LE + text.encode("utf-16-le")
        ).decode(),
        id="base64-utf16le",
    ),
    pytest.param(
        lambda text: base64.b64encode(
            codecs.BOM_UTF16_BE + text.encode("utf-16-be")
        ).decode(),
        id="base64-utf16be",
    ),
    pytest.param(lambda text: _base64(json.dumps(text)), id="base64-json-string"),
    pytest.param(lambda text: json.dumps(_base64(text)), id="json-string-base64"),
]


@pytest.mark.parametrize("render", RENDERERS)
@pytest.mark.parametrize("transport", TRANSPORTS)
def test_private_jwk_is_protected_through_supported_transports(render, transport):
    source = json.dumps(_jwk())
    transported = transport(source)
    output = render(transported)
    assert output != transported
    assert PRIVATE not in output
    assert transported not in output


@pytest.mark.parametrize("render", RENDERERS)
def test_raw_private_component_mask_keeps_public_coordinates_readable(render):
    source = json.dumps(_jwk())
    output = render(source)
    assert PRIVATE not in output
    assert PUBLIC in output
    assert '"x"' in output


@pytest.mark.parametrize("render", RENDERERS)
@pytest.mark.parametrize("transport", TRANSPORTS)
def test_public_only_jwk_transport_remains_readable(render, transport):
    public = {name: value for name, value in _jwk().items() if name != "d"}
    source = transport(json.dumps(public))
    output = render(source)
    assert output == source


@pytest.mark.parametrize("render", RENDERERS)
def test_complete_unknown_object_and_public_siblings_do_not_borrow_private_context(
    render,
):
    unknown = {"kind": "ordinary metadata", "d": PRIVATE, "k": PUBLIC}
    source = json.dumps(
        {"public": {"kty": "RSA", "n": PUBLIC, "e": "AQAB"}, "other": unknown}
    )
    assert render(source) == source


@pytest.mark.parametrize("render", RENDERERS)
def test_private_sibling_is_masked_without_masking_public_or_unknown_siblings(render):
    source = json.dumps(
        [
            _jwk(),
            {"kty": "RSA", "n": PUBLIC, "e": "AQAB"},
            {"kind": "metadata", "d": PUBLIC},
        ]
    )
    output = render(source)
    assert PRIVATE not in output
    assert PUBLIC in output
    assert '"e": "AQAB"' in output
    assert '"kind": "metadata"' in output


@pytest.mark.parametrize("render", RENDERERS)
@pytest.mark.parametrize("layers", [0, 1, 2, 3])
def test_truncated_type_last_jwk_is_protected_through_json_string_layers(
    render, layers
):
    source = json.dumps(
        {
            "d": PRIVATE,
            "padding": "p" * 4_096,
            "kty": "OKP",
            "crv": "Ed25519",
            "x": PUBLIC,
        }
    )
    truncated = _quoted(source, layers)[:400]
    assert PRIVATE in truncated
    output = render(truncated)
    assert PRIVATE not in output
    assert output != truncated


@pytest.mark.parametrize("render", RENDERERS)
@pytest.mark.parametrize(
    "transport",
    [
        _base64,
        lambda source: base64.b64encode(
            codecs.BOM_UTF16_LE + source.encode("utf-16-le")
        ).decode(),
    ],
)
def test_truncated_base64_carrier_masks_recoverable_private_prefix(render, transport):
    source = json.dumps({"k": PRIVATE, "padding": "p" * 4_096, "kty": "oct"})
    carrier = transport(source)[:400]
    decoded = redaction._base64_prefix_text(carrier)
    assert decoded is not None and PRIVATE in decoded
    output = render(carrier)
    assert carrier not in output
    assert output != carrier


def test_base64_carrier_mask_does_not_consume_surrounding_public_text():
    carrier = _base64(json.dumps(_jwk()))
    source = f"Public prefix {carrier} readable suffix"
    assert (
        redact_secret_records(source, REPLACEMENT)
        == f"Public prefix {REPLACEMENT} readable suffix"
    )


def test_percent_and_html_escape_masks_target_only_original_private_component():
    source = json.dumps(_jwk())
    for encoded, decode in (
        (quote(source, safe=""), unquote),
        (html.escape(source), html.unescape),
    ):
        output = redact_secret_records(encoded, REPLACEMENT)
        decoded = decode(output)
        assert PRIVATE not in decoded
        assert PUBLIC in decoded
        assert REPLACEMENT in decoded


def test_ci_truncation_before_late_kty_never_leaks_early_private_k():
    source = json.dumps({"k": PRIVATE, "padding": "p" * 8_192, "kty": "oct"})
    output = sanitize_untrusted_text(source, max_length=100, preserve_newlines=True)
    assert PRIVATE not in output
    assert len(output) <= 100


@pytest.mark.parametrize("render", RENDERERS)
@pytest.mark.parametrize("tail_length", [1, 2])
def test_percent_escape_cut_at_eof_protects_recoverable_private_field(
    render, tail_length
):
    source = quote(json.dumps({"k": PRIVATE, "padding": "more", "kty": "oct"}), safe="")
    cut = source.index("%22padding")
    truncated = source[: cut + tail_length]
    assert PRIVATE in truncated
    assert truncated.endswith("%" if tail_length == 1 else "%2")
    output = render(truncated)
    assert PRIVATE not in output
    assert output != truncated


@pytest.mark.parametrize(
    "limit_name,limit_value",
    [
        ("_MAX_TEXT", 32),
        ("_MAX_VIEWS", 1),
        ("_MAX_DECODED_BYTES", 32),
        ("_MAX_ESCAPE_DEPTH", 1),
    ],
)
def test_rendering_limits_fail_closed(limit_name, limit_value, monkeypatch):
    source = _quoted(json.dumps(_jwk()), 3)
    monkeypatch.setattr(redaction, limit_name, limit_value)
    output = redact_secret_records(source, REPLACEMENT)
    assert output == REPLACEMENT
    assert PRIVATE not in output


def test_fragment_depth_and_member_caps_never_leave_private_tail_unmasked(monkeypatch):
    monkeypatch.setattr(redaction, "_MAX_DEPTH", 2)
    source = json.dumps({"container": {"deeper": _jwk()}})
    assert PRIVATE not in redact_secret_records(source, REPLACEMENT)
    monkeypatch.setattr(redaction, "_MAX_PRIVATE_MEMBERS", 1)
    source = '{"kty":"RSA","d":"' + PRIVATE + '","p":"' + PUBLIC + '"}'
    output = redact_secret_records(source, REPLACEMENT)
    assert PRIVATE not in output and PUBLIC not in output


def test_short_ordinary_text_stays_readable_under_text_budget(monkeypatch):
    monkeypatch.setattr(redaction, "_MAX_TEXT", 32)
    assert (
        redact_secret_records("public explanation", REPLACEMENT) == "public explanation"
    )
