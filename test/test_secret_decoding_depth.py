"""Strict additional text transforms retain bounds and occurrence evidence."""

from __future__ import annotations

import base64
import codecs

import pytest

from skylos.rules.secret_decoding import decode_provider_views


TOKEN = "ghp_" + "A7bC9dE2fG4hJ6kL8mN0pQ1rS3tU5vW7xY9z"


def _scan(source, **limits):
    return decode_provider_views(source, provider_prefixes=("ghp_",), **limits)


def _percent(source):
    return "".join(f"%{byte:02X}" for byte in source.encode("utf-8"))


def _base64(source, *, urlsafe=False):
    data = source.encode("utf-8") if isinstance(source, str) else source
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return encoder(data).decode("ascii")


def _utf16(source, endian):
    bom = codecs.BOM_UTF16_LE if endian == "le" else codecs.BOM_UTF16_BE
    return bom + source.encode("utf-16-" + endian)


@pytest.mark.parametrize("style", ["all", "prefix", "lowercase"])
def test_percent_provider_views_retain_the_original_encoded_container(style):
    encoded = _percent(TOKEN) if style != "prefix" else _percent(TOKEN[:4]) + TOKEN[4:]
    if style == "lowercase":
        encoded = encoded.lower()
    expected = TOKEN
    source = f'key="{encoded}"'
    result = _scan(source)
    assert result.complete and result.diagnostics == ()
    assert len(result.views) == 1
    view = result.views[0]
    assert (view.text, view.encodings, view.frame) == (expected, ("percent",), ())
    assert source[view.start : view.end] == encoded
    assert view.source_range(0, len(expected)) == (5, 5 + len(encoded))


def test_percent_utf8_maps_codepoints_to_complete_original_byte_escape_ranges():
    encoded = _percent("🙂") + "+" + _percent(TOKEN[:4]) + TOKEN[4:]
    source = f'🙂 token="{encoded}"'
    result = _scan(source)
    assert result.complete and len(result.views) == 1
    view = result.views[0]
    start = source.index(encoded)
    assert view.text == "🙂+" + TOKEN
    assert view.source_range(0, 1) == (start, start + 12)
    assert view.source_range(1, 2) == (start + 12, start + 13)
    assert view.source_range(2, 3) == (start + 13, start + 16)
    assert view.source_range(6, 10) == (start + 25, start + 29)
    assert "+" in view.text and " " not in view.text


@pytest.mark.parametrize(
    "encoded",
    [
        "%6Ghp_" + TOKEN[4:],
        _percent(TOKEN[:4]) + TOKEN[4:] + "%",
        _percent(TOKEN[:4]) + TOKEN[4:] + "%0",
        _percent(TOKEN[:4]) + TOKEN[4:] + "%GG",
        "%C0%AF" + _percent(TOKEN),
        "%ED%A0%80" + _percent(TOKEN),
        "%F4%90%80%80" + _percent(TOKEN),
        "%F0%9F%99" + _percent(TOKEN),
        "%00" + _percent(TOKEN),
    ],
)
def test_malformed_or_nontext_percent_encoding_never_fabricates_provider_views(encoded):
    result = _scan(encoded)
    assert result.complete and result.views == () and result.diagnostics == ()


def test_percent_encoding_is_not_a_form_url_plus_replacement():
    encoded = _percent(TOKEN[:4]) + TOKEN[4:] + "+suffix"
    result = _scan(encoded)
    assert result.complete and len(result.views) == 1
    assert result.views[0].text == TOKEN + "+suffix"


def test_distinct_percent_encoded_occurrences_keep_distinct_original_locations():
    encoded = _percent(TOKEN)
    source = f'first="{encoded}" second="{encoded}"'
    result = _scan(source)
    assert result.complete and len(result.views) == 2
    assert [view.source_range(0, len(TOKEN)) for view in result.views] == [
        (source.index(encoded), source.index(encoded) + len(encoded)),
        (source.rindex(encoded), source.rindex(encoded) + len(encoded)),
    ]


def test_commuting_percent_unicode_paths_preserve_one_physical_occurrence():
    encoded = "\\u0067%68%70%5F" + TOKEN[4:]
    result = _scan(encoded)
    assert result.complete and len(result.views) == 1
    view = result.views[0]
    assert view.text == TOKEN and view.frame == ()
    assert view.source_range(0, len(TOKEN)) == (0, len(encoded))


@pytest.mark.parametrize("outer", ["percent", "base64"])
def test_percent_and_base64_composition_uses_two_transformations(outer):
    encoded = (
        _percent(_base64(TOKEN)) if outer == "percent" else _base64(_percent(TOKEN))
    )
    expected = ("percent", "base64") if outer == "percent" else ("base64", "percent")
    result = _scan(encoded)
    assert result.complete and len(result.views) == 1
    view = result.views[0]
    assert (view.text, view.encodings) == (TOKEN, expected)
    assert (view.start, view.end) == (0, len(encoded))


def test_percent_layers_obey_the_existing_depth_limit():
    encoded = _percent(_percent(_percent(TOKEN)))
    limited = _scan(encoded)
    assert not limited.complete and limited.views == ()
    assert limited.diagnostics == ("secret_decode_depth_limit",)
    complete = _scan(encoded, max_depth=3)
    assert complete.complete and len(complete.views) == 1
    assert complete.views[0].encodings == ("percent", "percent", "percent")
    assert complete.views[0].text == TOKEN


@pytest.mark.parametrize("endian", ["le", "be"])
@pytest.mark.parametrize("urlsafe", [False, True])
def test_base64_utf16_bom_is_two_explicit_transforms_with_one_carrier(endian, urlsafe):
    encoded = _base64(_utf16(TOKEN, endian), urlsafe=urlsafe)
    source = f'token="{encoded}"'
    result = _scan(source)
    assert result.complete and len(result.views) == 1
    view = result.views[0]
    family = "base64url" if any(char in encoded for char in "-_") else "base64"
    assert (view.text, view.encodings) == (TOKEN, (family, "utf16" + endian))
    assert result.candidates_checked == 1
    assert source[view.start : view.end] == encoded
    assert view.frame == ((7, 7 + len(encoded)),)
    assert view.source_range(0, len(TOKEN)) == (0, len(TOKEN))


@pytest.mark.parametrize("endian", ["le", "be"])
def test_utf16_requires_an_explicit_bom_instead_of_guessing_binary_text(endian):
    result = _scan(_base64(TOKEN.encode("utf-16-" + endian)))
    assert result.complete and result.views == () and result.diagnostics == ()


@pytest.mark.parametrize("endian", ["le", "be"])
@pytest.mark.parametrize("bad_suffix", ["odd", "surrogate", "wrong_surrogate"])
def test_invalid_utf16_does_not_create_partial_provider_views(endian, bad_suffix):
    raw = _utf16(TOKEN, endian)
    suffixes = {
        "odd": b"\x7f",
        "surrogate": (0xD800).to_bytes(2, "little" if endian == "le" else "big"),
        "wrong_surrogate": (0xDC00).to_bytes(2, "little" if endian == "le" else "big"),
    }
    result = _scan(_base64(raw + suffixes[bad_suffix]))
    assert result.complete and result.views == () and result.diagnostics == ()


@pytest.mark.parametrize("endian", ["le", "be"])
def test_utf16_handles_surrogate_pairs_without_byte_based_text_columns(endian):
    text = "🙂 " + TOKEN
    result = _scan(_base64(_utf16(text, endian)))
    assert result.complete and len(result.views) == 1
    view = result.views[0]
    assert view.text == text
    assert view.source_range(2, 6) == (2, 6)


@pytest.mark.parametrize("endian", ["le", "be"])
def test_utf16_carrier_cannot_bypass_one_transform_depth_budget(endian):
    result = _scan(_base64(_utf16(TOKEN, endian)), max_depth=1)
    assert not result.complete and result.views == ()
    assert result.diagnostics == ("secret_decode_depth_limit",)


@pytest.mark.parametrize("endian", ["le", "be"])
def test_utf16_nested_in_base64_needs_three_transform_slots(endian):
    encoded = _base64(_base64(_utf16(TOKEN, endian)))
    limited = _scan(encoded)
    assert not limited.complete and limited.views == ()
    assert limited.diagnostics == ("secret_decode_depth_limit",)
    complete = _scan(encoded, max_depth=3)
    assert complete.complete and len(complete.views) == 1
    assert complete.views[0].encodings == ("base64", "base64", "utf16" + endian)


@pytest.mark.parametrize("endian", ["le", "be"])
def test_utf16_byte_budget_counts_intermediate_bytes_and_final_utf8(endian):
    text = "🙂" + TOKEN
    raw = _utf16(text, endian)
    required = len(raw) + len(text.encode("utf-8"))
    limited = _scan(_base64(raw), max_decoded_bytes=required - 1)
    assert not limited.complete and limited.views == ()
    assert limited.diagnostics == ("secret_decode_byte_limit",)
    assert limited.decoded_bytes == 0
    complete = _scan(_base64(raw), max_decoded_bytes=required)
    assert complete.complete and len(complete.views) == 1
    assert complete.decoded_bytes == required


@pytest.mark.parametrize("endian", ["le", "be"])
def test_utf16_candidate_exhaustion_keeps_first_occurrence(endian):
    encoded = _base64(_utf16(TOKEN, endian))
    result = _scan(f'"{encoded}" "{encoded}"', max_candidates=1)
    assert not result.complete and len(result.views) == 1
    assert result.diagnostics == ("secret_decode_candidate_count_limit",)


@pytest.mark.parametrize("endian", ["le", "be"])
def test_oversized_utf16_carrier_remains_incomplete_not_binary_inert(endian):
    encoded = _base64(_utf16("🙂 " * 100 + TOKEN, endian))
    result = _scan(encoded, max_candidate_chars=36)
    assert not result.complete and result.views == ()
    assert result.diagnostics == ("secret_decode_candidate_limit",)


def test_percent_budgets_preserve_incomplete_status_without_credential_text():
    encoded = _percent(TOKEN)
    for limits, reason in [
        ({"max_candidates": 0}, "secret_decode_candidate_count_limit"),
        ({"max_decoded_bytes": 1}, "secret_decode_byte_limit"),
        ({"max_candidate_chars": 12}, "secret_decode_candidate_limit"),
    ]:
        result = _scan(encoded, **limits)
        assert not result.complete and result.views == ()
        assert result.diagnostics == (reason,)
        assert TOKEN not in repr(result) and TOKEN not in " ".join(result.diagnostics)


def test_inert_percent_prose_does_not_consume_the_recursive_budget():
    result = _scan(" ".join(["documentation%20label"] * 1000), max_candidates=0)
    assert result.complete and result.views == ()
    assert result.candidates_checked == result.decoded_bytes == 0


@pytest.mark.parametrize("suffix", ["%", "%GZ", "%1"])
def test_oversized_nonencoding_percent_prose_does_not_claim_incomplete(suffix):
    result = _scan("documentation" * 100 + suffix, max_candidate_chars=32)
    assert result.complete and result.views == () and result.diagnostics == ()


def test_provider_hint_casefold_preserves_a_case_insensitive_authority():
    value = "HTTPS://Hooks.Slack.COM/services/credential-shaped-path"
    result = decode_provider_views(
        _base64(value), provider_prefixes=("https://hooks.slack.com/services/",)
    )
    assert result.complete and len(result.views) == 1
    assert result.views[0].text == value
    assert result.views[0].encodings == ("base64",)


def test_casefolded_provider_hint_does_not_accept_an_unrelated_authority():
    value = "HTTPS://Hooks.Slack.COM.example.net/services/not-a-credential"
    result = decode_provider_views(
        _base64(value), provider_prefixes=("https://hooks.slack.com/services/",)
    )
    assert result.complete and result.views == () and result.diagnostics == ()
