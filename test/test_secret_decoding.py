"""Encoded views preserve evidence without broadening generic-secret heuristics."""

from __future__ import annotations

import base64
import hashlib
import random
import string

import pytest

from skylos.rules.secret_decoding import decode_provider_views


PREFIXES = ("ghp_", "github_pat_")


def _value():
    randomizer = random.Random(73017)
    return "ghp_" + "".join(
        randomizer.choices(string.ascii_letters + string.digits, k=36)
    )


def _encode(text):
    return base64.b64encode(text.encode()).decode()


def _scan(text, **limits):
    return decode_provider_views(text, provider_prefixes=PREFIXES, **limits)


@pytest.mark.parametrize("padding", [True, False])
def test_base64_provider_keeps_the_encoded_source_container(padding):
    value = _value()
    encoded = _encode(value)
    if not padding:
        encoded = encoded.rstrip("=")
    line = f'API_TOKEN = "{encoded}"'
    result = _scan(line)
    assert result.complete and result.diagnostics == ()
    assert len(result.views) == 1
    view = result.views[0]
    assert view.text == value
    assert view.encodings == ("base64",)
    assert line[view.start : view.end] == encoded
    assert view.start == line.index(encoded)


def test_unquoted_assignment_equals_is_a_valid_boundary_before_base64():
    value = _value()
    encoded = _encode(value)
    result = _scan("API_TOKEN=" + encoded)
    assert result.complete
    assert len(result.views) == 1
    assert result.views[0].text == value
    assert result.views[0].start == len("API_TOKEN=")


@pytest.mark.parametrize("padding", [True, False])
def test_urlsafe_alphabet_is_decoded_without_losing_unicode_text(padding):
    value = "🙂" + _value()
    encoded = base64.urlsafe_b64encode(value.encode()).decode()
    assert "-" in encoded or "_" in encoded
    if not padding:
        encoded = encoded.rstrip("=")
    result = _scan(encoded)
    assert result.complete
    assert [(view.text, view.encodings) for view in result.views] == [
        (value, ("base64url",))
    ]


def test_same_secret_in_distinct_containers_keeps_both_source_locations():
    encoded = _encode(_value())
    line = f'first="{encoded}"; second="{encoded}"'
    result = _scan(line)
    assert result.complete
    assert len(result.views) == 2
    assert result.views[0].start != result.views[1].start
    assert all(line[view.start : view.end] == encoded for view in result.views)


def test_nested_base64_keeps_the_original_outer_span():
    value = _value()
    encoded = _encode(_encode(value))
    line = f'payload = "{encoded}"'
    result = _scan(line)
    assert result.complete
    assert len(result.views) == 1
    assert result.views[0].text == value
    assert result.views[0].encodings == ("base64", "base64")
    assert result.views[0].complete_value
    assert line[result.views[0].start : result.views[0].end] == encoded


@pytest.mark.parametrize("same_value", [True, False])
def test_nested_child_occurrences_keep_distinct_decoded_parent_frames(same_value):
    first = _value()
    second = first if same_value else first[:-1] + ("A" if first[-1] != "A" else "B")
    encoded_first, encoded_second = _encode(first), _encode(second)
    payload = f'one="{encoded_first}";two="{encoded_second}"'
    outer = _encode(payload)
    result = _scan(outer)
    assert result.complete
    assert len(result.views) == 2
    frames = {view.frame for view in result.views}
    assert len(frames) == 2
    expected = {
        (
            (0, len(outer)),
            (
                payload.index(encoded_first),
                payload.index(encoded_first) + len(encoded_first),
            ),
        ),
        (
            (0, len(outer)),
            (
                payload.rindex(encoded_second),
                payload.rindex(encoded_second) + len(encoded_second),
            ),
        ),
    }
    assert frames == expected
    assert all(
        view.source_range(0, len(view.text)) == (0, len(view.text))
        for view in result.views
    )


@pytest.mark.parametrize("suffix", ["\\u0041", "&#65;", "&#x41;"])
def test_escaped_extension_maps_to_the_same_physical_token_start(suffix):
    value = _value()
    line = f'key="{value}{suffix}"'
    result = _scan(line)
    assert result.complete and len(result.views) == 1
    view = result.views[0]
    assert view.text == value + "A"
    assert view.frame == ()
    offset = line.index(value)
    assert view.source_range(0, len(view.text)) == (
        offset,
        offset + len(value) + len(suffix),
    )
    assert view.source_range(len(value), len(value) + 1) == (
        offset + len(value),
        offset + len(value) + len(suffix),
    )
    assert view.source_range(0, 4) == (offset, offset + 4)


def test_escape_mapping_inside_base64_preserves_the_decoded_parent_frame():
    value = _value()
    payload = value + "\\u0041"
    outer = _encode(payload)
    result = _scan(outer)
    assert result.complete and len(result.views) == 2
    before, after = result.views
    assert before.frame == after.frame == ((0, len(outer)),)
    assert before.source_range(0, len(value)) == (0, len(value))
    assert after.source_range(0, len(value) + 1) == (0, len(payload))


def test_commuting_escape_paths_do_not_duplicate_one_physical_occurrence():
    value = _value()
    container = "\\u0067\\u0068\\u0070&lowbar;" + value[4:]
    result = _scan(f'key="{container}"')
    assert result.complete and len(result.views) == 1
    view = result.views[0]
    assert view.text == value and view.frame == ()
    assert view.source_range(0, len(view.text)) == (5, 5 + len(container))


def test_multichar_html_entity_maps_both_characters_to_the_original_entity():
    value = "ghp_fj" + _value()[6:]
    container = value.replace("fj", "&fjlig;", 1)
    result = _scan(container)
    assert result.complete and len(result.views) == 1
    view = result.views[0]
    assert view.text == value and view.frame == ()
    assert view.source_range(4, 5) == view.source_range(5, 6) == (4, 11)


def test_chained_escape_maps_compose_without_treating_utf8_bytes_as_columns():
    value = _value()
    container = "\\u0067\\u0068\\u0070&lowbar;" + value[4:]
    line = f'🙂 key="{container}"'
    result = _scan(line)
    assert result.complete and len(result.views) == 1
    view = result.views[0]
    offset = line.index(container)
    assert view.frame == ()
    assert view.source_range(0, 1) == (offset, offset + 6)
    assert view.source_range(3, 4) == (offset + 18, offset + 26)
    assert view.source_range(4, 8) == (offset + 26, offset + 30)


@pytest.mark.parametrize("span", [(-1, 1), (0, 0), (0, 1000), (0.5, 2), (False, 2)])
def test_source_mapping_rejects_invalid_decoded_ranges(span):
    result = _scan(_encode(_value()))
    with pytest.raises(ValueError, match="nonempty and within"):
        result.views[0].source_range(*span)


def test_many_identical_escaped_values_keep_distinct_root_locations():
    value = _value()
    encoded = "\\u0067" + value[1:]
    count = 4000
    result = _scan(
        " ".join([encoded] * count),
        max_candidates=count + 1,
        max_decoded_bytes=count * len(value) + 128,
    )
    assert result.complete
    assert len(result.views) == count
    stride = len(encoded) + 1
    assert [view.source_range(0, len(value)) for view in result.views] == [
        (index * stride, index * stride + len(encoded)) for index in range(count)
    ]


def test_many_provider_queries_use_one_compressed_escape_map():
    count = 4000
    values = [
        "SK" + hashlib.sha256(str(index).encode()).hexdigest()[:32]
        for index in range(count)
    ]
    encoded = "|".join("\\u0053" + value[1:] for value in values)
    result = decode_provider_views(
        encoded,
        provider_prefixes=("SK",),
        max_candidate_chars=len(encoded),
        max_decoded_bytes=len(encoded),
    )
    assert result.complete and len(result.views) == 1
    view = result.views[0]
    assert view.frame == ()
    assert view.text == "|".join(values)
    assert [
        view.source_range(index * 35, index * 35 + 34) for index in range(count)
    ] == [(index * 40, index * 40 + 39) for index in range(count)]


def test_unicode_escaped_padding_has_one_canonical_complete_container():
    value = _value()
    encoded = _encode(value)
    assert encoded.endswith("==")
    container = encoded[:-2] + "\\u003d\\u003d"
    line = f'key="{container}"'
    result = _scan(line)
    assert result.complete
    assert len(result.views) == 1
    view = result.views[0]
    assert view.text == value and view.complete_value
    assert view.encodings == ("unicode", "base64")
    assert line[view.start : view.end] == container


def test_canonicalization_does_not_merge_disjoint_occurrences():
    encoded = _encode(_value())[:-2] + "\\u003d\\u003d"
    result = _scan(f'first="{encoded}" second="{encoded}"')
    assert result.complete
    assert len(result.views) == 2
    assert result.views[0].end < result.views[1].start
    assert all(view.complete_value for view in result.views)


def test_nested_subvalue_cannot_prove_the_whole_encoded_container_is_one_secret():
    value = _value()
    payload = "prefix:" + _encode(value) + ";another_field=unchanged"
    encoded = _encode(payload)
    result = _scan(encoded)
    assert result.complete
    assert len(result.views) == 1
    view = result.views[0]
    assert view.text == value
    assert not view.complete_value
    assert (view.start, view.end) == (0, len(encoded))


def test_decoded_text_with_prefix_and_suffix_is_not_collapsed_to_a_subvalue():
    value = _value()
    payload = value + ";nested=" + _encode(value)
    result = _scan(_encode(payload))
    assert result.complete
    assert len(result.views) == 2
    assert result.views[0].text == payload and result.views[0].complete_value
    assert result.views[1].text == value and not result.views[1].complete_value


def test_unicode_escaped_provider_is_only_a_candidate_for_the_normal_detector():
    value = _value()
    encoded = "".join(f"\\u{ord(character):04x}" for character in value[:4]) + value[4:]
    result = _scan(f'key="{encoded}"')
    assert result.complete
    assert [(view.text, view.encodings) for view in result.views] == [
        (value, ("unicode",))
    ]


@pytest.mark.parametrize("entity", ["&#95;", "&#x5f;", "&lowbar;"])
def test_html_entity_provider_retains_its_container(entity):
    value = _value()
    encoded = value.replace("_", entity, 1)
    line = f'<meta content="{encoded}">'
    result = _scan(line)
    assert result.complete
    assert len(result.views) == 1
    assert result.views[0].text == value
    assert result.views[0].encodings == ("html",)
    assert line[result.views[0].start : result.views[0].end] == encoded


def test_base64_can_contain_unicode_escapes():
    value = _value()
    escaped = "".join(f"\\u{ord(character):04x}" for character in value)
    result = _scan(_encode(escaped))
    assert result.complete
    assert [(view.text, view.encodings) for view in result.views] == [
        (value, ("base64", "unicode"))
    ]


def test_html_can_contain_base64():
    value = _value()
    encoded = "".join(f"&#{ord(character)};" for character in _encode(value))
    result = _scan(encoded)
    assert result.complete
    assert [(view.text, view.encodings) for view in result.views] == [
        (value, ("html", "base64"))
    ]


def test_prefix_hint_is_not_a_provider_validator():
    # The caller's full provider regex must reject this short lookalike.
    result = _scan(_encode("ghp_not_long_enough"))
    assert result.complete
    assert len(result.views) == 1
    assert result.views[0].text == "ghp_not_long_enough"


@pytest.mark.parametrize(
    "source",
    [
        "ordinary code and prose without an encoded credential",
        "\\uZZZZ and \\U00110000",
        "&notarealentity;",
        "YWJjZA===",  # Too many padding characters.
        "YQ=",  # A padded value must have complete groups.
        "Z2hw_+/a" * 4,  # Mixing standard and URL-safe alphabets.
    ],
)
def test_invalid_or_inert_text_stays_quiet(source):
    result = _scan(source)
    assert result.complete and result.views == ()
    assert result.diagnostics == ()


def test_noncanonical_padding_does_not_create_a_provider_view():
    encoded = _encode(_value())
    result = _scan(encoded + "=")
    assert result.complete and result.views == ()


def test_nonzero_unused_pad_bits_do_not_create_a_provider_view():
    encoded = _encode(_value())
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
    assert encoded.endswith("==")
    index = len(encoded) - 3
    replacement = alphabet[alphabet.index(encoded[index]) + 1]
    noncanonical = encoded[:index] + replacement + encoded[index + 1 :]
    assert base64.b64decode(noncanonical) == base64.b64decode(encoded)
    result = _scan(noncanonical)
    assert result.complete and result.views == ()


def test_public_checksum_is_not_treated_as_a_generic_decoded_secret():
    digest = base64.b64encode(
        hashlib.sha256(b"public fixture digest").digest()
    ).decode()
    result = _scan(f'integrity="sha256-{digest}"')
    assert result.complete and result.views == ()


def test_many_public_checksums_do_not_consume_the_recursive_work_budget():
    digests = [
        base64.b64encode(hashlib.sha256(str(number).encode()).digest()).decode()
        for number in range(1000)
    ]
    result = _scan(" ".join(digests))
    assert result.complete and result.views == ()
    assert result.candidates_checked == result.decoded_bytes == 0


def test_harmless_html_entities_do_not_exhaust_recursive_candidate_budget():
    result = _scan(" ".join("documentation&amp;label" for _ in range(1000)))
    assert result.complete and result.views == ()
    assert result.candidates_checked == result.decoded_bytes == 0


def test_no_prefixes_means_no_provider_decoding_work():
    result = decode_provider_views(_encode(_value()), provider_prefixes=())
    assert result.complete and result.views == ()
    assert result.candidates_checked == result.decoded_bytes == 0


def test_candidate_count_exhaustion_retains_the_first_finding_and_reports_incomplete():
    encoded = _encode(_value())
    result = _scan(f'"{encoded}" "{encoded}"', max_candidates=1)
    assert not result.complete
    assert result.diagnostics == ("secret_decode_candidate_count_limit",)
    assert len(result.views) == 1
    assert result.candidates_checked == 1


def test_byte_budget_is_shared_across_containers():
    value = _value()
    encoded = _encode(value)
    result = _scan(f'"{encoded}" "{encoded}"', max_decoded_bytes=len(value))
    assert not result.complete
    assert result.diagnostics == ("secret_decode_byte_limit",)
    assert len(result.views) == 1
    assert result.decoded_bytes == len(value)


@pytest.mark.parametrize(
    "limit, diagnostic",
    [
        ("max_candidates", "secret_decode_candidate_count_limit"),
        ("max_decoded_bytes", "secret_decode_byte_limit"),
    ],
)
def test_zero_remaining_file_budget_is_only_incomplete_for_a_plausible_carrier(
    limit, diagnostic
):
    limits = {limit: 0}
    inert = _scan("normal&amp;prose", **limits)
    assert inert.complete and inert.views == ()
    encoded = _scan(_encode(_value()), **limits)
    assert not encoded.complete and encoded.views == ()
    assert encoded.diagnostics == (diagnostic,)


def test_oversized_candidate_is_not_silently_skipped():
    result = _scan(_encode(_value()), max_candidate_chars=32)
    assert not result.complete and result.views == ()
    assert result.diagnostics == ("secret_decode_candidate_limit",)


@pytest.mark.parametrize("filler", ["A", "a", "abcdefghijklmnop", "sourceIdentifier"])
def test_oversized_nontext_base64_looking_filler_does_not_claim_incomplete(filler):
    value = (filler * (100_000 // len(filler) + 1))[:100_000]
    result = _scan(f'content="{value}"')
    assert result.complete and result.views == ()
    assert result.candidates_checked == result.decoded_bytes == 0


def test_oversized_printable_carrier_cannot_hide_a_provider_beyond_the_prefix_probe():
    encoded = _encode("harmless prefix " * 10_000 + _value())
    result = _scan(encoded)
    assert not result.complete and result.views == ()
    assert result.diagnostics == ("secret_decode_candidate_limit",)


def test_prefix_probe_does_not_mistake_an_unfinished_utf8_character_for_binary():
    encoded = _encode("🙂" * 100 + _value())
    result = _scan(encoded, max_candidate_chars=36)
    assert not result.complete and result.views == ()
    assert result.diagnostics == ("secret_decode_candidate_limit",)


def test_depth_exhaustion_reports_incomplete_instead_of_a_clean_result():
    value = _value()
    encoded = _encode(_encode(_encode(value)))
    limited = _scan(encoded)
    assert not limited.complete and limited.views == ()
    assert limited.diagnostics == ("secret_decode_depth_limit",)
    complete = _scan(encoded, max_depth=3)
    assert complete.complete
    assert [(view.text, view.encodings) for view in complete.views] == [
        (value, ("base64", "base64", "base64"))
    ]


def test_result_debug_repr_and_diagnostics_never_expose_decoded_credentials():
    value = _value()
    result = _scan(_encode(value))
    assert result.views
    assert value not in repr(result)
    assert value not in " ".join(result.diagnostics)


@pytest.mark.parametrize(
    "limits",
    [
        {"max_depth": 0},
        {"max_depth": 4},
        {"max_candidates": -1},
        {"max_decoded_bytes": -1},
        {"max_candidate_chars": 0},
    ],
)
def test_invalid_limits_are_explicit_errors(limits):
    with pytest.raises(ValueError, match="bounded limits"):
        _scan("unused", **limits)


def test_empty_provider_prefix_is_not_allowed_to_match_every_decoded_value():
    with pytest.raises(ValueError, match="nonempty strings"):
        decode_provider_views(_encode(_value()), provider_prefixes=("",))
