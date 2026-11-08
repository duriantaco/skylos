"""Issuer records require actual private components in the same literal scope."""

from __future__ import annotations

import base64
import hashlib
import json
from math import lcm

import pytest

from skylos.rules import secret_credentials as credentials
from skylos.rules.secrets import scan_ctx


# Public, deterministic test material; no provider-issued credential is used.
AZURE_KEY = base64.b64encode(
    hashlib.sha512(b"public synthetic Azure fixture").digest()
).decode()
AWS_ID = "AKIA" + hashlib.sha256(b"public AWS ID").hexdigest()[:16].upper()
AWS_TEMP_ID = "ASIA" + AWS_ID[4:]
AWS_SECRET = base64.b64encode(
    hashlib.sha256(b"public AWS secret fixture").digest()
).decode()[:40]
AWS_SESSION = base64.b64encode(
    hashlib.sha512(b"public AWS session fixture").digest()
).decode()
AZURE_EMULATOR_KEY = (
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6"
    "IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
)


def _der(tag, data):
    length = len(data)
    if length < 128:
        encoded_length = bytes([length])
    else:
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        encoded_length = bytes([128 | len(encoded)]) + encoded
    return bytes([tag]) + encoded_length + data


def _integer(value):
    data = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if data[0] & 128:
        data = b"\0" + data
    return _der(2, data)


def _public_fixture_rsa_pem():
    # Published Mersenne primes make this deliberately public test-only key.
    p, q, e = (1 << 521) - 1, (1 << 127) - 1, 65537
    d = pow(e, -1, lcm(p - 1, q - 1))
    values = (0, p * q, e, d, p, q, d % (p - 1), d % (q - 1), pow(q, -1, p))
    rsa = _der(48, b"".join(_integer(value) for value in values))
    algorithm = bytes.fromhex("300d06092a864886f70d0101010500")
    pkcs8 = _der(48, _integer(0) + algorithm + _der(4, rsa))
    body = base64.b64encode(pkcs8).decode()
    return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n"


def _azure(key=AZURE_KEY, account="skylosfixture", **extra):
    fields = {
        "DefaultEndpointsProtocol": "https",
        "AccountName": account,
        "AccountKey": key,
        **extra,
    }
    return ";".join(f"{name}={value}" for name, value in fields.items())


def _aws(identifier=AWS_ID, secret=AWS_SECRET, **extra):
    return {"accessKeyId": identifier, "secretAccessKey": secret, **extra}


def _scan(text, file_kind=""):
    result = credentials.scan_credential_records(text, file_kind=file_kind)
    assert result.issues == ()
    return result.matches


def _native(text, path="README.md"):
    return list(
        scan_ctx({"relpath": path, "lines": text.splitlines(True), "tree": None})
    )


@pytest.mark.parametrize(
    "wrapper", ["{}", 'VALUE = "{}";', "`{}`", "<add value='{}' />"]
)
def test_azure_complete_literal_maps_only_private_account_key(wrapper):
    text = wrapper.format(_azure(EndpointSuffix="core.windows.net"))
    matches = _scan(text)
    assert len(matches) == 1
    match = matches[0]
    assert match.provider == "azure_storage_account_key"
    assert text[match.start : match.end] == AZURE_KEY
    assert match.evidence["key_bytes"] == 64
    assert match.evidence["verified"] is False
    assert AZURE_KEY not in repr(match)
    assert "skylosfixture" not in repr(match)


@pytest.mark.parametrize(
    "source",
    [
        "AccountName=skylosfixture;AccountKey=" + AZURE_KEY,
        "AccountKey=" + AZURE_KEY + ";AccountName=skylosfixture",
        "accountname=skylosfixture;accountkey=" + AZURE_KEY,
        "AccountName = skylosfixture ; AccountKey = " + AZURE_KEY,
        _azure(EndpointSuffix="core.chinacloudapi.cn"),
        _azure(BlobEndpoint="https://storage.example.invalid/container"),
        _azure(account="devstoreaccount1"),
        _azure(UseDevelopmentStorage="true"),
    ],
)
def test_azure_complete_record_variants_keep_real_private_component(source):
    (match,) = _scan(source)
    assert source[match.start : match.end] == AZURE_KEY


@pytest.mark.parametrize(
    "source",
    [
        "AccountName=skylosfixture",
        "AccountKey=" + AZURE_KEY,
        "AccountName=skylosfixture\nAccountKey=" + AZURE_KEY,
        "AccountName=skylosfixture; unrelated=yes; AccountKey=" + AZURE_KEY,
        '"AccountName=skylosfixture"; other="AccountKey=' + AZURE_KEY + '"',
        _azure(key="${AZURE_ACCOUNT_KEY}"),
        _azure(key="<account-key>"),
        _azure(key=base64.b64encode(b"x" * 64).decode()),
        _azure(key=base64.b64encode(hashlib.sha256(b"32-byte-key").digest()).decode()),
        _azure(key=AZURE_KEY[:-1]),
        _azure(key=AZURE_KEY[:-2] + "_="),
        _azure(key=AZURE_EMULATOR_KEY),
        _azure(account="UPPERCASE"),
        _azure(account="ab"),
        _azure(account="a" * 25),
        _azure(DefaultEndpointsProtocol="ftp"),
        _azure(BlobEndpoint="storage.example.invalid"),
        _azure(BlobEndpoint="https://user:pass@storage.example.invalid"),
        _azure() + ";AccountName=anotheraccount",
        _azure() + ";AccountKey=" + AZURE_KEY,
    ],
)
def test_azure_public_incomplete_placeholder_or_ambiguous_records_are_quiet(source):
    assert _scan(source) == ()


def test_azure_noncanonical_base64_padding_bits_are_not_private_key_proof():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    # The final nonpadding character represents only two real data bits.
    index = alphabet.index(AZURE_KEY[-3])
    mutated = AZURE_KEY[:-3] + alphabet[index | 1] + "=="
    assert base64.b64decode(mutated) == base64.b64decode(AZURE_KEY)
    assert _scan(_azure(key=mutated)) == ()


def test_two_azure_literals_stay_separate_with_precise_offsets():
    text = 'a="' + _azure() + '";b="' + _azure() + '"'
    matches = _scan(text)
    assert len(matches) == 2
    assert matches[0].start != matches[1].start
    assert all(text[m.start : m.end] == AZURE_KEY for m in matches)


@pytest.mark.parametrize(
    "names",
    [
        ("accessKeyId", "secretAccessKey", "sessionToken"),
        ("AccessKeyId", "SecretAccessKey", "SessionToken"),
        ("aws_access_key_id", "aws_secret_access_key", "aws_session_token"),
        ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"),
    ],
)
@pytest.mark.parametrize("temporary", [False, True])
def test_aws_complete_record_pairs_direct_siblings_only(names, temporary):
    id_name, secret_name, session_name = names
    identifier = AWS_TEMP_ID if temporary else AWS_ID
    value = {id_name: identifier, secret_name: AWS_SECRET}
    if temporary:
        value[session_name] = AWS_SESSION
    text = json.dumps({"credentials": value})
    (match,) = _scan(text)
    assert match.provider == "aws_secret_access_key"
    assert text[match.start : match.end] == AWS_SECRET
    assert match.evidence["complete_components"] == (3 if temporary else 2)
    assert match.evidence["temporary"] is temporary
    assert match.related_spans[0].role == "access_key_id"
    span = match.related_spans[0]
    assert text[span.start : span.end] == identifier
    assert AWS_SECRET not in repr(match)
    assert identifier not in repr(match)


@pytest.mark.parametrize(
    "value",
    [
        {"accessKeyId": AWS_ID},
        {"secretAccessKey": AWS_SECRET},
        {"id": {"accessKeyId": AWS_ID}, "secretAccessKey": AWS_SECRET},
        [{"accessKeyId": AWS_ID}, {"secretAccessKey": AWS_SECRET}],
        _aws(identifier=AWS_TEMP_ID),
        _aws(identifier=AWS_TEMP_ID, sessionToken="${AWS_SESSION_TOKEN}"),
        _aws(identifier="AGPA" + AWS_ID[4:]),
        _aws(identifier="AKIA" + "A" * 16),
        _aws(identifier="AKIA" + "IOSFODNN7EXAMPLE"),
        _aws(secret="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        _aws(secret="${AWS_SECRET_ACCESS_KEY}"),
        _aws(secret="A" * 40),
        _aws(secret=AWS_SECRET[:-1]),
        _aws(secret=AWS_SECRET + "a"),
        _aws(AWS_SECRET_ACCESS_KEY=AWS_SECRET),
    ],
)
def test_aws_public_split_placeholder_or_incomplete_pairs_are_quiet(value):
    assert _scan(json.dumps(value)) == ()


def test_aws_repeated_records_each_keep_their_own_source_span():
    text = json.dumps([_aws(), _aws()])
    matches = _scan(text)
    assert len(matches) == 2
    assert matches[0].start != matches[1].start
    assert all(text[m.start : m.end] == AWS_SECRET for m in matches)


def test_aws_duplicate_direct_json_key_does_not_establish_a_pair():
    text = (
        '{"accessKeyId":'
        + json.dumps(AWS_ID)
        + ',"secretAccessKey":'
        + json.dumps(AWS_SECRET)
        + ',"accessKeyId":'
        + json.dumps(AWS_ID)
        + "}"
    )
    assert _scan(text) == ()


@pytest.mark.parametrize("suffix", ["ini", "cfg", "conf", "credentials", "config"])
def test_aws_profile_pair_carries_no_profile_name_or_values(suffix):
    text = (
        "[private-profile-name]\naws_access_key_id="
        + AWS_ID
        + "\naws_secret_access_key="
        + AWS_SECRET
        + "\n"
    )
    (match,) = _scan(text, suffix)
    assert text[match.start : match.end] == AWS_SECRET
    assert match.evidence["record_format"] == "ini_profile"
    assert "private-profile-name" not in repr(match)


@pytest.mark.parametrize(
    "text",
    [
        "[one]\naws_access_key_id="
        + AWS_ID
        + "\n[two]\naws_secret_access_key="
        + AWS_SECRET,
        "aws_access_key_id=" + AWS_ID + "\naws_secret_access_key=" + AWS_SECRET,
        "[one]\naws_access_key_id="
        + AWS_ID
        + "\nmalformed content\naws_secret_access_key="
        + AWS_SECRET,
        "[one]\naws_access_key_id="
        + AWS_ID
        + "\naws_access_key_id="
        + AWS_ID
        + "\naws_secret_access_key="
        + AWS_SECRET,
    ],
)
def test_aws_ini_never_joins_profiles_or_malformed_settings(text):
    assert _scan(text, "ini") == ()


def test_aws_profile_syntax_is_not_applied_to_arbitrary_source():
    text = (
        "[profile]\naws_access_key_id="
        + AWS_ID
        + "\naws_secret_access_key="
        + AWS_SECRET
    )
    assert _scan(text, "py") == ()


def test_aws_profile_accepts_actual_filename_and_preserves_source_coordinates():
    text = (
        "[profile fixture]\naws_access_key_id="
        + AWS_ID
        + "\naws_secret_access_key="
        + AWS_SECRET
    )
    (match,) = _scan(text, "settings/credentials.ini")
    assert text[match.start : match.end] == AWS_SECRET


def test_irrelevant_large_text_does_not_add_a_credential_parser_limit(monkeypatch):
    monkeypatch.setattr(credentials, "MAX_RECORD_TEXT", 32)
    result = credentials.scan_credential_records('{"integrity":"' + "a" * 256 + '"}')
    assert result.matches == ()
    assert result.issues == ()


def test_relevant_marker_beyond_input_cap_is_reported_incomplete(monkeypatch):
    monkeypatch.setattr(credentials, "MAX_RECORD_TEXT", 32)
    result = credentials.scan_credential_records("a" * 256 + _azure())
    assert result.matches == ()
    assert result.issues == ("credential_record_text_limit",)


def _google(private_key=None, **changes):
    return {
        "type": "service_account",
        "client_email": "fixture@project.iam.gserviceaccount.com",
        "private_key": _public_fixture_rsa_pem()
        if private_key is None
        else private_key,
        **changes,
    }


def test_google_service_account_requires_full_private_material_in_same_record():
    text = json.dumps({"credentials": _google()})
    (match,) = _scan(text)
    assert match.provider == "google_service_account"
    assert (
        json.loads('"' + text[match.start : match.end] + '"')
        == _public_fixture_rsa_pem()
    )
    assert match.evidence["key_algorithm"] == "RSA"
    assert match.evidence["complete_components"] == 3
    assert match.evidence["verified"] is False
    assert "fixture@" not in repr(match)
    assert _public_fixture_rsa_pem() not in repr(match)


@pytest.mark.parametrize(
    "record",
    [
        _google(
            private_key="-----BEGIN PRIVATE KEY-----\n<private key>\n-----END PRIVATE KEY-----"
        ),
        _google(private_key="-----BEGIN PRIVATE KEY-----"),
        _google(
            private_key="-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----"
        ),
        _google(private_key="${GOOGLE_PRIVATE_KEY}"),
        _google(type="authorized_user"),
        _google(client_email="fixture@example.invalid"),
        {
            "type": "service_account",
            "client_email": "fixture@project.iam.gserviceaccount.com",
        },
        {
            "type": "service_account",
            "private_key": _public_fixture_rsa_pem(),
            "nested": {"client_email": "fixture@project.iam.gserviceaccount.com"},
        },
    ],
)
def test_google_metadata_alone_or_public_and_elided_material_is_quiet(record):
    assert _scan(json.dumps(record)) == ()


def test_json_string_spans_preserve_escaped_unicode_and_quotes():
    text = '{"key":"a\\u0062\\"c"}'
    result = credentials.iter_json_string_records(text)
    (record,) = result.records
    scalar = record.fields["key"]
    assert scalar.value == 'ab"c'
    assert text[scalar.start : scalar.end] == 'a\\u0062\\"c'
    assert scalar.value not in repr(scalar)
    assert scalar.value not in repr(record)


def test_json_record_boundaries_do_not_merge_nested_children():
    text = '{"outer":"safe","nested":{"key":"private"},"other":[{"value":"separate"}]}'
    result = credentials.iter_json_string_records(text)
    assert {tuple(r.fields) for r in result.records} == {
        ("key",),
        ("value",),
        ("outer",),
    }


def test_invalid_outer_json_cannot_bless_an_outer_pair():
    text = (
        '{"accessKeyId":'
        + json.dumps(AWS_ID)
        + ', "secretAccessKey":'
        + json.dumps(AWS_SECRET)
        + ",bad}"
    )
    assert _scan(text) == ()


@pytest.mark.parametrize("space", ["\v", "\f", "\u00a0"])
def test_non_json_whitespace_does_not_establish_literal_json_record(space):
    text = json.dumps(_aws()).replace(", ", "," + space)
    assert _scan(text) == ()


@pytest.mark.parametrize(
    "limit,value,expected",
    [
        ("MAX_RECORD_TEXT", 16, "credential_record_text_limit"),
        ("MAX_JSON_NODES", 1, "json_record_node_limit"),
        ("MAX_JSON_DEPTH", 0, "json_record_depth_limit"),
        ("MAX_JSON_RECORDS", 0, "json_record_count_limit"),
        ("MAX_JSON_STRING", 3, "json_record_string_limit"),
        ("MAX_JSON_WORK", 4, "json_record_work_limit"),
    ],
)
def test_json_safety_limits_are_explicit_incomplete_evidence(
    monkeypatch, limit, value, expected
):
    monkeypatch.setattr(credentials, limit, value)
    result = credentials.iter_json_string_records(json.dumps(_aws()))
    assert result.issues == (expected,)


def test_connection_record_bound_is_explicit(monkeypatch):
    monkeypatch.setattr(credentials, "MAX_CONNECTION_RECORD", 10)
    result = credentials.scan_credential_records(_azure())
    assert result.matches == ()
    assert result.issues == ("connection_record_limit",)


def test_native_azure_private_key_reaches_provider_only_document():
    text = _azure()
    findings = _native(text)
    assert [f["provider"] for f in findings] == ["azure_storage_account_key"]
    assert text[findings[0]["col"] : findings[0]["end_col"]] == AZURE_KEY
    assert AZURE_KEY not in json.dumps(findings)


def test_native_aws_pair_adds_secret_without_hiding_public_id_legacy_finding():
    text = json.dumps(_aws())
    findings = _native(text)
    assert [f["provider"] for f in findings].count("aws_access_key_id") == 1
    assert [f["provider"] for f in findings].count("aws_secret_access_key") == 1
    assert AWS_SECRET not in json.dumps(findings)


def test_native_google_pair_annotates_existing_private_material_once():
    findings = _native(json.dumps(_google()))
    key_findings = [f for f in findings if f["provider"] == "private_key_block"]
    assert len(key_findings) == 1
    assert (
        key_findings[0]["structured_credential"]["credential_record"]
        == "google_service_account"
    )
    assert not any(f["provider"] == "google_service_account" for f in findings)


def test_native_google_unicode_private_header_is_enriched_once():
    text = json.dumps(_google()).replace(
        "-----BEGIN", r"\u002d\u002d\u002d\u002d\u002dBEGIN"
    )
    findings = _native(text)
    assert [f["provider"] for f in findings] == ["private_key_block"]
    finding = findings[0]
    assert (
        finding["structured_credential"]["credential_record"]
        == "google_service_account"
    )
    assert finding["decoding"]["source_path"] == [[finding["col"], finding["end_col"]]]


@pytest.mark.parametrize(
    "encoding",
    [
        lambda text: text,
        json.dumps,
        lambda text: base64.b64encode(text.encode()).decode(),
    ],
)
def test_native_repeated_google_records_keep_two_enriched_occurrences(encoding):
    findings = _native(encoding(json.dumps([_google(), _google()])))
    keys = [f for f in findings if f["provider"] == "private_key_block"]
    assert len(keys) == 2
    assert all(
        f["structured_credential"]["credential_record"] == "google_service_account"
        for f in keys
    )
    identities = [
        json.dumps(f.get("decoding", {}).get("source_path", [f["col"], f["end_col"]]))
        for f in keys
    ]
    assert len(set(identities)) == 2
    assert not any(f["provider"] == "google_service_account" for f in findings)


@pytest.mark.parametrize(
    "encoding",
    [lambda text: text, lambda text: base64.b64encode(text.encode()).decode()],
)
def test_native_google_record_never_enriches_unpaired_encoded_key(encoding):
    record = encoding(json.dumps(_google()))
    unpaired = base64.b64encode(_public_fixture_rsa_pem().encode()).decode()
    findings = _native(record + "; standalone=" + unpaired)
    keys = [f for f in findings if f["provider"] == "private_key_block"]
    assert len(keys) == 2
    paired = [
        f
        for f in keys
        if f.get("structured_credential", {}).get("credential_record")
        == "google_service_account"
    ]
    assert len(paired) == 1


def test_google_public_record_cannot_borrow_a_separate_encoded_private_key():
    record = json.dumps(
        {
            "type": "service_account",
            "client_email": "fixture@project.iam.gserviceaccount.com",
        }
    )
    unpaired = base64.b64encode(_public_fixture_rsa_pem().encode()).decode()
    findings = _native(record + "; standalone=" + unpaired)
    keys = [f for f in findings if f["provider"] == "private_key_block"]
    assert len(keys) == 1
    assert not keys[0].get("structured_credential")
