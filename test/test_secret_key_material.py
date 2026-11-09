"""Private-key evidence uses complete bounded records, never public markers."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
from math import lcm

import pytest

from skylos.rules import secret_key_material as material


def _url(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _uint(value):
    return _url(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def _rsa(crt=True):
    # Publicly known Mersenne primes produce a deterministic, explicitly
    # non-issued private fixture.  No external secret or crypto library is used.
    p, q = (1 << 521) - 1, (1 << 127) - 1
    e = 65537
    d = pow(e, -1, lcm(p - 1, q - 1))
    values = {
        "n": p * q,
        "e": e,
        "d": d,
        "p": p,
        "q": q,
        "dp": d % (p - 1),
        "dq": d % (q - 1),
        "qi": pow(q, -1, p),
    }
    result = {"kty": "RSA"}
    result.update(
        {
            name: _uint(value)
            for name, value in values.items()
            if crt or name in ("n", "e", "d")
        }
    )
    return result


def _ec(curve="P-256"):
    # Structural fixtures intentionally make no mathematical x/y = dG claim.
    width = {"P-256": 32, "P-384": 48, "P-521": 66}[curve]
    return {
        "kty": "EC",
        "crv": curve,
        "x": _url(bytes(range(width))),
        "y": _url(bytes(reversed(range(width)))),
        "d": _url((17).to_bytes(width, "big")),
    }


def _okp(curve="Ed25519"):
    width = {"Ed25519": 32, "X25519": 32, "Ed448": 57, "X448": 56}[curve]
    return {
        "kty": "OKP",
        "crv": curve,
        "x": _url(hashlib.sha512(b"public fixture").digest()[:width]),
        "d": _url(hashlib.sha512(b"private fixture").digest()[:width]),
    }


JWK_CASES = [
    pytest.param(_rsa(False), "RSA", id="rsa-minimal"),
    pytest.param(_rsa(), "RSA", id="rsa-crt"),
    *[
        pytest.param(_ec(curve), "EC", id=curve)
        for curve in ("P-256", "P-384", "P-521")
    ],
    *[
        pytest.param(_okp(curve), "OKP", id=curve)
        for curve in ("Ed25519", "Ed448", "X25519", "X448")
    ],
    pytest.param(
        {"kty": "oct", "k": _url(hashlib.sha256(b"symmetric fixture").digest())},
        "oct",
        id="symmetric",
    ),
]


@pytest.mark.parametrize("record,algorithm", JWK_CASES)
@pytest.mark.parametrize("prefix", ["", "α before\nconst literal = "])
def test_private_jwk_offsets_and_safe_structure_evidence(record, algorithm, prefix):
    source = prefix + json.dumps(record, indent=2) + "; trailing text"
    result = material.scan_private_jwk_objects(source)
    assert result.issues == ()
    assert len(result.matches) == 1
    candidate = result.matches[0]
    expected = "jwk_symmetric_key" if algorithm == "oct" else "jwk_private_key"
    assert candidate.provider == expected
    main = "k" if algorithm == "oct" else "d"
    assert source[candidate.start : candidate.end] == record[main]
    assert candidate.evidence["algorithm"] == algorithm
    assert candidate.evidence["validation"] == "structural"
    assert record[main] not in repr(result)
    assert record[main] not in json.dumps(dataclasses.asdict(result))
    private_names = material.private_jwk_member_names(record)
    assert main in private_names
    assert not set(private_names).intersection({"x", "y", "n", "e", "kty", "crv"})
    if algorithm == "RSA" and "p" in record:
        assert set(private_names) == {"d", "p", "q", "dp", "dq", "qi"}
        assert {source[span.start : span.end] for span in candidate.related_spans} == {
            record[name] for name in private_names if name != "d"
        }
    else:
        assert candidate.related_spans == ()


@pytest.mark.parametrize("record,algorithm", JWK_CASES)
def test_public_jwk_without_private_members_stays_quiet(record, algorithm):
    public = {
        name: value
        for name, value in record.items()
        if name not in {"d", "p", "q", "dp", "dq", "qi", "k"}
    }
    result = material.scan_private_jwk_objects(json.dumps(public))
    assert result.matches == ()
    assert result.issues == ()
    assert material.private_jwk_member_names(public) == ()


@pytest.mark.parametrize(
    "mutator",
    [
        lambda data: data.update(d="<redacted>"),
        lambda data: data.update(d="Zg=="),
        lambda data: data.update(d="A"),
        lambda data: data.update(d=_url(bytes(31))),
        lambda data: data.update(d=_url(bytes(33))),
        lambda data: data.update(d=_url(bytes(32))),
        lambda data: data.update(crv="unsupported"),
        lambda data: data.pop("x"),
        lambda data: data.pop("y"),
    ],
)
def test_incomplete_or_malformed_ec_private_record_is_not_proven(mutator):
    data = _ec()
    mutator(data)
    assert material.scan_private_jwk_objects(json.dumps(data)).matches == ()
    assert material.private_jwk_member_names(data) == ()


@pytest.mark.parametrize(
    "mutator",
    [
        lambda data: data.update(n=_uint(17)),
        lambda data: data.update(e=_uint(2)),
        lambda data: data.update(d=_uint(0)),
        lambda data: data.update(d=_uint(2)),
        lambda data: data.update(p=_uint(19)),
        lambda data: data.update(qi=_uint(1)),
        lambda data: data.update(dp=_uint(1)),
        lambda data: data.pop("dq"),
    ],
)
def test_bad_rsa_members_do_not_gain_structural_proof(mutator):
    data = _rsa()
    mutator(data)
    assert material.scan_private_jwk_objects(json.dumps(data)).matches == ()


def test_separate_objects_and_duplicate_direct_members_never_form_a_key():
    key = _okp()
    public = {name: value for name, value in key.items() if name != "d"}
    for source in (
        json.dumps([public, {"d": key["d"]}]),
        '{"kty":"EC","kty":"OKP","crv":"Ed25519","x":"'
        + key["x"]
        + '","d":"'
        + key["d"]
        + '"}',
        json.dumps(
            {"kty": "OKP", "crv": "Ed25519", "x": key["x"], "nested": {"d": key["d"]}}
        ),
    ):
        assert material.scan_private_jwk_objects(source).matches == ()


def test_nested_jwk_set_retains_each_private_object_and_ignores_other_fields():
    a, b = _rsa(), _okp()
    source = json.dumps({"keys": [a, b], "d": "unrelated", "description": "test text"})
    result = material.scan_private_jwk_objects(source)
    assert len(result.matches) == 2
    assert result.issues == ()
    assert {source[item.start : item.end] for item in result.matches} == {
        a["d"],
        b["d"],
    }


def test_noncanonical_base64url_pad_bits_are_rejected():
    data = _okp()
    # 32 bytes use two bits in the final sextet. A different low nibble
    # decodes to identical bytes but is not canonical JWK base64url.
    good = data["d"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    data["d"] = good[:-1] + alphabet[alphabet.index(good[-1]) + 1]
    assert base64.urlsafe_b64decode(data["d"] + "=") == base64.urlsafe_b64decode(
        good + "="
    )
    assert material.scan_private_jwk_objects(json.dumps(data)).matches == ()


def test_jwk_record_and_value_limits_are_explicit(monkeypatch):
    source = json.dumps([_okp(), _ec()])
    monkeypatch.setattr(material, "MAX_JWK_RECORDS", 1)
    result = material.scan_private_jwk_objects(source)
    assert len(result.matches) == 1
    assert "jwk_record_limit" in result.issues
    monkeypatch.setattr(material, "MAX_JWK_VALUE_CHARS", 32)
    result = material.scan_private_jwk_objects(json.dumps(_okp()))
    assert result.matches == ()
    assert "jwk_value_limit" in result.issues


def test_irrelevant_or_public_only_large_inputs_never_enter_record_parser(monkeypatch):
    from skylos.rules import secret_credentials

    def forbidden(_text):
        raise AssertionError("irrelevant source must not enter the bounded JSON parser")

    monkeypatch.setattr(secret_credentials, "iter_json_string_records", forbidden)
    assert material.scan_private_jwk_objects(
        '{"integrity":"data"}' * 50_000
    ) == material.KeyScan(())
    public = {
        name: value for name, value in _rsa().items() if name in ("kty", "n", "e")
    }
    assert material.scan_private_jwk_objects(json.dumps(public)) == material.KeyScan(())


def test_unicode_escaped_jwk_member_names_remain_eligible():
    source = (
        json.dumps(_okp())
        .replace('"kty"', '"\\u006b\\u0074\\u0079"')
        .replace('"d"', '"\\u0064"')
    )
    result = material.scan_private_jwk_objects(source)
    assert len(result.matches) == 1
    assert result.issues == ()


def test_real_zero_octets_are_not_suppressed_as_placeholder_proof():
    # A zero Ed25519 seed or symmetric key remains private material. A name
    # or low entropy alone cannot prove a complete JWK is a safe placeholder.
    okp = _okp()
    okp["d"] = _url(bytes(32))
    octet = {"kty": "oct", "k": _url(bytes(16))}
    for record in (okp, octet):
        result = material.scan_private_jwk_objects(json.dumps(record))
        assert len(result.matches) == 1
        assert result.issues == ()


@pytest.mark.parametrize(
    "placeholder",
    [
        "replace-with-your-secret-key",
        "replace_with_your_secret_key",
        "your-secret-key-goes-here",
        "your_secret_key_goes_here",
    ],
)
def test_exact_whole_value_symmetric_jwk_instruction_is_not_a_key(placeholder):
    record = {"kty": "oct", "k": placeholder}
    assert material.scan_private_jwk_objects(json.dumps(record)).matches == ()
    assert material.private_jwk_member_names(record) == ()


def test_embedded_placeholder_words_and_encoded_actual_bytes_remain_keys():
    for value in (
        "AAAA-replace-with-your-secret-key-AAAA",
        _url(b"replace-with-your-secret-key"),
    ):
        record = {"kty": "oct", "k": value}
        result = material.scan_private_jwk_objects(json.dumps(record))
        assert len(result.matches) == 1
        assert result.issues == ()
        assert material.private_jwk_member_names(record) == ("k",)


@pytest.mark.parametrize(
    "value",
    [None, [], {"kty": []}, {"kty": "EC", "d": 3}, {"kty": "unknown", "d": "sample"}],
)
def test_audit_member_helper_handles_unrecognized_data_without_claiming_keys(value):
    assert material.private_jwk_member_names(value) == ()


def test_audit_member_helper_uses_only_fixed_member_lookups():
    class NoIterationDict(dict):
        def items(self):
            raise AssertionError("audit must not traverse an unbounded record")

        def values(self):
            raise AssertionError("audit must not traverse an unbounded record")

        def __iter__(self):
            raise AssertionError("audit must not traverse an unbounded record")

    record = NoIterationDict(
        {f"metadata_{index}": "unrelated" for index in range(16_384)}
    )
    record.update(_okp())
    assert material.private_jwk_member_names(record) == ("d",)


def test_long_unrelated_jwk_metadata_does_not_hide_small_private_key():
    record = _okp()
    record["description"] = "documentation " * 1_024
    assert len(record["description"]) > material.MAX_JWK_VALUE_CHARS
    result = material.scan_private_jwk_objects(json.dumps(record))
    assert len(result.matches) == 1
    assert result.issues == ()
    assert material.private_jwk_member_names(record) == ("d",)


def test_actual_oversized_private_jwk_member_still_reports_value_limit():
    record = _okp()
    record["d"] = "A" * (material.MAX_JWK_VALUE_CHARS + 4)
    result = material.scan_private_jwk_objects(json.dumps(record))
    assert result.matches == ()
    assert "jwk_value_limit" in result.issues
    assert material.private_jwk_member_names(record) == ()


def _der(tag, content):
    length = len(content)
    if length < 128:
        encoded = bytes([length])
    else:
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        encoded = bytes([128 + len(encoded)]) + encoded
    return bytes([tag]) + encoded + content


def _integer(value):
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 128:
        raw = b"\x00" + raw
    return _der(2, raw)


def _rsa_der():
    fields = _rsa()
    return _der(
        0x30,
        _integer(0)
        + b"".join(
            _integer(
                int.from_bytes(
                    base64.urlsafe_b64decode(
                        fields[name] + "=" * (-len(fields[name]) % 4)
                    ),
                    "big",
                )
            )
            for name in ("n", "e", "d", "p", "q", "dp", "dq", "qi")
        ),
    )


def _pem(label, raw):
    encoded = base64.b64encode(raw).decode()
    body = "\n".join(
        encoded[index : index + 64] for index in range(0, len(encoded), 64)
    )
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"


def _pkcs8(oid, private, params=b""):
    return _der(
        0x30,
        _integer(0)
        + _der(0x30, _der(6, bytes.fromhex(oid)) + params)
        + _der(4, private),
    )


def _sec1(curve_oid="2a8648ce3d030107", width=32):
    return _der(
        0x30,
        _integer(1)
        + _der(4, (17).to_bytes(width, "big"))
        + _der(0xA0, _der(6, bytes.fromhex(curve_oid))),
    )


PEM_CASES = [
    pytest.param("RSA PRIVATE KEY", _rsa_der(), "pkcs1", "RSA", id="rsa-pkcs1"),
    pytest.param(
        "PRIVATE KEY",
        _pkcs8("2a864886f70d010101", _rsa_der(), _der(5, b"")),
        "pkcs8",
        "RSA",
        id="rsa-pkcs8",
    ),
    pytest.param("EC PRIVATE KEY", _sec1(), "sec1", "EC", id="ec-sec1"),
    pytest.param(
        "PRIVATE KEY",
        _pkcs8("2a8648ce3d0201", _sec1(), _der(6, bytes.fromhex("2a8648ce3d030107"))),
        "pkcs8",
        "EC",
        id="ec-pkcs8",
    ),
    *[
        pytest.param(
            "PRIVATE KEY",
            _pkcs8(oid, _der(4, bytes(range(width)))),
            "pkcs8",
            curve,
            id=curve,
        )
        for oid, curve, width in (
            ("2b6570", "Ed25519", 32),
            ("2b656e", "X25519", 32),
            ("2b6571", "Ed448", 57),
            ("2b656f", "X448", 56),
        )
    ],
]


@pytest.mark.parametrize("label,raw,expected_format,algorithm", PEM_CASES)
def test_complete_private_pem_gets_only_offline_structure_evidence(
    label, raw, expected_format, algorithm
):
    source = _pem(label, raw)
    proof = material.inspect_pem_private_key(source)
    assert proof == material.KeyMaterialProof(expected_format, algorithm)
    assert proof.validation == "structural"
    assert not proof.encrypted
    assert source not in repr(proof)


@pytest.mark.parametrize("label,raw,expected_format,algorithm", PEM_CASES)
def test_truncated_or_extra_der_never_gains_private_key_proof(
    label, raw, expected_format, algorithm
):
    assert material.inspect_pem_private_key(_pem(label, raw[:-1])) is None
    assert material.inspect_pem_private_key(_pem(label, raw + b"extra")) is None


@pytest.mark.parametrize(
    "label",
    [
        "PUBLIC KEY",
        "RSA PUBLIC KEY",
        "CERTIFICATE",
        "CERTIFICATE REQUEST",
        "PGP PUBLIC KEY BLOCK",
    ],
)
def test_public_pem_label_is_never_private_key_proof(label):
    assert material.inspect_pem_private_key(_pem(label, _rsa_der())) is None


def test_pem_header_excerpts_mismatched_labels_and_bad_base64_are_not_proof():
    for value in (
        _pem("RSA PRIVATE KEY", b"not DER private key material"),
        "-----BEGIN " + "PRIVATE KEY-----\n",
        _pem("RSA PRIVATE KEY", _rsa_der()).replace("-----END RSA", "-----END EC"),
        _pem("RSA PRIVATE KEY", _rsa_der()).replace("\n", "\\n"),
        _pem("RSA PRIVATE KEY", _rsa_der()).replace("\n", "\n...\n", 1),
    ):
        assert material.inspect_pem_private_key(value) is None


def test_noncanonical_der_lengths_and_negative_integer_do_not_gain_proof():
    assert (
        material.inspect_pem_private_key(_pem("EC PRIVATE KEY", b"\x30\x80\x00\x00"))
        is None
    )
    assert (
        material.inspect_pem_private_key(
            _pem("EC PRIVATE KEY", b"\x30\x81\x03\x02\x01\x01")
        )
        is None
    )
    assert (
        material.inspect_pem_private_key(
            _pem("RSA PRIVATE KEY", _der(0x30, _der(2, b"\xff")))
        )
        is None
    )


def test_pem_length_limit_never_runs_unbounded_decode(monkeypatch):
    source = _pem("RSA PRIVATE KEY", _rsa_der())
    monkeypatch.setattr(material, "MAX_PEM_CHARS", len(source) - 1)
    assert material.inspect_pem_private_key(source) is None


def _encrypted_pem(parameters):
    algorithm = _der(
        0x30, _der(6, bytes.fromhex("2a864886f70d01050d")) + _der(0x30, parameters)
    )
    return _pem(
        "ENCRYPTED PRIVATE KEY", _der(0x30, algorithm + _der(4, bytes(range(32))))
    )


def test_encrypted_key_proof_is_container_only_and_requires_real_parameters():
    kdf = _der(
        0x30,
        _der(6, bytes.fromhex("2a864886f70d01050c"))
        + _der(0x30, _der(4, bytes(range(16))) + _integer(1000)),
    )
    cipher = _der(
        0x30, _der(6, bytes.fromhex("608648016503040102")) + _der(4, bytes(range(16)))
    )
    proof = material.inspect_pem_private_key(_encrypted_pem(kdf + cipher))
    assert proof == material.KeyMaterialProof(
        "pkcs8_encrypted", "encrypted", "encrypted_container", True
    )
    assert material.inspect_pem_private_key(_encrypted_pem(b"")) is None


def test_unproven_legacy_header_findings_are_preserved():
    from skylos.rules.secrets import scan_ctx

    source = _pem(
        "RSA PRIVATE KEY", b"not DER but still exposed private-looking material"
    )
    assert material.inspect_pem_private_key(source) is None
    findings = scan_ctx(
        {"relpath": "README.md", "lines": source.splitlines(True), "tree": None}
    )
    assert any(item["provider"] == "private_key_block" for item in findings)
