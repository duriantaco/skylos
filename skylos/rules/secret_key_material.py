"""Bounded offline evidence for serialized private keys.

The layouts come from RFCs 7518, 8037, 5208, 5915 and 8410.  This module
recognizes private material; it does not authenticate an issuer, decrypt keys,
or establish that a key is usable.  A missing proof must never suppress an
existing secret finding.  Returned records contain offsets and safe metadata,
never the private bytes.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from math import lcm


MAX_PEM_CHARS = 65_536
MAX_JWK_VALUE_CHARS = 8_192
MAX_JWK_RECORDS = 256
_B64URL = re.compile(r"[A-Za-z0-9_-]+\Z")
_OCT_EXACT_PLACEHOLDERS = frozenset(
    {
        "replace-with-your-secret-key",
        "replace_with_your_secret_key",
        "your-secret-key-goes-here",
        "your_secret_key_goes_here",
    }
)
_KTY_MARKER = re.compile(r'"(?:k|\\u006[bB])(?:t|\\u0074)(?:y|\\u0079)"\s*:')
_PRIVATE_MARKER = re.compile(r'"(?:d|k|\\u0064|\\u006[bB])"\s*:')
_PEM = re.compile(
    r"\A\s*-----BEGIN (?P<label>RSA PRIVATE KEY|EC PRIVATE KEY|PRIVATE KEY|"
    r"ENCRYPTED PRIVATE KEY)-----[ \t]*\r?\n"
    r"(?P<body>[A-Za-z0-9+/=\r\n \t]+)"
    r"-----END (?P=label)-----\s*\Z"
)


@dataclass(frozen=True)
class KeyMaterialProof:
    format: str
    algorithm: str
    validation: str = "structural"
    encrypted: bool = False


@dataclass(frozen=True)
class KeyRelatedSpan:
    role: str
    start: int
    end: int


@dataclass(frozen=True)
class KeyMatch:
    provider: str
    start: int
    end: int
    evidence: dict
    related_spans: tuple[KeyRelatedSpan, ...] = ()


@dataclass(frozen=True)
class KeyScan:
    matches: tuple[KeyMatch, ...]
    issues: tuple[str, ...] = ()


@dataclass(frozen=True)
class _JWKField:
    value: str = field(repr=False)


def _base64url(value: str) -> bytes | None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_JWK_VALUE_CHARS
        or not _B64URL.fullmatch(value)
        or len(value) % 4 == 1
    ):
        return None
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error):
        return None
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        return None
    return raw


def _jwk_integer(value: str) -> int | None:
    raw = _base64url(value)
    if not raw or raw[0] == 0:
        return None
    return int.from_bytes(raw, "big")


def _rsa_components(values: dict[str, int], *, crt: bool) -> bool:
    n, e, d = (values[name] for name in ("n", "e", "d"))
    if not (512 <= n.bit_length() <= 16_384 and n & 1 and 3 <= e < n and e & 1):
        return False
    if not (1 < d < n and d & 1):
        return False
    if not crt:
        return True
    p, q, dp, dq, qi = (values[name] for name in ("p", "q", "dp", "dq", "qi"))
    if not (p > 2 and q > 2 and p != q and p & 1 and q & 1 and p * q == n):
        return False
    return (
        e * d % lcm(p - 1, q - 1) == 1
        and dp == d % (p - 1)
        and dq == d % (q - 1)
        and qi * q % p == 1
        and 0 < qi < p
    )


# Coordinate widths are mandated by the named curves' JWK representations.
# Their subgroup orders bound private scalars without executing crypto code.
_EC_CURVES = {
    "P-256": (
        32,
        int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
    ),
    "P-384": (
        48,
        int(
            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
            16,
        ),
    ),
    "P-521": (
        66,
        int(
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
            16,
        ),
    ),
}
_OKP_CURVES = {"Ed25519": 32, "X25519": 32, "Ed448": 57, "X448": 56}
_RSA_PRIVATE = ("d", "p", "q", "dp", "dq", "qi")
_JWK_MEMBER_NAMES = (
    "kty",
    "crv",
    "n",
    "e",
    "d",
    "p",
    "q",
    "dp",
    "dq",
    "qi",
    "oth",
    "x",
    "y",
    "k",
)


def _jwk_evidence(fields) -> tuple[str, dict] | None:
    kind_field = fields.get("kty")
    if kind_field is None:
        return None
    kind = kind_field.value
    if kind == "RSA":
        required = ("n", "e", "d")
        if not all(name in fields for name in required) or "oth" in fields:
            return None
        # A supplied CRT group is checked as a complete group.  A simple
        # n/e/d private key is also permitted by RFC 7518 section 6.3.2.
        crt = any(name in fields for name in _RSA_PRIVATE[1:])
        names = (*required, *_RSA_PRIVATE[1:]) if crt else required
        if not all(name in fields for name in names):
            return None
        values = {name: _jwk_integer(fields[name].value) for name in names}
        if any(value is None for value in values.values()):
            return None
        if not _rsa_components(values, crt=crt):
            return None
        return "jwk_private_key", {
            "format": "jwk",
            "algorithm": "RSA",
            "validation": "structural",
            "key_bits": values["n"].bit_length(),
        }
    if kind in {"EC", "OKP"}:
        curve_field = fields.get("crv")
        if curve_field is None:
            return None
        curve = curve_field.value
        names = ("x", "y", "d") if kind == "EC" else ("x", "d")
        if not all(name in fields for name in names):
            return None
        data = {name: _base64url(fields[name].value) for name in names}
        if any(value is None for value in data.values()):
            return None
        if kind == "EC":
            parameters = _EC_CURVES.get(curve)
            if parameters is None:
                return None
            width, order = parameters
            if not all(len(value) == width for value in data.values()):
                return None
            if not 0 < int.from_bytes(data["d"], "big") < order:
                return None
        else:
            width = _OKP_CURVES.get(curve)
            if width is None or not all(len(value) == width for value in data.values()):
                return None
        return "jwk_private_key", {
            "format": "jwk",
            "algorithm": kind,
            "curve": curve,
            "validation": "structural",
        }
    if kind == "oct" and "k" in fields:
        # These complete instruction strings happen to be canonical
        # base64url. Their exact whole-value meaning proves a placeholder;
        # words embedded in a longer/random payload prove nothing.
        if fields["k"].value.casefold() in _OCT_EXACT_PLACEHOLDERS:
            return None
        raw = _base64url(fields["k"].value)
        # A narrow >=128-bit profile avoids treating short prose as a key;
        # generic detectors retain their independent behavior for short keys.
        if raw is None or len(raw) < 16:
            return None
        return "jwk_symmetric_key", {
            "format": "jwk",
            "algorithm": "oct",
            "validation": "structural",
            "key_bits": len(raw) * 8,
        }
    return None


def private_jwk_member_names(record: dict) -> tuple[str, ...]:
    """Private members to mask in one structurally recognized JWK dictionary.

    This is the same recognition policy used by the scanner.  Public n/e/x/y
    members and unrelated neighboring fields are never included in the result.
    """
    if not isinstance(record, dict):
        return ()
    fields = {
        name: _JWKField(value)
        for name in _JWK_MEMBER_NAMES
        if isinstance(value := dict.get(record, name), str)
    }
    result = _jwk_evidence(fields)
    if result is None:
        return ()
    provider, evidence = result
    if provider == "jwk_symmetric_key":
        return ("k",)
    if evidence["algorithm"] == "RSA":
        return tuple(name for name in _RSA_PRIVATE if name in fields)
    return ("d",)


def scan_private_jwk_objects(text: str) -> KeyScan:
    """Find private members in complete literal JSON records, never proximity pairs.

    JSON syntax, duplicate keys and resource limits are handled by the shared
    record reader.  Its issues remain visible even when other records match.
    """
    if not _KTY_MARKER.search(text) or not _PRIVATE_MARKER.search(text):
        return KeyScan(())
    # The credential reader uses inspect_pem_private_key at runtime as well;
    # a local import keeps the two pure helpers free of an import cycle.
    from skylos.rules.secret_credentials import iter_json_string_records

    records = iter_json_string_records(text)
    matches = []
    issues = list(records.issues)
    inspected = 0
    for record in records.records:
        fields = record.fields
        if "kty" not in fields or not any(name in fields for name in ("d", "k")):
            continue
        if inspected >= MAX_JWK_RECORDS:
            issues.append("jwk_record_limit")
            break
        inspected += 1
        if any(
            len(fields[name].value) > MAX_JWK_VALUE_CHARS
            for name in _JWK_MEMBER_NAMES
            if name in fields
        ):
            issues.append("jwk_value_limit")
            continue
        result = _jwk_evidence(fields)
        if result is None:
            continue
        provider, evidence = result
        main = fields["k" if provider == "jwk_symmetric_key" else "d"]
        related = tuple(
            KeyRelatedSpan("jwk_private_" + name, fields[name].start, fields[name].end)
            for name in _RSA_PRIVATE[1:]
            if evidence["algorithm"] == "RSA" and name in fields
        )
        matches.append(KeyMatch(provider, main.start, main.end, evidence, related))
    return KeyScan(tuple(matches), tuple(dict.fromkeys(issues)))


class _InvalidDER(ValueError):
    pass


class _DER:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.pos = 0

    def read(self, expected: int | None = None) -> tuple[int, bytes]:
        if self.pos + 2 > len(self.raw):
            raise _InvalidDER
        tag, length = self.raw[self.pos : self.pos + 2]
        self.pos += 2
        if tag & 31 == 31:
            raise _InvalidDER
        if length & 128:
            count = length & 127
            if not 1 <= count <= 3 or self.pos + count > len(self.raw):
                raise _InvalidDER
            size = self.raw[self.pos : self.pos + count]
            self.pos += count
            if size[0] == 0:
                raise _InvalidDER
            length = int.from_bytes(size, "big")
            if length < 128:
                raise _InvalidDER
        if expected is not None and tag != expected:
            raise _InvalidDER
        if self.pos + length > len(self.raw):
            raise _InvalidDER
        content = self.raw[self.pos : self.pos + length]
        self.pos += length
        return tag, content

    def integer(self) -> int:
        _, content = self.read(2)
        if not content or content[0] & 128:
            raise _InvalidDER
        if len(content) > 1 and content[0] == 0 and not content[1] & 128:
            raise _InvalidDER
        return int.from_bytes(content, "big")

    def finish(self):
        if self.pos != len(self.raw):
            raise _InvalidDER


def _sequence(raw: bytes) -> _DER:
    outer = _DER(raw)
    _, content = outer.read(0x30)
    outer.finish()
    return _DER(content)


_OID_RSA = bytes.fromhex("2a864886f70d010101")
_OID_EC = bytes.fromhex("2a8648ce3d0201")
_CURVE_OIDS = {
    bytes.fromhex("2a8648ce3d030107"): "P-256",
    bytes.fromhex("2b81040022"): "P-384",
    bytes.fromhex("2b81040023"): "P-521",
}
_OKP_OIDS = {
    bytes.fromhex("2b6570"): "Ed25519",
    bytes.fromhex("2b656e"): "X25519",
    bytes.fromhex("2b6571"): "Ed448",
    bytes.fromhex("2b656f"): "X448",
}


def _pkcs1(raw: bytes) -> bool:
    body = _sequence(raw)
    if body.integer() != 0:
        return False
    values = {
        name: body.integer() for name in ("n", "e", "d", "p", "q", "dp", "dq", "qi")
    }
    body.finish()
    return _rsa_components(values, crt=True)


def _sec1(raw: bytes, curve: str | None = None) -> bool:
    body = _sequence(raw)
    if body.integer() != 1:
        return False
    _, secret = body.read(4)
    if body.pos < len(body.raw) and body.raw[body.pos] == 0xA0:
        _, params = body.read(0xA0)
        oid = _DER(params)
        _, value = oid.read(6)
        oid.finish()
        own_curve = _CURVE_OIDS.get(value)
        if own_curve is None or (curve is not None and curve != own_curve):
            return False
        curve = own_curve
    if curve not in _EC_CURVES:
        return False
    width, order = _EC_CURVES[curve]
    if len(secret) != width or not 0 < int.from_bytes(secret, "big") < order:
        return False
    if body.pos < len(body.raw):
        _, public_wrapper = body.read(0xA1)
        public_reader = _DER(public_wrapper)
        _, public = public_reader.read(3)
        public_reader.finish()
        # Uncompressed points (0x04) and compressed points (0x02/0x03)
        # have fixed widths.  No mathematical public/private equality claim.
        if not public or public[0] != 0 or len(public) < 2:
            return False
        if not (
            (public[1] == 4 and len(public) == 2 + 2 * width)
            or (public[1] in (2, 3) and len(public) == 2 + width)
        ):
            return False
    body.finish()
    return True


def _pkcs8(raw: bytes) -> str | None:
    body = _sequence(raw)
    if body.integer() != 0:
        return None
    _, algorithm = body.read(0x30)
    parameters = _DER(algorithm)
    _, oid = parameters.read(6)
    _, private = body.read(4)
    body.finish()
    if oid == _OID_RSA:
        if parameters.pos < len(parameters.raw):
            _, null = parameters.read(5)
            if null:
                return None
        parameters.finish()
        return "RSA" if _pkcs1(private) else None
    if oid == _OID_EC:
        _, curve_oid = parameters.read(6)
        parameters.finish()
        curve = _CURVE_OIDS.get(curve_oid)
        return "EC" if curve and _sec1(private, curve) else None
    curve = _OKP_OIDS.get(oid)
    if curve is None:
        return None
    parameters.finish()
    private_reader = _DER(private)
    _, secret = private_reader.read(4)
    private_reader.finish()
    return curve if len(secret) == _OKP_CURVES[curve] else None


def _pbes2_parameters(content: bytes) -> bool:
    """Recognize PBKDF2 plus AES-CBC/GCM container parameters, without work."""
    body = _DER(content)
    _, derivation = body.read(0x30)
    _, encryption = body.read(0x30)
    body.finish()
    kdf = _DER(derivation)
    _, oid = kdf.read(6)
    if oid != bytes.fromhex("2a864886f70d01050c"):
        return False
    _, parameters = kdf.read(0x30)
    kdf.finish()
    pbkdf = _DER(parameters)
    _, salt = pbkdf.read(4)
    if not salt or pbkdf.integer() <= 0:
        return False
    if pbkdf.pos < len(pbkdf.raw) and pbkdf.raw[pbkdf.pos] == 2:
        if pbkdf.integer() <= 0:
            return False
    if pbkdf.pos < len(pbkdf.raw):
        _, prf = pbkdf.read(0x30)
        prf_reader = _DER(prf)
        _, prf_oid = prf_reader.read(6)
        if prf_oid not in {
            bytes.fromhex("2a864886f70d0207"),
            bytes.fromhex("2a864886f70d0209"),
            bytes.fromhex("2a864886f70d020a"),
            bytes.fromhex("2a864886f70d020b"),
        }:
            return False
        if prf_reader.pos < len(prf_reader.raw):
            _, null = prf_reader.read(5)
            if null:
                return False
        prf_reader.finish()
    pbkdf.finish()
    cipher = _DER(encryption)
    _, oid = cipher.read(6)
    aes_prefix = bytes.fromhex("6086480165030401")
    if len(oid) != len(aes_prefix) + 1 or not oid.startswith(aes_prefix):
        return False
    mode = oid[-1]
    if mode in (2, 22, 42):
        _, iv = cipher.read(4)
        if len(iv) != 16:
            return False
    elif mode in (6, 26, 46):
        _, parameters = cipher.read(0x30)
        gcm = _DER(parameters)
        _, nonce = gcm.read(4)
        if not nonce:
            return False
        if gcm.pos < len(gcm.raw) and not 12 <= gcm.integer() <= 16:
            return False
        gcm.finish()
    else:
        return False
    cipher.finish()
    return True


def inspect_pem_private_key(text: str) -> KeyMaterialProof | None:
    """Return offline structure evidence for supported complete private PEMs.

    The input must be the decoded PEM value, not source-language quotes.  A
    complete unsupported or encrypted format is left to the legacy detector;
    ``None`` is absence of this proof, never evidence that material is safe.
    """
    if not isinstance(text, str) or len(text) > MAX_PEM_CHARS:
        return None
    match = _PEM.fullmatch(text)
    if match is None:
        return None
    encoded = "".join(match.group("body").split())
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return None
    if base64.b64encode(raw).decode("ascii") != encoded:
        return None
    label = match.group("label")
    try:
        if label == "RSA PRIVATE KEY":
            return KeyMaterialProof("pkcs1", "RSA") if _pkcs1(raw) else None
        if label == "EC PRIVATE KEY":
            return KeyMaterialProof("sec1", "EC") if _sec1(raw) else None
        if label == "PRIVATE KEY":
            algorithm = _pkcs8(raw)
            return KeyMaterialProof("pkcs8", algorithm) if algorithm else None
        # EncryptedPrivateKeyInfo proves a container, not the underlying key.
        body = _sequence(raw)
        _, algorithm = body.read(0x30)
        algorithm_reader = _DER(algorithm)
        _, oid = algorithm_reader.read(6)
        if oid != bytes.fromhex("2a864886f70d01050d"):
            return None
        _, parameters = algorithm_reader.read(0x30)
        algorithm_reader.finish()
        if not _pbes2_parameters(parameters):
            return None
        _, encrypted = body.read(4)
        body.finish()
        if len(encrypted) < 16:
            return None
        return KeyMaterialProof(
            "pkcs8_encrypted", "encrypted", "encrypted_container", True
        )
    except (_InvalidDER, ValueError, OverflowError):
        return None
