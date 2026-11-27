"""Security checks for identified Rust cryptographic APIs and exposed SecretString values."""

import base64
import binascii
import re
from dataclasses import dataclass, replace

from ._security_bindings import Value
from .log_formats import displayed_arguments
from .permissions import trait_in_scope

SECRET = "secrecy::SecretString"
EXPOSED = "rust_exposed_secret_string"
LOG_MACROS = {
    f"{crate}::{level}"
    for crate in ("log", "tracing")
    for level in ("trace", "debug", "info", "warn", "error")
}
_EXPOSURE = "secrecy::ExposeSecret::expose_secret"
_DIGESTS = {"md5": "SKY-D207", "sha1": "SKY-D208"}
_HASH_CALLS = {
    "md5::compute": "md5",
    "md5::Md5::digest": "md5",
    "sha1::Sha1::digest": "sha1",
    "openssl::sha::sha1": "sha1",
}
_WEAK_CIPHERS = {"des_cbc", "des_ecb", "rc4", "rc2_cbc", "rc2_40_cbc"}
_JWT_KEYS = {
    f"jsonwebtoken::EncodingKey::{method}"
    for method in ("from_secret", "from_base64_secret", "from_urlsafe_base64_secret")
}
_IDENT = r"[a-z_][a-z_0-9]*"
_TABLE = rf"{_IDENT}(?:\.{_IDENT})?"
_SLOT = r"(?:\?|[?$][1-9][0-9]{0,2})"
_INSERT = re.compile(
    rf"\s*INSERT\s+INTO\s+{_TABLE}\s*\(([^()]+)\)\s*VALUES\s*\(([^()]+)\)\s*;?\s*",
    re.IGNORECASE | re.ASCII,
)
_UPDATE = re.compile(
    rf"\s*UPDATE\s+{_TABLE}\s+SET\s+(.+?)(?:\s+WHERE\s+{_TABLE}\s*=\s*({_SLOT}|[0-9]+))?\s*;?\s*",
    re.IGNORECASE | re.ASCII | re.DOTALL,
)
_ASSIGN = re.compile(rf"\s*({_IDENT})\s*=\s*({_SLOT})\s*", re.IGNORECASE | re.ASCII)
_PASSWORD_NAMES = {"password", "passwd", "password_hash"}


@dataclass(frozen=True)
class PasswordWrite:
    parameter_count: int
    password_slots: frozenset[int]
    placeholder_style: str
    bound: int = 0
    exposed: bool = False

    def bind(self, value):
        index = self.bound + 1
        raw = index in self.password_slots and value.kind == EXPOSED and not value.items
        return replace(self, bound=index, exposed=self.exposed or raw)

    @property
    def complete(self):
        return self.exposed and self.parameter_count == self.bound


def password_write(query):
    """Identify the numbered binds stored directly into named password columns."""
    text = query.literal if not query.items and query.kind == "string" else None
    if not text or len(text) > 4096 or "pass" not in text.lower():
        return None
    insert = _INSERT.fullmatch(text)
    if insert:
        names = [s.strip().lower() for s in insert[1].split(",")]
        slots = [s.strip() for s in insert[2].split(",")]
        if (
            len(names) != len(slots)
            or len(names) != len(set(names))
            or not all(re.fullmatch(_IDENT, n) for n in names)
        ):
            return None
    else:
        update = _UPDATE.fullmatch(text)
        if not update:
            return None
        assignments = [_ASSIGN.fullmatch(s) for s in update[1].split(",")]
        if not all(assignments):
            return None
        names = [a[1].lower() for a in assignments]
        if len(set(names)) != len(names):
            return None
        slots = [a[2] for a in assignments]
        if update[2] and not update[2].isdecimal():
            slots.append(update[2])
    if not slots or not all(re.fullmatch(_SLOT, s) for s in slots):
        return None
    if all(s == "?" for s in slots):
        indices = list(range(1, len(slots) + 1))
    elif all(s.startswith(slots[0][0]) and len(s) > 1 for s in slots):
        indices = [int(s[1:]) for s in slots]
    else:
        return None
    count = max(indices)
    if len(set(indices)) != count:
        return None
    password = frozenset(
        i for i, name in zip(indices, names, strict=False) if name in _PASSWORD_NAMES
    )
    style = slots[0] if slots[0] == "?" else slots[0][0] + "N"
    return PasswordWrite(count, password, style) if password else None


def identifier_call(api, args, state):
    """Return value identities for selectors. None delegates to the ordinary Rust flow."""
    if not api:
        return None
    if not args:
        owner, _, option = api.rpartition("::")
        if option == "new" and owner in _DIGEST_TYPES and digest_trait(state, owner):
            return Value(kind=owner)
        if owner == "openssl::hash::MessageDigest" and option in _DIGESTS:
            return Value(kind="openssl_digest", literal=option)
        if owner == "openssl::symm::Cipher" and option in _WEAK_CIPHERS:
            return Value(kind="openssl_legacy_cipher", literal=option)
    if (
        api == _EXPOSURE
        and len(args) == 1
        and args[0].kind == SECRET
        and not args[0].items
    ):
        return Value(kind=EXPOSED)
    if api == SECRET + "::from" and len(args) == 1:
        return Value(kind=SECRET)
    return None


def method_result(receiver, name, args, state):
    if args or receiver.items:
        return None
    if (
        receiver.kind == SECRET
        and name == "expose_secret"
        and trait_in_scope(state, "secrecy::ExposeSecret")
    ):
        return Value(kind=EXPOSED)
    if receiver.kind == EXPOSED and name in {
        "as_str",
        "as_bytes",
        "to_owned",
        "to_string",
    }:
        return receiver
    return None


def literal_signing_key(api, args):
    if (
        len(args) != 1
        or args[0].kind != "string"
        or not args[0].literal
        or args[0].items
    ):
        return False
    if api.endswith("::from_secret"):
        return True
    # The base64 constructors reject malformed or empty data.
    try:
        encoded = args[0].literal.encode("ascii")
        alphabet = b"-_" if api.endswith("::from_urlsafe_base64_secret") else None
        decoded = base64.b64decode(encoded, altchars=alphabet, validate=True)
        return bool(decoded) and base64.b64encode(decoded, altchars=alphabet) == encoded
    except (UnicodeError, binascii.Error):
        return False


def call_finding(api, args, state):
    if api and len(args) == 1:
        owner, _, name = api.rpartition("::")
        if (
            owner in _AES_KEYS
            and name in {"new", "new_from_slice"}
            and args[0].kind == f"rust_fixed_bytes_{_AES_KEYS[owner]}"
            and any(
                trait_in_scope(state, trait)
                for trait in (
                    "aes_gcm::KeyInit",
                    "aes_gcm::aead::KeyInit",
                    "aead::KeyInit",
                )
            )
        ):
            return (
                "SKY-D388",
                "HIGH",
                "The AES-GCM key comes from a fixed byte array in source. Load a key from secret storage.",
            )
    if api in _JWT_KEYS and literal_signing_key(api, args):
        return (
            "SKY-D388",
            "HIGH",
            "The JWT signing key comes from a source literal. Load the HMAC key from secret storage.",
        )
    if (
        api == "openssl::symm::encrypt"
        and len(args) == 4
        and args[0].kind == "openssl_legacy_cipher"
    ):
        return (
            "SKY-D386",
            "HIGH",
            f"OpenSSL encrypts new data with {args[0].literal}. Use a modern authenticated cipher.",
        )
    if not args or args[-1].kind != EXPOSED or args[-1].items:
        return None
    digest = _HASH_CALLS.get(api) if len(args) == 1 else None
    if (
        api == "openssl::hash::hash"
        and len(args) == 2
        and args[0].kind == "openssl_digest"
    ):
        digest = args[0].literal
    if digest in _DIGESTS:
        return (
            _DIGESTS[digest],
            "MEDIUM",
            f"{api} hashes exposed secret data with {digest.upper()}. Use a digest or password hash suited to its purpose.",
        )
    return None


def writes_password(receiver, method, args):
    if (
        receiver.kind != "rusqlite::Connection"
        or receiver.items
        or method != "execute"
        or len(args) != 2
    ):
        return False
    parameters = args[1].items
    if not any(p.kind == EXPOSED and not p.items for p in parameters):
        return False
    write = password_write(args[0])
    if write is None or write.placeholder_style == "$N":
        # With rusqlite, a $name is a named parameter, including names made of digits.
        return False
    for parameter in parameters:
        write = write.bind(parameter)
    return write.complete


def exposed_argument(tokens, state):
    if not tokens or tokens[0].type != "identifier":
        return False
    kind = state.get(tokens[0].text.decode("utf-8", "replace")).kind
    if len(tokens) == 1:
        return kind == EXPOSED
    return (
        kind == SECRET
        and trait_in_scope(state, "secrecy::ExposeSecret")
        and [part.text for part in tokens[1:]] == [b".", b"expose_secret", b"()"]
    )


def logs_secret(api, tree, state):
    for argument, spec in displayed_arguments(
        tree, structured=api.startswith("tracing::")
    ):
        if spec not in {"", "?"}:
            continue
        if isinstance(argument, str):
            if state.get(argument).kind == EXPOSED:
                return True
        elif exposed_argument(argument, state):
            return True
    return False


_DIGEST_TYPES = {"sha1::Sha1": "sha1", "md5::Md5": "md5"}
_AES_KEYS = {"aes_gcm::Aes128Gcm": 16, "aes_gcm::Aes256Gcm": 32}


def repeated_key_kind(initializer):
    """Recognize only fixed AES-sized byte arrays, never their material."""
    if initializer is None or initializer.type != "array_expression":
        return None
    fields = initializer.named_children
    if (
        len(fields) != 2
        or any(v.type != "integer_literal" for v in fields)
        or not any(c.type == ";" for c in initializer.children)
    ):
        return None
    if not re.fullmatch(rb"(?:[0-9]{1,3}|0x[0-9a-fA-F]{1,2})(?:u8)?", fields[0].text):
        return None
    return {b"16": "rust_fixed_bytes_16", b"32": "rust_fixed_bytes_32"}.get(
        fields[1].text
    )


def legacy_encryptor(owner, owner_node, constructor, args, state):
    if owner != "cbc::Encryptor" or constructor != "new" or len(args) != 2:
        return False
    types = owner_node.child_by_field_name("type_arguments")
    parts = types.named_children if types is not None else ()
    return (
        len(parts) == 1
        and state.resolve(parts[0].text.decode("utf-8", "replace")) == "des::Des"
        and any(
            trait_in_scope(state, prefix + "::KeyIvInit")
            for prefix in ("cbc::cipher", "cipher", "des::cipher")
        )
    )


def crypto_method_finding(receiver, name, args, state):
    if receiver.items:
        return None
    if (
        receiver.kind == "rustcrypto_legacy_encryptor"
        and name
        in {
            "encrypt_padded_vec_mut",
            "encrypt_padded_vec",
            "encrypt_padded",
            "encrypt_padded_mut",
            "encrypt_padded_b2b",
            "encrypt_padded_b2b_mut",
        }
        and args
    ):
        return (
            "SKY-D386",
            "HIGH",
            "RustCrypto encrypts new data with single DES. Use a modern authenticated cipher.",
        )
    if (
        receiver.kind in _DIGEST_TYPES
        and name == "update"
        and len(args) == 1
        and args[0].kind == EXPOSED
        and not args[0].items
        and digest_trait(state, receiver.kind)
    ):
        digest = _DIGEST_TYPES[receiver.kind]
        return (
            _DIGESTS[digest],
            "MEDIUM",
            f"{receiver.kind} hashes an exposed SecretString with {digest.upper()}.",
        )
    return None


def digest_trait(state, owner):
    return trait_in_scope(state, "digest::Digest") or trait_in_scope(
        state, owner.split("::")[0] + "::Digest"
    )
