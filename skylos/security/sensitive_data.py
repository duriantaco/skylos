"""Whether a name in code holds sensitive data: credentials, account or
session identity, certificates or private personal data.

Weak hashes are a vulnerability only when what they hash must stay secret or
unforgeable; MD5 over a URL to name a cache file protects nothing. The same
idea drives CodeQL's sensitive-data hashing query. Here a name is split into
lowercase words and judged by those words, single or paired, and a word that
says the value is already derived or is a location (``hash``, ``digest``,
``path``, ``url``) means the name is not sensitive.
"""

from __future__ import annotations

import re

_CREDENTIAL_WORDS = frozenset(
    {
        "password",
        "passwd",
        "passcode",
        "passphrase",
        "pwd",
        "secret",
        "secrets",
        "confidential",
        "token",
        "tokens",
        "apikey",
        "oauth",
        "mfa",
        "otp",
        "credential",
        "credentials",
        "privkey",
        "cookie",
        "cookies",
        "csrf",
        "jwt",
    }
)
_IDENTITY_WORDS = frozenset({"username", "userid", "uid", "account", "ssn", "passport"})
_CERTIFICATE_WORDS = frozenset({"cert", "certificate", "certs"})
_SENSITIVE_PAIRS = frozenset(
    {
        ("pass", "word"),
        ("pass", "phrase"),
        ("api", "key"),
        ("api", "token"),
        ("auth", "key"),
        ("access", "key"),
        ("private", "key"),
        ("secret", "key"),
        ("signing", "key"),
        ("user", "id"),
        ("user", "name"),
        ("session", "id"),
        ("session", "key"),
        ("card", "number"),
        ("credit", "card"),
    }
)
_DERIVED_OR_LOCATION_WORDS = frozenset(
    {
        "hash",
        "hashed",
        "digest",
        "md5",
        "sha",
        "sha1",
        "sha256",
        "checksum",
        "fingerprint",
        "redact",
        "redacted",
        "censor",
        "censored",
        "obfuscate",
        "obfuscated",
        "masked",
        "random",
        "path",
        "file",
        "filename",
        "url",
        "uri",
        "format",
        "question",
    }
)
_CERTIFICATE_NOT_SENSITIVE = frozenset({"format", "name", "path", "file", "verify"})
_WORD_SPLIT = re.compile(r"[^A-Za-z0-9]+")
_CAMEL = re.compile(r"([a-z0-9])([A-Z])")


def name_words(name: str) -> list[str]:
    spaced = _CAMEL.sub(r"\1_\2", str(name or ""))
    return [word.lower() for word in _WORD_SPLIT.split(spaced) if word]


def sensitive_category(name: str) -> str | None:
    """``credential``, ``identity`` or ``certificate`` when the name holds
    such data, else None. Text with spaces is prose, not a name."""
    text = str(name or "")
    if not text or len(text) > 80 or any(char.isspace() for char in text):
        return None
    words = name_words(text)
    if not words or set(words) & _DERIVED_OR_LOCATION_WORDS:
        return None
    pairs = set(zip(words, words[1:]))
    if set(words) & _CREDENTIAL_WORDS:
        if "secret" in words and words.index("secret") > 0:
            if words[words.index("secret") - 1] == "is":
                return None
        return "credential"
    if pairs & _SENSITIVE_PAIRS:
        if pairs & {("user", "id"), ("user", "name"), ("session", "id")}:
            return "identity"
        return "credential"
    if set(words) & _IDENTITY_WORDS:
        return "identity"
    if set(words) & _CERTIFICATE_WORDS and not set(words) & _CERTIFICATE_NOT_SENSITIVE:
        return "certificate"
    return None


def first_sensitive_name(names) -> str | None:
    for name in names:
        if sensitive_category(name) is not None:
            return name
    return None
