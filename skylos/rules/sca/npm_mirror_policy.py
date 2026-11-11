"""Data-only validation for explicitly configured npm registry mirrors."""

from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import urlsplit, urlunsplit

MAX_MIRRORS = 50
MAX_MIRROR_URL_LENGTH = 2048
_DIGEST_BYTES = {"sha256": 32, "sha384": 48, "sha512": 64}


def _mirror_url(value: object):
    if not isinstance(value, str) or not 0 < len(value) <= MAX_MIRROR_URL_LENGTH:
        return None
    if (
        value != value.strip()
        or not value.isascii()
        or any(ord(char) <= 32 or ord(char) == 127 for char in value)
        or any(char in value for char in ("\\", "%", "?", "#"))
    ):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.hostname.endswith(".")
        or parsed.query
        or parsed.fragment
    ):
        return None
    if "//" in parsed.path:
        return None
    path = parsed.path.rstrip("/")
    if path and any(part in {"", ".", ".."} for part in path.split("/")[1:]):
        return None
    host = parsed.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    authority = host if port in {None, 443} else f"{host}:{port}"
    return urlunsplit(("https", authority, path, "", ""))


def normalize_npm_mirror_prefixes(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list) or len(value) > MAX_MIRRORS:
        return None
    prefixes = []
    for item in value:
        normalized = _mirror_url(item)
        if normalized is None:
            return None
        if normalized not in prefixes:
            prefixes.append(normalized)
    return tuple(prefixes)


def mirror_url_matches(
    value: object,
    prefixes: tuple[str, ...],
    *,
    allow_legacy_hash_fragment: bool = False,
) -> bool:
    """Match an origin and complete path segments, without opening the URL."""
    if allow_legacy_hash_fragment and isinstance(value, str) and "#" in value:
        base, fragment = value.rsplit("#", 1)
        if not re.fullmatch(r"[0-9a-fA-F]{40}", fragment):
            return False
        value = base
    normalized = _mirror_url(value)
    return normalized is not None and any(
        normalized == prefix or normalized.startswith(prefix + "/")
        for prefix in prefixes
    )


def canonical_integrity(value: object) -> str | None:
    """One canonical, strong SRI digest, with no alternate artifacts or options."""
    if not isinstance(value, str) or len(value) > 100:
        return None
    algorithm, separator, encoded = value.partition("-")
    if not separator or algorithm not in _DIGEST_BYTES:
        return None
    try:
        digest = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if (
        len(digest) != _DIGEST_BYTES[algorithm]
        or base64.b64encode(digest).decode("ascii") != encoded
    ):
        return None
    return value
