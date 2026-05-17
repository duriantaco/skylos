import ipaddress
import os
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


__all__ = [
    "_append_query_param",
    "_artifact_upload_host_allowed",
    "_host_is_private_or_metadata",
    "_normalize_http_url",
    "_validate_api_request_url",
    "_validate_artifact_upload_url",
    "_validate_github_oidc_request_url",
]


_ARTIFACT_UPLOAD_HOST_ALLOWLIST_ENV = "SKYLOS_ARTIFACT_UPLOAD_HOST_ALLOWLIST"
_DEFAULT_ARTIFACT_UPLOAD_HOST_ALLOWLIST = frozenset(
    {
        "skylos.dev",
        "*.skylos.dev",
    }
)


def _normalize_http_url(
    url: Any,
    *,
    allowed_schemes: frozenset[str],
    allow_fragment: bool = False,
) -> str:
    if not isinstance(url, str):
        raise ValueError("URL must be a string")
    stripped = url.strip()
    parsed = urlsplit(stripped)
    scheme = parsed.scheme.lower()
    if scheme not in allowed_schemes:
        raise ValueError("URL scheme is not allowed")
    if not parsed.hostname:
        raise ValueError("URL host is required")
    if parsed.username or parsed.password:
        raise ValueError("URL credentials are not allowed")
    if parsed.fragment and not allow_fragment:
        raise ValueError("URL fragment is not allowed")
    return urlunsplit(
        (
            scheme,
            parsed.netloc.lower(),
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )


def _artifact_upload_host_patterns() -> tuple[str, ...]:
    patterns = list(sorted(_DEFAULT_ARTIFACT_UPLOAD_HOST_ALLOWLIST))
    configured = os.getenv(_ARTIFACT_UPLOAD_HOST_ALLOWLIST_ENV, "").strip()
    if not configured:
        return tuple(patterns)
    for item in configured.split(","):
        pattern = item.strip().lower().rstrip(".")
        if not pattern:
            continue
        if "://" in pattern:
            pattern = (urlsplit(pattern).hostname or "").rstrip(".").lower()
        if pattern:
            patterns.append(pattern)
    return tuple(patterns)


def _artifact_upload_host_allowed(hostname: str | None) -> bool:
    if not hostname:
        return False
    host = hostname.rstrip(".").lower()
    for pattern in _artifact_upload_host_patterns():
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if host.endswith(suffix) and host != suffix.lstrip("."):
                return True
            continue
        if pattern == host:
            return True
    return False


def _host_is_private_or_metadata(hostname: str | None) -> bool:
    if not hostname:
        return True
    host = hostname.strip("[]").rstrip(".").lower()
    if host in {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
    }:
        return True
    if host.endswith(".localhost") or host.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _validate_api_request_url(url: Any) -> str:
    return _normalize_http_url(
        url,
        allowed_schemes=frozenset({"http", "https"}),
    )


def _validate_artifact_upload_url(url: Any) -> str:
    safe_url = _normalize_http_url(url, allowed_schemes=frozenset({"https"}))
    parsed = urlsplit(safe_url)
    if _host_is_private_or_metadata(parsed.hostname):
        raise ValueError("upload URL host is not allowed")
    if not _artifact_upload_host_allowed(parsed.hostname):
        raise ValueError("upload URL host is not in the artifact upload allowlist")
    return safe_url


def _validate_github_oidc_request_url(url: Any) -> str:
    safe_url = _normalize_http_url(url, allowed_schemes=frozenset({"https"}))
    host = (urlsplit(safe_url).hostname or "").rstrip(".").lower()
    if host != "actions.githubusercontent.com" and not host.endswith(
        ".actions.githubusercontent.com"
    ):
        raise ValueError("GitHub OIDC URL host is not allowed")
    return safe_url


def _append_query_param(url: str, key: str, value: str) -> str:
    parsed = urlsplit(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.append((key, value))
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(query),
            parsed.fragment,
        )
    )
