import ipaddress
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


__all__ = [
    "_append_query_param",
    "_host_is_private_or_metadata",
    "_normalize_http_url",
    "_validate_api_request_url",
    "_validate_artifact_upload_url",
    "_validate_github_oidc_request_url",
]


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
