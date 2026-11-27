"""Request construction and dispatch in reqwest and reqwest-middleware."""

from dataclasses import replace

from ._security_bindings import Value
from .web_model import HTTP_VERBS

TYPES = {
    "reqwest::Client": "reqwest_client",
    "reqwest::ClientBuilder": "reqwest_client_builder",
    "reqwest::RequestBuilder": "reqwest_builder",
    "reqwest::Request": "reqwest_request",
    "reqwest::blocking::Client": "reqwest_blocking_client",
    "reqwest::blocking::ClientBuilder": "reqwest_blocking_client_builder",
    "reqwest::blocking::RequestBuilder": "reqwest_blocking_builder",
    "reqwest::blocking::Request": "reqwest_blocking_request",
    "reqwest_middleware::ClientWithMiddleware": "reqwest_middleware_client",
    "reqwest_middleware::ClientBuilder": "reqwest_middleware_client_builder",
    "reqwest_middleware::RequestBuilder": "reqwest_middleware_builder",
}
_CLIENT_BUILDERS = {
    "reqwest_client_builder": "result_reqwest_client",
    "reqwest_blocking_client_builder": "result_reqwest_blocking_client",
    "reqwest_middleware_client_builder": "reqwest_middleware_client",
}
_CLIENTS = {
    "reqwest_client": "reqwest_builder",
    "reqwest_blocking_client": "reqwest_blocking_builder",
    "reqwest_middleware_client": "reqwest_middleware_builder",
}
_BUILDERS = {
    "reqwest_builder": "reqwest_request",
    "reqwest_blocking_builder": "reqwest_blocking_request",
    "reqwest_middleware_builder": "reqwest_request",
}
REQUESTS = frozenset(_BUILDERS.values())
_REQUEST_SETTINGS = frozenset(
    {
        "basic_auth",
        "bearer_auth",
        "body",
        "form",
        "header",
        "headers",
        "json",
        "multipart",
        "query",
        "timeout",
        "version",
    }
)
_CLIENT_SETTINGS = frozenset(
    {
        "add_root_certificate",
        "brotli",
        "connect_timeout",
        "cookie_provider",
        "cookie_store",
        "danger_accept_invalid_certs",
        "danger_accept_invalid_hostnames",
        "default_headers",
        "deflate",
        "dns_resolver",
        "gzip",
        "http1_only",
        "http2_prior_knowledge",
        "https_only",
        "identity",
        "local_address",
        "max_tls_version",
        "min_tls_version",
        "no_proxy",
        "pool_idle_timeout",
        "pool_max_idle_per_host",
        "proxy",
        "read_timeout",
        "redirect",
        "referer",
        "resolve",
        "resolve_to_addrs",
        "tcp_keepalive",
        "tcp_nodelay",
        "timeout",
        "tls_built_in_root_certs",
        "use_native_tls",
        "use_rustls_tls",
        "user_agent",
        "zstd",
    }
)
SPAWN = frozenset(
    {
        "tokio::spawn",
        "tokio::task::spawn",
        "tokio::task::spawn_local",
        "async_std::task::spawn",
        "async_std::task::spawn_local",
    }
)


def has_dispatch(via):
    """True when a helper chain ends in this model's execution of a request."""
    return via.rsplit(" -> ", 1)[-1].startswith("reqwest dispatch (")


def destination(value, kind):
    # Project onto the authority when the string formatter identified it.
    # Request bodies, headers and query parameters never contribute URL facts.
    host = value.host if value.host is not None else value
    return Value(kind=kind, sources=host.sources, cleared=host.cleared)


def function(api, args):
    if api == "reqwest::get" and len(args) == 1:
        return destination(args[0], "reqwest_future")
    if api == "reqwest::blocking::get" and len(args) == 1:
        return destination(args[0], "reqwest_blocking_dispatch")
    owner, _, name = api.rpartition("::")
    kind = TYPES.get(owner)
    if kind in _CLIENTS:
        if name in {"new", "default"}:
            return Value(kind=kind)
        if name == "builder" and not args and kind != "reqwest_middleware_client":
            return Value(kind=kind + "_builder")
    if kind in _CLIENT_BUILDERS and name in {"new", "default", "from_client"}:
        return Value(kind=kind)
    if kind in REQUESTS and name == "new" and len(args) == 2:
        return destination(args[1], kind)
    if (
        kind in _BUILDERS
        and name == "from_parts"
        and len(args) == 2
        and args[1].kind == _BUILDERS[kind]
    ):
        return destination(args[1], kind)
    if kind and args:
        # Fully qualified method call, e.g. RequestBuilder::send(builder).
        return method(replace(args[0], kind=kind), name, args[1:])
    return None


def method(receiver, name, args):
    kind = receiver.kind
    if kind in _CLIENT_BUILDERS:
        if name == "build" and not args:
            return Value(kind=_CLIENT_BUILDERS[kind])
        if kind == "reqwest_middleware_client_builder":
            if name in {"with", "with_arc", "with_init", "with_arc_init"}:
                return receiver
        elif name in _CLIENT_SETTINGS:
            return receiver
    if kind in _CLIENTS:
        if name == "clone" and not args:
            return receiver
        position = HTTP_VERBS.get(name)
        if position is not None and len(args) == position + 1:
            return destination(args[position], _CLIENTS[kind])
        if name == "execute" and len(args) == 1:
            request = args[0]
            if request.kind == _BUILDERS[_CLIENTS[kind]]:
                return dispatch(request)
    if kind in _BUILDERS:
        if name == "send" and not args:
            return dispatch(receiver)
        if name == "build" and not args:
            return replace(receiver, kind="result_" + _BUILDERS[kind])
        if name in _REQUEST_SETTINGS or (
            kind == "reqwest_middleware_builder" and name == "with_extension"
        ):
            return receiver
    if (kind in REQUESTS or kind in _BUILDERS) and name == "try_clone" and not args:
        return replace(receiver, kind="option_" + kind)
    if kind in REQUESTS and name == "url" and not args:
        return destination(receiver, "string")
    return None


def dispatch(value):
    if value.kind in {"reqwest_blocking_request", "reqwest_blocking_builder"}:
        return destination(value, "reqwest_blocking_dispatch")
    return destination(value, "reqwest_future")
