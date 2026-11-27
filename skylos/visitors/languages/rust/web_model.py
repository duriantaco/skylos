"""Request sources, outbound-HTTP and HTML sinks, and encoders for Rust.

A Rust value is request data only when it comes from an incoming request:

* an extractor parameter of a web framework handler: actix-web
  ``web::{Path, Query, Json, Form, Bytes, Payload}``, axum
  ``extract::{Path, Query, Json, Form, RawQuery, RawForm, Multipart}`` (and the
  ``axum::Json``/``axum::Form``/axum-extra re-exports), Rocket
  ``Json``/``Form``/``Data`` guards;
* a Rocket route parameter: a parameter whose name appears as ``<name>``,
  ``<name..>`` or ``data = "<name>"`` in a ``#[get]``/``#[post]``/... route
  attribute, unless its type is a number, a bool or another type whose
  ``FromParam`` already validated it (only ``&str``/``String``/``Cow<str>``
  and their ``Option``s carry text);
* the request object's own data: ``HttpRequest``/``Request`` methods such as
  ``uri()``, ``query_string()``, ``match_info()``, ``headers()``, ``body()``
  (not ``app_data()`` or ``method()``-like accessors of server state).

Environment variables, command-line arguments, configuration and library
parameters are the operator's or the calling code's choice, as in the Go and
Python engines: they are never request data.
"""

from __future__ import annotations

import re

_ACTIX = "actix_web::web"
_AXUM = "axum::extract"

REQUEST_EXTRACTORS = frozenset(
    {
        f"{_ACTIX}::{name}"
        for name in ("Path", "Query", "Json", "Form", "Bytes", "Payload")
    }
    | {
        f"{_AXUM}::{name}"
        for name in (
            "Path",
            "Query",
            "Json",
            "Form",
            "RawQuery",
            "RawForm",
            "Multipart",
        )
    }
    | {f"axum::{name}" for name in ("Json", "Form")}
    | {
        f"axum_extra::extract::{name}"
        for name in ("Query", "Form", "Json", "Multipart")
    }
    | {
        "rocket::serde::json::Json",
        "rocket::form::Form",
        "rocket::Data",
        "rocket::data::Data",
    }
)

# Request objects: only these methods return request data.
REQUEST_OBJECTS = frozenset(
    {
        "actix_web::HttpRequest",
        "actix_web::web::HttpRequest",
        "axum::extract::Request",
        "axum::http::Request",
        "http::Request",
        "hyper::Request",
        "tonic::Request",
    }
)
REQUEST_OBJECT_METHODS = frozenset(
    {
        "uri",
        "path",
        "query_string",
        "match_info",
        "headers",
        "head",
        "cookie",
        "cookies",
        "full_url",
        "body",
        "body_mut",
        "into_body",
        "into_parts",
        "into_inner",
        "get_ref",
        "get_mut",
        "metadata",
    }
)

# Names a glob import of these modules provides.
GLOB_EXPORTS = {
    _ACTIX: (
        "Path",
        "Query",
        "Json",
        "Form",
        "Bytes",
        "Payload",
        "Data",
        "HttpRequest",
    ),
    _AXUM: (
        "Path",
        "Query",
        "Json",
        "Form",
        "RawQuery",
        "RawForm",
        "Multipart",
        "Request",
        "State",
    ),
    "actix_web": ("HttpRequest",),
}

# ``Data<Client>``, ``Arc<Client>``, ``State<Client>``: look at the argument.
TRANSPARENT_WRAPPERS = frozenset(
    {
        "actix_web::web::Data",
        "std::sync::Arc",
        "std::rc::Rc",
        "std::boxed::Box",
        "rocket::State",
        "axum::extract::State",
    }
)

ROCKET_ROUTE_ATTRIBUTES = frozenset(
    {"get", "post", "put", "delete", "patch", "head", "options", "route"}
)
ROCKET_SEGMENT_RE = re.compile(r"<([A-Za-z_][A-Za-z0-9_]*)(?:\.\.)?>")
# Parameter types that cannot carry request text, or that a FromParam /
# FromSegments implementation already validated.
NON_TEXT_TYPES = frozenset(
    {
        "i8",
        "i16",
        "i32",
        "i64",
        "i128",
        "isize",
        "u8",
        "u16",
        "u32",
        "u64",
        "u128",
        "usize",
        "f32",
        "f64",
        "bool",
        "char",
    }
)

HTTP_CLIENT_TYPES = frozenset(
    {
        "awc::Client",
        "awc::ClientBuilder",
        "ureq::Agent",
        "ureq::AgentBuilder",
        "surf::Client",
        "isahc::HttpClient",
        "hyper::Client",
        "hyper_util::client::legacy::Client",
    }
)
HTTP_CLIENT_CONSTRUCTORS = frozenset(
    {
        f"{name}::{ctor}"
        for name in HTTP_CLIENT_TYPES
        for ctor in ("new", "builder", "default")
    }
    | {"ureq::agent", "ureq::builder", "surf::client"}
)
# Methods of an HTTP client and the index of their URL argument.
HTTP_VERBS = {
    "get": 0,
    "post": 0,
    "put": 0,
    "patch": 0,
    "delete": 0,
    "head": 0,
    "request": 1,
}
# Functions that send a request, and the index of their URL argument.
HTTP_FUNCTIONS = {
    **{
        f"ureq::{verb}": 0 for verb in ("get", "post", "put", "patch", "delete", "head")
    },
    "ureq::request": 1,
    **{
        f"surf::{verb}": 0 for verb in ("get", "post", "put", "patch", "delete", "head")
    },
    **{f"isahc::{verb}": 0 for verb in ("get", "post", "put", "delete", "head")},
    **{
        f"attohttpc::{verb}": 0
        for verb in ("get", "post", "put", "patch", "delete", "head")
    },
    **{
        f"minreq::{verb}": 0
        for verb in ("get", "post", "put", "patch", "delete", "head")
    },
    # ``Webmention::new(source, target).send()`` fetches the target page.
    "webmention::Webmention::new": 1,
}

# Percent/form encoders: the result cannot choose a URL's host or open markup.
URL_ENCODERS = frozenset(
    {
        "percent_encoding::utf8_percent_encode",
        "percent_encoding::percent_encode",
        "urlencoding::encode",
        "urlencoding::encode_binary",
        "url::form_urlencoded::byte_serialize",
        "form_urlencoded::byte_serialize",
    }
)
HTML_ESCAPERS = frozenset(
    {
        "html_escape::encode_text",
        "html_escape::encode_safe",
        "html_escape::encode_quoted_attribute",
        "html_escape::encode_double_quoted_attribute",
        "html_escape::encode_single_quoted_attribute",
        "html_escape::encode_unquoted_attribute",
        "html_escape::encode_text_minimal",
        "htmlescape::encode_minimal",
        "htmlescape::encode_attribute",
        "v_htmlescape::escape",
        "askama_escape::escape",
        "ammonia::clean",
    }
)

# HTML element names: ``Vec<u8>`` or ``Option<String>`` in a message is not markup.
_HTML_TAGS = (
    "a|abbr|area|article|aside|audio|b|base|blockquote|body|br|button|canvas|"
    "caption|cite|code|col|colgroup|dd|del|details|dialog|div|dl|dt|em|embed|"
    "fieldset|figcaption|figure|footer|form|h[1-6]|head|header|hr|html|i|iframe|"
    "img|input|ins|kbd|label|legend|li|link|main|mark|meta|nav|noscript|object|"
    "ol|optgroup|option|p|picture|pre|q|script|section|select|small|source|span|"
    "strong|style|sub|summary|sup|svg|table|tbody|td|template|textarea|tfoot|th|"
    "thead|time|title|tr|u|ul|video"
)
# A start or end tag of an HTML element: ``<a href=...>``, ``<br/>``, ``</b>``.
HTML_MARKUP_RE = re.compile(
    rf"<(?:{_HTML_TAGS})(?:\s[^<>]*)?/?>|</(?:{_HTML_TAGS})\s*>", re.IGNORECASE
)
_FIXED_HOST_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/?#{}\s]+[/?#]")


def fixes_host(prefix: str) -> bool:
    """A literal ``scheme://host`` followed by ``/``, ``?`` or ``#``: text
    appended later cannot change the host."""
    return bool(_FIXED_HOST_RE.match(prefix))


def request_label(description: str) -> str:
    return f"request:{description}"
