"""Small lexical binding and value facts for the Rust security visitor."""

from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Value:
    sources: frozenset[str] = frozenset()
    return_sources: frozenset[str] = frozenset()
    kind: str | None = None
    api: str | None = None
    guarded_api: tuple[frozenset[tuple[str, ...]], str] | None = None
    literal: str | None = None
    canonical: bool = False
    contained: bool = False
    shell: bool = False
    shell_switch: bool = False
    items: tuple["Value", ...] = ()
    # Rules whose sinks an encoder made this value safe for (a percent-encoded
    # string cannot choose a URL's host or open an HTML tag).
    cleared: frozenset[str] = frozenset()
    # For a URL string: the part that chooses the host. ``None`` means the
    # whole value; a value without sources means a literal fixed the host.
    host: Value | None = None
    # A local async helper can send several requests and return a separate
    # value. Its sends take effect when a caller actually polls its future.
    pending_http: tuple[tuple[str, Value], ...] = ()
    awaited: Value | None = None
    local_function: int | None = None

    @property
    def real_sources(self):
        """Sources other than the symbolic ``param#`` labels that record which
        of the enclosing function's parameters a value came from."""
        return frozenset(s for s in self.sources if not s.startswith(SYMBOLIC))

    @property
    def request_sources(self):
        return frozenset(s for s in self.sources if s.startswith(REQUEST))

    @property
    def tainted(self):
        return bool(self.real_sources) and not self.contained


SYMBOLIC = "param#"
REQUEST = "request:"
UNKNOWN = Value()


def joined(values):
    values = tuple(values)
    if not values:
        return UNKNOWN
    first = values[0]
    if len(values) == 1:
        return first
    items = first.items if all(v.items == first.items for v in values) else ()
    if not items and any(v.items for v in values):
        items = (
            Value(
                sources=frozenset().union(*(v.sources for v in values)),
                kind="unknown_args",
            ),
        )
    sourced = [v.cleared for v in values if v.sources]
    return Value(
        sources=frozenset().union(*(v.sources for v in values)),
        return_sources=frozenset().union(*(v.return_sources for v in values)),
        cleared=frozenset.intersection(*sourced) if sourced else frozenset(),
        host=joined([v.host for v in values])
        if all(v.host is not None for v in values)
        else None,
        kind=first.kind if all(v.kind == first.kind for v in values) else None,
        api=first.api if all(v.api == first.api for v in values) else None,
        guarded_api=first.guarded_api
        if all(v.guarded_api == first.guarded_api for v in values)
        else None,
        local_function=first.local_function
        if all(v.local_function == first.local_function for v in values)
        else None,
        pending_http=tuple(
            dict.fromkeys(effect for v in values for effect in v.pending_http)
        )
        if any(v.pending_http for v in values)
        else (),
        awaited=joined(v.awaited for v in values)
        if all(v.awaited is not None for v in values)
        else None,
        literal=first.literal
        if all(v.literal == first.literal for v in values)
        else None,
        canonical=all(v.canonical for v in values),
        contained=all(v.contained for v in values),
        shell=any(v.shell for v in values),
        shell_switch=any(v.shell_switch for v in values),
        items=items,
    )


def bind_http_return(template, function_key, arguments):
    """Replace formal destination parameters in a helper's returned HTTP value."""
    prefix = f"{SYMBOLIC}{function_key}#"
    sources = []
    for label in template.sources:
        if label.startswith(prefix):
            index = int(label[len(prefix) :])
            if index < len(arguments):
                value = arguments[index]
                sources.append(value.host if value.host is not None else value)
        elif not label.startswith("parameter:"):
            sources.append(Value(sources=frozenset({label})))
    bound = joined(sources)
    return replace(
        template,
        sources=bound.sources,
        cleared=template.cleared | bound.cleared,
        host=bind_http_return(template.host, function_key, arguments)
        if template.host is not None
        else None,
        pending_http=tuple(
            (via, bind_http_return(value, function_key, arguments))
            for via, value in template.pending_http
        ),
        awaited=bind_http_return(template.awaited, function_key, arguments)
        if template.awaited is not None
        else None,
    )


# Crate roots whose paths the security rules model. A local item or module of
# the same name shadows the crate, as in Rust's own resolution.
KNOWN_CRATES = frozenset(
    {
        "std",
        "tokio",
        "async_std",
        "axum",
        "axum_extra",
        "actix_web",
        "awc",
        "rocket",
        "hyper",
        "hyper_util",
        "http",
        "tonic",
        "reqwest",
        "reqwest_middleware",
        "ureq",
        "surf",
        "isahc",
        "attohttpc",
        "minreq",
        "webmention",
        "url",
        "percent_encoding",
        "urlencoding",
        "form_urlencoded",
        "html_escape",
        "htmlescape",
        "v_htmlescape",
        "askama_escape",
        "ammonia",
        "rustls",
        "tokio_rustls",
        "native_tls",
        "tokio_native_tls",
        "openssl",
    }
)


class State:
    def __init__(self, frames=None, conditions=frozenset()):
        self.frames = frames if frames is not None else [{}]
        self.conditions = conditions

    def copy(self):
        return State([dict(frame) for frame in self.frames], self.conditions)

    def get(self, name):
        for frame in reversed(self.frames):
            if name in frame:
                value = frame[name]
                if value.guarded_api is not None:
                    guards, api = value.guarded_api
                    return replace(
                        value, api=api if guards <= self.conditions else None
                    )
                return value
        if name in KNOWN_CRATES:
            return Value(api=name)
        if name == "String":
            return Value(api="std::string::String")
        if name == "Box":
            return Value(api="std::boxed::Box")
        if name in {"format", "format_args", "write", "writeln"}:
            return Value(api=f"std::{name}")
        return UNKNOWN

    def bind(self, name, value):
        self.frames[-1][name] = value

    def assign(self, name, value):
        for frame in reversed(self.frames):
            if name in frame:
                frame[name] = value
                return
        self.bind(name, value)

    def resolve(self, path):
        if path.startswith(("::std::", "::tokio::", "::async_std::")):
            return path[2:]
        if path.startswith(("::reqwest::", "::reqwest_middleware::")):
            root = path.split("::", 2)[1]
            if not any(root in frame for frame in self.frames):
                return path[2:]
        parts = path.split("::")
        base = self.get(parts[0]).api
        return "::".join([base, *parts[1:]]) if base else None

    def merge(self, branches):
        for index, frame in enumerate(self.frames):
            for name in frame:
                frame[name] = joined(
                    branch.frames[index].get(name, UNKNOWN) for branch in branches
                )


def use_bindings(node, text, prefix=""):
    """Expand tree-sitter use trees without interpreting comments as paths."""
    if node is None:
        return []
    kind = node.type
    if kind == "use_declaration":
        return use_bindings(node.child_by_field_name("argument"), text, prefix)
    if kind == "scoped_use_list":
        path = node.child_by_field_name("path")
        base = "::".join(part for part in (prefix, text(path)) if part)
        return use_bindings(node.child_by_field_name("list"), text, base)
    if kind == "use_list":
        return [
            item
            for child in node.named_children
            for item in use_bindings(child, text, prefix)
        ]
    if kind == "use_as_clause":
        path = node.child_by_field_name("path")
        alias = node.child_by_field_name("alias")
        full = (
            prefix
            if path.type == "self"
            else "::".join(part for part in (prefix, text(path)) if part)
        )
        return [(text(alias), full)]
    if kind in {"identifier", "scoped_identifier", "self"}:
        path = (
            prefix
            if kind == "self"
            else "::".join(part for part in (prefix, text(node)) if part)
        )
        return [(path.rsplit("::", 1)[-1], path)]
    if kind == "use_wildcard":
        # ``use actix_web::web::*``: the caller decides which names a glob of
        # a known module provides; an explicit import always wins.
        module = next(
            (
                child
                for child in node.named_children
                if child.type in {"identifier", "scoped_identifier"}
            ),
            None,
        )
        path = "::".join(
            part
            for part in (prefix, text(module) if module is not None else "")
            if part
        )
        return [("*", path)] if path else []
    return []


def unwrap(value):
    kind = value.kind
    if kind and kind.startswith(("result_", "option_")):
        return replace(value, kind=kind.split("_", 1)[1])
    return value
