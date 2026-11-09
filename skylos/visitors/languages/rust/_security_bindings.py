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

    @property
    def tainted(self):
        return bool(self.sources) and not self.contained


UNKNOWN = Value()


def joined(values):
    values = tuple(values)
    if not values:
        return UNKNOWN
    first = values[0]
    items = first.items if all(v.items == first.items for v in values) else ()
    if not items and any(v.items for v in values):
        items = (
            Value(
                sources=frozenset().union(*(v.sources for v in values)),
                kind="unknown_args",
            ),
        )
    return Value(
        sources=frozenset().union(*(v.sources for v in values)),
        return_sources=frozenset().union(*(v.return_sources for v in values)),
        kind=first.kind if all(v.kind == first.kind for v in values) else None,
        api=first.api if all(v.api == first.api for v in values) else None,
        guarded_api=first.guarded_api
        if all(v.guarded_api == first.guarded_api for v in values)
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
        if name in {"std", "tokio", "async_std"}:
            return Value(api=name)
        if name == "String":
            return Value(api="std::string::String")
        if name in {"format", "format_args"}:
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
    return []


def unwrap(value):
    kind = value.kind
    if kind and kind.startswith(("result_", "option_")):
        return replace(value, kind=kind.split("_", 1)[1])
    return value
