from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from skylos.visitors.languages.typescript.core import TypeScriptCore


@dataclass(frozen=True)
class JsApiReference:
    source: str | None
    symbol: str | None
    kind: str
    line: int
    col: int
    source_line: int
    type_only: bool = False
    skip_reason: str | None = None


@dataclass(frozen=True)
class NamespaceBinding:
    source: str
    source_line: int
    kind: str
    type_only: bool = False


@dataclass(frozen=True)
class ImportContext:
    source: str
    source_line: int
    clause: Any
    type_only: bool


def source_string_node(node: Any) -> Any | None:
    return first_named_child(node, "string")


def string_value(core: TypeScriptCore, node: Any | None) -> str | None:
    if node is None or node.type != "string":
        return None
    text = core._get_text(node).strip()
    if len(text) < 2 or text[0] not in {"'", '"'} or text[-1] != text[0]:
        return None
    return text[1:-1]


def property_name(core: TypeScriptCore, node: Any) -> str | None:
    if node.type in {"identifier", "property_identifier"}:
        return core._get_text(node)
    return string_value(core, node)


def named_child(node: Any, node_type: str) -> Any | None:
    return first_named_child(node, node_type)


def first_named_child(node: Any, node_type: str) -> Any | None:
    for child in node.named_children:
        if child.type == node_type:
            return child
    return None


def make_reference(
    source: str,
    symbol: str | None,
    kind: str,
    node: Any,
    source_line: int,
    *,
    type_only: bool = False,
    skip_reason: str | None = None,
) -> JsApiReference:
    return JsApiReference(
        source=source,
        symbol=symbol,
        kind=kind,
        line=node_line(node),
        col=int(node.start_point[1]),
        source_line=source_line,
        type_only=type_only,
        skip_reason=skip_reason,
    )


def node_line(node: Any) -> int:
    return int(node.start_point[0]) + 1
