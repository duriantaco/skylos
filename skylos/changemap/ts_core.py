from __future__ import annotations

from dataclasses import dataclass, field

from skylos.changemap.symbols import Symbol
from skylos.changemap.ts_imports import Bindings, Resolver, collect_bindings
from skylos.changemap.ts_nodes import BODY
from skylos.changemap.ts_params import _params, _signature, _typed_locals
from skylos.changemap.ts_walk import Scope, walk_body

FUNCTION_VALUES = frozenset({"arrow_function", "function_expression", "function", "generator_function"})


@dataclass
class Decl:
    qual: str
    kind: str
    node: object
    start_node: object
    function_node: object = None
    decorators: list[str] = field(default_factory=list)


class TsFile:
    def __init__(self, *, module: str, path: str, source: bytes, root, resolver: Resolver, security_named):
        self.module = module
        self.path = path
        self.source = source
        self.security_named = security_named
        self.bindings: Bindings = collect_bindings(root, module, path, self.text, resolver)
        self.symbols: dict[str, Symbol] = {}
        self.facts: dict[str, object] = {}
        self.assignments: dict[str, tuple[int, int, str]] = {}
        self.local_tops: set[str] = set()

    def text(self, node) -> str:
        return self.source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def tokens(self, node, skip=frozenset()) -> str:
        parts = []
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type == "comment" or current.id in skip:
                continue
            if current.child_count == 0:
                parts.append(self.text(current))
            stack.extend(reversed(current.children))
        return " ".join(parts)


def _apply_facts(symbol: Symbol, facts) -> None:
    symbol.calls = set(facts.calls)
    symbol.guards = list(facts.guards)
    symbol.rejections = list(facts.rejections)
    symbol.reads = set(facts.reads)


def make_symbol(file: TsFile, decl: Decl, scope: Scope) -> Symbol:
    facts = None
    params = ()
    signature = ""
    if decl.function_node is not None:
        scope.locals_typed = _typed_locals(decl.function_node, scope, file)
        facts = walk_body(decl.function_node.child_by_field_name(BODY), scope, file.local_tops, file.security_named)
        params = _params(decl.function_node, file.text)
        signature = _signature(decl.function_node, file)
    start = decl.start_node.start_point[0] + 1
    end = decl.node.end_point[0] + 1
    symbol = Symbol(
        qual=decl.qual, full_name=f"{file.module}.{decl.qual}", kind=decl.kind, start=start, end=end,
        signature=signature, decorators=decl.decorators, node=None, owned_lines=set(range(start, end + 1)),
        params=params, cached_shape=file.tokens(decl.node),
    )
    if facts is not None:
        _apply_facts(symbol, facts)
    file.symbols[decl.qual] = symbol
    file.facts[symbol.full_name] = facts
    return symbol


def make_scope(file: TsFile, class_name: str | None = None, base: str | None = None, members=frozenset()) -> Scope:
    return Scope(
        module=file.module, class_name=class_name, names=file.bindings.names,
        namespaces=file.bindings.namespaces, locals_typed={}, base_class=base, text=file.text,
        own_members=frozenset(members),
    )


def decorator_names(nodes, file: TsFile) -> list[str]:
    return [file.text(node.named_children[0]).split("(", 1)[0] for node in nodes if node.named_children]
