"""Source-bound Swift private declaration reachability.

Public/internal APIs are roots. Private/fileprivate declarations use a lexical
declaration graph, not text matching. Unknown dispatch and runtime entry points
retain possible declarations; this is not Swift compiler or macro expansion.
"""

from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict, deque
from dataclasses import dataclass, field
import hashlib

from skylos.visitors.base import Definition

try:
    from tree_sitter import Language, Parser
    import tree_sitter_swift
except ImportError:
    Language = Parser = tree_sitter_swift = None


MAX_SWIFT_NODES = 100_000
MAX_SWIFT_SYMBOLS = 20_000
MAX_SWIFT_EDGES = 200_000
MAX_SWIFT_RESOLUTION_WORK = 500_000
_FUNCTIONS = {"function_declaration", "protocol_function_declaration"}
_TYPES = {"class_declaration", "protocol_declaration"}
_TYPE_BODIES = {"class_body", "protocol_body", "enum_class_body"}
_SCOPES = {
    "statements",
    "lambda_literal",
    "for_statement",
    "switch_entry",
    "catch_block",
}
_PASSIVE_ATTRIBUTES = {
    "available",
    "backDeployed",
    "discardableResult",
    "inlinable",
    "inline",
    "usableFromInline",
    "MainActor",
    "preconcurrency",
    "Sendable",
    "nonobjc",
    "objc",
    "objcMembers",
    "propertyWrapper",
    "resultBuilder",
    "frozen",
    "_transparent",
    "_alwaysEmitIntoClient",
    "_documentation",
    "_spi",
}
_RUNTIME_ATTRIBUTES = {
    "objc",
    "objcMembers",
    "IBAction",
    "IBOutlet",
    "IBInspectable",
    "IBDesignable",
    "NSManaged",
    "main",
    "UIApplicationMain",
    "NSApplicationMain",
    "Test",
    "_cdecl",
    "_silgen_name",
    "GKInspectable",
}
_PROPERTY_WRAPPERS = {
    "State",
    "StateObject",
    "ObservedObject",
    "Environment",
    "EnvironmentObject",
    "Binding",
    "FocusState",
    "AppStorage",
    "SceneStorage",
    "Published",
    "UIApplicationDelegateAdaptor",
    "NSApplicationDelegateAdaptor",
}
_SYNTHESIZED_PROPERTIES = {"Codable", "Encodable", "Decodable", "Equatable", "Hashable"}
_SKIP_TEXT = {"comment", "multiline_comment", "line_str_text", "multi_line_str_text"}
_LITERAL_TYPES = {
    "integer_literal": "Int",
    "real_literal": "Double",
    "boolean_literal": "Bool",
    "line_string_literal": "String",
    "multi_line_string_literal": "String",
    "array_literal": "Array",
    "dictionary_literal": "Dictionary",
}


class SwiftScanError(ValueError):
    def __init__(self, message, *, kind="source_complexity"):
        super().__init__(message)
        self.kind = kind


def descendants(node):
    pending = [node] if node is not None else []
    while pending:
        current = pending.pop()
        yield current
        pending.extend(reversed(current.named_children))


def parse(source):
    if Language is None or Parser is None or tree_sitter_swift is None:
        return None
    try:
        return Parser(Language(tree_sitter_swift.language())).parse(source)
    except (ValueError, TypeError, RuntimeError) as error:
        raise SwiftScanError(
            "Swift grammar could not be initialized", kind="parser_unavailable"
        ) from error


@dataclass(eq=False)
class Scope:
    node: object
    parent: Scope | None = None
    owner: str = ""
    bindings: dict[str, list] = field(default_factory=lambda: defaultdict(list))
    index: dict | None = None


@dataclass(eq=False)
class Binding:
    name: str
    scope: Scope
    start: int
    node: object
    symbol: object = None
    value: object = None
    type_name: str | None = None
    constant: bool = False
    writes: bool = False
    generic: bool = False


@dataclass(eq=False)
class Symbol:
    node: object
    name: str
    owner: str
    kind: str
    private: bool
    scope: Scope
    attributes: set = field(default_factory=set)
    modifiers: set = field(default_factory=set)
    labels: tuple = ()
    defaults: tuple = ()
    parameter_types: tuple = ()
    variadic: bool = False
    return_type: str | None = None
    type_name: str | None = None
    value: object = None
    conditional: bool = False
    definition: object = None
    reasons: set = field(default_factory=set)

    @property
    def canonical(self):
        return f"{self.owner}.{self.name}" if self.owner else self.name


class SwiftCore:
    def __init__(self, file_path, source):
        self.file_path = str(file_path)
        self.source = source
        self.tree = parse(source)
        self.root_node = self.tree.root_node if self.tree is not None else None
        self.defs = []
        self.refs = []
        self.raw_imports = []
        self.classes = {}
        self.unresolved = []
        self.symbols = []
        self.types = {}
        self.members = defaultdict(lambda: defaultdict(list))
        self.member_names = defaultdict(list)
        self.aliases = {}
        self.edges = defaultdict(set)
        self.roots = set()
        self.reflection_edges = defaultdict(set)
        self.reflection_roots = set()
        self.reflection_reasons = defaultdict(set)
        self.node_scopes = {}
        self.node_sources = {}
        self.declarations = set()
        self.bindings = []
        self.scopes = []
        self.inherits = defaultdict(set)
        self._nodes = []
        self._edge_count = 0
        self.resolution_work = 0
        self._conditional_ranges = []
        self._conditional_starts = []
        self._unknown_macro = False
        self._project_requests = []
        self.project_reflection_facts = None

    def text(self, node):
        return (
            self.source[node.start_byte : node.end_byte].decode("utf-8")
            if node is not None
            else ""
        )

    def name(self, node):
        return self.text(node).strip("`")

    def _work(self, count=1):
        self.resolution_work += count
        if self.resolution_work > MAX_SWIFT_RESOLUTION_WORK:
            raise SwiftScanError("Swift name resolution work limit exceeded")

    def _modifiers(self, node):
        result, attributes = set(), set()
        container = next(
            (n for n in node.named_children if n.type == "modifiers"), None
        )
        if container is not None:
            for child in container.named_children:
                if child.type == "attribute":
                    user_type = next(
                        (n for n in child.named_children if n.type == "user_type"), None
                    )
                    value = self._type_text(user_type)
                    if value:
                        attributes.add(value.rsplit(".", 1)[-1])
                else:
                    result.add(self.text(child))
        return result, attributes

    def _type_text(self, node):
        if node is None:
            return None
        if node.type == "type_identifier":
            return self.name(node)
        if node.type == "user_type":
            parts = [
                self.name(n) for n in node.named_children if n.type == "type_identifier"
            ]
            return ".".join(parts) or None
        if node.type in {
            "type_annotation",
            "optional_type",
            "existential_type",
            "metatype",
        }:
            children = [
                n for n in node.named_children if n.type not in {"type_modifiers"}
            ]
            return self._type_text(children[-1]) if len(children) == 1 else None
        return None

    def _names(self, pattern):
        if pattern is None:
            return []
        result = []
        for node in descendants(pattern):
            bound = node.child_by_field_name("bound_identifier")
            if bound is not None and bound.type == "simple_identifier":
                result.append(bound)
            elif (
                node.type == "pattern"
                and len(node.named_children) == 1
                and node.named_children[0].type == "simple_identifier"
            ):
                result.append(node.named_children[0])
        if pattern.type == "simple_identifier":
            result.append(pattern)
        return list({n.id: n for n in result}.values())

    def _bind(self, scope, node, *, start=None, **facts):
        if node is None:
            return None
        name = self.name(node)
        if not name or name == "_":
            self.declarations.add(node.id)
            return None
        binding = Binding(
            name,
            scope,
            scope.node.start_byte if start is None else start,
            node,
            **facts,
        )
        scope.bindings[name].append(binding)
        self.bindings.append(binding)
        self.declarations.add(node.id)
        return binding

    def _scope(self, node, parent, owner=None):
        scope = Scope(
            node, parent, parent.owner if owner is None and parent else owner or ""
        )
        self.scopes.append(scope)
        return scope

    def _symbol(self, node, name, owner, kind, private, scope, modifiers, attributes):
        if len(self.symbols) >= MAX_SWIFT_SYMBOLS:
            raise SwiftScanError("Swift symbol analysis limit exceeded")
        if kind in {"function", "method"} and not name.isidentifier():
            private = False
        symbol = Symbol(node, name, owner, kind, private, scope, attributes, modifiers)
        conditional = bisect_right(self._conditional_starts, node.start_byte) - 1
        symbol.conditional = (
            conditional >= 0
            and node.start_byte < self._conditional_ranges[conditional][1]
        )
        self.symbols.append(symbol)
        self.members[owner][name].append(symbol)
        if owner:
            self.member_names[name].append(symbol)
        if kind == "class":
            self.types[symbol.canonical] = symbol
        return symbol

    def _conditional_spans(self):
        opens = []
        spans = []
        for node in self._nodes:
            if node.type != "directive":
                continue
            text = self.text(node).lstrip()
            if text.startswith("#if ") or text.startswith("#if\t"):
                opens.append(node.start_byte)
            elif text.startswith("#endif") and opens:
                spans.append((opens.pop(), node.end_byte))
        spans.extend((start, len(self.source)) for start in opens)
        merged = []
        for start, end in sorted(spans):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return merged

    def scan(self):
        if self.root_node is None or self.root_node.has_error:
            return
        for node in descendants(self.root_node):
            self._nodes.append(node)
            if len(self._nodes) > MAX_SWIFT_NODES:
                raise SwiftScanError("Swift syntax analysis limit exceeded")
        self._conditional_ranges = self._conditional_spans()
        self._conditional_starts = [start for start, _ in self._conditional_ranges]
        module = self._scope(self.root_node, None)
        pending = [(self.root_node, module, None, "", False)]
        while pending:
            node, outer, caller, owner, default_private = pending.pop()
            scope = outer
            children = list(node.named_children)
            source = caller
            child_owner, child_private = owner, default_private
            if node.type in _TYPES:
                modifiers, attributes = self._modifiers(node)
                name_node = node.child_by_field_name("name")
                extension = any(child.type == "extension" for child in node.children)
                raw_name = self._type_text(name_node) or self.name(name_node)
                private = (
                    bool({"private", "fileprivate"} & modifiers) or default_private
                )
                if extension:
                    child_owner = raw_name
                    source = self.types.get(raw_name)
                    child_private = private
                    self.declarations.update(
                        n.id
                        for n in descendants(name_node)
                        if n.type in {"simple_identifier", "type_identifier"}
                    )
                else:
                    name = raw_name.rsplit(".", 1)[-1]
                    symbol = self._symbol(
                        node,
                        name,
                        owner,
                        "class",
                        private,
                        outer,
                        modifiers,
                        attributes,
                    )
                    self._bind(outer, name_node, symbol=symbol)
                    source = symbol
                    child_owner = symbol.canonical
                    child_private = False
                    self.declarations.add(name_node.id)
                scope = self._scope(node, outer, child_owner)
                for inherited in node.named_children:
                    if inherited.type == "inheritance_specifier":
                        inherited_name = self._type_text(
                            inherited.child_by_field_name("inherits_from")
                        )
                        if inherited_name:
                            self.inherits[child_owner].add(inherited_name)
                body = node.child_by_field_name("body")
                if body is not None:
                    self.node_scopes[body.id] = scope
            elif node.type in _FUNCTIONS:
                modifiers, attributes = self._modifiers(node)
                name_node = node.child_by_field_name("name")
                name = self.name(name_node)
                local = (
                    caller is not None
                    and caller.kind != "class"
                    and outer.owner == owner
                )
                symbol_owner = caller.canonical if local else owner
                private = (
                    bool({"private", "fileprivate"} & modifiers)
                    or default_private
                    or local
                )
                symbol = self._symbol(
                    node,
                    name,
                    symbol_owner,
                    "method" if owner and not local else "function",
                    private,
                    outer,
                    modifiers,
                    attributes,
                )
                self._bind(outer, name_node, symbol=symbol)
                scope = self._scope(node, outer, owner)
                source = symbol
                body = node.child_by_field_name("body")
                labels, defaults, parameter_types = [], [], []
                parameters = [n for n in node.named_children if n.type == "parameter"]
                default_values = {
                    n.id
                    for index, n in enumerate(node.named_children)
                    if node.field_name_for_named_child(index) == "default_value"
                }
                for parameter in parameters:
                    external = parameter.child_by_field_name("external_name")
                    names = [
                        n
                        for n in parameter.named_children
                        if n.type == "simple_identifier" and n != external
                    ]
                    internal = names[0] if names else None
                    label = self.name(external or internal)
                    labels.append(label or "_")
                    following = parameter.next_named_sibling
                    defaults.append(
                        following is not None and following.id in default_values
                    )
                    type_node = next(
                        (
                            n
                            for n in parameter.named_children
                            if n.type
                            in {
                                "user_type",
                                "optional_type",
                                "function_type",
                                "existential_type",
                                "array_type",
                                "dictionary_type",
                                "tuple_type",
                            }
                        ),
                        None,
                    )
                    type_name = self._type_text(type_node)
                    parameter_types.append(type_name)
                    symbol.variadic |= any(c.type == "..." for c in parameter.children)
                    self._bind(
                        scope,
                        internal,
                        start=body.start_byte if body is not None else node.end_byte,
                        type_name=type_name,
                    )
                    if external is not None:
                        self.declarations.add(external.id)
                symbol.labels, symbol.defaults, symbol.parameter_types = (
                    tuple(labels),
                    tuple(defaults),
                    tuple(parameter_types),
                )
                # Swift's grammar repeats the name field on the return type.
                returns = [
                    n
                    for n in node.named_children
                    if n.type in {"user_type", "optional_type", "existential_type"}
                ]
                symbol.return_type = self._type_text(returns[-1]) if returns else None
            elif node.type == "property_declaration":
                modifiers, attributes = self._modifiers(node)
                pattern = node.child_by_field_name("name")
                names = self._names(pattern)
                value = node.child_by_field_name("value")
                annotation = next(
                    (n for n in node.named_children if n.type == "type_annotation"),
                    None,
                )
                type_name = self._type_text(annotation)
                constant = any(
                    c.type == "let"
                    for p in node.named_children
                    if p.type == "value_binding_pattern"
                    for c in p.children
                )
                is_local = caller is not None and caller.kind != "class"
                if not is_local and len(names) == 1:
                    private = (
                        bool({"private", "fileprivate"} & modifiers) or default_private
                    )
                    symbol = self._symbol(
                        node,
                        self.name(names[0]),
                        owner,
                        "variable",
                        private,
                        outer,
                        modifiers,
                        attributes,
                    )
                    symbol.type_name, symbol.value = type_name, value
                    self._bind(
                        outer,
                        names[0],
                        symbol=symbol,
                        value=value,
                        type_name=type_name,
                        constant=constant,
                    )
                    source = symbol
                    # Stored instance initializers run when the owner is used,
                    # even if the property is never subsequently read.
                    if (
                        value is not None
                        and owner
                        and not ({"static", "class", "lazy"} & modifiers)
                    ):
                        source = self.types.get(owner, symbol)
                else:
                    for name_node in names:
                        self._bind(
                            outer,
                            name_node,
                            start=node.end_byte,
                            value=value if len(names) == 1 else None,
                            type_name=type_name,
                            constant=constant,
                        )
            elif node.type in {
                "init_declaration",
                "deinit_declaration",
                "subscript_declaration",
            }:
                scope = self._scope(node, outer, owner)
                source = self.types.get(owner, caller)
                body = node.child_by_field_name("body")
                for parameter in (
                    n for n in node.named_children if n.type == "parameter"
                ):
                    external = parameter.child_by_field_name("external_name")
                    internal = next(
                        (
                            n
                            for n in parameter.named_children
                            if n.type == "simple_identifier" and n != external
                        ),
                        None,
                    )
                    self._bind(
                        scope,
                        internal,
                        start=body.start_byte if body is not None else node.start_byte,
                    )
                    if external is not None:
                        self.declarations.add(external.id)
            elif node.type in _SCOPES:
                scope = self._scope(node, outer, owner)
            elif node.type == "import_declaration":
                self.raw_imports.append(
                    {
                        "source": self.text(node).removeprefix("import").strip(),
                        "names": [],
                        "line": node.start_point[0] + 1,
                    }
                )
                self.declarations.update(n.id for n in descendants(node))
            elif node.type == "typealias_declaration":
                name_node = node.child_by_field_name("name")
                value = next(
                    (
                        n
                        for n in reversed(node.named_children)
                        if n.type
                        in {
                            "user_type",
                            "optional_type",
                            "function_type",
                            "tuple_type",
                            "array_type",
                            "dictionary_type",
                        }
                    ),
                    None,
                )
                if name_node is not None:
                    self.aliases[(outer, self.name(name_node))] = self._type_text(value)
                    self.declarations.add(name_node.id)
                # Generic parameters belong to the alias, not its enclosing
                # function/module. They must not shadow unrelated source types.
                scope = self._scope(node, outer, owner)
            elif node.type in {"macro_invocation", "external_macro_definition"}:
                self._unknown_macro = True
            self.node_scopes[node.id] = scope
            self.node_sources[node.id] = source
            pending.extend(
                (child, scope, source, child_owner, child_private)
                for child in reversed(children)
            )
        self._finish_bindings()
        self._index_bindings()
        self._establish_roots()
        self._scan_references()
        self._emit_definitions()

    def _finish_bindings(self):
        for node in self._nodes:
            scope = self.node_scopes[node.id]
            if node.type == "lambda_parameter":
                self._bind(
                    scope, node.child_by_field_name("name"), start=scope.node.start_byte
                )
            elif node.type == "for_statement":
                body = next(
                    (n for n in node.named_children if n.type == "statements"), None
                )
                for name in self._names(node.child_by_field_name("item")):
                    self._bind(
                        scope, name, start=body.start_byte if body else node.end_byte
                    )
            elif node.type in {"if_statement", "while_statement", "guard_statement"}:
                names = [
                    node.child(i)
                    for i in range(node.child_count)
                    if node.field_name_for_child(i) == "bound_identifier"
                ]
                body = next(
                    (n for n in node.named_children if n.type == "statements"), None
                )
                target = (
                    scope
                    if node.type == "guard_statement"
                    else self.node_scopes.get(body.id)
                    if body
                    else None
                )
                if target is not None:
                    for name in names:
                        self._bind(
                            target,
                            name,
                            start=node.end_byte
                            if node.type == "guard_statement"
                            else body.start_byte,
                        )
            elif node.type in {"generic_parameter", "type_parameter"}:
                name = next(
                    (n for n in node.named_children if n.type == "type_identifier"),
                    None,
                )
                self._bind(scope, name, start=scope.node.start_byte, generic=True)
            elif node.type == "capture_list_item":
                name_node = node.child_by_field_name("name")
                value = node.child_by_field_name("value")
                if value is None and name_node is not None:
                    # A shorthand capture reads its outer binding before the
                    # capture or enclosing local initializer is introduced.
                    binding = self._binding(name_node)
                    if binding is not None and binding.symbol is not None:
                        self._add(
                            self.node_sources[node.id],
                            binding.symbol,
                            "outer shorthand closure capture",
                        )
                body = next(
                    (n for n in scope.node.named_children if n.type == "statements"),
                    None,
                )
                self._bind(
                    scope,
                    name_node,
                    start=body.start_byte if body is not None else node.end_byte,
                    value=value,
                    constant=True,
                )
            elif node.type == "assignment":
                target = node.child_by_field_name("target")
                if (
                    target is not None
                    and target.type == "directly_assignable_expression"
                    and len(target.named_children) == 1
                ):
                    binding = self._binding(target.named_children[0])
                    if binding is not None:
                        binding.writes = True

    def _index_bindings(self):
        for scope in self.scopes:
            scope.index = {}
            for name, bindings in scope.bindings.items():
                locals_here = sorted(
                    (b for b in bindings if b.symbol is None), key=lambda b: b.start
                )
                symbols = sorted(
                    (b for b in bindings if b.symbol is not None), key=lambda b: b.start
                )
                scope.index[name] = (
                    [b.start for b in locals_here],
                    locals_here,
                    [b.start for b in symbols],
                    symbols,
                )

    def _binding_name(self, name, position, scope):
        while scope is not None:
            self._work()
            if scope.index is not None:
                entry = scope.index.get(name)
                if entry is not None:
                    for starts, bindings in (entry[:2], entry[2:]):
                        index = bisect_right(starts, position) - 1
                        if index >= 0:
                            return bindings[index]
                scope = scope.parent
                continue
            self._work(len(scope.bindings.get(name, ())))
            candidates = [
                b for b in scope.bindings.get(name, ()) if b.start <= position
            ]
            if candidates:
                # Overloaded declarations intentionally share a binding name.
                non_symbols = [b for b in candidates if b.symbol is None]
                return max(non_symbols or candidates, key=lambda b: b.start)
            scope = scope.parent
        return None

    def _binding(self, node):
        return self._binding_name(
            self.name(node), node.start_byte, self.node_scopes.get(node.id)
        )

    def _type(self, name, scope, seen=frozenset()):
        if not name:
            return None
        if name in {"Self", "self"}:
            return scope.owner or None
        current = scope
        while current is not None:
            self._work(1 + len(current.bindings.get(name, ())))
            if any(b.generic for b in current.bindings.get(name, ())):
                return None
            identity = (current, name)
            if identity in self.aliases:
                if identity in seen or len(seen) >= 32:
                    return None
                return self._type(self.aliases[identity], current, seen | {identity})
            current = current.parent
        owner = scope.owner
        while owner:
            candidate = f"{owner}.{name}"
            if candidate in self.types:
                return candidate
            owner = owner.rpartition(".")[0]
        return name

    def _add(self, caller, target, reason="source reference"):
        self._work()
        if target is None:
            return
        if caller is None:
            self.roots.add(target)
        elif target not in self.edges[caller]:
            self.edges[caller].add(target)
            self._edge_count += 1
            if self._edge_count > MAX_SWIFT_EDGES:
                raise SwiftScanError("Swift reachability analysis limit exceeded")
        target.reasons.add(reason)

    def _add_reflection(self, caller, target, reason):
        self._work()
        if caller is None:
            self.reflection_roots.add(target)
        elif target not in self.reflection_edges[caller]:
            self.reflection_edges[caller].add(target)
            self._edge_count += 1
            if self._edge_count > MAX_SWIFT_EDGES:
                raise SwiftScanError("Swift reachability analysis limit exceeded")
        self.reflection_reasons[target].add(reason)

    def _establish_roots(self):
        for symbol in self.symbols:
            parent = self.types.get(symbol.owner)
            if not symbol.private:
                self._add(parent, symbol, "source-visible API")
            if symbol.conditional:
                self._add(None, symbol, "conditional compilation is not evaluated")
            if (
                symbol.attributes & _RUNTIME_ATTRIBUTES
                or "override" in symbol.modifiers
                or "dynamic" in symbol.modifiers
            ):
                self._add(parent, symbol, "runtime or override entry point")
            unknown = (
                symbol.attributes
                - _PASSIVE_ATTRIBUTES
                - _RUNTIME_ATTRIBUTES
                - _PROPERTY_WRAPPERS
            )
            if unknown:
                self._add(parent, symbol, "unexpanded declaration attribute")
                self.unresolved.append(
                    {
                        "line": symbol.node.start_point[0] + 1,
                        "kind": "declaration_attribute",
                        "names": sorted(unknown),
                    }
                )
            if symbol.kind == "variable" and symbol.attributes:
                self._add(parent, symbol, "property wrapper or runtime property")
            if symbol.kind == "class" and "NSObject" in self.inherits[symbol.canonical]:
                self._add(None, symbol, "Objective-C runtime type")
            if self._unknown_macro:
                self._add(None, symbol, "unexpanded source macro")
        inherited = {name: set(values) for name, values in self.inherits.items()}
        inherited_count = sum(map(len, inherited.values()))
        for _ in range(min(len(inherited), 64)):
            changed = False
            for name, values in inherited.items():
                self._work(
                    len(values) + sum(len(inherited.get(value, ())) for value in values)
                )
                additions = (
                    set().union(
                        *(inherited.get(value, set()) for value in list(values))
                    )
                    if values
                    else set()
                )
                if additions - values:
                    inherited_count += len(additions - values)
                    if inherited_count > MAX_SWIFT_EDGES:
                        raise SwiftScanError(
                            "Swift inheritance analysis limit exceeded"
                        )
                    values.update(additions)
                    changed = True
            if not changed:
                break
        for owner, symbols in self.members.items():
            parent = self.types.get(owner)
            if parent is None:
                continue
            synth = {
                n.rsplit(".", 1)[-1] for n in inherited.get(owner, ())
            } & _SYNTHESIZED_PROPERTIES
            runtime = "objcMembers" in parent.attributes
            requirements = set()
            for protocol in inherited.get(owner, ()):
                declaration = self.types.get(protocol)
                if (
                    declaration is not None
                    and declaration.node.type == "protocol_declaration"
                ):
                    requirements.update(self.members.get(protocol, {}))
            for values in symbols.values():
                for symbol in values:
                    if (
                        runtime
                        or (synth and symbol.kind == "variable")
                        or symbol.name in requirements
                    ):
                        self._add(parent, symbol, "runtime or synthesized member")

    def _call_labels(self, node):
        parent = node.parent
        if (
            parent is None
            or parent.type != "call_expression"
            or not parent.named_children
            or parent.named_children[0] != node
        ):
            return None
        suffix = next(
            (n for n in parent.named_children if n.type == "call_suffix"), None
        )
        if suffix is None or any(
            n.type == "lambda_literal" for n in suffix.named_children
        ):
            return None
        arguments = next(
            (n for n in suffix.named_children if n.type == "value_arguments"), None
        )
        if arguments is None:
            return None
        labels = []
        for argument in arguments.named_children:
            if argument.type != "value_argument":
                continue
            label = argument.child_by_field_name(
                "name"
            ) or argument.child_by_field_name("reference_specifier")
            labels.append(self.name(label) if label is not None else "_")
        return tuple(labels)

    def _matches(self, symbol, labels):
        self._work()
        if (
            labels is None
            or symbol.kind not in {"function", "method"}
            or symbol.variadic
        ):
            return True
        if len(symbol.labels) > 64:
            return True
        states = {0}
        for parameter, default in zip(symbol.labels, symbol.defaults):
            self._work(len(states))
            next_states = set()
            for position in states:
                if default:
                    next_states.add(position)
                if position < len(labels) and parameter == labels[position]:
                    next_states.add(position + 1)
            states = next_states
        return len(labels) in states

    def _lookup(self, node):
        name = self.name(node)
        binding = self._binding(node)
        if binding is not None:
            if binding.symbol is None:
                return []
            symbols = self.members[binding.symbol.owner][binding.symbol.name]
        else:
            owner = self.node_scopes[node.id].owner
            symbols = []
            while owner:
                if self.members[owner].get(name):
                    symbols = self.members[owner][name]
                    break
                owner = owner.rpartition(".")[0]
            if not symbols:
                symbols = self.members[""].get(name, [])
        labels = self._call_labels(node)
        self._work(len(symbols))
        return [s for s in symbols if self._matches(s, labels)]

    def _infer(self, node, seen=frozenset(), depth=0):
        self._work()
        if node is None or depth > 32:
            return None
        scope = self.node_scopes.get(node.id)
        if scope is None:
            return None
        if node.type in {"self_expression", "super_expression"}:
            return scope.owner or None
        if node.type in _LITERAL_TYPES:
            return _LITERAL_TYPES[node.type]
        if node.type in {"simple_identifier", "type_identifier"}:
            name = self.name(node)
            if name in {"Self", "self"}:
                return scope.owner or None
            binding = self._binding(node)
            if binding is not None:
                if binding in seen or binding.generic:
                    return None
                if binding.symbol is not None and binding.symbol.kind == "class":
                    return binding.symbol.canonical
                if binding.type_name:
                    return self._type(binding.type_name, scope)
                if binding.constant and not binding.writes:
                    return self._infer(binding.value, seen | {binding}, depth + 1)
                return None
            canonical = self._type(name, scope)
            return (
                canonical
                if canonical in self.types or canonical in self.members
                else None
            )
        if node.type == "key_path_expression":
            name = next(
                (n for n in node.named_children if n.type == "type_identifier"), None
            )
            return (
                self._type(self.name(name), scope)
                if name is not None
                else scope.owner or None
            )
        if node.type == "call_expression" and node.named_children:
            callee = node.named_children[0]
            inferred = self._infer(callee, seen, depth + 1)
            if inferred:
                return inferred
            targets = (
                self._lookup(callee)
                if callee.type == "simple_identifier"
                else self._navigation(callee)
                if callee.type == "navigation_expression"
                else []
            )
            returns = {
                self._type(s.return_type, scope) for s in targets if s.return_type
            }
            return next(iter(returns)) if len(returns) == 1 else None
        if node.type == "navigation_expression":
            targets = self._navigation(node, depth + 1)
            types = {self._type(s.type_name, scope) for s in targets if s.type_name}
            if len(types) == 1:
                return next(iter(types))
        if node.type in {
            "parenthesized_expression",
            "tuple_expression",
            "try_expression",
            "await_expression",
            "postfix_expression",
            "prefix_expression",
        }:
            children = [n for n in node.named_children if n.type not in {"operator"}]
            if len(children) == 1:
                return self._infer(children[0], seen, depth + 1)
        return None

    def _navigation(self, node, depth=0):
        if depth > 32:
            return []
        suffix = node.child_by_field_name("suffix")
        name_node = suffix.child_by_field_name("suffix") if suffix is not None else None
        if name_node is None:
            return []
        name = self.name(name_node)
        target = node.child_by_field_name("target")
        owner = self._infer(target, depth=depth + 1)
        if owner:
            targets = self.members.get(owner, {}).get(name, [])
        else:
            # No guessed receiver identity. An unresolved dispatch may reach
            # any same-spelled source member; keep it with an explicit reason.
            targets = self.member_names.get(name, [])
        labels = self._call_labels(node)
        self._work(len(targets))
        return [s for s in targets if self._matches(s, labels)]

    def _scan_references(self):
        for node in self._nodes:
            self._work()
            if node.id in self.declarations or node.type in _SKIP_TEXT:
                continue
            caller = self.node_sources[node.id]
            if node.type == "navigation_expression":
                targets = self._navigation(node)
                owner = self._infer(node.child_by_field_name("target"))
                for symbol in targets:
                    self._add(
                        caller,
                        symbol,
                        "resolved owner member"
                        if owner
                        else "unresolved receiver may reach member",
                    )
            elif node.type in {"simple_identifier", "type_identifier"}:
                parent = node.parent
                if parent is None or parent.type in {
                    "navigation_suffix",
                    "value_argument_label",
                    "directive",
                    "value_binding_pattern",
                }:
                    continue
                if node.type == "type_identifier":
                    binding = self._binding(node)
                    if binding is not None and binding.generic:
                        continue
                    scope = self.node_scopes[node.id]
                    symbol = self.types.get(self._type(self.name(node), scope))
                    if symbol is not None:
                        self._add(caller, symbol, "source type reference")
                else:
                    for symbol in self._lookup(node):
                        self._add(caller, symbol)
            if node.type == "call_expression":
                self._reflection(node, caller)

    def _arguments(self, node):
        suffix = next((n for n in node.named_children if n.type == "call_suffix"), None)
        arguments = (
            next(
                (n for n in suffix.named_children if n.type == "value_arguments"), None
            )
            if suffix is not None
            else None
        )
        return (
            [n for n in arguments.named_children if n.type == "value_argument"]
            if arguments is not None
            else []
        )

    def _name_shadowed(self, name, scope, position):
        if self._binding_name(name, position, scope) is not None:
            return True
        while scope is not None:
            self._work()
            if (scope, name) in self.aliases:
                return True
            scope = scope.parent
        return False

    def _reflection_provider(self, node, seen=frozenset(), depth=0):
        """Resolve the real standard constructor or a stable function value."""
        if node is None or depth > 32:
            return None
        self._work()
        scope = self.node_scopes[node.id]
        if node.type == "simple_identifier":
            binding = self._binding(node)
            if binding is not None:
                if (
                    binding in seen
                    or binding.symbol is not None
                    or not binding.constant
                    or binding.writes
                ):
                    return None
                return self._reflection_provider(
                    binding.value, seen | {binding}, depth + 1
                )
            name = self._type(self.name(node), scope)
            qualified = bool(name and name.startswith("Swift."))
            if name and name.startswith("Swift."):
                if self._name_shadowed("Swift", scope, node.start_byte):
                    return None
                name = name.removeprefix("Swift.")
            if name in {"Mirror", "String", "dump"} and name not in self.types:
                return name, False, qualified
        elif node.type == "navigation_expression":
            target = node.child_by_field_name("target")
            suffix = node.child_by_field_name("suffix")
            name = (
                self.name(suffix.child_by_field_name("suffix"))
                if suffix is not None
                else ""
            )
            if name in {"init", "self"}:
                provider = self._reflection_provider(target, seen, depth + 1)
                return (provider[0], name == "init", provider[2]) if provider else None
            if (
                target is not None
                and target.type == "simple_identifier"
                and self.name(target) == "Swift"
                and not self._name_shadowed("Swift", scope, node.start_byte)
            ):
                return (
                    (name, False, True)
                    if name in {"Mirror", "String", "dump"}
                    else None
                )
        elif node.type == "call_expression" and node.named_children:
            arguments = self._arguments(node)
            if arguments and all(
                a.child_by_field_name("reference_specifier") is not None
                and a.child_by_field_name("value") is None
                for a in arguments
            ):
                labels = {
                    self.name(a.child_by_field_name("reference_specifier"))
                    for a in arguments
                }
                provider = self._reflection_provider(
                    node.named_children[0], seen, depth + 1
                )
                if provider and labels <= {"reflecting", "describing"}:
                    return provider[0], True, provider[2]
        return None

    def _stored_instance_property(self, symbol):
        return bool(
            symbol.owner
            and symbol.kind == "variable"
            and not ({"static", "class"} & symbol.modifiers)
            and symbol.node.child_by_field_name("computed_value") is None
        )

    def _reflect_properties(
        self, caller, owner, *, provider, qualified, intrinsic=False
    ):
        if intrinsic:
            return
        self._project_requests.append((caller, owner, provider, qualified))
        if owner is None:
            self._work(len(self.symbols))
            candidates = (s for s in self.symbols if self._stored_instance_property(s))
        else:
            owners = {owner}
            pending = [owner]
            while pending and len(owners) <= 64:
                current = pending.pop()
                for parent in self.inherits.get(current, ()):
                    if parent in self.types and parent not in owners:
                        owners.add(parent)
                        pending.append(parent)
            candidates = (
                s
                for current in owners
                for values in self.members.get(current, {}).values()
                for s in values
                if self._stored_instance_property(s)
            )
        for symbol in candidates:
            self._add_reflection(
                caller,
                symbol,
                "source-visible reflection"
                if owner
                else "generic reflection may observe stored properties",
            )

    def _reflection(self, node, caller):
        if not node.named_children:
            return
        provider = self._reflection_provider(node.named_children[0])
        if provider is None:
            return
        kind, indirect, qualified = provider
        arguments = self._arguments(node)
        if arguments and all(
            a.child_by_field_name("reference_specifier") is not None for a in arguments
        ):
            parent = node.parent
            if parent is not None and parent.type not in {
                "property_declaration",
                "assignment",
            }:
                self._reflect_properties(
                    caller, None, provider=kind, qualified=qualified
                )
            return
        for index, argument in enumerate(arguments):
            value = argument.child_by_field_name("value")
            label = argument.child_by_field_name("name")
            if value is None or not (
                self.name(label) in {"reflecting", "describing"}
                or (indirect and label is None and index == 0)
                or (kind == "dump" and label is None and index == 0)
            ):
                continue
            owner = self._infer(value)
            declaration = self.types.get(owner)
            if owner in {"Any", "AnyObject"} or (
                declaration is not None
                and declaration.node.type == "protocol_declaration"
            ):
                owner = None
            self._reflect_properties(
                caller,
                owner,
                provider=kind,
                qualified=qualified,
                intrinsic=value.type in _LITERAL_TYPES,
            )

    def _reachable(self, *, reflection):
        reachable = set(self.roots)
        if reflection:
            reachable.update(self.reflection_roots)
        pending = deque(reachable)
        while pending:
            symbol = pending.popleft()
            targets = self.edges.get(symbol, set())
            if reflection:
                targets = targets | self.reflection_edges.get(symbol, set())
            self._work(1 + len(targets))
            for target in targets:
                if target not in reachable:
                    reachable.add(target)
                    pending.append(target)
        return reachable

    def _emit_definitions(self):
        base_reachable = self._reachable(reflection=False)
        reachable = self._reachable(reflection=True)
        label_counts = {}
        for owner, groups in self.members.items():
            for name, group in groups.items():
                counts = defaultdict(int)
                for symbol in group:
                    counts[symbol.labels] += 1
                label_counts[(owner, name)] = counts
        for symbol in self.symbols:
            group = self.members[symbol.owner][symbol.name]
            name = symbol.canonical
            if symbol.kind in {"function", "method"} and len(group) > 1:
                signature = "".join(label + ":" for label in symbol.labels)
                if label_counts[(symbol.owner, symbol.name)][symbol.labels] > 1:
                    signature = ",".join(
                        f"{label}:{kind or '?'}"
                        for label, kind in zip(symbol.labels, symbol.parameter_types)
                    )
                name += f"({signature})"
            definition = Definition(
                name, symbol.kind, self.file_path, symbol.node.start_point[0] + 1
            )
            definition.binding_name = symbol.name
            definition.references = int(symbol in reachable)
            definition.is_exported = not symbol.private
            definition.confidence_factors.append("Swift private source reachability")
            if symbol in reachable:
                definition.framework_signals.extend(
                    sorted(
                        (symbol.reasons | self.reflection_reasons[symbol])
                        or {"reachable source declaration"}
                    )
                )
            definition.suppression_lines.update(
                n.start_point[0] + 1
                for n in symbol.node.named_children
                if n.type == "modifiers"
            )
            symbol.definition = definition
            self.defs.append(definition)
            if symbol.kind == "class":
                self.classes[symbol.canonical] = definition
        properties = []
        for symbol in self.symbols:
            if self._stored_instance_property(symbol):
                properties.append(
                    {
                        "name": symbol.definition.name,
                        "line": symbol.definition.line,
                        "owner": symbol.owner,
                        "owner_reachable": self.types.get(symbol.owner) in reachable,
                        "base_reachable": symbol in base_reachable,
                        "base_signals": sorted(symbol.reasons)
                        if symbol in base_reachable
                        else [],
                        "core_signals": list(symbol.definition.framework_signals),
                    }
                )
        requests = [
            {
                "owner": owner,
                "owner_file": self.file_path if owner in self.types else None,
                "provider": provider,
                "qualified": qualified,
            }
            for caller, owner, provider, qualified in self._project_requests
            if caller is None or caller in reachable
        ]
        self.project_reflection_facts = {
            "proof_version": 2,
            "source_sha256": hashlib.sha256(self.source).hexdigest(),
            "properties": properties,
            "requests": requests,
            "types": [
                {"name": name, "private": symbol.private}
                for name, symbol in self.types.items()
            ],
        }


__all__ = ["SwiftCore", "SwiftScanError", "descendants"]
