"""Bounded namespace-member reads for the TS/JS module graph.

Only statically identified member reads narrow a namespace import. Passing the
namespace elsewhere, reflection, mutation and unknown computed keys keep its
whole export surface. Names are resolved lexically before crediting members.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from skylos.core.js_ast import node_text, string_literal_value

_FUNCTIONS = frozenset(
    {
        "function_declaration",
        "function_expression",
        "generator_function_declaration",
        "generator_function",
        "arrow_function",
        "method_definition",
    }
)
_BLOCKS = frozenset(
    {
        "statement_block",
        "catch_clause",
        "for_statement",
        "for_in_statement",
        "switch_body",
    }
)
_WRAPPERS = frozenset(
    {
        "parenthesized_expression",
        "as_expression",
        "satisfies_expression",
        "non_null_expression",
        "type_assertion",
    }
)
_MAX_NODES = 50_000


@dataclass(eq=False)
class _Scope:
    parent: _Scope | None
    function: bool = False
    bindings: dict[str, list[_Binding]] = field(default_factory=dict)


@dataclass(eq=False)
class _Binding:
    node: object
    scope: _Scope
    value: object | None = None
    constant: bool = False
    namespace: str | None = None


def _pattern_names(pattern):
    if pattern is None:
        return
    stack = [pattern]
    while stack:
        node = stack.pop()
        if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
            yield node
        elif node.type in {
            "pair_pattern",
            "assignment_pattern",
            "object_assignment_pattern",
        }:
            value = node.child_by_field_name("value") or node.child_by_field_name(
                "left"
            )
            if value is not None:
                stack.append(value)
        elif node.type in {"required_parameter", "optional_parameter"}:
            value = node.child_by_field_name("pattern")
            if value is not None:
                stack.append(value)
        elif node.type in {
            "formal_parameters",
            "array_pattern",
            "object_pattern",
            "rest_pattern",
        }:
            stack.extend(reversed(node.named_children))


def _unwrap(node):
    while node is not None and node.type in _WRAPPERS:
        node = next(
            (
                c
                for c in node.named_children
                if c.type
                not in {"type_identifier", "predefined_type", "type_arguments"}
            ),
            None,
        )
    return node


def namespace_member_reads(
    root,
    source: bytes,
    *,
    shadowed_properties: set[int] | None = None,
    local_value_reads: set[int] | None = None,
    include_named_imports: bool = False,
    member_paths: bool = False,
) -> dict[str, set[str | tuple[str, ...]] | None]:
    """Map namespace locals to read export names; ``None`` means opaque use.

    This is deliberately independent of security-flow facts: graph construction
    needs declaration identity even in functions that are not security routes.
    ``include_named_imports`` also records imported values that may resolve to
    namespace exports. ``member_paths`` returns tuples for their nested member
    demand; resolving a value's actual namespace provider belongs to the graph.
    """
    namespace_nodes = []
    nodes = []
    stack = [root]
    while stack:
        node = stack.pop()
        nodes.append(node)
        if node.type == "namespace_import":
            namespace_nodes.extend(
                c for c in node.named_children if c.type == "identifier"
            )
        elif include_named_imports and node.type == "import_clause":
            for child in node.named_children:
                if child.type == "identifier":
                    namespace_nodes.append(child)
                elif child.type == "named_imports":
                    namespace_nodes.extend(
                        spec.child_by_field_name("alias")
                        or spec.child_by_field_name("name")
                        for spec in child.named_children
                        if spec.type == "import_specifier"
                    )
        if len(nodes) > _MAX_NODES:
            return {node_text(source, n): None for n in namespace_nodes}
        stack.extend(reversed(node.named_children))
    if not namespace_nodes and local_value_reads is None:
        return {}
    result: dict[str, set[str | tuple[str, ...]] | None] = {
        node_text(source, n): set() for n in namespace_nodes
    }
    if root.has_error:
        return dict.fromkeys(result)
    unrelated_properties: dict[str, set[int]] = {}
    for node in nodes:
        # Tree-sitter preserves escaped identifier spelling, not its runtime
        # binding/member name. Decline narrowing without normalization.
        if node.type in {
            "identifier",
            "property_identifier",
            "type_identifier",
            "shorthand_property_identifier",
            "shorthand_property_identifier_pattern",
            "private_property_identifier",
            "statement_identifier",
        } and "\\" in node_text(source, node):
            return dict.fromkeys(result)
        # Direct eval can read lexical bindings absent from parsed references.
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if (
                function is not None
                and function.type == "identifier"
                and node_text(source, function) == "eval"
            ):
                return dict.fromkeys(result)

    scopes = {}
    module = _Scope(None, function=True)
    declarations = set()
    bindings = []

    def bind(scope, name_node, *, value=None, constant=False, namespace=None):
        if name_node is None:
            return
        name = node_text(source, name_node)
        binding = _Binding(name_node, scope, value, constant, namespace)
        scope.bindings.setdefault(name, []).append(binding)
        declarations.add(name_node.id)
        bindings.append(binding)

    stack = [(root, module)]
    while stack:
        node, outer = stack.pop()
        scope = outer
        if node.type in {
            "function_declaration",
            "generator_function_declaration",
            "class_declaration",
            "abstract_class_declaration",
            "enum_declaration",
        }:
            bind(outer, node.child_by_field_name("name"))
        if node.type in _FUNCTIONS:
            scope = _Scope(outer, function=True)
            if node.type in {"function_expression", "generator_function"}:
                bind(scope, node.child_by_field_name("name"))
            parameters = node.child_by_field_name(
                "parameters"
            ) or node.child_by_field_name("parameter")
            for name in _pattern_names(parameters):
                bind(scope, name)
        elif node.type in {"class", "class_declaration", "abstract_class_declaration"}:
            scope = _Scope(outer)
            if node.type == "class":
                bind(scope, node.child_by_field_name("name"))
        elif node is not root and node.type in _BLOCKS:
            # Body var declarations do not shadow parameter-default reads.
            function_body = bool(
                node.parent is not None
                and node.parent.type in _FUNCTIONS
                and node.parent.child_by_field_name("body") == node
            )
            scope = _Scope(outer, function=function_body)
            if node.type == "catch_clause":
                for name in _pattern_names(node.child_by_field_name("parameter")):
                    bind(scope, name)
        scopes[node.id] = scope
        if node.type == "variable_declarator":
            owner = scope
            parent = node.parent
            constant = bool(parent and any(c.type == "const" for c in parent.children))
            if parent is not None and parent.type == "variable_declaration":
                while owner.parent is not None and not owner.function:
                    owner = owner.parent
            pattern = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            for name in _pattern_names(pattern):
                bind(
                    owner,
                    name,
                    value=value if pattern.type == "identifier" else None,
                    constant=constant,
                )
        elif node.type == "for_in_statement":
            kind = node.child_by_field_name("kind")
            if kind is not None:
                owner = scope
                if kind.type == "var":
                    while owner.parent is not None and not owner.function:
                        owner = owner.parent
                for name in _pattern_names(node.child_by_field_name("left")):
                    bind(owner, name)
        elif node.type == "namespace_import":
            for name in node.named_children:
                if name.type == "identifier":
                    bind(scope, name, constant=True, namespace=node_text(source, name))
        elif node.type == "import_clause":
            for child in node.named_children:
                if child.type == "identifier":
                    bind(
                        scope,
                        child,
                        namespace=node_text(source, child)
                        if include_named_imports
                        else None,
                    )
                elif child.type == "named_imports":
                    for spec in child.named_children:
                        if spec.type == "import_specifier":
                            name = spec.child_by_field_name(
                                "alias"
                            ) or spec.child_by_field_name("name")
                            bind(
                                scope,
                                name,
                                namespace=node_text(source, name)
                                if include_named_imports
                                else None,
                            )
        stack.extend((child, scope) for child in reversed(node.named_children))

    def resolve(node):
        name = node_text(source, node)
        scope = scopes[node.id]
        while scope is not None:
            candidates = scope.bindings.get(name)
            if candidates:
                return candidates[0] if len(candidates) == 1 else None
            scope = scope.parent
        return None

    # Follow only stable, simple const aliases; mutable aliases are escapes.
    for _ in range(min(len(bindings), 32)):
        changed = False
        for binding in bindings:
            if binding.namespace is not None or not binding.constant:
                continue
            value = _unwrap(binding.value)
            if value is not None and value.type == "identifier":
                origin = resolve(value)
                if origin is not None and origin.namespace is not None:
                    binding.namespace = origin.namespace
                    changed = True
        if not changed:
            break

    for node in nodes:
        if (
            node.type not in {"identifier", "shorthand_property_identifier"}
            or node.id in declarations
        ):
            continue
        binding = resolve(node)
        if binding is None:
            name = node_text(source, node)
            if name in result:
                result[name] = None
            continue
        if binding.namespace is None:
            name = node_text(source, node)
            parent = node.parent
            value = _unwrap(binding.value)
            # Ordinary reads of a parameter or local value cannot read an
            # unrelated module function with the same spelling. Callable local
            # definitions still use the visitor's existing definition identity;
            # their initializer/reference sources are scanned separately.
            if (
                local_value_reads is not None
                and binding.scope.parent is not None
                and binding.node.parent is not None
                and binding.node.parent.type
                not in {
                    "function_declaration",
                    "generator_function_declaration",
                    "function_expression",
                    "generator_function",
                    "class",
                    "class_declaration",
                    "abstract_class_declaration",
                    "enum_declaration",
                }
                and (value is None or value.type not in _FUNCTIONS | {"class"})
            ):
                local_value_reads.add(node.id)
            # Type namespace lookup is distinct from a same-spelled value
            # parameter. Keep the imported namespace opaque in that case.
            if (
                name in result
                and parent is not None
                and parent.type == "nested_type_identifier"
            ):
                result[name] = None
            known_global = bool(
                value is not None
                and value.type == "identifier"
                and node_text(source, value)
                in {"window", "globalThis", "self", "global"}
            )
            if (
                not known_global
                and name in result
                and parent is not None
                and parent.type == "member_expression"
                and parent.child_by_field_name("object") == node
            ):
                property_node = parent.child_by_field_name("property")
                if property_node is not None:
                    unrelated_properties.setdefault(name, set()).add(property_node.id)
            continue
        namespace = binding.namespace
        members = result[namespace]
        if members is None:
            continue
        expression = node
        while expression.parent is not None and expression.parent.type in _WRAPPERS:
            expression = expression.parent
        parent = expression.parent
        member = None
        if (
            parent is not None
            and parent.type in {"member_expression", "subscript_expression"}
            and parent.child_by_field_name("object") == expression
        ):
            key = parent.child_by_field_name("property") or parent.child_by_field_name(
                "index"
            )
            if key is not None:
                member = (
                    node_text(source, key)
                    if key.type == "property_identifier"
                    else _plain_string(source, key)
                )
            owner = parent.parent
            if owner is not None and (
                (
                    owner.type
                    in {"assignment_expression", "augmented_assignment_expression"}
                    and owner.child_by_field_name("left") == parent
                )
                or owner.type == "update_expression"
                or (
                    owner.type == "unary_expression"
                    and any(c.type == "delete" for c in owner.children)
                )
            ):
                member = None
        elif (
            parent is not None
            and parent.type == "nested_type_identifier"
            and parent.child_by_field_name("module") == expression
        ):
            member = node_text(source, parent.child_by_field_name("name"))
        elif (
            parent is not None
            and parent.type == "variable_declarator"
            and parent.child_by_field_name("value") == expression
        ):
            pattern = parent.child_by_field_name("name")
            alias = resolve(pattern) if pattern.type == "identifier" else None
            if alias is not None and alias.namespace == namespace:
                continue
            if pattern.type == "object_pattern":
                keys = _destructured_keys(pattern, source)
                if keys is not None:
                    members.update(
                        (key,) for key in keys
                    ) if member_paths else members.update(keys)
                    continue
        # Named default declarations have their own identity in the graph;
        # leave that surface opaque until default-member mapping is proven.
        if member and member != "default":
            if member_paths:
                parts = [member]
                expression = parent
                while len(parts) < 32 and expression is not None:
                    while (
                        expression.parent is not None
                        and expression.parent.type in _WRAPPERS
                    ):
                        expression = expression.parent
                    outer = expression.parent
                    if (
                        outer is None
                        or outer.type
                        not in {"member_expression", "subscript_expression"}
                        or outer.child_by_field_name("object") != expression
                    ):
                        break
                    key = outer.child_by_field_name(
                        "property"
                    ) or outer.child_by_field_name("index")
                    value = (
                        node_text(source, key)
                        if key is not None and key.type == "property_identifier"
                        else _plain_string(source, key)
                    )
                    if not value:
                        break
                    owner = outer.parent
                    if owner is not None and (
                        (
                            owner.type
                            in {
                                "assignment_expression",
                                "augmented_assignment_expression",
                            }
                            and owner.child_by_field_name("left") == outer
                        )
                        or owner.type == "update_expression"
                        or (
                            owner.type == "unary_expression"
                            and any(child.type == "delete" for child in owner.children)
                        )
                    ):
                        break
                    parts.append(value)
                    expression = outer
                members.add(tuple(parts))
            else:
                members.add(member)
        else:
            result[namespace] = None
    if shadowed_properties is not None:
        for name, properties in unrelated_properties.items():
            if result[name] is not None:
                shadowed_properties.update(properties)
    return result


def _destructured_keys(pattern, source):
    keys = set()
    for child in pattern.named_children:
        if child.type == "comment":
            continue
        if child.type == "shorthand_property_identifier_pattern":
            keys.add(node_text(source, child))
        elif child.type in {"pair_pattern", "object_assignment_pattern"}:
            key = child.child_by_field_name("key") or child.child_by_field_name("left")
            if key is None:
                return None
            if key.type in {
                "property_identifier",
                "shorthand_property_identifier_pattern",
            }:
                keys.add(node_text(source, key))
            elif key.type == "string":
                value = _plain_string(source, key)
                if value is None:
                    return None
                keys.add(value)
            else:
                return None
        else:
            return None
    return None if "default" in keys else keys


def _plain_string(source, node):
    value = string_literal_value(source, node)
    # The grammar helper returns spelling, not JavaScript escape evaluation.
    return value if value is not None and "\\" not in value else None
