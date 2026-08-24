from __future__ import annotations

import re
from bisect import bisect_right
from pathlib import Path

from tree_sitter import Language

from .security_flow import FlowLimits, SecurityFlow, build_security_flow
from .type_safety import _is_generated_file

_TYPED_EXTENSIONS = frozenset({".ts", ".tsx", ".mts", ".cts"})
_TEST_SOURCE_SUFFIXES = (
    ".cy.cjs",
    ".cy.cts",
    ".cy.js",
    ".cy.jsx",
    ".cy.mjs",
    ".cy.mts",
    ".cy.ts",
    ".cy.tsx",
    ".e2e.cjs",
    ".e2e.cts",
    ".e2e.js",
    ".e2e.jsx",
    ".e2e.mjs",
    ".e2e.mts",
    ".e2e.ts",
    ".e2e.tsx",
    ".test.cjs",
    ".test.cts",
    ".test.js",
    ".test.jsx",
    ".test.mjs",
    ".test.mts",
    ".test.ts",
    ".test.tsx",
    ".spec.cjs",
    ".spec.cts",
    ".spec.js",
    ".spec.jsx",
    ".spec.mjs",
    ".spec.mts",
    ".spec.ts",
    ".spec.tsx",
)
_FUNCTION_NODES = frozenset(
    {
        "arrow_function",
        "function",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)
_TYPE_DECLARATIONS = frozenset(
    {
        "abstract_class_declaration",
        "ambient_declaration",
        "class_declaration",
        "enum_declaration",
        "function_declaration",
        "generator_function_declaration",
        "interface_declaration",
        "internal_module",
        "type_alias_declaration",
    }
)
_CLASS_DECLARATIONS = frozenset({"abstract_class_declaration", "class_declaration"})
_CLASS_MEMBERS = frozenset(
    {
        "abstract_method_signature",
        "method_definition",
        "method_signature",
        "public_field_definition",
    }
)
_VALUE_WRAPPERS = frozenset(
    {
        "as_expression",
        "non_null_expression",
        "parenthesized_expression",
        "satisfies_expression",
        "type_assertion",
    }
)
_DISCARD_WRAPPERS = _VALUE_WRAPPERS | frozenset({"await_expression"})
_ARRAY_FACTORY_METHODS = frozenset({"from", "of"})
_ARRAY_CHAIN_METHODS = frozenset(
    {
        "concat",
        "copyWithin",
        "fill",
        "filter",
        "flat",
        "flatMap",
        "map",
        "reverse",
        "slice",
        "sort",
        "splice",
        "toReversed",
        "toSorted",
        "toSpliced",
    }
)
_INTENTIONAL_EMPTY_CATCH_RE = re.compile(
    r"\b(?:best[- ]effort|circular references?|do nothing|expected|fallback|ignore(?:d)?|intentional(?:ly)?|no changes?|no[- ]?op|optional|skip(?:ped)?)\b",
    re.IGNORECASE,
)
_NOT_IMPLEMENTED_RE = re.compile(
    r"(?:\bnot[ _-]?implemented\b|\bunimplemented\b|\bimplement me\b|"
    r"^\s*todo\s*$|^\s*todo\s*[:\-]|"
    r"^\s*todo\s+(?:add|complete|finish|implement|replace|support|wire)\b)",
    re.IGNORECASE,
)
_ESLINT_DIRECTIVE_RE = re.compile(
    r"^/\*\s*eslint-(disable|enable)\b(.*?)\*/\s*$",
    re.IGNORECASE | re.DOTALL,
)


def scan_quality_signals(
    root_node,
    source: bytes,
    file_path: str,
    lang: Language | None,
    generated_file: bool | None = None,
) -> list[dict]:
    """Detect concrete JS/TS quality mistakes often seen in generated code."""
    if (
        root_node is None
        or lang is None
        or (
            _is_generated_file(file_path, source)
            if generated_file is None
            else generated_file
        )
    ):
        return []

    nodes: list = []
    comments: list = []
    async_candidates: list = []
    async_binding_scopes: dict[str, list[tuple[int, int]]] = {}
    root_scope = (root_node.start_byte, root_node.end_byte)
    stack = [(root_node, False, root_scope)]
    while stack:
        node, inside_recovery, declaring_scope = stack.pop()
        intersects_recovery = bool(
            inside_recovery
            or node.type == "ERROR"
            or getattr(node, "is_missing", False)
        )
        if not intersects_recovery and not bool(getattr(node, "has_error", False)):
            nodes.append(node)
            if node.type == "comment":
                comments.append(node)
            else:
                binding_name = _declared_async_binding_name(node, source)
                if binding_name is not None:
                    async_binding_scopes.setdefault(binding_name, []).append(
                        declaring_scope
                    )
                if _is_async_candidate(node, source):
                    async_candidates.append(node)

        child_scope = declaring_scope
        if node.type in _FUNCTION_NODES:
            body = node.child_by_field_name("body")
            if body is not None:
                child_scope = (body.start_byte, body.end_byte)
        stack.extend(
            (child, intersects_recovery, child_scope)
            for child in reversed(node.named_children)
        )

    findings: list[dict] = []
    findings.extend(_blanket_eslint_findings(root_node, comments, source, file_path))
    findings.extend(_unfinished_stub_findings(nodes, source, file_path))
    findings.extend(_empty_catch_findings(nodes, source, file_path))

    async_binding_index = _index_async_binding_scopes(async_binding_scopes)
    async_candidates = [
        candidate
        for candidate in async_candidates
        if _candidate_has_possible_async_callback(
            candidate, async_binding_index, source
        )
    ]
    if async_candidates and not bool(getattr(root_node, "has_error", False)):
        flow = build_security_flow(
            root_node,
            source,
            file_path,
            lang,
            FlowLimits(
                max_scopes=50_000,
                max_events_per_scope=50_000,
                max_bindings_per_scope=50_000,
                analyze_routes=False,
            ),
        )
        if flow.analysis_complete:
            findings.extend(
                _async_misuse_findings(
                    async_candidates,
                    source,
                    file_path,
                    flow,
                )
            )

    if Path(str(file_path)).suffix.lower() in _TYPED_EXTENSIONS and not bool(
        getattr(root_node, "has_error", False)
    ):
        findings.extend(_unsafe_export_findings(root_node, source, file_path))

    return sorted(findings, key=_finding_sort_key)


def _node_text(source: bytes, node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _is_async_candidate(node, source: bytes) -> bool:
    if node.type == "new_expression":
        constructor = node.child_by_field_name("constructor")
        return bool(
            constructor is not None
            and constructor.type == "identifier"
            and _node_text(source, constructor) == "Promise"
            and _first_async_executor_argument(node) is not None
        )
    if node.type != "call_expression":
        return False
    method = _member_call_parts(node, source)
    return bool(
        method is not None
        and method[1] in {"forEach", "map"}
        and (
            _first_async_argument(node) is not None
            or _first_callback_identifier(node) is not None
        )
    )


def _candidate_has_possible_async_callback(
    node,
    async_binding_index: dict[str, tuple[tuple[int, ...], tuple[int, ...]]],
    source: bytes,
) -> bool:
    if node.type == "new_expression" or _first_async_argument(node) is not None:
        return True
    identifier = _first_callback_identifier(node)
    if identifier is None:
        return False
    name = _node_text(source, identifier)
    index = async_binding_index.get(name)
    if index is None:
        return False
    starts, prefix_max_ends = index
    candidate = bisect_right(starts, node.start_byte) - 1
    return candidate >= 0 and prefix_max_ends[candidate] >= node.end_byte


def _index_async_binding_scopes(
    scopes_by_name: dict[str, list[tuple[int, int]]],
) -> dict[str, tuple[tuple[int, ...], tuple[int, ...]]]:
    """Build an interval index for the cheap named-callback prefilter."""
    result: dict[str, tuple[tuple[int, ...], tuple[int, ...]]] = {}
    for name, intervals in scopes_by_name.items():
        ordered = sorted(set(intervals))
        starts: list[int] = []
        prefix_max_ends: list[int] = []
        max_end = -1
        for start, end in ordered:
            starts.append(start)
            max_end = max(max_end, end)
            prefix_max_ends.append(max_end)
        result[name] = (tuple(starts), tuple(prefix_max_ends))
    return result


def _declared_async_binding_name(node, source: bytes) -> str | None:
    if node.type in {"function_declaration", "generator_function_declaration"}:
        value = node
        name = node.child_by_field_name("name")
    elif node.type == "variable_declarator":
        value = node.child_by_field_name("value")
        name = node.child_by_field_name("name")
        while value is not None and value.type in _VALUE_WRAPPERS:
            value = _wrapped_value(value)
    else:
        return None
    if (
        name is None
        or name.type != "identifier"
        or value is None
        or not _is_async_function(value)
    ):
        return None
    return _node_text(source, name)


def _first_async_argument(call) -> object | None:
    arguments = call.child_by_field_name("arguments")
    if arguments is None:
        return None
    first = next(
        (child for child in arguments.named_children if child.type != "comment"),
        None,
    )
    current = first
    while current is not None and current.type in _VALUE_WRAPPERS:
        current = _wrapped_value(current)
        if current is None:
            return None
    return current if current is not None and _is_async_function(current) else None


def _first_async_executor_argument(call) -> object | None:
    arguments = call.child_by_field_name("arguments")
    if arguments is None:
        return None
    current = next(
        (child for child in arguments.named_children if child.type != "comment"),
        None,
    )
    while current is not None and current.type in _VALUE_WRAPPERS:
        current = _wrapped_value(current)
    return (
        current
        if current is not None
        and current.type in _FUNCTION_NODES
        and any(child.type == "async" for child in current.children)
        else None
    )


def _first_callback_identifier(call) -> object | None:
    arguments = call.child_by_field_name("arguments")
    if arguments is None:
        return None
    first = next(
        (child for child in arguments.named_children if child.type != "comment"),
        None,
    )
    current = first
    while current is not None and current.type in _VALUE_WRAPPERS:
        current = _wrapped_value(current)
    return current if current is not None and current.type == "identifier" else None


def _wrapped_value(node) -> object | None:
    """Return the runtime expression inside a transparent TS wrapper."""
    candidates = [
        child
        for child in node.named_children
        if child.type != "comment"
        and child.type != "type_arguments"
        and not child.type.endswith("_type")
        and child.type not in {"predefined_type", "type_annotation", "type_identifier"}
    ]
    if not candidates:
        return None
    return candidates[-1] if node.type == "type_assertion" else candidates[0]


def _is_async_function(node) -> bool:
    return bool(
        node.type in _FUNCTION_NODES
        and "generator" not in node.type
        and not any(child.type == "*" for child in node.children)
        and any(child.type == "async" for child in node.children)
    )


def _async_misuse_findings(
    candidates: list,
    source: bytes,
    file_path: str,
    flow: SecurityFlow,
) -> list[dict]:
    findings: list[dict] = []
    for node in candidates:
        scope_id = flow.scope_for_node(node).id
        if node.type == "new_expression":
            if not flow.is_stable_global_path(
                ("Promise",),
                node.start_byte,
                scope_id,
                include_nested_writes=True,
            ):
                continue
            findings.append(
                _finding(
                    rule_id="SKY-Q405",
                    severity="HIGH",
                    message=(
                        "Promise executors must not be async; move async work outside "
                        "the constructor. An async-generator executor does not run its body."
                    ),
                    file_path=file_path,
                    node=node,
                    name="Promise",
                )
            )
            continue

        if not _has_proven_async_callback(node, flow, source, scope_id):
            continue
        parts = _member_call_parts(node, source)
        if parts is None:
            continue
        receiver, method = parts
        if not _is_proven_array_receiver(
            receiver,
            method,
            node.start_byte,
            scope_id,
            flow,
            source,
        ):
            continue
        if method == "forEach":
            findings.append(
                _finding(
                    rule_id="SKY-Q406",
                    severity="HIGH",
                    message=(
                        "Array.forEach does not await an async callback; use "
                        "for...of or await Promise.all(array.map(...))."
                    ),
                    file_path=file_path,
                    node=node,
                    name="forEach",
                )
            )
        elif method == "map" and _is_discarded_expression(node, source, flow):
            findings.append(
                _finding(
                    rule_id="SKY-Q407",
                    severity="HIGH",
                    message=(
                        "The promises returned by array.map(async ...) are "
                        "discarded; await Promise.all(...) or return the result."
                    ),
                    file_path=file_path,
                    node=node,
                    name="map",
                )
            )
    return findings


def _has_proven_async_callback(
    call, flow: SecurityFlow, source: bytes, scope_id: int
) -> bool:
    if _first_async_argument(call) is not None:
        return True
    identifier = _first_callback_identifier(call)
    if identifier is None:
        return False
    binding = flow.resolve_unique_binding_with_hoisted_functions(
        _node_text(source, identifier), call.start_byte, scope_id
    )
    if binding is None or binding.value_node is None:
        return False
    value = flow.unwrap(binding.value_node)
    if value is None or not _is_async_function(value):
        return False
    if _is_const_binding(binding):
        return flow.is_binding_value_stable(binding, call.start_byte, scope_id)
    return bool(
        value.type == "function_declaration"
        and flow.is_binding_value_stable(binding, call.start_byte, scope_id)
    )


def _member_call_parts(call, source: bytes) -> tuple[object, str] | None:
    function = call.child_by_field_name("function")
    if function is None or function.type not in {
        "member_expression",
        "subscript_expression",
    }:
        return None
    return _member_expression_parts(function, source)


def _member_expression_parts(member, source: bytes) -> tuple[object, str] | None:
    receiver = member.child_by_field_name("object")
    prop = member.child_by_field_name(
        "property" if member.type == "member_expression" else "index"
    )
    if receiver is None or prop is None:
        return None
    if prop.type in {"identifier", "property_identifier"}:
        return receiver, _node_text(source, prop)
    if prop.type == "string":
        text = _node_text(source, prop)
        if (
            len(text) >= 2
            and text[0] == text[-1]
            and text[0] in {"'", '"'}
            and "\\" not in text[1:-1]
        ):
            return receiver, text[1:-1]
    return None


def _is_proven_array_receiver(
    receiver,
    method: str,
    before_byte: int,
    scope_id: int,
    flow: SecurityFlow,
    source: bytes,
    *,
    depth: int = 0,
    seen_bindings: frozenset[tuple[int, str, int]] = frozenset(),
) -> bool:
    if depth > 12:
        return False
    current = flow.unwrap(receiver)
    if current is None:
        return False
    if not flow.is_stable_global_path(
        ("Array", "prototype", method),
        before_byte,
        scope_id,
        include_nested_writes=True,
    ):
        return False
    if current.type == "array":
        return True

    if current.type == "identifier":
        binding = flow.resolve_unique_binding(
            _node_text(source, current), before_byte, scope_id
        )
        if binding is None or binding.value_node is None:
            return False
        symbol_key = (
            binding.symbol.scope_id,
            binding.symbol.name,
            binding.symbol.decl_byte,
        )
        if symbol_key in seen_bindings or not _is_const_binding(binding):
            return False
        value = flow.unwrap(binding.value_node)
        if not flow.is_binding_member_stable(
            binding,
            method,
            before_byte,
            scope_id,
            include_nested_writes=True,
        ) and not (
            value is not None
            and value.type == "array"
            and flow.is_binding_member_unmodified_allowing_escape(
                binding,
                method,
                before_byte,
                scope_id,
                include_nested_writes=True,
            )
        ):
            return False
        # Proving aliases soundly requires tracking mutations through every name
        # that refers to the same object. SecurityFlow tracks binding mutations,
        # not object identity across aliases, so remain conservative here.
        if value is not None and value.type == "identifier":
            return False
        return _is_proven_array_receiver(
            binding.value_node,
            method,
            binding.symbol.decl_byte,
            binding.symbol.scope_id,
            flow,
            source,
            depth=depth + 1,
            seen_bindings=seen_bindings | {symbol_key},
        )

    if current.type == "new_expression":
        constructor = current.child_by_field_name("constructor")
        init_scope = flow.scope_for_node(current).id
        return bool(
            constructor is not None
            and constructor.type == "identifier"
            and _node_text(source, constructor) == "Array"
            and flow.is_stable_global_path(
                ("Array",),
                current.start_byte,
                init_scope,
                include_nested_writes=True,
            )
        )

    if current.type != "call_expression":
        return False
    path = flow.callee_path(current)
    init_scope = flow.scope_for_node(current).id
    if path == ("Array",):
        return flow.is_stable_global_path(
            ("Array",),
            current.start_byte,
            init_scope,
            include_nested_writes=True,
        )
    if len(path) == 2 and path[0] == "Array" and path[1] in _ARRAY_FACTORY_METHODS:
        return flow.is_stable_global_path(
            path,
            current.start_byte,
            init_scope,
            include_nested_writes=True,
        )

    chained = _member_call_parts(current, source)
    if chained is None or chained[1] not in _ARRAY_CHAIN_METHODS:
        return False
    return _is_proven_array_receiver(
        chained[0],
        chained[1],
        current.start_byte,
        init_scope,
        flow,
        source,
        depth=depth + 1,
        seen_bindings=seen_bindings,
    )


def _is_const_binding(binding) -> bool:
    declaration = binding.declaration_node
    parent = declaration.parent if declaration is not None else None
    return bool(
        parent is not None
        and parent.type == "lexical_declaration"
        and any(child.type == "const" for child in parent.children)
    )


def _is_discarded_expression(
    node,
    source: bytes,
    flow: SecurityFlow,
) -> bool:
    current = node
    for _ in range(64):
        parent = current.parent
        if parent is None:
            return False
        if parent.type in _DISCARD_WRAPPERS:
            current = parent
            continue
        if parent.type == "sequence_expression":
            expressions = [
                child for child in parent.named_children if child.type != "comment"
            ]
            if expressions and expressions[-1].id != current.id:
                return True
            current = parent
            continue
        if parent.type == "ternary_expression" or (
            parent.type == "binary_expression"
            and _expression_operator(parent, source) in {"&&", "||", "??"}
        ):
            current = parent
            continue
        if parent.type in {"member_expression", "subscript_expression"}:
            parts = _member_expression_parts(parent, source)
            if parts is None or parts[0].id != current.id:
                return False
            _, member = parts
            # Reading only the result length drops every promise immediately,
            # even when the numeric length is returned, assigned, or passed on.
            if member == "length":
                return True
            outer_call = parent.parent
            if (
                member == "filter"
                and outer_call is not None
                and outer_call.type == "call_expression"
                and outer_call.child_by_field_name("function") is not None
                and outer_call.child_by_field_name("function").id == parent.id
                and _is_boolean_filter_call(current, outer_call, source, flow)
            ):
                current = outer_call
                continue
            return False
        if parent.type == "expression_statement":
            return True
        if parent.type == "unary_expression":
            return _expression_operator(parent, source) == "void"
        return False
    return False


def _is_boolean_filter_call(
    receiver,
    call,
    source: bytes,
    flow: SecurityFlow,
) -> bool:
    arguments = call.child_by_field_name("arguments")
    values = (
        [child for child in arguments.named_children if child.type != "comment"]
        if arguments is not None
        else []
    )
    callback = flow.unwrap(values[0]) if len(values) == 1 else None
    if (
        callback is None
        or callback.type != "identifier"
        or _node_text(source, callback) != "Boolean"
    ):
        return False
    scope_id = flow.scope_for_node(call).id
    return bool(
        flow.is_stable_global_path(
            ("Boolean",),
            call.start_byte,
            scope_id,
            include_nested_writes=True,
        )
        and _is_proven_array_receiver(
            receiver,
            "filter",
            call.start_byte,
            scope_id,
            flow,
            source,
        )
    )


def _expression_operator(node, source: bytes) -> str | None:
    operator = next((child for child in node.children if not child.is_named), None)
    return _node_text(source, operator) if operator is not None else None


def _unfinished_stub_findings(nodes: list, source: bytes, file_path: str) -> list[dict]:
    if _is_test_source(file_path):
        return []
    findings: list[dict] = []
    for node in nodes:
        if node.type not in _FUNCTION_NODES:
            continue
        body = node.child_by_field_name("body")
        if body is None or body.type != "statement_block":
            continue
        statements = [
            child
            for child in body.named_children
            if child.type not in {"comment", "empty_statement"}
        ]
        while statements and _is_directive_prologue_statement(statements[0], source):
            statements.pop(0)
        if len(statements) != 1 or statements[0].type != "throw_statement":
            continue
        message = _static_thrown_message(statements[0], source)
        if message is None or _NOT_IMPLEMENTED_RE.search(message) is None:
            continue
        name = _function_name(node, source)
        findings.append(
            _finding(
                rule_id="SKY-L026",
                severity="MEDIUM",
                message=(
                    f"Function '{name}' is only a not-implemented stub; "
                    "implement it or remove it from the runtime surface."
                ),
                file_path=file_path,
                node=node,
                name=name,
            )
        )
    return findings


def _is_directive_prologue_statement(node, source: bytes) -> bool:
    if node.type != "expression_statement":
        return False
    value = next(
        (child for child in node.named_children if child.type != "comment"),
        None,
    )
    return value is not None and value.type == "string"


def _is_test_source(file_path: str) -> bool:
    path = Path(str(file_path).replace("\\", "/").lower())
    return bool(
        path.name.startswith("test_")
        or path.name.endswith(_TEST_SOURCE_SUFFIXES)
        or any(
            path.name.endswith(f".stories{extension}")
            for extension in (
                ".js",
                ".jsx",
                ".ts",
                ".tsx",
            )
        )
        or {
            "cypress",
            "e2e",
            "fixture",
            "fixtures",
            "mock",
            "mocks",
            "test",
            "tests",
            "__mocks__",
            "__tests__",
        }.intersection(path.parts)
    )


def _static_thrown_message(throw_node, source: bytes) -> str | None:
    expression = next(iter(throw_node.named_children), None)
    if expression is None:
        return None
    for _ in range(16):
        if expression.type != "parenthesized_expression":
            break
        values = [
            child for child in expression.named_children if child.type != "comment"
        ]
        if len(values) != 1:
            return None
        expression = values[0]
    if expression.type in {"new_expression", "call_expression"}:
        target = expression.child_by_field_name(
            "constructor"
        ) or expression.child_by_field_name("function")
        if target is None or target.type != "identifier":
            return None
        target_name = _node_text(source, target)
        if not target_name.endswith("Error"):
            return None
        arguments = expression.child_by_field_name("arguments")
        if arguments is None:
            return None
        expression = next(
            (child for child in arguments.named_children if child.type != "comment"),
            None,
        )
        if expression is None:
            return "Not implemented" if target_name == "NotImplementedError" else None
    if expression.type == "string":
        text = _node_text(source, expression)
        return text[1:-1] if len(text) >= 2 else ""
    if expression.type == "template_string" and not any(
        child.type == "template_substitution" for child in expression.named_children
    ):
        text = _node_text(source, expression)
        return text[1:-1] if len(text) >= 2 else ""
    return None


def _empty_catch_findings(nodes: list, source: bytes, file_path: str) -> list[dict]:
    if _is_test_source(file_path):
        return []
    findings: list[dict] = []
    for node in nodes:
        if node.type != "catch_clause":
            continue
        body = node.child_by_field_name("body")
        if body is None:
            continue
        statements = [
            child
            for child in body.named_children
            if child.type not in {"comment", "empty_statement"}
        ]
        if statements:
            continue
        comments = [
            _node_text(source, child)
            for child in body.named_children
            if child.type == "comment"
        ]
        if any(_documents_intentional_ignore(comment) for comment in comments):
            continue
        parameter = node.child_by_field_name("parameter")
        if (
            parameter is not None
            and parameter.type == "identifier"
            and _node_text(source, parameter).startswith("_")
        ):
            continue
        if _has_immediate_fallback_return(node):
            continue
        findings.append(
            _finding(
                rule_id="SKY-L007",
                severity="MEDIUM",
                message=(
                    "Empty catch block silently discards an error; handle it, "
                    "report it, or document why ignoring it is safe."
                ),
                file_path=file_path,
                node=node,
                name="catch",
            )
        )
    return findings


def _has_immediate_fallback_return(catch_clause) -> bool:
    try_statement = catch_clause.parent
    parent = try_statement.parent if try_statement is not None else None
    if try_statement is None or try_statement.type != "try_statement" or parent is None:
        return False
    siblings = [
        child
        for child in parent.named_children
        if child.type not in {"comment", "empty_statement"}
    ]
    for index, sibling in enumerate(siblings):
        if sibling.id != try_statement.id:
            continue
        return bool(
            index + 1 < len(siblings) and siblings[index + 1].type == "return_statement"
        )
    return False


def _documents_intentional_ignore(comment: str) -> bool:
    normalized = " ".join(comment.lower().replace("'", "").split())
    if any(
        phrase in normalized
        for phrase in (
            "cannot ignore",
            "do not ignore",
            "dont ignore",
            "must not ignore",
            "never ignore",
            "cannot skip",
            "do not skip",
            "dont skip",
            "must not skip",
            "never skip",
            "should not ignore",
            "should not skip",
            "not intentionally ignore",
            "not intentionally ignored",
        )
    ):
        return False
    if re.search(r"\b(?:todo|fixme|xxx)\b", normalized):
        return False
    return _INTENTIONAL_EMPTY_CATCH_RE.search(comment) is not None


def _blanket_eslint_findings(
    root_node, comments: list, source: bytes, file_path: str
) -> list[dict]:
    leading_ids: set[int] = set()
    for child in root_node.named_children:
        if child.type == "comment":
            leading_ids.add(child.id)
            continue
        if child.type == "hash_bang_line":
            continue
        break

    candidates = [
        comment
        for comment in comments
        if comment.id in leading_ids
        and _eslint_directive(_node_text(source, comment)) == ("disable", True)
    ]
    if not candidates:
        return []
    candidate = candidates[-1]
    if any(
        comment.start_byte > candidate.start_byte
        and _eslint_directive(_node_text(source, comment)) == ("enable", True)
        for comment in comments
    ):
        return []
    return [
        _finding(
            rule_id="SKY-L035",
            severity="HIGH",
            message=(
                "A bare file-wide eslint-disable turns off every ESLint rule; "
                "name only the required rule and keep the suppression narrow."
            ),
            file_path=file_path,
            node=candidate,
            name="eslint-disable",
        )
    ]


def _eslint_directive(comment_text: str) -> tuple[str, bool] | None:
    match = _ESLINT_DIRECTIVE_RE.match(comment_text.strip())
    if match is None:
        return None
    payload = match.group(2).split("--", 1)[0].strip()
    return match.group(1).lower(), not bool(payload)


_EXPORT_TYPE_ONLY_DECLARATIONS = frozenset(
    {"interface_declaration", "type_alias_declaration"}
)
_EXPORT_VALUE_ONLY_DECLARATIONS = frozenset(
    {
        "function_declaration",
        "function_signature",
        "generator_function_declaration",
        "lexical_declaration",
        "variable_declaration",
    }
)
_EXPORT_DUAL_DECLARATIONS = frozenset(
    {
        "abstract_class_declaration",
        "class_declaration",
        "enum_declaration",
        "internal_module",
        "module",
    }
)
_EXPORT_DECLARATIONS = (
    _EXPORT_TYPE_ONLY_DECLARATIONS
    | _EXPORT_VALUE_ONLY_DECLARATIONS
    | _EXPORT_DUAL_DECLARATIONS
    | frozenset({"ambient_declaration"})
)
_PUBLIC_CLASS_NODES = frozenset(
    {"abstract_class_declaration", "class", "class_declaration"}
)
_PUBLIC_FUNCTION_NODES = _FUNCTION_NODES | frozenset(
    {
        "abstract_method_signature",
        "call_signature",
        "construct_signature",
        "function_signature",
        "method_signature",
    }
)
_PUBLIC_CLASS_MEMBERS = _CLASS_MEMBERS | frozenset({"index_signature"})
_FUNCTION_TYPE_NODES = frozenset({"constructor_type", "function_type"})
_MAX_EXPORTED_ROOTS = 20_000
_MAX_PUBLIC_TYPE_NODES = 100_000
_MAX_RECORD_CONTEXT_NODES = 300_000
_MAX_MODULE_VALUE_CONTEXT_NODES = 300_000


def _unsafe_export_findings(root_node, source: bytes, file_path: str) -> list[dict]:
    lower_path = str(file_path).replace("\\", "/").lower()
    value_declarations = _value_declaration_index(root_node, source)
    exported = _exported_roots(
        root_node,
        source,
        force_external=lower_path.endswith((".mts", ".cts")),
        include_script_globals=lower_path.endswith(".d.ts"),
    )
    if not exported:
        return []
    module_value_reference_ids = _module_level_value_reference_ids(root_node)
    findings: list[dict] = []
    seen_targets: set[tuple[int, int, str]] = set()
    record_scope_cache: dict[int, bool] = {}
    record_parameter_cache: dict[int, bool] = {}
    record_resolution_cache: dict[int, bool] = {}
    processed_contracts: set[object] = set()
    destructured_contract_cache: dict[int, dict[str, object]] = {}
    declaration_file = lower_path.endswith((".d.ts", ".d.mts", ".d.cts"))
    for root, api_name, selector, export_namespace in exported:
        contract_key: object = (root.id, selector, export_namespace)
        if contract_key in processed_contracts:
            continue
        processed_contracts.add(contract_key)
        selected_contract = None
        if selector is not None:
            contracts = destructured_contract_cache.get(root.id)
            if contracts is None:
                contracts = _destructured_contracts(root, source)
                destructured_contract_cache[root.id] = contracts
            selected_contract = contracts.get(selector)
            if selected_contract is None:
                continue
        annotations = _public_type_annotations(
            root,
            source,
            api_name,
            selected_contract=selected_contract,
            declaration_file=declaration_file,
            destructured_contract_cache=destructured_contract_cache,
            type_only=export_namespace == "type",
            value_declarations=value_declarations,
            module_value_reference_ids=module_value_reference_ids,
        )
        for annotation, owner_name, index_signature in annotations:
            unsafe_kind, target = _unsafe_annotation_kind(
                annotation,
                source,
                root_node,
                record_scope_cache,
                record_parameter_cache,
                record_resolution_cache,
                index_signature=index_signature,
            )
            if unsafe_kind is None or target is None:
                continue
            key = (target.start_byte, target.end_byte, unsafe_kind)
            if key in seen_targets:
                continue
            seen_targets.add(key)
            findings.append(
                _finding(
                    rule_id="SKY-T106",
                    severity="MEDIUM",
                    message=(
                        f"Exported API '{owner_name}' uses {unsafe_kind}; "
                        "use a precise type or unknown with validation."
                    ),
                    file_path=file_path,
                    node=target,
                    name=owner_name,
                )
            )
    return findings


def _value_declaration_index(root_node, source: bytes) -> dict[str, list[object]]:
    declarations: dict[str, list[object]] = {}
    for statement in root_node.named_children:
        declaration = _declaration_from_statement(statement)
        if declaration is None:
            continue
        for name, node, namespaces in _declared_roots(declaration, source):
            if "value" not in namespaces:
                continue
            declarations.setdefault(name, []).append(node)
    return declarations


def _module_level_value_reference_ids(root_node) -> set[int]:
    eligible: set[int] = set()
    stack = [root_node]
    visited = 0
    boundaries = (
        _FUNCTION_NODES
        | _PUBLIC_CLASS_NODES
        | frozenset({"statement_block", "internal_module", "module"})
    )
    while stack and visited < _MAX_MODULE_VALUE_CONTEXT_NODES:
        current = stack.pop()
        visited += 1
        eligible.add(current.id)
        stack.extend(
            child
            for child in reversed(current.named_children)
            if child.type not in boundaries
        )
    return eligible


def _exported_roots(
    root_node,
    source: bytes,
    *,
    force_external: bool = False,
    include_script_globals: bool = False,
) -> list[tuple[object, str, str | None, str]]:
    declarations: dict[str, dict[str, list[tuple[object, str | None]]]] = {}
    for child in root_node.named_children:
        declaration = _declaration_from_statement(child)
        if declaration is None:
            continue
        for name, node, namespaces in _declared_roots(declaration, source):
            by_namespace = declarations.setdefault(name, {"type": [], "value": []})
            selector = _declaration_selector(node, name)
            for namespace in namespaces:
                by_namespace[namespace].append((node, selector))

    hidden_overload_implementations = {
        target.id
        for by_namespace in declarations.values()
        for targets in by_namespace.values()
        if any(target.type == "function_signature" for target, _ in targets)
        for target, _ in targets
        if target.type in {"function_declaration", "generator_function_declaration"}
        and target.child_by_field_name("body") is not None
    }

    pending: list[tuple[object, str, str | None, str]] = []
    external_scope = force_external or any(
        child.type in {"export_statement", "import_statement"}
        for child in root_node.named_children
    )
    if include_script_globals and not external_scope:
        for child in root_node.named_children:
            declaration = _declaration_from_statement(child)
            if declaration is None:
                continue
            _extend_export_roots(
                pending,
                (
                    (node, name, _declaration_selector(node, name), namespace)
                    for name, node, namespaces in _declared_roots(declaration, source)
                    for namespace in namespaces
                ),
            )
    for child in root_node.named_children:
        if child.type != "ambient_declaration":
            continue
        nested_modules = [
            nested
            for nested in child.named_children
            if nested.type == "module"
            or (nested.type == "internal_module" and not external_scope)
        ]
        for nested in nested_modules:
            name = nested.child_by_field_name("name")
            owner_name = (
                _node_text(source, name).strip("'\"") if name is not None else "module"
            )
            _extend_export_roots(pending, ((nested, owner_name, None, "value"),))
        if any(token.type == "global" for token in child.children):
            _extend_export_roots(pending, ((child, "global", None, "value"),))

    for child in root_node.named_children:
        if child.type != "export_statement":
            continue
        if child.child_by_field_name("source") is not None:
            continue

        declaration = _declaration_from_statement(child)
        if declaration is not None:
            declared = _declared_roots(declaration, source)
            if declared:
                _extend_export_roots(
                    pending,
                    (
                        (node, name, _declaration_selector(node, name), namespace)
                        for name, node, namespaces in declared
                        for namespace in namespaces
                    ),
                )
            else:
                _extend_export_roots(
                    pending, ((declaration, "default", None, "value"),)
                )
            continue

        value = child.child_by_field_name("value")
        if value is None and any(
            not token.is_named and token.type == "=" for token in child.children
        ):
            value = next(
                (
                    item
                    for item in child.named_children
                    if item.type not in {"export_clause", "string"}
                ),
                None,
            )
        if value is not None:
            assertion, preserved_value = _api_value_contract(value, source)
            if assertion is None and preserved_value.type == "identifier":
                name = _node_text(source, preserved_value)
                _extend_export_roots(
                    pending,
                    (
                        (target, name, selector, "value")
                        for target, selector in declarations.get(name, {}).get(
                            "value", []
                        )
                    ),
                )
            else:
                _extend_export_roots(pending, ((value, "default", None, "value"),))

        statement_type_only = any(
            not item.is_named and item.type == "type" for item in child.children
        )
        for specifier in _descendants_of_type(child, "export_specifier"):
            local = specifier.child_by_field_name("name")
            if local is None:
                continue
            name = _node_text(source, local)
            specifier_type_only = statement_type_only or any(
                not item.is_named and item.type == "type" for item in specifier.children
            )
            namespaces = ("type",) if specifier_type_only else ("type", "value")
            for namespace in namespaces:
                _extend_export_roots(
                    pending,
                    (
                        (target, name, selector, namespace)
                        for target, selector in declarations.get(name, {}).get(
                            namespace, []
                        )
                    ),
                )

    result: list[tuple[object, str, str | None, str]] = []
    seen: set[tuple[int, int, str, str | None, str]] = set()
    index = 0
    while index < len(pending) and len(result) < _MAX_EXPORTED_ROOTS:
        node, owner_name, selector, export_namespace = pending[index]
        index += 1
        if node.id in hidden_overload_implementations:
            continue
        key = (
            node.start_byte,
            node.end_byte,
            owner_name,
            selector,
            export_namespace,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append((node, owner_name, selector, export_namespace))

        alias = _const_alias_name(node, source)
        if alias is None:
            continue
        _extend_export_roots(
            pending,
            (
                (target, owner_name, target_selector, export_namespace)
                for target, target_selector in declarations.get(alias, {}).get(
                    export_namespace, []
                )
            ),
        )
    return result


def _extend_export_roots(
    pending: list[tuple[object, str, str | None, str]], roots
) -> None:
    for root in roots:
        if len(pending) >= _MAX_EXPORTED_ROOTS:
            return
        pending.append(root)


def _declaration_selector(node, declared_name: str) -> str | None:
    if node.type != "variable_declarator":
        return None
    pattern = node.child_by_field_name("name")
    if pattern is None or pattern.type == "identifier":
        return None
    return declared_name


def _const_alias_name(node, source: bytes) -> str | None:
    if node.type != "variable_declarator":
        return None
    name = node.child_by_field_name("name")
    if name is None or name.type != "identifier":
        return None
    if node.child_by_field_name("type") is not None:
        return None
    parent = node.parent
    if (
        parent is None
        or parent.type != "lexical_declaration"
        or not any(child.type == "const" for child in parent.children)
    ):
        return None
    value = node.child_by_field_name("value")
    if value is None:
        return None
    value = _unwrap_api_value(value, source)
    return _node_text(source, value) if value.type == "identifier" else None


def _declaration_from_statement(node):
    if node.type in _EXPORT_DECLARATIONS:
        return node
    if node.type != "export_statement":
        return None
    declaration = node.child_by_field_name("declaration")
    if declaration is not None:
        return declaration
    return next(
        (child for child in node.named_children if child.type in _EXPORT_DECLARATIONS),
        None,
    )


def _declared_roots(
    declaration, source: bytes
) -> list[tuple[str, object, frozenset[str]]]:
    if declaration.type == "ambient_declaration":
        nested = next(
            (
                child
                for child in declaration.named_children
                if child.type in _EXPORT_DECLARATIONS
                or child.type == "function_signature"
            ),
            None,
        )
        return _declared_roots(nested, source) if nested is not None else []
    if declaration.type in {"lexical_declaration", "variable_declaration"}:
        roots: list[tuple[str, object, frozenset[str]]] = []
        for declarator in declaration.named_children:
            if declarator.type != "variable_declarator":
                continue
            name = declarator.child_by_field_name("name")
            if name is None:
                continue
            for binding_name in _bound_pattern_names(name, source):
                roots.append((binding_name, declarator, frozenset({"value"})))
        return roots
    name = declaration.child_by_field_name("name")
    if name is None:
        return []
    if declaration.type in _EXPORT_TYPE_ONLY_DECLARATIONS:
        namespaces = frozenset({"type"})
    elif declaration.type in _EXPORT_DUAL_DECLARATIONS:
        namespaces = frozenset({"type", "value"})
    else:
        namespaces = frozenset({"value"})
    return [(_node_text(source, name), declaration, namespaces)]


def _bound_pattern_names(pattern, source: bytes) -> list[str]:
    names: list[str] = []
    stack = [pattern]
    while stack:
        current = stack.pop()
        if current.type in {"identifier", "shorthand_property_identifier_pattern"}:
            names.append(_node_text(source, current))
            continue
        if current.type == "pair_pattern":
            value = current.child_by_field_name("value")
            if value is not None:
                stack.append(value)
            continue
        if current.type in {"assignment_pattern", "object_assignment_pattern"}:
            left = current.child_by_field_name("left")
            if left is not None:
                stack.append(left)
            continue
        if current.type == "rest_pattern":
            target = next(iter(current.named_children), None)
            if target is not None:
                stack.append(target)
            continue
        if current.type in {"array_pattern", "object_pattern"}:
            stack.extend(reversed(current.named_children))
    return list(dict.fromkeys(names))


def _destructured_contracts(declarator, source: bytes) -> dict[str, object]:
    if declarator.type != "variable_declarator":
        return {}
    pattern = declarator.child_by_field_name("name")
    if pattern is None or pattern.type == "identifier":
        return {}
    contract = declarator.child_by_field_name("type")
    if contract is None:
        value = declarator.child_by_field_name("value")
        if value is None:
            return {}
        contract, _ = _api_value_contract(value, source)
    if contract is None:
        return {}
    return _map_pattern_contracts(pattern, contract, source)


def _map_pattern_contracts(pattern, contract, source: bytes) -> dict[str, object]:
    contracts: dict[str, object] = {}
    stack = [(pattern, contract)]
    while stack:
        current_pattern, current_contract = stack.pop()
        target = _type_annotation_target(current_contract)
        if target is None:
            continue
        if (
            target.type == "predefined_type" and _node_text(source, target) == "any"
        ) or _is_record_string_any(target, source):
            for name in _bound_pattern_names(current_pattern, source):
                contracts[name] = current_contract
            continue
        if current_pattern.type in {
            "identifier",
            "shorthand_property_identifier_pattern",
        }:
            contracts[_node_text(source, current_pattern)] = current_contract
            continue
        if current_pattern.type in {"assignment_pattern", "object_assignment_pattern"}:
            left = current_pattern.child_by_field_name("left")
            if left is not None:
                stack.append((left, current_contract))
            continue
        if current_pattern.type == "rest_pattern":
            continue
        if current_pattern.type == "object_pattern" and target.type == "object_type":
            members = {
                key: member.child_by_field_name("type") or member
                for member in target.named_children
                if member.type in {"method_signature", "property_signature"}
                and (key := _type_member_key(member, source)) is not None
            }
            for child_pattern, key in _object_pattern_entries(current_pattern, source):
                member_contract = members.get(key)
                if member_contract is not None:
                    stack.append((child_pattern, member_contract))
            continue
        if current_pattern.type == "array_pattern" and target.type == "tuple_type":
            elements = [
                child for child in target.named_children if child.type != "comment"
            ]
            for child_pattern, index in _array_pattern_entries(current_pattern):
                if index < len(elements):
                    stack.append((child_pattern, elements[index]))
    return contracts


def _type_annotation_target(node):
    current = _unwrap_public_type(node)
    if current is not None and current.type == "type_annotation":
        current = next(
            (child for child in current.named_children if child.type != "comment"),
            None,
        )
    return _unwrap_public_type(current)


def _object_pattern_entries(pattern, source: bytes) -> list[tuple[object, str]]:
    entries: list[tuple[object, str]] = []
    for member in pattern.named_children:
        if member.type == "shorthand_property_identifier_pattern":
            entries.append((member, _node_text(source, member)))
        elif member.type == "pair_pattern":
            key = _pattern_property_key(member.child_by_field_name("key"), source)
            value = member.child_by_field_name("value")
            if key is not None and value is not None:
                entries.append((value, key))
        elif member.type == "object_assignment_pattern":
            left = member.child_by_field_name("left")
            key = _pattern_property_key(left, source)
            if key is not None and left is not None:
                entries.append((left, key))
    return entries


def _array_pattern_entries(pattern) -> list[tuple[object, int]]:
    entries: list[tuple[object, int]] = []
    index = 0
    for child in pattern.children:
        if child.type == ",":
            index += 1
        elif child.is_named and child.type not in {"comment", "rest_pattern"}:
            entries.append((child, index))
    return entries


def _pattern_property_key(node, source: bytes) -> str | None:
    if node is None or node.type == "computed_property_name":
        return None
    return _node_text(source, node).strip("'\"")


def _type_member_key(node, source: bytes) -> str | None:
    name = node.child_by_field_name("name")
    if name is None or name.type == "computed_property_name":
        return None
    return _node_text(source, name).strip("'\"")


def _public_type_annotations(
    node,
    source: bytes,
    owner_name: str,
    *,
    selected_contract=None,
    declaration_file: bool = False,
    destructured_contract_cache: dict[int, dict[str, object]] | None = None,
    type_only: bool = False,
    value_declarations: dict[str, list[object]] | None = None,
    module_value_reference_ids: set[int] | None = None,
) -> list[tuple[object, str, bool]]:
    """Return exact public type slots without walking runtime implementation code."""
    found: list[tuple[object, str, bool]] = []
    stack: list[tuple[str, object, str]] = (
        [
            ("type", selected_contract, owner_name),
            ("exact_type", selected_contract, owner_name),
        ]
        if selected_contract is not None
        else [
            (
                (
                    "class_type"
                    if node.type in _PUBLIC_CLASS_NODES
                    else "module_type"
                    if node.type in {"internal_module", "module"}
                    else "api"
                )
                if type_only
                else "api",
                node,
                owner_name,
            )
        ]
    )
    contract_cache = (
        destructured_contract_cache if destructured_contract_cache is not None else {}
    )
    module_value_ids = (
        module_value_reference_ids if module_value_reference_ids is not None else set()
    )
    ambient_module_ids: set[int] = set()
    if node.type in {"internal_module", "module"} and (
        declaration_file or _inside_ambient_declaration(node)
    ):
        ambient_module_ids.add(node.id)
    visited: set[tuple[str, int]] = set()
    visited_count = 0

    while stack and visited_count < _MAX_PUBLIC_TYPE_NODES:
        mode, current, current_owner = stack.pop()
        key = (mode, current.id)
        if key in visited:
            continue
        visited.add(key)
        visited_count += 1

        if mode == "exact_type":
            found.append((current, current_owner, False))
            continue

        if mode == "index_type":
            found.append((current, current_owner, True))
            stack.extend(
                ("type", child, current_owner)
                for child in reversed(current.named_children)
                if child.type != "comment"
            )
            continue

        if mode == "type":
            if current.type == "index_signature":
                annotation = current.child_by_field_name("type")
                if annotation is not None:
                    stack.append(("index_type", annotation, current_owner))
                continue
            _push_type_parameter_defaults(stack, current, current_owner)
            if current.type in {"type_alias_declaration", "type_annotation"}:
                found.append((current, current_owner, False))
            elif current.type in _FUNCTION_TYPE_NODES:
                return_type = current.child_by_field_name("return_type")
                if return_type is not None and return_type.type != "type_annotation":
                    found.append((return_type, current_owner, False))
            if current.type == "tuple_type":
                for element in reversed(current.named_children):
                    contract = _tuple_element_contract(element)
                    if contract is not None:
                        stack.append(("exact_type", contract, current_owner))
            stack.extend(
                ("type", child, current_owner)
                for child in reversed(current.named_children)
                if child.type != "comment"
            )
            continue

        if current.type == "ambient_declaration":
            if any(child.type == "global" for child in current.children):
                body = next(
                    (
                        child
                        for child in current.named_children
                        if child.type == "statement_block"
                    ),
                    None,
                )
                if body is not None:
                    for statement in reversed(body.named_children):
                        declaration = _declaration_from_statement(statement)
                        if declaration is None:
                            continue
                        for name, nested, _ in reversed(
                            _declared_roots(declaration, source)
                        ):
                            nested_owner = f"{current_owner}.{name}"
                            selector = _declaration_selector(nested, name)
                            if selector is None:
                                stack.append(("api", nested, nested_owner))
                                if nested.type in {"internal_module", "module"}:
                                    ambient_module_ids.add(nested.id)
                                continue
                            contracts = contract_cache.get(nested.id)
                            if contracts is None:
                                contracts = _destructured_contracts(nested, source)
                                contract_cache[nested.id] = contracts
                            contract = contracts.get(selector)
                            if contract is not None:
                                _push_asserted_public_type(
                                    stack, contract, nested_owner
                                )
                continue
            stack.extend(
                ("api", child, current_owner)
                for child in reversed(current.named_children)
                if child.type in _EXPORT_DECLARATIONS
                or child.type == "function_signature"
            )
            continue

        if current.type in {"internal_module", "module"} or mode == "module_type":
            body = current.child_by_field_name("body")
            if body is None:
                continue
            ambient = declaration_file or current.id in ambient_module_ids
            nested_roots = (
                _all_declared_roots(body, source)
                if ambient
                else _exported_roots(body, source)
            )
            for nested, nested_name, selector, nested_namespace in reversed(
                nested_roots
            ):
                if mode == "module_type" and nested_namespace != "type":
                    continue
                nested_owner = f"{current_owner}.{nested_name}"
                if selector is not None:
                    contracts = contract_cache.get(nested.id)
                    if contracts is None:
                        contracts = _destructured_contracts(nested, source)
                        contract_cache[nested.id] = contracts
                    contract = contracts.get(selector)
                    if contract is not None:
                        _push_asserted_public_type(stack, contract, nested_owner)
                    continue
                stack.append(
                    (
                        (
                            "class_type"
                            if nested.type in _PUBLIC_CLASS_NODES
                            else "module_type"
                            if nested.type in {"internal_module", "module"}
                            else "api"
                        )
                        if nested_namespace == "type"
                        else "api",
                        nested,
                        nested_owner,
                    )
                )
                if ambient and nested.type in {"internal_module", "module"}:
                    ambient_module_ids.add(nested.id)
            continue

        if current.type == "variable_declarator":
            pattern = current.child_by_field_name("name")
            annotation = current.child_by_field_name("type")
            if pattern is not None and pattern.type != "identifier":
                continue
            if annotation is not None:
                stack.append(("type", annotation, current_owner))
                continue
            value = current.child_by_field_name("value")
            if value is not None:
                stack.append(("api", value, current_owner))
            continue

        if current.type in _PUBLIC_CLASS_NODES or mode in {"class", "class_type"}:
            _push_type_parameter_defaults(stack, current, current_owner)
            body = current.child_by_field_name("body")
            if body is None:
                continue
            hidden_implementations = _class_overload_implementation_ids(body, source)
            for member in reversed(body.named_children):
                if (
                    member.type not in _PUBLIC_CLASS_MEMBERS
                    or _skip_class_member(member, source)
                    or member.id in hidden_implementations
                ):
                    continue
                member_name = _public_member_name(member, source)
                if mode == "class_type":
                    if any(child.type == "static" for child in member.children):
                        continue
                    if member_name == "constructor":
                        _push_constructor_parameter_properties(
                            stack, member, current_owner, source
                        )
                        continue
                member_owner = f"{current_owner}.{member_name}"
                stack.append(("member", member, member_owner))
            continue

        if current.type in _PUBLIC_FUNCTION_NODES or mode == "function":
            _push_function_signature(stack, current, current_owner, source)
            continue

        if mode == "member":
            if current.type in _PUBLIC_FUNCTION_NODES:
                _push_function_signature(stack, current, current_owner, source)
                continue
            annotation = current.child_by_field_name("type")
            if annotation is not None:
                stack.append(
                    (
                        "index_type" if current.type == "index_signature" else "type",
                        annotation,
                        current_owner,
                    )
                )
                continue
            value = current.child_by_field_name("value")
            if value is not None:
                _push_public_api_value(stack, value, current_owner, source)
            if current.type == "index_signature":
                stack.append(("type", current, current_owner))
            continue

        if current.type == "object" or mode == "object":
            for member in reversed(current.named_children):
                if member.type == "method_definition":
                    child_owner = (
                        f"{current_owner}.{_public_member_name(member, source)}"
                    )
                    stack.append(("function", member, child_owner))
                    continue
                if member.type == "shorthand_property_identifier":
                    child_owner = f"{current_owner}.{_node_text(source, member)}"
                    stack.append(("api", member, child_owner))
                    continue
                if member.type != "pair":
                    continue
                value = member.child_by_field_name("value")
                if value is None:
                    continue
                child_owner = f"{current_owner}.{_public_member_name(member, source)}"
                stack.append(("api", value, child_owner))
            continue

        annotation, value = _api_value_contract(current, source)
        if annotation is not None:
            _push_asserted_public_type(stack, annotation, current_owner)
            continue
        if value is not current:
            stack.append(("api", value, current_owner))
            continue

        if current.type in {"identifier", "shorthand_property_identifier"}:
            declarations = value_declarations or {}
            name = _node_text(source, current)
            for target in reversed(
                _resolved_module_value_targets(
                    current,
                    name,
                    declarations,
                    module_value_ids,
                )
            ):
                stack.append(("api", target, current_owner))
            continue

        if current.type in _PUBLIC_FUNCTION_NODES:
            _push_function_signature(stack, current, current_owner, source)
            continue
        if current.type in _PUBLIC_CLASS_NODES:
            stack.append(("class", current, current_owner))
            continue
        if current.type == "type_alias_declaration":
            _push_type_parameter_defaults(stack, current, current_owner)
            stack.append(("type", current, current_owner))
            continue
        if current.type == "interface_declaration":
            _push_type_parameter_defaults(stack, current, current_owner)
            body = current.child_by_field_name("body")
            if body is not None:
                stack.append(("type", body, current_owner))
            continue

    return found


def _tuple_element_contract(node):
    current = _unwrap_public_type(node)
    if current is None:
        return None
    if current.type in {"required_parameter", "optional_parameter"}:
        annotation = current.child_by_field_name("type")
        return _type_annotation_target(annotation)
    if current.type == "optional_type":
        return next(
            (child for child in current.named_children if child.type != "comment"),
            None,
        )
    return current


def _resolved_module_value_targets(
    reference,
    name: str,
    declarations: dict[str, list[object]],
    module_value_reference_ids: set[int],
) -> list[object]:
    if reference.id not in module_value_reference_ids:
        return []
    targets = declarations.get(name, [])
    if len(targets) <= 1:
        return targets
    if not all(target.type in _PUBLIC_FUNCTION_NODES for target in targets):
        return []
    if not any(target.type == "function_signature" for target in targets):
        return []
    return [
        target
        for target in targets
        if not (
            target.type in {"function_declaration", "generator_function_declaration"}
            and target.child_by_field_name("body") is not None
        )
    ]


def _push_type_parameter_defaults(stack: list, node, owner_name: str) -> None:
    parameters = node.child_by_field_name("type_parameters")
    if parameters is None:
        return
    for parameter in reversed(parameters.named_children):
        if parameter.type != "type_parameter":
            continue
        default = parameter.child_by_field_name("value")
        if default is None:
            continue
        if default.type == "default_type":
            default = next(
                (child for child in default.named_children if child.type != "comment"),
                None,
            )
        if default is not None:
            _push_asserted_public_type(stack, default, owner_name)


def _push_parameter_contract(
    stack: list, parameter, owner_name: str, source: bytes
) -> None:
    annotation = parameter.child_by_field_name("type")
    if annotation is not None:
        stack.append(("type", annotation, owner_name))
        return
    default = parameter.child_by_field_name("value")
    if default is None:
        return
    inferred_annotation, _ = _api_value_contract(default, source)
    if inferred_annotation is not None:
        _push_asserted_public_type(stack, inferred_annotation, owner_name)


def _push_constructor_parameter_properties(
    stack: list, constructor, owner_name: str, source: bytes
) -> None:
    parameters = constructor.child_by_field_name("parameters")
    if parameters is None:
        return
    for parameter in reversed(parameters.named_children):
        accessibility = next(
            (
                _node_text(source, child)
                for child in parameter.children
                if child.type == "accessibility_modifier"
            ),
            None,
        )
        readonly = any(child.type == "readonly" for child in parameter.children)
        override = any(
            child.type == "override_modifier" for child in parameter.children
        )
        if accessibility in {"private", "protected"} or not (
            accessibility == "public" or readonly or override
        ):
            continue
        name = parameter.child_by_field_name("pattern")
        if name is None or name.type != "identifier":
            continue
        parameter_owner = f"{owner_name}.{_node_text(source, name)}"
        _push_parameter_contract(stack, parameter, parameter_owner, source)


def _push_function_signature(stack: list, node, owner_name: str, source: bytes) -> None:
    type_parameters = node.child_by_field_name("type_parameters")
    if type_parameters is not None:
        stack.append(("type", type_parameters, owner_name))
    _push_type_parameter_defaults(stack, node, owner_name)
    parameters = node.child_by_field_name("parameters")
    if parameters is not None:
        for parameter in reversed(parameters.named_children):
            _push_parameter_contract(stack, parameter, owner_name, source)
    return_type = node.child_by_field_name("return_type")
    if return_type is not None:
        stack.append(("type", return_type, owner_name))
        return
    inferred_return = _single_sync_return_value(node, source)
    if inferred_return is not None:
        _push_public_api_value(stack, inferred_return, owner_name, source)


def _single_sync_return_value(node, source: bytes):
    if "generator" in node.type or any(
        child.type in {"async", "*"} for child in node.children
    ):
        return None
    name = node.child_by_field_name("name")
    if name is not None and _node_text(source, name) == "constructor":
        return None
    body = node.child_by_field_name("body")
    if body is None:
        return None
    if body.type != "statement_block":
        return body
    statements = [
        child
        for child in body.named_children
        if child.type not in {"comment", "empty_statement"}
        and not _is_directive_prologue_statement(child, source)
    ]
    if len(statements) != 1 or statements[0].type != "return_statement":
        return None
    values = [
        child for child in statements[0].named_children if child.type != "comment"
    ]
    return values[0] if len(values) == 1 else None


def _push_public_api_value(stack: list, node, owner_name: str, source: bytes) -> None:
    annotation, value = _api_value_contract(node, source)
    if annotation is not None:
        _push_asserted_public_type(stack, annotation, owner_name)
    elif value.type in _PUBLIC_FUNCTION_NODES:
        stack.append(("function", value, owner_name))
    elif value.type in _PUBLIC_CLASS_NODES:
        stack.append(("class", value, owner_name))
    elif value.type == "object":
        stack.append(("object", value, owner_name))


def _push_asserted_public_type(stack: list, annotation, owner_name: str) -> None:
    stack.append(("type", annotation, owner_name))
    stack.append(("exact_type", annotation, owner_name))


def _api_value_contract(node, source: bytes):
    """Return an asserted public type or the expression whose type is preserved."""
    current = node
    saw_await = False
    for _ in range(16):
        named = [child for child in current.named_children if child.type != "comment"]
        if current.type in {"parenthesized_expression", "non_null_expression"}:
            if len(named) != 1:
                break
            current = named[0]
            continue
        if current.type == "await_expression":
            if len(named) != 1:
                break
            saw_await = True
            current = named[0]
            continue
        if current.type == "satisfies_expression":
            if len(named) < 2:
                break
            current = named[0]
            continue
        if current.type == "as_expression":
            if len(named) == 1:  # `as const` preserves the expression's shape.
                current = named[0]
                continue
            if len(named) >= 2:
                annotation = named[-1]
                if saw_await and not _await_preserves_checked_contract(
                    annotation, source
                ):
                    return None, node
                return annotation, current
            break
        if current.type == "type_assertion":
            if len(named) < 2:
                break
            assertion = named[0]
            if assertion.named_child_count == 0:  # `<const>` assertion.
                current = named[-1]
                continue
            asserted_types = [
                child for child in assertion.named_children if child.type != "comment"
            ]
            annotation = asserted_types[0] if len(asserted_types) == 1 else assertion
            if saw_await and not _await_preserves_checked_contract(annotation, source):
                return None, node
            return annotation, current
        break
    return None, node if saw_await else current


def _await_preserves_checked_contract(annotation, source: bytes) -> bool:
    return annotation.type == "predefined_type" or _is_record_string_any(
        annotation, source
    )


def _unwrap_api_value(node, source: bytes):
    annotation, value = _api_value_contract(node, source)
    return node if annotation is not None else value


def _class_overload_implementation_ids(body, source: bytes) -> set[int]:
    signatures: set[tuple[str, bool]] = set()
    implementations: list[tuple[tuple[str, bool], object]] = []
    for member in body.named_children:
        if member.type not in {"method_signature", "method_definition"}:
            continue
        name = member.child_by_field_name("name")
        if name is None:
            continue
        member_key = (
            "<computed>"
            if name.type == "computed_property_name"
            else _node_text(source, name)
        )
        key = (member_key, any(child.type == "static" for child in member.children))
        if member.type == "method_signature":
            signatures.add(key)
        elif member.child_by_field_name("body") is not None:
            implementations.append((key, member))
    return {member.id for key, member in implementations if key in signatures}


def _inside_ambient_declaration(node) -> bool:
    current = node.parent
    while current is not None:
        if current.type == "ambient_declaration":
            return True
        current = current.parent
    return False


def _all_declared_roots(
    root_node, source: bytes
) -> list[tuple[object, str, str | None, str]]:
    roots: list[tuple[object, str, str | None, str]] = []
    seen: set[tuple[int, str, str | None, str]] = set()
    for statement in root_node.named_children:
        declaration = _declaration_from_statement(statement)
        if declaration is None:
            continue
        for name, node, namespaces in _declared_roots(declaration, source):
            selector = _declaration_selector(node, name)
            for namespace in namespaces:
                key = (node.id, name, selector, namespace)
                if key in seen:
                    continue
                seen.add(key)
                roots.append((node, name, selector, namespace))
    return roots


def _public_member_name(node, source: bytes) -> str:
    name = node.child_by_field_name("name") or node.child_by_field_name("key")
    if name is None or name.type == "computed_property_name":
        return "member"
    return _node_text(source, name)


def _skip_class_member(node, source: bytes) -> bool:
    name = node.child_by_field_name("name")
    if name is not None and name.type == "private_property_identifier":
        return True
    for child in node.children:
        if child.type == "override_modifier":
            return True
        if child.type == "accessibility_modifier" and _node_text(source, child) in {
            "private",
            "protected",
        }:
            return True
    return False


def _unsafe_annotation_kind(
    annotation,
    source: bytes,
    root_node,
    record_scope_cache: dict[int, bool],
    record_parameter_cache: dict[int, bool],
    record_resolution_cache: dict[int, bool],
    *,
    index_signature: bool = False,
) -> tuple[str | None, object | None]:
    if annotation.type == "type_alias_declaration":
        target = annotation.child_by_field_name("value")
    elif annotation.type == "type_annotation":
        target = next(
            (child for child in annotation.named_children if child.type != "comment"),
            None,
        )
    else:
        target = annotation
    target = _unwrap_public_type(target)
    if target is None:
        return None, None

    if target.type == "predefined_type" and _node_text(source, target) == "any":
        if index_signature:
            return "an any-valued index signature", target
        return "the exact type 'any'", target

    if not _is_record_string_any(target, source):
        return None, None
    if not _record_reference_is_builtin(
        target,
        root_node,
        source,
        record_scope_cache,
        record_parameter_cache,
        record_resolution_cache,
    ):
        return None, None
    return "'Record<string, any>'", target


def _unwrap_public_type(node):
    current = node
    for _ in range(32):
        if current is None or current.type != "parenthesized_type":
            break
        named = [child for child in current.named_children if child.type != "comment"]
        if len(named) != 1:
            break
        current = named[0]
    return current


def _is_record_string_any(node, source: bytes) -> bool:
    if node.type != "generic_type":
        return False
    name = node.child_by_field_name("name")
    arguments = node.child_by_field_name("type_arguments")
    if (
        name is None
        or name.type != "type_identifier"
        or _node_text(source, name) != "Record"
        or arguments is None
    ):
        return False
    values = [child for child in arguments.named_children if child.type != "comment"]
    return bool(
        len(values) == 2
        and values[0].type == "predefined_type"
        and _node_text(source, values[0]) == "string"
        and values[1].type == "predefined_type"
        and _node_text(source, values[1]) == "any"
    )


def _record_reference_is_builtin(
    node,
    root_node,
    source: bytes,
    scope_cache: dict[int, bool],
    parameter_cache: dict[int, bool],
    resolution_cache: dict[int, bool],
) -> bool:
    if root_node.id not in resolution_cache:
        _build_record_resolution_cache(
            root_node,
            source,
            scope_cache,
            parameter_cache,
            resolution_cache,
        )
    return resolution_cache.get(node.id, False)


def _build_record_resolution_cache(
    root_node,
    source: bytes,
    scope_cache: dict[int, bool],
    parameter_cache: dict[int, bool],
    resolution_cache: dict[int, bool],
) -> None:
    stack = [(root_node, True)]
    visited = 0
    while stack and visited < _MAX_RECORD_CONTEXT_NODES:
        current, inherited_builtin = stack.pop()
        visited += 1
        shadows_record = _node_has_record_type_parameter(
            current, source, parameter_cache
        ) or (
            current.type in {"program", "statement_block"}
            and _scope_shadows_record(current, source, scope_cache)
        )
        builtin = inherited_builtin and not shadows_record
        resolution_cache[current.id] = builtin
        stack.extend((child, builtin) for child in reversed(current.named_children))


def _node_has_record_type_parameter(
    node, source: bytes, cache: dict[int, bool]
) -> bool:
    cached = cache.get(node.id)
    if cached is not None:
        return cached
    if node.type == "infer_type":
        name = node.child_by_field_name("name")
        result = bool(name is not None and _node_text(source, name) == "Record")
        cache[node.id] = result
        return result
    parameters = node.child_by_field_name("type_parameters")
    result = False
    if parameters is not None:
        for parameter in parameters.named_children:
            if parameter.type != "type_parameter":
                continue
            name = parameter.child_by_field_name("name")
            if name is not None and _node_text(source, name) == "Record":
                result = True
                break
    cache[node.id] = result
    return result


def _scope_shadows_record(node, source: bytes, cache: dict[int, bool]) -> bool:
    cached = cache.get(node.id)
    if cached is not None:
        return cached
    result = False
    for statement in node.named_children:
        if statement.type == "import_statement" and _import_binds_record(
            statement, source
        ):
            result = True
            break
        if statement.type == "import_alias":
            local = next(iter(statement.named_children), None)
            if local is not None and _node_text(source, local) == "Record":
                result = True
                break
        declaration = _declaration_from_statement(statement)
        if declaration is None:
            continue
        if any(
            name == "Record" and "type" in namespaces
            for name, _, namespaces in _declared_roots(declaration, source)
        ):
            result = True
            break
    cache[node.id] = result
    return result


def _import_binds_record(node, source: bytes) -> bool:
    stack = list(reversed(node.named_children))
    while stack:
        current = stack.pop()
        if current.type == "import_specifier":
            local = current.child_by_field_name("alias") or current.child_by_field_name(
                "name"
            )
            if local is not None and _node_text(source, local) == "Record":
                return True
            continue
        if current.type in {"namespace_import", "import_require_clause"}:
            local = next(
                (
                    child
                    for child in current.named_children
                    if child.type == "identifier"
                ),
                None,
            )
            if local is not None and _node_text(source, local) == "Record":
                return True
            continue
        if current.type == "import_clause":
            default_import = next(
                (
                    child
                    for child in current.named_children
                    if child.type == "identifier"
                ),
                None,
            )
            if (
                default_import is not None
                and _node_text(source, default_import) == "Record"
            ):
                return True
        stack.extend(reversed(current.named_children))
    return False


def _descendants_of_type(node, node_type: str) -> list:
    found: list = []
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == node_type:
            found.append(current)
        stack.extend(reversed(current.named_children))
    return found


def _function_name(node, source: bytes) -> str:
    name = node.child_by_field_name("name")
    if name is not None:
        return _node_text(source, name)
    parent = node.parent
    if parent is not None and parent.type == "variable_declarator":
        name = parent.child_by_field_name("name")
        if name is not None:
            return _node_text(source, name)
    return "anonymous"


def _finding(
    *,
    rule_id: str,
    severity: str,
    message: str,
    file_path: str,
    node,
    name: str,
) -> dict:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "message": message,
        "file": str(file_path),
        "line": node.start_point[0] + 1,
        "col": node.start_point[1],
        "name": name,
        "simple_name": name,
    }


def _finding_sort_key(finding: dict) -> tuple[int, int, str]:
    return (
        int(finding.get("line", 0)),
        int(finding.get("col", 0)),
        str(finding.get("rule_id", "")),
    )
