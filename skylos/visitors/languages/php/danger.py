from __future__ import annotations

import re
from pathlib import Path

from skylos.rules.danger.danger_web.html_context import (
    ATTR_SAFE,
    TEXT_SAFE,
    hole_requirements,
)

_SUPERGLOBALS = {
    "$_GET",
    "$_POST",
    "$_REQUEST",
    "$_COOKIE",
    "$_FILES",
}

_FILE_SINKS = {
    "file_get_contents",
    "file_put_contents",
    "fopen",
    "readfile",
    "unlink",
    "file",
    "copy",
    "rename",
    "mkdir",
    "rmdir",
    "chmod",
}
_NUMERIC_SANITIZERS = {"intval", "floatval"}
# Drupal: Symfony request bags, Form API input, and the static escapers.
_REQUEST_BAGS = {"query", "request", "cookies"}
_FORM_STATE_GETTERS = {"getValue", "getValues"}
_HTML_CLASS = "drupal\\component\\utility\\html"
_XSS_CLASS = "drupal\\component\\utility\\xss"
# Xss::filterAdmin() uses this documented HTML-body tag list. A literal
# subset passed to the same filter is no less restrictive than filterAdmin.
_XSS_BODY_TAGS = frozenset(
    "a abbr acronym address article aside b bdi bdo big blockquote br caption "
    "cite code col colgroup command dd del details dfn div dl dt em figcaption "
    "figure footer h1 h2 h3 h4 h5 h6 header hgroup hr i img ins kbd li mark menu "
    "meter nav ol output p pre progress q rp rt ruby s samp section small span "
    "strong sub summary sup table tbody td tfoot th thead time tr tt u ul var wbr".split()
)
_SQL_SINKS = {"query", "queryRange", "where"}
_SQL_FUNCTION_SINKS = {"db_query", "db_query_range"}
_MARKUP_CLASSES = {
    "drupal\\core\\render\\markup",
    "drupal\\views\\render\\viewsrenderpipelinemarkup",
}
_CONVENTIONAL_CLASSES = {
    "html": _HTML_CLASS,
    "xss": _XSS_CLASS,
    "markup": "drupal\\core\\render\\markup",
    "viewsrenderpipelinemarkup": "drupal\\views\\render\\viewsrenderpipelinemarkup",
}
_TAINT_CONTEXTS = {"path", "sql", "template", "deserialize", "html", "attribute", "raw"}
_FILTER_INPUT_SOURCES = {
    "INPUT_GET",
    "INPUT_POST",
    "INPUT_REQUEST",
    "INPUT_COOKIE",
    "INPUT_SERVER",
}
_DOUBLE_QUOTED_ESCAPES = re.compile(
    r"\\(?:[nrtvef\\$\"]|[0-7]{1,3}|x[0-9a-fA-F]{1,2}|u\{[0-9a-fA-F]+\})"
)


def _php_literal_text(value: str, *, double_quoted: bool) -> str:
    if not double_quoted:
        return re.sub(r"\\([\\'])", r"\1", value)
    replacements = {
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "e": "\x1b",
        "f": "\f",
        "\\": "\\",
        "$": "$",
        '"': '"',
    }

    def replace(match):
        escape = match[0][1:]
        if escape in replacements:
            return replacements[escape]
        if escape.startswith("x"):
            return chr(int(escape[1:], 16))
        if escape.startswith("u{"):
            codepoint = int(escape[2:-1], 16)
            if codepoint <= 0x10FFFF:
                return chr(codepoint)
            return match[0]
        return chr(int(escape, 8) & 0xFF)

    return _DOUBLE_QUOTED_ESCAPES.sub(replace, value)


def scan_danger(root_node, file_path: str, source: bytes) -> list[dict]:
    if root_node is None:
        return []

    findings: list[dict] = []

    def text(node) -> str:
        return source[node.start_byte : node.end_byte].decode("utf-8", "ignore")

    def child_by_type(node, type_name: str):
        for child in node.children:
            if child.type == type_name:
                return child
        return None

    def is_superglobal_var(node) -> bool:
        return (
            node is not None
            and node.type == "variable_name"
            and text(node).strip() in _SUPERGLOBALS
        )

    def is_filter_input_source(node) -> bool:
        if node is None or node.type != "function_call_expression":
            return False
        call_name = functions.get(node.start_byte, "")
        if call_name != "filter_input":
            return False
        args = child_by_type(node, "arguments")
        return args is not None and any(
            text(child).strip() in _FILTER_INPUT_SOURCES for child in args.children
        )

    def field_text(node, field: str) -> str:
        child = node.child_by_field_name(field)
        if child is None:
            return ""
        return text(child).strip().lstrip("\\")

    static_classes: dict[int, str] = {}
    functions: dict[int, str] = {}
    catch_all_handlers: set[int] = set()

    def index_namespace(nodes, namespace: str) -> None:
        aliases = {}
        declared = set()
        declared_functions = set()

        def declarations(node):
            if node.type in {
                "class_declaration",
                "interface_declaration",
                "trait_declaration",
                "enum_declaration",
            }:
                declared.add(field_text(node, "name").casefold())
            if node.type == "function_definition":
                declared_functions.add(field_text(node, "name").casefold())
            for child in node.named_children:
                declarations(child)

        for node in nodes:
            declarations(node)
            if node.type != "namespace_use_declaration":
                continue
            group = child_by_type(node, "namespace_use_group")
            prefix = None
            if group is not None:
                prefix = child_by_type(node, "namespace_name")
            clauses = (group or node).named_children
            for clause in clauses:
                if (
                    clause.type != "namespace_use_clause"
                    or text(clause).startswith("const ")
                    or text(node).startswith("use const ")
                ):
                    continue
                if text(clause).startswith("function ") or text(node).startswith(
                    "use function "
                ):
                    kind = "function"
                else:
                    kind = "class"
                names = clause.named_children
                if not names:
                    continue
                target = text(names[0]).lstrip("\\")
                if prefix is not None:
                    target = text(prefix) + "\\" + target
                if len(names) > 1:
                    alias = text(names[-1])
                else:
                    alias = target.rpartition("\\")[2]
                aliases[kind, alias.casefold()] = target.casefold()

        def visit(node):
            if node.type == "scoped_call_expression":
                scope = node.child_by_field_name("scope")
                value = ""
                if scope is not None:
                    value = text(scope).strip()
                parts = value.lstrip("\\").split("\\")
                first = parts[0].casefold()
                if value.startswith("\\"):
                    resolved = value.lstrip("\\").casefold()
                elif first == "namespace":
                    resolved = (
                        "\\".join([namespace, *parts[1:]]).casefold().lstrip("\\")
                    )
                elif ("class", first) in aliases:
                    resolved = "\\".join(
                        [aliases["class", first], *parts[1:]]
                    ).casefold()
                elif not namespace and len(parts) == 1 and first not in declared:
                    # Retain the existing bare Drupal spellings, but never an
                    # explicit local declaration or a different imported class.
                    resolved = _CONVENTIONAL_CLASSES.get(first, first)
                else:
                    resolved = "\\".join(filter(None, [namespace, value])).casefold()
                static_classes[node.start_byte] = resolved
            elif node.type == "function_call_expression":
                function = node.child_by_field_name("function")
                value = ""
                if function is not None:
                    value = text(function).strip()
                parts = value.lstrip("\\").split("\\")
                first = parts[0].casefold()
                if value.startswith("\\"):
                    resolved = value.lstrip("\\").casefold()
                elif first == "namespace":
                    resolved = (
                        "\\".join([namespace, *parts[1:]]).casefold().lstrip("\\")
                    )
                elif len(parts) == 1 and ("function", first) in aliases:
                    resolved = aliases["function", first]
                elif len(parts) > 1:
                    prefix = aliases.get(
                        ("class", first), "\\".join(filter(None, [namespace, parts[0]]))
                    )
                    resolved = "\\".join([prefix, *parts[1:]]).casefold()
                elif first in declared_functions:
                    resolved = "\\".join(filter(None, [namespace, first])).casefold()
                    # A global local declaration cannot be a PHP builtin.
                    if not namespace:
                        resolved = "<local>\\" + resolved
                else:
                    # PHP falls back to global functions for an unqualified
                    # name without a namespace-local definition or import.
                    resolved = first
                functions[node.start_byte] = resolved
            elif node.type == "catch_clause":
                types = node.child_by_field_name("type")
                if types is not None:
                    for type_node in types.named_children:
                        value = text(type_node).strip()
                        canonical = value.lstrip("\\").casefold()
                        if value.startswith("\\") and canonical == "throwable":
                            catch_all_handlers.add(node.start_byte)
                        elif aliases.get(("class", canonical)) == "throwable":
                            catch_all_handlers.add(node.start_byte)
                        elif (
                            not namespace
                            and canonical == "throwable"
                            and canonical not in declared
                        ):
                            catch_all_handlers.add(node.start_byte)
            for child in node.named_children:
                visit(child)

        for node in nodes:
            visit(node)

    def index_scopes(node) -> None:
        namespace = ""
        pending = []
        for child in node.named_children:
            if child.type != "namespace_definition":
                pending.append(child)
                continue
            index_namespace(pending, namespace)
            pending = []
            name = child_by_type(child, "namespace_name")
            namespace = ""
            if name is not None:
                namespace = text(name)
            body = child.child_by_field_name("body")
            if body is not None:
                index_namespace(body.named_children, namespace)
                namespace = ""
        index_namespace(pending, namespace)

    index_scopes(root_node)

    def static_call(node) -> tuple[str, str]:
        return (
            static_classes.get(node.start_byte, ""),
            field_text(node, "name").casefold(),
        )

    def is_drupal_source(node) -> bool:
        if node.type != "member_call_expression":
            return False
        method = field_text(node, "name")
        target = node.child_by_field_name("object")
        if method == "getUserInput":
            return True
        if method in _FORM_STATE_GETTERS:
            return target is not None and text(target).strip() == "$form_state"
        return (
            method in {"get", "all"}
            and target is not None
            and target.type == "member_access_expression"
            and field_text(target, "name") in _REQUEST_BAGS
        )

    def has_safe_xss_tags(node) -> bool:
        args = node.child_by_field_name("arguments")
        if args is None or len(args.named_children) == 1:
            return True
        if len(args.named_children) != 2:
            return False
        tag_argument = args.named_children[1]
        if len(tag_argument.named_children) != 1:
            return False
        tags = tag_argument.named_children[0]
        if tags.type == "null":
            return True
        if tags.type != "array_creation_expression":
            return False
        for element in tags.named_children:
            if (
                element.type != "array_element_initializer"
                or len(element.named_children) != 1
            ):
                return False
            value = element.named_children[0]
            if value.type not in {"string", "encapsed_string"}:
                return False
            if any(
                child.type not in {"string_content", "escape_sequence"}
                for child in value.named_children
            ):
                return False
            literal = text(value)
            tag = _php_literal_text(literal[1:-1], double_quoted=literal[:1] == '"')
            if tag not in _XSS_BODY_TAGS:
                return False
        return True

    def is_tainted_expr(node, tainted_vars: dict[str, set[str]], context: str) -> bool:
        if node is None:
            return False
        if is_filter_input_source(node) or is_drupal_source(node):
            return True
        if node.type == "cast_expression":
            cast = child_by_type(node, "cast_type")
            if cast is not None and text(cast).strip() in {"int", "integer", "float"}:
                return False
        if node.type == "scoped_call_expression":
            owner, method = static_call(node)
            if (
                owner == _HTML_CLASS
                and method == "escape"
                and context in {"html", "attribute"}
            ):
                return False
            if (
                owner == _XSS_CLASS
                and method in {"filter", "filteradmin"}
                and context == "html"
            ):
                # A caller-supplied allowed-tag list can even allow <script>.
                if method == "filteradmin" or has_safe_xss_tags(node):
                    return False
        if is_superglobal_var(node):
            return True
        if node.type == "variable_name":
            return context in tainted_vars.get(text(node).strip().lstrip("$"), set())
        if node.type == "function_call_expression":
            call_name = functions.get(node.start_byte, "")
            if call_name in _NUMERIC_SANITIZERS or (
                context == "path" and call_name == "basename"
            ):
                return False
        return any(
            is_tainted_expr(child, tainted_vars, context) for child in node.children
        )

    def html_parts(node):
        if (
            node.type in {"argument", "parenthesized_expression"}
            and len(node.named_children) == 1
        ):
            return html_parts(node.named_children[0])
        if node.type == "binary_expression" and any(
            child.type == "." for child in node.children
        ):
            return [part for child in node.named_children for part in html_parts(child)]
        if node.type in {"string", "encapsed_string"}:
            literal = text(node)
            offset = 0
            if literal[:1] in {"b", "B"}:
                offset = 1
            double_quoted = literal[offset : offset + 1] == '"'
            if all(
                child.type in {"string_content", "escape_sequence"}
                for child in node.named_children
            ):
                return [
                    (
                        "text",
                        _php_literal_text(
                            literal[offset + 1 : -1], double_quoted=double_quoted
                        ),
                    )
                ]
            parts = []
            for child in node.named_children:
                if child.type in {"string_content", "escape_sequence"}:
                    parts.append(
                        (
                            "text",
                            _php_literal_text(text(child), double_quoted=double_quoted),
                        )
                    )
                else:
                    parts.append(("value", (child,), False))
            return parts
        return [("value", (node,), False)]

    def is_tainted_html(node, tainted_vars: dict[str, set[str]]) -> bool:
        parts = html_parts(node)
        requirements = iter(hole_requirements(parts))
        for part in parts:
            if part[0] == "text":
                continue
            level, _ = next(requirements)
            if level == TEXT_SAFE:
                context = "html"
            elif level == ATTR_SAFE:
                context = "attribute"
            else:
                context = "raw"
            if any(is_tainted_expr(value, tainted_vars, context) for value in part[1]):
                return True
        return False

    def handle_assignment(node, tainted_vars: dict[str, set[str]]):
        if node.type != "assignment_expression":
            return
        assign = node
        lhs = assign.child_by_field_name("left")
        rhs = assign.child_by_field_name("right")
        if lhs is None or rhs is None:
            parts = [child for child in assign.children if child.type != "="]
            if len(parts) >= 2:
                lhs, rhs = parts[0], parts[1]
        if lhs is None or rhs is None:
            return
        if lhs.type == "variable_name":
            name = text(lhs).strip().lstrip("$")
            contexts = set()
            for context in _TAINT_CONTEXTS:
                if context == "html":
                    tainted = is_tainted_html(rhs, tainted_vars)
                else:
                    tainted = is_tainted_expr(rhs, tainted_vars, context)
                if tainted:
                    contexts.add(context)
            tainted_vars[name] = contexts

    def add_finding(rule_id: str, message: str, node) -> None:
        findings.append(
            {
                "rule_id": rule_id,
                "severity": "HIGH",
                "message": message,
                "file": str(Path(file_path)),
                "line": node.start_point[0] + 1,
                "col": node.start_point[1],
                "category": "danger",
            }
        )

    def first_argument(node):
        args = node.child_by_field_name("arguments")
        if args is None:
            return None
        return next((c for c in args.children if c.type not in {"(", ")", ","}), None)

    def check_drupal_sinks(node, tainted_vars: dict[str, set[str]]) -> None:
        arg = first_argument(node)
        if arg is None:
            return
        if node.type == "member_call_expression":
            value = arg
            if arg.named_children:
                value = arg.named_children[0]
            if (
                field_text(node, "name") in _SQL_SINKS
                and value.type != "array_creation_expression"
                and is_tainted_expr(arg, tainted_vars, "sql")
            ):
                add_finding(
                    "SKY-D211",
                    "Request-controlled data is built into an SQL string; use placeholders.",
                    node,
                )
        elif node.type == "scoped_call_expression":
            owner, method = static_call(node)
            if (
                owner in _MARKUP_CLASSES
                and method == "create"
                and is_tainted_html(arg, tainted_vars)
            ):
                add_finding(
                    "SKY-D226",
                    "Request-controlled data is marked safe with Markup::create(); escape it or use a render array.",
                    node,
                )
        elif functions.get(
            node.start_byte, ""
        ) in _SQL_FUNCTION_SINKS and is_tainted_expr(arg, tainted_vars, "sql"):
            add_finding(
                "SKY-D211",
                "Request-controlled data is built into an SQL string; use placeholders.",
                node,
            )

    def array_fields(array) -> dict:
        fields = {}
        for child in array.named_children:
            if (
                child.type == "array_element_initializer"
                and len(child.named_children) == 2
            ):
                key = text(child.named_children[0]).strip("'\"")
                fields[key] = child
        return fields

    def is_inline_template(element) -> bool:
        array = element.parent
        if array is None or array.type != "array_creation_expression":
            return False
        fields = array_fields(array)
        type_element = fields.get("#type")
        return (
            type_element is not None
            and text(type_element.named_children[1]).strip("'\"") == "inline_template"
            and fields.get("#template") == element
        )

    def report_template(source_node) -> None:
        add_finding(
            "SKY-D349",
            "Request-controlled data is compiled as an inline Twig template; pass it in #context instead.",
            source_node,
        )

    def update_template_builder(node, tainted_vars, builders) -> None:
        if node.type == "unset_statement":
            for target in node.named_children:
                if target.type == "variable_name":
                    builders.pop(text(target), None)
                elif target.type == "subscript_expression":
                    parts = target.named_children
                    if len(parts) != 2 or parts[0].type != "variable_name":
                        continue
                    name = text(parts[0])
                    states = builders.get(name)
                    if states is None:
                        continue
                    key = text(parts[1]).strip("'\"")
                    if key == "#template":
                        builders[name] = frozenset(
                            (None, inline) for _, inline in states
                        )
                    elif key == "#type":
                        builders[name] = frozenset(
                            (origin, False) for origin, _ in states
                        )
            return
        if node.type != "assignment_expression":
            return
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        if left.type == "variable_name":
            name = text(left)
            states = None
            if right.type == "array_creation_expression":
                fields = array_fields(right)
                template = fields.get("#template")
                origin = None
                if template is not None and is_tainted_expr(
                    template.named_children[1], tainted_vars, "template"
                ):
                    origin = template
                type_element = fields.get("#type")
                inline = (
                    type_element is not None
                    and text(type_element.named_children[1]).strip("'\"")
                    == "inline_template"
                )
                states = frozenset({(origin, inline)})
            elif right.type == "variable_name":
                # PHP arrays are copied by value. Keep an immutable snapshot;
                # subsequent writes to either local builder cannot affect its copy.
                states = builders.get(text(right))
            builders.pop(name, None)
            if states is None:
                return
        elif left.type == "subscript_expression":
            parts = left.named_children
            if len(parts) != 2 or parts[0].type != "variable_name":
                return
            name = text(parts[0])
            states = builders.get(name)
            if states is None:
                return
            key = text(parts[1]).strip("'\"")
            if key == "#type":
                inline = text(right).strip("'\"") == "inline_template"
                states = frozenset((origin, inline) for origin, _ in states)
            elif key == "#template":
                origin = None
                if is_tainted_expr(right, tainted_vars, "template"):
                    origin = node
                states = frozenset((origin, inline) for _, inline in states)
            else:
                return
        else:
            return
        builders[name] = states
        for origin, inline in sorted(states, key=template_state_order):
            if origin is not None and inline:
                report_template(origin)

    def template_state_order(state):
        origin, inline = state
        offset = -1
        if origin is not None:
            offset = origin.start_byte
        return offset, inline

    def join_states(outputs, tainted_vars, builders) -> None:
        merged_taint = {}
        merged_builders = {}
        for branch_taint, branch_builders in outputs:
            for name, contexts in branch_taint.items():
                merged_taint.setdefault(name, set()).update(contexts)
            for name, alternatives in branch_builders.items():
                merged_builders.setdefault(name, set()).update(alternatives)
        tainted_vars.clear()
        tainted_vars.update(merged_taint)
        builders.clear()
        builders.update(
            (name, frozenset(alternatives))
            for name, alternatives in merged_builders.items()
        )

    def snapshot(tainted_vars, builders):
        return dict(tainted_vars), dict(builders)

    def record_exit(flow, kind, tainted_vars, builders, level=0) -> None:
        flow.setdefault((kind, level), []).append(snapshot(tainted_vars, builders))

    def forward_exits(source, destination, *, consume_breaks=False):
        normal = []
        for (kind, level), states in source.items():
            if consume_breaks and kind in {"break", "continue"}:
                if level == 1:
                    normal.extend(states)
                    continue
                level -= 1
            if destination is not None:
                destination.setdefault((kind, level), []).extend(states)
        return normal

    def walk_conditional(node, tainted_vars, builders, flow) -> bool:
        fallthrough_taint = dict(tainted_vars)
        fallthrough_builders = dict(builders)
        outputs = []
        clauses = [node]
        clauses.extend(
            child
            for child in node.named_children
            if child.type in {"else_if_clause", "else_clause"}
        )
        for clause in clauses:
            condition = clause.child_by_field_name("condition")
            if condition is not None:
                if not walk_nodes(
                    [condition], fallthrough_taint, fallthrough_builders, flow
                ):
                    break
            branch_taint = dict(fallthrough_taint)
            branch_builders = dict(fallthrough_builders)
            body = clause.child_by_field_name("body")
            reachable = True
            if body is not None:
                reachable = walk_nodes([body], branch_taint, branch_builders, flow)
            if reachable:
                outputs.append((branch_taint, branch_builders))
            if condition is None:
                break
        else:
            # With no final else, all conditions can be false.
            outputs.append((fallthrough_taint, fallthrough_builders))
        join_states(outputs, tainted_vars, builders)
        return bool(outputs)

    def walk_loop(node, tainted_vars, builders, flow) -> bool:
        # Colon-form for loops repeat body fields. These are all conditional
        # body statements, rather than unconditional header effects.
        bodies = node.children_by_field_name("body")
        updates = node.children_by_field_name("update")
        if node.type == "do_statement":
            header = []
            updates = node.children_by_field_name("condition")
        else:
            header = [
                child
                for child in node.named_children
                if child not in bodies and child not in updates
            ]
        if not walk_nodes(header, tainted_vars, builders, flow):
            return False
        outputs = []
        if node.type != "do_statement":
            outputs.append(snapshot(tainted_vars, builders))
        body_taint = dict(tainted_vars)
        body_builders = dict(builders)
        body_flow = {}
        reachable = walk_nodes(bodies, body_taint, body_builders, body_flow)
        continued = body_flow.pop(("continue", 1), [])
        if reachable:
            continued.append(snapshot(body_taint, body_builders))
        for update_taint, update_builders in continued:
            if walk_nodes(updates, update_taint, update_builders, body_flow):
                outputs.append((update_taint, update_builders))
        outputs.extend(forward_exits(body_flow, flow, consume_breaks=True))
        join_states(outputs, tainted_vars, builders)
        return bool(outputs)

    def walk_switch(node, tainted_vars, builders, flow) -> bool:
        condition = node.child_by_field_name("condition")
        if condition is not None:
            if not walk_nodes([condition], tainted_vars, builders, flow):
                return False
        body = node.child_by_field_name("body")
        if body is None:
            return True
        dispatch_taint = dict(tainted_vars)
        dispatch_builders = dict(builders)
        dispatch_entries = {}
        dispatch_reachable = True
        fallthrough = None
        outputs = []
        case_flow = {}
        cases = [
            case
            for case in body.named_children
            if case.type in {"case_statement", "default_statement"}
        ]
        default = None
        for case in cases:
            if case.type == "default_statement":
                default = case
                continue
            if not dispatch_reachable:
                continue
            value = case.child_by_field_name("value")
            if value is not None:
                dispatch_reachable = walk_nodes(
                    [value], dispatch_taint, dispatch_builders, case_flow
                )
            if dispatch_reachable:
                dispatch_entries[case.start_byte] = snapshot(
                    dispatch_taint, dispatch_builders
                )
        if dispatch_reachable:
            if default is not None:
                dispatch_entries[default.start_byte] = snapshot(
                    dispatch_taint, dispatch_builders
                )
            else:
                outputs.append(snapshot(dispatch_taint, dispatch_builders))
        for case in cases:
            # Dispatch evaluates labels until a match; falling through an
            # earlier body jumps over all subsequent label expressions.
            incoming = []
            entry = dispatch_entries.get(case.start_byte)
            if entry is not None:
                incoming.append(entry)
            if fallthrough is not None:
                incoming.append(fallthrough)
            if not incoming:
                continue
            case_taint = {}
            case_builders = {}
            join_states(incoming, case_taint, case_builders)
            value = case.child_by_field_name("value")
            statements = [child for child in case.named_children if child != value]
            if walk_nodes(statements, case_taint, case_builders, case_flow):
                fallthrough = snapshot(case_taint, case_builders)
            else:
                fallthrough = None
        if fallthrough is not None:
            outputs.append(fallthrough)
        outputs.extend(forward_exits(case_flow, flow, consume_breaks=True))
        join_states(outputs, tainted_vars, builders)
        return bool(outputs)

    def walk_try(node, tainted_vars, builders, flow) -> bool:
        body = node.child_by_field_name("body")
        if body is None:
            return True
        body_taint = dict(tainted_vars)
        body_builders = dict(builders)
        pending = {}
        outputs = []
        if walk_nodes([body], body_taint, body_builders, pending):
            outputs.append(snapshot(body_taint, body_builders))
        exceptions = pending.pop(("throw", 0), [])
        catches = [
            child for child in node.named_children if child.type == "catch_clause"
        ]
        if catches and exceptions:
            for catch in catches:
                catch_taint = {}
                catch_builders = {}
                join_states(exceptions, catch_taint, catch_builders)
                catch_body = catch.child_by_field_name("body")
                if catch_body is not None:
                    if walk_nodes([catch_body], catch_taint, catch_builders, pending):
                        outputs.append(snapshot(catch_taint, catch_builders))
            # Exception classes are otherwise unknown. A non-catch-all handler
            # cannot prove that every exceptional path stops at this try.
            if not any(catch.start_byte in catch_all_handlers for catch in catches):
                pending.setdefault(("throw", 0), []).extend(exceptions)
        elif exceptions:
            pending.setdefault(("throw", 0), []).extend(exceptions)
        final = child_by_type(node, "finally_clause")
        if final is not None:
            final_body = final.child_by_field_name("body")
            if final_body is not None:
                final_outputs = []
                final_flow = {}
                for final_taint, final_builders in outputs:
                    if walk_nodes(
                        [final_body], final_taint, final_builders, final_flow
                    ):
                        final_outputs.append(snapshot(final_taint, final_builders))
                for completion, states in pending.items():
                    for final_taint, final_builders in states:
                        if walk_nodes(
                            [final_body], final_taint, final_builders, final_flow
                        ):
                            final_flow.setdefault(completion, []).append(
                                snapshot(final_taint, final_builders)
                            )
                outputs = final_outputs
                pending = final_flow
        forward_exits(pending, flow)
        join_states(outputs, tainted_vars, builders)
        return bool(outputs)

    visited_callables: set[int] = set()

    def walk_nodes(
        nodes, tainted_vars: dict[str, set[str]], builders: dict, flow=None
    ) -> bool:
        for child in nodes:
            if child.type in {"function_definition", "method_declaration"}:
                visited_callables.add(child.start_byte)
                body = child_by_type(child, "compound_statement")
                if body is not None:
                    walk_scope(body, {}, {})
                continue
            if child.type == "arrow_function":
                # Its body is an expression, so visit that expression itself
                # as a child, including a possible outermost sink call.
                walk_scope(child, dict(tainted_vars), {})
                continue
            if child.type == "anonymous_function":
                body = child.child_by_field_name("body")
                if body is not None:
                    walk_scope(body, dict(tainted_vars), {})
                continue
            if child.type == "if_statement":
                if not walk_conditional(child, tainted_vars, builders, flow):
                    return False
                continue
            if child.type in {
                "while_statement",
                "for_statement",
                "foreach_statement",
                "do_statement",
            }:
                if not walk_loop(child, tainted_vars, builders, flow):
                    return False
                continue
            if child.type == "switch_statement":
                if not walk_switch(child, tainted_vars, builders, flow):
                    return False
                continue
            if child.type == "try_statement":
                if not walk_try(child, tainted_vars, builders, flow):
                    return False
                continue

            if child.type in {
                "function_call_expression",
                "member_call_expression",
                "scoped_call_expression",
            }:
                check_drupal_sinks(child, tainted_vars)

            # Render array ['#type' => 'inline_template', '#template' => ...]:
            # Twig compiles the value as template source.
            if child.type == "array_element_initializer":
                parts = child.named_children
                if (
                    len(parts) == 2
                    and text(parts[0]).strip("'\"") == "#template"
                    and is_inline_template(child)
                    and is_tainted_expr(parts[1], tainted_vars, "template")
                ):
                    report_template(child)

            if child.type == "function_call_expression":
                call_name = functions.get(child.start_byte, "")
                args = child_by_type(child, "arguments")
                first_arg = None
                if args is not None:
                    for arg_child in args.children:
                        if arg_child.type not in {"(", ")", ","}:
                            first_arg = arg_child
                            break

                if (
                    call_name == "unserialize"
                    and first_arg is not None
                    and is_tainted_expr(first_arg, tainted_vars, "deserialize")
                ):
                    add_finding(
                        "SKY-D204",
                        "unserialize on user-controlled data is unsafe and can lead to code execution.",
                        child,
                    )

                if (
                    call_name in _FILE_SINKS
                    and first_arg is not None
                    and is_tainted_expr(first_arg, tainted_vars, "path")
                ):
                    add_finding(
                        "SKY-D215",
                        "Request-controlled path reaches a filesystem sink without path validation.",
                        child,
                    )

            if child.type in _IMPORT_EXPR_TYPES:
                expr = None
                for expr_child in child.children:
                    if expr_child.type not in {
                        "include",
                        "include_once",
                        "require",
                        "require_once",
                    }:
                        expr = expr_child
                        break
                if expr is not None and is_tainted_expr(expr, tainted_vars, "path"):
                    add_finding(
                        "SKY-D215",
                        "Request-controlled path reaches a filesystem sink without path validation.",
                        child,
                    )

            if not walk_scope(child, tainted_vars, builders, flow):
                return False
            # A throwing RHS never replaces the old value on its catch path.
            handle_assignment(child, tainted_vars)
            update_template_builder(child, tainted_vars, builders)
            if flow is not None:
                if child.type in {
                    "function_call_expression",
                    "member_call_expression",
                    "scoped_call_expression",
                    "object_creation_expression",
                    *_IMPORT_EXPR_TYPES,
                }:
                    record_exit(flow, "throw", tainted_vars, builders)
                if child.type in {"break_statement", "continue_statement"}:
                    level = 1
                    argument = next(iter(child.named_children), None)
                    if argument is not None and text(argument).isdigit():
                        level = max(1, int(text(argument)))
                    kind = child.type.removesuffix("_statement")
                    record_exit(flow, kind, tainted_vars, builders, level)
                    return False
                if child.type == "return_statement":
                    record_exit(flow, "return", tainted_vars, builders)
                    return False
                if child.type == "throw_expression":
                    record_exit(flow, "throw", tainted_vars, builders)
                    return False
        return True

    def walk_scope(
        node, tainted_vars: dict[str, set[str]], builders: dict, flow=None
    ) -> bool:
        return walk_nodes(node.children, tainted_vars, builders, flow)

    walk_scope(root_node, {}, {})

    # Named callable declarations retain independent static analysis even
    # when an earlier statement terminates the surrounding execution path.
    pending_nodes = [root_node]
    named_callables = []
    while pending_nodes:
        node = pending_nodes.pop()
        if node.type in {"function_definition", "method_declaration"}:
            named_callables.append(node)
        pending_nodes.extend(node.named_children)
    for node in sorted(named_callables, key=lambda item: item.start_byte):
        if node.start_byte in visited_callables:
            continue
        visited_callables.add(node.start_byte)
        body = child_by_type(node, "compound_statement")
        if body is not None:
            walk_scope(body, {}, {})

    return _dedupe_findings(findings)


_IMPORT_EXPR_TYPES = {
    "include_expression",
    "include_once_expression",
    "require_expression",
    "require_once_expression",
}


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, int]] = set()
    deduped: list[dict] = []
    for finding in findings:
        key = (finding["rule_id"], finding["file"], finding["line"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
