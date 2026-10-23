from __future__ import annotations

from pathlib import Path

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
_SANITIZERS = {"basename", "intval", "floatval"}
# Drupal: Symfony request bags, Form API input, and the static escapers.
_REQUEST_BAGS = {"query", "request", "cookies"}
_FORM_STATE_GETTERS = {"getValue", "getValues"}
_STATIC_SANITIZERS = {("Html", "escape"), ("Xss", "filter"), ("Xss", "filterAdmin")}
_SQL_SINKS = {"query", "queryRange", "where"}
_SQL_FUNCTION_SINKS = {"db_query", "db_query_range"}
_SAFE_MARKUP_SINKS = {("Markup", "create"), ("ViewsRenderPipelineMarkup", "create")}
_FILTER_INPUT_SOURCES = {
    "INPUT_GET",
    "INPUT_POST",
    "INPUT_REQUEST",
    "INPUT_COOKIE",
    "INPUT_SERVER",
}


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
        name_node = child_by_type(node, "name")
        call_name = (
            text(name_node).strip().lstrip("\\") if name_node else ""
        )  # skylos: ignore[SKY-D211]
        if call_name != "filter_input":
            return False
        args = child_by_type(node, "arguments")
        return args is not None and any(
            text(child).strip() in _FILTER_INPUT_SOURCES for child in args.children
        )

    def field_text(node, field: str) -> str:
        child = node.child_by_field_name(field)
        return text(child).strip().lstrip("\\") if child is not None else ""

    def static_call(node) -> tuple[str, str]:
        """``(Class, method)`` of a static call, the class without namespace."""
        return (field_text(node, "scope").rpartition("\\")[2], field_text(node, "name"))

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

    def is_tainted_expr(node, tainted_vars: set[str]) -> bool:
        if node is None:
            return False
        if is_filter_input_source(node) or is_drupal_source(node):
            return True
        if node.type == "cast_expression":
            cast = child_by_type(node, "cast_type")
            if cast is not None and text(cast).strip() in {"int", "integer", "float"}:
                return False
        if (
            node.type == "scoped_call_expression"
            and static_call(node) in _STATIC_SANITIZERS
        ):
            return False
        if is_superglobal_var(node):
            return True
        if node.type == "variable_name":
            return text(node).strip().lstrip("$") in tainted_vars
        if node.type == "function_call_expression":
            name_node = child_by_type(node, "name")
            call_name = text(name_node).strip().lstrip("\\") if name_node else ""
            if call_name in _SANITIZERS:
                return False
        return any(is_tainted_expr(child, tainted_vars) for child in node.children)

    def extract_assignment(node):
        if node.type == "assignment_expression":
            return node
        for child in node.children:
            found = extract_assignment(child)
            if found is not None:
                return found
        return None

    def handle_assignment(node, tainted_vars: set[str]):
        assign = extract_assignment(node)
        if assign is None:
            return
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
            if is_tainted_expr(rhs, tainted_vars):
                tainted_vars.add(name)
            else:
                tainted_vars.discard(name)

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

    def check_drupal_sinks(node, tainted_vars: set[str]) -> None:
        arg = first_argument(node)
        if arg is None or not is_tainted_expr(arg, tainted_vars):
            return
        if node.type == "member_call_expression":
            value = arg.named_children[0] if arg.named_children else arg
            if (
                field_text(node, "name") in _SQL_SINKS
                and value.type != "array_creation_expression"
            ):
                add_finding(
                    "SKY-D211",
                    "Request-controlled data is built into an SQL string; use placeholders.",
                    node,
                )
        elif node.type == "scoped_call_expression":
            if static_call(node) in _SAFE_MARKUP_SINKS:
                add_finding(
                    "SKY-D226",
                    "Request-controlled data is marked safe with Markup::create(); escape it or use a render array.",
                    node,
                )
        elif field_text(node, "function") in _SQL_FUNCTION_SINKS:
            add_finding(
                "SKY-D211",
                "Request-controlled data is built into an SQL string; use placeholders.",
                node,
            )

    def walk_scope(node, tainted_vars: set[str]) -> None:
        for child in node.children:
            if child.type in {"function_definition", "method_declaration"}:
                body = child_by_type(child, "compound_statement")
                if body is not None:
                    walk_scope(body, set())
                continue

            handle_assignment(child, tainted_vars)

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
                    and is_tainted_expr(parts[1], tainted_vars)
                ):
                    add_finding(
                        "SKY-D349",
                        "Request-controlled data is compiled as an inline Twig template; pass it in #context instead.",
                        child,
                    )

            if child.type == "function_call_expression":
                name_node = child_by_type(child, "name")
                call_name = text(name_node).strip().lstrip("\\") if name_node else ""
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
                    and is_tainted_expr(first_arg, tainted_vars)
                ):
                    add_finding(
                        "SKY-D204",
                        "unserialize on user-controlled data is unsafe and can lead to code execution.",
                        child,
                    )

                if (
                    call_name in _FILE_SINKS
                    and first_arg is not None
                    and is_tainted_expr(first_arg, tainted_vars)
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
                if expr is not None and is_tainted_expr(expr, tainted_vars):
                    add_finding(
                        "SKY-D215",
                        "Request-controlled path reaches a filesystem sink without path validation.",
                        child,
                    )

            walk_scope(child, tainted_vars)

    walk_scope(root_node, set())

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
