from __future__ import annotations

import re
from pathlib import Path

_TAINT_NAME_RE = re.compile(
    r"(arg|cmd|command|file|filename|input|name|path|payload|request|url|uri)",
    re.I,
)

_SOURCE_HINTS = {
    "Platform.environment",
    "stdin.readLineSync",
    "Uri.base",
    "window.location",
}

_SANITIZER_HINTS = {
    "canonicalize",
    "basename(",
    "path.basename",
    "Uri.https(",
}

_PROCESS_RE = re.compile(r"\bProcess\.(run|runSync|start|startDetached)\s*\(")
_HTTP_RE = re.compile(
    r"(\bhttp\.(get|post|put|patch|delete|head)\s*\(|\bDio\(\)\.(get|post|put|patch|delete|head)\s*\(|\bHttpClient\(\)\.(getUrl|openUrl)\s*\()"
)
_FILE_RE = re.compile(
    r"(\bFile\s*\(|\bDirectory\s*\(|\brootBundle\.loadString\s*\(|\bFileImage\s*\()"
)


def scan_danger(root_node, file_path: str, source: bytes) -> list[dict]:
    if root_node is None:
        return []

    findings: list[dict] = []

    def node_text(node) -> str:
        return source[node.start_byte : node.end_byte].decode("utf-8", "ignore")

    def child_by_type(node, type_name: str):
        for child in node.children:
            if child.type == type_name:
                return child
        return None

    def first_descendant(node, type_name: str):
        if node.type == type_name:
            return node
        for child in node.children:
            found = first_descendant(child, type_name)
            if found is not None:
                return found
        return None

    def descendants(node, type_name: str):
        if node.type == type_name:
            yield node
        for child in node.children:
            yield from descendants(child, type_name)

    def function_name(signature) -> str:
        by_field = signature.child_by_field_name("name")
        if by_field is not None:
            return node_text(by_field).strip()
        params = child_by_type(signature, "formal_parameter_list")
        candidates = []
        for child in signature.children:
            if child is params:
                break
            if child.type == "identifier":
                candidates.append(child)
        return node_text(candidates[-1]).strip() if candidates else ""

    def collect_tainted_params(signature) -> set[str]:
        params = child_by_type(signature, "formal_parameter_list")
        if params is None:
            return set()
        names: set[str] = set()
        for param in descendants(params, "formal_parameter"):
            identifiers = [
                node_text(i).strip() for i in descendants(param, "identifier")
            ]
            if not identifiers:
                continue
            name = identifiers[-1]
            if _TAINT_NAME_RE.search(name):
                names.add(name)
        return names

    def is_sanitized_expr_text(expr: str) -> bool:
        compact = re.sub(r"\s+", "", expr)
        return any(hint in expr or hint in compact for hint in _SANITIZER_HINTS)

    def is_tainted_text(expr: str, tainted_vars: set[str]) -> bool:
        if not expr or is_sanitized_expr_text(expr):
            return False
        if any(hint in expr for hint in _SOURCE_HINTS):
            return True
        return any(re.search(rf"\b{re.escape(name)}\b", expr) for name in tainted_vars)

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

    def assignment_lhs_rhs(node):
        if node.type == "local_variable_declaration":
            definition = first_descendant(node, "initialized_variable_definition")
            if definition is None:
                return None, None
            lhs = child_by_type(definition, "identifier")
            rhs_parts = []
            seen_eq = False
            for child in definition.children:
                if child.type == "=":
                    seen_eq = True
                    continue
                if seen_eq:
                    rhs_parts.append(node_text(child))
            return lhs, " ".join(rhs_parts).strip()

        if node.type == "assignment_expression":
            lhs = node.child_by_field_name("left")
            rhs = node.child_by_field_name("right")
            if lhs is not None and rhs is not None:
                return lhs, node_text(rhs)
            parts = [child for child in node.children if child.type != "="]
            if len(parts) >= 2:
                return parts[0], node_text(parts[1])

        return None, None

    def handle_assignment(node, tainted_vars: set[str]) -> None:
        lhs, rhs_text = assignment_lhs_rhs(node)
        if lhs is None or not rhs_text:
            return
        name = node_text(lhs).strip()
        if not name:
            return
        if is_tainted_text(rhs_text, tainted_vars):
            tainted_vars.add(name)
        else:
            tainted_vars.discard(name)

    def handle_expression(node, tainted_vars: set[str]) -> None:
        expr = node_text(node)
        if not is_tainted_text(expr, tainted_vars):
            return

        if _PROCESS_RE.search(expr):
            add_finding(
                "SKY-D212",
                "Process execution receives tainted input; validate or allowlist the command.",
                node,
            )
            return

        if _HTTP_RE.search(expr):
            add_finding(
                "SKY-D216",
                "User-controlled URL reaches an outbound request sink.",
                node,
            )
            return

        if _FILE_RE.search(expr):
            add_finding(
                "SKY-D215",
                "User-controlled path reaches a filesystem sink without path validation.",
                node,
            )

    def walk_scope(node, tainted_vars: set[str]) -> None:
        for child in node.children:
            if child.type in {"function_signature", "method_signature"}:
                continue

            handle_assignment(child, tainted_vars)

            if child.type in {
                "expression_statement",
                "return_statement",
                "local_variable_declaration",
            }:
                handle_expression(child, tainted_vars)

            walk_scope(child, tainted_vars)

    def scan_functions(node) -> None:
        children = list(node.children)
        index = 0
        while index < len(children):
            child = children[index]
            if child.type == "function_signature":
                body = (
                    children[index + 1]
                    if index + 1 < len(children)
                    and children[index + 1].type == "function_body"
                    else None
                )
                if body is not None:
                    _ = function_name(child)
                    walk_scope(body, collect_tainted_params(child))
                    index += 2
                    continue

            if child.type == "method_signature":
                signature = first_descendant(child, "function_signature")
                body = (
                    children[index + 1]
                    if index + 1 < len(children)
                    and children[index + 1].type == "function_body"
                    else None
                )
                if signature is not None and body is not None:
                    _ = function_name(signature)
                    walk_scope(body, collect_tainted_params(signature))
                    index += 2
                    continue

            scan_functions(child)
            index += 1

    scan_functions(root_node)
    return _dedupe_findings(findings)


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
