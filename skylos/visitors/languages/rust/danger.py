from __future__ import annotations

import re
from pathlib import Path

_TAINT_NAME_RE = re.compile(
    r"(arg|cmd|command|dir|file|filename|input|name|path|payload|request|url|uri)",
    re.I,
)

_FILE_SINKS = {
    "read",
    "read_to_string",
    "write",
    "copy",
    "remove_file",
    "remove_dir",
    "remove_dir_all",
    "rename",
    "open",
    "create",
}

_PATH_MUTATION_SINKS = {
    "push",
    "set_extension",
    "set_file_name",
}

_SANITIZER_HINTS = {
    "canonicalize",
    "file_name",
    "strip_prefix",
}

_TAINT_SOURCE_HINTS = {
    "std::env::args",
    "std::env::args_os",
    "std::env::var",
    "std::env::var_os",
    "env::args",
    "env::args_os",
    "env::var",
    "env::var_os",
}


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

    def first_argument(args_node):
        if args_node is None:
            return None
        for child in args_node.children:
            if child.type not in {"(", ")", ","}:
                return child
        return None

    def call_name(node) -> str:
        if node is None or node.type != "call_expression" or not node.children:
            return ""
        callee = node.children[0]
        if callee.type == "identifier":
            return node_text(callee).strip()
        if callee.type == "scoped_identifier":
            return node_text(callee).strip()
        if callee.type == "field_expression":
            field = child_by_type(callee, "field_identifier")
            return node_text(field).strip() if field else node_text(callee).strip()
        return node_text(callee).strip()

    def is_string_literal(node) -> bool:
        return node is not None and node.type in {
            "string_literal",
            "raw_string_literal",
        }

    def is_sanitized_expr(node) -> bool:
        if node is None:
            return False
        expr_text = node_text(node)
        return any(hint in expr_text for hint in _SANITIZER_HINTS)

    def is_tainted_expr(node, tainted_vars: set[str]) -> bool:
        if node is None:
            return False
        if is_sanitized_expr(node):
            return False
        if node.type == "identifier":
            return node_text(node).strip() in tainted_vars
        if is_string_literal(node):
            return False
        return any(is_tainted_expr(child, tainted_vars) for child in node.children)

    def is_taint_source_expr(node) -> bool:
        if node is None:
            return False
        expr_text = node_text(node)
        return any(source_hint in expr_text for source_hint in _TAINT_SOURCE_HINTS)

    def is_tainted_or_source(node, tainted_vars: set[str]) -> bool:
        if node is None or is_sanitized_expr(node):
            return False
        return is_tainted_expr(node, tainted_vars) or is_taint_source_expr(node)

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

    def collect_param_names(function_node) -> set[str]:
        params = child_by_type(function_node, "parameters")
        if params is None:
            return set()
        names: set[str] = set()
        for child in params.children:
            if child.type != "parameter":
                continue
            ident = child_by_type(child, "identifier")
            if ident is None:
                continue
            name = node_text(ident).strip()
            if _TAINT_NAME_RE.search(name):
                names.add(name)
        return names

    def assignment_lhs_rhs(node):
        if node.type == "let_declaration":
            lhs = child_by_type(node, "identifier")
            rhs = None
            seen_eq = False
            for child in node.children:
                if child.type == "=":
                    seen_eq = True
                    continue
                if seen_eq and child.type != ";":
                    rhs = child
                    break
            return lhs, rhs
        if node.type == "assignment_expression":
            lhs = node.child_by_field_name("left")
            rhs = node.child_by_field_name("right")
            if lhs is not None and rhs is not None:
                return lhs, rhs
            parts = [child for child in node.children if child.type != "="]
            if len(parts) >= 2:
                return parts[0], parts[1]
        return None, None

    def handle_assignment(node, tainted_vars: set[str]) -> None:
        lhs, rhs = assignment_lhs_rhs(node)
        if lhs is None or rhs is None or lhs.type != "identifier":
            return
        name = node_text(lhs).strip()
        if is_tainted_expr(rhs, tainted_vars) or is_taint_source_expr(rhs):
            tainted_vars.add(name)
        else:
            tainted_vars.discard(name)

    def has_shell_c_with_tainted_arg(call_node, tainted_vars: set[str]) -> bool:
        call_text = node_text(call_node)
        if "Command::new" not in call_text:
            return False
        if not re.search(
            r'Command::new\(\s*"(?:sh|bash|zsh|cmd|powershell)"\s*\)', call_text
        ):
            return False
        shell_switch = r'(?:"-c"|"/C"|"-Command")'
        has_single_switch = re.search(
            rf"\.arg\(\s*{shell_switch}\s*\)", call_text
        )
        has_args_switch = re.search(
            rf"\.args\([^)]*{shell_switch}", call_text, re.S
        )
        if not has_single_switch and not has_args_switch:
            return False
        return is_tainted_expr(call_node, tainted_vars)

    def handle_call(node, tainted_vars: set[str]) -> None:
        name = call_name(node)
        args = child_by_type(node, "arguments")
        first_arg = first_argument(args)
        name_tail = name.split("::")[-1].split(".")[-1]

        if name.endswith("Command::new"):
            if (
                first_arg is not None
                and not is_string_literal(first_arg)
                and is_tainted_or_source(first_arg, tainted_vars)
            ):
                add_finding(
                    "SKY-D212",
                    "Command::new receives tainted input; validate or allowlist the executable.",
                    node,
                )
                return

        if has_shell_c_with_tainted_arg(node, tainted_vars):
            add_finding(
                "SKY-D212",
                "User-controlled input reaches a shell command argument.",
                node,
            )
            return

        if name_tail in _FILE_SINKS and first_arg is not None:
            if is_tainted_or_source(first_arg, tainted_vars):
                add_finding(
                    "SKY-D215",
                    "Tainted path-like input reaches a filesystem sink without canonicalization.",
                    node,
                )
                return

        if name_tail in _PATH_MUTATION_SINKS and first_arg is not None:
            if is_tainted_or_source(first_arg, tainted_vars):
                add_finding(
                    "SKY-D215",
                    "Tainted path-like input is appended to a filesystem path without canonicalization.",
                    node,
                )

    def walk_scope(node, tainted_vars: set[str]) -> None:
        for child in node.children:
            if child.type == "function_item":
                body = child_by_type(child, "block")
                if body is not None:
                    walk_scope(body, collect_param_names(child))
                continue

            handle_assignment(child, tainted_vars)

            if child.type == "call_expression":
                handle_call(child, tainted_vars)

            walk_scope(child, tainted_vars)

    walk_scope(root_node, set())
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
