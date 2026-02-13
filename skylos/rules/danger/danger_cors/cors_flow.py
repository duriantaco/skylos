from __future__ import annotations
import ast
import sys


def _qualified_name(node):
    func = node.func
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        parts.reverse()
        return ".".join(parts)
    return None


class _CORSChecker(ast.NodeVisitor):
    def __init__(self, file_path, findings):
        self.file_path = file_path
        self.findings = findings

    def generic_visit(self, node):
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    def _report(self, node, message):
        self.findings.append(
            {
                "rule_id": "SKY-D231",
                "severity": "HIGH",
                "message": message,
                "file": str(self.file_path),
                "line": node.lineno,
                "col": node.col_offset,
            }
        )

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id
            elif isinstance(target, ast.Attribute):
                name = target.attr
            else:
                self.generic_visit(node)
                return

            if name == "CORS_ALLOW_ALL_ORIGINS" and isinstance(
                node.value, ast.Constant
            ):
                if node.value.value is True:
                    self._report(
                        node, "CORS misconfiguration: CORS_ALLOW_ALL_ORIGINS = True"
                    )

            if name in (
                "ACCESS_CONTROL_ALLOW_ORIGIN",
                "Access-Control-Allow-Origin",
            ):
                if isinstance(node.value, ast.Constant) and node.value.value == "*":
                    self._report(
                        node,
                        "CORS misconfiguration: Access-Control-Allow-Origin set to '*'",
                    )

        self.generic_visit(node)

    def visit_Call(self, node):
        qn = _qualified_name(node)
        if qn and qn.endswith("CORS"):
            has_origins = False
            for kw in node.keywords:
                if kw.arg in ("origins", "resources"):
                    has_origins = True
                    break
            if not has_origins and len(node.args) <= 1:
                self._report(
                    node,
                    "CORS misconfiguration: CORS() called without explicit origins restriction.",
                )

        self.generic_visit(node)

    def visit_Dict(self, node):
        for key, value in zip(node.keys, node.values):
            if (
                isinstance(key, ast.Constant)
                and key.value == "Access-Control-Allow-Origin"
                and isinstance(value, ast.Constant)
                and value.value == "*"
            ):
                self._report(
                    key,
                    "CORS misconfiguration: Access-Control-Allow-Origin set to '*'",
                )
        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _CORSChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"CORS analysis failed for {file_path}: {e}", file=sys.stderr)
