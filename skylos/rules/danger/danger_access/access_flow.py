from __future__ import annotations
import ast
import sys


class _MassAssignmentChecker(ast.NodeVisitor):
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

    def _report(self, node, rule_id, message, severity="HIGH"):
        self.findings.append(
            {
                "rule_id": rule_id,
                "severity": severity,
                "message": message,
                "file": str(self.file_path),
                "line": node.lineno,
                "col": node.col_offset,
            }
        )

    def visit_ClassDef(self, node):
        for item in node.body:
            if not isinstance(item, ast.ClassDef):
                continue
            if item.name != "Meta":
                continue

            for stmt in item.body:
                if not isinstance(stmt, ast.Assign):
                    continue

                for target in stmt.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    if target.id != "fields":
                        continue

                    if (
                        isinstance(stmt.value, ast.Constant)
                        and stmt.value.value == "__all__"
                    ):
                        self._report(
                            stmt,
                            "SKY-D234",
                            "Mass assignment: Meta.fields = '__all__' exposes all model fields.",
                        )

        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _MassAssignmentChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"Access control analysis failed for {file_path}: {e}", file=sys.stderr)
