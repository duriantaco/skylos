from __future__ import annotations
import ast
import sys

from .jwt_provenance import JWTImportVisitor


class _JWTChecker(JWTImportVisitor):
    def __init__(self, file_path, findings):
        super().__init__()
        self.file_path = file_path
        self.findings = findings

    def _report(self, node, message, severity="HIGH"):
        self.findings.append(
            {
                "rule_id": "SKY-D232",
                "severity": severity,
                "message": message,
                "file": str(self.file_path),
                "line": node.lineno,
                "col": node.col_offset,
            }
        )

    def visit_Call(self, node):
        if not self.is_jwt_decode(node):
            self.generic_visit(node)
            return

        for kw in node.keywords:
            if kw.arg == "algorithms" and isinstance(kw.value, ast.List):
                for elt in kw.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        if elt.value.lower() == "none":
                            self._report(
                                node,
                                'JWT vulnerability: algorithms=["none"] allows unsigned tokens.',
                                severity="CRITICAL",
                            )

            if kw.arg == "verify" and isinstance(kw.value, ast.Constant):
                if kw.value.value is False:
                    self._report(
                        node,
                        "JWT vulnerability: verify=False disables signature verification.",
                        severity="CRITICAL",
                    )

            if kw.arg == "options" and isinstance(kw.value, ast.Dict):
                for key, val in zip(kw.value.keys, kw.value.values):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value == "verify_signature"
                        and isinstance(val, ast.Constant)
                        and val.value is False
                    ):
                        self._report(
                            node,
                            "JWT vulnerability: verify_signature=False disables signature verification.",
                            severity="CRITICAL",
                        )

        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _JWTChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"JWT analysis failed for {file_path}: {e}", file=sys.stderr)
