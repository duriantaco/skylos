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


class _JWTChecker(ast.NodeVisitor):
    def __init__(self, file_path, findings):
        self.file_path = file_path
        self.findings = findings
        self._jwt_aliases = set()    # names that alias to jwt module
        self._jwt_funcs = set()      # functions imported directly from jwt

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name == "jwt":
                self._jwt_aliases.add(alias.asname or "jwt")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module == "jwt":
            for alias in node.names:
                self._jwt_funcs.add(alias.asname or alias.name)
        self.generic_visit(node)

    def _is_jwt_decode(self, qn: str) -> bool:
        """Check if qn refers to jwt.decode, accounting for aliases."""
        if qn == "jwt.decode" or qn.startswith("jwt.") and qn.endswith(".decode"):
            return True
        if qn.endswith("jwt.decode"):
            return True
        if qn in self._jwt_funcs:
            return True
        if any(qn == f"{alias}.decode" for alias in self._jwt_aliases):
            return True
        return False

    def generic_visit(self, node):
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

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
        qn = _qualified_name(node)
        if not qn:
            self.generic_visit(node)
            return
        if not qn.endswith((".decode", ".encode")) and qn not in self._jwt_funcs:
            self.generic_visit(node)
            return

        if not self._is_jwt_decode(qn):
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
