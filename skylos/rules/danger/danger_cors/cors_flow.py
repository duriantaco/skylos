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


def _is_true(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_name(node, name: str) -> bool:
    if isinstance(node, ast.Name):
        return node.id == name
    if isinstance(node, ast.Attribute):
        return node.attr == name
    return False


def _is_wildcard_origin(node) -> bool:
    if isinstance(node, ast.Constant):
        return node.value == "*"
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(
            isinstance(elt, ast.Constant) and elt.value == "*" for elt in node.elts
        )
    return False


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

    def _check_wildcard_with_credentials(self, node, qn):
        last = (qn or "").rsplit(".", 1)[-1]
        kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        if last in ("CORS", "cross_origin"):
            # flask_cors: origins="*" (also the per-resource form) with cookies.
            if not _is_true(kwargs.get("supports_credentials")):
                return
            wildcard = _is_wildcard_origin(kwargs.get("origins"))
            resources = kwargs.get("resources")
            if not wildcard and isinstance(resources, ast.Dict):
                for value in resources.values:
                    if isinstance(value, ast.Dict):
                        for key, origin in zip(value.keys, value.values):
                            if (
                                isinstance(key, ast.Constant)
                                and key.value == "origins"
                                and _is_wildcard_origin(origin)
                            ):
                                wildcard = True
            if wildcard:
                origins = kwargs.get("origins")
                self._report(
                    origins if _is_wildcard_origin(origins) else node,
                    "CORS misconfiguration: wildcard origin with "
                    "supports_credentials=True lets any site make credentialed "
                    "requests (flask-cors reflects the request Origin).",
                )
            return
        is_cors_middleware = last == "CORSMiddleware" or any(
            _is_name(arg, "CORSMiddleware") for arg in node.args
        )
        if not is_cors_middleware:
            return
        if not _is_true(kwargs.get("allow_credentials")):
            return
        regex = kwargs.get("allow_origin_regex")
        origins = kwargs.get("allow_origins")
        if _is_wildcard_origin(origins) or (
            isinstance(regex, ast.Constant)
            and isinstance(regex.value, str)
            and regex.value.strip() in (".*", "^.*$", ".+", "^.+$", "*")
        ):
            # Anchor on the origin setting: that is the line a reviewer changes.
            anchor = origins if _is_wildcard_origin(origins) else regex
            self._report(
                anchor,
                "CORS misconfiguration: allow_origins='*' with "
                "allow_credentials=True; Starlette then reflects any request "
                "Origin, so every site can make credentialed requests.",
            )

    def visit_Call(self, node):
        qn = _qualified_name(node)
        self._check_wildcard_with_credentials(node, qn)
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
