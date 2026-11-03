from __future__ import annotations
import ast
import sys
from skylos.rules.danger.taint import TaintVisitor
from skylos.rules.danger.untrusted_sources import UntrustedSourceIndex


def _qualified_name(node: ast.Call):
    f = node.func
    parts = []

    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value

    if isinstance(f, ast.Name):
        parts.append(f.id)
        parts.reverse()
        return ".".join(parts)

    if isinstance(f, ast.Name):
        return f.id
    return None


def _is_static_string_expr(n: ast.AST) -> bool:
    if isinstance(n, ast.Constant):
        return isinstance(n.value, str)
    if isinstance(n, ast.JoinedStr):
        for value in n.values:
            if isinstance(value, ast.Constant):
                continue
            if isinstance(value, ast.FormattedValue) and isinstance(
                value.value, ast.Constant
            ):
                continue
            return False
        return True
    if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
        return _is_static_string_expr(n.left) and _is_static_string_expr(n.right)
    if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod):
        if not _is_static_string_expr(n.left):
            return False
        if isinstance(n.right, ast.Tuple):
            return all(_is_static_string_expr(elt) for elt in n.right.elts)
        return _is_static_string_expr(n.right)
    if (
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "format"
    ):
        return (
            _is_static_string_expr(n.func.value)
            and all(_is_static_string_expr(arg) for arg in n.args)
            and all(_is_static_string_expr(k.value) for k in n.keywords)
        )
    return False


def _is_interpolated_string(n: ast.AST):
    if isinstance(n, (ast.JoinedStr, ast.BinOp)):
        return not _is_static_string_expr(n)
    if (
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "format"
    ):
        return not _is_static_string_expr(n)
    return False


def _chain_attributes(node: ast.AST) -> set[str]:
    """Attribute names along a receiver chain, through calls:
    ``Entry.objects.filter(a=1)`` gives ``{"objects", "filter"}``."""
    names = set()
    current = node
    while isinstance(current, (ast.Attribute, ast.Call)):
        if isinstance(current, ast.Call):
            current = current.func
            continue
        names.add(current.attr)
        current = current.value
    return names


_DJANGO_RAW_SQL = frozenset(
    {"django.db.models.RawSQL", "django.db.models.expressions.RawSQL"}
)
_EXTRA_POSITIONS = {0: "select", 1: "where", 3: "tables", 4: "order_by"}
_EXTRA_SQL_ARGUMENTS = frozenset(_EXTRA_POSITIONS.values())


class _SQLRawFlowChecker(TaintVisitor):
    def __init__(self, tree: ast.AST, file_path, findings):
        super().__init__(file_path, findings)
        self.untrusted_sources = UntrustedSourceIndex(tree)

    def _raw_sql_finding(self, node: ast.Call, sql: ast.AST, message: str, sink: str):
        finding = {
            "rule_id": "SKY-D217",
            "severity": "CRITICAL",
            "message": message,
            "file": str(self.file_path),
            "line": node.lineno,
            "col": node.col_offset,
            "symbol": self._current_symbol(),
        }
        evidence = self.untrusted_sources.evidence(
            self._current_function(),
            sql,
            sink=sink,
            missing_guard="parameterized SQL binding",
            evidence_kind="python_sql_taint",
        )
        if evidence is not None:
            finding["metadata"] = {"security_evidence": evidence}
        self.findings.append(finding)

    def visit_Call(self, node: ast.Call):
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "extra"
            and (
                _chain_attributes(node.func.value) & {"objects"}
                or self._imports("django")
            )
        ):
            sql = self._tainted_extra_fragment(node)
            if sql is not None:
                self._raw_sql_finding(
                    node,
                    sql,
                    "Possible SQL injection: tainted SQL fragment passed to Django QuerySet.extra().",
                    "SQL fragment passed to Django QuerySet.extra()",
                )

        qn = _qualified_name(node)
        if not qn:
            self.generic_visit(node)
            return

        if qn.endswith(".objects.raw") and node.args:
            sql = node.args[0]
            if _is_interpolated_string(sql) or self.is_tainted(sql):
                self._raw_sql_finding(
                    node,
                    sql,
                    "Possible SQL injection: tainted SQL passed to Django .raw().",
                    "SQL text passed to Django .raw()",
                )
        elif qn.endswith(".raw") and node.args and self._imports("peewee"):
            sql = node.args[0]
            if _is_interpolated_string(sql) or self.is_tainted(sql):
                self._raw_sql_finding(
                    node,
                    sql,
                    "Possible SQL injection: tainted SQL passed to peewee Model.raw().",
                    "SQL text passed to peewee Model.raw()",
                )

        if self._is_django_raw_sql(qn) and node.args:
            sql = node.args[0]
            if _is_interpolated_string(sql) or self.is_tainted(sql):
                self._raw_sql_finding(
                    node,
                    sql,
                    "Possible SQL injection: tainted SQL passed to Django RawSQL().",
                    "SQL text passed to Django RawSQL()",
                )

        self.generic_visit(node)

    def _imports(self, module: str) -> bool:
        tree = self.untrusted_sources.module
        if tree is None:
            return False
        for child in ast.walk(tree):
            if isinstance(child, ast.Import) and any(
                alias.name.split(".", 1)[0] == module for alias in child.names
            ):
                return True
            if (
                isinstance(child, ast.ImportFrom)
                and not child.level
                and (child.module or "").split(".", 1)[0] == module
            ):
                return True
        return False

    def _is_django_raw_sql(self, qn: str) -> bool:
        if qn.rsplit(".", 1)[-1] != "RawSQL":
            return False
        resolved = self.untrusted_sources.resolved_import(self._current_function(), qn)
        return bool(resolved) and resolved in _DJANGO_RAW_SQL

    def _tainted_extra_fragment(self, node: ast.Call):
        """The first string-built or tainted SQL fragment among
        ``extra()``'s ``select`` values and ``where``/``tables``/``order_by``
        entries. ``params`` and ``select_params`` are bound parameters."""
        fragments = {}
        for index, argument in enumerate(node.args):
            name = _EXTRA_POSITIONS.get(index)
            if name is not None:
                fragments[name] = argument
        for keyword in node.keywords:
            if keyword.arg in _EXTRA_SQL_ARGUMENTS:
                fragments[keyword.arg] = keyword.value
        for name, value in fragments.items():
            if name == "select":
                if not isinstance(value, ast.Dict):
                    continue
                parts = value.values
            elif isinstance(value, (ast.List, ast.Tuple)):
                parts = value.elts
            else:
                continue
            for part in parts:
                if _is_interpolated_string(part) or self.is_tainted(part):
                    return part
        return None


def scan(tree: ast.AST, file_path, findings):
    try:
        checker = _SQLRawFlowChecker(tree, file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"Raw SQL flow analysis failed for {file_path}: {e}", file=sys.stderr)
