import ast
import os
from pathlib import Path
from skylos.rules.base import SkylosRule


MUTABLE_CONSTRUCTORS = {
    "list",
    "dict",
    "set",
    "defaultdict",
    "OrderedDict",
    "Counter",
    "deque",
    "array",
}


class MutableDefaultRule(SkylosRule):
    rule_id = "SKY-L001"
    name = "Mutable Default Argument"

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        findings = []

        kw_defaults_filtered = []
        for d in node.args.kw_defaults:
            if d:
                kw_defaults_filtered.append(d)

        for default in node.args.defaults + kw_defaults_filtered:
            is_mutable = False

            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                is_mutable = True

            elif isinstance(default, (ast.ListComp, ast.DictComp, ast.SetComp)):
                is_mutable = True

            elif isinstance(default, ast.Call):
                if isinstance(default.func, ast.Name):
                    if default.func.id in MUTABLE_CONSTRUCTORS:
                        is_mutable = True

            if is_mutable:
                findings.append(
                    {
                        "rule_id": self.rule_id,
                        "kind": "logic",
                        "severity": "HIGH",
                        "type": "function",
                        "name": node.name,
                        "simple_name": node.name,
                        "value": "mutable",
                        "threshold": 0,
                        "message": "Mutable default argument detected. This causes state leaks between calls.",
                        "file": context.get("filename"),
                        "basename": Path(context.get("filename", "")).name,
                        "line": default.lineno,
                        "col": default.col_offset,
                    }
                )

        if findings:
            return findings
        return None


class BareExceptRule(SkylosRule):
    rule_id = "SKY-L002"
    name = "Bare Except Block"

    def visit_node(self, node, context):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            return [
                {
                    "rule_id": self.rule_id,
                    "kind": "logic",
                    "severity": "MEDIUM",
                    "type": "block",
                    "name": "except",
                    "simple_name": "except",
                    "value": "bare",
                    "threshold": 0,
                    "message": "Bare 'except:' block swallows SystemExit and other critical errors.",
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            ]
        return None


class DangerousComparisonRule(SkylosRule):
    rule_id = "SKY-L003"
    name = "Dangerous Comparison"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Compare):
            return None

        findings = []
        for op, comparator in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Eq, ast.NotEq)):
                if isinstance(comparator, ast.Constant):
                    val = comparator.value
                    if val is True or val is False or val is None:
                        findings.append(
                            {
                                "rule_id": self.rule_id,
                                "kind": "logic",
                                "severity": "LOW",
                                "type": "comparison",
                                "name": "==",
                                "simple_name": "==",
                                "value": str(comparator.value),
                                "threshold": 0,
                                "message": f"Comparison to {comparator.value} should use 'is' or 'is not'.",
                                "file": context.get("filename"),
                                "basename": Path(context.get("filename", "")).name,
                                "line": node.lineno,
                                "col": node.col_offset,
                            }
                        )

        if findings:
            return findings
        return None


def _walk_scope(nodes):
    stack = []

    if isinstance(nodes, list):
        for n in nodes:
            stack.append(n)
    else:
        stack.append(nodes)

    while stack:
        node = stack.pop()

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue

        yield node

        for child in ast.iter_child_nodes(node):
            stack.append(child)


def _is_function_level_try(node: ast.Try, parent_body: list[ast.stmt]) -> bool:
    if len(parent_body) == 1 and parent_body[0] is node:
        return True
    if (
        len(parent_body) == 2
        and isinstance(parent_body[0], ast.Expr)
        and isinstance(parent_body[0].value, ast.Constant)
        and isinstance(parent_body[0].value.value, str)
        and parent_body[1] is node
    ):
        return True
    return False


class TryBlockPatternsRule(SkylosRule):
    rule_id = "SKY-L004"
    name = "Anti-Pattern Try Block"

    def __init__(self, max_lines=15, max_control_flow=3):
        self.max_lines = max_lines
        self.max_control_flow = max_control_flow

    def visit_node(self, node, context):
        if not isinstance(node, ast.Try):
            return None

        parent_body = context.get("_parent_body")
        is_func_level = parent_body is not None and _is_function_level_try(
            node, parent_body
        )

        findings = []

        if node.body and not is_func_level:
            start = node.body[0].lineno
            end = getattr(node.body[-1], "end_lineno", start)
            length = end - start + 1

            if length > self.max_lines:
                findings.append(
                    self._create_finding(
                        node,
                        context,
                        severity="LOW",
                        value=length,
                        msg=f"Try block covers {length} lines (limit: {self.max_lines}). Reduce scope to the risky operation only.",
                    )
                )

        control_flow_count = 0
        has_nested_try = False

        for stmt in node.body:
            for child in _walk_scope([stmt]):
                if child is stmt:
                    continue
                if isinstance(child, ast.Try):
                    has_nested_try = True
                if isinstance(child, (ast.If, ast.For, ast.While)):
                    control_flow_count += 1

        if has_nested_try:
            findings.append(
                self._create_finding(
                    node,
                    context,
                    severity="MEDIUM",
                    value="nested",
                    msg="Nested 'try' block detected. Flatten logic or move inner try to a helper function.",
                )
            )

        if control_flow_count > self.max_control_flow:
            findings.append(
                self._create_finding(
                    node,
                    context,
                    severity="HIGH",
                    value=control_flow_count,
                    msg=f"Try block contains {control_flow_count} control flow statements. Don't wrap complex logic in error handling.",
                )
            )

        if findings:
            return findings
        return None

    def _create_finding(self, node, context, severity, value, msg):
        return {
            "rule_id": self.rule_id,
            "kind": "quality",
            "severity": severity,
            "type": "block",
            "name": "try",
            "simple_name": "try",
            "value": value,
            "threshold": 0,
            "message": msg,
            "file": context.get("filename"),
            "basename": Path(context.get("filename", "")).name,
            "line": node.lineno,
            "col": node.col_offset,
        }


class UnusedExceptVarRule(SkylosRule):
    rule_id = "SKY-L005"
    name = "Unused Exception Variable"

    def visit_node(self, node, context):
        if not isinstance(node, ast.ExceptHandler):
            return None
        if not node.name:
            return None

        use_count = 0
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id == node.name:
                use_count += 1

        if use_count == 0:
            return [
                {
                    "rule_id": self.rule_id,
                    "kind": "logic",
                    "severity": "LOW",
                    "type": "variable",
                    "name": node.name,
                    "simple_name": node.name,
                    "value": "unused",
                    "threshold": 0,
                    "message": f"Exception variable '{node.name}' is captured but never used. Use '_' or remove it.",
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            ]
        return None


def _annotation_allows_none(annotation) -> bool:
    if annotation is None:
        return False

    if isinstance(annotation, ast.Constant) and annotation.value is None:
        return True

    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        if _annotation_allows_none(annotation.left):
            return True
        if _annotation_allows_none(annotation.right):
            return True

    if isinstance(annotation, ast.Subscript):
        func = annotation.value
        name = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr

        if name in ("Optional",):
            return True

        if name in ("Union",):
            slice_node = annotation.slice
            if isinstance(slice_node, ast.Tuple):
                for elt in slice_node.elts:
                    if isinstance(elt, ast.Constant) and elt.value is None:
                        return True
                    if isinstance(elt, ast.Name) and elt.id == "None":
                        return True

    if isinstance(annotation, ast.Name) and annotation.id == "None":
        return True

    return False


class ReturnConsistencyRule(SkylosRule):
    rule_id = "SKY-L006"
    name = "Inconsistent Return"

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        if _annotation_allows_none(node.returns):
            return None

        returns_value = False
        returns_none = False

        for child in _walk_scope(node.body):
            if isinstance(child, ast.Return):
                if child.value is None:
                    returns_none = True
                elif (
                    isinstance(child.value, ast.Constant) and child.value.value is None
                ):
                    returns_none = True
                else:
                    returns_value = True

        if returns_value and returns_none:
            return [
                {
                    "rule_id": self.rule_id,
                    "kind": "logic",
                    "severity": "MEDIUM",
                    "type": "function",
                    "name": node.name,
                    "simple_name": node.name,
                    "value": "inconsistent",
                    "threshold": 0,
                    "message": f"Function '{node.name}' has inconsistent returns: some paths return a value, others return None.",
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            ]
        return None


_LOGGING_NAMES = {"logger", "logging", "log"}
_INTENTIONAL_EXCEPTIONS = {"KeyboardInterrupt", "SystemExit"}


def _is_logging_call(node):
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        func = node.value.func
        if isinstance(func, ast.Attribute):
            val = func.value
            if isinstance(val, ast.Name) and val.id in _LOGGING_NAMES:
                return True
    return False


def _is_reraise(node):
    if isinstance(node, ast.Raise):
        return True
    return False


def _handler_body_is_trivial(body):
    for stmt in body:
        if isinstance(stmt, ast.Pass):
            continue
        if isinstance(stmt, ast.Continue):
            continue
        if isinstance(stmt, ast.Expr):
            if isinstance(stmt.value, ast.Constant) and stmt.value.value is ...:
                continue
            if isinstance(stmt.value, ast.Constant) and isinstance(
                stmt.value.value, str
            ):
                continue
        if isinstance(stmt, ast.Return):
            if stmt.value is None:
                continue
            if isinstance(stmt.value, ast.Constant) and stmt.value.value is None:
                continue
        return False
    return True


def _handler_has_real_work(body):
    for stmt in body:
        if _is_logging_call(stmt):
            return True
        if _is_reraise(stmt):
            return True
    return False


def _exception_type_name(exc_type):
    if exc_type is None:
        return None
    if isinstance(exc_type, ast.Name):
        return exc_type.id
    if isinstance(exc_type, ast.Attribute):
        return exc_type.attr
    if isinstance(exc_type, ast.Tuple):
        names = []
        for elt in exc_type.elts:
            n = _exception_type_name(elt)
            if n:
                names.append(n)
        return ", ".join(names) if names else None
    return None


class EmptyErrorHandlerRule(SkylosRule):
    rule_id = "SKY-L007"
    name = "Empty Error Handler"

    def visit_node(self, node, context):
        findings = []

        if isinstance(node, ast.ExceptHandler):
            exc_name = _exception_type_name(node.type)
            if exc_name in _INTENTIONAL_EXCEPTIONS:
                return None

            if not node.body:
                findings.append(self._make_finding(node, context, "MEDIUM", "empty"))
            elif _handler_has_real_work(node.body):
                return None
            elif _handler_body_is_trivial(node.body):
                has_return = any(isinstance(s, ast.Return) for s in node.body)
                severity = "HIGH" if has_return else "MEDIUM"
                findings.append(self._make_finding(node, context, severity, "trivial"))

        if isinstance(node, ast.With):
            for item in node.items:
                ctx_expr = item.context_expr
                if isinstance(ctx_expr, ast.Call):
                    func = ctx_expr.func
                    is_suppress = False
                    if isinstance(func, ast.Attribute) and func.attr == "suppress":
                        if isinstance(func.value, ast.Name) and func.value.id == "contextlib":
                            is_suppress = True
                    if isinstance(func, ast.Name) and func.id == "suppress":
                        is_suppress = True

                    if is_suppress and ctx_expr.args:
                        for arg in ctx_expr.args:
                            arg_name = None
                            if isinstance(arg, ast.Name):
                                arg_name = arg.id
                            elif isinstance(arg, ast.Attribute):
                                arg_name = arg.attr
                            if arg_name in ("Exception", "BaseException"):
                                findings.append(
                                    {
                                        "rule_id": self.rule_id,
                                        "kind": "logic",
                                        "severity": "MEDIUM",
                                        "type": "block",
                                        "name": "suppress",
                                        "simple_name": "suppress",
                                        "value": "broad",
                                        "threshold": 0,
                                        "message": f"contextlib.suppress({arg_name}) silently swallows all errors.",
                                        "file": context.get("filename"),
                                        "basename": Path(context.get("filename", "")).name,
                                        "line": node.lineno,
                                        "col": node.col_offset,
                                    }
                                )

        return findings if findings else None

    def _make_finding(self, node, context, severity, value):
        return {
            "rule_id": self.rule_id,
            "kind": "logic",
            "severity": severity,
            "type": "block",
            "name": "except",
            "simple_name": "except",
            "value": value,
            "threshold": 0,
            "message": "Empty error handler silently swallows exceptions.",
            "file": context.get("filename"),
            "basename": Path(context.get("filename", "")).name,
            "line": node.lineno,
            "col": node.col_offset,
        }


RESOURCE_FUNCTIONS = {
    "open", "sqlite3.connect", "socket.socket",
    "requests.Session", "tempfile.NamedTemporaryFile",
    "tempfile.TemporaryFile", "tempfile.SpooledTemporaryFile",
    "psycopg2.connect", "pymysql.connect", "cx_Oracle.connect",
    "urllib3.PoolManager", "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
}

_RESOURCE_SIMPLE_NAMES = set()
_RESOURCE_ATTR_NAMES = {}

for _fn in RESOURCE_FUNCTIONS:
    if "." in _fn:
        parts = _fn.rsplit(".", 1)
        _RESOURCE_ATTR_NAMES.setdefault(parts[1], set()).add(parts[0])
    else:
        _RESOURCE_SIMPLE_NAMES.add(_fn)


def _call_matches_resource(call_node):
    func = call_node.func
    if isinstance(func, ast.Name) and func.id in _RESOURCE_SIMPLE_NAMES:
        return func.id
    if isinstance(func, ast.Attribute) and func.attr in _RESOURCE_ATTR_NAMES:
        if isinstance(func.value, ast.Name):
            expected_modules = _RESOURCE_ATTR_NAMES[func.attr]
            if func.value.id in expected_modules:
                return f"{func.value.id}.{func.attr}"
        if isinstance(func.value, ast.Attribute):
            parts = []
            node = func.value
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                parts.append(node.id)
            parts.reverse()
            full_mod = ".".join(parts)
            expected_modules = _RESOURCE_ATTR_NAMES[func.attr]
            if full_mod in expected_modules:
                return f"{full_mod}.{func.attr}"
    if isinstance(func, ast.Attribute) and func.attr == "open":
        if isinstance(func.value, ast.Call):
            inner = func.value.func
            if isinstance(inner, ast.Name) and inner.id == "Path":
                return "Path.open"
            if isinstance(inner, ast.Attribute) and inner.attr == "Path":
                return "Path.open"
        if isinstance(func.value, ast.Name):
            return None
    return None


class MissingResourceCleanupRule(SkylosRule):
    rule_id = "SKY-L008"
    name = "Missing Resource Cleanup"

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            return None

        filename = context.get("filename", "")
        basename = Path(filename).name
        if basename == "__enter__.py":
            return None

        body = node.body if hasattr(node, "body") else []
        findings = []

        for stmt in body:
            self._check_stmt(stmt, context, findings, body)

        return findings if findings else None

    def _check_stmt(self, stmt, context, findings, scope_body):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return

        if isinstance(stmt, ast.Try):
            for sub in stmt.body:
                self._check_stmt(sub, context, findings, scope_body)
            for sub in stmt.orelse:
                self._check_stmt(sub, context, findings, scope_body)
            return

        if isinstance(stmt, ast.Assign):
            if isinstance(stmt.value, ast.Call):
                resource_name = _call_matches_resource(stmt.value)
                if resource_name:
                    if not self._is_inside_with(stmt, scope_body):
                        var_name = self._get_assign_name(stmt)
                        if var_name:
                            if self._is_returned_or_yielded(var_name, scope_body):
                                return
                            if self._has_close_in_finally(var_name, scope_body):
                                return
                        findings.append(self._make_finding(stmt, context, resource_name))

        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            resource_name = _call_matches_resource(stmt.value)
            if resource_name:
                if not self._is_inside_with(stmt, scope_body):
                    findings.append(self._make_finding(stmt, context, resource_name))

        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(child, (ast.With, ast.AsyncWith)):
                continue
            if hasattr(child, "body") and isinstance(child.body, list):
                for sub in child.body:
                    self._check_stmt(sub, context, findings, scope_body)
            if hasattr(child, "orelse") and isinstance(child.orelse, list):
                for sub in child.orelse:
                    self._check_stmt(sub, context, findings, scope_body)

    def _is_inside_with(self, stmt, scope_body):
        for top_stmt in scope_body:
            if isinstance(top_stmt, (ast.With, ast.AsyncWith)):
                for node in ast.walk(top_stmt):
                    if node is stmt:
                        return True
        return False

    def _get_assign_name(self, assign_node):
        if assign_node.targets and isinstance(assign_node.targets[0], ast.Name):
            return assign_node.targets[0].id
        return None

    def _is_returned_or_yielded(self, var_name, scope_body):
        for node in ast.walk(ast.Module(body=scope_body, type_ignores=[])):
            if isinstance(node, ast.Return) and node.value:
                if isinstance(node.value, ast.Name) and node.value.id == var_name:
                    return True
            if isinstance(node, ast.Yield) and node.value:
                if isinstance(node.value, ast.Name) and node.value.id == var_name:
                    return True
        return False

    def _has_close_in_finally(self, var_name, scope_body):
        for stmt in scope_body:
            if isinstance(stmt, ast.Try) and stmt.finalbody:
                for final_stmt in stmt.finalbody:
                    for node in ast.walk(final_stmt):
                        if (
                            isinstance(node, ast.Call)
                            and isinstance(node.func, ast.Attribute)
                            and node.func.attr == "close"
                            and isinstance(node.func.value, ast.Name)
                            and node.func.value.id == var_name
                        ):
                            return True
        return False

    def _make_finding(self, node, context, resource_name):
        return {
            "rule_id": self.rule_id,
            "kind": "logic",
            "severity": "MEDIUM",
            "type": "resource",
            "name": resource_name,
            "simple_name": resource_name,
            "value": "no_cleanup",
            "threshold": 0,
            "message": f"Resource '{resource_name}' opened without 'with' statement. Use a context manager to ensure cleanup.",
            "file": context.get("filename"),
            "basename": Path(context.get("filename", "")).name,
            "line": node.lineno,
            "col": node.col_offset,
        }


DEBUG_FUNCTIONS = {"print", "pprint", "breakpoint", "ic"}
DEBUG_METHOD_CALLS = {
    ("pdb", "set_trace"),
    ("ipdb", "set_trace"),
    ("pudb", "set_trace"),
    ("code", "interact"),
    ("pprint", "pprint"),
}

_CLI_FILENAMES = {"cli.py", "__main__.py", "manage.py"}
_SKIP_DIRS = {"scripts", "bin", "tools"}


def _is_test_file(filename):
    base = Path(filename).name
    if base.startswith("test_") or base.endswith("_test.py") or base == "conftest.py":
        return True
    return False


def _is_cli_or_script(filename):
    p = Path(filename)
    if p.name in _CLI_FILENAMES:
        return True
    for part in p.parts:
        if part in _SKIP_DIRS:
            return True
    return False


class DebugLeftoverRule(SkylosRule):
    rule_id = "SKY-L009"
    name = "Debug Leftover"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Call):
            return None

        filename = context.get("filename", "")

        func = node.func
        func_name = None
        is_method = False
        method_obj = None

        if isinstance(func, ast.Name):
            func_name = func.id
        elif isinstance(func, ast.Attribute):
            func_name = func.attr
            is_method = True
            if isinstance(func.value, ast.Name):
                method_obj = func.value.id

        if not func_name:
            return None

        matched = False
        severity = "LOW"
        debug_name = func_name

        if not is_method and func_name in DEBUG_FUNCTIONS:
            matched = True
            if func_name in ("breakpoint", "ic"):
                severity = "HIGH"
            else:
                severity = "LOW"
            debug_name = func_name

        if is_method and method_obj:
            for obj, method in DEBUG_METHOD_CALLS:
                if method_obj == obj and func_name == method:
                    matched = True
                    severity = "HIGH"
                    debug_name = f"{obj}.{method}"
                    break

        if not matched:
            return None

        if func_name == "print" or (func_name == "pprint" and not is_method):
            if _is_cli_or_script(filename):
                return None
            if _is_test_file(filename):
                return None
            if self._has_main_guard(context):
                return None

        if func_name == "breakpoint" or debug_name.endswith("set_trace"):
            pass

        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": severity,
                "type": "call",
                "name": debug_name,
                "simple_name": debug_name,
                "value": "debug",
                "threshold": 0,
                "message": f"Debug leftover '{debug_name}()' found. Remove before shipping.",
                "file": filename,
                "basename": Path(filename).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]

    def _has_main_guard(self, context):
        return context.get("_has_main_guard", False)
