import ast
import re
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


def _exception_type_names(exc_type):
    if exc_type is None:
        return []
    if isinstance(exc_type, ast.Name):
        return [exc_type.id]
    if isinstance(exc_type, ast.Attribute):
        return [exc_type.attr]
    if isinstance(exc_type, ast.Tuple):
        names = []
        for elt in exc_type.elts:
            names.extend(_exception_type_names(elt))
        return names
    return []


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
                        if (
                            isinstance(func.value, ast.Name)
                            and func.value.id == "contextlib"
                        ):
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
                                        "basename": Path(
                                            context.get("filename", "")
                                        ).name,
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
    "open",
    "sqlite3.connect",
    "socket.socket",
    "requests.Session",
    "tempfile.NamedTemporaryFile",
    "tempfile.TemporaryFile",
    "tempfile.SpooledTemporaryFile",
    "psycopg2.connect",
    "pymysql.connect",
    "cx_Oracle.connect",
    "urllib3.PoolManager",
    "http.client.HTTPConnection",
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
                        findings.append(
                            self._make_finding(stmt, context, resource_name)
                        )

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


_SECURITY_TODO_RE = re.compile(
    r"#\s*(?:TODO|FIXME|HACK|XXX|TEMP)\b[:\s].*?"
    r"(?:auth|authenticat|authori[sz]|login|permission|credential|password|secret"
    r"|token|csrf|xss|inject|sanitiz|validat|escap|encrypt|decrypt|ssl|tls"
    r"|verify|cert|cors|session|cookie|jwt|oauth|api.?key|firewall"
    r"|rate.?limit|brute.?force|acl|rbac|security|vulnerable|exploit"
    r"|unsafe|insecure|disable|bypass|hack|workaround|temporary|fixme"
    r"|hardcod)",
    re.IGNORECASE,
)


class SecurityTodoRule(SkylosRule):
    rule_id = "SKY-L010"
    name = "Security TODO Marker"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Module):
            return None

        filename = context.get("filename", "")
        src = context.get("_source")
        if not src:
            try:
                src = Path(filename).read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return None

        findings = []
        for i, line in enumerate(src.splitlines(), start=1):
            m = _SECURITY_TODO_RE.search(line)
            if m:
                comment = m.group(0).strip()
                if len(comment) > 120:
                    comment = comment[:117] + "..."
                findings.append(
                    {
                        "rule_id": self.rule_id,
                        "kind": "logic",
                        "severity": "MEDIUM",
                        "type": "comment",
                        "name": "security_todo",
                        "simple_name": "security_todo",
                        "value": "unfulfilled",
                        "threshold": 0,
                        "message": f"Security-related TODO left in code: {comment}",
                        "file": filename,
                        "basename": Path(filename).name,
                        "line": i,
                        "col": m.start(),
                    }
                )

        return findings if findings else None


_DISABLED_SECURITY_PATTERNS = {
    "verify": "Requests TLS verification disabled (verify=False).",
    "check_hostname": "TLS hostname verification disabled (check_hostname=False).",
}

_DANGEROUS_CALLS = {
    "_create_unverified_context": "ssl._create_unverified_context() disables certificate verification.",
    "_create_default_https_context": None,
}

_DANGEROUS_DECORATORS = {
    "csrf_exempt": "CSRF protection disabled via @csrf_exempt.",
    "login_not_required": "Authentication bypassed via @login_not_required.",
}

_DANGEROUS_ASSIGNMENTS = {
    "DEBUG": (True, "DEBUG = True left in code. Disable in production."),
    "ALLOWED_HOSTS": (
        None,
        'ALLOWED_HOSTS contains wildcard "*". Restrict in production.',
    ),
    "SECRET_KEY": (None, None),
}


class DisabledSecurityRule(SkylosRule):
    rule_id = "SKY-L011"
    name = "Disabled Security Control"

    def visit_node(self, node, context):
        findings = []
        filename = context.get("filename", "")
        basename = Path(filename).name

        if _is_test_file(filename):
            return None

        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg in _DISABLED_SECURITY_PATTERNS:
                    if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        findings.append(
                            {
                                "rule_id": self.rule_id,
                                "kind": "logic",
                                "severity": "HIGH",
                                "type": "call",
                                "name": kw.arg,
                                "simple_name": kw.arg,
                                "value": "disabled",
                                "threshold": 0,
                                "message": _DISABLED_SECURITY_PATTERNS[kw.arg],
                                "file": filename,
                                "basename": basename,
                                "line": kw.value.lineno,
                                "col": kw.value.col_offset,
                            }
                        )

            func = node.func
            func_name = None
            if isinstance(func, ast.Attribute):
                func_name = func.attr
            elif isinstance(func, ast.Name):
                func_name = func.id
            if func_name in _DANGEROUS_CALLS:
                msg = _DANGEROUS_CALLS[func_name]
                if msg:
                    findings.append(
                        {
                            "rule_id": self.rule_id,
                            "kind": "logic",
                            "severity": "HIGH",
                            "type": "call",
                            "name": func_name,
                            "simple_name": func_name,
                            "value": "disabled",
                            "threshold": 0,
                            "message": msg,
                            "file": filename,
                            "basename": basename,
                            "line": node.lineno,
                            "col": node.col_offset,
                        }
                    )

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                dec_name = None
                if isinstance(dec, ast.Name):
                    dec_name = dec.id
                elif isinstance(dec, ast.Attribute):
                    dec_name = dec.attr
                if dec_name in _DANGEROUS_DECORATORS:
                    findings.append(
                        {
                            "rule_id": self.rule_id,
                            "kind": "logic",
                            "severity": "HIGH",
                            "type": "decorator",
                            "name": dec_name,
                            "simple_name": dec_name,
                            "value": "disabled",
                            "threshold": 0,
                            "message": _DANGEROUS_DECORATORS[dec_name],
                            "file": filename,
                            "basename": basename,
                            "line": dec.lineno,
                            "col": dec.col_offset,
                        }
                    )

        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in _DANGEROUS_ASSIGNMENTS:
                expected_val, msg = _DANGEROUS_ASSIGNMENTS[target.id]
                if msg is None:
                    pass
                elif target.id == "ALLOWED_HOSTS":
                    if isinstance(node.value, ast.List):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant) and elt.value == "*":
                                findings.append(
                                    {
                                        "rule_id": self.rule_id,
                                        "kind": "logic",
                                        "severity": "HIGH",
                                        "type": "assignment",
                                        "name": target.id,
                                        "simple_name": target.id,
                                        "value": "wildcard",
                                        "threshold": 0,
                                        "message": msg,
                                        "file": filename,
                                        "basename": basename,
                                        "line": node.lineno,
                                        "col": node.col_offset,
                                    }
                                )
                elif (
                    isinstance(node.value, ast.Constant)
                    and node.value.value == expected_val
                ):
                    findings.append(
                        {
                            "rule_id": self.rule_id,
                            "kind": "logic",
                            "severity": "MEDIUM",
                            "type": "assignment",
                            "name": target.id,
                            "simple_name": target.id,
                            "value": "insecure",
                            "threshold": 0,
                            "message": msg,
                            "file": filename,
                            "basename": basename,
                            "line": node.lineno,
                            "col": node.col_offset,
                        }
                    )

        return findings if findings else None


_PHANTOM_SECURITY_NAMES = {
    "sanitize_input",
    "sanitize_html",
    "sanitize_sql",
    "sanitize_query",
    "sanitize_string",
    "sanitize_data",
    "sanitize_url",
    "sanitize_path",
    "sanitize_output",
    "sanitize_request",
    "sanitize_params",
    "sanitize_user_input",
    "validate_token",
    "validate_jwt",
    "validate_session",
    "validate_auth",
    "validate_credentials",
    "validate_api_key",
    "escape_html",
    "escape_sql",
    "escape_input",
    "escape_output",
    "escape_string",
    "escape_query",
    "check_permission",
    "check_permissions",
    "check_auth",
    "check_authorization",
    "check_access",
    "check_role",
    "verify_token",
    "verify_jwt",
    "verify_signature",
    "verify_auth",
    "require_auth",
    "require_login",
    "require_permission",
    "encrypt_password",
    "hash_password",
    "secure_random",
    "clean_input",
    "clean_html",
    "clean_data",
    "filter_xss",
    "prevent_injection",
    "prevent_xss",
    "rate_limit",
    "throttle_request",
}


class PhantomCallRule(SkylosRule):
    rule_id = "SKY-L012"
    name = "Phantom Function Call"

    def __init__(self):
        self._defined_names = None
        self._current_file = None

    def visit_node(self, node, context):
        filename = context.get("filename", "")

        if isinstance(node, ast.Module):
            self._current_file = filename
            self._defined_names = set()
            self._imported_names = set()
            for child in ast.walk(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._defined_names.add(child.name)
                elif isinstance(child, ast.ClassDef):
                    self._defined_names.add(child.name)
                    for item in child.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            self._defined_names.add(item.name)
                elif isinstance(child, ast.ImportFrom):
                    if child.names:
                        for alias in child.names:
                            name = alias.asname if alias.asname else alias.name
                            self._imported_names.add(name)
                elif isinstance(child, ast.Import):
                    for alias in child.names:
                        name = alias.asname if alias.asname else alias.name
                        self._imported_names.add(name.split(".")[0])
            return None

        if self._defined_names is None:
            return None

        if not isinstance(node, ast.Call):
            return None

        func = node.func
        func_name = None

        if isinstance(func, ast.Name):
            func_name = func.id
        elif isinstance(func, ast.Attribute):
            return None

        if not func_name:
            return None

        if func_name not in _PHANTOM_SECURITY_NAMES:
            return None

        if func_name in self._defined_names:
            return None
        if func_name in self._imported_names:
            return None

        basename = Path(filename).name
        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "CRITICAL",
                "type": "call",
                "name": func_name,
                "simple_name": func_name,
                "value": "phantom",
                "threshold": 0,
                "message": (
                    f"Call to '{func_name}()' but this function is never defined or imported. "
                    f"AI-generated code often hallucinates security functions."
                ),
                "file": filename,
                "basename": basename,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]


_PHANTOM_SECURITY_DECORATORS = {
    "requires_auth",
    "require_auth",
    "require_login",
    "login_required",
    "require_permission",
    "require_permissions",
    "require_admin",
    "require_role",
    "check_auth",
    "check_access",
    "check_permission",
    "check_permissions",
    "authenticate",
    "authorize",
    "authorized",
    "validate_jwt",
    "verify_token",
    "verify_jwt",
    "rate_limit",
    "rate_limiter",
    "throttle",
    "throttle_request",
    "sanitize_input",
    "csrf_protect",
    "csrf_required",
    "cors_protect",
    "secure",
    "secured",
    "permissions_required",
    "roles_required",
    "roles_accepted",
    "auth_required",
    "token_required",
    "api_key_required",
}


class PhantomDecoratorRule(SkylosRule):
    rule_id = "SKY-L023"
    name = "Phantom Decorator"

    def __init__(self):
        self._defined_names = None
        self._imported_names = None
        self._current_file = None

    def visit_node(self, node, context):
        filename = context.get("filename", "")

        if isinstance(node, ast.Module):
            self._current_file = filename
            self._defined_names = set()
            self._imported_names = set()
            for child in ast.walk(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._defined_names.add(child.name)
                elif isinstance(child, ast.ClassDef):
                    self._defined_names.add(child.name)
                    for item in child.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            self._defined_names.add(item.name)
                elif isinstance(child, ast.ImportFrom):
                    if child.names:
                        for alias in child.names:
                            name = alias.asname if alias.asname else alias.name
                            self._imported_names.add(name)
                elif isinstance(child, ast.Import):
                    for alias in child.names:
                        name = alias.asname if alias.asname else alias.name
                        self._imported_names.add(name.split(".")[0])
            return None

        if self._defined_names is None:
            return None

        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return None

        findings = []
        for deco in node.decorator_list:
            deco_name = self._extract_decorator_name(deco)
            if not deco_name:
                continue
            if deco_name not in _PHANTOM_SECURITY_DECORATORS:
                continue
            if deco_name in self._defined_names:
                continue
            if deco_name in self._imported_names:
                continue

            basename = Path(filename).name
            findings.append(
                {
                    "rule_id": self.rule_id,
                    "kind": "logic",
                    "severity": "CRITICAL",
                    "type": "decorator",
                    "name": deco_name,
                    "simple_name": deco_name,
                    "value": "phantom",
                    "threshold": 0,
                    "message": (
                        f"Decorator '@{deco_name}' is used but never defined or imported. "
                        f"AI-generated code often hallucinates security decorators."
                    ),
                    "file": filename,
                    "basename": basename,
                    "line": deco.lineno,
                    "col": deco.col_offset,
                    "vibe_category": "hallucinated_reference",
                    "ai_likelihood": "high",
                }
            )

        return findings if findings else None

    @staticmethod
    def _extract_decorator_name(deco):
        if isinstance(deco, ast.Call):
            return PhantomDecoratorRule._extract_decorator_name(deco.func)
        if isinstance(deco, ast.Name):
            return deco.id
        if isinstance(deco, ast.Attribute):
            return None
        return None


class UnfinishedGenerationRule(SkylosRule):
    rule_id = "SKY-L026"
    name = "Unfinished Generation"

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        filename = context.get("filename", "")

        for deco in node.decorator_list:
            deco_name = None
            if isinstance(deco, ast.Name):
                deco_name = deco.id
            elif isinstance(deco, ast.Attribute):
                deco_name = deco.attr
            if deco_name in ("abstractmethod", "overload"):
                return None

        basename = Path(filename).name
        if basename == "__init__.py":
            return None
        if basename.startswith("test_") or basename.startswith("conftest"):
            return None

        if node.name.startswith("__") and node.name.endswith("__"):
            return None

        body = node.body
        if not body:
            return None

        stmts = body
        if isinstance(body[0], ast.Expr) and isinstance(
            body[0].value, (ast.Constant, ast.Str)
        ):
            val = body[0].value
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                stmts = body[1:]
            elif isinstance(val, ast.Str):
                stmts = body[1:]

        if not stmts:
            return None

        if len(stmts) != 1:
            return None

        stmt = stmts[0]
        marker = None
        marker_line = stmt.lineno

        if isinstance(stmt, ast.Pass):
            marker = "pass"
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            if stmt.value.value is ...:
                marker = "..."
        elif isinstance(stmt, ast.Raise):
            exc = stmt.exc
            if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name):
                if exc.func.id == "NotImplementedError":
                    marker = "NotImplementedError"
            elif isinstance(exc, ast.Name) and exc.id == "NotImplementedError":
                marker = "NotImplementedError"

        if not marker:
            return None

        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "MEDIUM",
                "type": "function",
                "name": node.name,
                "simple_name": node.name,
                "value": marker,
                "threshold": 0,
                "message": (
                    f"Function '{node.name}' has only `{marker}` in its body. "
                    f"AI-generated code often leaves stub implementations that "
                    f"silently do nothing in production."
                ),
                "file": filename,
                "basename": basename,
                "line": marker_line,
                "col": stmt.col_offset,
                "vibe_category": "incomplete_generation",
                "ai_likelihood": "medium",
            }
        ]


class UndefinedConfigRule(SkylosRule):
    rule_id = "SKY-L016"
    name = "Undefined Config"

    def __init__(self):
        self._env_refs = None
        self._env_sets = None
        self._current_file = None

    def visit_node(self, node, context):
        filename = context.get("filename", "")

        if isinstance(node, ast.Module):
            self._current_file = filename
            self._env_refs = []
            self._env_sets = set()
            for child in ast.walk(node):
                if isinstance(child, ast.Subscript):
                    if (
                        isinstance(child.value, ast.Attribute)
                        and isinstance(child.value.value, ast.Name)
                        and child.value.value.id == "os"
                        and child.value.attr == "environ"
                    ):
                        if isinstance(child.slice, ast.Constant) and isinstance(
                            child.slice.value, str
                        ):
                            self._env_sets.add(child.slice.value)
            return None

        if self._env_refs is None:
            return None

        if not isinstance(node, ast.Call):
            return None

        env_var_name = self._extract_env_var(node)
        if not env_var_name:
            return None

        if env_var_name in _WELL_KNOWN_ENV_VARS:
            return None

        if env_var_name in self._env_sets:
            return None

        upper = env_var_name.upper()
        is_flag = any(
            upper.startswith(p)
            for p in ("ENABLE_", "DISABLE_", "USE_", "FEATURE_", "FLAG_", "TOGGLE_")
        )

        if not is_flag:
            return None

        basename = Path(filename).name
        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "MEDIUM",
                "type": "call",
                "name": env_var_name,
                "simple_name": env_var_name,
                "value": "undefined",
                "threshold": 0,
                "message": (
                    f"Feature flag '{env_var_name}' is checked but never defined in this file. "
                    f"AI-generated code often references configuration that was never set up."
                ),
                "file": filename,
                "basename": basename,
                "line": node.lineno,
                "col": node.col_offset,
                "vibe_category": "ghost_config",
                "ai_likelihood": "medium",
            }
        ]

    @staticmethod
    def _extract_env_var(node):
        func = node.func
        if isinstance(func, ast.Attribute):
            if (
                func.attr == "getenv"
                and isinstance(func.value, ast.Name)
                and func.value.id == "os"
            ):
                if node.args and isinstance(node.args[0], ast.Constant):
                    return node.args[0].value
            if (
                func.attr == "get"
                and isinstance(func.value, ast.Attribute)
                and func.value.attr == "environ"
                and isinstance(func.value.value, ast.Name)
                and func.value.value.id == "os"
            ):
                if node.args and isinstance(node.args[0], ast.Constant):
                    return node.args[0].value
        return None


_WELL_KNOWN_ENV_VARS = {
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "LANG",
    "TERM",
    "PWD",
    "EDITOR",
    "VIRTUAL_ENV",
    "PYTHONPATH",
    "PYTHONDONTWRITEBYTECODE",
    "CI",
    "DEBUG",
    "LOG_LEVEL",
    "TESTING",
    "DATABASE_URL",
    "REDIS_URL",
    "SECRET_KEY",
    "PORT",
    "HOST",
    "BIND",
}


class StaleMockRule(SkylosRule):
    rule_id = "SKY-L024"
    name = "Stale Mock"

    def __init__(self):
        self._current_file = None
        self._is_test = False

    def visit_node(self, node, context):
        filename = context.get("filename", "")

        if isinstance(node, ast.Module):
            self._current_file = filename
            basename = Path(filename).name
            self._is_test = basename.startswith("test_") or basename.startswith(
                "conftest"
            )
            return None

        if not self._is_test:
            return None

        target_str = None
        target_node = None

        if isinstance(node, ast.Call):
            target_str, target_node = self._extract_patch_target(node)

        if not target_str or not target_node:
            return None

        parts = target_str.split(".")
        if len(parts) < 2:
            return None

        attr_name = parts[-1]
        module_parts = parts[:-1]

        project_root = self._find_project_root(filename)
        if not project_root:
            return None

        module_file = self._resolve_module(project_root, module_parts)
        if not module_file:
            return None

        try:
            source = module_file.read_text(errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            return None

        defined_names = set()
        for child in ast.walk(tree):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defined_names.add(child.name)
            elif isinstance(child, ast.ClassDef):
                defined_names.add(child.name)
            elif isinstance(child, ast.Assign):
                for t in child.targets:
                    if isinstance(t, ast.Name):
                        defined_names.add(t.id)
            elif isinstance(child, ast.ImportFrom):
                if child.names:
                    for alias in child.names:
                        name = alias.asname if alias.asname else alias.name
                        defined_names.add(name)
            elif isinstance(child, ast.Import):
                for alias in child.names:
                    name = alias.asname if alias.asname else alias.name
                    defined_names.add(name.split(".")[0])

        if attr_name in defined_names:
            return None

        basename = Path(filename).name
        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "HIGH",
                "type": "mock",
                "name": target_str,
                "simple_name": attr_name,
                "value": "stale",
                "threshold": 0,
                "message": (
                    f"mock.patch('{target_str}') references '{attr_name}' "
                    f"but it does not exist in '{'.'.join(module_parts)}'. "
                    f"The function may have been renamed or removed, "
                    f"making this mock silently ineffective."
                ),
                "file": filename,
                "basename": basename,
                "line": target_node.lineno,
                "col": target_node.col_offset,
                "vibe_category": "stale_reference",
                "ai_likelihood": "medium",
            }
        ]

    @staticmethod
    def _extract_patch_target(call_node):
        func = call_node.func

        is_patch = False
        if isinstance(func, ast.Attribute) and func.attr == "patch":
            is_patch = True
        elif isinstance(func, ast.Name) and func.id == "patch":
            is_patch = True
        elif isinstance(func, ast.Attribute) and func.attr == "object":
            return None, None

        if not is_patch:
            return None, None

        if call_node.args and isinstance(call_node.args[0], ast.Constant):
            if isinstance(call_node.args[0].value, str):
                return call_node.args[0].value, call_node
        return None, None

    @staticmethod
    def _find_project_root(filepath):
        p = Path(filepath).resolve().parent
        for _ in range(20):
            if (p / "pyproject.toml").exists():
                return p
            if (p / "setup.py").exists():
                return p
            if (p / ".git").exists():
                return p
            parent = p.parent
            if parent == p:
                break
            p = parent
        return None

    @staticmethod
    def _resolve_module(project_root, module_parts):
        pkg_path = project_root / "/".join(module_parts) / "__init__.py"
        if pkg_path.is_file():
            return pkg_path

        mod_path = (
            project_root / "/".join(module_parts[:-1]) / (module_parts[-1] + ".py")
            if len(module_parts) > 1
            else project_root / (module_parts[0] + ".py")
        )
        if mod_path.is_file():
            return mod_path

        if len(module_parts) >= 2:
            flat_path = project_root / ("/".join(module_parts) + ".py")
            if Path(flat_path).is_file():
                return Path(flat_path)

        direct = project_root / ("/".join(module_parts) + ".py")
        if Path(direct).is_file():
            return Path(direct)

        return None


_SECURITY_VAR_KEYWORDS = {
    "token",
    "secret",
    "key",
    "password",
    "nonce",
    "session",
    "otp",
    "salt",
    "csrf",
    "auth",
    "code",
    "pin",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "reset_token",
    "verification",
    "confirm",
}

_INSECURE_RANDOM_FUNCS = {
    "randint",
    "choice",
    "choices",
    "random",
    "randrange",
    "sample",
    "shuffle",
    "randbytes",
    "getrandbits",
    "uniform",
}


def _var_name_is_security(name):
    lower = name.lower()
    for kw in _SECURITY_VAR_KEYWORDS:
        if kw in lower:
            return True
    return False


class InsecureRandomRule(SkylosRule):
    rule_id = "SKY-L013"
    name = "Insecure Randomness"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Assign):
            return None

        filename = context.get("filename", "")
        if _is_test_file(filename):
            return None

        call = node.value
        if not isinstance(call, ast.Call):
            return None

        func = call.func
        func_name = None
        is_random_module = False

        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name) and func.value.id == "random":
                if func.attr in _INSECURE_RANDOM_FUNCS:
                    func_name = f"random.{func.attr}"
                    is_random_module = True
        elif isinstance(func, ast.Name):
            if func.id in _INSECURE_RANDOM_FUNCS:
                func_name = func.id

        if not func_name or not is_random_module:
            return None

        for target in node.targets:
            var_name = None
            if isinstance(target, ast.Name):
                var_name = target.id
            elif isinstance(target, ast.Attribute):
                var_name = target.attr
            elif isinstance(target, ast.Subscript) and isinstance(
                target.value, ast.Name
            ):
                var_name = target.value.id

            if var_name and _var_name_is_security(var_name):
                basename = Path(filename).name
                return [
                    {
                        "rule_id": self.rule_id,
                        "kind": "logic",
                        "severity": "HIGH",
                        "type": "call",
                        "name": func_name,
                        "simple_name": func_name,
                        "value": "insecure_random",
                        "threshold": 0,
                        "message": (
                            f"'{func_name}()' used for security-sensitive value '{var_name}'. "
                            f"Use 'secrets' module instead (e.g. secrets.token_urlsafe())."
                        ),
                        "file": filename,
                        "basename": basename,
                        "line": node.lineno,
                        "col": node.col_offset,
                    }
                ]

        return None


_CREDENTIAL_VAR_NAMES = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "auth_token",
    "access_token",
    "refresh_token",
    "db_password",
    "database_url",
    "connection_string",
    "db_url",
    "dsn",
    "private_key",
    "secret_key",
    "encryption_key",
    "signing_key",
    "client_secret",
    "app_secret",
}

_CREDENTIAL_VAR_SUFFIXES = {
    "_password",
    "_passwd",
    "_secret",
    "_token",
    "_key",
    "_api_key",
    "_apikey",
}

_CREDENTIAL_DSN_RE = re.compile(
    r"[a-zA-Z][a-zA-Z0-9+.-]*://[^:]+:[^@]+@",
)

_PLACEHOLDER_VALUES = {
    "changeme",
    "your_api_key_here",
    "replace_me",
    "todo",
    "xxx",
    "yyy",
    "zzz",
    "placeholder",
    "example",
    "test",
    "dummy",
    "fake",
    "sample",
    "your_password_here",
    "insert_key_here",
    "your_secret_here",
}


def _is_credential_var(name):
    lower = name.lower()
    if lower in _CREDENTIAL_VAR_NAMES:
        return True
    for suffix in _CREDENTIAL_VAR_SUFFIXES:
        if lower.endswith(suffix):
            return True
    return False


def _is_env_lookup(node):
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                if func.value.id == "os" and func.attr in ("getenv", "environ"):
                    return True
            if isinstance(func.value, ast.Attribute):
                if hasattr(func.value, "attr") and func.value.attr == "environ":
                    return True
        if isinstance(func, ast.Name) and func.id == "getenv":
            return True
    if isinstance(func if isinstance(node, ast.Call) else node, ast.Subscript):
        val = node.value if isinstance(node, ast.Subscript) else None
        if val and isinstance(val, ast.Attribute):
            if hasattr(val, "attr") and val.attr == "environ":
                return True
    return False


class HardcodedCredentialRule(SkylosRule):
    rule_id = "SKY-L014"
    name = "Hardcoded Credential"

    def visit_node(self, node, context):
        filename = context.get("filename", "")
        if _is_test_file(filename):
            return None

        findings = []
        basename = Path(filename).name

        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            var_name = None
            if isinstance(target, ast.Name):
                var_name = target.id
            elif isinstance(target, ast.Attribute):
                var_name = target.attr

            if var_name and _is_credential_var(var_name):
                value = node.value
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    str_val = value.value
                    if not str_val or str_val.strip() == "":
                        return None
                    try:
                        if _is_env_lookup(value):
                            return None
                    except Exception:
                        pass

                    severity = "HIGH"
                    if str_val.lower() in _PLACEHOLDER_VALUES:
                        severity = "MEDIUM"

                    findings.append(
                        {
                            "rule_id": self.rule_id,
                            "kind": "logic",
                            "severity": severity,
                            "type": "assignment",
                            "name": var_name,
                            "simple_name": var_name,
                            "value": "hardcoded",
                            "threshold": 0,
                            "message": (
                                f"Hardcoded credential in '{var_name}'. "
                                f"Use environment variables or a secrets manager instead."
                            ),
                            "file": filename,
                            "basename": basename,
                            "line": node.lineno,
                            "col": node.col_offset,
                        }
                    )

                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    if _CREDENTIAL_DSN_RE.search(value.value):
                        findings.append(
                            {
                                "rule_id": self.rule_id,
                                "kind": "logic",
                                "severity": "HIGH",
                                "type": "assignment",
                                "name": var_name,
                                "simple_name": var_name,
                                "value": "hardcoded_dsn",
                                "threshold": 0,
                                "message": (
                                    f"Connection string in '{var_name}' contains embedded credentials. "
                                    f"Use environment variables for database URLs."
                                ),
                                "file": filename,
                                "basename": basename,
                                "line": node.lineno,
                                "col": node.col_offset,
                            }
                        )

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg, default in _iter_arg_defaults(node):
                if hasattr(arg, "arg"):
                    arg_name = arg.arg
                else:
                    arg_name = str(arg)

                if _is_credential_var(arg_name):
                    if isinstance(default, ast.Constant) and isinstance(
                        default.value, str
                    ):
                        str_val = default.value
                        if str_val and str_val.strip():
                            severity = "HIGH"
                            if str_val.lower() in _PLACEHOLDER_VALUES:
                                severity = "MEDIUM"
                            findings.append(
                                {
                                    "rule_id": self.rule_id,
                                    "kind": "logic",
                                    "severity": severity,
                                    "type": "default",
                                    "name": arg_name,
                                    "simple_name": arg_name,
                                    "value": "hardcoded_default",
                                    "threshold": 0,
                                    "message": (
                                        f"Hardcoded credential in default argument '{arg_name}'. "
                                        f"Use environment variables or None with runtime lookup."
                                    ),
                                    "file": filename,
                                    "basename": basename,
                                    "line": default.lineno,
                                    "col": default.col_offset,
                                }
                            )

        return findings if findings else None


def _iter_arg_defaults(func_node):
    args = func_node.args
    num_defaults = len(args.defaults)
    num_args = len(args.args)
    offset = num_args - num_defaults

    for i, default in enumerate(args.defaults):
        if default:
            yield args.args[offset + i], default
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        if default:
            yield arg, default


_HTTP_RESPONSE_CONSTRUCTORS = {
    "JsonResponse",
    "jsonify",
    "Response",
    "HTMLResponse",
    "JSONResponse",
    "PlainTextResponse",
    "make_response",
    "HttpResponse",
    "HttpResponseBadRequest",
    "HttpResponseServerError",
}

_HTTP_RETURN_KEYS = {"error", "message", "detail", "msg", "reason"}


class ErrorDisclosureRule(SkylosRule):
    rule_id = "SKY-L017"
    name = "Error Information Disclosure"

    def visit_node(self, node, context):
        if not isinstance(node, ast.ExceptHandler):
            return None

        filename = context.get("filename", "")
        if _is_test_file(filename):
            return None

        exc_var = node.name
        if not exc_var:
            return None

        findings = []
        basename = Path(filename).name

        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value:
                self._check_disclosure(
                    child.value, exc_var, child, filename, basename, findings
                )

            if isinstance(child, ast.Call):
                func = child.func
                func_name = None
                if isinstance(func, ast.Name):
                    func_name = func.id
                elif isinstance(func, ast.Attribute):
                    func_name = func.attr
                if func_name in _HTTP_RESPONSE_CONSTRUCTORS:
                    for arg in child.args:
                        self._check_disclosure(
                            arg, exc_var, child, filename, basename, findings
                        )
                    for kw in child.keywords:
                        self._check_disclosure(
                            kw.value, exc_var, child, filename, basename, findings
                        )

        return findings if findings else None

    def _check_disclosure(
        self, value_node, exc_var, report_node, filename, basename, findings
    ):
        if self._is_exc_stringification(value_node, exc_var):
            findings.append(
                self._make_finding(report_node, filename, basename, exc_var)
            )
            return

        if isinstance(value_node, ast.Dict):
            for k, v in zip(value_node.keys, value_node.values):
                if k and isinstance(k, ast.Constant) and isinstance(k.value, str):
                    if k.value.lower() in _HTTP_RETURN_KEYS:
                        if self._is_exc_stringification(v, exc_var):
                            findings.append(
                                self._make_finding(
                                    report_node, filename, basename, exc_var
                                )
                            )
                            return

        if isinstance(value_node, ast.JoinedStr):
            for val in value_node.values:
                if isinstance(val, ast.FormattedValue):
                    if self._is_exc_stringification(val.value, exc_var):
                        findings.append(
                            self._make_finding(report_node, filename, basename, exc_var)
                        )
                        return
                    if isinstance(val.value, ast.Name) and val.value.id == exc_var:
                        findings.append(
                            self._make_finding(report_node, filename, basename, exc_var)
                        )
                        return

    def _is_exc_stringification(self, node, exc_var):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in ("str", "repr"):
                if node.args and isinstance(node.args[0], ast.Name):
                    if node.args[0].id == exc_var:
                        return True

            if isinstance(func, ast.Attribute) and func.attr == "format_exc":
                if isinstance(func.value, ast.Name) and func.value.id == "traceback":
                    return True

        if isinstance(node, ast.Name) and node.id == exc_var:
            return True
        return False

    def _make_finding(self, node, filename, basename, exc_var):
        return {
            "rule_id": self.rule_id,
            "kind": "logic",
            "severity": "MEDIUM",
            "type": "block",
            "name": "error_disclosure",
            "simple_name": "error_disclosure",
            "value": "exception_leaked",
            "threshold": 0,
            "message": (
                f"Exception details ('{exc_var}') returned in HTTP response. "
                f"This exposes internal stack traces to attackers. Return a generic error message instead."
            ),
            "file": filename,
            "basename": basename,
            "line": node.lineno,
            "col": node.col_offset,
        }


_SENSITIVE_FILE_KEYWORDS = {
    ".env",
    ".pem",
    ".key",
    ".cert",
    ".crt",
    ".p12",
    ".pfx",
    "credentials",
    "secrets",
    "private",
    "id_rsa",
    "id_ed25519",
    "keyfile",
    "keystore",
}


def _is_sensitive_filename(name):
    lower = name.lower()
    for kw in _SENSITIVE_FILE_KEYWORDS:
        if kw in lower:
            return True
    return False


class BroadFilePermissionsRule(SkylosRule):
    rule_id = "SKY-L020"
    name = "Overly Broad File Permissions"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Call):
            return None

        filename = context.get("filename", "")
        if _is_test_file(filename):
            return None

        func = node.func
        func_name = None

        if isinstance(func, ast.Attribute) and func.attr == "chmod":
            if isinstance(func.value, ast.Name) and func.value.id == "os":
                func_name = "os.chmod"

        if func_name != "os.chmod":
            return None

        if len(node.args) < 2:
            return None

        mode_node = node.args[1]
        mode_val = None

        if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, int):
            mode_val = mode_node.value

        if mode_val is None:
            return None

        basename = Path(filename).name

        path_arg = node.args[0]
        target_name = ""
        if isinstance(path_arg, ast.Constant) and isinstance(path_arg.value, str):
            target_name = path_arg.value
        elif isinstance(path_arg, ast.Name):
            target_name = path_arg.id

        is_sensitive = _is_sensitive_filename(target_name)

        if mode_val & 0o777 == 0o777:
            return [
                self._make_finding(
                    node,
                    filename,
                    basename,
                    mode_val,
                    "HIGH",
                    f"os.chmod() with mode {oct(mode_val)} grants full access to all users.",
                )
            ]

        if mode_val & 0o002:
            return [
                self._make_finding(
                    node,
                    filename,
                    basename,
                    mode_val,
                    "HIGH",
                    f"os.chmod() with mode {oct(mode_val)} is world-writable.",
                )
            ]

        if is_sensitive and mode_val & 0o077:
            return [
                self._make_finding(
                    node,
                    filename,
                    basename,
                    mode_val,
                    "HIGH",
                    f"os.chmod() with mode {oct(mode_val)} on sensitive file. Use 0o600 for private keys and credentials.",
                )
            ]

        return None

    def _make_finding(self, node, filename, basename, mode_val, severity, message):
        return {
            "rule_id": self.rule_id,
            "kind": "logic",
            "severity": severity,
            "type": "call",
            "name": "os.chmod",
            "simple_name": "os.chmod",
            "value": oct(mode_val),
            "threshold": 0,
            "message": message,
            "file": filename,
            "basename": basename,
            "line": node.lineno,
            "col": node.col_offset,
        }


class DuplicateStringLiteralRule(SkylosRule):
    rule_id = "SKY-L027"
    name = "Duplicate String Literal"

    def __init__(self, threshold=3):
        self.threshold = threshold

    def _is_docstring(self, node, parent_map):
        parent = parent_map.get(id(node))
        if parent is None:
            return False
        if isinstance(parent, ast.Expr):
            grandparent = parent_map.get(id(parent))
            if grandparent is not None and isinstance(
                grandparent,
                (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
            ):
                body = grandparent.body
                if body and body[0] is parent:
                    return True
        return False

    def visit_node(self, node, context):
        if not isinstance(node, ast.Module):
            return None

        filename = context.get("filename", "")
        basename = Path(filename).name

        if basename.startswith("test_") or basename.endswith("_test.py"):
            return None

        parent_map = {}
        for parent in ast.walk(node):
            for child in ast.iter_child_nodes(parent):
                parent_map[id(child)] = parent

        string_occurrences = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if len(child.value) < 5:
                    continue
                if self._is_docstring(child, parent_map):
                    continue
                key = child.value
                if key not in string_occurrences:
                    string_occurrences[key] = []
                string_occurrences[key].append(child)

        findings = []
        for value, nodes in string_occurrences.items():
            count = len(nodes)
            if count < self.threshold:
                continue
            severity = "MEDIUM" if count >= 6 else "LOW"
            display = value if len(value) <= 40 else value[:37] + "..."
            findings.append(
                {
                    "rule_id": self.rule_id,
                    "kind": "quality",
                    "severity": severity,
                    "type": "string",
                    "name": display,
                    "simple_name": display,
                    "value": count,
                    "threshold": self.threshold,
                    "message": f"String literal '{display}' repeated {count} times (threshold: {self.threshold}).",
                    "file": filename,
                    "basename": basename,
                    "line": nodes[0].lineno,
                    "col": nodes[0].col_offset,
                }
            )

        return findings if findings else None


class TooManyReturnsRule(SkylosRule):
    rule_id = "SKY-L028"
    name = "Too Many Returns"

    def __init__(self, threshold=5):
        self.threshold = threshold

    def _count_returns(self, func_node):
        count = 0
        stack = list(func_node.body)
        while stack:
            child = stack.pop()
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(child, ast.Return):
                count += 1
            for attr in ("body", "orelse", "finalbody", "handlers"):
                block = getattr(child, attr, None)
                if block and isinstance(block, list):
                    stack.extend(block)
        return count

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        count = self._count_returns(node)
        if count < self.threshold:
            return None

        severity = "MEDIUM" if count >= 9 else "LOW"
        filename = context.get("filename", "")

        return [
            {
                "rule_id": self.rule_id,
                "kind": "structure",
                "severity": severity,
                "type": "function",
                "name": node.name,
                "simple_name": node.name,
                "value": count,
                "threshold": self.threshold,
                "message": f"Function has {count} return statements (limit: {self.threshold}). Consider simplifying control flow.",
                "file": filename,
                "basename": Path(filename).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]


_BOOLEAN_TRAP_ALLOWED_NAMES = {
    "inplace",
    "reverse",
    "recursive",
    "verbose",
    "debug",
    "force",
    "dry_run",
    "strict",
}


class BooleanTrapRule(SkylosRule):
    rule_id = "SKY-L029"
    name = "Boolean Trap"

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        func_name = node.name
        if func_name.startswith("__") and func_name.endswith("__"):
            return None

        args = node.args
        positional_args = args.args

        num_defaults = len(args.defaults)
        num_positional = len(positional_args)

        findings = []
        filename = context.get("filename", "")

        for i, arg in enumerate(positional_args):
            arg_name = arg.arg
            if arg_name in ("self", "cls"):
                continue
            if arg_name in _BOOLEAN_TRAP_ALLOWED_NAMES:
                continue

            is_bool_trap = False

            if arg.annotation is not None:
                if isinstance(arg.annotation, ast.Name) and arg.annotation.id == "bool":
                    is_bool_trap = True
                elif (
                    isinstance(arg.annotation, ast.Constant)
                    and arg.annotation.value == "bool"
                ):
                    is_bool_trap = True

            if not is_bool_trap and num_defaults > 0:
                default_index = i - (num_positional - num_defaults)
                if 0 <= default_index < num_defaults:
                    default = args.defaults[default_index]
                    if isinstance(default, ast.Constant) and isinstance(
                        default.value, bool
                    ):
                        is_bool_trap = True

            if is_bool_trap:
                findings.append(
                    {
                        "rule_id": self.rule_id,
                        "kind": "quality",
                        "severity": "LOW",
                        "type": "function",
                        "name": f"{func_name}.{arg_name}",
                        "simple_name": arg_name,
                        "value": arg_name,
                        "threshold": 0,
                        "message": f"Boolean positional parameter '{arg_name}' is a readability trap. Use keyword-only arguments instead.",
                        "file": filename,
                        "basename": Path(filename).name,
                        "line": arg.lineno if hasattr(arg, "lineno") else node.lineno,
                        "col": arg.col_offset
                        if hasattr(arg, "col_offset")
                        else node.col_offset,
                    }
                )

        return findings if findings else None


class BroadExceptionRule(SkylosRule):
    rule_id = "SKY-L030"
    name = "Broad Exception with Trivial Handler"

    _BROAD_EXCEPTION_TYPES = {"Exception", "BaseException"}

    def visit_node(self, node, context):
        if not isinstance(node, ast.ExceptHandler) or node.type is None:
            return None

        broad_types = [
            exc_name
            for exc_name in _exception_type_names(node.type)
            if exc_name in self._BROAD_EXCEPTION_TYPES
        ]
        if not broad_types:
            return None
        if _handler_has_real_work(node.body):
            return None
        if not _handler_body_is_trivial(node.body):
            return None

        exc_name = ", ".join(sorted(set(broad_types)))

        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "MEDIUM",
                "type": "block",
                "name": "except",
                "simple_name": "except",
                "value": "broad",
                "threshold": 0,
                "message": f"Catching broad '{exc_name}' with a trivial handler silently hides bugs. Narrow the exception type or add logging/re-raise.",
                "file": context.get("filename"),
                "basename": Path(context.get("filename", "")).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]
