"""Conditional urllib scheme audit, separate from attacker-proven SSRF.

Uses the SSRF visitor's import, local-binding, Request and dominance evidence.
Unknown URLs merit review because urllib also handles file/data/FTP URLs;
this does not assert that an attacker controls the URL.
"""

from __future__ import annotations

import ast

from skylos.rules.danger.module_namespace import (
    attribute_write_names,
    has_mock_api_patching,
)


def _text(node):
    return (
        node.value
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        else None
    )


def _name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name(node.value)
        return f"{prefix}.{node.attr}" if prefix else None
    return None


def _module_literal_value(checker, expr, at):
    """An earlier, unconditionally assigned module string or literal alias."""
    if checker._name_is_local(expr.id, expr) or not checker._module_global_is_stable(
        expr.id
    ):
        return None, None
    writes, computed = _api_writes(checker)
    if computed or expr.id in writes:
        return None, None
    value = checker._module_scope.values.get(expr.id)
    if _text(value) is None and not isinstance(value, ast.Name):
        return None, None
    statement = checker.parents.get(id(value))
    if (
        not isinstance(statement, (ast.Assign, ast.AnnAssign))
        or checker.parents.get(id(statement)) is not checker.tree
        or statement.lineno >= at.lineno
    ):
        return None, None
    return value, statement


def _fixed_scheme(checker, expr, at, depth=0):
    if depth > 5:
        return False
    # A literal URL explicitly chooses the resource; audit only dynamic schemes.
    if _text(expr) is not None:
        return True
    if isinstance(expr, ast.JoinedStr) and expr.values:
        prefix = _text(expr.values[0])
        return prefix is not None and prefix.lower().startswith(("http://", "https://"))
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        prefix = _text(expr.left)
        # An unknown object can replace the whole string via __radd__.
        return prefix is not None and _text(expr.right) is not None
    func = checker._current_function()
    if isinstance(expr, ast.Name):
        value, statement = (None, None)
        if func is not None:
            value, statement = checker._single_local_value(expr, func, at)
        if value is None:
            value, statement = _module_literal_value(checker, expr, at)
        if value is not None:
            return _fixed_scheme(checker, value, statement, depth + 1)
    return False


def _allowed_literals(expr, *, prefixes=False):
    values = expr.elts if isinstance(expr, (ast.Tuple, ast.List, ast.Set)) else [expr]
    allowed = {"http://", "https://"} if prefixes else {"http", "https"}
    return bool(values) and all(_text(value) in allowed for value in values)


def _normalization_result_stable(checker):
    """Decline new string-method proof when native result capability escapes.

    Parser identity alone does not protect a mutable result class's scheme
    descriptor. Track syntactic capability origins, not arbitrary objects
    that happen to have a scheme attribute.
    """
    cached = getattr(checker, "_url_scheme_normalization_stable", None)
    if cached is not None:
        return cached
    checker._url_scheme_normalization_stable = False
    nodes = list(ast.walk(checker.tree))
    imports = {}
    result_types = {
        "ParseResult",
        "SplitResult",
        "ParseResultBytes",
        "SplitResultBytes",
        "_ParseResultBase",
        "_SplitResultBase",
    }
    for node in nodes:
        if isinstance(node, ast.ImportFrom) and any(
            alias.name == "*" for alias in node.names
        ):
            return False
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.setdefault(alias.asname or alias.name.split(".")[0], set()).add(
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                if node.module == "urllib.parse" and (
                    alias.name in result_types
                    or alias.name.startswith(("_ResultMixin", "_NetlocResultMixin"))
                ):
                    return False
                imports.setdefault(alias.asname or alias.name, set()).add(
                    node.module + "." + alias.name
                )

    module, parser, result, exposed = 1, 2, 4, 8
    result_names = set()

    def qualified(expr, depth=0):
        if depth >= 12:
            return set()
        if isinstance(expr, ast.Name):
            return imports.get(expr.id, set())
        if isinstance(expr, ast.Attribute):
            return {
                prefix + "." + expr.attr for prefix in qualified(expr.value, depth + 1)
            }
        return set()

    namespace_builtins = {
        "globals",
        "locals",
        "vars",
        "__import__",
        "exec",
        "eval",
        "compile",
        "getattr",
    }
    reflective_attributes = {
        "__dict__",
        "__globals__",
        "__closure__",
        "__code__",
        "__wrapped__",
        "__class__",
        "__mro__",
        "__bases__",
        "__subclasses__",
        "__getattribute__",
        "__getattr__",
        "f_globals",
        "f_locals",
        "f_builtins",
        "f_back",
        "gi_frame",
        "cr_frame",
        "ag_frame",
        "tb_frame",
    }
    for node in nodes:
        if isinstance(node, ast.Attribute) and node.attr in reflective_attributes:
            return False
        if not isinstance(node, (ast.Name, ast.Attribute)) or not isinstance(
            node.ctx, ast.Load
        ):
            continue
        if isinstance(node, ast.Name) and node.id in namespace_builtins | {
            "__builtins__"
        }:
            return False
        paths = qualified(node)
        parent = checker.parents.get(id(node))
        if paths & {"sys", "builtins", "importlib", "operator", "_operator"} and not (
            isinstance(parent, ast.Attribute) and parent.value is node
        ):
            return False
        if any(
            path in {"sys.modules", "sys._getframe"}
            or path.startswith(("sys.modules.", "importlib."))
            or path.startswith(("sys.__", "builtins.__"))
            or path in {"builtins." + name for name in namespace_builtins}
            or path
            in {
                "operator.attrgetter",
                "operator.methodcaller",
                "_operator.attrgetter",
                "_operator.methodcaller",
            }
            for path in paths
        ):
            # Dynamic namespace access can expose the same mutable native
            # result types without naming them in an ordinary import.
            return False

    string_types = {"str", "bytes"}
    assignments = [
        node for node in nodes if isinstance(node, (ast.Assign, ast.AnnAssign))
    ]
    for _ in range(8):
        before = len(string_types)
        for node in assignments:
            value = node.value
            if (isinstance(value, ast.Name) and value.id in string_types) or qualified(
                value
            ) & {"builtins.str", "builtins.bytes"}:
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                string_types.update(
                    target.id for target in targets if isinstance(target, ast.Name)
                )
        if len(string_types) == before:
            break
    else:
        return False
    if any(
        isinstance(node, ast.ClassDef)
        and any(
            (isinstance(base, ast.Name) and base.id in string_types)
            or qualified(base) & {"builtins.str", "builtins.bytes"}
            for base in node.bases
        )
        for node in nodes
    ):
        # Native parsing invokes string coercion/slicing methods. An exposed
        # local string subclass can make its scheme field a non-string value.
        return False

    def kind(expr, depth=0):
        if depth >= 12:
            return exposed
        capability = (
            result if isinstance(expr, ast.Name) and expr.id in result_names else 0
        )
        paths = qualified(expr)
        parser_paths = {"urllib.parse.urlsplit", "urllib.parse.urlparse"}
        if paths & {"urllib", "urllib.parse"}:
            capability |= module
        if paths & parser_paths:
            capability |= parser
        if any(
            path.startswith("urllib.parse.") and path not in parser_paths
            for path in paths
        ):
            capability |= exposed
        if isinstance(expr, ast.Call) and qualified(expr.func) & {
            "urllib.parse.urlsplit",
            "urllib.parse.urlparse",
        }:
            capability |= result
        if isinstance(expr, ast.Attribute):
            base = kind(expr.value, depth + 1)
            if base & result:
                fields = {
                    "scheme",
                    "netloc",
                    "path",
                    "params",
                    "query",
                    "fragment",
                    "hostname",
                    "port",
                    "username",
                    "password",
                }
                capability |= 0 if expr.attr in fields else exposed
            if base & parser or (base & module and expr.attr.startswith("__")):
                capability |= exposed
        return capability

    for _ in range(8):
        before = len(result_names)
        for node in assignments:
            if not kind(node.value) & result:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            result_names.update(
                target.id for target in targets if isinstance(target, ast.Name)
            )
        if len(result_names) == before:
            break
    else:
        return False

    for node in nodes:
        if not isinstance(node, ast.expr) or (
            isinstance(node, (ast.Name, ast.Attribute))
            and not isinstance(node.ctx, ast.Load)
        ):
            continue
        capability = kind(node)
        if not capability:
            continue
        parent = checker.parents.get(id(node))
        if (
            capability == module
            and isinstance(parent, ast.Attribute)
            and parent.value is node
            and isinstance(parent.ctx, ast.Load)
        ):
            continue
        if (
            capability == parser
            and isinstance(parent, ast.Call)
            and parent.func is node
        ):
            continue
        if capability == result:
            if (
                isinstance(parent, ast.Attribute)
                and parent.value is node
                and isinstance(parent.ctx, ast.Load)
                and not kind(parent)
            ):
                continue
            if isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is node:
                targets = (
                    parent.targets
                    if isinstance(parent, ast.Assign)
                    else [parent.target]
                )
                scope = checker.parents.get(id(parent))
                while scope is not None and not isinstance(
                    scope,
                    (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module),
                ):
                    scope = checker.parents.get(id(scope))
                if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and all(
                    isinstance(target, ast.Name) for target in targets
                ):
                    continue
        return False
    checker._url_scheme_normalization_stable = True
    return True


def _guard_read(checker, test, name, func, guard, *, truth):
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _guard_read(checker, test.operand, name, func, guard, truth=not truth)
    if isinstance(test, ast.BoolOp):
        # A true AND or false OR entails every member. Other forms do not.
        if (truth and isinstance(test.op, ast.And)) or (
            not truth and isinstance(test.op, ast.Or)
        ):
            reads = [
                _guard_read(checker, value, name, func, guard, truth=truth)
                for value in test.values
            ]
            return next((read for read in reads if read is not None), None)
    if truth and isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute):
        if (
            test.func.attr == "startswith"
            and checker._reads_local(test.func.value, name, func)
            and len(test.args) == 1
            and not test.keywords
            and isinstance(test.args[0], (ast.Constant, ast.Tuple))
            and _allowed_literals(test.args[0], prefixes=True)
        ):
            return test.lineno
    if (
        not isinstance(test, ast.Compare)
        or len(test.ops) != 1
        or len(test.comparators) != 1
    ):
        return None
    op = test.ops[0]
    if not (
        (truth and isinstance(op, (ast.In, ast.Eq)))
        or (not truth and isinstance(op, (ast.NotIn, ast.NotEq)))
    ):
        return None
    value, allowed = test.left, test.comparators[0]
    if isinstance(op, (ast.Eq, ast.NotEq)) and _text(allowed) is None:
        return None
    if isinstance(op, (ast.In, ast.NotIn)) and not isinstance(
        allowed, (ast.Tuple, ast.List, ast.Set)
    ):
        return None
    if not _allowed_literals(allowed):
        return None
    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and value.func.attr == "lower"
        and not value.args
        and not value.keywords
    ):
        if not _normalization_result_stable(checker):
            return None
        value = value.func.value
    if isinstance(value, ast.Attribute) and value.attr == "scheme":
        return checker._parsed_url_read_line(value.value, name, func, guard)
    return None


def _guarded(checker, url, sink):
    writes, computed = _api_writes(checker)
    if computed or writes & {"urlparse", "urlsplit"}:
        return False
    func = checker._current_function()
    if (
        not isinstance(url, ast.Name)
        or func is None
        or not checker._reads_local(url, url.id, func)
    ):
        return False
    bindings = checker._binding_nodes(func, url.id)
    # All writes must precede the guard's read, including writes in child scopes.
    # This intentionally declines complex proofs instead of hiding an audit.
    candidates = [
        (guard, False)
        for guard in checker._dominating_statements(sink, func)
        if isinstance(guard, ast.If) and checker._block_always_exits(guard.body, func)
    ]
    current = sink
    while current is not None and current is not func:
        parent = checker.parents.get(id(current))
        if isinstance(parent, ast.If):
            if current in parent.body:
                candidates.append((parent, True))
            elif current in parent.orelse:
                candidates.append((parent, False))
        current = parent
    for guard, truth in candidates:
        read = _guard_read(checker, guard.test, url.id, func, guard, truth=truth)
        if read is not None and all(
            getattr(binding, "lineno", 0) < read for binding in bindings
        ):
            return True
    return False


def _api_writes(checker):
    cached = getattr(checker, "_url_scheme_api_writes", None)
    if cached is None:
        writes, computed = attribute_write_names(checker.tree)
        cached = (writes, computed or has_mock_api_patching(checker.tree))
        checker._url_scheme_api_writes = cached
    return cached


def audit_urlopen(checker, node):
    qualified = _name(node.func)
    if (
        not qualified
        or checker.untrusted_sources.resolved_import(
            checker._current_function(), qualified
        )
        != "urllib.request.urlopen"
    ):
        return
    raw = checker._urlopen_argument(node)
    if raw is None:
        return
    candidates = checker._urlopen_url_candidates(raw)
    writes, computed = _api_writes(checker)
    if computed or "Request" in writes:
        # A later from-import may capture an already replaced constructor.
        candidates = [raw]
    if all(
        _fixed_scheme(checker, url, node) or _guarded(checker, url, node)
        for url in candidates
    ):
        return
    message = (
        "Audit URL schemes: urllib can open local files and other non-HTTP resources; "
        "validate dynamic URLs against the intended schemes."
    )
    if checker._current_function() is not None:
        message += " Caller-side URL scheme validation is not analysed."
    checker.findings.append(
        {
            "rule_id": "SKY-D218",
            "severity": "MEDIUM",
            "message": message,
            "file": str(checker.file_path),
            "line": node.lineno,
            "col": node.col_offset,
            "symbol": checker._current_symbol(),
            "metadata": {
                "security_evidence": {
                    "evidence_kind": "url_scheme_audit",
                    "source": "dynamic URL; attacker control is not established",
                    "sink": qualified,
                    "guards_missing": ["proven HTTP/HTTPS scheme restriction"],
                    "assumption": "The URL can originate outside the application's trust boundary.",
                }
            },
        }
    )
