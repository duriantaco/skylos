from __future__ import annotations
import ast
import re
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


_ALLOW_ORIGIN_HEADER = "access-control-allow-origin"
_ORIGIN_KEYS = frozenset({"origin", "http_origin"})
_HEADER_MAPPINGS = frozenset({"headers", "META", "environ"})
_HEADER_SETTERS = frozenset({"set", "add", "setdefault", "add_header", "__setitem__"})
_ANY_ORIGIN_PATTERNS = frozenset({".*", "^.*$", ".+", "^.+$", "*"})
_TERMINATORS = (ast.Return, ast.Raise, ast.Continue, ast.Break)


def _is_allow_origin_header(node) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.lower() == _ALLOW_ORIGIN_HEADER
    )


def _is_origin_key(node) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.lower() in _ORIGIN_KEYS
    )


def _is_header_mapping(node) -> bool:
    return isinstance(node, ast.Attribute) and node.attr in _HEADER_MAPPINGS


def _reads_request_origin(node, names) -> bool:
    """The request's own Origin header (or a local holding it)."""
    if isinstance(node, ast.Name):
        return node.id in names
    if isinstance(node, ast.BoolOp):
        return any(_reads_request_origin(value, names) for value in node.values)
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(value, ast.FormattedValue)
            and _reads_request_origin(value.value, names)
            for value in node.values
        )
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return (
            node.func.attr == "get"
            and bool(node.args)
            and _is_origin_key(node.args[0])
            and _is_header_mapping(node.func.value)
        )
    if isinstance(node, ast.Subscript):
        return _is_origin_key(node.slice) and _is_header_mapping(node.value)
    if isinstance(node, ast.Attribute):
        return node.attr == "origin" and _qualified_attr(node.value) in {
            "request",
            "flask.request",
        }
    return False


def _qualified_attr(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append(node.id)
    return ".".join(reversed(parts))


def _origin_names(function) -> set[str]:
    """Locals assigned from the request Origin, followed to a fixed point."""
    names: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(function):
            if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                continue
            value = node.value
            if value is None or not _reads_request_origin(value, names):
                continue
            if isinstance(node, ast.Assign):
                targets = node.targets
            else:
                targets = [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in names:
                    names.add(target.id)
                    changed = True
    return names


def _module_helpers(tree) -> dict:
    """Module functions and class methods, by name, when defined once."""
    seen: dict = {}
    duplicate = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in seen:
                duplicate.add(node.name)
            seen[node.name] = node
    return {name: node for name, node in seen.items() if name not in duplicate}


class _OriginContext:
    """Origin locals of one function plus module facts the checks resolve."""

    def __init__(self, names, values, helpers):
        self.names = names
        self.values = values
        self.helpers = helpers


_WILDCARD_PATTERN = re.compile(r"(?<!\\)\.[*+]")
_UNSAFE_ALLOWED = frozenset({"*", "null"})


def _pattern_text(node, ctx) -> str | None:
    if isinstance(node, ast.Name) and node.id in ctx.values:
        node = ctx.values[node.id]
    if isinstance(node, ast.Call) and node.args:
        callee = _qualified_attr(node.func).rsplit(".", 1)[-1]
        if callee == "compile":
            node = node.args[0]
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _allowlist_operand(node, ctx, membership: bool) -> bool:
    """A value that can only hold specific origins: not the request's own
    Origin, not a string (``in`` would be a substring test), and with no
    wildcard or ``null`` entry."""
    if _reads_request_origin(node, ctx.names):
        return False
    resolved = node
    if isinstance(node, ast.Name) and node.id in ctx.values:
        resolved = ctx.values[node.id]
    if membership and isinstance(resolved, (ast.Constant, ast.JoinedStr)):
        return False
    for part in ast.walk(resolved):
        if isinstance(part, ast.Constant) and part.value in _UNSAFE_ALLOWED:
            return False
    if isinstance(resolved, (ast.List, ast.Tuple, ast.Set)):
        return all(
            isinstance(element, ast.Constant)
            and (element.value is None or isinstance(element.value, str))
            for element in resolved.elts
        )
    return True


def _any_equal(test, terms, ctx) -> bool:
    """``any(origin == allowed for allowed in ALLOWED)``."""
    if not (
        _qualified_attr(test.func) == "any"
        and len(test.args) == 1
        and isinstance(test.args[0], ast.GeneratorExp)
        and len(test.args[0].generators) == 1
    ):
        return False
    generator = test.args[0]
    loop = generator.generators[0]
    element = generator.elt
    if loop.ifs or loop.is_async or not isinstance(loop.target, ast.Name):
        return False
    if not (
        isinstance(element, ast.Compare)
        and len(element.ops) == 1
        and isinstance(element.ops[0], ast.Eq)
    ):
        return False
    sides = [element.left, element.comparators[0]]
    loop_name = loop.target.id
    return (
        any(isinstance(side, ast.Name) and side.id == loop_name for side in sides)
        and any(_checked_term(side, terms, ctx) for side in sides)
        and _allowlist_operand(loop.iter, ctx, True)
    )


def _checked_term(node, terms, ctx) -> bool:
    if terms:
        return isinstance(node, ast.Name) and node.id in terms
    return _reads_request_origin(node, ctx.names)


def _helper_proves_allowed(call, terms, ctx) -> bool:
    """A same-module function or method whose every return is an allowlist
    test of the parameter that receives the origin."""
    name = _qualified_attr(call.func)
    if name.startswith("self.") or name.startswith("cls."):
        name = name.split(".", 1)[1]
    helper = ctx.helpers.get(name)
    if helper is None or helper.decorator_list:
        return False
    parameters = [argument.arg for argument in helper.args.args]
    if parameters and parameters[0] in {"self", "cls"}:
        parameters = parameters[1:]
    for index, argument in enumerate(call.args):
        if not _checked_term(argument, terms, ctx) or index >= len(parameters):
            continue
        parameter = parameters[index]
        returns = [node for node in ast.walk(helper) if isinstance(node, ast.Return)]
        inner = _OriginContext(set(), ctx.values, {})
        if returns and all(
            node.value is not None
            and _origin_test(node.value, {parameter}, inner, True)
            for node in returns
        ):
            return True
    return False


def _origin_test(test, terms, ctx, positive: bool) -> bool:
    """Whether ``test`` being true proves (``positive``) or disproves the
    origin is on an allowlist: membership, equality, an anchored
    ``fullmatch`` without wildcard runs, or a same-module helper doing one."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _origin_test(test.operand, terms, ctx, not positive)
    if isinstance(test, ast.BoolOp):
        joined = isinstance(test.op, ast.And)
        if joined == positive:
            return any(
                _origin_test(value, terms, ctx, positive) for value in test.values
            )
        return all(_origin_test(value, terms, ctx, positive) for value in test.values)
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        left, right = test.left, test.comparators[0]
        op = test.ops[0]
        accepted = (ast.In, ast.Eq)
        if not positive:
            accepted = (ast.NotIn, ast.NotEq)
        if not isinstance(op, accepted):
            return False
        membership = isinstance(op, (ast.In, ast.NotIn))
        if _checked_term(left, terms, ctx) and _allowlist_operand(
            right, ctx, membership
        ):
            return True
        return (
            not membership
            and _checked_term(right, terms, ctx)
            and _allowlist_operand(left, ctx, False)
        )
    if not positive or not isinstance(test, ast.Call):
        return False
    if isinstance(test.func, ast.Attribute) and test.func.attr == "fullmatch":
        arguments = list(test.args)
        pattern = None
        if _qualified_attr(test.func) in {"re.fullmatch", "regex.fullmatch"}:
            if not arguments:
                return False
            pattern = _pattern_text(arguments[0], ctx)
            arguments = arguments[1:]
        else:
            pattern = _pattern_text(test.func.value, ctx)
        return (
            pattern is not None
            and not _WILDCARD_PATTERN.search(pattern)
            and any(_checked_term(argument, terms, ctx) for argument in arguments)
        )
    if _any_equal(test, terms, ctx):
        return True
    return _helper_proves_allowed(test, terms, ctx)


def _reassigns_origin(body, terms, ctx) -> bool:
    """``origin = DEFAULT`` replaces a rejected origin with a fixed value."""
    if len(body) != 1 or not isinstance(body[0], ast.Assign):
        return False
    statement = body[0]
    return (
        len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and statement.targets[0].id in terms
        and not _reads_request_origin(statement.value, ctx.names)
        and not any(
            isinstance(part, ast.Name) and part.id in terms
            for part in ast.walk(statement.value)
        )
    )


def _terminates(body) -> bool:
    if not body:
        return False
    last = body[-1]
    if isinstance(last, _TERMINATORS):
        return True
    return (
        isinstance(last, ast.Expr)
        and isinstance(last.value, ast.Call)
        and _qualified_attr(last.value.func).rsplit(".", 1)[-1] in {"abort", "exit"}
    )


class _CORSChecker(ast.NodeVisitor):
    def __init__(self, file_path, findings, tree=None):
        self.file_path = file_path
        self.findings = findings
        self.tree = tree
        self._open_routes = None
        self.parents = {}
        self.origin_names = {}
        self.module_values = {}
        self.helpers = {}
        if tree is not None:
            for parent in ast.walk(tree):
                for child in ast.iter_child_nodes(parent):
                    self.parents[child] = parent
            if isinstance(tree, ast.Module):
                from skylos.rules.quality._route_exposure import single_module_values

                self.module_values = single_module_values(tree)
                self.helpers = _module_helpers(tree)

    def _open_state_routes(self):
        if self._open_routes is None:
            self._open_routes = []
            if isinstance(self.tree, ast.Module):
                from skylos.rules.quality.practices import open_unguarded_routes

                self._open_routes = open_unguarded_routes(
                    self.tree, str(self.file_path)
                )
        return self._open_routes

    def _report_open_wildcard(self, anchor, setting):
        routes = self._open_state_routes()
        if not routes:
            return
        privileged = [route for route in routes if route["severity"] is not None]
        severity = "MEDIUM"
        listed = routes
        if privileged:
            severity = "HIGH"
            listed = privileged
        names = ", ".join(f"'{route['function'].name}'" for route in listed[:3])
        self._report(
            anchor,
            f"CORS misconfiguration: {setting} allows every origin while this app "
            f"has state-changing routes that nothing authenticates ({names}); any "
            "web page a user opens can call them from the browser and read the "
            "responses.",
            severity=severity,
        )

    def _enclosing_function(self, node):
        current = self.parents.get(node)
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current
            current = self.parents.get(current)
        return None

    def _origin_is_allowlisted(self, node, terms, ctx) -> bool:
        child = node
        current = self.parents.get(node)
        while current is not None:
            if isinstance(current, (ast.If, ast.IfExp)):
                in_body = child is current.body or (
                    isinstance(current.body, list) and child in current.body
                )
                in_else = child is current.orelse or (
                    isinstance(current.orelse, list) and child in current.orelse
                )
                if in_body and _origin_test(current.test, terms, ctx, True):
                    return True
                if in_else and _origin_test(current.test, terms, ctx, False):
                    return True
            for field in ("body", "orelse", "finalbody"):
                block = getattr(current, field, None)
                if not isinstance(block, list) or child not in block:
                    continue
                for statement in block[: block.index(child)]:
                    if (
                        isinstance(statement, ast.If)
                        and not statement.orelse
                        and (
                            _terminates(statement.body)
                            or _reassigns_origin(statement.body, terms, ctx)
                        )
                        and _origin_test(statement.test, terms, ctx, False)
                    ):
                        return True
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return False
            child = current
            current = self.parents.get(current)
        return False

    def _check_reflected_origin(self, value):
        function = self._enclosing_function(value)
        names = set()
        if function is not None:
            if function not in self.origin_names:
                self.origin_names[function] = _origin_names(function)
            names = self.origin_names[function]
        candidates = [value]
        if isinstance(value, ast.IfExp):
            candidates = [value.body, value.orelse]
        for candidate in candidates:
            if not _reads_request_origin(candidate, names):
                continue
            terms = {
                part.id
                for part in ast.walk(candidate)
                if isinstance(part, ast.Name) and part.id in names
            }
            ctx = _OriginContext(names, self.module_values, self.helpers)
            if self._origin_is_allowlisted(candidate, terms, ctx):
                continue
            self._report(
                value,
                "CORS misconfiguration: Access-Control-Allow-Origin echoes the "
                "request's Origin header without an allowlist check, so every "
                "site is allowed.",
            )
            return

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
                "rule_id": "SKY-D231",
                "severity": severity,
                "message": message,
                "file": str(self.file_path),
                "line": node.lineno,
                "col": node.col_offset,
            }
        )

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Subscript) and _is_allow_origin_header(
                target.slice
            ):
                self._check_reflected_origin(node.value)
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
                origins = kwargs.get("origins")
                if _is_wildcard_origin(origins):
                    self._report_open_wildcard(origins, "origins='*'")
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
        regex = kwargs.get("allow_origin_regex")
        origins = kwargs.get("allow_origins")
        if not _is_true(kwargs.get("allow_credentials")):
            if _is_wildcard_origin(origins):
                self._report_open_wildcard(origins, "allow_origins='*'")
            elif (
                isinstance(regex, ast.Constant)
                and isinstance(regex.value, str)
                and regex.value.strip() in _ANY_ORIGIN_PATTERNS
            ):
                self._report_open_wildcard(regex, "allow_origin_regex")
            return
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
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in _HEADER_SETTERS
            and len(node.args) >= 2
            and _is_allow_origin_header(node.args[0])
        ):
            self._check_reflected_origin(node.args[1])
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
            elif _is_allow_origin_header(key):
                self._check_reflected_origin(value)
        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _CORSChecker(file_path, findings, tree)
        checker.visit(tree)
    except Exception as e:
        print(f"CORS analysis failed for {file_path}: {e}", file=sys.stderr)
