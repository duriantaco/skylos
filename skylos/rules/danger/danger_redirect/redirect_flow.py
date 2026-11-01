from __future__ import annotations
import ast
from collections import Counter
import sys
from skylos.rules.danger.taint import TaintVisitor
from skylos.rules.danger.untrusted_sources import UntrustedSourceIndex, _dotted
from skylos.rules.danger import import_proof


REDIRECT_FUNCS = {"redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect"}

REQUEST_ARGS_ATTRS = {"args", "params", "query", "GET"}

# Native route builders keep user values in path/query parameters. A matching
# method or local function spelling alone says nothing about the target host.
_NATIVE_URL_BUILDERS = frozenset(
    {
        "flask.url_for",
        "flask.helpers.url_for",
        "quart.url_for",
        "django.urls.reverse",
        "django.urls.reverse_lazy",
        "django.core.urlresolvers.reverse",
        "django.core.urlresolvers.reverse_lazy",
    }
)


def _is_request_args_get(node):
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr != "get":
        return False
    val = func.value
    if (
        isinstance(val, ast.Attribute)
        and val.attr in REQUEST_ARGS_ATTRS
        and isinstance(val.value, ast.Name)
        and val.value.id == "request"
    ):
        return True
    return False


def _fixed_local_prefix(node):
    """A fixed first path segment keeps a suffix on the current origin.

    A slash alone is insufficient: ``'/' + '/example.com'`` changes the host.
    Require a literal alphanumeric character after that slash, before any
    untrusted suffix. Browser control stripping cannot remove that character.
    """
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _fixed_local_prefix(node.left)
    if isinstance(node, ast.JoinedStr) and node.values:
        return _fixed_local_prefix(node.values[0])
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and len(node.value) > 1
        and node.value[0] == "/"
        and node.value[1].isascii()
        and node.value[1].isalnum()
    )


def _stable_module_classes(tree):
    """A class spelling proves ancestry only while its binding is unique."""
    counts = Counter()
    classes = {}
    pending = list(tree.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            counts[node.name] += 1
            if isinstance(node, ast.ClassDef):
                if node in tree.body:
                    classes[node.name] = node
                pending.extend(node.bases)
                pending.extend(keyword.value for keyword in node.keywords)
            else:
                pending.extend(node.args.defaults)
                pending.extend(value for value in node.args.kw_defaults if value)
            pending.extend(node.decorator_list)
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            counts[node.id] += 1
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                counts[alias.asname or alias.name.split(".", 1)[0]] += 1
        elif isinstance(node, ast.ExceptHandler) and node.name:
            counts[node.name] += 1
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            counts[node.name] += 1
        elif isinstance(node, ast.MatchMapping) and node.rest:
            counts[node.rest] += 1
        pending.extend(ast.iter_child_nodes(node))
    global_names = {
        name
        for node in ast.walk(tree)
        if isinstance(node, ast.Global)
        for name in node.names
    }
    return {
        name: node
        for name, node in classes.items()
        if counts[name] == 1 and name not in global_names
    }


class _RedirectFlowChecker(TaintVisitor):
    def __init__(self, file_path, findings, tree):
        super().__init__(file_path, findings)
        self._exception_states = []
        self._loop_states = []
        self.untrusted_sources = UntrustedSourceIndex(tree)
        self._classes = _stable_module_classes(tree)
        self._class_stack = []
        self._reader_override_cache = {}
        self._class_aliases = {}
        self._reader_writes = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(
                node.value, ast.Name
            ):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                for target in targets:
                    if isinstance(target, ast.Name):
                        self._class_aliases.setdefault(target.id, set()).add(
                            node.value.id
                        )
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and isinstance(node.value, ast.Name)
            ):
                self._reader_writes.setdefault(node.attr, set()).add(node.value.id)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr"}
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
            ):
                member = node.args[1]
                name = member.value if isinstance(member, ast.Constant) else None
                self._reader_writes.setdefault(name, set()).add(node.args[0].id)

    def _reader_replaced(self, klass, name):
        key = klass, name
        if key not in self._reader_override_cache:
            aliases = {klass.name}
            for _ in range(24):
                expanded = aliases | {
                    alias
                    for alias, sources in self._class_aliases.items()
                    if sources & aliases
                }
                if expanded == aliases:
                    break
                aliases = expanded
            else:
                self._reader_override_cache[key] = True
                return True
            if aliases & (
                self._reader_writes.get(name, set())
                | self._reader_writes.get(None, set())
            ):
                self._reader_override_cache[key] = True
                return True
            self._reader_override_cache[key] = any(
                (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                    and node.attr == name
                )
                or (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in {"setattr", "delattr"}
                    and len(node.args) >= 2
                    and (
                        not isinstance(node.args[1], ast.Constant)
                        or node.args[1].value == name
                    )
                )
                for node in ast.walk(klass)
            )
        return self._reader_override_cache[key]

    def visit_ClassDef(self, node):
        self._class_stack.append(node)
        super().visit_ClassDef(node)
        self._class_stack.pop()

    def _noninstance_descriptor(self, decorator):
        pending = [_dotted(decorator)]
        seen = set()
        while pending and len(seen) < 24:
            name = pending.pop()
            if name in seen:
                continue
            seen.add(name)
            if name.rsplit(".", 1)[-1] in {"staticmethod", "classmethod"} or (
                self.untrusted_sources.resolved_import(None, name)
                in {"builtins.staticmethod", "builtins.classmethod"}
            ):
                return True
            pending.extend(self._class_aliases.get(name, ()))
        return bool(pending)

    def _tornado_argument_read(self, node):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr
            in {"get_argument", "get_query_argument", "get_body_argument"}
            and isinstance(node.func.value, ast.Name)
            and self._class_stack
            and self._current_function() is not None
        ):
            return False
        function = self._current_function()
        parameters = function.args.posonlyargs + function.args.args
        if not parameters or node.func.value.id != parameters[0].arg:
            return False
        if any(
            self._noninstance_descriptor(decorator)
            for decorator in function.decorator_list
        ):
            return False
        if function not in self._class_stack[-1].body or any(
            isinstance(child, ast.Name)
            and isinstance(child.ctx, (ast.Store, ast.Del))
            and child.id == parameters[0].arg
            for statement in function.body
            for child in ast.walk(statement)
        ):
            return False
        visited = set()

        def inherits_handler(klass):
            if id(klass) in visited:
                return False
            visited.add(id(klass))
            if len(klass.bases) != 1:
                # An unknown mixin can override the request-reading method.
                return False
            if self._reader_replaced(klass, node.func.attr):
                return False
            # A local override may return application data instead of a request
            # argument. Do not infer its semantics from the method name.
            if any(
                (
                    isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and member.name == node.func.attr
                )
                or (
                    isinstance(member, (ast.Assign, ast.AnnAssign))
                    and any(
                        isinstance(target, ast.Name) and target.id == node.func.attr
                        for target in (
                            member.targets
                            if isinstance(member, ast.Assign)
                            else [member.target]
                        )
                    )
                )
                for member in klass.body
            ):
                return False
            for base in klass.bases:
                dotted = _dotted(base)
                if self.untrusted_sources.resolved_import(None, dotted) == (
                    "tornado.web.RequestHandler"
                ):
                    return True
                if (
                    isinstance(base, ast.Name)
                    and base.id in self._classes
                    and self._import_names_are_stable(base.id)
                ):
                    if inherits_handler(self._classes[base.id]):
                        return True
            return False

        return inherits_handler(self._class_stack[-1])

    def _visit_block(self, statements):
        """Return whether the block has a path reaching its next statement."""
        for statement in statements:
            continues = self.visit(statement)
            for states in self._exception_states:
                states.append(self._copy_env(self.env_stack))
            if continues is False:
                return False
        return True

    def _visit_function(self, node):
        # Each function has its own flow; a return must not stop its enclosing
        # module or function from being scanned.
        for expression in node.decorator_list + node.args.defaults:
            self.visit(expression)
        for expression in node.args.kw_defaults:
            if expression is not None:
                self.visit(expression)
        self._push()
        outer_exceptions = self._exception_states
        outer_loops = self._loop_states
        self._exception_states = []
        self._loop_states = []
        self._symbol_stack.append(node.name)
        self._function_stack.append(node)
        self._taint_params(node)
        self._visit_block(node.body)
        self._function_stack.pop()
        self._symbol_stack.pop()
        self._pop()
        self._exception_states = outer_exceptions
        self._loop_states = outer_loops

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_Return(self, node):
        self.generic_visit(node)
        return False

    def visit_Raise(self, node):
        self.generic_visit(node)
        return False

    def visit_Break(self, node):
        if self._loop_states:
            self._loop_states[-1].append(self._copy_env(self.env_stack))
        return False

    visit_Continue = visit_Break

    def is_tainted(self, node):
        if _fixed_local_prefix(node):
            return False
        if self._tornado_argument_read(node):
            return True
        if isinstance(node, ast.NamedExpr):
            return self.is_tainted(node.value)
        if self._starts_with_internal_url(node):
            return False
        if isinstance(node, ast.IfExp):
            return self.is_tainted(node.body) or self.is_tainted(node.orelse)
        if isinstance(node, ast.BoolOp):
            return any(self.is_tainted(value) for value in node.values)
        return super().is_tainted(node)

    def _starts_with_internal_url(self, node):
        if isinstance(node, ast.Call):
            if self._native_instance_path(node):
                return True
            dotted = _dotted(node.func)
            if not dotted or not self._import_names_are_stable(dotted):
                return False
            imported = self.untrusted_sources.resolved_import(
                self._current_function(), dotted
            )
            return bool(
                imported in _NATIVE_URL_BUILDERS
                and self._sanitizer_is_unpatched(imported)
                and import_proof.provider_binding_is_stable(
                    imported,
                    self.untrusted_sources.module,
                    self.file_path,
                    getattr(self, "project_root", None),
                )
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self._starts_with_internal_url(node.left)
        if isinstance(node, ast.JoinedStr) and node.values:
            first = node.values[0]
            return isinstance(
                first, ast.FormattedValue
            ) and self._starts_with_internal_url(first.value)
        return False

    def _native_instance_path(self, node):
        """A native application plus a fixed-prefix, literal route table.

        Native instance methods need receiver proof as well as provider proof.
        In particular, a catch-all '/{path:path}' route is not a fixed-origin
        guarantee merely because its router is Starlette.
        """
        if not (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "url_path_for"
            and isinstance(node.func.value, ast.Name)
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            return False
        tree = self.untrusted_sources.module
        receiver = node.func.value.id
        if not self._import_names_are_stable(receiver):
            return False
        if not self._sanitizer_is_unpatched("starlette.url_path_for"):
            return False
        # Index only module bindings. A local parameter with the same spelling
        # in an unrelated handler cannot invalidate the application binding.
        bindings = {}
        pending = list(tree.body)
        while pending:
            current = pending.pop()
            if isinstance(
                current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                bindings.setdefault(current.name, []).append(None)
                continue
            if isinstance(current, (ast.Assign, ast.AnnAssign)):
                targets = (
                    current.targets
                    if isinstance(current, ast.Assign)
                    else [current.target]
                )
                for target in targets:
                    if isinstance(target, ast.Name):
                        bindings.setdefault(target.id, []).append(
                            current.value if current in tree.body else None
                        )
            elif isinstance(current, (ast.Import, ast.ImportFrom)):
                for alias in current.names:
                    bindings.setdefault(
                        alias.asname or alias.name.split(".", 1)[0], []
                    ).append(None)
            elif isinstance(current, ast.Name) and isinstance(current.ctx, ast.Del):
                bindings.setdefault(current.id, []).append(None)
            pending.extend(ast.iter_child_nodes(current))
        seen = set()
        root_name = receiver
        constructor = None
        for _ in range(32):
            if root_name in seen:
                return False
            seen.add(root_name)
            values = bindings.get(root_name, ())
            if len(values) != 1:
                return False
            value = values[0]
            if isinstance(value, ast.Name):
                root_name = value.id
            elif isinstance(value, ast.Call):
                constructor = value
                break
            else:
                return False
        if constructor is None:
            return False
        aliases = {root_name}
        for _ in range(32):
            expanded = aliases | {
                name
                for name, values in bindings.items()
                if len(values) == 1
                and isinstance(values[0], ast.Name)
                and values[0].id in aliases
            }
            if expanded == aliases:
                break
            aliases = expanded
        else:
            return False
        if receiver not in aliases:
            return False
        function = self._current_function()
        if function is not None:
            if any(
                arg.arg in aliases
                for arg in ast.walk(function.args)
                if isinstance(arg, ast.arg)
            ):
                return False
            if any(
                isinstance(part, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and part is not function
                and part.name in aliases
                or isinstance(part, (ast.Import, ast.ImportFrom))
                and any(
                    (alias.asname or alias.name.split(".", 1)[0]) in aliases
                    for alias in part.names
                )
                for part in ast.walk(function)
            ):
                return False
            if any(
                isinstance(part, ast.Name)
                and part.id in aliases
                and isinstance(part.ctx, (ast.Store, ast.Del))
                for part in ast.walk(function)
            ):
                return False
        parents = {
            id(child): parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for part in ast.walk(tree):
            if (
                not isinstance(part, ast.Name)
                or part.id not in aliases
                or not isinstance(part.ctx, ast.Load)
            ):
                continue
            # Same-spelled parameters/local variables in another scope are
            # separate objects, rather than escapes of the module instance.
            scope = parents.get(id(part))
            local = False
            while scope is not None and scope is not tree:
                if isinstance(
                    scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
                ):
                    scoped = (
                        list(scope.body)
                        if not isinstance(scope, ast.Lambda)
                        else [scope.body]
                    )
                    local_names = {
                        arg.arg
                        for arg in ast.walk(scope.args)
                        if isinstance(arg, ast.arg)
                    }
                    globals_ = set()
                    while scoped:
                        item = scoped.pop()
                        if isinstance(
                            item,
                            (
                                ast.FunctionDef,
                                ast.AsyncFunctionDef,
                                ast.ClassDef,
                                ast.Lambda,
                            ),
                        ):
                            if not isinstance(item, ast.Lambda):
                                local_names.add(item.name)
                            continue
                        if isinstance(item, ast.Name) and isinstance(
                            item.ctx, (ast.Store, ast.Del)
                        ):
                            local_names.add(item.id)
                        elif isinstance(item, (ast.Import, ast.ImportFrom)):
                            local_names.update(
                                alias.asname or alias.name.split(".", 1)[0]
                                for alias in item.names
                            )
                        elif isinstance(item, ast.Global):
                            globals_.update(item.names)
                        scoped.extend(ast.iter_child_nodes(item))
                    if part.id in globals_:
                        break
                    if part.id in local_names:
                        local = True
                        break
                scope = parents.get(id(scope))
            if local:
                continue
            parent = parents.get(id(part))
            if (
                isinstance(parent, ast.Assign)
                and parent.value is part
                and all(
                    isinstance(target, ast.Name) and target.id in aliases
                    for target in parent.targets
                )
            ):
                continue
            if (
                isinstance(parent, ast.AnnAssign)
                and parent.value is part
                and isinstance(parent.target, ast.Name)
                and parent.target.id in aliases
            ):
                continue
            if (
                isinstance(parent, ast.Attribute)
                and parent.value is part
                and parent.attr == "url_path_for"
            ):
                call = parents.get(id(parent))
                if isinstance(call, ast.Call) and call.func is parent:
                    continue
            return False
        imported = self.untrusted_sources.resolved_import(
            None, _dotted(constructor.func)
        )
        if imported not in {
            "starlette.applications.Starlette",
            "starlette.routing.Router",
            "fastapi.FastAPI",
            "fastapi.applications.FastAPI",
        }:
            return False
        if not import_proof.provider_binding_is_stable(
            imported, tree, self.file_path, getattr(self, "project_root", None)
        ):
            return False
        routes = next(
            (kw.value for kw in constructor.keywords if kw.arg == "routes"), None
        )
        if not isinstance(routes, (ast.List, ast.Tuple)) or any(
            kw.arg is None for kw in constructor.keywords
        ):
            return False
        found = False
        for route in routes.elts:
            if not isinstance(route, ast.Call) or any(
                kw.arg is None for kw in route.keywords
            ):
                return False
            provider = self.untrusted_sources.resolved_import(None, _dotted(route.func))
            if (
                provider != "starlette.routing.Route"
                or not import_proof.provider_binding_is_stable(
                    provider, tree, self.file_path, getattr(self, "project_root", None)
                )
            ):
                return False
            path = (
                route.args[0]
                if route.args
                else next((kw.value for kw in route.keywords if kw.arg == "path"), None)
            )
            name = next((kw.value for kw in route.keywords if kw.arg == "name"), None)
            if (
                not isinstance(path, ast.Constant)
                or not isinstance(path.value, str)
                or not isinstance(name, ast.Constant)
                or not isinstance(name.value, str)
            ):
                return False
            if name.value == node.args[0].value:
                if not _fixed_local_prefix(path):
                    return False
                found = True
        return found

    def visit_NamedExpr(self, node):
        if isinstance(node.target, ast.Name):
            self._set(node.target.id, self.is_tainted(node.value))
        self.generic_visit(node)

    @staticmethod
    def _copy_env(env):
        return [scope.copy() for scope in env]

    @staticmethod
    def _merge_env(states):
        # A name missing in a local scope can still resolve to an outer binding.
        # Keep that inherited taint when only one branch creates a local name.
        merged = []
        for index in range(len(states[0])):
            names = set().union(*(state[index] for state in states))
            scope = {}
            for name in names:
                scope[name] = any(
                    next(
                        (
                            part[name]
                            for part in reversed(state[: index + 1])
                            if name in part
                        ),
                        False,
                    )
                    for state in states
                )
            merged.append(scope)
        return merged

    def _narrow_literal_guard(self, test, truth):
        """Only equality with immutable literal values proves a target bounded.

        A netloc check or leading slash alone is not browser redirect safety,
        and a check on one expression does not validate a later request read.
        """
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self._narrow_literal_guard(test.operand, not truth)
        if not isinstance(test, ast.Compare) or len(test.ops) != 1:
            return
        left, right, op = test.left, test.comparators[0], test.ops[0]
        if isinstance(op, (ast.Eq, ast.NotEq)):
            if isinstance(right, ast.Name) and isinstance(left, ast.Constant):
                left, right = right, left
            bounded = isinstance(right, ast.Constant) and isinstance(right.value, str)
            matches = truth if isinstance(op, ast.Eq) else not truth
        elif isinstance(op, (ast.In, ast.NotIn)):
            bounded = isinstance(right, (ast.Tuple, ast.List, ast.Set)) and all(
                isinstance(value, ast.Constant) and isinstance(value.value, str)
                for value in right.elts
            )
            matches = truth if isinstance(op, ast.In) else not truth
        else:
            return
        if isinstance(left, ast.Name) and bounded and matches:
            self._set(left.id, False)

    def visit_If(self, node):
        self.visit(node.test)
        entry = self._copy_env(self.env_stack)
        continuing = []
        for truth, statements in ((True, node.body), (False, node.orelse)):
            self.env_stack = self._copy_env(entry)
            self._narrow_literal_guard(node.test, truth)
            if self._visit_block(statements):
                continuing.append(self._copy_env(self.env_stack))
        self.env_stack = self._merge_env(continuing) if continuing else entry
        return bool(continuing)

    def visit_With(self, node):
        for item in node.items:
            self.visit(item)
        # An unknown context manager can suppress an exception from any body
        # statement, including a rejected target. Do not leak that proof out.
        states = [self._copy_env(self.env_stack)]
        self._exception_states.append(states)
        self._visit_block(node.body)
        self._exception_states.pop()
        self.env_stack = self._merge_env(states)

    visit_AsyncWith = visit_With

    def _visit_loop(self, node):
        expression = node.test if isinstance(node, ast.While) else node.iter
        self.visit(expression)
        entry = self._copy_env(self.env_stack)
        if isinstance(node, (ast.For, ast.AsyncFor)) and isinstance(
            node.target, ast.Name
        ):
            self._set(node.target.id, self.is_tainted(node.iter))
        exits = []
        self._loop_states.append(exits)
        self._visit_block(node.body)
        self._loop_states.pop()
        # Zero iterations and break/continue both retain possible values.
        self.env_stack = self._merge_env([entry, self.env_stack, *exits])
        if node.orelse:
            before_else = self._copy_env(self.env_stack)
            self._visit_block(node.orelse)
            self.env_stack = self._merge_env([before_else, self.env_stack])

    visit_For = _visit_loop
    visit_AsyncFor = _visit_loop
    visit_While = _visit_loop

    def visit_Try(self, node):
        exceptional = [self._copy_env(self.env_stack)]
        self._exception_states.append(exceptional)
        normal = self._visit_block(node.body)
        self._exception_states.pop()
        continuing = []
        if normal and self._visit_block(node.orelse):
            continuing.append(self._copy_env(self.env_stack))
        for handler in node.handlers:
            self.env_stack = self._merge_env(exceptional)
            if handler.type is not None:
                self.visit(handler.type)
            if handler.name:
                self._set(handler.name, True)
            if self._visit_block(handler.body):
                continuing.append(self._copy_env(self.env_stack))
        self.env_stack = self._merge_env(continuing or exceptional)
        final_continues = self._visit_block(node.finalbody)
        return bool(continuing) and final_continues

    visit_TryStar = visit_Try

    def visit_Match(self, node):
        self.visit(node.subject)
        entry = self._copy_env(self.env_stack)
        states = [entry]
        for case in node.cases:
            self.env_stack = self._copy_env(entry)
            for pattern in ast.walk(case.pattern):
                if isinstance(pattern, (ast.MatchAs, ast.MatchStar)) and pattern.name:
                    self._set(pattern.name, self.is_tainted(node.subject))
            if case.guard is not None:
                self.visit(case.guard)
            if self._visit_block(case.body):
                states.append(self._copy_env(self.env_stack))
        self.env_stack = self._merge_env(states)

    def visit_Call(self, node):
        func = node.func
        func_name = None

        if isinstance(func, ast.Name):
            func_name = func.id
        elif isinstance(func, ast.Attribute):
            func_name = func.attr

        if func_name in REDIRECT_FUNCS and node.args:
            url_arg = node.args[0]

            if _is_request_args_get(url_arg):
                self.findings.append(
                    {
                        "rule_id": "SKY-D230",
                        "severity": "HIGH",
                        "message": (
                            "Possible open redirect: request parameter passed to "
                            "redirect via .get() — default value does not prevent "
                            "attacker-supplied input."
                        ),
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                        "symbol": self._current_symbol(),
                    }
                )
            elif self._starts_with_internal_url(url_arg):
                pass
            elif self.is_tainted(url_arg):
                self.findings.append(
                    {
                        "rule_id": "SKY-D230",
                        "severity": "HIGH",
                        "message": "Possible open redirect: user-controlled URL passed to redirect.",
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                        "symbol": self._current_symbol(),
                    }
                )

        self.generic_visit(node)


def scan(tree, file_path, findings, *, project_root=None):
    try:
        checker = _RedirectFlowChecker(file_path, findings, tree)
        checker.project_root = project_root
        checker.visit(tree)
    except Exception as e:
        print(f"Redirect flow analysis failed for {file_path}: {e}", file=sys.stderr)
