"""Source-owned reads of imports forwarded through Python wildcard imports."""

from __future__ import annotations

import ast

from skylos.deadcode._reachability_bindings import (
    argument_nodes,
    bound_names,
    default_expressions,
    import_bindings,
    relative_parent,
)
from skylos.deadcode.type_checking_imports import _FunctionBindings

_UNSUPPORTED = (
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    getattr(ast, "TryStar", ast.Try),
    ast.With,
    ast.AsyncWith,
    ast.Match,
)


def _stops(body):
    for node in body:
        if isinstance(node, (ast.Return, ast.Raise)):
            return True
        if isinstance(node, ast.If):
            if isinstance(node.test, ast.Constant):
                if _stops(node.body if node.test.value else node.orelse):
                    return True
            elif node.orelse and _stops(node.body) and _stops(node.orelse):
                return True
    return False


def _statements(body):
    for node in body:
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for name in ("body", "orelse", "finalbody"):
            children = getattr(node, name, ())
            if isinstance(children, list):
                yield from _statements(children)
        for handler in getattr(node, "handlers", ()):
            yield from _statements(handler.body)
        for case in getattr(node, "cases", ()):
            yield from _statements(case.body)


def _star(node):
    return isinstance(node, ast.ImportFrom) and any(
        alias.name == "*" for alias in node.names
    )


def _merge(states):
    keys = set().union(*(state.keys() for state in states))
    return {
        key: frozenset().union(*(state.get(key, ()) for state in states))
        for key in keys
    }


class _Reads(ast.NodeVisitor):
    def __init__(self, state, read):
        self.state = state
        self.read = read

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            self.read(self.state.get(node.id, ()))

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        if isinstance(node.target, ast.Name):
            self.state[node.target.id] = frozenset()

    def visit_Lambda(self, node):
        for value in default_expressions(node.args):
            self.visit(value)
        # A deferred lambda needs its own reachable-owner proof.

    def visit_IfExp(self, node):
        self.visit(node.test)
        if isinstance(node.test, ast.Constant):
            self.visit(node.body if node.test.value else node.orelse)
        else:
            self.visit(node.body)
            self.visit(node.orelse)

    def visit_BoolOp(self, node):
        for value in node.values:
            self.visit(value)
            if isinstance(value, ast.Constant) and (
                isinstance(node.op, ast.And)
                and not value.value
                or isinstance(node.op, ast.Or)
                and value.value
            ):
                break

    def visit_GeneratorExp(self, node):
        # Creating a generator evaluates only its outermost iterable.
        if node.generators:
            self.visit(node.generators[0].iter)

    def visit_ListComp(self, node):
        previous = self.state
        self.state = dict(previous)
        for generator in node.generators:
            self.visit(generator.iter)
            if (
                isinstance(generator.iter, (ast.List, ast.Tuple, ast.Set))
                and not generator.iter.elts
            ):
                self.state = previous
                return
            for child in ast.walk(generator.target):
                if isinstance(child, ast.Name):
                    self.state[child.id] = frozenset()
            for condition in generator.ifs:
                self.visit(condition)
                if isinstance(condition, ast.Constant) and not condition.value:
                    self.state = previous
                    return
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)
        self.state = previous
        # Walrus targets belong to the enclosing scope. Conservatively forget
        # their old binding even when a comprehension's iteration is unknown.
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr) and isinstance(child.target, ast.Name):
                self.state[child.target.id] = frozenset()

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp


class _NamespaceChanges(ast.NodeVisitor):
    """Track actual module namespace handles, rather than arbitrary objects."""

    def __init__(self, module):
        self.module = module
        self.bindings = dict(module.bindings)
        for node in module.tree.body:
            if isinstance(node, ast.ClassDef) and len(module.names) == 1:
                self.bindings[node.name] = (
                    "qualified",
                    f"{next(iter(module.names))}.{node.name}",
                )
        self.changed = set()
        self.changed_attributes = set()
        self.deferred = False
        self.class_globals = None

    def resolve(self, node):
        if isinstance(node, ast.Name):
            return self.bindings.get(node.id)
        if isinstance(node, ast.Attribute):
            owner = self.resolve(node.value)
            if owner and owner[0] == "module":
                if node.attr == "__dict__":
                    return ("namespace", owner[1])
                return ("module", f"{owner[1]}.{node.attr}")
        if isinstance(node, ast.Subscript):
            owner = self.resolve(node.value)
            if owner and owner[1] == "sys.modules":
                name = node.slice
                if isinstance(name, ast.Constant) and isinstance(name.value, str):
                    return ("module", name.value)
                if isinstance(name, ast.Name) and name.id == "__name__":
                    return ("module", next(iter(self.module.names), ""))
                return ("module", "*")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "globals" or (
                not self.deferred
                and node.func.id in {"locals", "vars"}
                and not node.args
                and not node.keywords
            ):
                return ("namespace", next(iter(self.module.names), ""))
        return None

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load) and node.id in {"globals", "eval", "exec"}:
            self.changed.update(self.module.names)
        binding = self.resolve(node)
        if binding and binding[0] == "namespace":
            self.changed.add(binding[1])

    def visit_Attribute(self, node):
        binding = self.resolve(node)
        if binding and binding[0] == "namespace":
            self.changed.add(binding[1])
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            owner = self.resolve(node.value)
            if owner:
                self.changed_attributes.add((owner[1], node.attr))
                if owner[0] == "module":
                    self.changed.add(owner[1])
        self.generic_visit(node)

    def visit_Call(self, node):
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in {"setattr", "delattr"}
            and node.args
        ):
            owner = self.resolve(node.args[0])
            if owner:
                attribute = node.args[1] if len(node.args) > 1 else None
                name = (
                    attribute.value
                    if isinstance(attribute, ast.Constant)
                    and isinstance(attribute.value, str)
                    else "*"
                )
                self.changed_attributes.add((owner[1], name))
                if owner[0] in {"module", "namespace"}:
                    self.changed.add(owner[1])
        binding = self.resolve(node)
        if binding and binding[0] == "namespace":
            self.changed.add(binding[1])
        self.generic_visit(node)

    def visit_Assign(self, node):
        self.generic_visit(node)
        binding = self.resolve(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.bindings[target.id] = binding

    def visit_AnnAssign(self, node):
        self.generic_visit(node)
        if isinstance(node.target, ast.Name):
            self.bindings[node.target.id] = self.resolve(node.value)

    def visit_Import(self, node):
        self.bindings.update(import_bindings(node, self.module))

    visit_ImportFrom = visit_Import

    def visit_If(self, node):
        self.visit(node.test)
        if isinstance(node.test, ast.Constant):
            for child in node.body if node.test.value else node.orelse:
                self.visit(child)
        else:
            for child in [*node.body, *node.orelse]:
                self.visit(child)

    def visit_FunctionDef(self, node):
        for value in [*node.decorator_list, *default_expressions(node.args)]:
            self.visit(value)
        previous, deferred = self.bindings, self.deferred
        self.bindings = dict(self.class_globals or previous)
        locals_ = _FunctionBindings()
        for child in node.body:
            locals_.visit(child)
        for name in set(locals_.counts) | {
            arg.arg for arg in argument_nodes(node.args)
        }:
            self.bindings[name] = None
        self.deferred = True
        for child in node.body:
            self.visit(child)
        self.bindings, self.deferred = previous, deferred

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        for value in [
            *node.decorator_list,
            *node.bases,
            *(keyword.value for keyword in node.keywords),
        ]:
            self.visit(value)
        previous, class_globals = self.bindings, self.class_globals
        self.class_globals = previous
        self.bindings = dict(previous)
        for child in node.body:
            self.visit(child)
        self.bindings, self.class_globals = previous, class_globals


class _DirectStaticCall(_Reads):
    def __init__(self, owner, method):
        super().__init__({}, lambda values: None)
        self.owner, self.method = owner, method
        self.found = False

    def visit_Call(self, node):
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == self.owner
            and node.func.attr == self.method
        ):
            self.found = True
        self.generic_visit(node)

    def body(self, statements):
        for node in statements:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(node, _UNSUPPORTED):
                break
            if isinstance(node, ast.If):
                self.visit(node.test)
                branches = [node.body, node.orelse]
                if isinstance(node.test, ast.Constant):
                    branches = [node.body if node.test.value else node.orelse]
                for branch in branches:
                    self.body(branch)
                if all(_stops(branch) for branch in branches):
                    break
            else:
                self.visit(node)
                if isinstance(node, (ast.Return, ast.Raise)):
                    break


class _WildcardReads:
    def __init__(self, definitions, report):
        self.definitions = definitions
        self.report = report
        self.modules = report.index.modules
        self.exports_cache = {}
        self.origins = {}
        self.used = set()
        self.identities = {}
        self.functions = {}
        self.changed_namespaces = set()
        self.changed_attributes = set()
        self.module_changed_attributes = {}
        for module in self.modules.values():
            changes = _NamespaceChanges(module)
            changes.visit(module.tree)
            self.changed_namespaces.update(changes.changed)
            self.changed_attributes.update(changes.changed_attributes)
            self.module_changed_attributes[module.path] = changes.changed_attributes
        for key, definition in definitions.items():
            if definition.type in {"function", "method"}:
                self.functions.setdefault(
                    (str(definition.filename), definition.line), []
                ).append(key)
            if definition.type == "import":
                name = definition.binding_name or definition.simple_name
                self.origins.setdefault(
                    (str(definition.filename), definition.line, name), set()
                ).add(key)
        self.live_callers = set(getattr(report, "proven_reachable_keys", ()))
        self.live_callers.update(
            key
            for key, definition in definitions.items()
            if definition.type in {"function", "method"}
            and (
                bool(getattr(definition, "is_exported", False))
                or any(
                    marker in getattr(definition, "heuristic_refs", {})
                    for marker in (
                        "top_level_execution",
                        "framework_root",
                        "package_entrypoint",
                        "test_entrypoint",
                        "coverage_hit",
                        "trace_hit",
                    )
                )
            )
        )

    def unstable_namespace(self, module):
        return (
            "*" in self.changed_namespaces
            or bool(module.names & self.changed_namespaces)
            or any(
                isinstance(node, (ast.Global, ast.Nonlocal))
                for node in ast.walk(module.tree)
            )
        )

    def exported(self, module, stack=()):
        if module.path in self.exports_cache:
            return self.exports_cache[module.path]
        if module.path in stack or len(stack) >= 16:
            return None
        if self.unstable_namespace(module):
            return None
        if any(
            isinstance(node, _UNSUPPORTED) for node in _statements(module.tree.body)
        ):
            return None
        state = self.block(module.tree.body, {}, module, stack=(*stack, module.path))
        exports = None
        declared = False
        conditional = False
        for node in _statements(module.tree.body):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                if any(
                    isinstance(target, ast.Name) and target.id == "__all__"
                    for target in targets
                ):
                    declared = True
                    conditional |= node not in module.tree.body
                    value = node.value
                    if isinstance(value, (ast.List, ast.Tuple, ast.Set)) and all(
                        isinstance(item, ast.Constant) and isinstance(item.value, str)
                        for item in value.elts
                    ):
                        exports = {item.value for item in value.elts}
                    else:
                        exports = None
        # Mutating or computing __all__ is not a complete export declaration.
        if any(
            isinstance(node, ast.Name)
            and node.id == "__all__"
            and isinstance(node.ctx, ast.Load)
            for node in ast.walk(module.tree)
        ):
            exports = None
        if declared and (exports is None or conditional):
            result = None
        else:
            names = (
                exports
                if declared
                else {name for name in state if not name.startswith("_")}
            )
            result = {name: state.get(name, frozenset()) for name in names}
        self.exports_cache[module.path] = result
        return result

    def provider(self, node, module):
        name = relative_parent(node, module) if node.level else node.module
        matches = self.report.index.module_names.get(name, ())
        return matches[0] if len(matches) == 1 else None

    def redundant_consumer_import(self, current, forwarded, module):
        if not current or not forwarded:
            return False
        if any(
            str(self.definitions[key].filename) != str(module.path) for key in current
        ):
            return False
        identities = {self.identities.get(key) for key in current | forwarded}
        return (
            len(identities) == 1
            and None not in identities
            and next(iter(identities))[0] == "module"
        )

    def live_function(self, module, node):
        owner = next(
            (
                item
                for item in module.tree.body
                if isinstance(item, ast.ClassDef) and node in item.body
            ),
            None,
        )
        changed = owner is not None and any(
            (f"{name}.{owner.name}", attribute) in self.changed_attributes
            for name in module.names
            for attribute in (node.name, "*")
        )
        if owner is not None and any(
            (f"{name}.{owner.name}", attribute)
            in self.module_changed_attributes[module.path]
            for name in module.names
            for attribute in (node.name, "*")
        ):
            return False
        key = module.functions.get(node.lineno)
        if key is not None:
            return key not in self.report.unreachable_keys
        keys = self.functions.get((str(module.path), node.lineno), ())
        if len(keys) != 1 or keys[0] in self.report.unreachable_keys:
            return False
        refs = self.definitions[keys[0]].heuristic_refs
        if not changed and any(
            marker in refs
            for marker in (
                "top_level_execution",
                "framework_root",
                "package_entrypoint",
                "reachable_from_root",
                "dead_code_liveness:source_provider_method",
            )
        ):
            return True
        # Some class registries keep their factory method outside the bounded
        # callable index. Follow an exact static call from an indexed retained
        # owner, rather than treating attribute-reference counts as roots.
        definition = self.definitions[keys[0]]
        callers = set(getattr(definition, "called_by", ()) or ())
        if not callers:
            return False
        bindings = bound_names(module.tree.body)
        if bindings.counts.get("staticmethod"):
            return False
        if (
            owner is None
            or bindings.counts.get(owner.name) != 1
            or owner.bases
            or owner.keywords
            or owner.decorator_list
            or bound_names(owner.body).counts.get("staticmethod")
            or not any(
                isinstance(item, ast.Name) and item.id == "staticmethod"
                for item in node.decorator_list
            )
        ):
            return False
        for caller in module.tree.body:
            if not isinstance(caller, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            caller_key = module.functions.get(caller.lineno)
            if (
                caller_key not in callers
                or caller_key in self.report.unreachable_keys
                or caller_key not in self.live_callers
            ):
                continue
            if changed:
                caller_definition = self.definitions.get(caller_key)
                exported = bool(getattr(caller_definition, "is_exported", False))
                # An exported package API is an independent existing root.
                # A deferred foreign patch does not replace its own module's
                # binding. Otherwise require an import-time call that happens
                # before another module can obtain and replace the class.
                import_time = "top_level_execution" in getattr(
                    caller_definition, "heuristic_refs", {}
                ) and all(
                    isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Pass))
                    or (
                        isinstance(item, ast.Expr)
                        and isinstance(item.value, ast.Call)
                        and isinstance(item.value.func, ast.Name)
                        and item.value.func.id == caller.name
                    )
                    for item in module.tree.body[module.tree.body.index(owner) + 1 :]
                )
                if not exported and not import_time:
                    continue
            local_names = set(bound_names(caller.body).counts) | {
                arg.arg for arg in argument_nodes(caller.args)
            }
            if owner.name in local_names:
                continue
            visitor = _DirectStaticCall(owner.name, node.name)
            visitor.body(caller.body)
            if visitor.found:
                return True
        return False

    def credit(self, values, module):
        for key in values:
            if str(self.definitions[key].filename) != str(module.path):
                self.used.add(key)

    def read(self, node, state, module, collecting):
        read = (
            (lambda values: self.credit(values, module))
            if collecting
            else lambda values: None
        )
        _Reads(state, read).visit(node)

    def block(
        self,
        body,
        state,
        module,
        *,
        stack=(),
        collecting=False,
        globals_state=None,
        shadowed=frozenset(),
    ):
        state = dict(state)
        for node in body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if _star(node):
                    provider = self.provider(node, module)
                    exports = (
                        self.exported(provider, stack) if provider is not None else None
                    )
                    if exports is None:
                        state = {
                            name: value if name.startswith("_") else frozenset()
                            for name, value in state.items()
                        }
                    else:
                        for name, values in exports.items():
                            current = state.get(name, frozenset())
                            if not self.redundant_consumer_import(
                                current, values, module
                            ):
                                state[name] = values
                else:
                    bindings = import_bindings(node, module)
                    for alias in node.names:
                        name = alias.asname or (
                            alias.name.split(".")[0]
                            if isinstance(node, ast.Import)
                            else alias.name
                        )
                        state[name] = frozenset(
                            self.origins.get((str(module.path), alias.lineno, name), ())
                        )
                        for key in state[name]:
                            self.identities[key] = bindings.get(name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for expression in [
                    *node.decorator_list,
                    *default_expressions(node.args),
                    *(
                        arg.annotation
                        for arg in argument_nodes(node.args)
                        if arg.annotation
                    ),
                    *([node.returns] if node.returns else []),
                ]:
                    self.read(expression, state, module, collecting)
                if collecting:
                    if self.live_function(module, node):
                        locals_ = _FunctionBindings()
                        for child in node.body:
                            locals_.visit(child)
                        if not locals_.scope_writes:
                            local = dict(globals_state or {})
                            local_names = (
                                shadowed
                                | set(locals_.counts)
                                | {arg.arg for arg in argument_nodes(node.args)}
                            )
                            for name in local_names:
                                local[name] = frozenset()
                            self.block(
                                node.body,
                                local,
                                module,
                                collecting=True,
                                globals_state=globals_state,
                                shadowed=local_names,
                            )
                state[node.name] = frozenset()
            elif isinstance(node, ast.ClassDef):
                for expression in [
                    *node.decorator_list,
                    *node.bases,
                    *(keyword.value for keyword in node.keywords),
                ]:
                    self.read(expression, state, module, collecting)
                if collecting:
                    # Unqualified double-private names in a class are mangled;
                    # they cannot read a same-spelled module wildcard binding.
                    class_state = {
                        name: value
                        for name, value in state.items()
                        if not name.startswith("__")
                    }
                    class_globals = {
                        name: value
                        for name, value in (globals_state or {}).items()
                        if not name.startswith("__")
                    }
                    self.block(
                        node.body,
                        class_state,
                        module,
                        collecting=True,
                        globals_state=class_globals,
                        shadowed=shadowed,
                    )
                state[node.name] = frozenset()
            elif isinstance(node, ast.If):
                self.read(node.test, state, module, collecting)
                branches = [node.body, node.orelse]
                if isinstance(node.test, ast.Constant):
                    branches = [node.body if node.test.value else node.orelse]
                state = _merge(
                    [
                        self.block(
                            branch,
                            state,
                            module,
                            stack=stack,
                            collecting=collecting,
                            globals_state=globals_state,
                            shadowed=shadowed,
                        )
                        for branch in branches
                    ]
                )
                if all(_stops(branch) for branch in branches):
                    break
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                value = node.value
                if value is not None:
                    self.read(value, state, module, collecting)
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                for target in targets:
                    self.read(target, state, module, collecting)
                    if (
                        isinstance(node, ast.AugAssign)
                        and isinstance(target, ast.Name)
                        and collecting
                    ):
                        self.credit(state.get(target.id, ()), module)
                    for child in ast.walk(target):
                        if isinstance(child, ast.Name) and isinstance(
                            child.ctx, ast.Store
                        ):
                            state[child.id] = frozenset()
            elif isinstance(node, ast.Delete):
                self.read(node, state, module, collecting)
                for child in ast.walk(node):
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Del):
                        state.pop(child.id, None)
            elif isinstance(node, (ast.Return, ast.Raise)):
                self.read(node, state, module, collecting)
                break
            elif isinstance(node, _UNSUPPORTED):
                # Unsupported control flow may replace a name. Never use a
                # later read as proof that an earlier wildcard supplied it.
                for name in bound_names([node]).counts:
                    state[name] = frozenset()
                break
            else:
                self.read(node, state, module, collecting)
        return state

    def run(self):
        for module in self.modules.values():
            if not any(_star(node) for node in _statements(module.tree.body)):
                continue
            if self.unstable_namespace(module):
                continue
            if any(
                isinstance(node, _UNSUPPORTED) for node in _statements(module.tree.body)
            ):
                continue
            final = self.block(module.tree.body, {}, module)
            self.block(
                module.tree.body, {}, module, collecting=True, globals_state=final
            )
        return self.used


def wildcard_provider_import_reads(definitions, report):
    """Return exact import-definition keys with a source-owned wildcard read."""
    if (
        report is None
        or not report.complete
        or not any(
            _star(node)
            for module in report.index.modules.values()
            for node in _statements(module.tree.body)
        )
    ):
        return set()
    return _WildcardReads(definitions, report).run()
