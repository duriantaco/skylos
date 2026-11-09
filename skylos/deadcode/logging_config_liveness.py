"""Bounded, source-only logging.config factory references.

A dotted string is a use only when a real dictConfig consumer receives the
containing configuration. Follow stable aliases, supplied/default arguments,
and constructor-owned attributes; never import or execute scanned modules.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

from skylos.deadcode._registration_common import (
    _FUNCTION_NODES,
    _decorator_reference,
    _executed_nodes,
    _import_aliases,
)
from skylos.deadcode.provider_method_liveness import _ProofLimit, _ProviderCalls
from skylos.deadcode._reachability_bindings import bound_names


_ROOTS = {
    "framework_root",
    "package_entrypoint",
    "test_entrypoint",
    "top_level_execution",
    "coverage_hit",
    "trace_hit",
    "reachable_from_root",
}


def _assignment(statement):
    if isinstance(statement, ast.Assign):
        return statement.targets, statement.value
    if isinstance(statement, ast.AnnAssign):
        return [statement.target], statement.value
    return (), None


def _entries(node):
    """Later literal dictionary keys replace earlier ones."""
    result = {}
    for key, value in zip(node.keys, node.values):
        if key is None:
            return {}
        if not isinstance(key, ast.Constant):
            return {}
        if isinstance(key.value, str):
            result[key.value] = value
    return result


class _LoggingConfigurations(_ProviderCalls):
    def __init__(self, definitions, parsed):
        super().__init__(definitions, parsed)
        self.arguments = defaultdict(set)
        self.reached = set()
        self.owners = {}
        self.sinks = []
        self.qualified_cache = {}
        self.exit_cache = {}
        self.site_cache = {}
        self.mutation_cache = {}
        self.origin_cache = {}
        self.external_write_cache = {}
        self.type_cache = {}
        self.sink_providers = {}
        self.mutation_nodes = [
            node
            for module in parsed
            for node in ast.walk(module.tree)
            if isinstance(node, ast.Call)
            or isinstance(node, (ast.Subscript, ast.Attribute))
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ]
        self.consumer_names = {
            alias.asname or alias.name
            for module in parsed
            for statement in ast.walk(module.tree)
            if isinstance(statement, ast.ImportFrom)
            and statement.module == "logging.config"
            for alias in statement.names
            if alias.name == "dictConfig"
        }

    def step(self):
        self.steps += 1
        if self.steps > 300_000:
            raise _ProofLimit

    def block_exits(self, statements):
        key = tuple(statements)
        if key not in self.exit_cache:
            self.exit_cache[key] = super().block_exits(statements)
        return self.exit_cache[key]

    def possible_site(self, node):
        if node not in self.site_cache:
            self.site_cache[node] = super().possible_site(node)
        return self.site_cache[node]

    def provider(self, expression, context):
        key = context, ast.dump(expression)
        if key not in self.qualified_cache:
            self.qualified_cache[key] = self._provider(expression, context)
        return self.qualified_cache[key]

    def imported_value(self, expression, context, seen=frozenset()):
        """Canonical imports through stable local/argument aliases, without trust."""
        self.step()
        if expression in seen or len(seen) >= 24:
            return None
        seen = seen | {expression}
        if isinstance(expression, ast.Attribute):
            base = self.imported_value(expression.value, context, seen)
            return f"{base}.{expression.attr}" if base else None
        if not isinstance(expression, ast.Name):
            return None
        binding, scope = self._lookup(expression.id, context)
        if isinstance(binding, ast.arg):
            values = {
                self.imported_value(actual, owner, seen)
                for actual, owner in self.arguments[binding]
            }
            return next(iter(values)) if len(values) == 1 else None
        if isinstance(binding, (ast.Name, ast.Attribute)):
            return self.imported_value(binding, scope, seen)
        imports = [binding] if isinstance(binding, (ast.Import, ast.ImportFrom)) else []
        if not imports and scope is not None:
            imports = [
                statement
                for statement in scope.body
                if isinstance(statement, (ast.Import, ast.ImportFrom))
            ]
            if isinstance(scope, _FUNCTION_NODES) and any(
                arg.arg == expression.id
                for arg in [
                    *scope.args.posonlyargs,
                    *scope.args.args,
                    *scope.args.kwonlyargs,
                ]
            ):
                return None
        if not imports or scope is None:
            return None
        parsed = self.files[self.file_for_node[scope]]
        resolved = []
        for statement in imports:
            names, modules = _import_aliases(
                ast.Module(body=[statement], type_ignores=[]),
                self.modules[self.file_for_node[scope]],
                parsed.path,
            )
            _, value = _decorator_reference(expression, names, modules, "")
            value = value or modules.get(expression.id)
            if value is not None:
                resolved.append(value)
        if not resolved or len(set(resolved)) != 1:
            return None
        if (
            binding is None
            and len(resolved) != bound_names(scope.body).counts[expression.id]
        ):
            return None
        return resolved[0]

    def _provider(self, expression, context):
        qualified = self.imported_value(expression, context)
        if qualified is None:
            return None
        for node in self.mutation_nodes:
            if isinstance(node, ast.Attribute) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                changed = self.imported_value(node, self.context(node))
                if changed and (
                    qualified == changed or qualified.startswith(changed + ".")
                ):
                    return None
            if isinstance(node, ast.Call) and len(node.args) >= 2:
                # An opaque setter receiving this provider also loses proof.
                setter = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else getattr(node.func, "attr", None)
                )
                if setter not in {"setattr", "delattr"}:
                    continue
                owner = self.imported_value(node.args[0], self.context(node))
                member = node.args[1]
                if owner and qualified.startswith(owner + "."):
                    if not isinstance(
                        member, ast.Constant
                    ) or qualified == owner + "." + str(member.value):
                        return None
        return qualified

    def bind_call(self, function, call, *, bound=False):
        positional = [*function.args.posonlyargs, *function.args.args]
        if bound and positional:
            positional = positional[1:]
        defaults = dict(
            zip(
                [*function.args.posonlyargs, *function.args.args][
                    -len(function.args.defaults) :
                ]
                if function.args.defaults
                else [],
                function.args.defaults,
            )
        )
        defaults.update(zip(function.args.kwonlyargs, function.args.kw_defaults))
        if any(isinstance(value, ast.Starred) for value in call.args):
            return
        keywords = {item.arg: item.value for item in call.keywords}
        for position, parameter in enumerate([*positional, *function.args.kwonlyargs]):
            value = keywords.get(parameter.arg)
            context = self.context(call)
            if value is None and parameter in positional and position < len(call.args):
                value = call.args[position]
            if value is None and None not in keywords:
                value = defaults.get(parameter)
                context = self.context(function)
            if value is not None:
                self.arguments[parameter].add((value, context))

    def collect_calls(self, definitions):
        pending = [parsed.tree for parsed in self.files.values()]
        for parsed in self.files.values():
            for node in ast.walk(parsed.tree):
                if isinstance(node, _FUNCTION_NODES):
                    matches = self.definitions_by_location.get(
                        (self.file_for_node[node], node.lineno), ()
                    )
                    if len(matches) == 1:
                        self.owners[node] = matches[0]
                        if _ROOTS.intersection(
                            getattr(matches[0], "heuristic_refs", {})
                        ):
                            pending.append(node)
        while pending:
            owner = pending.pop()
            if owner in self.reached:
                continue
            self.reached.add(owner)
            for call in _executed_nodes(owner.body):
                self.step()
                if not isinstance(call, ast.Call):
                    continue
                context = self.context(call)
                candidate = (
                    isinstance(call.func, ast.Attribute)
                    and call.func.attr == "dictConfig"
                    or isinstance(call.func, ast.Name)
                    and call.func.id in self.consumer_names
                )
                consumer = (
                    candidate
                    and self.provider(call.func, context) == "logging.config.dictConfig"
                )
                targets = self.call_targets(call)
                if not (consumer or targets) or not self.possible_site(call):
                    continue
                if consumer:
                    value = (
                        call.args[0]
                        if call.args
                        else next(
                            (
                                item.value
                                for item in call.keywords
                                if item.arg == "config"
                            ),
                            None,
                        )
                    )
                    if value is not None:
                        caller = self.owners.get(owner)
                        self.sinks.append((value, context, caller))
                        self.sink_providers[(id(value), id(context), id(caller))] = (
                            call.func
                        )
                for target, kind in targets:
                    if kind == "class":
                        scope = self.method_scope(target)
                        for initializer in scope.class_methods.get("__init__", ()):
                            self.bind_call(initializer, call, bound=True)
                            pending.append(initializer)
                    elif kind == "function" and self.executes_body(target, call):
                        bound = isinstance(
                            self.context(target), ast.ClassDef
                        ) and isinstance(call.func, ast.Attribute)
                        self.bind_call(target, call, bound=bound)
                        pending.append(target)

    def selects_dictionary(
        self, expression, context, dictionary, seen=frozenset(), *, exact=False
    ):
        """Follow aliases; containment/projection only counts for mutation checks."""
        self.step()
        if expression is dictionary:
            return True
        if expression is None or expression in seen or len(seen) >= 32:
            return False
        key = expression, context, dictionary, exact
        if key in self.origin_cache:
            return self.origin_cache[key]
        seen = seen | {expression}
        values = []
        if isinstance(expression, ast.Name):
            binding, scope = self._lookup(expression.id, context)
            if isinstance(binding, ast.arg):
                values.extend(self.arguments[binding])
            elif isinstance(binding, ast.ImportFrom):
                parsed = self.files[self.file_for_node[scope]]
                names, _ = _import_aliases(
                    ast.Module(body=[binding], type_ignores=[]),
                    self.modules[self.file_for_node[scope]],
                    parsed.path,
                )
                parts = names.get(expression.id, "").split(".")
                modules = self.module_paths.get(tuple(parts[:-1]), ())
                if len(modules) == 1:
                    values.append(
                        (ast.Name(id=parts[-1], ctx=ast.Load()), modules[0].tree)
                    )
            elif isinstance(binding, ast.AST):
                values.append((binding, scope))
        elif isinstance(expression, ast.Subscript) and not exact:
            values.append((expression.value, context))
        elif isinstance(expression, ast.Attribute):
            receiver = self.resolve(expression.value, context)
            if receiver and receiver[1] == "instance":
                for initializer in self.method_scope(receiver[0]).class_methods.get(
                    "__init__", ()
                ):
                    if initializer not in self.reached:
                        continue
                    params = [*initializer.args.posonlyargs, *initializer.args.args]
                    if not params:
                        continue
                    for statement in initializer.body:
                        targets, value = _assignment(statement)
                        if value is not None and any(
                            isinstance(target, ast.Attribute)
                            and target.attr == expression.attr
                            and isinstance(target.value, ast.Name)
                            and target.value.id == params[0].arg
                            for target in targets
                        ):
                            values.append((value, initializer))
        elif isinstance(expression, ast.IfExp):
            truth = self.literal_truth(expression.test)
            choices = (
                [expression.body, expression.orelse]
                if truth is None
                else [expression.body if truth else expression.orelse]
            )
            values.extend((value, context) for value in choices)
        elif not exact and isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
            values.extend((value, context) for value in expression.elts)
        elif not exact and isinstance(expression, ast.Dict):
            values.extend((value, context) for value in expression.values)
        elif (
            isinstance(expression, ast.Call)
            and isinstance(expression.func, ast.Attribute)
            and expression.func.attr == "copy"
        ):
            values.append((expression.func.value, context))
        result = any(
            self.selects_dictionary(value, owner, dictionary, seen, exact=exact)
            for value, owner in values
        )
        self.origin_cache[key] = result
        return result

    def literal_dictionary_site(self, node, dictionary):
        """Discard branches whose exact builtin type excludes a literal dict."""

        def truth(test):
            if (
                isinstance(test, ast.Call)
                and isinstance(test.func, ast.Name)
                and test.func.id == "isinstance"
                and len(test.args) == 2
            ):
                binding, scope = self._lookup("isinstance", self.context(test))
                if (
                    binding is not None
                    or scope is not None
                    or not self.selects_dictionary(
                        test.args[0], self.context(test), dictionary, exact=True
                    )
                ):
                    return None
                kind = test.args[1]
                if isinstance(kind, ast.Name) and kind.id in {
                    "dict",
                    "str",
                    "bytes",
                    "list",
                    "tuple",
                }:
                    binding, scope = self._lookup(kind.id, self.context(test))
                    if binding is None and scope is None:
                        return kind.id == "dict"
                if (
                    self.provider(kind, self.context(test)) == "os.PathLike"
                    and not self.module_paths.get(("os",))
                    and self.stable_type("os.PathLike")
                ):
                    return False
            if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                value = truth(test.operand)
                return None if value is None else not value
            if isinstance(test, ast.BoolOp):
                values = [truth(value) for value in test.values]
                if isinstance(test.op, ast.And):
                    if False in values:
                        return False
                    if all(value is True for value in values):
                        return True
                if isinstance(test.op, ast.Or):
                    if True in values:
                        return True
                    if all(value is False for value in values):
                        return False
            return None

        child = node
        parent = self.parents.get(child)
        while parent is not None:
            if isinstance(parent, ast.BoolOp) and child in parent.values:
                for previous in parent.values[: parent.values.index(child)]:
                    value = truth(previous)
                    if (isinstance(parent.op, ast.And) and value is False) or (
                        isinstance(parent.op, ast.Or) and value is True
                    ):
                        return False
            if isinstance(parent, ast.If):
                value = truth(parent.test)
                if value is not None and (
                    (child in parent.body and not value)
                    or (child in parent.orelse and value)
                ):
                    return False
            child, parent = parent, self.parents.get(parent)
        return True

    def stable_type(self, qualified):
        """ABC registration, type hooks and class escapes can change isinstance."""
        if qualified in self.type_cache:
            return self.type_cache[qualified]
        stable = True
        for node in self.mutation_nodes:
            self.step()
            context = self.context(node)
            if isinstance(node, ast.Attribute) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                changed = self.imported_value(node, context)
                if changed and changed.startswith(qualified + "."):
                    stable = False
                    break
            if not isinstance(node, ast.Call):
                continue
            if self.imported_value(node.func, context) == qualified + ".register":
                stable = False
                break
            escaped = any(
                self.imported_value(value, context) == qualified
                for argument in [*node.args, *(item.value for item in node.keywords)]
                for value in ast.walk(argument)
            )
            if not escaped:
                continue
            if isinstance(node.func, ast.Name) and node.func.id in {
                "isinstance",
                "issubclass",
            }:
                binding, scope = self._lookup(node.func.id, context)
                if binding is None and scope is None:
                    continue
            stable = False
            break
        self.type_cache[qualified] = stable
        return stable

    def stable_dictionary(self, dictionary):
        if dictionary in self.mutation_cache:
            return self.mutation_cache[dictionary]
        stable = True
        for node in self.mutation_nodes:
            self.step()
            context = self.context(node)
            if not self.literal_dictionary_site(node, dictionary):
                continue
            if isinstance(node, (ast.Subscript, ast.Attribute)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                if not self.selects_dictionary(node.value, context, dictionary):
                    continue
                path = []
                target = node
                while isinstance(target, ast.Subscript):
                    if not isinstance(target.slice, ast.Constant):
                        stable = False
                        break
                    path.append(target.slice.value)
                    target = target.value
                if (
                    not stable
                    or not path
                    or len(path) < 3
                    or path[0] in {"()", "class"}
                ):
                    stable = False
                    break
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute) and self.selects_dictionary(
                node.func.value, context, dictionary
            ):
                if node.func.attr not in {
                    "get",
                    "items",
                    "keys",
                    "values",
                    "copy",
                    "endswith",
                    "startswith",
                }:
                    stable = False
                    break
            passed = any(
                self.selects_dictionary(value, context, dictionary)
                for value in [*node.args, *(item.value for item in node.keywords)]
            )
            if not passed:
                continue
            if self.imported_value(node.func, context) in {
                "logging.config.dictConfig",
                "copy.deepcopy",
            }:
                continue
            if isinstance(node.func, ast.Name) and node.func.id in {
                "isinstance",
                "len",
                "bool",
                "type",
            }:
                binding, scope = self._lookup(node.func.id, context)
                if binding is None and scope is None:
                    continue
            if self.call_targets(node):
                continue
            stable = False
            break
        self.mutation_cache[dictionary] = stable
        return stable

    def external_attribute_write(self, owner, attribute):
        key = owner, attribute
        if key in self.external_write_cache:
            return self.external_write_cache[key]
        changed = False
        for node in self.mutation_nodes:
            if (
                not isinstance(node, ast.Attribute)
                or not isinstance(node.ctx, (ast.Store, ast.Del))
                or node.attr != attribute
            ):
                continue
            context = self.context(node)
            if isinstance(context, _FUNCTION_NODES) and self.context(context) is owner:
                params = [*context.args.posonlyargs, *context.args.args]
                if (
                    params
                    and isinstance(node.value, ast.Name)
                    and node.value.id == params[0].arg
                ):
                    continue
            receiver = self.resolve(node.value, context)
            if receiver == (owner, "instance"):
                changed = True
                break
        self.external_write_cache[key] = changed
        return changed

    def destructive_attribute_use(self, method, attribute):
        params = [*method.args.posonlyargs, *method.args.args]
        if not params:
            return False

        def selected(node):
            while isinstance(node, ast.Subscript):
                node = node.value
            return (
                isinstance(node, ast.Attribute)
                and node.attr == attribute
                and isinstance(node.value, ast.Name)
                and node.value.id == params[0].arg
            )

        for node in _executed_nodes(method.body):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if selected(node.func.value) and node.func.attr in {
                    "clear",
                    "update",
                    "pop",
                    "popitem",
                    "setdefault",
                    "__setitem__",
                    "__delitem__",
                }:
                    return True
            if (
                isinstance(node, ast.Subscript)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and selected(node)
            ):
                path = []
                value = node
                while isinstance(value, ast.Subscript):
                    if not isinstance(value.slice, ast.Constant):
                        return True
                    path.append(value.slice.value)
                    value = value.value
                if len(path) < 3 or path[0] in {"()", "class"}:
                    return True
        return False

    def values(self, expression, context, seen=frozenset()):
        self.step()
        if expression is None or expression in seen or len(seen) >= 32:
            return set()
        seen = seen | {expression}
        if isinstance(expression, ast.Dict):
            return (
                {(expression, context)} if self.stable_dictionary(expression) else set()
            )
        if isinstance(expression, ast.Name):
            binding, scope = self._lookup(expression.id, context)
            if isinstance(binding, ast.arg):
                return {
                    value
                    for actual, owner in self.arguments[binding]
                    for value in self.values(actual, owner, seen)
                }
            if isinstance(binding, ast.ImportFrom):
                parsed = self.files[self.file_for_node[scope]]
                names, _ = _import_aliases(
                    ast.Module(body=[binding], type_ignores=[]),
                    self.modules[self.file_for_node[scope]],
                    parsed.path,
                )
                qualified = names.get(expression.id, "")
                parts = qualified.split(".")
                modules = self.module_paths.get(tuple(parts[:-1]), ())
                if len(modules) == 1:
                    self.prepare(modules[0])
                    return self.values(
                        ast.Name(id=parts[-1], ctx=ast.Load()), modules[0].tree, seen
                    )
            if isinstance(binding, ast.AST) and not isinstance(
                binding, (ast.Import, ast.ImportFrom, *_FUNCTION_NODES, ast.ClassDef)
            ):
                return self.values(binding, scope, seen)
        elif isinstance(expression, ast.IfExp):
            truth = self.literal_truth(expression.test)
            choices = (
                [expression.body, expression.orelse]
                if truth is None
                else [expression.body if truth else expression.orelse]
            )
            return {
                value
                for choice in choices
                for value in self.values(choice, context, seen)
            }
        elif isinstance(expression, ast.Attribute):
            receiver = self.resolve(expression.value, context)
            if receiver and receiver[1] == "instance":
                if self.external_attribute_write(receiver[0], expression.attr):
                    return set()
                scopes = self.method_scope(receiver[0]).class_methods
                if any(
                    method in self.reached
                    and self.destructive_attribute_use(method, expression.attr)
                    for methods in scopes.values()
                    for method in methods
                ):
                    return set()
                # A definite write in this method precedes constructor state.
                methods = [context] if isinstance(context, _FUNCTION_NODES) else []
                methods.extend(scopes.get("__init__", ()))
                for method in methods:
                    params = [*method.args.posonlyargs, *method.args.args]
                    if not params or method not in self.reached:
                        continue
                    writes = []
                    for statement in method.body:
                        if method is context and statement.lineno >= expression.lineno:
                            break
                        targets, value = _assignment(statement)
                        if value is not None and any(
                            isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == params[0].arg
                            and target.attr == expression.attr
                            for target in targets
                        ):
                            writes.append(value)
                    if writes:
                        return self.values(writes[-1], method, seen)
        return set()

    def factory(self, name):
        if not isinstance(name, str) or len(name) > 300:
            return None
        resolved = self._qualified(name, frozenset())
        if resolved is None or resolved[1] not in {"class", "function"}:
            return None
        node = resolved[0]
        matches = self.definitions_by_location.get(
            (self.file_for_node[node], node.lineno), ()
        )
        return matches[0] if len(matches) == 1 else None


def find_logging_config_targets(definitions, parsed_files, root):
    """Return (factory, consumer owner) pairs with a proven source flow."""
    parsed = list(parsed_files)
    # Do not add another source index to projects with no factory configuration.
    aliases = {
        alias.asname or alias.name
        for module in parsed
        for statement in ast.walk(module.tree)
        if isinstance(statement, ast.ImportFrom)
        and statement.module == "logging.config"
        for alias in statement.names
        if alias.name == "dictConfig"
    }
    if not any(
        isinstance(node, ast.Call)
        and (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "dictConfig"
            or isinstance(node.func, ast.Name)
            and node.func.id in aliases
        )
        for module in parsed
        for node in ast.walk(module.tree)
    ):
        return []
    if not any(
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value in {"()", "class"}
        for module in parsed
        for node in ast.walk(module.tree)
    ):
        return []
    root = Path(root)
    if any(
        module.path.resolve() in {root / "logging.py", root / "logging" / "__init__.py"}
        for module in parsed
    ):
        return []
    try:
        source = _LoggingConfigurations(definitions, parsed)
        source.collect_calls(definitions)
        # Argument aliases are complete only after the reachable call graph.
        source.qualified_cache.clear()
        found = {}
        for value, context, caller in source.sinks:
            provider = source.sink_providers[(id(value), id(context), id(caller))]
            if source.provider(provider, context) != "logging.config.dictConfig":
                continue
            for config, _scope in source.values(value, context):
                entries = _entries(config)
                version = entries.get("version")
                if (
                    not isinstance(version, ast.Constant)
                    or type(version.value) is not int
                    or version.value != 1
                ):
                    continue
                incremental = entries.get("incremental")
                if incremental is not None and not (
                    isinstance(incremental, ast.Constant) and incremental.value is False
                ):
                    continue
                for section in ("formatters", "filters", "handlers"):
                    configs = entries.get(section)
                    if not isinstance(configs, ast.Dict):
                        continue
                    for settings in _entries(configs).values():
                        if not isinstance(settings, ast.Dict):
                            continue
                        factory = _entries(settings).get("()")
                        if factory is None and section != "filters":
                            factory = _entries(settings).get("class")
                        if isinstance(factory, ast.Constant):
                            target = source.factory(factory.value)
                            if target is not None:
                                found[(id(target), id(caller))] = target, caller
        return list(found.values())
    except (_ProofLimit, RecursionError):
        return []
