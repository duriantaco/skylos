"""Source-bound, caller-owned edges for finite Python reflection.

This proves possible calls, never framework roots. Unsupported lookup values
remain the responsibility of the existing conservative reflection analysis.
"""

from __future__ import annotations

import ast
from collections import defaultdict

from skylos.analysis.ast_cache import MODE_STRICT, load_python_source, run_memo
from skylos.deadcode._reachability_bindings import bound_names
from skylos.deadcode.plugin_registry import _reachable_live_functions

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_ROOTS = {
    "framework_root",
    "package_entrypoint",
    "top_level_execution",
    "reachable_from_root",
}
_CUSTOM = {
    "__new__",
    "__getattribute__",
    "__getattr__",
    "__setattr__",
    "__delattr__",
    "__init_subclass__",
}
_UNKNOWN = object()


def _own_nodes(node):
    def expression(item):
        yield item
        if isinstance(item, (*_FUNCTIONS, ast.ClassDef, ast.Lambda)):
            return
        if isinstance(item, ast.If):
            yield from expression(item.test)
            if isinstance(item.test, ast.Constant):
                yield from block(item.body if item.test.value else item.orelse)
            else:
                yield from block(item.body)
                yield from block(item.orelse)
            return
        if (
            isinstance(item, ast.While)
            and isinstance(item.test, ast.Constant)
            and not item.test.value
        ):
            yield from expression(item.test)
            yield from block(item.orelse)
            return
        for field, value in ast.iter_fields(item):
            if field in {"body", "orelse", "finalbody"} and isinstance(value, list):
                yield from block(value)
            elif isinstance(value, ast.AST):
                yield from expression(value)
            elif isinstance(value, list):
                for child in value:
                    if isinstance(child, ast.AST):
                        yield from expression(child)

    def block(statements):
        for statement in statements:
            yield from expression(statement)
            if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                break

    yield from block(node.body)


def _assignments(function):
    counts = bound_names(function.body).counts
    values = {}
    for node in _own_nodes(function):
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and counts[target.id] == 1:
                values[target.id] = value
    return counts, values


def _parameters(function):
    args = function.args
    return [
        *args.posonlyargs,
        *args.args,
        *args.kwonlyargs,
        *([args.vararg] if args.vararg else []),
        *([args.kwarg] if args.kwarg else []),
    ]


def _literal(node):
    try:
        if sum(1 for _ in ast.walk(node)) > 1024:
            return _UNKNOWN
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, RecursionError):
        return _UNKNOWN


def _called_lookup(node, nodes, counts):
    """The lookup is called directly or through a single-write local alias."""
    for call in nodes:
        if not isinstance(call, ast.Call):
            continue
        if call.func is node:
            return True
        if isinstance(call.func, ast.Name):
            name = call.func.id
            if counts[name] != 1:
                continue
            for statement in nodes:
                if isinstance(statement, ast.Assign) and statement.value is node:
                    if any(
                        isinstance(t, ast.Name) and t.id == name
                        for t in statement.targets
                    ):
                        return True
                if isinstance(statement, ast.AnnAssign) and statement.value is node:
                    if (
                        isinstance(statement.target, ast.Name)
                        and statement.target.id == name
                    ):
                        return True
    return False


def _has_global_candidate(tree):
    return any(
        isinstance(node, ast.Subscript)
        and isinstance(node.ctx, ast.Load)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "globals"
        and not node.value.args
        and not node.value.keywords
        for node in ast.walk(tree)
    )


def _has_class_candidate(tree):
    for cls in tree.body:
        if not isinstance(cls, ast.ClassDef):
            continue
        if not any(
            isinstance(statement, (ast.Assign, ast.AnnAssign))
            and isinstance(statement.value, ast.Dict)
            for statement in cls.body
        ):
            continue
        for function in cls.body:
            if not isinstance(function, _FUNCTIONS):
                continue
            args = [*function.args.posonlyargs, *function.args.args]
            if not args:
                continue
            if any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) == 2
                and not node.keywords
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == args[0].arg
                for node in ast.walk(function)
            ):
                return True
    return False


def _module_parts(parsed, definitions):
    candidates = []
    for source in parsed:
        text = load_python_source(source.path, MODE_STRICT) or ""
        if "globals" in text and _has_global_candidate(source.tree):
            candidates.append(source)
        elif "getattr" in text and _has_class_candidate(source.tree):
            candidates.append(source)
    if not candidates:
        return [], {}
    by_location = defaultdict(list)
    for definition in definitions.values():
        if definition.type in {"function", "method", "class"}:
            by_location[str(definition.filename), definition.line].append(definition)
    by_file = defaultdict(dict)
    for (file, line), values in by_location.items():
        if len(values) == 1:
            by_file[file][line] = values[0]
    modules = []
    for source in candidates:
        # Only supported lookup shapes justify project-wide proof work.
        definitions_here = by_file[str(source.path)]
        parents = {
            id(child): parent
            for parent in ast.walk(source.tree)
            for child in ast.iter_child_nodes(parent)
        }
        counts = bound_names(source.tree.body).counts
        classes = {
            n.name: n
            for n in source.tree.body
            if isinstance(n, ast.ClassDef) and counts[n.name] == 1
        }
        modules.append((source, definitions_here, parents, counts, classes))
    return modules, by_location


def _unsafe_module(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Global, ast.Nonlocal)) and set(node.names) & {
            "globals",
            "getattr",
        }:
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"exec", "eval", "setattr", "delattr"}:
                return True
        if isinstance(node, ast.Attribute):
            if node.attr in {"__dict__", "__bases__", "__class__"}:
                return True
            if node.attr in {"globals", "getattr"} and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                return True
        if isinstance(node, ast.Subscript) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            if isinstance(node.value, ast.Call) and isinstance(
                node.value.func, ast.Name
            ):
                if node.value.func.id in {"globals", "locals", "vars"}:
                    return True
    return False


def _safe_class(node, classes, counts, seen=()):
    if node.name in seen or len(seen) > 16 or node.decorator_list or node.keywords:
        return False
    if _CUSTOM.intersection(bound_names(node.body).counts):
        return False
    for statement in node.body:
        if isinstance(statement, _FUNCTIONS):
            if statement.decorator_list:
                return False
        elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
            if statement.value is not None and _literal(statement.value) is _UNKNOWN:
                return False
        elif not (
            isinstance(statement, ast.Pass)
            or isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
        ):
            return False
    for base in node.bases:
        if not isinstance(base, ast.Name):
            return False
        if base.id == "object" and not counts["object"]:
            continue
        parent = classes.get(base.id)
        if parent is None or not _safe_class(
            parent, classes, counts, (*seen, node.name)
        ):
            return False
    return True


def _class_edges(source, here, parents, module_counts, classes, mutations):
    if (
        module_counts["getattr"]
        or "getattr" in mutations
        or _unsafe_module(source.tree)
    ):
        return []
    edges = []
    for cls in classes.values():
        if not _safe_class(cls, classes, module_counts):
            continue
        if any(
            isinstance(n, ast.Global) and cls.name in n.names
            for n in ast.walk(source.tree)
        ):
            continue
        descendants = []
        pending = {cls.name}
        for _ in range(16):
            children = [
                n
                for n in classes.values()
                if n not in descendants
                and n is not cls
                and any(isinstance(b, ast.Name) and b.id in pending for b in n.bases)
            ]
            if not children:
                break
            descendants.extend(children)
            pending.update(n.name for n in children)
        else:
            continue
        if any(not _safe_class(child, classes, module_counts) for child in descendants):
            continue
        descendant_names = set().union(
            *(set(bound_names(child.body).counts) for child in descendants)
        )
        members = bound_names(cls.body).counts
        methods = {
            n.name: here.get(n.lineno)
            for n in cls.body
            if isinstance(n, _FUNCTIONS) and members[n.name] == 1
        }
        tables = {}
        for statement in cls.body:
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                target, value = statement.targets[0], statement.value
            elif isinstance(statement, ast.AnnAssign):
                target, value = statement.target, statement.value
            else:
                continue
            if (
                not isinstance(target, ast.Name)
                or members[target.id] != 1
                or not isinstance(value, ast.Dict)
            ):
                continue
            literal = _literal(value)
            if isinstance(literal, dict):
                if target.id not in mutations:
                    tables[target.id] = literal
        for function in cls.body:
            if not isinstance(function, _FUNCTIONS):
                continue
            caller = here.get(function.lineno)
            args = [*function.args.posonlyargs, *function.args.args]
            if caller is None or not args:
                continue
            receiver = args[0].arg
            parameter_names = {argument.arg for argument in _parameters(function)}
            counts, assignments = _assignments(function)
            if (
                counts[receiver]
                or counts["getattr"]
                or any(a.arg == "getattr" for a in _parameters(function))
            ):
                continue
            nodes = list(_own_nodes(function))

            def values(expr, seen=()):
                if expr is None or id(expr) in seen or len(seen) > 16:
                    return []
                seen = (*seen, id(expr))
                if isinstance(expr, ast.Name) and expr.id in assignments:
                    return values(assignments[expr.id], seen)
                if isinstance(expr, ast.Subscript) and isinstance(
                    expr.slice, ast.Constant
                ):
                    index = expr.slice.value
                    if not isinstance(index, int):
                        return []
                    return [
                        v[index]
                        for v in values(expr.value, seen)
                        if isinstance(v, (tuple, list)) and -len(v) <= index < len(v)
                    ]
                if not (
                    isinstance(expr, ast.Call)
                    and isinstance(expr.func, ast.Attribute)
                    and expr.func.attr == "get"
                    and len(expr.args) == 1
                    and not expr.keywords
                ):
                    return []
                table_expr = expr.func.value
                if not isinstance(table_expr, ast.Attribute) or not isinstance(
                    table_expr.value, ast.Name
                ):
                    return []
                owner = table_expr.value.id
                if owner not in {cls.name, receiver} or (
                    owner == cls.name and (counts[owner] or owner in parameter_names)
                ):
                    return []
                if owner == receiver and table_expr.attr in descendant_names:
                    return []
                table = tables.get(table_expr.attr)
                if table is None:
                    return []
                # Any other access can mutate/escape the registry. Only exact
                # lookups on this receiver or this source-defined class qualify.
                for part in ast.walk(source.tree):
                    if (
                        not isinstance(part, ast.Attribute)
                        or part.attr != table_expr.attr
                    ):
                        continue
                    if not isinstance(part.value, ast.Name) or part.value.id not in {
                        cls.name,
                        receiver,
                    }:
                        continue
                    parent = parents.get(id(part))
                    grand = parents.get(id(parent))
                    if not (
                        isinstance(parent, ast.Attribute)
                        and parent.attr == "get"
                        and isinstance(grand, ast.Call)
                        and grand.func is parent
                    ):
                        return []
                key = _literal(expr.args[0])
                if key is _UNKNOWN:
                    return list(table.values())
                try:
                    return [table[key]] if key in table else []
                except TypeError:
                    return []

            for call in nodes:
                if not (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id == "getattr"
                    and len(call.args) == 2
                    and not call.keywords
                ):
                    continue
                if (
                    not isinstance(call.args[0], ast.Name)
                    or call.args[0].id != receiver
                ):
                    continue
                if not _called_lookup(call, nodes, counts):
                    continue
                for name in values(call.args[1]):
                    target = methods.get(name) if isinstance(name, str) else None
                    if target is not None:
                        if name in descendant_names or name in mutations:
                            continue
                        if any(
                            isinstance(n, ast.Attribute)
                            and n.attr == name
                            and isinstance(n.ctx, (ast.Store, ast.Del))
                            for n in ast.walk(source.tree)
                        ):
                            continue
                        edges.append((target, caller))
    return edges


def _import_map(nodes, prefix):
    imports = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                if prefix is None:
                    continue
                package = prefix.rpartition(".")[0]
                parts = package.split(".")
                base = ".".join(
                    [*parts[: len(parts) - node.level + 1], *([base] if base else [])]
                )
            for alias in node.names:
                if alias.name != "*":
                    imports[alias.asname or alias.name] = ".".join(
                        filter(None, [base, alias.name])
                    )
    return imports


def _call_arguments(parsed, by_location, reachable):
    """Index source-bound calls once, including script-only importing modules."""
    by_file = defaultdict(dict)
    for (file, line), definitions in by_location.items():
        if len(definitions) == 1:
            by_file[file][line] = definitions[0]
    calls = defaultdict(list)
    for source in parsed:
        definitions = by_file[str(source.path)]
        prefix = next(
            (
                d.name.rsplit(".", 1)[0]
                for d in definitions.values()
                if d.type == "function"
            ),
            None,
        )
        module_counts = bound_names(source.tree.body).counts
        imports = _import_map(source.tree.body, prefix)
        written_attributes = {
            n.attr
            for n in ast.walk(source.tree)
            if isinstance(n, ast.Attribute) and isinstance(n.ctx, (ast.Store, ast.Del))
        }
        pending = [source.tree]
        while pending:
            scope = pending.pop()
            nodes = list(_own_nodes(scope))
            pending.extend(
                n for n in nodes if isinstance(n, (*_FUNCTIONS, ast.ClassDef))
            )
            if isinstance(scope, ast.ClassDef):
                continue
            owner = (
                definitions.get(scope.lineno) if isinstance(scope, _FUNCTIONS) else None
            )
            if isinstance(scope, _FUNCTIONS) and (
                owner is None or owner.name not in reachable
            ):
                continue
            if isinstance(scope, _FUNCTIONS):
                counts = bound_names(scope.body).counts
                parameters = {a.arg for a in _parameters(scope)}
                local_imports = _import_map(nodes, prefix)
            else:
                counts, parameters, local_imports = {}, set(), {}
            for call in nodes:
                if (
                    not isinstance(call, ast.Call)
                    or any(isinstance(a, ast.Starred) for a in call.args)
                    or any(k.arg is None for k in call.keywords)
                ):
                    continue
                chain = []
                expr = call.func
                while isinstance(expr, ast.Attribute):
                    chain.append(expr.attr)
                    expr = expr.value
                if not isinstance(expr, ast.Name) or expr.id in parameters:
                    continue
                if counts.get(expr.id, 0):
                    if counts[expr.id] != 1 or expr.id not in local_imports:
                        continue
                    binding = local_imports[expr.id]
                elif module_counts[expr.id] == 1:
                    binding = imports.get(expr.id)
                    if binding is None and prefix is not None and not chain:
                        binding = prefix + "." + expr.id
                else:
                    continue
                if binding is None or chain and chain[0] in written_attributes:
                    continue
                qualified = ".".join([binding, *reversed(chain)])
                calls[qualified].append(call)
    return calls


def _global_edges(modules, parsed, by_location, reachable, mutations):
    edges = []
    if "globals" in mutations:
        return edges
    if not any(_has_global_candidate(m[0].tree) for m in modules):
        return edges
    call_arguments = _call_arguments(parsed, by_location, reachable)
    for source, here, parents, module_counts, _classes in modules:
        if module_counts["globals"] or _unsafe_module(source.tree):
            continue
        for function in source.tree.body:
            if (
                not isinstance(function, _FUNCTIONS)
                or module_counts[function.name] != 1
            ):
                continue
            caller = here.get(function.lineno)
            if caller is None:
                continue
            counts, assignments = _assignments(function)
            positional = [*function.args.posonlyargs, *function.args.args]
            parameters = [*positional, *function.args.kwonlyargs]
            parameter_names = [p.arg for p in parameters]
            if (
                any(p.arg == "globals" for p in _parameters(function))
                or counts["globals"]
            ):
                continue
            nodes = list(_own_nodes(function))
            for lookup in nodes:
                if not (
                    isinstance(lookup, ast.Subscript)
                    and isinstance(lookup.ctx, ast.Load)
                    and isinstance(lookup.value, ast.Call)
                ):
                    continue
                call = lookup.value
                if not (
                    isinstance(call.func, ast.Name)
                    and call.func.id == "globals"
                    and not call.args
                    and not call.keywords
                    and _called_lookup(lookup, nodes, counts)
                ):
                    continue
                name = lookup.slice
                if isinstance(name, ast.Constant) and isinstance(name.value, str):
                    selected = {name.value}
                elif (
                    isinstance(name, ast.Name)
                    and isinstance(assignments.get(name.id), ast.Constant)
                    and isinstance(assignments[name.id].value, str)
                ):
                    selected = {assignments[name.id].value}
                elif (
                    isinstance(name, ast.Name)
                    and name.id in parameter_names
                    and not counts[name.id]
                ):
                    selected = set()
                    position = parameter_names.index(name.id)
                    for site in call_arguments.get(caller.name, ()):
                        value = (
                            site.args[position]
                            if position < len(positional) and len(site.args) > position
                            else next(
                                (k.value for k in site.keywords if k.arg == name.id),
                                None,
                            )
                        )
                        if isinstance(value, ast.Constant) and isinstance(
                            value.value, str
                        ):
                            selected.add(value.value)
                else:
                    continue
                for selected_name in selected:
                    if module_counts[selected_name] != 1 or selected_name in mutations:
                        continue
                    if any(
                        isinstance(n, ast.Global) and selected_name in n.names
                        for n in ast.walk(source.tree)
                    ):
                        continue
                    target = next(
                        (
                            here.get(n.lineno)
                            for n in source.tree.body
                            if isinstance(n, _FUNCTIONS) and n.name == selected_name
                        ),
                        None,
                    )
                    if target is not None:
                        edges.append((target, caller))
    return edges


def finite_dispatch_edges(definitions, parsed):
    def collect():
        modules, by_location = _module_parts(parsed, definitions)
        if not modules:
            return []
        mutations = set()
        inspected = 0
        for source in parsed:
            for node in ast.walk(source.tree):
                inspected += 1
                if inspected > 2_000_000:
                    return []
                if isinstance(node, ast.Attribute) and isinstance(
                    node.ctx, (ast.Store, ast.Del)
                ):
                    mutations.add(node.attr)
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, (ast.Name, ast.Attribute))
                    and (
                        getattr(node.func, "id", None)
                        or getattr(node.func, "attr", None)
                    )
                    in {"setattr", "delattr"}
                    and len(node.args) >= 2
                ):
                    if isinstance(node.args[1], ast.Constant) and isinstance(
                        node.args[1].value, str
                    ):
                        mutations.add(node.args[1].value)
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr
                    in {
                        "update",
                        "clear",
                        "pop",
                        "popitem",
                        "setdefault",
                        "__setitem__",
                        "__delitem__",
                    }
                ):
                    if isinstance(node.func.value, ast.Attribute):
                        mutations.add(node.func.value.attr)
        reachable = _reachable_live_functions(definitions)
        edges = _global_edges(modules, parsed, by_location, reachable, mutations)
        for module in modules:
            edges.extend(_class_edges(*module, mutations))
        return list({(id(t), id(c)): (t, c) for t, c in edges}.values())

    return run_memo(("finite_dispatch_edges", id(definitions)), collect)


def active_dispatch_callers(definitions):
    reachable = _reachable_live_functions(definitions)
    live_classes = {
        (d.name, str(d.filename))
        for d in definitions.values()
        if d.type == "class" and _ROOTS.intersection(d.heuristic_refs)
    }
    for caller in definitions.values():
        if caller.type == "method" and str(
            getattr(caller, "skip_reason", "")
        ).startswith("overrides "):
            if (caller.name.rsplit(".", 1)[0], str(caller.filename)) in live_classes:
                reachable.add(caller.name)
    return reachable


def record_finite_dispatch_references(definitions, parsed):
    """Record edges after callers' current hierarchy/root evidence is known."""
    edges = finite_dispatch_edges(definitions, parsed)
    if not edges:
        return edges
    active = active_dispatch_callers(definitions)
    for target, caller in edges:
        if caller.name in active and caller.name not in target.called_by:
            target.references += 1
            target.called_by.add(caller.name)
            caller.calls.add(target.name)
    return edges
