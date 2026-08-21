from __future__ import annotations

import ast
from collections import defaultdict
from collections.abc import Mapping
from typing import Any


def _shared_signature_parameters(
    child: ast.FunctionDef | ast.AsyncFunctionDef,
    parent: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[set[str], set[str]]:
    """Return child and parent parameter names occupying shared API slots."""
    child_names: set[str] = set()
    parent_names: set[str] = set()

    for child_arg, parent_arg in zip(
        child.args.posonlyargs, parent.args.posonlyargs
    ):
        child_names.add(child_arg.arg)
        parent_names.add(parent_arg.arg)

    shared_positional_names = {
        arg.arg for arg in child.args.args
    } & {arg.arg for arg in parent.args.args}
    child_names.update(shared_positional_names)
    parent_names.update(shared_positional_names)

    shared_keyword_names = {
        arg.arg for arg in child.args.kwonlyargs
    } & {arg.arg for arg in parent.args.kwonlyargs}
    child_names.update(shared_keyword_names)
    parent_names.update(shared_keyword_names)

    if child.args.vararg is not None and parent.args.vararg is not None:
        child_names.add(child.args.vararg.arg)
        parent_names.add(parent.args.vararg.arg)
    if child.args.kwarg is not None and parent.args.kwarg is not None:
        child_names.add(child.args.kwarg.arg)
        parent_names.add(parent.args.kwarg.arg)

    return child_names, parent_names


def _joined_string_static_affixes(expr: ast.expr) -> tuple[str, str] | None:
    if not isinstance(expr, ast.JoinedStr):
        return None

    dynamic_indexes = [
        index
        for index, value in enumerate(expr.values)
        if isinstance(value, ast.FormattedValue)
    ]
    if len(dynamic_indexes) != 1:
        return None

    dynamic_index = dynamic_indexes[0]
    dynamic_value = expr.values[dynamic_index]
    if (
        not isinstance(dynamic_value, ast.FormattedValue)
        or isinstance(dynamic_value.value, ast.Constant)
        or dynamic_value.conversion != -1
        or dynamic_value.format_spec is not None
    ):
        return None
    prefix_parts: list[str] = []
    suffix_parts: list[str] = []
    for index, value in enumerate(expr.values):
        if index == dynamic_index:
            continue
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return None
        target = prefix_parts if index < dynamic_index else suffix_parts
        target.append(value.value)

    prefix = "".join(prefix_parts)
    suffix = "".join(suffix_parts)
    return (prefix, suffix) if prefix or suffix else None


def _dynamic_dispatch_keyword_contracts(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    binding_kind: str,
) -> set[tuple[str, str]]:
    """Return method-name affixes for dispatchers that forward ``**kwargs``."""
    positional_args = [*node.args.posonlyargs, *node.args.args]
    if (
        node.args.kwarg is None
        or binding_kind == "static"
        or not positional_args
        or _function_binds_name(node, "getattr")
    ):
        return set()

    kwarg_name = node.args.kwarg.arg
    receiver_name = positional_args[0].arg
    contracts: set[tuple[str, str]] = set()
    stack: list[ast.AST] = list(reversed(node.body))
    while stack:
        candidate = stack.pop()
        if isinstance(
            candidate,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(candidate))))

        call = candidate
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Call):
            continue

        getter = call.func
        if (
            not isinstance(getter.func, ast.Name)
            or getter.func.id != "getattr"
            or len(getter.args) < 2
            or not isinstance(getter.args[0], ast.Name)
            or getter.args[0].id != receiver_name
        ):
            continue

        affixes = _joined_string_static_affixes(getter.args[1])
        if affixes is None:
            continue

        forwards_kwargs = any(
            keyword.arg is None
            and isinstance(keyword.value, ast.Name)
            and keyword.value.id == kwarg_name
            for keyword in call.keywords
        )
        if forwards_kwargs:
            contracts.add(affixes)

    return contracts


def _mark_contract_parameter(parameter_def: Any) -> None:
    parameter_def.references = max(parameter_def.references, 1)
    heuristic_refs = getattr(parameter_def, "heuristic_refs", None)
    if isinstance(heuristic_refs, dict):
        heuristic_refs["signature_contract"] = max(
            heuristic_refs.get("signature_contract", 0.0), 1.0
        )


def _method_binding_kind(method_def: Any) -> str:
    decorator_names = {
        decorator.rsplit(".", 1)[-1]
        for decorator in getattr(method_def, "decorators", [])
    }
    if "staticmethod" in decorator_names:
        return "static"
    if "classmethod" in decorator_names:
        return "class"
    return "instance"


class _ClassBindingCollector(ast.NodeVisitor):
    """Collect names a compound class-body statement may bind."""

    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)
        self._visit_function_header(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.names.add(node.name)
        self._visit_function_header(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)

    def _visit_function_header(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in node.args.defaults:
            self.visit(default)
        for default in node.args.kw_defaults:
            if default is not None:
                self.visit(default)

    def visit_Import(self, node: ast.Import) -> None:
        self.names.update(
            imported.asname or imported.name.split(".", 1)[0]
            for imported in node.names
        )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.names.update(
            imported.asname or imported.name for imported in node.names
        )

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name is not None:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name is not None:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name is not None:
            self.names.add(node.name)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest is not None:
            self.names.add(node.rest)
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node.generators, node.elt)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node.generators, node.elt)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node.generators, node.elt)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node.generators, node.key, node.value)

    def _visit_comprehension(
        self,
        generators: list[ast.comprehension],
        *values: ast.expr,
    ) -> None:
        for generator in generators:
            self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        for value in values:
            self.visit(value)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in node.args.defaults:
            self.visit(default)
        for default in node.args.kw_defaults:
            if default is not None:
                self.visit(default)


def _function_binds_name(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    name: str,
) -> bool:
    parameters = {
        argument.arg
        for argument in (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        )
    }
    if node.args.vararg is not None:
        parameters.add(node.args.vararg.arg)
    if node.args.kwarg is not None:
        parameters.add(node.args.kwarg.arg)
    if name in parameters:
        return True

    collector = _ClassBindingCollector()
    for statement in node.body:
        collector.visit(statement)
    return name in collector.names


def _compound_class_bindings(statement: ast.stmt) -> set[str]:
    collector = _ClassBindingCollector()
    collector.visit(statement)
    return collector.names


def _class_namespace_members(
    class_def: Any,
    methods: Mapping[str, Any],
) -> dict[str, Any | None]:
    """Return conservative final bindings for a class namespace."""
    members: dict[str, Any | None] = {}
    for statement in class_def.node.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for name in _compound_class_bindings(statement):
                members[name] = None
            members[statement.name] = methods.get(statement.name)
            continue
        if isinstance(statement, ast.ClassDef):
            for name in _compound_class_bindings(statement):
                members[name] = None
            continue
        for name in _compound_class_bindings(statement):
            members[name] = None
    return members


def _merge_c3_mro(sequences: list[list[str]]) -> list[str] | None:
    merged: list[str] = []
    while True:
        sequences = [sequence for sequence in sequences if sequence]
        if not sequences:
            return merged

        candidate = next(
            (
                sequence[0]
                for sequence in sequences
                if not any(sequence[0] in other[1:] for other in sequences)
            ),
            None,
        )
        if candidate is None:
            return None
        merged.append(candidate)
        for sequence in sequences:
            if sequence and sequence[0] == candidate:
                sequence.pop(0)


def mark_signature_contract_parameters(
    definitions: Mapping[str, Any],
) -> None:
    """Keep parameters required by resolvable override and dispatch contracts."""
    class_defs = {
        defn.name: defn
        for defn in definitions.values()
        if defn.type == "class" and isinstance(defn.node, ast.ClassDef)
    }
    if not class_defs:
        return

    suffix_to_classes: dict[str, set[str]] = defaultdict(set)
    for class_qname in class_defs:
        parts = class_qname.split(".")
        for index in range(len(parts)):
            suffix_to_classes[".".join(parts[index:])].add(class_qname)

    def resolve_class(raw_qname: str) -> str | None:
        if raw_qname in class_defs:
            return raw_qname
        candidates = suffix_to_classes.get(raw_qname, set())
        if len(candidates) == 1:
            return next(iter(candidates))
        return None

    parents_of: dict[str, set[str]] = defaultdict(set)
    ordered_parents_of: dict[str, tuple[str, ...]] = {}
    hierarchy_is_complete: dict[str, bool] = {}
    for class_qname, class_def in class_defs.items():
        raw_bases = list(getattr(class_def, "base_classes", []))
        ordered_parents: list[str] = []
        hierarchy_is_complete[class_qname] = len(raw_bases) == len(
            class_def.node.bases
        )
        for raw_base in raw_bases:
            resolved = resolve_class(raw_base)
            if resolved is not None and resolved != class_qname:
                parents_of[class_qname].add(resolved)
                if resolved not in ordered_parents:
                    ordered_parents.append(resolved)
            elif resolved is None:
                hierarchy_is_complete[class_qname] = False
        ordered_parents_of[class_qname] = tuple(ordered_parents)

    class_methods = defaultdict(dict)
    for defn in definitions.values():
        if (
            defn.type != "method"
            or not isinstance(defn.node, (ast.FunctionDef, ast.AsyncFunctionDef))
            or "." not in defn.name
        ):
            continue
        owner, method_name = defn.name.rsplit(".", 1)
        if owner in class_defs:
            class_methods[owner][method_name] = defn

    class_members = {
        class_qname: _class_namespace_members(
            class_def,
            class_methods.get(class_qname, {}),
        )
        for class_qname, class_def in class_defs.items()
    }

    parameter_defs = {
        defn.name: defn
        for defn in definitions.values()
        if defn.type == "parameter"
    }

    def mark_parameters(method_def: Any, parameter_names: set[str]) -> None:
        for parameter_name in parameter_names:
            parameter_def = parameter_defs.get(f"{method_def.name}.{parameter_name}")
            if parameter_def is not None:
                _mark_contract_parameter(parameter_def)

    ancestor_cache: dict[str, frozenset[str]] = {}
    def ancestors(class_qname: str) -> frozenset[str]:
        cached = ancestor_cache.get(class_qname)
        if cached is not None:
            return cached
        found: set[str] = set()
        stack = list(parents_of.get(class_qname, set()))
        while stack:
            parent = stack.pop()
            if parent in found:
                continue
            found.add(parent)
            stack.extend(parents_of.get(parent, set()))
        result = frozenset(found)
        ancestor_cache[class_qname] = result
        return result

    for child_qname, child_methods in class_methods.items():
        for parent_qname in ancestors(child_qname):
            parent_methods = class_methods.get(parent_qname, {})
            for method_name in child_methods.keys() & parent_methods.keys():
                if method_name.startswith("__") and not method_name.endswith(
                    "__"
                ):
                    continue
                child_method = child_methods[method_name]
                parent_method = parent_methods[method_name]
                if (
                    class_members.get(child_qname, {}).get(method_name)
                    is not child_method
                    or class_members.get(parent_qname, {}).get(method_name)
                    is not parent_method
                ):
                    continue
                if _method_binding_kind(child_method) != _method_binding_kind(
                    parent_method
                ):
                    continue
                child_names, parent_names = _shared_signature_parameters(
                    child_method.node, parent_method.node
                )
                mark_parameters(child_method, child_names)
                mark_parameters(parent_method, parent_names)

    dynamic_contracts_by_method: dict[str, set[tuple[str, str]]] = {}
    dispatcher_names: set[str] = set()
    for class_qname, methods in class_methods.items():
        module_qname = class_qname.rsplit(".", 1)[0]
        module_shadows_getattr = bool(
            getattr(class_defs[class_qname], "module_shadows_getattr", False)
            or f"{module_qname}.getattr" in definitions
        )
        for dispatcher_name, method_def in methods.items():
            if module_shadows_getattr:
                continue
            contracts = _dynamic_dispatch_keyword_contracts(
                method_def.node,
                _method_binding_kind(method_def),
            )
            if not contracts:
                continue
            dynamic_contracts_by_method[method_def.name] = contracts
            dispatcher_names.add(dispatcher_name)

    if not dynamic_contracts_by_method:
        return

    mro_cache: dict[str, tuple[str, ...] | None] = {}

    def class_mro(
        class_qname: str,
        visiting: frozenset[str] = frozenset(),
    ) -> tuple[str, ...] | None:
        if class_qname in mro_cache:
            return mro_cache[class_qname]
        if class_qname in visiting or not hierarchy_is_complete.get(
            class_qname, False
        ):
            mro_cache[class_qname] = None
            return None

        parent_mros: list[list[str]] = []
        next_visiting = visiting | {class_qname}
        for parent_qname in ordered_parents_of.get(class_qname, ()):
            parent_mro = class_mro(parent_qname, next_visiting)
            if parent_mro is None:
                mro_cache[class_qname] = None
                return None
            parent_mros.append(list(parent_mro))

        merged = _merge_c3_mro(
            [*parent_mros, list(ordered_parents_of.get(class_qname, ()))]
        )
        if merged is None:
            mro_cache[class_qname] = None
            return None
        result = (class_qname, *merged)
        mro_cache[class_qname] = result
        return result

    def visible_member(
        mro: tuple[str, ...],
        member_name: str,
    ) -> tuple[bool, Any | None]:
        for owner_qname in mro:
            members = class_members.get(owner_qname, {})
            if member_name in members:
                return True, members[member_name]
        return False, None

    for class_qname in class_defs:
        resolved_mro = class_mro(class_qname)
        mro = resolved_mro if resolved_mro is not None else (class_qname,)
        visible_names = {
            member_name
            for owner_qname in mro
            for member_name in class_members.get(owner_qname, {})
        }
        for dispatcher_name in dispatcher_names:
            found_dispatcher, dispatcher_method = visible_member(
                mro, dispatcher_name
            )
            if not found_dispatcher or dispatcher_method is None:
                continue
            contracts = dynamic_contracts_by_method.get(dispatcher_method.name)
            if not contracts:
                continue
            for method_prefix, method_suffix in contracts:
                for method_name in visible_names:
                    if not (
                        method_name.startswith(method_prefix)
                        and method_name.endswith(method_suffix)
                        and len(method_name)
                        >= len(method_prefix) + len(method_suffix)
                    ):
                        continue
                    found_handler, handler_method = visible_member(mro, method_name)
                    if not found_handler or handler_method is None:
                        continue
                    method_node = handler_method.node
                    if method_node.args.kwarg is not None:
                        mark_parameters(
                            handler_method,
                            {method_node.args.kwarg.arg},
                        )
