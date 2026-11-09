"""Bounded source receivers for calls through local provider factories."""

from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

from skylos.deadcode._registration_common import _FUNCTION_NODES, _executed_nodes
from skylos.deadcode._registration_receivers import _RegistrationReceivers


class _ProofLimit(Exception):
    pass


class _ProviderCalls(_RegistrationReceivers):
    def __init__(self, definitions, parsed_files):
        super().__init__(definitions, parsed_files)
        self.steps = 0
        self.deferred = {}
        for parsed in parsed_files:
            self.prepare(parsed)

    def step(self):
        self.steps += 1
        if self.steps > 50_000:
            raise _ProofLimit

    def possible(self, expression, context, seen=frozenset()):
        """Finite class/instance choices; unrelated module calls yield none."""
        self.step()
        if expression is None or expression in seen or len(seen) >= 48:
            return set()
        seen = seen | {expression}
        direct = self.resolve(expression, context)
        if direct is not None:
            return {direct}
        if isinstance(expression, ast.Name):
            value, scope = self._lookup(expression.id, context)
            if value is not None and not isinstance(value, ast.arg):
                return self.possible(value, scope, seen)
        if isinstance(expression, ast.IfExp):
            values = set()
            choices = (expression.body, expression.orelse)
            if isinstance(expression.test, ast.Constant):
                choices = (
                    expression.body if expression.test.value else expression.orelse,
                )
            for choice in choices:
                values.update(self.possible(choice, context, seen))
            return values
        if isinstance(expression, ast.Call):
            values = set()
            for target, kind in self.possible(expression.func, context, seen):
                if kind == "class":
                    values.add((target, "instance"))
                elif kind == "function" and target not in seen:
                    if self.deferred_body(target):
                        continue
                    for node in _executed_nodes(target.body):
                        self.step()
                        if isinstance(node, ast.Return) and self.possible_site(node):
                            values.update(
                                self.possible(node.value, target, seen | {target})
                            )
            return values
        return set()

    def deferred_body(self, function):
        if function not in self.deferred:
            self.deferred[function] = isinstance(function, ast.AsyncFunctionDef) or any(
                isinstance(node, (ast.Yield, ast.YieldFrom))
                for node in _executed_nodes(function.body)
            )
        return self.deferred[function]

    def executes_body(self, function, call):
        if not self.deferred_body(function):
            return True
        parent = self.parents.get(call)
        if isinstance(function, ast.AsyncFunctionDef):
            return isinstance(parent, ast.Await)
        if isinstance(parent, ast.For) and parent.iter is call:
            return True
        if isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name):
            if parent.func.id in {"next", "list", "tuple", "set", "sum", "any", "all"}:
                binding, scope = self._lookup(parent.func.id, self.context(parent))
                return binding is None and scope is None
        return False

    def possible_site(self, node):
        """A reachable owner does not make statements after return execute."""
        child = node
        parent = self.parents.get(child)
        while parent is not None:
            self.step()
            if isinstance(parent, (ast.If, ast.IfExp)):
                truth = self.literal_truth(parent.test)
                if truth is not None:
                    if isinstance(parent, ast.IfExp):
                        selected = parent.body if truth else parent.orelse
                        if (
                            child in (parent.body, parent.orelse)
                            and child is not selected
                        ):
                            return False
                    elif (child in parent.body and not truth) or (
                        child in parent.orelse and truth
                    ):
                        return False
            if isinstance(parent, ast.BoolOp) and child in parent.values:
                for previous in parent.values[: parent.values.index(child)]:
                    truth = self.literal_truth(previous)
                    if (isinstance(parent.op, ast.And) and truth is False) or (
                        isinstance(parent.op, ast.Or) and truth is True
                    ):
                        return False
            for field in ("body", "orelse", "finalbody"):
                block = getattr(parent, field, ())
                if isinstance(block, list) and child in block:
                    if self.block_exits(block[: block.index(child)]):
                        return False
                    if (
                        field == "body"
                        and isinstance(parent, (ast.For, ast.AsyncFor))
                        and isinstance(parent.iter, (ast.Tuple, ast.List, ast.Set))
                        and not parent.iter.elts
                    ):
                        return False
            child, parent = parent, self.parents.get(parent)
        return True

    def block_exits(self, statements):
        return "fallthrough" not in self.completions(statements)

    def literal_truth(self, node, depth=0):
        self.step()
        if depth >= 24:
            return None
        if isinstance(node, ast.Constant):
            return bool(node.value)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            inner = self.literal_truth(node.operand, depth + 1)
            return None if inner is None else not inner
        if isinstance(node, ast.BoolOp):
            unknown = False
            for value in node.values:
                truth = self.literal_truth(value, depth + 1)
                if isinstance(node.op, ast.And) and truth is False:
                    return False
                if isinstance(node.op, ast.Or) and truth is True:
                    return True
                unknown |= truth is None
            if not unknown:
                return isinstance(node.op, ast.And)
        return None

    def call_raises(self, node, seen):
        if not isinstance(node, ast.Call):
            return False
        target = self.resolve(node.func, self.context(node))
        if target is None or target[1] != "function":
            return False
        function = target[0]
        # An annotation-only receiver can dispatch an override; do not infer
        # abrupt completion from a base method's NotImplementedError stub.
        if isinstance(self.context(function), ast.ClassDef):
            return False
        if function in seen or len(seen) >= 24 or self.deferred_body(function):
            return False
        return self.completions(function.body, seen | {function}) == {"raise"}

    def completions(self, statements, seen=frozenset()):
        outcomes = {"fallthrough"}
        for statement in statements:
            self.step()
            if "fallthrough" not in outcomes:
                break
            outcomes.remove("fallthrough")
            if isinstance(statement, ast.Return):
                outcomes.add(
                    "raise" if self.call_raises(statement.value, seen) else "return"
                )
            elif isinstance(statement, ast.Raise):
                outcomes.add("raise")
            elif isinstance(statement, ast.Break):
                outcomes.add("break")
            elif isinstance(statement, ast.Continue):
                outcomes.add("continue")
            elif isinstance(statement, ast.If):
                truth = self.literal_truth(statement.test)
                branches = (statement.body, statement.orelse)
                if truth is not None:
                    branches = (statement.body if truth else statement.orelse,)
                for branch in branches:
                    outcomes.update(self.completions(branch, seen))
            elif isinstance(statement, ast.Expr) and self.call_raises(
                statement.value, seen
            ):
                outcomes.add("raise")
            else:
                outcomes.add("fallthrough")
        return outcomes

    def call_targets(self, node):
        context = self.context(node)
        targets = set()
        direct = self.resolve(node.func, context)
        if direct is not None:
            targets.add(direct)
        if isinstance(node.func, ast.Attribute):
            for receiver, kind in self.possible(node.func.value, context):
                if kind not in {"class", "instance"}:
                    continue
                if self.member_rebound(
                    node.func.value,
                    receiver,
                    node.func.attr,
                    context,
                    instance=kind == "instance",
                ):
                    continue
                scope = self.method_scope(receiver)
                methods = scope.class_methods.get(node.func.attr, ()) if scope else ()
                if len(methods) == 1:
                    targets.add((methods[0], "function"))
        return targets


def find_provider_method_targets(
    definitions, parsed_files, candidates, *, proxy_names, common_proxy_methods
):
    """Find methods consumed by reachable calls with a source-owned receiver.

    A finite factory can return several providers. That permits its returned
    classes' methods, without crediting another class with the same spelling.
    The longstanding current_app proxy contract remains a narrow fallback.
    """
    if not candidates:
        return []
    try:
        source = _ProviderCalls(definitions, parsed_files)
        by_location = defaultdict(list)
        by_name = defaultdict(list)
        for candidate in candidates:
            key = (str(Path(candidate.filename).resolve()), candidate.line)
            by_location[key].append(candidate)
            by_name[candidate.simple_name].append(candidate)
        owners = {}
        framework_owners = []
        pending = [parsed.tree for parsed in parsed_files]
        root_markers = {
            "framework_root",
            "package_entrypoint",
            "test_entrypoint",
            "top_level_execution",
            "coverage_hit",
            "trace_hit",
            "reachable_from_root",
        }
        for file_key, parsed in source.files.items():
            for node in ast.walk(parsed.tree):
                source.step()
                if not isinstance(node, _FUNCTION_NODES):
                    continue
                matches = source.definitions_by_location.get(
                    (file_key, node.lineno), ()
                )
                if len(matches) != 1:
                    continue
                definition = matches[0]
                owners[node] = definition
                evidence = getattr(definition, "heuristic_refs", {})
                if "framework_root" in evidence:
                    framework_owners.append(
                        (
                            node,
                            "dead_code_liveness:django_web_management_command_handle"
                            in evidence,
                        )
                    )
                actual_callback = {
                    "framework_root",
                    "test_entrypoint",
                    "coverage_hit",
                    "trace_hit",
                }.intersection(evidence)
                ordinary_root = getattr(
                    definition, "is_exported", False
                ) or root_markers.intersection(evidence)
                if actual_callback or (
                    ordinary_root and not source.deferred_body(node)
                ):
                    pending.append(node)
        reached = set()
        found = {}
        while pending:
            owner = pending.pop()
            if owner in reached:
                continue
            reached.add(owner)
            for node in _executed_nodes(owner.body):
                source.step()
                if not isinstance(node, ast.Call) or not source.possible_site(node):
                    continue
                targets = source.call_targets(node)
                for target, kind in targets:
                    if kind == "class":
                        scope = source.method_scope(target)
                        if scope:
                            pending.extend(scope.class_methods.get("__init__", ()))
                        continue
                    if kind != "function":
                        continue
                    if not source.executes_body(target, node):
                        continue
                    pending.append(target)
                    key = (source.file_for_node[target], target.lineno)
                    matches = by_location.get(key, ())
                    if len(matches) == 1:
                        definition = matches[0]
                        found[id(definition)] = (
                            definition,
                            owners.get(owner),
                            "top_level_execution"
                            if isinstance(owner, ast.Module)
                            else "reachable_from_root",
                        )
                if (
                    not targets
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in proxy_names
                    and node.func.attr not in common_proxy_methods
                ):
                    matches = by_name.get(node.func.attr, ())
                    if len(matches) != 1:
                        continue
                    definition = matches[0]
                    if Path(definition.filename).resolve() == Path(
                        source.file_for_node[node]
                    ):
                        continue
                    # The unresolved proxy preserves its historical uncertainty;
                    # only source-resolved calls carry actual execution evidence.
                    found.setdefault(
                        id(definition), (definition, owners.get(owner), None)
                    )
        try:
            from skylos.deadcode.provider_source_dispatch import _SourceDispatch

            dispatch = _SourceDispatch(
                definitions, parsed_files, framework_owners=framework_owners
            )
            for target, caller in dispatch.targets():
                key = (dispatch.file_for_node[target], target.lineno)
                matches = by_location.get(key, ())
                if len(matches) == 1:
                    definition = matches[0]
                    found[id(definition)] = (
                        definition,
                        owners.get(caller),
                        "top_level_execution"
                        if isinstance(caller, ast.Module)
                        else "reachable_from_root",
                    )
        except (_ProofLimit, RecursionError):
            # Preserve the established proofs when the supplemental domain ends.
            pass
        return list(found.values())
    except (_ProofLimit, RecursionError):
        # No partial name-based rescue when source resolution exceeds its bound.
        return []
