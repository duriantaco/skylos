"""Source-bound concurrent.futures callbacks used as decorators.

Only canonical provider construction, typed Executor inputs, and submit results
supply receiver evidence. Names, Future annotations on unknown values and dotted
decorator spelling alone never retain a function.
"""

from __future__ import annotations

import ast
from pathlib import Path

from skylos.deadcode._registration_common import _FUNCTION_NODES, _import_aliases
from skylos.deadcode._registration_receivers import _RegistrationReceivers

_EXECUTORS = {
    "concurrent.futures.Executor",
    "concurrent.futures.ThreadPoolExecutor",
    "concurrent.futures.ProcessPoolExecutor",
}
_FUTURE = "concurrent.futures.Future"


class _FutureReceivers(_RegistrationReceivers):
    def __init__(self, definitions, parsed_files):
        super().__init__(definitions, parsed_files)
        self.provider_mutations = {}

    def origin(self, node, context, seen=frozenset()):
        if id(node) in seen:
            return None
        if isinstance(node, ast.Name):
            binding, scope = self._lookup(node.id, context)
            if isinstance(binding, ast.arg):
                return ("argument", id(binding))
            if binding is not None:
                return self.origin(binding, scope, seen | {id(node)})
        if isinstance(node, ast.Attribute):
            base = self.origin(node.value, context, seen | {id(node)})
            return ("member", base, node.attr) if base is not None else None
        return id(node) if not isinstance(node, ast.Name) else None

    def provider_replaced(self, provider):
        if provider in self.provider_mutations:
            return self.provider_mutations[provider]
        changed = False
        for parsed in self.files.values():
            self.prepare(parsed)
            for node in ast.walk(parsed.tree):
                receiver = None
                if isinstance(node, ast.Attribute) and isinstance(
                    node.ctx, (ast.Store, ast.Del)
                ):
                    receiver = node.value
                elif isinstance(node, ast.Call) and node.args:
                    # Provider aliases passed to unknown code can be patched,
                    # including through an alias of setattr/delattr.
                    for argument in node.args:
                        if self.imported(argument, self.context(node)) == provider:
                            changed = True
                if (
                    receiver is not None
                    and self.imported(receiver, self.context(node)) == provider
                ):
                    changed = True
        self.provider_mutations[provider] = changed
        return changed

    def imported(self, node, context, seen=frozenset()):
        if node is None or id(node) in seen:
            return None
        seen = seen | {id(node)}
        if isinstance(node, ast.Name):
            binding, scope = self._lookup(node.id, context)
            if isinstance(binding, (ast.Import, ast.ImportFrom)):
                parsed = self.files[self.file_for_node[scope]]
                names, modules = _import_aliases(
                    ast.Module(body=[binding], type_ignores=[]), None, parsed.path
                )
                return names.get(node.id) or modules.get(node.id)
            if binding is not None and not isinstance(binding, ast.arg):
                return self.imported(binding, scope, seen)
        if isinstance(node, ast.Attribute):
            base = self.imported(node.value, context, seen)
            if base and not self.replaced(node.value, node.attr, context):
                return f"{base}.{node.attr}"
        return None

    def replaced(self, receiver, member, context):
        """Reject source-visible replacement of this receiver's member."""
        key = ast.dump(receiver, include_attributes=False)
        origin = self.origin(receiver, context)
        current = context
        while current is not None:
            if isinstance(current, (ast.Module, ast.ClassDef, *_FUNCTION_NODES)):
                self._scope_bindings(current)
                for write in self.member_writes[current]:
                    if write.attr == member and (
                        ast.dump(write.value, include_attributes=False) == key
                        or origin is not None
                        and self.origin(write.value, current) == origin
                    ):
                        return True
                for statement in current.body:
                    if isinstance(statement, _FUNCTION_NODES):
                        continue
                    for node in ast.walk(statement):
                        if (
                            isinstance(node, ast.Call)
                            and origin is not None
                            and any(
                                self.origin(argument, current) == origin
                                for argument in node.args
                            )
                        ):
                            return True
                        if (
                            isinstance(node, ast.Call)
                            and isinstance(node.func, ast.Name)
                            and node.func.id in {"setattr", "delattr"}
                            and len(node.args) >= 2
                            and ast.dump(node.args[0], include_attributes=False) == key
                            and isinstance(node.args[1], ast.Constant)
                            and node.args[1].value == member
                        ):
                            return True
            current = self.context(current)
        return False

    def executor_annotation(self, annotation, context):
        if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
            try:
                annotation = ast.parse(annotation.value, mode="eval").body
            except SyntaxError:
                return False
        if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
            sides = (annotation.left, annotation.right)
            non_none = [
                side
                for side in sides
                if not (isinstance(side, ast.Constant) and side.value is None)
            ]
            return len(non_none) == 1 and self.executor_annotation(non_none[0], context)
        return self.imported(annotation, context) in _EXECUTORS

    def receiver_type(self, node, context, seen=frozenset()):
        if node is None or id(node) in seen:
            return None
        seen = seen | {id(node)}
        if isinstance(node, ast.Name):
            binding, scope = self._lookup(node.id, context)
            if isinstance(binding, ast.arg):
                return (
                    "executor"
                    if self.executor_annotation(binding.annotation, self.context(scope))
                    else None
                )
            if binding is not None:
                return self.receiver_type(binding, scope, seen)
        elif isinstance(node, ast.Call):
            provider = self.imported(node.func, context)
            if provider == _FUTURE and not self.provider_replaced(provider):
                return "future"
            if provider in _EXECUTORS and not self.provider_replaced(provider):
                return "executor"
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "submit"
                and not self.replaced(node.func.value, "submit", context)
                and self.receiver_type(node.func.value, context, seen) == "executor"
            ):
                return "future"
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            binding, scope = self._lookup(node.value.id, context)
            if not isinstance(binding, ast.arg) or not isinstance(
                scope, _FUNCTION_NODES
            ):
                return None
            owner = self.context(scope)
            positional = [*scope.args.posonlyargs, *scope.args.args]
            if (
                not isinstance(owner, ast.ClassDef)
                or not positional
                or binding is not positional[0]
            ):
                return None
            values = []
            for method in owner.body:
                if not isinstance(method, _FUNCTION_NODES):
                    continue
                parameters = [*method.args.posonlyargs, *method.args.args]
                if not parameters:
                    continue
                for child in ast.walk(method):
                    targets = (
                        child.targets
                        if isinstance(child, ast.Assign)
                        else [child.target]
                        if isinstance(child, ast.AnnAssign)
                        else []
                    )
                    for target in targets:
                        if (
                            isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == parameters[0].arg
                            and target.attr == node.attr
                        ):
                            if method.name != "__init__":
                                return None
                            values.append(self.receiver_type(child.value, method, seen))
            return (
                "executor"
                if values and all(value == "executor" for value in values)
                else None
            )
        return None


def find_future_callback_targets(definitions, parsed_files):
    receivers = _FutureReceivers(definitions, parsed_files)
    by_location = {
        (str(Path(d.filename).resolve()), d.line): d
        for d in definitions.values()
        if getattr(d, "type", None) in {"function", "method"}
    }
    targets = []
    for parsed in parsed_files:
        receivers.prepare(parsed)
        for node in ast.walk(parsed.tree):
            if not isinstance(node, _FUNCTION_NODES):
                continue
            context = receivers.context(node)
            for decorator in node.decorator_list:
                if (
                    isinstance(decorator, ast.Attribute)
                    and decorator.attr == "add_done_callback"
                    and not receivers.replaced(decorator.value, decorator.attr, context)
                    and receivers.receiver_type(decorator.value, context) == "future"
                ):
                    target = by_location.get((str(parsed.path.resolve()), node.lineno))
                    if target is not None:
                        targets.append(target)
                    break
    return targets
