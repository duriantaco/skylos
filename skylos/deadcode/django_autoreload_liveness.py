"""Source-proven Django autoreload callbacks and management entry points."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

from skylos.deadcode.django_converter_liveness import _ConverterScanner
from skylos.deadcode.django_hook_proofs import DjangoHookProof
from skylos.deadcode.framework_liveness import (
    _DefinitionIndex,
    _eager_nodes,
    _qualified,
)
from skylos.deadcode.web_framework_liveness import _executed_definitions
from skylos.rules.danger.module_namespace import module_name_for, module_rebinding


_RELOADER = "django.utils.autoreload.run_with_reloader"
_INSTANCE = "@django.autoreload_instance:"


def _ordinary_function(statement):
    return (
        isinstance(statement, ast.FunctionDef)
        and not statement.decorator_list
        and not any(
            isinstance(node, (ast.Yield, ast.YieldFrom))
            for child in statement.body
            for node in _eager_nodes(child)
        )
    )


class _AutoreloadScanner(_ConverterScanner):
    def _scan_function(self, statement, bindings, owner):
        definition = self.evidence.at(statement, "function")
        if definition is None:
            definition = self.evidence.at(statement, "method")
        if definition is None or not _ordinary_function(statement):
            bindings[statement.name] = None
            return
        self.functions[definition.name] = statement, definition
        bindings[statement.name] = definition.name

    def _scan_class(self, statement, bindings, owner):
        super()._scan_class(statement, bindings, owner)
        definition = self.evidence.at(statement, "class")
        if definition is None or statement.decorator_list or statement.keywords:
            return
        # Nested classes (e.g. Meta inside a factory) may have a Definition
        # without a matching evidence.classes entry; skip rather than aborting
        # the whole dead-code liveness pass.
        info = self.evidence.classes.get(definition.name)
        if info is None:
            return
        members = info[2]
        local = bindings.copy()
        for member in statement.body:
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                members.get(member.name) is member
            ):
                self._scan_function(member, local, definition.name)

    def _scan_import(self, statement, bindings, owner):
        super()._scan_import(statement, bindings, owner)
        for alias in statement.names:
            name = alias.asname or alias.name.split(".", 1)[0]
            qualified = bindings.get(name)
            if self.registry.changed(qualified):
                bindings[name] = None

    def _invalidate_provider_attribute(self, target, bindings):
        qualified = _qualified(target, bindings)
        if isinstance(target, ast.Attribute) and qualified is not None:
            self.registry.changed_providers.add(qualified)
        super()._invalidate_provider_attribute(target, bindings)

    def _scan_assignment(self, statement, bindings, owner):
        value = getattr(statement, "value", None)
        changed = isinstance(value, ast.Attribute) and self.registry.changed(
            _qualified(value, bindings)
        )
        if not isinstance(value, (ast.Name, ast.Attribute, ast.Constant)):
            self._command_namespace_escapes(value, bindings)
        super()._scan_assignment(statement, bindings, owner)
        if changed:
            targets = []
            if isinstance(statement, ast.Assign):
                targets = statement.targets
            elif isinstance(statement, ast.AnnAssign):
                targets = [statement.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    bindings[target.id] = None

    def _command_namespace_escapes(self, expression, bindings):
        if expression is None:
            return
        for node in _eager_nodes(expression):
            if isinstance(node, (ast.Name, ast.Attribute)):
                qualified = _qualified(node, bindings)
                if qualified is not None:
                    self.registry.command_namespace_escapes.add(qualified)

    def _calls(self, expression, bindings, *, routes=False):
        for call in _eager_nodes(expression):
            if not isinstance(call, ast.Call):
                continue
            target = _qualified(call.func, bindings)
            builtin_mutation = (
                isinstance(call.func, ast.Name)
                and call.func.id in {"setattr", "delattr"}
                and call.func.id not in bindings
            ) or target in {"builtins.setattr", "builtins.delattr"}
            if builtin_mutation and len(call.args) >= 2:
                owner = _qualified(call.args[0], bindings)
                member = call.args[1]
                if owner is not None and isinstance(member, ast.Constant):
                    if isinstance(member.value, str):
                        self.registry.changed_providers.add(owner + "." + member.value)
            if target == _RELOADER and not (
                isinstance(call.func, ast.Attribute) and self.registry.changed(target)
            ):
                callback = None
                if call.args:
                    callback = call.args[0]
                else:
                    for keyword in call.keywords:
                        if keyword.arg == "main_func":
                            callback = keyword.value
                qualified = _qualified(callback, bindings)
                scanner, function = None, None
                if not (
                    isinstance(callback, ast.Attribute)
                    and self.registry.changed(qualified)
                ):
                    scanner, function = self.registry.function(qualified)
                if scanner is not None:
                    definition = function[1]
                    self.registry.callbacks[id(definition)] = definition
            if isinstance(call.func, ast.Attribute) and self.registry.changed(target):
                continue
            scanner, function = self.registry.function(target)
            if scanner is not None:
                receiver = None
                if isinstance(call.func, ast.Attribute):
                    receiver = _qualified(call.func.value, bindings)
                elif target is not None and target.startswith(_INSTANCE):
                    receiver = target.rpartition(".")[0]
                if receiver is not None and receiver.startswith(_INSTANCE):
                    instance = ast.Name(id="_skylos_bound_instance", ctx=ast.Load())
                    bound_call = ast.Call(
                        func=call.func,
                        args=[instance, *call.args],
                        keywords=call.keywords,
                    )
                    scanner.invoke(
                        function, bound_call, {**bindings, instance.id: receiver}
                    )
                else:
                    scanner.invoke(function, call, bindings)
            else:
                for argument in (
                    *call.args,
                    *(keyword.value for keyword in call.keywords),
                ):
                    self._command_namespace_escapes(argument, bindings)


class _AutoreloadRegistry:
    def __init__(self, index, parsed):
        self.scanners = {}
        self.callbacks = {}
        self.changed_providers = set()
        # Additional command-entry proof only; these do not change which
        # autoreload callbacks the existing interpreter discovers.
        self.command_namespace_escapes = set()
        self.command_module_namespaces = {}
        for module in parsed:
            scanner = _AutoreloadScanner(index, module, self)
            self.scanners[scanner.evidence.module] = scanner

    def changed(self, qualified):
        if qualified is None:
            return False
        qualified = qualified.removeprefix(_INSTANCE)
        for provider in self.changed_providers:
            provider = provider.removeprefix(_INSTANCE)
            if qualified == provider or qualified.startswith(provider + "."):
                return True
        return False

    def function(self, qualified):
        if qualified is None:
            return None, None
        qualified = qualified.removeprefix(_INSTANCE)
        module = qualified
        while "." in module:
            module = module.rpartition(".")[0]
            scanner = self.scanners.get(module)
            if scanner is not None:
                scanner.collect()
                function = scanner.functions.get(qualified)
                if function is not None:
                    return scanner, function
        return None, None


def _command_handles(definitions, root, registry):
    """Django loads Command.handle from genuine management command modules."""
    proof = None
    for module, scanner in registry.scanners.items():
        path = scanner.evidence.path
        if path.parent.name != "commands" or path.parent.parent.name != "management":
            continue
        if path.stem.startswith("_"):
            continue
        if proof is None:
            proof = DjangoHookProof(
                SimpleNamespace(defs=definitions, _project_root=root)
            )
        command = proof.expand(module + ".Command")
        if proof.status(command, "command") is not True:
            continue
        for owner in proof._mro(command) or ():
            if owner not in proof.classes:
                break
            member = proof.classes[owner][2].get("handle")
            if member is None:
                continue
            name = owner + ".handle"
            if (
                _ordinary_function(member)
                and name not in proof.provider_overrides
                and not registry.changed(name)
            ):
                selected, function = registry.function(name)
                if selected is not None and function[0].lineno == member.lineno:
                    yield selected, function, command, proof, scanner
            break


def _command_module_stable(scanner, names, registry):
    key = id(scanner)
    if key not in registry.command_module_namespaces:
        registry.command_module_namespaces[key] = module_rebinding(
            scanner.tree, module_name_for(scanner.evidence.path)
        )
    dynamic, rebound = registry.command_module_namespaces[key]
    return not dynamic and not rebound.intersection(names)


def _command_dispatch_proven(command, proof, registry, discovery):
    """The selected handle survives ordinary construction and lookup.

    Unknown constructors, descriptors, class effects or escaped namespaces do
    not justify a new entry point. Existing autoreload interpretation remains
    independent of this narrower proof.
    """
    lineage = proof._mro(command)
    if not lineage or not _command_module_stable(discovery, {"Command"}, registry):
        return False
    protocols = {
        "__init__",
        "__new__",
        "__getattribute__",
        "__getattr__",
        "__setattr__",
        "__delattr__",
        "__init_subclass__",
        "__bases__",
    }
    for owner in lineage:
        if any(
            escaped == owner
            or escaped.startswith(owner + ".")
            or owner.startswith(escaped + ".")
            for escaped in registry.command_namespace_escapes
        ):
            return False
        protected = {owner + "." + member for member in protocols | {"handle"}}
        changed = set(proof.provider_overrides) | registry.changed_providers
        if any(
            target == written
            or target.startswith(written + ".")
            or written.startswith(target + ".")
            for target in protected
            for written in changed
        ):
            return False
        info = proof.classes.get(owner)
        if info is None:
            if (
                owner != "builtins.object"
                and proof.status(owner, "command") is not True
            ):
                return False
            continue
        definition, _bases, members, _bindings, scanner = info
        if not _command_module_stable(scanner, {definition.simple_name}, registry):
            return False
        if (
            definition.node.decorator_list
            or definition.node.keywords
            or protocols.intersection(members)
        ):
            return False
        deferred_annotations = any(
            isinstance(statement, ast.ImportFrom)
            and statement.module == "__future__"
            and any(alias.name == "annotations" for alias in statement.names)
            for statement in scanner.tree.body
        )
        for statement in definition.node.body:
            if isinstance(statement, ast.Pass):
                continue
            if isinstance(statement, ast.Expr) and isinstance(
                statement.value, ast.Constant
            ):
                continue
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Definition headers can execute user code too.
                headers = [*statement.decorator_list, *statement.args.defaults]
                headers.extend(
                    item for item in statement.args.kw_defaults if item is not None
                )
                if any(not _command_literal(item) for item in headers):
                    return False
                annotations = [
                    argument.annotation
                    for argument in (
                        *statement.args.posonlyargs,
                        *statement.args.args,
                        *statement.args.kwonlyargs,
                        *([statement.args.vararg] if statement.args.vararg else []),
                        *([statement.args.kwarg] if statement.args.kwarg else []),
                    )
                ] + [statement.returns]
                if not deferred_annotations and any(
                    annotation is not None
                    and not isinstance(annotation, (ast.Name, ast.Constant))
                    for annotation in annotations
                ):
                    return False
                continue
            if (
                isinstance(statement, ast.Assign)
                and all(isinstance(target, ast.Name) for target in statement.targets)
                and _command_literal(statement.value)
            ):
                continue
            if (
                isinstance(statement, ast.AnnAssign)
                and isinstance(statement.target, ast.Name)
                and (statement.value is None or _command_literal(statement.value))
                and (
                    deferred_annotations
                    or isinstance(statement.annotation, (ast.Name, ast.Constant))
                )
            ):
                continue
            return False
    return True


def _command_literal(node):
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_command_literal(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            key is not None and _command_literal(key) and _command_literal(value)
            for key, value in zip(node.keys, node.values)
        )
    return False


def find_django_autoreload_targets(definitions, parsed_files, root):
    """Find executing autoreload callbacks and proven management handles."""
    if not any(
        definition.type == "import" and definition.name.split(".", 1)[0] == "django"
        for definition in definitions.values()
    ):
        return []
    root = Path(root).resolve()
    if root.is_file():
        root = root.parent
    parsed = list(parsed_files)
    index = _DefinitionIndex(definitions, parsed, root)
    if "django" in index.shadowed:
        return []
    registry = _AutoreloadRegistry(index, parsed)
    for scanner in registry.scanners.values():
        scanner.collect()
    executed = _executed_definitions(index)
    for scanner in registry.scanners.values():
        for function in tuple(scanner.functions.values()):
            if id(function[1]) in executed and id(function[1]) not in scanner.invoked:
                scanner.invoke(function)
    handles = list(_command_handles(definitions, root, registry))
    # Freeze entry proofs before invoking command bodies: effects inside an
    # already-entered handle cannot disprove that the body was entered.
    command_roots = {
        id(function[1]): function[1]
        for _scanner, function, command, proof, discovery in handles
        if _command_dispatch_proven(command, proof, registry, discovery)
    }
    for scanner, function, command, _proof, _discovery in handles:
        instance = ast.Name(id="_skylos_command_instance", ctx=ast.Load())
        call = ast.Call(
            func=ast.Name(id="handle", ctx=ast.Load()), args=[instance], keywords=[]
        )
        scanner.invoke(function, call, {instance.id: _INSTANCE + command})
    return [
        (definition, "django_web_autoreload_callback")
        for definition in registry.callbacks.values()
    ] + [
        (definition, "django_web_management_command_handle")
        for definition in command_roots.values()
    ]
