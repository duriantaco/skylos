"""Join reachable subclass discovery to source-proved module loading.

A computed import path does not show that every project plugin was loaded.
Only unconditional imports at the discovery site or its reachable callers
establish that an otherwise unnamed subclass exists at that discovery site.
"""

from __future__ import annotations

import ast
from pathlib import Path

from skylos.deadcode._reachability_bindings import (
    argument_nodes,
    bound_names,
    relative_parent,
)
from skylos.deadcode.python_proofs import (
    _has_fromlist,
    _provider_available,
    qualified_name,
    scope_bindings,
)


def _dynamic_import(node, bindings, filename, *, receiver=False):
    if not isinstance(node, ast.Call) or not node.args:
        return None
    first = node.args[0]
    if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
        return None
    if qualified_name(
        node.func, bindings
    ) == "importlib.import_module" and _provider_available("importlib", filename):
        return first.value
    if (
        isinstance(node.func, ast.Name)
        and node.func.id == "__import__"
        and "__import__" not in bindings
    ):
        if receiver and not _has_fromlist(node):
            return first.value.split(".", 1)[0]
        return first.value
    return None


def _scope(module, owner, report):
    if not owner:
        return module.tree.body, scope_bindings(module.tree.body)
    definition = report.index.candidates.get(owner)
    node = getattr(definition, "node", None)
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return (), {}
    inherited = scope_bindings(module.tree.body)
    return node.body, scope_bindings(node.body, inherited, node.args)


def _module_loads(module, owner, cutoff, report, subject=""):
    body, bindings = _scope(module, owner, report)
    loaded = set()
    counts = {}
    if subject:
        for statement in body:
            for node in ast.walk(statement):
                if isinstance(node, ast.Name) and isinstance(
                    node.ctx, (ast.Store, ast.Del)
                ):
                    counts[node.id] = counts.get(node.id, 0) + 1
    for statement in body:
        if statement.lineno >= cutoff:
            continue
        if isinstance(statement, ast.Import) and not subject:
            loaded.update(alias.name for alias in statement.names)
        elif isinstance(statement, ast.ImportFrom) and not subject:
            parent = (
                relative_parent(statement, module)
                if statement.level
                else statement.module
            )
            if parent:
                loaded.add(parent)
                loaded.update(
                    f"{parent}.{alias.name}"
                    for alias in statement.names
                    if alias.name != "*"
                )
        elif isinstance(statement, ast.Assign):
            imported = _dynamic_import(
                statement.value, bindings, str(module.path), receiver=bool(subject)
            )
            if imported and not subject:
                loaded.add(imported)
            elif imported and len(statement.targets) == 1:
                target = statement.targets[0]
                if (
                    isinstance(target, ast.Name)
                    and target.id == subject
                    and counts.get(subject) == 1
                ):
                    loaded.add(imported)
        elif isinstance(statement, ast.Expr) and not subject:
            imported = _dynamic_import(statement.value, bindings, str(module.path))
            if imported:
                loaded.add(imported)
    return loaded


def _reference_sites(report):
    sites = {}
    call_lines = {
        path: {
            node.lineno for node in ast.walk(module.tree) if isinstance(node, ast.Call)
        }
        for path, module in report.index.modules.items()
    }
    for (path, line), references in report.graph.references.items():
        module = report.index.modules.get(path)
        if module is None:
            continue
        # An import binds a function but does not invoke the function. Keep
        # only source lines containing a call/registration expression.
        if line not in call_lines[path]:
            continue
        for reference in references:
            if reference.target:
                sites.setdefault(reference.target, set()).add(
                    (path, reference.owner or "", line)
                )
    return sites


def _loaded_module_paths(loaded, report):
    paths = set()
    pending = list(loaded)
    seen = set()
    while pending and len(seen) < 4096:
        imported = pending.pop()
        if imported in seen:
            continue
        seen.add(imported)
        parts = imported.split(".")
        for end in range(1, len(parts) + 1):
            for module in report.index.module_names.get(".".join(parts[:end]), ()):
                if module.path in paths:
                    continue
                paths.add(module.path)
                pending.extend(_module_loads(module, "", float("inf"), report))
    return paths


def _loading_contexts(owner, module, line, report, sites):
    contexts = {(module.path, owner, line)}
    pending = [owner] if owner else []
    seen = set()
    while pending and len(seen) < 256:
        target = pending.pop()
        if target in seen:
            continue
        seen.add(target)
        for path, caller, call_line in sites.get(target, ()):
            if caller and caller not in report.proven_reachable_keys:
                continue
            contexts.add((path, caller, call_line))
            if caller:
                pending.append(caller)
    # Imports above the enclosing function definition execute before its
    # body can run. Imports in unrelated functions do not count.
    for path, context_owner, _line in tuple(contexts):
        definition = report.index.candidates.get(context_owner)
        if definition is not None:
            contexts.add((path, "", definition.line))
    return contexts


def _builtin_subclass_lookup(base, module, owner, line, report, definitions):
    body, bindings = _scope(module, owner, report)
    calls = [
        node
        for statement in body
        for node in ast.walk(statement)
        if isinstance(node, ast.Call)
        and node.lineno == line
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "__subclasses__"
    ]
    if len(calls) != 1:
        return False
    receiver = calls[0].func.value
    resolved = qualified_name(receiver, bindings)
    if resolved != base:
        if not isinstance(receiver, ast.Name):
            return False
        if owner:
            function = report.index.candidates[owner].node
            local_names = set(bound_names(function.body).counts)
            local_names.update(
                argument.arg for argument in argument_nodes(function.args)
            )
            if receiver.id in local_names:
                return False
        if bound_names(module.tree.body).counts[receiver.id] != 1:
            return False
        if not any(f"{identity}.{receiver.id}" == base for identity in module.names):
            return False
    pending = [base]
    seen = set()
    while pending:
        target = pending.pop()
        if target in seen:
            continue
        seen.add(target)
        definition = definitions.get(target)
        node = getattr(definition, "node", None)
        if not isinstance(node, ast.ClassDef):
            return False
        if any(keyword.arg == "metaclass" for keyword in node.keywords):
            return False
        if "__subclasses__" in bound_names(node.body).counts:
            return False
        parents = list(getattr(definition, "base_classes", ()) or ())
        source_module = report.index.modules.get(Path(definition.filename).resolve())
        if source_module is not None:
            bindings = scope_bindings(source_module.tree.body)
            explicit_object = any(
                isinstance(parent, ast.Name)
                and parent.id == "object"
                and "object" not in bindings
                for parent in node.bases
            )
            if explicit_object:
                parents = [
                    parent
                    for parent in parents
                    if parent.rpartition(".")[2] != "object"
                ]
        pending.extend(parents)
    # A source-owned replacement of the class attribute changes the operation.
    for source_module in report.index.modules.values():
        for node in ast.walk(source_module.tree):
            receiver = None
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and node.attr == "__subclasses__"
            ):
                receiver = node.value
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr"}
                and len(node.args) >= 2
            ):
                if (
                    isinstance(node.args[1], ast.Constant)
                    and node.args[1].value == "__subclasses__"
                ):
                    receiver = node.args[0]
            if receiver is not None:
                binding = report.index.resolve(receiver, source_module, {})
                if binding and binding[1] in seen:
                    return False
    return True


def discovered_classes(discoveries, report, definitions, children_of):
    from skylos.deadcode.module_loader_proofs import executed_modules

    found = set()
    sites = _reference_sites(report)
    execution = executed_modules(
        report,
        {site[1] for site in discoveries if isinstance(site, tuple) and len(site) == 6},
    )
    for discovery in discoveries:
        if not isinstance(discovery, tuple) or len(discovery) != 6:
            # Old tracker payloads containing only a base name are hints.
            continue
        base, owner, module_name, line, kind, subject = discovery
        if (
            owner
            and owner not in report.proven_reachable_keys
            and owner not in execution.source_called
        ):
            continue
        modules = report.index.module_names.get(module_name, ())
        if len(modules) != 1:
            continue
        module = modules[0]
        if kind == "members":
            # Enumerating one module cannot reach subclasses in another.
            loaded = _module_loads(module, owner, line, report, subject=subject)
            directly_loaded = set(execution.receivers.get((owner, subject), ()))
        elif kind == "subclasses":
            if not _builtin_subclass_lookup(
                base, module, owner, line, report, definitions
            ):
                continue
            loaded = set()
            directly_loaded = set()
            for path, context_owner, cutoff in _loading_contexts(
                owner, module, line, report, sites
            ):
                context_module = report.index.modules.get(path)
                if context_module is not None:
                    loaded.update(
                        _module_loads(context_module, context_owner, cutoff, report)
                    )
                    directly_loaded.update(
                        execution.loaded_before(path, context_owner, cutoff)
                    )
        else:
            continue
        if kind == "members":
            eligible_paths = {
                candidate.path
                for name in loaded
                for candidate in report.index.module_names.get(name, ())
            } | directly_loaded
        else:
            eligible_paths = _loaded_module_paths(loaded, report) | directly_loaded
        pending = list(children_of.get(base, ()))
        descendants = set()
        while pending:
            child = pending.pop()
            if child in descendants:
                continue
            descendants.add(child)
            if kind == "members":
                pending.extend(children_of.get(child, ()))
        for child in descendants:
            definition = definitions.get(child)
            if definition is None:
                continue
            path = Path(definition.filename).resolve()
            source_module = report.index.modules.get(path)
            if source_module is None:
                continue
            local_cutoff = line
            if owner:
                owner_definition = report.index.candidates.get(owner)
                if owner_definition is not None:
                    local_cutoff = owner_definition.line
                for context_path, context_owner, cutoff in _loading_contexts(
                    owner, module, line, report, sites
                ):
                    if context_path == module.path and not context_owner:
                        local_cutoff = max(local_cutoff, cutoff)
            local_class = path == module.path and definition.line < local_cutoff
            if path not in eligible_paths and not local_class:
                continue
            # A nested or conditionally defined class is not established by
            # merely importing its module.
            if any(
                isinstance(node, ast.ClassDef) and node.lineno == definition.line
                for node in source_module.tree.body
            ):
                found.add(child)
    return found
