"""Resolve static pytest plugin declarations to the modules pytest loads."""

from __future__ import annotations

import ast
from collections import defaultdict, deque

from skylos.analysis.known_patterns import PYTEST_HOOKS
from skylos.analysis.pyproject_entrypoints import extract_entrypoint_references
from skylos.deadcode._reachability_bindings import FUNCTION_NODES, bound_names
from skylos.deadcode.framework_liveness import _eager_nodes

_HOOKS = PYTEST_HOOKS | {
    "pytest_assertion_pass",
    "pytest_collect_directory",
    "pytest_collection",
    "pytest_collectreport",
    "pytest_collectstart",
    "pytest_deselected",
    "pytest_enter_pdb",
    "pytest_itemcollected",
    "pytest_leave_pdb",
    "pytest_make_collect_report",
    "pytest_make_parametrize_id",
    "pytest_markeval_namespace",
    "pytest_plugin_registered",
    "pytest_pycollect_makeitem",
    "pytest_pycollect_makemodule",
    "pytest_report_from_serializable",
    "pytest_report_teststatus",
    "pytest_report_to_serializable",
    "pytest_runtestloop",
    "pytest_warning_recorded",
}


def _plugin_value(node, bindings):
    if isinstance(node, ast.Name):
        return bindings.get(node.id)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple)):
        values = tuple(_plugin_value(element, bindings) for element in node.elts)
        if all(isinstance(value, str) for value in values):
            return list(values) if isinstance(node, ast.List) else values
    return None


def _forget_escaped_lists(statement, bindings):
    escaped = {
        id(value)
        for node in _eager_nodes(statement)
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and isinstance(value := bindings.get(node.id), list)
    }
    if escaped:
        for name in [name for name, value in bindings.items() if id(value) in escaped]:
            del bindings[name]


def _module_bindings(tree):
    bindings = {}
    hooks = {}
    for statement in tree.body:
        targets = []
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            value = _plugin_value(statement.value, bindings)
        else:
            value = None
        is_literal_assignment = value is not None and all(
            isinstance(target, ast.Name) for target in targets
        )
        if not is_literal_assignment and any(
            isinstance(item, list) for item in bindings.values()
        ):
            _forget_escaped_lists(statement, bindings)
        for name in bound_names((statement,)).counts:
            bindings.pop(name, None)
            if name in _HOOKS:
                hooks[name] = statement
        if is_literal_assignment:
            for target in targets:
                bindings[target.id] = value
    return bindings.get("pytest_plugins"), hooks


def _loaded_plugin_modules(index, parsed_files, root):
    modules = defaultdict(list)
    pending = deque()
    for source in parsed_files:
        path = index._resolve_path(source.path)
        module = index.modules[path]
        modules[module].append(source)
        if path.name == "conftest.py":
            pending.append((source, True))
        elif path.match("test_*.py") or path.match("*_test.py"):
            pending.append((source, False))

    def include(name):
        candidates = modules.get(name, ())
        if len(candidates) == 1:
            pending.append((candidates[0], True))

    for module, attribute in extract_entrypoint_references(root, group="pytest11"):
        if not attribute:
            include(module)

    loaded = set()
    while pending:
        source, registered = pending.popleft()
        path = index._resolve_path(source.path)
        identity = (path, registered)
        if identity in loaded:
            continue
        loaded.add(identity)
        specs, hooks = _module_bindings(source.tree)
        module = index.modules[path]
        if registered and len(modules[module]) == 1:
            yield path, module, hooks
        if isinstance(specs, str):
            specs = specs.split(",")
        if isinstance(specs, (list, tuple)):
            for name in specs:
                include(name)


def find_pytest_hook_targets(index, parsed_files, root):
    for path, module, hooks in _loaded_plugin_modules(index, parsed_files, root):
        for name, statement in hooks.items():
            definition = index.class_or_function(f"{module}.{name}")
            hook = getattr(definition, "node", None)
            if not isinstance(hook, FUNCTION_NODES):
                continue
            yield definition, "pytest_hook"
            if isinstance(statement, ast.ImportFrom):
                for target in index.all_by_location.get((path, statement.lineno), ()):
                    if target.type == "import" and target.binding_name == name:
                        yield target, "pytest_hook_import"
            # Pluggy supplies required positional arguments and leaves optional
            # parameters at their defaults.
            args = [*hook.args.posonlyargs, *hook.args.args]
            required = args[: len(args) - len(hook.args.defaults)]
            parameters = index.parameters.get(definition.name, {})
            for arg in required:
                parameter = parameters.get(arg.arg)
                if parameter is not None and parameter.line == arg.lineno:
                    yield parameter, "pytest_hook_parameter"
