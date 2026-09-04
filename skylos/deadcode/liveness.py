from __future__ import annotations

import ast
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from skylos.deadcode.plugin_registry import find_literal_plugin_registry_targets
from skylos.deadcode.python_ast import ParsedPythonFile, parse_python_files


SENTINEL_CALLER = "<skylos.deadcode.liveness>"
DOC_EXTS = {".md", ".rst", ".txt"}
DOC_NAMES = {"README", "FAQ"}
REGISTRATION_WORDS = (
    "callback",
    "command",
    "decorator",
    "handler",
    "hook",
    "listener",
    "processor",
    "receiver",
    "register",
    "route",
    "signal",
    "subscriber",
)
REGISTRATION_MUTATORS = {"add", "append", "extend", "insert", "register", "setdefault"}
PROTOCOL_METHODS_BY_BASE = {
    "Handler": {"emit"},
    "logging.Handler": {"emit"},
    "Formatter": {"format", "formatException", "formatMessage", "formatTime"},
    "logging.Formatter": {"format", "formatException", "formatMessage", "formatTime"},
}
COMMON_UNTYPED_ATTR_CALLS = {
    "add",
    "append",
    "clear",
    "close",
    "copy",
    "extend",
    "format",
    "get",
    "items",
    "keys",
    "pop",
    "read",
    "remove",
    "render",
    "setdefault",
    "update",
    "values",
    "write",
}
FRAMEWORK_PROXY_NAMES = {"current_app"}
CELERY_ROUTE_SETTING_NAMES = {"task_routes", "CELERY_TASK_ROUTES"}
PYTHON_SOURCE_ROOT_NAMES = {"src", "lib", "python"}
_DISABLE_VALUES = {"0", "false", "no", "off"}


@dataclass(frozen=True)
class LivenessRescue:
    name: str
    reason: str
    file: str
    line: int


@dataclass
class LivenessReport:
    rescued: list[LivenessRescue] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        rescued_items: list[dict[str, Any]] = []
        for rescue in self.rescued:
            rescued_items.append(
                {
                    "name": rescue.name,
                    "reason": rescue.reason,
                    "file": rescue.file,
                    "line": rescue.line,
                }
            )
        return {
            "rescued_count": len(self.rescued),
            "rescued": rescued_items,
        }


@dataclass(frozen=True)
class _AttrCall:
    attr: str
    base_name: str
    file: Path
    line: int


def apply_dead_code_liveness(
    definitions: dict[str, Any],
    refs: Iterable[tuple[str, Any]],
    project_root: str | Path,
    files: Iterable[str | Path] | None = None,
) -> LivenessReport:

    report = LivenessReport()
    if os.getenv("SKYLOS_DEAD_CODE_LIVENESS", "1").lower() in _DISABLE_VALUES:
        return report

    root = Path(project_root).resolve()
    py_files = _python_files(root, files)
    parsed_files = tuple(parse_python_files(py_files))
    docs_text = _read_public_docs(root)
    attr_calls = _collect_attr_calls(parsed_files)

    classes: dict[str, Any] = {}
    class_methods: dict[str, list[Any]] = defaultdict(list)
    for defn in definitions.values():
        if getattr(defn, "type", None) == "class":
            classes[getattr(defn, "name", "")] = defn
        elif getattr(defn, "type", None) == "method" and "." in getattr(
            defn, "name", ""
        ):
            class_methods[defn.name.rsplit(".", 1)[0]].append(defn)

    _rescue_optional_import_fallbacks(definitions, refs, report)
    if not _project_shadows_top_level_module(root, parsed_files, "django"):
        _rescue_django_migration_callbacks(definitions, parsed_files, report)
        _rescue_django_appconfig_signal_imports(definitions, parsed_files, report)
    if not _project_shadows_top_level_module(root, parsed_files, "celery"):
        _rescue_celery_task_routers(definitions, parsed_files, report)
    _rescue_protocol_overrides(classes, class_methods, report)
    _rescue_registration_methods(classes, class_methods, report)
    for target in find_literal_plugin_registry_targets(definitions, parsed_files):
        _mark(target, "literal_plugin_registry", report)
    _rescue_documented_public_methods(classes, class_methods, docs_text, report)
    _rescue_unique_external_attr_calls(classes, class_methods, attr_calls, report)
    return report


def _project_shadows_top_level_module(
    root: Path,
    parsed_files: Iterable[ParsedPythonFile],
    module_name: str,
) -> bool:
    for parsed in parsed_files:
        try:
            relative_parts = parsed.path.resolve().relative_to(root).parts
        except (OSError, ValueError):
            continue
        if not relative_parts:
            continue
        if root.name == module_name and relative_parts[0] == "__init__.py":
            return True
        if relative_parts[0] == f"{module_name}.py":
            return True
        if relative_parts[0] == module_name and len(relative_parts) > 1:
            return True
        if (
            relative_parts[0] in PYTHON_SOURCE_ROOT_NAMES
            and len(relative_parts) > 1
            and relative_parts[1] in {module_name, f"{module_name}.py"}
        ):
            return True
    return False


def _mark(defn: Any, reason: str, report: LivenessReport) -> None:
    if getattr(defn, "references", 0) <= 0:
        defn.references += 1
    refs = getattr(defn, "heuristic_refs", None)
    if refs is not None:
        refs[f"dead_code_liveness:{reason}"] = 1.0
    signals = getattr(defn, "framework_signals", None)
    if signals is not None and reason not in signals:
        signals.append(reason)
    called_by = getattr(defn, "called_by", None)
    if called_by is not None:
        called_by.add(SENTINEL_CALLER)
    report.rescued.append(
        LivenessRescue(
            name=str(getattr(defn, "name", "")),
            reason=reason,
            file=str(getattr(defn, "filename", "")),
            line=int(getattr(defn, "line", 0) or 0),
        )
    )


def _rescue_django_migration_callbacks(
    definitions: dict[str, Any],
    parsed_files: Iterable[ParsedPythonFile],
    report: LivenessReport,
) -> None:
    """Keep the parameters Django supplies to ``RunPython`` callbacks live."""

    defs_by_location = _definitions_by_location(definitions)
    defs_by_name = {
        str(getattr(defn, "name", "")): defn
        for defn in definitions.values()
        if getattr(defn, "type", None) == "function"
    }
    params_by_owner = _parameters_by_owner(definitions)
    for parsed in parsed_files:
        if "migrations" not in parsed.path.parts:
            continue
        module_aliases, callable_aliases = _django_runpython_aliases(parsed.tree)
        if not module_aliases and not callable_aliases:
            continue
        imported_symbols = _top_level_imported_symbols(parsed.tree)

        top_level_functions = {
            node.name: node
            for node in parsed.tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for node, class_bindings in _calls_outside_function_scopes_with_bindings(
            parsed.tree
        ):
            callee_root = _qualified_expr_name(node.func).split(".", 1)[0]
            if callee_root in class_bindings:
                continue
            if not _is_django_runpython_call(
                node, module_aliases, callable_aliases
            ):
                continue
            for callback in _runpython_callback_expressions(node):
                if not isinstance(callback, ast.Name):
                    continue
                if callback.id in class_bindings:
                    continue
                function_node = top_level_functions.get(callback.id)
                function_def = None
                if function_node is not None:
                    function_def = defs_by_location.get(
                        (
                            str(parsed.path.resolve()),
                            function_node.lineno,
                            function_node.name,
                            "function",
                        )
                    )
                if function_def is None:
                    imported_name = imported_symbols.get(callback.id)
                    if imported_name is not None:
                        function_def = defs_by_name.get(imported_name)
                if function_def is None:
                    continue
                _mark_first_positional_parameters(
                    function_def,
                    params_by_owner,
                    2,
                    "django_migration_callback",
                    report,
                )


def _django_runpython_aliases(tree: ast.Module) -> tuple[set[str], set[str]]:
    module_aliases: set[str] = set()
    callable_aliases: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            if node.level != 0:
                continue
            if node.module == "django.db":
                for alias in node.names:
                    if alias.name == "migrations":
                        module_aliases.add(alias.asname or alias.name)
            elif node.module == "django.db.migrations":
                for alias in node.names:
                    if alias.name == "RunPython":
                        callable_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name != "django.db.migrations":
                    continue
                if alias.asname:
                    module_aliases.add(alias.asname)
                else:
                    module_aliases.add("django.db.migrations")
    rebound_names = _top_level_rebound_names(tree)
    module_aliases = {
        alias for alias in module_aliases if alias.split(".", 1)[0] not in rebound_names
    }
    callable_aliases.difference_update(rebound_names)
    return module_aliases, callable_aliases


def _is_django_runpython_call(
    node: ast.Call, module_aliases: set[str], callable_aliases: set[str]
) -> bool:
    if isinstance(node.func, ast.Name):
        return node.func.id in callable_aliases
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "RunPython":
        return False
    return _qualified_expr_name(node.func.value) in module_aliases


def _runpython_callback_expressions(node: ast.Call) -> list[ast.expr]:
    callbacks = list(node.args[:2])
    for keyword in node.keywords:
        if keyword.arg in {"code", "reverse_code"}:
            callbacks.append(keyword.value)
    return callbacks


def _rescue_django_appconfig_signal_imports(
    definitions: dict[str, Any],
    parsed_files: Iterable[ParsedPythonFile],
    report: LivenessReport,
) -> None:
    """Recognize signal-module imports used for side effects in ``ready``."""

    defs_by_file_line = _definitions_by_file_line(definitions)
    for parsed in parsed_files:
        appconfig_bases = _django_appconfig_base_aliases(parsed.tree)
        if not appconfig_bases:
            continue
        for class_node in parsed.tree.body:
            if not isinstance(class_node, ast.ClassDef):
                continue
            if not any(
                _qualified_expr_name(base) in appconfig_bases
                for base in class_node.bases
            ):
                continue
            for statement in class_node.body:
                if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if statement.name != "ready":
                    continue
                for (
                    import_line,
                    imported_name,
                    binding_name,
                ) in _signal_imports_in_ready(statement):
                    candidates = defs_by_file_line.get(
                        (str(parsed.path.resolve()), import_line), ()
                    )
                    for defn in candidates:
                        if getattr(defn, "type", None) != "import":
                            continue
                        if getattr(defn, "binding_name", "") != binding_name:
                            continue
                        defn_name = str(getattr(defn, "name", ""))
                        if imported_name.rsplit(".", 1)[-1] == "signals" or (
                            defn_name.endswith(".signals")
                        ):
                            _mark_if_unused(
                                defn,
                                "django_appconfig_signal_import",
                                report,
                            )


def _django_appconfig_base_aliases(tree: ast.Module) -> set[str]:
    aliases: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.level == 0:
            if node.module == "django.apps":
                for alias in node.names:
                    if alias.name == "AppConfig":
                        aliases.add(alias.asname or alias.name)
            elif node.module == "django":
                for alias in node.names:
                    if alias.name == "apps":
                        aliases.add(f"{alias.asname or alias.name}.AppConfig")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name != "django.apps":
                    continue
                if alias.asname:
                    aliases.add(f"{alias.asname}.AppConfig")
                else:
                    aliases.add("django.apps.AppConfig")
    rebound_names = _top_level_rebound_names(tree)
    return {alias for alias in aliases if alias.split(".", 1)[0] not in rebound_names}


class _ReadySignalImportCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.imports: list[tuple[int, str, str]] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name.rsplit(".", 1)[-1] != "signals":
                continue
            binding_name = alias.asname or alias.name.split(".", 1)[0]
            self.imports.append(
                (getattr(alias, "lineno", node.lineno), alias.name, binding_name)
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "signals":
                continue
            self.imports.append(
                (
                    getattr(alias, "lineno", node.lineno),
                    alias.name,
                    alias.asname or alias.name,
                )
            )

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, _node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return


def _signal_imports_in_ready(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[int, str, str]]:
    collector = _ReadySignalImportCollector()
    for statement in node.body:
        collector.visit(statement)
    return collector.imports


def _rescue_celery_task_routers(
    definitions: dict[str, Any],
    parsed_files: Iterable[ParsedPythonFile],
    report: LivenessReport,
) -> None:
    """Resolve callable routers registered in Celery's ``task_routes`` setting."""

    params_by_owner = _parameters_by_owner(definitions)
    defs_by_name = {
        str(getattr(defn, "name", "")): defn
        for defn in definitions.values()
        if getattr(defn, "type", None) in {"function", "class"}
    }
    local_callables: dict[tuple[str, str], Any] = {}
    for defn in definitions.values():
        if getattr(defn, "type", None) not in {"function", "class"}:
            continue
        node = getattr(defn, "node", None)
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if getattr(node, "col_offset", -1) != 0:
            continue
        local_callables[
            (str(Path(getattr(defn, "filename", "")).resolve()), defn.simple_name)
        ] = defn

    for parsed in parsed_files:
        imported_symbols = _top_level_imported_symbols(parsed.tree)
        for value, allow_name_candidates in _celery_task_route_values(parsed.tree):
            for candidate in _literal_router_candidates(value):
                defn = None
                if isinstance(candidate, ast.Name):
                    if not allow_name_candidates:
                        continue
                    defn = local_callables.get(
                        (str(parsed.path.resolve()), candidate.id)
                    )
                    if defn is None:
                        imported_name = imported_symbols.get(candidate.id)
                        if imported_name is not None:
                            defn = defs_by_name.get(imported_name)
                elif isinstance(candidate, str):
                    normalized = candidate.replace(":", ".")
                    defn = defs_by_name.get(normalized)
                if defn is None:
                    continue
                _mark_if_unused(defn, "celery_task_router", report)
                _mark_celery_router_parameters(
                    defn,
                    params_by_owner,
                    "celery_task_router",
                    report,
                )


def _celery_task_route_values(tree: ast.Module) -> list[tuple[ast.expr, bool]]:
    values: list[tuple[ast.expr, bool]] = []
    celery_factories = _celery_factory_names(tree)
    celery_app_initializers = _celery_app_initializers(tree, celery_factories)
    celery_apps = set(celery_app_initializers)
    instantiated_local_classes = {
        _qualified_expr_name(call.func)
        for call in _calls_outside_function_scopes(tree)
    }

    module_settings: dict[str, ast.expr] = {}
    app_settings: dict[str, ast.expr] = {}
    app_last_write: dict[str, int] = {}
    direct_update_calls: set[int] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if _is_module_task_routes_target(target):
                    module_settings[target.id] = node.value
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None and _is_module_task_routes_target(node.target):
                module_settings[node.target.id] = node.value

        for app_name, initializer in _celery_initializer_assignments(
            node,
            celery_app_initializers,
        ):
            app_settings.pop(app_name, None)
            app_last_write[app_name] = node.lineno
            route_values = _celery_keyword_route_values(initializer)
            if route_values:
                app_settings[app_name] = route_values[-1]

        for app_name, assigned_value in _celery_app_conf_assignments(
            node, celery_apps
        ):
            app_settings[app_name] = assigned_value
            app_last_write[app_name] = node.lineno

        direct_call = node.value if isinstance(node, ast.Expr) else None
        if not isinstance(direct_call, ast.Call):
            continue
        app_name = _celery_conf_update_app(direct_call, celery_apps)
        if app_name is None:
            continue
        direct_update_calls.add(id(direct_call))
        route_values, unknown_mapping = _celery_update_route_values(direct_call)
        if unknown_mapping:
            app_settings.pop(app_name, None)
            app_last_write[app_name] = node.lineno
        if route_values:
            app_settings[app_name] = route_values[-1]
            app_last_write[app_name] = node.lineno

    values.extend((value, True) for value in module_settings.values())
    values.extend((value, True) for value in app_settings.values())

    for call in _calls_outside_function_scopes(tree):
        if id(call) in direct_update_calls:
            continue
        app_name = _celery_conf_update_app(call, celery_apps)
        if app_name is None:
            continue
        route_values, _unknown_mapping = _celery_update_route_values(call)
        if call.lineno > app_last_write.get(app_name, -1) and route_values:
            values.append((route_values[-1], True))

    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or not _is_celery_class(
            node,
            celery_factories,
            instantiated_local_classes,
        ):
            continue
        for statement in node.body:
            if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if statement.name != "__init__":
                continue
            values.extend(
                (value, False)
                for value in _self_task_route_values_in_init(statement)
            )
    return values


def _is_module_task_routes_target(node: ast.expr) -> bool:
    if isinstance(node, ast.Name):
        return node.id in CELERY_ROUTE_SETTING_NAMES
    return False


def _celery_factory_names(tree: ast.Module) -> set[str]:
    names = {
        node.name
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "Celery"
    }
    for node in tree.body:
        if (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module == "celery"
        ):
            for alias in node.names:
                if alias.name == "Celery":
                    names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "celery":
                    names.add(
                        f"{alias.asname}.Celery" if alias.asname else "celery.Celery"
                    )
    rebound_names = _top_level_rebound_names(tree)
    return {
        name for name in names if name.split(".", 1)[0] not in rebound_names
    }


def _celery_app_initializers(
    tree: ast.Module, factories: set[str]
) -> dict[str, ast.Call]:
    initializers: dict[str, ast.Call] = {}
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Call):
            continue
        if _qualified_expr_name(value.func) not in factories:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                initializers[target.id] = value
    rebound_names = _top_level_rebound_names(tree)
    return {
        name: initializer
        for name, initializer in initializers.items()
        if name not in rebound_names
    }


def _celery_initializer_assignments(
    node: ast.stmt,
    app_initializers: dict[str, ast.Call],
) -> list[tuple[str, ast.Call]]:
    if not isinstance(node, (ast.Assign, ast.AnnAssign)):
        return []
    if not isinstance(node.value, ast.Call):
        return []
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return [
        (target.id, node.value)
        for target in targets
        if isinstance(target, ast.Name)
        and app_initializers.get(target.id) is node.value
    ]


def _celery_app_conf_assignments(
    node: ast.stmt, celery_apps: set[str]
) -> list[tuple[str, ast.expr]]:
    if not isinstance(node, (ast.Assign, ast.AnnAssign)):
        return []
    if node.value is None:
        return []
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    assignments: list[tuple[str, ast.expr]] = []
    for target in targets:
        target_name = _qualified_expr_name(target)
        for app_name in celery_apps:
            if target_name in {
                f"{app_name}.conf.task_routes",
                f"{app_name}.conf.CELERY_TASK_ROUTES",
            }:
                assignments.append((app_name, node.value))
    return assignments


def _is_celery_class(
    node: ast.ClassDef,
    factories: set[str],
    instantiated_local_classes: set[str],
) -> bool:
    is_celery_class = node.name == "Celery" or any(
        _qualified_expr_name(base) in factories for base in node.bases
    )
    return is_celery_class and node.name in instantiated_local_classes


def _celery_conf_update_app(
    call: ast.Call,
    celery_apps: set[str],
) -> str | None:
    callee = _qualified_expr_name(call.func)
    for app_name in celery_apps:
        if callee == f"{app_name}.conf.update":
            return app_name
    return None


def _celery_keyword_route_values(call: ast.Call) -> list[ast.expr]:
    return [
        keyword.value
        for keyword in call.keywords
        if keyword.arg in CELERY_ROUTE_SETTING_NAMES
    ]


def _celery_update_route_values(call: ast.Call) -> tuple[list[ast.expr], bool]:
    values: list[ast.expr] = []
    unknown_mapping = False
    for argument in call.args:
        literal_values, literal_is_unknown = _literal_route_settings(argument)
        values.extend(literal_values)
        unknown_mapping = unknown_mapping or literal_is_unknown
    for keyword in call.keywords:
        if keyword.arg is None:
            unknown_mapping = True
        elif keyword.arg in CELERY_ROUTE_SETTING_NAMES:
            values.append(keyword.value)
    return values, unknown_mapping


def _literal_route_settings(node: ast.expr) -> tuple[list[ast.expr], bool]:
    if not isinstance(node, ast.Dict):
        return [], True
    values: list[ast.expr] = []
    unknown_mapping = False
    for key, value in zip(node.keys, node.values):
        if key is None:
            unknown_mapping = True
            continue
        if (
            isinstance(key, ast.Constant)
            and isinstance(key.value, str)
            and key.value in CELERY_ROUTE_SETTING_NAMES
        ):
            values.append(value)
    return values, unknown_mapping


def _self_task_routes_assignment(
    node: ast.Assign | ast.AnnAssign,
) -> ast.expr | None:
    if node.value is None:
        return None
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    for target in targets:
        if _qualified_expr_name(target) == "self.task_routes":
            return node.value
    return None


def _self_task_route_values_in_init(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.expr]:
    last_direct_value: ast.expr | None = None
    last_direct_line = -1
    conditional_values: list[tuple[int, ast.expr]] = []
    for statement in node.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            assigned_value = _self_task_routes_assignment(statement)
            if assigned_value is not None:
                last_direct_value = assigned_value
                last_direct_line = statement.lineno
                continue
        for assignment in _assignments_outside_nested_scopes(statement):
            assigned_value = _self_task_routes_assignment(assignment)
            if assigned_value is not None:
                conditional_values.append((assignment.lineno, assigned_value))

    values = [last_direct_value] if last_direct_value is not None else []
    values.extend(
        value for line, value in conditional_values if line > last_direct_line
    )
    return values


def _literal_router_candidates(value: ast.expr) -> list[ast.Name | str]:
    if isinstance(value, ast.Name):
        return [value]
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return [value.value]
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        candidates: list[ast.Name | str] = []
        for element in value.elts:
            if _is_ordered_task_route_pair(element):
                continue
            candidates.extend(_literal_router_candidates(element))
        return candidates
    # A mapping in ``task_routes`` maps task names to destinations; neither side
    # is a router callback, even when it happens to look like a dotted path.
    return []


def _is_ordered_task_route_pair(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Tuple)
        and len(node.elts) == 2
        and isinstance(node.elts[1], ast.Dict)
    )


def _qualified_expr_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_expr_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


class _CallOutsideFunctionCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.calls: list[tuple[ast.Call, frozenset[str]]] = []
        self._class_bindings: set[str] | None = None

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append((node, frozenset(self._class_bindings or ())))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if self._class_bindings is not None:
            self._class_bindings.add(node.name)
        return

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)

        outer_bindings = self._class_bindings
        self._class_bindings = set()
        for statement in node.body:
            self.visit(statement)
        self._class_bindings = outer_bindings
        if outer_bindings is not None:
            outer_bindings.add(node.name)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            self.visit(target)
        self._record_class_bindings(node.targets)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        self.visit(node.annotation)
        self.visit(node.target)
        self._record_class_bindings((node.target,))

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.target)
        self.visit(node.value)
        self._record_class_bindings((node.target,))

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self.visit(node.target)
        self._record_class_bindings((node.target,))

    def visit_Import(self, node: ast.Import) -> None:
        if self._class_bindings is None:
            return
        self._class_bindings.update(
            alias.asname or alias.name.split(".", 1)[0] for alias in node.names
        )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if self._class_bindings is None:
            return
        self._class_bindings.update(
            alias.asname or alias.name
            for alias in node.names
            if alias.name != "*"
        )

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        self.visit(node.target)
        self._record_class_bindings((node.target,))
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self.visit(item.optional_vars)
                self._record_class_bindings((item.optional_vars,))
        for statement in node.body:
            self.visit(statement)

    visit_AsyncWith = visit_With

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return

    def _record_class_bindings(self, targets: Iterable[ast.expr]) -> None:
        if self._class_bindings is None:
            return
        for target in targets:
            self._class_bindings.update(_bound_target_names(target))


def _calls_outside_function_scopes_with_bindings(
    tree: ast.Module,
) -> list[tuple[ast.Call, frozenset[str]]]:
    collector = _CallOutsideFunctionCollector()
    collector.visit(tree)
    return collector.calls


def _calls_outside_function_scopes(tree: ast.Module) -> list[ast.Call]:
    return [
        call
        for call, _class_bindings in _calls_outside_function_scopes_with_bindings(
            tree
        )
    ]


class _AssignmentOutsideNestedScopeCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.assignments: list[ast.Assign | ast.AnnAssign] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        self.assignments.append(node)
        self.generic_visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.assignments.append(node)
        if node.value is not None:
            self.visit(node.value)

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, _node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return


def _assignments_outside_nested_scopes(
    node: ast.stmt,
) -> list[ast.Assign | ast.AnnAssign]:
    collector = _AssignmentOutsideNestedScopeCollector()
    collector.visit(node)
    return collector.assignments


def _top_level_rebound_names(tree: ast.Module) -> set[str]:
    binding_sources: dict[str, set[tuple[str, object]]] = defaultdict(set)
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    binding_name = alias.asname
                    imported_name = alias.name
                else:
                    binding_name = alias.name.split(".", 1)[0]
                    imported_name = binding_name
                binding_sources[binding_name].add(("import", imported_name))
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name != "*":
                    binding_name = alias.asname or alias.name
                    module = "." * node.level + (node.module or "")
                    imported_name = f"{module}.{alias.name}".lstrip(".")
                    if node.level:
                        imported_name = "." * node.level + imported_name
                    binding_sources[binding_name].add(("import", imported_name))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            binding_sources[node.name].add(
                ("definition", (node.lineno, node.col_offset))
            )
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for name in _bound_target_names(target):
                    binding_sources[name].add(
                        ("assignment", (node.lineno, node.col_offset))
                    )
    return {
        name for name, sources in binding_sources.items() if len(sources) > 1
    }


def _top_level_imported_symbols(tree: ast.Module) -> dict[str, str]:
    rebound_names = _top_level_rebound_names(tree)
    imported: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom) or node.level != 0 or not node.module:
            continue
        for alias in node.names:
            if alias.name == "*":
                continue
            binding_name = alias.asname or alias.name
            if binding_name in rebound_names:
                continue
            imported[binding_name] = f"{node.module}.{alias.name}"
    return imported


def _bound_target_names(node: ast.expr) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for element in node.elts:
            names.update(_bound_target_names(element))
        return names
    return set()


def _definitions_by_location(
    definitions: dict[str, Any],
) -> dict[tuple[str, int, str, str], Any]:
    indexed: dict[tuple[str, int, str, str], Any] = {}
    for defn in definitions.values():
        indexed[
            (
                str(Path(getattr(defn, "filename", "")).resolve()),
                int(getattr(defn, "line", 0) or 0),
                str(getattr(defn, "simple_name", "")),
                str(getattr(defn, "type", "")),
            )
        ] = defn
    return indexed


def _definitions_by_file_line(
    definitions: dict[str, Any],
) -> dict[tuple[str, int], list[Any]]:
    indexed: dict[tuple[str, int], list[Any]] = defaultdict(list)
    for defn in definitions.values():
        indexed[
            (
                str(Path(getattr(defn, "filename", "")).resolve()),
                int(getattr(defn, "line", 0) or 0),
            )
        ].append(defn)
    return indexed


def _parameters_by_owner(definitions: dict[str, Any]) -> dict[str, dict[str, Any]]:
    params: dict[str, dict[str, Any]] = defaultdict(dict)
    for defn in definitions.values():
        if getattr(defn, "type", None) != "parameter":
            continue
        owner, _, name = str(getattr(defn, "name", "")).rpartition(".")
        params[owner][name] = defn
    return params


def _mark_celery_router_parameters(
    callable_def: Any,
    params_by_owner: dict[str, dict[str, Any]],
    reason: str,
    report: LivenessReport,
) -> None:
    node = getattr(callable_def, "node", None)
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return
    owner_params = params_by_owner.get(str(getattr(callable_def, "name", "")), {})
    positional_args = [*node.args.posonlyargs, *node.args.args]
    args = list(positional_args[:4])
    if len(positional_args) < 4 and node.args.vararg is not None:
        args.append(node.args.vararg)
    args.extend(arg for arg in node.args.args if arg.arg == "task")
    args.extend(arg for arg in node.args.kwonlyargs if arg.arg == "task")
    if node.args.kwarg is not None:
        args.append(node.args.kwarg)
    for arg in args:
        parameter = owner_params.get(arg.arg)
        if parameter is not None:
            _mark_if_unused(parameter, reason, report)


def _mark_first_positional_parameters(
    callable_def: Any,
    params_by_owner: dict[str, dict[str, Any]],
    count: int,
    reason: str,
    report: LivenessReport,
) -> None:
    node = getattr(callable_def, "node", None)
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return
    owner_params = params_by_owner.get(str(getattr(callable_def, "name", "")), {})
    positional_args = [*node.args.posonlyargs, *node.args.args]
    for arg in positional_args[:count]:
        parameter = owner_params.get(arg.arg)
        if parameter is not None:
            _mark_if_unused(parameter, reason, report)
    if len(positional_args) < count and node.args.vararg is not None:
        parameter = owner_params.get(node.args.vararg.arg)
        if parameter is not None:
            _mark_if_unused(parameter, reason, report)


def _mark_if_unused(defn: Any, reason: str, report: LivenessReport) -> None:
    if getattr(defn, "references", 0) <= 0:
        _mark(defn, reason, report)


def _is_live_class(defn: Any) -> bool:
    if getattr(defn, "references", 0) > 0:
        return True
    if getattr(defn, "is_exported", False):
        return True
    if _is_public_name(getattr(defn, "simple_name", "")):
        return True
    return False


def _is_public_name(name: str) -> bool:
    return bool(name and not name.startswith("_"))


def _owner_live(classes: dict[str, Any], owner: str) -> bool:
    class_def = classes.get(owner)
    if not class_def:
        return False
    return _is_live_class(class_def)


def _is_support_file(defn: Any) -> bool:
    try:
        path_parts = Path(getattr(defn, "filename", "")).parts
    except TypeError:
        return False
    for part in path_parts:
        if part.lower() in {"test", "tests", "docs", "examples"}:
            return True
    return False


def _python_files(root: Path, files: Iterable[str | Path] | None) -> list[Path]:
    if files is not None:
        explicit_files: list[Path] = []
        for file in files:
            path = Path(file)
            if path.suffix == ".py":
                explicit_files.append(path)
        return explicit_files
    if not root.exists():
        return []
    ignored = {".git", ".venv", "venv", "__pycache__"}
    python_files: list[Path] = []
    for path in root.rglob("*.py"):
        if _path_has_ignored_part(path, ignored):
            continue
        python_files.append(path)
    return python_files


def _path_has_ignored_part(path: Path, ignored: set[str]) -> bool:
    for part in path.parts:
        if part in ignored:
            return True
    return False


def _read_public_docs(root: Path) -> str:
    if not root.exists() or not root.is_dir():
        return ""

    ignored = {".git", ".venv", "venv", "__pycache__"}
    parts: list[str] = []
    seen_bytes = 0
    for path in root.rglob("*"):
        if not path.is_file() or _path_has_ignored_part(path, ignored):
            continue
        if path.suffix.lower() not in DOC_EXTS and path.stem.upper() not in DOC_NAMES:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > 300_000:
            continue
        if seen_bytes + size > 2_000_000:
            break
        try:
            parts.append(path.read_text(encoding="utf-8", errors="ignore"))
            seen_bytes += size
        except OSError:
            continue
    return "\n".join(parts)


def _collect_attr_calls(files: Iterable[ParsedPythonFile]) -> list[_AttrCall]:
    calls: list[_AttrCall] = []
    for parsed in files:
        for node in ast.walk(parsed.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                calls.append(
                    _AttrCall(
                        node.func.attr,
                        _attr_call_base_name(node.func),
                        parsed.path,
                        getattr(node, "lineno", 0),
                    )
                )
    return calls


def _attr_call_base_name(func: ast.Attribute) -> str:
    value = func.value
    if isinstance(value, ast.Name):
        return value.id
    while isinstance(value, ast.Attribute):
        value = value.value
    if isinstance(value, ast.Name):
        return value.id
    return ""


def _rescue_optional_import_fallbacks(
    definitions: dict[str, Any],
    refs: Iterable[tuple[str, Any]],
    report: LivenessReport,
) -> None:
    conditional_imports = []
    for defn in definitions.values():
        if getattr(defn, "type", None) != "import":
            continue
        if not getattr(defn, "conditional_import", False):
            continue
        conditional_imports.append(defn)
    if not conditional_imports:
        return

    referenced_simples: set[str] = set()
    for ref, _ref_file in refs:
        referenced_simples.add(str(ref).rsplit(".", 1)[-1])

    conditional_by_file: dict[tuple[str, str], bool] = {}
    for imp in conditional_imports:
        simple = getattr(imp, "simple_name", "")
        if simple:
            conditional_by_file[(str(Path(imp.filename).resolve()), simple)] = True

    for defn in definitions.values():
        if getattr(defn, "type", None) not in {"class", "function"}:
            continue
        simple = getattr(defn, "simple_name", "")
        if simple not in referenced_simples:
            continue
        key = (str(Path(defn.filename).resolve()), simple)
        if key in conditional_by_file:
            _mark(defn, "optional_import_fallback", report)


def _rescue_protocol_overrides(
    classes: dict[str, Any],
    class_methods: dict[str, list[Any]],
    report: LivenessReport,
) -> None:
    for owner, methods in class_methods.items():
        class_def = classes.get(owner)
        if not class_def:
            continue
        base_names = _base_names_for_class(class_def)
        live_methods: set[str] = set()
        for base in base_names:
            live_methods.update(PROTOCOL_METHODS_BY_BASE.get(base, set()))
        for method in methods:
            if getattr(method, "simple_name", "") in live_methods:
                _mark(method, "protocol_override", report)


def _rescue_registration_methods(
    classes: dict[str, Any],
    class_methods: dict[str, list[Any]],
    report: LivenessReport,
) -> None:
    for owner, methods in class_methods.items():
        if not _owner_live(classes, owner):
            continue
        for method in methods:
            if _is_support_file(method):
                continue
            name = getattr(method, "simple_name", "")
            if not _is_public_name(name):
                continue
            decorators = _decorator_leaf_names(method)
            if not _looks_registered_method(name, decorators):
                continue
            if not _stores_and_returns_callable(method):
                continue
            _mark(method, "registration_api", report)


def _base_names_for_class(class_def: Any) -> set[str]:
    base_names: set[str] = set()
    for base in getattr(class_def, "base_classes", []):
        if not isinstance(base, str):
            continue
        base_names.add(base)
        base_names.add(base.rsplit(".", 1)[-1])
    return base_names


def _decorator_leaf_names(method: Any) -> set[str]:
    decorators: set[str] = set()
    for decorator in getattr(method, "decorators", []):
        decorators.add(str(decorator).rsplit(".", 1)[-1].lower())
    return decorators


def _looks_registered_method(name: str, decorators: set[str]) -> bool:
    lowered_name = name.lower()
    for word in REGISTRATION_WORDS:
        if word in lowered_name:
            return True
    for decorator in decorators:
        if decorator in {"setupmethod", "route", "command", "receiver"}:
            return True
    return False


def _stores_and_returns_callable(method: Any) -> bool:
    node = getattr(method, "node", None)
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    params: list[str] = []
    for arg in node.args.args:
        params.append(arg.arg)
    if params and params[0] in {"self", "cls"}:
        params = params[1:]
    if not params:
        return False
    first_param = params[0]
    stores_param = False
    returns_param = False
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            if _call_stores_param_on_self_or_cls(child, first_param):
                stores_param = True
        elif isinstance(child, ast.Return):
            if isinstance(child.value, ast.Name) and child.value.id == first_param:
                returns_param = True
    return stores_param and returns_param


def _call_stores_param_on_self_or_cls(call: ast.Call, param_name: str) -> bool:
    func = call.func
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr not in REGISTRATION_MUTATORS:
        return False
    if not isinstance(func.value, ast.Attribute):
        return False
    receiver = func.value.value
    if not isinstance(receiver, ast.Name):
        return False
    if receiver.id not in {"self", "cls"}:
        return False
    return _call_has_arg_name(call, param_name)


def _call_has_arg_name(call: ast.Call, name: str) -> bool:
    for arg in call.args:
        if isinstance(arg, ast.Name) and arg.id == name:
            return True
    return False


def _rescue_documented_public_methods(
    classes: dict[str, Any],
    class_methods: dict[str, list[Any]],
    docs_text: str,
    report: LivenessReport,
) -> None:
    if not docs_text:
        return
    candidates: list[tuple[Any, tuple[str, str]]] = []
    for owner, methods in class_methods.items():
        if not _owner_live(classes, owner):
            continue
        class_name = owner.rsplit(".", 1)[-1]
        for method in methods:
            if _is_support_file(method):
                continue
            name = getattr(method, "simple_name", "")
            if _is_public_name(name):
                candidates.append((method, (class_name, name)))

    referenced = _documented_method_keys(
        docs_text,
        {key for _method, key in candidates},
    )
    for method, key in candidates:
        if key in referenced:
            _mark(method, "documented_public_api", report)


def _documented_method_keys(
    text: str,
    candidates: set[tuple[str, str]],
) -> set[tuple[str, str]]:
    if not text or not candidates:
        return set()

    qualified, by_method = _documented_method_candidates(candidates)
    referenced = _qualified_documented_method_keys(text, candidates, qualified)
    referenced.update(_sphinx_documented_method_keys(text, by_method))
    referenced.update(_long_call_documented_method_keys(text, by_method))
    return referenced


def _documented_method_candidates(
    candidates: set[tuple[str, str]],
) -> tuple[dict[str, set[tuple[str, str]]], dict[str, set[tuple[str, str]]]]:
    qualified: dict[str, set[tuple[str, str]]] = defaultdict(set)
    by_method: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for key in candidates:
        class_name, method_name = key
        qualified[f"{class_name}.{method_name}"].add(key)
        by_method[method_name].add(key)
    return qualified, by_method


def _qualified_documented_method_keys(
    text: str,
    candidates: set[tuple[str, str]],
    qualified: dict[str, set[tuple[str, str]]],
) -> set[tuple[str, str]]:
    referenced: set[tuple[str, str]] = set()
    word_candidates = {
        key
        for key in candidates
        if _is_regex_word_identifier(key[0]) and _is_regex_word_identifier(key[1])
    }
    for match in re.finditer(r"(?=\b([^\W\d]\w*)\.([^\W\d]\w*)\b)", text):
        key = match.group(1), match.group(2)
        if key in word_candidates:
            referenced.add(key)

    unusual_qualified = {
        name: keys - word_candidates
        for name, keys in qualified.items()
        if keys - word_candidates
    }
    for qualified_name, keys in unusual_qualified.items():
        if re.search(rf"\b{re.escape(qualified_name)}\b", text):
            referenced.update(keys)
    return referenced


def _sphinx_documented_method_keys(
    text: str,
    by_method: dict[str, set[tuple[str, str]]],
) -> set[tuple[str, str]]:
    referenced: set[tuple[str, str]] = set()
    role_targets = [
        match.group(1)
        for match in re.finditer(r"(?=:meth:`([^`]*)`)", text)
    ]
    for method_name, keys in by_method.items():
        if any(target.endswith(method_name) for target in role_targets):
            referenced.update(keys)
    return referenced


def _long_call_documented_method_keys(
    text: str,
    by_method: dict[str, set[tuple[str, str]]],
) -> set[tuple[str, str]]:
    referenced: set[tuple[str, str]] = set()
    long_methods = {
        method_name: keys
        for method_name, keys in by_method.items()
        if "_" in method_name and len(method_name) >= 10
    }
    for match in re.finditer(r"\.[ \t]*([^\W\d]\w*)\(", text):
        referenced.update(long_methods.get(match.group(1), ()))

    unusual_methods = {
        method_name: keys
        for method_name, keys in long_methods.items()
        if not _is_regex_word_identifier(method_name)
    }
    for method_name, keys in unusual_methods.items():
        if re.search(rf"\.[ \t]*{re.escape(method_name)}\(", text):
            referenced.update(keys)
    return referenced


def _is_regex_word_identifier(value: str) -> bool:
    return re.fullmatch(r"[^\W\d]\w*", value) is not None


def _rescue_unique_external_attr_calls(
    classes: dict[str, Any],
    class_methods: dict[str, list[Any]],
    attr_calls: list[_AttrCall],
    report: LivenessReport,
) -> None:
    if not attr_calls:
        return

    method_by_simple: dict[str, list[tuple[str, Any]]] = defaultdict(list)
    for owner, methods in class_methods.items():
        if not _owner_live(classes, owner):
            continue
        for method in methods:
            if _is_support_file(method):
                continue
            name = getattr(method, "simple_name", "")
            if _is_public_name(name):
                method_by_simple[name].append((owner, method))

    call_count: Counter[str] = Counter()
    calls_by_attr: dict[str, list[_AttrCall]] = defaultdict(list)
    for call in attr_calls:
        call_count[call.attr] += 1
        calls_by_attr[call.attr].append(call)

    for method_name, owner_methods in method_by_simple.items():
        if len(owner_methods) != 1:
            continue
        if method_name in COMMON_UNTYPED_ATTR_CALLS:
            continue
        if call_count.get(method_name, 0) == 0:
            continue
        _owner, method = owner_methods[0]
        method_file = Path(getattr(method, "filename", "")).resolve()
        if _has_external_framework_proxy_call(calls_by_attr[method_name], method_file):
            _mark(method, "unique_external_attr_call", report)


def _has_external_framework_proxy_call(
    calls: list[_AttrCall],
    method_file: Path,
) -> bool:
    for call in calls:
        if call.file.resolve() == method_file:
            continue
        if call.base_name not in FRAMEWORK_PROXY_NAMES:
            continue
        return True
    return False
