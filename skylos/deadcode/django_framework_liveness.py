"""Django startup, admin registration and routed generic-view contracts."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from skylos.deadcode.django_setting_bindings import selected_setting_views
from skylos.deadcode.django_template_liveness import (
    _configured_template_directories,
    _template_members,
)
from skylos.deadcode.framework_liveness import _FUNCTIONS, _qualified
from skylos.deadcode.web_framework_ast import (
    _dict_values,
    _has_base,
    _has_member,
    _literal,
    _member_names,
    _member_value,
)

_DETAIL_VIEWS = {
    "django.views.generic.DetailView",
    "django.views.generic.detail.DetailView",
}
_LIST_VIEWS = {"django.views.generic.ListView", "django.views.generic.list.ListView"}
_DJANGO_VIEWS = (
    _DETAIL_VIEWS
    | _LIST_VIEWS
    | {
        "django.views.generic.TemplateView",
        "django.views.generic.base.TemplateView",
    }
)
_CBV_OPTIONS = {
    "model",
    "queryset",
    "template_name",
    "template_name_suffix",
    "context_object_name",
    "extra_context",
    "paginate_by",
    "ordering",
    "allow_empty",
    "slug_field",
    "slug_url_kwarg",
    "pk_url_kwarg",
    "http_method_names",
    "content_type",
}
_TEMPLATE_OPTIONS = {
    "template_name",
    "extra_context",
    "http_method_names",
    "content_type",
}
_MODEL_OVERRIDES = {
    "queryset",
    "get_queryset",
    "get_object",
    "get_context_data",
    "get_context_object_name",
    "get_template_names",
}
_ADMIN_CONFIGS = {"django.contrib.admin", "django.contrib.admin.apps.AdminConfig"}
# Django dispatches these methods on the instances in AUTHENTICATION_BACKENDS.
# Merely looking like a backend, or appearing in another setting, is not proof.
_AUTH_BACKEND_METHODS = {
    "authenticate",
    "aauthenticate",
    "get_user",
    "aget_user",
    "get_user_permissions",
    "aget_user_permissions",
    "get_group_permissions",
    "aget_group_permissions",
    "get_all_permissions",
    "aget_all_permissions",
    "has_perm",
    "ahas_perm",
    "has_module_perms",
    "ahas_module_perms",
    "with_perm",
}
# Django storage backends loaded from STORAGES / DEFAULT_FILE_STORAGE.
_STORAGE_BACKEND_METHODS = {
    "save",
    "delete",
    "exists",
    "open",
    "listdir",
    "path",
    "size",
    "url",
    "generate_filename",
    "get_valid_name",
    "get_available_name",
    "get_accessed_time",
    "get_created_time",
    "get_modified_time",
}
# Classes constructed from LOGGING \"()\" / \"class\" paths.
_LOGGING_FACTORY_METHODS = {
    "filter",
    "format",
    "formatTime",
    "formatException",
    "formatStack",
}


@dataclass
class _Activation:
    settings: set
    apps: set = field(default_factory=set)
    admin_autodiscovery: bool = False
    url_roots: set = field(default_factory=set)
    routed: set = field(default_factory=set)
    loaded: set = field(default_factory=set)
    setting_views: list = field(default_factory=list)


@dataclass
class _DjangoProject:
    index: Any
    scanners: dict
    classes: dict
    root: Path
    exclude_folders: Iterable[str] | None
    directories: set
    view_overrides: set


def _app_name(name, classes):
    if name in classes and _has_base(name, {"django.apps.AppConfig"}, classes):
        return _literal(_member_value(classes[name][2], "name"))
    return name


# A module assigning INSTALLED_APPS plus one of these is a settings module,
# even when DJANGO_SETTINGS_MODULE is chosen outside the code.
_SETTINGS_MARKERS = {"ROOT_URLCONF", "MIDDLEWARE", "DATABASES", "SECRET_KEY"}
_DOTTED_PATH = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")


def _setting_names(scanner):
    names = (
        set(scanner.values)
        | set(getattr(scanner, "module_settings", {}))
        | set(getattr(scanner, "setting_bindings", {}))
    )
    return {name for name in names if name.isupper()}


def _setting_targets(scanner):
    """Django reads every UPPER_CASE setting by name via django.conf.settings."""
    targets = []
    for setting in sorted(_setting_names(scanner)):
        source_name = getattr(scanner, "setting_source_names", {}).get(setting, setting)
        qualified = scanner.module + "." + source_name
        definition = scanner.definition(qualified, kind="variable")
        if definition is not None:
            targets.append((definition, "django_web_setting"))
        else:
            # Assigned more than once (e.g. under ``if DEBUG:``): mark each.
            for candidate in scanner.index.all_by_name.get(qualified, ()):
                if candidate.type == "variable":
                    targets.append((candidate, "django_web_setting"))
    return targets


def _setting_reference_targets(scanner):
    """Project classes/functions named by dotted strings in settings.

    ``MIDDLEWARE``, ``STORAGES`` backends, ``TEMPLATES`` context processors,
    ``AUTHENTICATION_BACKENDS`` and ``REST_FRAMEWORK`` classes are imported by
    Django from these strings, whether assigned or added in place
    (``MIDDLEWARE.append(...)`` under ``if DEBUG:``).
    """
    targets = []
    for values in (
        *getattr(scanner, "module_settings", {}).values(),
        *getattr(scanner, "setting_mutations", {}).values(),
    ):
        for value in values:
            for node in ast.walk(value):
                if not isinstance(node, ast.Constant) or not isinstance(
                    node.value, str
                ):
                    continue
                path = node.value.strip().replace(":", ".")
                if len(path) > 300 or not _DOTTED_PATH.match(path):
                    continue
                definition = scanner.definition(path)
                if definition is not None and definition.type in {
                    "class",
                    "function",
                    "variable",
                }:
                    targets.append((definition, "django_web_setting_reference"))
    return targets


def _looks_like_settings(scanner):
    names = _setting_names(scanner)
    return "INSTALLED_APPS" in names and bool(names & _SETTINGS_MARKERS)


def _settings_closure(roots, scanners):
    """Whole-settings imports retain their existing star-import closure."""
    settings = set(roots)
    pending = list(roots)
    while pending:
        scanner = scanners.get(pending.pop())
        if scanner is None:
            continue
        for name in getattr(scanner, "star_imports", ()):
            if name in scanners and name not in settings:
                settings.add(name)
                pending.append(name)
    changed = True
    while changed:
        changed = False
        for name, scanner in scanners.items():
            if name in settings or not any(
                "settings" in part for part in name.split(".")
            ):
                continue
            if set(getattr(scanner, "star_imports", ())) & settings:
                settings.add(name)
                changed = True
    return settings


def _settings_activation(scanners, classes):
    settings = {name for scanner in scanners.values() for name in scanner.settings}
    settings |= {
        name for name, scanner in scanners.items() if _looks_like_settings(scanner)
    }
    settings = _settings_closure(settings, scanners)
    activation = _Activation(
        settings, setting_views=selected_setting_views(settings, scanners)
    )
    targets = []
    for name in settings:
        scanner = scanners.get(name)
        if scanner is None:
            continue
        targets.extend(_setting_targets(scanner))
    for scanner in activation.setting_views:
        targets.extend(_setting_targets(scanner))
        targets.extend(_setting_reference_targets(scanner))
        urlconf = _literal(scanner.values.get("ROOT_URLCONF"))
        if isinstance(urlconf, str):
            activation.url_roots.add(urlconf)
        configured = _member_names(scanner.values.get("INSTALLED_APPS"))
        activation.admin_autodiscovery |= bool(configured & _ADMIN_CONFIGS)
        apps = {_app_name(app, classes) for app in configured}
        activation.apps.update(app for app in apps if isinstance(app, str))
    return activation, targets


def _auth_backend_names(scanner):
    """Literal backend entries, excluding superseded straight-line settings."""
    final = scanner.values.get("AUTHENTICATION_BACKENDS")
    boundary = (getattr(final, "lineno", 0), getattr(final, "col_offset", 0))
    if any(
        position >= boundary
        for position in scanner.authentication_backend_invalidations
    ):
        return set()
    names = set()
    for value in scanner.authentication_backend_assignments:
        if (value.lineno, value.col_offset) >= boundary:
            names.update(_member_names(value))
    for value, position in scanner.authentication_backend_mutations:
        if position < boundary:
            continue
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            names.add(value.value)
        else:
            names.update(_member_names(value))
    return {name for name in names if len(name) <= 300 and _DOTTED_PATH.fullmatch(name)}


def _auth_class_binding(name, scanners, classes):
    """Resolve import/assignment aliases to a module's surviving class object."""
    seen = set()
    while name not in seen and len(seen) < 32:
        seen.add(name)
        module, _, local = name.rpartition(".")
        scanner = scanners.get(module)
        if scanner is None:
            return None
        binding = scanner.bindings.get(local)
        if binding == name:
            if name in classes:
                definition = scanner.definition(name, kind="class")
                if definition is not None and _auth_plain_class(definition):
                    return name
            return None
        if binding is None:
            return None
        name = binding
    return None


def _auth_plain_class(definition):
    node = getattr(definition, "node", None)
    return (
        isinstance(node, ast.ClassDef) and not node.decorator_list and not node.keywords
    )


def _auth_class_mro(name, scanners, classes, trail=(), cache=None):
    """C3 preserves which implementation Django actually obtains by getattr."""
    if cache is None:
        cache = {}
    if name in cache:
        cached = cache[name]
        if cached is None:
            return None
        return list(cached)
    if name in trail or len(trail) >= 32:
        return None
    if name not in classes:
        return [name]
    definition, bases, _, _ = classes[name]
    if not _auth_plain_class(definition):
        return None
    module = definition.name.rpartition(".")[0]
    scanner = scanners.get(module)
    if scanner is None or scanner.definition(name, kind="class") is None:
        return None
    parents = []
    sequences = []
    for base in bases:
        if base is None:
            return None
        if base not in classes:
            resolved = _auth_class_binding(base, scanners, classes)
            if resolved is not None:
                base = resolved
        parent_mro = _auth_class_mro(base, scanners, classes, (*trail, name), cache)
        if parent_mro is None:
            cache[name] = None
            return None
        parents.append(base)
        sequences.append(parent_mro)
    sequences.append(parents)
    result = [name]
    while any(sequences):
        sequences = [sequence for sequence in sequences if sequence]
        candidate = None
        for sequence in sequences:
            head = sequence[0]
            if not any(head in other[1:] for other in sequences):
                candidate = head
                break
        if candidate is None:
            cache[name] = None
            return None
        result.append(candidate)
        for sequence in sequences:
            if sequence[0] == candidate:
                sequence.pop(0)
    cache[name] = tuple(result)
    return result


def _effective_setting_values(scanner, name):
    """Possible values since the last unconditional replacement of a setting."""
    final = scanner.values.get(name)
    boundary = (getattr(final, "lineno", 0), getattr(final, "col_offset", 0))
    values = (
        *getattr(scanner, "module_settings", {}).get(name, ()),
        *getattr(scanner, "setting_mutations", {}).get(name, ()),
    )
    return tuple(
        value
        for value in values
        if any(
            position >= boundary
            for position in getattr(scanner, "setting_mutation_positions", {}).get(
                id(value), ((value.lineno, value.col_offset),)
            )
        )
    )


def _storage_backend_names(scanner):
    """Literal storage backend class paths from STORAGES / DEFAULT_FILE_STORAGE."""
    names = set()
    for setting in ("DEFAULT_FILE_STORAGE", "STATICFILES_STORAGE"):
        value = scanner.values.get(setting)
        literal = _literal(value)
        if isinstance(literal, str):
            names.add(literal)
    for values in _effective_setting_values(scanner, "STORAGES"):
        for node in ast.walk(values):
            if not isinstance(node, ast.Dict):
                continue
            for key, value in zip(node.keys, node.values):
                if (
                    isinstance(key, ast.Constant)
                    and key.value == "BACKEND"
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ):
                    names.add(value.value)
    return {name for name in names if len(name) <= 300 and _DOTTED_PATH.fullmatch(name)}


def _protocol_method_targets(configured, scanners, classes, methods, reason, loaded):
    """Mark bounded protocol methods on settings-wired plain classes."""
    bindings = {}
    for configured_name in configured:
        name = _auth_class_binding(configured_name, scanners, classes)
        if name is not None:
            bindings[configured_name] = name
    if not bindings:
        return []
    loaded = _loaded_modules(
        loaded | {name.rpartition(".")[0] for name in (*bindings, *bindings.values())},
        scanners,
    )
    overrides = {
        member
        for module in loaded
        if module in scanners
        for member in scanners[module].class_member_overrides
    }
    names = {
        name
        for configured_name, name in bindings.items()
        if configured_name not in overrides and name not in overrides
    }
    targets = []
    mros = {}
    for name in names:
        definition = classes[name][0]
        targets.append((definition, "django_web_setting_reference"))
        mro = _auth_class_mro(name, scanners, classes, cache=mros)
        if mro is None:
            continue
        for method in methods:
            for owner in mro:
                if owner == "builtins.object":
                    continue
                if owner not in classes:
                    break
                if owner + "." + method in overrides:
                    break
                node = classes[owner][2].get(method)
                if node is None:
                    continue
                module = owner.rpartition(".")[0]
                if (
                    isinstance(node, _FUNCTIONS)
                    and node in scanners[module].protocol_methods
                ):
                    target = scanners[module].definition(
                        owner + "." + method, line=node.lineno, kind="method"
                    )
                    if target is not None:
                        targets.append((target, reason))
                break
    return targets


def _auth_backend_targets(activation, scanners, classes):
    configured = {
        backend
        for scanner in activation.setting_views
        for backend in _auth_backend_names(scanner)
    }
    return _protocol_method_targets(
        configured,
        scanners,
        classes,
        _AUTH_BACKEND_METHODS,
        "django_web_auth_backend",
        activation.loaded,
    )


def _storage_backend_targets(activation, scanners, classes):
    configured = {
        backend
        for scanner in activation.setting_views
        for backend in _storage_backend_names(scanner)
    }
    return _protocol_method_targets(
        configured,
        scanners,
        classes,
        _STORAGE_BACKEND_METHODS,
        "django_web_storage_backend",
        activation.loaded,
    )


def _logging_factory_names(scanner):
    """Dotted class paths from LOGGING dict ``()`` / ``class`` entries."""
    names = set()
    for values in _effective_setting_values(scanner, "LOGGING"):
        for node in ast.walk(values):
            if not isinstance(node, ast.Dict):
                continue
            for key, value in zip(node.keys, node.values):
                if (
                    isinstance(key, ast.Constant)
                    and key.value in {"()", "class"}
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ):
                    names.add(value.value)
    return {name for name in names if len(name) <= 300 and _DOTTED_PATH.fullmatch(name)}


def _logging_factory_targets(activation, scanners, classes):
    configured = {
        factory
        for scanner in activation.setting_views
        for factory in _logging_factory_names(scanner)
    }
    return _protocol_method_targets(
        configured,
        scanners,
        classes,
        _LOGGING_FACTORY_METHODS,
        "django_web_logging_factory",
        activation.loaded,
    )


def _route_modules(activation, scanners):
    pending = list(activation.url_roots)
    visited = set()
    while pending:
        name = pending.pop()
        if name in visited or name not in scanners:
            continue
        visited.add(name)
        scanner = scanners[name]
        activation.routed.update(scanner.routes)
        pending.extend(scanner.includes)
    return visited


def _loaded_modules(roots, scanners):
    loaded = set(roots)
    pending = list(roots)
    while pending:
        scanner = scanners.get(pending.pop())
        if scanner is None:
            continue
        for name in scanner.imported_modules:
            if name in scanners and name not in loaded:
                loaded.add(name)
                pending.append(name)
    return loaded


def _admin_callbacks(scanner, name, members):
    targets = []
    for option in ("list_display", "readonly_fields", "actions"):
        for method in _member_names(_member_value(members, option)):
            node = members.get(method)
            if not isinstance(node, _FUNCTIONS):
                continue
            target = scanner.definition(
                name + "." + method, line=node.lineno, kind="method"
            )
            if target is not None:
                targets.append((target, "django_web_admin_callback"))
    return targets


def _registered_admin_targets(scanner, classes):
    targets = []
    for name in scanner.admins:
        if name not in classes or not _has_base(
            name,
            {"django.contrib.admin.ModelAdmin"},
            classes,
        ):
            continue
        definition, _, members, _ = classes[name]
        targets.append((definition, "django_web_admin_registration"))
        targets.extend(_admin_callbacks(scanner, name, members))
    return targets


def _admin_targets(activation, scanners, classes):
    targets = []
    for scanner in scanners.values():
        autodiscovered = (
            activation.admin_autodiscovery
            and scanner.module.rpartition(".")[0] in activation.apps
        )
        loaded = scanner.module in activation.loaded
        if scanner.path.name == "admin.py" and (autodiscovered or loaded):
            targets.extend(_registered_admin_targets(scanner, classes))
    return targets


def _template_directories(activation, scanners):
    directories = set()
    for scanner in activation.setting_views:
        directories.update(
            _configured_template_directories(scanner, activation.apps, scanners)
        )
    return directories


def _view_option_targets(scanner, name, members, classes):
    is_generic = _has_base(name, _DETAIL_VIEWS | _LIST_VIEWS, classes)
    options = _CBV_OPTIONS if is_generic else _TEMPLATE_OPTIONS
    targets = []
    for option in options & members.keys():
        definition = scanner.definition(name + "." + option, kind="variable")
        if definition is not None:
            targets.append((definition, "django_web_view_option"))
    return targets


def _view_model(name, project):
    if not _has_base(name, _DETAIL_VIEWS, project.classes):
        return None
    if name in project.view_overrides:
        return None
    if any(_has_member(name, member, project.classes) for member in _MODEL_OVERRIDES):
        # These hooks can change the object, aliases or template.
        return None
    _, _, members, bindings = project.classes[name]
    model = _qualified(_member_value(members, "model"), bindings)
    if model in project.classes and _has_base(
        model,
        {"django.db.models.Model"},
        project.classes,
    ):
        return model
    return None


def _view_template(model, classes, members):
    template = _literal(_member_value(members, "template_name"))
    if isinstance(template, str):
        return template
    if "template_name" in members:
        node = _member_value(members, "template_name")
        if not isinstance(node, ast.Constant) or node.value is not None:
            return None
    suffix = _literal(_member_value(members, "template_name_suffix"))
    if "template_name_suffix" in members and not isinstance(suffix, str):
        return None
    suffix = suffix if isinstance(suffix, str) else "_detail"
    app = model.rsplit(".", 2)[0].rsplit(".", 1)[-1]
    model_name = classes[model][0].simple_name.lower()
    return f"{app}/{model_name}{suffix}.html"


def _view_aliases(name, model_name, classes):
    members = classes[name][2]
    context = _literal(_member_value(members, "context_object_name"))
    aliases = {"object", context if isinstance(context, str) else model_name}
    if "context_object_name" in members and not isinstance(context, str):
        node = _member_value(members, "context_object_name")
        if not isinstance(node, ast.Constant) or node.value is not None:
            aliases.discard(model_name)
    if _has_member(name, "extra_context", classes):
        extra = _dict_values(_member_value(members, "extra_context"))
        if extra is None:
            return None
        aliases.difference_update(extra)
    return aliases


def _model_method_targets(scanner, model, methods, classes):
    targets = []
    for method in methods:
        node = classes[model][2].get(method)
        if not isinstance(node, _FUNCTIONS):
            continue
        definition = scanner.definition(
            model + "." + method, line=node.lineno, kind="method"
        )
        if definition is not None:
            targets.append((definition, "django_web_template_member"))
    return targets


def _view_targets(name, project):
    classes = project.classes
    if name not in classes or not _has_base(name, _DJANGO_VIEWS, classes):
        return []
    definition, _, members, _ = classes[name]
    module = project.index.modules[
        project.index._resolve_path(Path(definition.filename))
    ]
    scanner = project.scanners[module]
    targets = [(definition, "django_web_view_registration")]
    targets.extend(_view_option_targets(scanner, name, members, classes))
    model = _view_model(name, project)
    if model is None:
        return targets
    template = _view_template(model, classes, members)
    model_name = classes[model][0].simple_name.lower()
    aliases = _view_aliases(name, model_name, classes)
    if template is not None and aliases is not None:
        methods = _template_members(
            project.root,
            project.directories,
            template,
            aliases,
            project.exclude_folders,
        )
        targets.extend(_model_method_targets(scanner, model, methods, classes))
    return targets


def _function_view_targets(activation, scanners, index):
    """Read only the active source URL tables and their captured callbacks."""
    if not activation.url_roots:
        return []
    from skylos.deadcode.provider_method_liveness import _ProofLimit
    from skylos.deadcode.provider_source_dispatch import _DispatchValue, _SourceDispatch

    definitions = {
        id(item): item for items in index.all_by_name.values() for item in items
    }
    source = _SourceDispatch(definitions, index._backend_modules)
    changed = {
        name
        for module in activation.loaded
        if module in scanners
        for name in scanners[module].callback_mutations
    }

    def intact(name):
        return not any(
            name == item or name.startswith(item + ".") or item.startswith(name + ".")
            for item in changed
        )

    def module_tree(name):
        scanner = scanners.get(name)
        return (
            source.files[str(scanner.path.resolve())].tree
            if scanner is not None
            else None
        )

    found = {}
    visited = set()

    def visit_table(tree):
        if (
            tree in visited
            or tree in source.invalid_modules
            or not source.initialize(tree)
        ):
            return
        visited.add(tree)
        for value in source.environments.get(tree, {}).get("urlpatterns", []):
            visit_value(value)

    def visit_value(value):
        if not isinstance(value, _DispatchValue) or not source.usable(value):
            return
        if value.kind == "sequence":
            for members in value.fields.values():
                for item in members:
                    visit_value(item)
        elif value.kind == "urlinclude":
            visit_table(value.node)
        elif value.kind == "urlpattern":
            if not all(
                intact(guard.node)
                for guard in value.guards
                if isinstance(guard, _DispatchValue)
                and guard.kind == "django_registration"
            ):
                return
            for callback in value.fields.get("callback", []):
                if not isinstance(callback, _DispatchValue) or not source.usable(
                    callback
                ):
                    continue
                if callback.kind == "urlinclude":
                    visit_table(callback.node)
                    continue
                if callback.kind != "function":
                    continue
                node = callback.node
                if (
                    not isinstance(node, ast.FunctionDef)
                    or node.decorator_list
                    or source.deferred_body(node)
                ):
                    continue
                arguments = node.args
                if (
                    len([*arguments.posonlyargs, *arguments.args]) != 1
                    or arguments.defaults
                    or arguments.kwonlyargs
                    or arguments.vararg
                    or arguments.kwarg
                ):
                    # This proof models a request-only callback. It must not
                    # replace URL/default argument bindings with unknown data.
                    continue
                options = value.fields.get("kwargs", [])
                if (
                    len(options) != 1
                    or not isinstance(options[0], _DispatchValue)
                    or options[0].kind != "registry"
                    or options[0].fields
                    or not source.usable(options[0])
                ):
                    continue
                tree = source.context(node)
                if (
                    not isinstance(tree, ast.Module)
                    or tree in source.invalid_modules
                    or not source.initialize(tree)
                ):
                    continue
                location = (Path(source.file_for_node[node]), node.lineno)
                candidates = [
                    item
                    for item in index.all_by_location.get(location, ())
                    if item.type == "function"
                ]
                if len(candidates) == 1:
                    definition = candidates[0]
                    if (
                        intact(definition.name)
                        and index.class_or_function(definition.name) is definition
                    ):
                        found[id(definition)] = definition

    try:
        roots = [
            tree
            for name in activation.url_roots
            if (tree := module_tree(name)) is not None
        ]
        for tree in roots:
            source.initialize(tree)
        changed.update(
            name
            for scanner in scanners.values()
            if str(scanner.path.resolve()) in source.files
            and source.files[str(scanner.path.resolve())].tree in source.module_states
            for name in scanner.callback_mutations
        )
        for tree in roots:
            visit_table(tree)
    except (_ProofLimit, RecursionError):
        return []
    return [(item, "django_web_function_view") for item in found.values()]


def find_django_targets(
    index: Any,
    scanners: dict,
    classes: dict,
    root: Path,
    *,
    exclude_folders: Iterable[str] | None = None,
) -> list[tuple[Any, str]]:
    activation, targets = _settings_activation(scanners, classes)
    routes = _route_modules(activation, scanners)
    launchers = {scanner.module for scanner in scanners.values() if scanner.settings}
    activation.loaded = _loaded_modules(
        activation.settings | routes | launchers, scanners
    )
    targets.extend(_auth_backend_targets(activation, scanners, classes))
    targets.extend(_storage_backend_targets(activation, scanners, classes))
    targets.extend(_logging_factory_targets(activation, scanners, classes))
    targets.extend(_admin_targets(activation, scanners, classes))
    targets.extend(_function_view_targets(activation, scanners, index))
    project = _DjangoProject(
        index,
        scanners,
        classes,
        root,
        exclude_folders,
        _template_directories(activation, scanners),
        {name for scanner in scanners.values() for name in scanner.view_overrides},
    )
    for name in activation.routed:
        targets.extend(_view_targets(name, project))
    return targets
