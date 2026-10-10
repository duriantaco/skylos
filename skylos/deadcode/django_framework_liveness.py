"""Django startup, admin registration and routed generic-view contracts."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

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


@dataclass
class _Activation:
    settings: set
    apps: set = field(default_factory=set)
    admin_autodiscovery: bool = False
    url_roots: set = field(default_factory=set)
    routed: set = field(default_factory=set)
    loaded: set = field(default_factory=set)


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


def _setting_targets(scanner):
    targets = []
    for setting in scanner.values:
        if setting.isupper():
            definition = scanner.definition(
                scanner.module + "." + setting, kind="variable"
            )
            if definition is not None:
                targets.append((definition, "django_web_setting"))
    return targets


def _settings_activation(scanners, classes):
    settings = {name for scanner in scanners.values() for name in scanner.settings}
    activation = _Activation(settings)
    targets = []
    for name in settings:
        scanner = scanners.get(name)
        if scanner is None:
            continue
        targets.extend(_setting_targets(scanner))
        urlconf = _literal(scanner.values.get("ROOT_URLCONF"))
        if isinstance(urlconf, str):
            activation.url_roots.add(urlconf)
        configured = _member_names(scanner.values.get("INSTALLED_APPS"))
        activation.admin_autodiscovery |= bool(configured & _ADMIN_CONFIGS)
        apps = {_app_name(app, classes) for app in configured}
        activation.apps.update(app for app in apps if isinstance(app, str))
    return activation, targets


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
    for name in activation.settings:
        if name in scanners:
            directories.update(
                _configured_template_directories(
                    scanners[name], activation.apps, scanners
                )
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
    targets.extend(_admin_targets(activation, scanners, classes))
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
