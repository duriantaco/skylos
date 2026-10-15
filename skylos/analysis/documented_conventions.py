"""Django and Wagtail names the frameworks read by convention, not by reference.

Each rule follows the framework's documented behaviour and is gated on the
module (or project) importing the framework:

* ``Meta`` inner classes and their options: Django models/forms, DRF
  serializers, django-filter, Wagtail blocks and factory_boy all read
  ``class Meta`` through a metaclass.
* Wagtail attributes looked up by name on Page models, snippets, view sets,
  workflow tasks and the accessibility checker (Wagtail reference: Page,
  ``SnippetViewSet``/``ModelViewSet``, ``Task``, ``AccessibilityItem``).
* Parameters fixed by a documented hook signature: Wagtail page/preview/task
  methods, Django class-based-view handlers (``View.dispatch`` calls
  ``handler(request, *args, **kwargs)``), system checks
  (``app_configs``, ``**kwargs``), signal receivers (``sender``,
  ``**kwargs``), context processors (``request``), field/backend converters
  (``value``, ``expression``, ``connection``), ModelAdmin and inline hooks,
  and Widget/Field/Form hooks.
* Classes registered by a ``register*`` class decorator
  (``@register_setting``, ``@register_snippet``, ``@admin.register``) and
  Django models in an app's ``models`` module (the app registry loads them).
* UPPERCASE names in Django format files (``locale/<lang>/formats.py`` and
  ``FORMAT_MODULE_PATH`` packages), which ``get_format()`` reads with
  ``getattr``. Settings modules are not covered here: their liveness needs the
  proven ``DJANGO_SETTINGS_MODULE`` activation in ``web_framework_liveness``.

Template lookups are not matched by name here either: Django template
evidence is proof-based (a resolved view, template and model alias; see
``django_template_liveness``), and a project-wide name match would undo it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

WAGTAIL_CLASS_ATTRIBUTES = frozenset(
    {
        # Page
        "content_panels",
        "promote_panels",
        "settings_panels",
        "panels",
        "edit_handler",
        "search_fields",
        "api_fields",
        "graphql_fields",
        "template",
        "ajax_template",
        "subpage_types",
        "parent_page_types",
        "max_count",
        "max_count_per_parent",
        "page_description",
        "is_creatable",
        "show_in_menus_default",
        "preview_modes",
        "default_preview_mode",
        "context_object_name",
        "base_form_class",
        "password_required_template",
        "private_page_options",
        "exclude_fields_in_copy",
        "default_exclude_fields_in_copy",
        # Snippet / Model view sets
        "model",
        "icon",
        "menu_label",
        "menu_name",
        "menu_icon",
        "menu_order",
        "menu_item_is_registered",
        "add_to_admin_menu",
        "add_to_settings_menu",
        "exclude_from_explorer",
        "list_display",
        "list_filter",
        "list_export",
        "list_per_page",
        "export_filename",
        "export_headings",
        "search_backend_name",
        "ordering",
        "sort_order_field",
        "filterset_class",
        "form_fields",
        "exclude_form_fields",
        "inspect_view_enabled",
        "inspect_view_fields",
        "inspect_view_fields_exclude",
        "copy_view_enabled",
        "admin_url_namespace",
        "base_url_path",
        "url_prefix",
        "url_namespace",
        "template_prefix",
        "index_template_name",
        "index_results_template_name",
        "create_template_name",
        "edit_template_name",
        "delete_template_name",
        "history_template_name",
        "chooser_per_page",
        "items",
        "name",
        # Workflow tasks
        "task_state_class",
        # Accessibility checker (userbar AccessibilityItem)
        "axe_include",
        "axe_exclude",
        "axe_run_only",
        "axe_rules",
        "axe_custom_rules",
        "axe_custom_checks",
        "axe_messages",
        "axe_rules_options",
    }
)

WAGTAIL_HOOK_METHODS = frozenset(
    {
        # Page and PreviewableMixin
        "serve",
        "serve_preview",
        "get_context",
        "get_template",
        "get_preview_template",
        "get_preview_context",
        "route",
        "get_sitemap_urls",
        "get_url_parts",
        "get_admin_display_title",
        "can_create_at",
        "can_exist_under",
        "can_move_to",
        "get_cached_paths",
        "get_route_paths",
        "with_content_json",
        # Workflow Task
        "user_can_access_editor",
        "page_locked_for_user",
        "locked_for_user",
        "user_can_lock",
        "user_can_unlock",
        "get_actions",
        "get_task_states_user_can_moderate",
        "on_action",
        "get_form_for_action",
        "get_template_for_action",
        "start",
        # StreamField blocks
        "get_form_context",
        "render",
        "render_basic",
        "get_api_representation",
        "to_python",
        "get_prep_value",
        "bulk_to_python",
        "clean",
        "get_searchable_content",
    }
)

DJANGO_VIEW_HANDLERS = frozenset(
    {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "trace",
        "dispatch",
        "setup",
        "http_method_not_allowed",
    }
)

# (base-name suffixes, method-name prefixes or exact names) for Django hooks.
_DJANGO_HOOKS_BY_BASE_SUFFIX = (
    (
        ("Admin", "Inline"),
        (
            "get_",
            "has_",
            "save_",
            "delete_",
            "response_",
            "formfield_for_",
            "lookup_allowed",
            "log_",
            "message_user",
            "render_",
            "changelist_view",
            "changeform_view",
            "add_view",
            "change_view",
            "delete_view",
            "history_view",
        ),
    ),
    (
        ("Widget",),
        (
            "value_from_datadict",
            "value_omitted_from_data",
            "get_context",
            "render",
            "format_value",
            "id_for_label",
            "use_required_attribute",
        ),
    ),
    (
        ("Field",),
        (
            "clean",
            "to_python",
            "validate",
            "run_validators",
            "prepare_value",
            "bound_data",
            "has_changed",
            "widget_attrs",
            "from_db_value",
            "get_prep_value",
            "get_db_prep_value",
            "contribute_to_class",
            "deconstruct",
        ),
    ),
    (
        ("Form", "FormSet"),
        ("clean", "save", "get_context", "add_prefix", "full_clean"),
    ),
)

_REGISTER_DECORATOR_RE = re.compile(r"(?:^|\.)register\w*$")
_CONVERTER_RE = re.compile(r"^convert_\w+_value$")
_UPPERCASE_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_MODEL_BASE_SUFFIXES = (
    "Model",
    "Page",
    "Orderable",
    "Task",
    "Setting",
    "FormField",
)


def _owner(name: str) -> str:
    return name.rsplit(".", 1)[0] if "." in name else ""


def _detected(framework: Any) -> set[str]:
    return set(getattr(framework, "detected_frameworks", None) or ())


def _project_uses_django(analyzer: Any) -> bool:
    cached = getattr(analyzer, "_documented_conventions_django", None)
    if cached is None:
        cached = any(
            getattr(definition, "type", None) == "import"
            and str(getattr(definition, "name", "")).split(".", 1)[0] == "django"
            for definition in getattr(analyzer, "defs", {}).values()
        )
        try:
            analyzer._documented_conventions_django = cached
        except AttributeError:
            pass
    return cached


def _class_bases(class_simple_name: str, framework: Any) -> tuple[str, ...]:
    node = (getattr(framework, "class_defs", None) or {}).get(class_simple_name)
    names = []
    for base in getattr(node, "bases", ()) or ():
        if hasattr(base, "id"):
            names.append(base.id)
        elif hasattr(base, "attr"):
            names.append(base.attr)
    return tuple(names)


def _is_format_module(path: Path) -> bool:
    """A Django format file: ``locale/<lang>/formats.py`` or a
    ``FORMAT_MODULE_PATH`` package (``mysite/formats/en/formats.py``)."""
    return path.name == "formats.py" and (
        "locale" in path.parts or "formats" in path.parts[:-1]
    )


def _parameter_reason(def_obj: Any, analyzer: Any, framework: Any) -> str | None:
    owner = _owner(def_obj.name)
    method = owner.rsplit(".", 1)[-1]
    class_name = _owner(owner).rsplit(".", 1)[-1]
    detected = _detected(framework)
    owner_def = getattr(analyzer, "defs", {}).get(owner)
    is_method = getattr(owner_def, "type", None) == "method"

    if "wagtail" in detected and method in WAGTAIL_HOOK_METHODS:
        return "Wagtail hook signature"
    if "django" not in detected:
        return None
    defs = getattr(analyzer, "defs", {})
    parameter = def_obj.simple_name
    # System checks: ``def check(app_configs, **kwargs)``, decorated or
    # registered with ``checks.register(check)``.
    if f"{owner}.app_configs" in defs and parameter in {
        "app_configs",
        "kwargs",
        "databases",
    }:
        return "Django system check signature"
    # Signal receivers: ``def receiver(sender, **kwargs)``.
    if f"{owner}.sender" in defs and parameter in {"sender", "kwargs"}:
        return "Django signal receiver signature"
    # Context processors take the request, used or not.
    if parameter == "request" and Path(str(def_obj.filename)).name == (
        "context_processors.py"
    ):
        return "Django context processor signature"
    # ``Field.from_db_value`` and backend ``convert_*_value`` converters are
    # called as ``(value, expression, connection)``.
    if (method == "from_db_value" or _CONVERTER_RE.match(method)) and parameter in {
        "value",
        "expression",
        "connection",
    }:
        return "Django converter signature"
    if is_method and method in DJANGO_VIEW_HANDLERS:
        return "Django view handler signature"
    decorators = getattr(owner_def, "decorators", None) or ()
    if any(
        str(decorator).rsplit(".", 1)[-1] == "register" for decorator in decorators
    ) and parameter in {"app_configs", "kwargs", "databases"}:
        return "Django system check signature"
    if not is_method:
        return None
    bases = _class_bases(class_name, framework)
    for suffixes, hooks in _DJANGO_HOOKS_BY_BASE_SUFFIX:
        if not any(base.endswith(suffixes) for base in bases):
            continue
        if any(
            method == hook or (hook.endswith("_") and method.startswith(hook))
            for hook in hooks
        ):
            return "Django hook signature"
    return None


def _class_reason(def_obj: Any, analyzer: Any, framework: Any) -> str | None:
    if def_obj.simple_name == "Meta" and "." in def_obj.name:
        return "Meta options class"
    decorators = getattr(def_obj, "decorators", None) or ()
    if any(_REGISTER_DECORATOR_RE.search(str(d)) for d in decorators):
        return "registered by a class decorator"
    path = Path(str(def_obj.filename))
    in_models_module = path.name == "models.py" or "models" in path.parent.parts[-1:]
    if not in_models_module or not _project_uses_django(analyzer):
        return None
    bases = _class_bases(def_obj.simple_name, framework)
    declares_fields = any(
        field.startswith(def_obj.name + ".")
        for field in getattr(framework, "orm_declarative_fields", ()) or ()
    )
    if declares_fields or any(base.endswith(_MODEL_BASE_SUFFIXES) for base in bases):
        return "Django model (loaded by the app registry)"
    return None


def documented_convention_reason(
    def_obj: Any, analyzer: Any, framework: Any
) -> str | None:
    """Why a framework uses ``def_obj`` by documented convention, or None."""
    kind = getattr(def_obj, "type", None)
    if kind == "parameter":
        return _parameter_reason(def_obj, analyzer, framework)
    if kind == "class":
        return _class_reason(def_obj, analyzer, framework)
    if kind != "variable":
        return None

    owner = _owner(def_obj.name)
    owner_simple = owner.rsplit(".", 1)[-1]
    if owner_simple == "Meta":
        return "Meta option read by the framework"
    owner_def = getattr(analyzer, "defs", {}).get(owner)
    in_class = getattr(owner_def, "type", None) == "class"
    if (
        in_class
        and "wagtail" in _detected(framework)
        and def_obj.simple_name in WAGTAIL_CLASS_ATTRIBUTES
    ):
        return "Wagtail attribute read by name"
    if (
        not in_class
        and _UPPERCASE_NAME_RE.match(def_obj.simple_name)
        and _is_format_module(Path(str(def_obj.filename)))
        and _project_uses_django(analyzer)
    ):
        return "Django format read by get_format()"
    return None
