import ast
import re
from typing import Any, Optional, NamedTuple
from skylos.constants import PENALTIES, get_non_library_dir_kind, is_test_path
from skylos.config import is_whitelisted
from skylos.deadcode.config_entrypoints import configured_entrypoint_reason
from skylos.deadcode._reachability_bindings import bound_names
from skylos.deadcode.django_hook_proofs import (
    django_clean_field,
    django_hook_ancestry,
    django_method_hook,
)
from skylos.analysis.known_patterns import (
    HARD_ENTRYPOINTS,
    PYTEST_HOOKS,
    UNITTEST_METHODS,
    DJANGO_MODEL_METHODS,
    DJANGO_MODEL_BASES,
    DJANGO_VIEW_METHODS,
    DJANGO_VIEW_BASES,
    DJANGO_ADMIN_METHODS,
    DJANGO_ADMIN_BASES,
    DJANGO_FORM_METHODS,
    DJANGO_FORM_BASES,
    DJANGO_COMMAND_METHODS,
    DJANGO_COMMAND_BASES,
    DJANGO_APPCONFIG_METHODS,
    DJANGO_APPCONFIG_BASES,
    DJANGO_MIDDLEWARE_METHODS,
    DJANGO_MIDDLEWARE_BASES,
    DRF_VIEWSET_METHODS,
    DRF_VIEWSET_BASES,
    DRF_SERIALIZER_METHODS,
    DRF_SERIALIZER_BASES,
    DRF_PERMISSION_METHODS,
    DRF_PERMISSION_BASES,
    DOCUTILS_DIRECTIVE_ATTRS,
    STARLETTE_MIDDLEWARE_METHODS,
    STARLETTE_MIDDLEWARE_BASES,
    STARLETTE_ENDPOINT_METHODS,
    STARLETTE_ENDPOINT_BASES,
    FLASK_RESTFUL_METHODS,
    FLASK_RESTFUL_BASES,
    TORNADO_HANDLER_METHODS,
    TORNADO_HANDLER_BASES,
    CELERY_TASK_METHODS,
    CELERY_TASK_BASES,
    CLICK_COMMAND_METHODS,
    CLICK_COMMAND_BASES,
    PYDANTIC_MODEL_METHODS,
    PYDANTIC_MODEL_BASES,
    SOFT_PATTERNS,
    matches_pattern,
    has_base_class,
    PROTOCOL_METHOD_TO_BASES,
    SQLALCHEMY_TYPE_ATTRS,
    SQLALCHEMY_TYPE_BASES,
    base_class_name,
)
from skylos.analysis.documented_conventions import documented_convention_reason
from skylos.analysis.external_bases import (
    external_member_owner,
    external_override_owner,
    project_class_graph,
)
from skylos.visitors.framework_aware import detect_framework_usage
from pathlib import Path

_FOLDER_ROLE_REASONS = {
    "test": "test-only path",
    "example": "standalone example path",
    "benchmark": "benchmark entrypoint path",
}

_ADMIN_ATTRS = {
    "list_display",
    "list_display_links",
    "list_filter",
    "list_select_related",
    "list_per_page",
    "list_max_show_all",
    "list_editable",
    "search_fields",
    "search_help_text",
    "date_hierarchy",
    "ordering",
    "readonly_fields",
    "fieldsets",
    "fields",
    "exclude",
    "filter_horizontal",
    "filter_vertical",
    "radio_fields",
    "prepopulated_fields",
    "raw_id_fields",
    "autocomplete_fields",
    "actions",
    "actions_on_top",
    "actions_on_bottom",
    "inlines",
    "form",
    "model",
    "extra",
    "max_num",
    "min_num",
    "can_delete",
    "fk_name",
    "formset",
    "verbose_name",
    "verbose_name_plural",
    # Remaining documented ModelAdmin / InlineModelAdmin options:
    # https://docs.djangoproject.com/en/stable/ref/contrib/admin/#modeladmin-options
    # https://docs.djangoproject.com/en/stable/ref/contrib/admin/#inlinemodeladmin-options
    "actions_selection_counter",
    "empty_value_display",
    "formfield_overrides",
    "paginator",
    "preserve_filters",
    "save_as",
    "save_as_continue",
    "save_on_top",
    "show_facets",
    "show_full_result_count",
    "sortable_by",
    "view_on_site",
    "add_form_template",
    "change_form_template",
    "change_list_template",
    "delete_confirmation_template",
    "delete_selected_confirmation_template",
    "object_history_template",
    "popup_response_template",
    "classes",
    "show_change_link",
}

_META_ATTRS = {
    # ModelForm / DRF / django-filter Meta options
    "widgets",
    "labels",
    "help_texts",
    "error_messages",
    "field_classes",
    "localized_fields",
    "formfield_callback",
    "read_only_fields",
    "extra_kwargs",
    "depth",
    "list_serializer_class",
    # Model Meta options
    "base_manager_name",
    "order_with_respect_to",
    "select_on_save",
    "required_db_features",
    "required_db_vendor",
    "db_table_comment",
    "db_tablespace",
    "ordering",
    "verbose_name",
    "verbose_name_plural",
    "db_table",
    "abstract",
    "app_label",
    "proxy",
    "unique_together",
    "index_together",
    "indexes",
    "constraints",
    "permissions",
    "default_permissions",
    "default_related_name",
    "get_latest_by",
    "managed",
    "default_manager_name",
    "model",
    "fields",
    "exclude",
    "read_only_fields",
    "extra_kwargs",
    "depth",
    "filter_overrides",
}

_DRF_VIEW_ATTRS = {
    "serializer_class",
    "permission_classes",
    "authentication_classes",
    "throttle_classes",
    "pagination_class",
    "filter_backends",
    "filterset_class",
    "filterset_fields",
    "queryset",
    "lookup_field",
    "lookup_url_kwarg",
    # ScopedRateThrottle reads ``view.throttle_scope``:
    # https://www.django-rest-framework.org/api-guide/throttling/#scopedratethrottle
    "throttle_scope",
    # View.dispatch and the DRF routers honour ``http_method_names``:
    # https://docs.djangoproject.com/en/stable/ref/class-based-views/base/#django.views.generic.base.View.http_method_names
    "http_method_names",
}

_MIGRATION_ATTRS = {
    "initial",
    "dependencies",
    "operations",
    "replaces",
    "run_before",
    "atomic",
}

# Class attributes a framework reads from a subclass, keyed by base name.
_FRAMEWORK_CLASS_ATTRS = {
    # DRF pagination classes are configured by settings strings.
    "PageNumberPagination": {
        "page_size",
        "page_query_param",
        "page_size_query_param",
        "max_page_size",
        "last_page_strings",
        "django_paginator_class",
        "template",
        "invalid_page_message",
    },
    "LimitOffsetPagination": {
        "default_limit",
        "limit_query_param",
        "offset_query_param",
        "max_limit",
        "template",
    },
    "CursorPagination": {
        "page_size",
        "cursor_query_param",
        "ordering",
        "page_size_query_param",
        "max_page_size",
        "template",
        "offset_cutoff",
    },
    # DRF builds the error response from these.
    "APIException": {"status_code", "default_detail", "default_code"},
    # drf-spectacular extensions register themselves by subclassing.
    "OpenApiAuthenticationExtension": {
        "target_class",
        "name",
        "match_subclasses",
        "priority",
    },
    "OpenApiSerializerExtension": {"target_class", "match_subclasses", "priority"},
    "OpenApiViewExtension": {"target_class", "match_subclasses", "priority"},
    "OpenApiFilterExtension": {"target_class", "match_subclasses", "priority"},
    "OpenApiSerializerFieldExtension": {"target_class", "match_subclasses", "priority"},
}
_FRAMEWORK_SELF_REGISTERING_BASES = {
    "OpenApiAuthenticationExtension",
    "OpenApiSerializerExtension",
    "OpenApiViewExtension",
    "OpenApiFilterExtension",
    "OpenApiSerializerFieldExtension",
}

_ALEMBIC_MODULE_ATTRS = {
    "revision",
    "down_revision",
    "branch_labels",
    "depends_on",
}

_DJANGO_MODULE_VARS = {
    "urlpatterns",
    "app_name",
    "default_app_config",
}

_DJANGO_URLCONF_HANDLER_VARS = {
    "handler400",
    "handler403",
    "handler404",
    "handler500",
}

_GUNICORN_CONFIG_SETTINGS = {
    "access_log_format",
    "accesslog",
    "backlog",
    "bind",
    "ca_certs",
    "capture_output",
    "cert_reqs",
    "certfile",
    "chdir",
    "check_config",
    "child_exit",
    "ciphers",
    "config",
    "control_socket_disable",
    "daemon",
    "default_proc_name",
    "disable_redirect_access_to_syslog",
    "do_handshake_on_connect",
    "enable_stdio_inheritance",
    "env",
    "errorlog",
    "forwarded_allow_ips",
    "graceful_timeout",
    "group",
    "initgroups",
    "keepalive",
    "keyfile",
    "limit_request_field_size",
    "limit_request_fields",
    "limit_request_line",
    "logconfig",
    "logconfig_dict",
    "logconfig_json",
    "logger_class",
    "loglevel",
    "max_requests",
    "max_requests_jitter",
    "nworkers_changed",
    "on_exit",
    "on_reload",
    "on_starting",
    "paste",
    "pidfile",
    "post_fork",
    "post_request",
    "post_worker_init",
    "pre_exec",
    "pre_fork",
    "pre_request",
    "preload_app",
    "proc_name",
    "pythonpath",
    "raw_env",
    "reload",
    "reload_engine",
    "reload_extra_files",
    "reuse_port",
    "secure_scheme_headers",
    "sendfile",
    "spew",
    "ssl_context",
    "statsd_host",
    "statsd_prefix",
    "strip_header_spaces",
    "suppress_ragged_eofs",
    "threads",
    "timeout",
    "tmp_upload_dir",
    "umask",
    "user",
    "when_ready",
    "worker_abort",
    "worker_class",
    "worker_connections",
    "worker_exit",
    "worker_int",
    "worker_tmp_dir",
    "workers",
    "wsgi_app",
}

_GUNICORN_CONFIG_HOOKS = {
    "child_exit",
    "nworkers_changed",
    "on_exit",
    "on_reload",
    "on_starting",
    "post_fork",
    "post_request",
    "post_worker_init",
    "pre_exec",
    "pre_fork",
    "pre_request",
    "ssl_context",
    "when_ready",
    "worker_abort",
    "worker_exit",
    "worker_int",
}

_DJANGO_COMMAND_ATTRS = {
    "help",
    "missing_args_message",
    "requires_migrations_checks",
    "requires_system_checks",
    "stealth_options",
    "suppressed_base_arguments",
    "output_transaction",
}

_DRF_BACKEND_METHODS = {
    "filter_queryset",
    "get_schema_fields",
    "get_schema_operation_parameters",
}

_DRF_BACKEND_BASES = {
    "BaseFilterBackend",
    "FilterSet",
    "BaseThrottle",
    "BasePermission",
}

_PYTEST_HOOKS_LOCAL = {
    "pytest_configure",
    "pytest_unconfigure",
    "pytest_addoption",
}

_DJANGO_TEST_BASES = {
    "TestCase",
    "SimpleTestCase",
    "TransactionTestCase",
    "LiveServerTestCase",
    "StaticLiveServerTestCase",
}

_FUTURE_IMPORTS = {
    "annotations",
    "absolute_import",
    "division",
    "print_function",
    "unicode_literals",
    "generator_stop",
}

_NOQA_DEAD_CODE_CODES_BY_TYPE = {
    "import": {"F401"},
    "variable": {"F841"},
    "constant": {"F841"},
}


def _suppress(def_obj, reason=None, code=None, folder_role=None):
    def_obj.confidence = 0
    if reason:
        def_obj.skip_reason = reason
    if code:
        def_obj.suppression_code = code
    if folder_role:
        def_obj.folder_role = folder_role
    return True


def _class_base_names(simple_name, framework) -> set[str]:
    class_defs = getattr(framework, "class_defs", {})
    cls_node = class_defs.get(simple_name)
    if cls_node is None:
        return set()

    base_names: set[str] = set()
    for base in getattr(cls_node, "bases", []):
        name = base_class_name(base)
        if name:
            base_names.add(name)
    return base_names


def _class_declares_attr(def_obj, attr_name: str) -> bool:
    node = getattr(def_obj, "node", None)
    if not isinstance(node, ast.ClassDef):
        return False

    for item in node.body:
        targets = []
        if isinstance(item, ast.Assign):
            targets.extend(item.targets)
        elif isinstance(item, ast.AnnAssign):
            targets.append(item.target)
        else:
            continue

        for target in targets:
            if isinstance(target, ast.Name) and target.id == attr_name:
                return True
    return False


def _name_parent_has_base(def_obj, required_bases, framework) -> bool:
    parts = str(getattr(def_obj, "name", "")).split(".")
    if len(parts) < 2:
        return False

    class_defs = getattr(framework, "class_defs", {})
    for part in parts[:-1]:
        cls_node = class_defs.get(part)
        if cls_node is None:
            continue
        for base in getattr(cls_node, "bases", []):
            base_name = getattr(base, "id", None) or getattr(base, "attr", None)
            if base_name in required_bases:
                return True
    return False


def _is_alembic_revision_path(filename: str) -> bool:
    normalized = filename.replace("\\", "/")
    return "/versions/" in normalized and normalized.endswith(".py")


def _coerce_line_set(value, fallback) -> set[int]:
    if value is None or isinstance(value, (str, bytes)):
        return {fallback}
    try:
        return {int(line) for line in value}
    except (TypeError, ValueError):
        return {fallback}


def _check_inline_ignore(def_obj, visitor):
    suppression_lines = _coerce_line_set(
        getattr(def_obj, "suppression_lines", None),
        def_obj.line,
    )
    ignore_lines = _coerce_line_set(getattr(visitor, "ignore_lines", None), -1)
    if suppression_lines & ignore_lines:
        return _suppress(def_obj, "inline ignore comment")
    noqa_codes_by_line = getattr(visitor, "noqa_codes_by_line", None) or {}
    if not isinstance(noqa_codes_by_line, dict):
        noqa_codes_by_line = {}
    noqa_codes = None
    for line in sorted(suppression_lines):
        if line in noqa_codes_by_line:
            noqa_codes = noqa_codes_by_line[line]
            break
    if noqa_codes is None:
        return None
    if not noqa_codes:
        return _suppress(def_obj, "inline ignore comment", code="noqa")
    matching_codes = _NOQA_DEAD_CODE_CODES_BY_TYPE.get(def_obj.type, set())
    if noqa_codes & matching_codes:
        return _suppress(
            def_obj,
            "inline ignore comment",
            code="noqa:" + ",".join(sorted(noqa_codes & matching_codes)),
        )
    return None


def _check_docs_path(def_obj):
    fname = str(def_obj.filename)
    if (
        def_obj.type == "variable"
        and fname.endswith("conf.py")
        and ("/docs/" in fname or "/doc/" in fname)
    ):
        return _suppress(def_obj)

    if "/docs/" in fname or "/doc/" in fname:
        if "_theme" in fname or "theme_support" in fname:
            return _suppress(def_obj)

    return None


def _check_version_conditional(def_obj, framework):
    if getattr(framework, "version_conditional_lines", None):
        if def_obj.line in framework.version_conditional_lines:
            return -60
    return None


def _check_conditional_import(def_obj):
    if def_obj.type == "import" and getattr(def_obj, "conditional_import", False):
        why_reduced = getattr(def_obj, "why_confidence_reduced", None)
        if isinstance(why_reduced, list):
            why_reduced.append("conditional_import_fallback")
        return "cap_40"
    return None


def _check_config_whitelist(def_obj, cfg):
    if not cfg:
        return None
    is_wl, reason, conf_reduction = is_whitelisted(
        def_obj.simple_name, str(def_obj.filename), cfg
    )
    if is_wl:
        return _suppress(def_obj, reason)
    if conf_reduction > 0:
        return -conf_reduction
    return None


def _check_configured_entrypoint(def_obj, analyzer, cfg):
    reason = configured_entrypoint_reason(def_obj, analyzer, cfg)
    if reason:
        return _suppress(def_obj, reason, code="configured_entrypoint")
    return None


def _check_hard_entrypoint(def_obj):
    if def_obj.simple_name in HARD_ENTRYPOINTS:
        if Path(str(def_obj.filename)).name == "__main__.py":
            return _suppress(def_obj, "__main__ entrypoint")
    return None


def _check_non_library_path(def_obj, analyzer, cfg):
    extra_dirs = (cfg or {}).get("non_library_dirs", None)
    non_library_kind = get_non_library_dir_kind(
        def_obj.filename,
        getattr(analyzer, "_project_root", None),
        extra_dirs=extra_dirs,
    )
    if non_library_kind and def_obj.type in (
        "function",
        "method",
        "class",
        "import",
        "variable",
        "parameter",
    ):
        reason = _FOLDER_ROLE_REASONS.get(non_library_kind, f"{non_library_kind} path")
        return _suppress(
            def_obj,
            reason,
            code="non_library_path",
            folder_role=non_library_kind,
        )
    return None


def _check_framework_decorations(def_obj, framework):
    if def_obj.type == "parameter" and def_obj.line in getattr(
        framework, "fastapi_candidate_lines", ()
    ):
        return None
    if def_obj.line in getattr(framework, "framework_decorated_lines", set()):
        return _suppress(def_obj)
    return None


def _check_pytest_unittest(def_obj, framework):
    simple_name = def_obj.simple_name
    detected = getattr(framework, "detected_frameworks", set())
    filename = str(def_obj.filename)

    if simple_name in PYTEST_HOOKS:
        if "pytest" in detected or "conftest" in filename:
            return _suppress(def_obj)

    if def_obj.type == "parameter" and "." in def_obj.name:
        parts = def_obj.name.split(".")
        hook_name = parts[-2] if len(parts) >= 2 else ""
        if hook_name in PYTEST_HOOKS:
            if "pytest" in detected or "conftest" in filename:
                return _suppress(def_obj, "pytest hook parameter")

    if simple_name in UNITTEST_METHODS:
        if has_base_class(def_obj, {"TestCase"}, framework):
            return _suppress(def_obj)

    return None


def _check_alembic_migration(def_obj):
    if not _is_alembic_revision_path(str(def_obj.filename)):
        return None

    if def_obj.type == "function" and def_obj.simple_name in {"upgrade", "downgrade"}:
        return _suppress(def_obj, "Alembic migration lifecycle function")

    if def_obj.type == "variable" and def_obj.simple_name in _ALEMBIC_MODULE_ATTRS:
        return _suppress(def_obj, "Alembic revision metadata")

    return None


def _is_likely_module_level(def_obj):
    parts = str(def_obj.name).split(".")
    if len(parts) < 2:
        return True
    owner = parts[-2]
    return not (owner and owner[0].isupper())


def _parent_simple_name(def_obj):
    if "." not in str(def_obj.name):
        return None
    parent = str(def_obj.name).rsplit(".", 1)[0]
    return parent.split(".")[-1]


def _check_django_path_converter(def_obj, analyzer, framework):
    converter_classes = getattr(analyzer, "_global_django_path_converter_classes", set())
    if not converter_classes:
        return None
    if def_obj.type != "class" and not (
        def_obj.type == "variable" and def_obj.simple_name == "regex"
    ):
        return None
    key = str(Path(def_obj.filename).resolve()), def_obj.name
    if key not in converter_classes:
        return None
    if def_obj.type == "class":
        return _suppress(def_obj, "Django path converter class")
    return _suppress(def_obj, "Django path converter regex")


def _is_gunicorn_config_path(filename):
    normalized = (
        Path(str(filename))
        .stem.lower()
        .replace(".", "_")
        .replace("-", "_")
    )
    parts = set(filter(None, normalized.split("_")))
    if normalized == "gunicorn":
        return True
    return "gunicorn" in parts and bool(parts & {"conf", "config"})


def _check_gunicorn_config(def_obj):
    if not _is_gunicorn_config_path(def_obj.filename):
        return None
    if not _is_likely_module_level(def_obj):
        return None

    simple_name = def_obj.simple_name
    if def_obj.type == "variable" and simple_name in _GUNICORN_CONFIG_SETTINGS:
        return _suppress(def_obj, "Gunicorn config setting")
    if def_obj.type == "function" and simple_name in _GUNICORN_CONFIG_HOOKS:
        return _suppress(def_obj, "Gunicorn lifecycle hook")
    return None


def _check_django_drf_structural(def_obj, framework, analyzer=None):
    detected = getattr(framework, "detected_frameworks", set())
    simple_name = def_obj.simple_name
    _DJANGO_DRF_FRAMEWORKS = {
        "django",
        "rest_framework",
        "django_filters",
        "marshmallow",
    }

    if def_obj.type == "class" and simple_name == "Meta":
        if "." in def_obj.name and detected & _DJANGO_DRF_FRAMEWORKS:
            return _suppress(def_obj)

    if _is_django_migration_class(def_obj, framework):
        return _suppress(def_obj, "Django migration (loaded by the migration executor)")

    if (
        def_obj.type == "variable"
        and simple_name in _MIGRATION_ATTRS
        and _name_parent_has_base(def_obj, {"Migration"}, framework)
    ):
        return _suppress(def_obj, "Django migration attribute")

    if def_obj.type == "variable" and "." in def_obj.name:
        parent = def_obj.name.rsplit(".", 1)[0].split(".")[-1]
        for base in _class_base_names(parent, framework):
            if simple_name in _FRAMEWORK_CLASS_ATTRS.get(base, ()):
                family = None
                if base in DJANGO_MODEL_BASES:
                    family = "model"
                elif base in DJANGO_FORM_BASES:
                    family = "form"
                elif base in DJANGO_COMMAND_BASES:
                    family = "command"
                if family is not None and django_hook_ancestry(
                    def_obj, analyzer, family
                ) is False:
                    continue
                return _suppress(def_obj, f"{base} attribute read by the framework")

    if def_obj.type == "class" and (
        _class_base_names(simple_name, framework) & _FRAMEWORK_SELF_REGISTERING_BASES
    ):
        return _suppress(def_obj, "Framework extension registered by subclassing")

    if def_obj.type == "variable" and simple_name in _META_ATTRS:
        if "." in def_obj.name and "Meta" in def_obj.name:
            return _suppress(def_obj)

    if def_obj.type == "variable" and simple_name in _DJANGO_MODULE_VARS:
        return _suppress(def_obj)

    if (
        def_obj.type == "variable"
        and simple_name in _DJANGO_URLCONF_HANDLER_VARS
        and "django" in detected
        and _is_likely_module_level(def_obj)
    ):
        return _suppress(def_obj, "Django URLconf error handler")

    if def_obj.type == "variable" and simple_name in _MIGRATION_ATTRS:
        fname = str(def_obj.filename)
        if "/migrations/" in fname or "\\migrations\\" in fname:
            return _suppress(def_obj)

    if def_obj.type == "variable" and simple_name in _DJANGO_COMMAND_ATTRS:
        status = django_hook_ancestry(def_obj, analyzer, "command")
        if status is True or (
            status is None
            and _name_parent_has_base(def_obj, DJANGO_COMMAND_BASES, framework)
        ):
            return _suppress(def_obj, "Django management command attribute")

    if def_obj.type == "class":
        class_bases = _class_base_names(simple_name, framework)

        proven_families = {
            family: django_hook_ancestry(def_obj, analyzer, family)
            for family in ("model", "form", "command")
        }
        if True in proven_families.values():
            return _suppress(def_obj, "Django framework class")

        legacy_bases = DJANGO_VIEW_BASES | DJANGO_ADMIN_BASES | DJANGO_APPCONFIG_BASES | DJANGO_MIDDLEWARE_BASES
        uncertain_bases = set()
        for family, bases in (
            ("model", DJANGO_MODEL_BASES),
            ("form", DJANGO_FORM_BASES),
            ("command", DJANGO_COMMAND_BASES),
        ):
            if proven_families[family] is None:
                uncertain_bases.update(bases)

        if "django" in detected and class_bases.intersection(
            legacy_bases | uncertain_bases
        ):
            return _suppress(def_obj, "Django framework class")

        if "rest_framework" in detected and class_bases.intersection(
            DRF_VIEWSET_BASES | DRF_SERIALIZER_BASES | DRF_PERMISSION_BASES
        ):
            return _suppress(def_obj, "DRF framework class")

        if "marshmallow" in detected and "Schema" in class_bases:
            return _suppress(def_obj, "Marshmallow schema")

        if "sqlalchemy" in detected and simple_name in getattr(
            framework, "orm_model_classes", set()
        ):
            if not _class_declares_attr(def_obj, "__tablename__"):
                return _suppress(def_obj, "ORM declarative base class")

        if "celery" in detected and class_bases.intersection(CELERY_TASK_BASES):
            return _suppress(def_obj, "Celery task class")

        if "click" in detected and class_bases.intersection(CLICK_COMMAND_BASES):
            return _suppress(def_obj, "Click command class")

    return None


def _is_django_migration_class(def_obj, framework):
    """``class Migration(migrations.Migration)`` is loaded by name by Django's
    migration loader, never referenced from project code."""
    if def_obj.type != "class" or def_obj.simple_name != "Migration":
        return False
    if "Migration" not in _class_base_names("Migration", framework):
        return False
    detected = getattr(framework, "detected_frameworks", set())
    filename = str(def_obj.filename).replace("\\", "/")
    return "django" in detected or "/migrations/" in filename


def _check_django_methods(def_obj, framework, analyzer=None):
    detected = getattr(framework, "detected_frameworks", set())
    simple_name = def_obj.simple_name

    _DJANGO_CHECKS = [
        (DJANGO_MODEL_METHODS, DJANGO_MODEL_BASES, "model"),
        (DJANGO_VIEW_METHODS, DJANGO_VIEW_BASES, None),
        (DJANGO_ADMIN_METHODS, DJANGO_ADMIN_BASES, None),
        (DJANGO_FORM_METHODS, DJANGO_FORM_BASES, "form"),
        (DJANGO_COMMAND_METHODS, DJANGO_COMMAND_BASES, "command"),
        (DJANGO_APPCONFIG_METHODS, DJANGO_APPCONFIG_BASES, None),
        (DJANGO_MIDDLEWARE_METHODS, DJANGO_MIDDLEWARE_BASES, None),
    ]

    for methods, bases, family in _DJANGO_CHECKS:
        if simple_name not in methods or def_obj.type != "method":
            continue
        status = None
        if family is not None:
            status = django_method_hook(def_obj, analyzer)
        if status is True:
            return _suppress(def_obj, "Django framework hook")
        if status is False:
            continue
        if "django" in detected and has_base_class(def_obj, bases, framework):
            return _suppress(def_obj)

    if def_obj.type == "method" and simple_name.startswith("clean_"):
        status = django_hook_ancestry(def_obj, analyzer, "form")
        if status is True:
            if django_clean_field(def_obj, analyzer) is not False:
                return _suppress(def_obj, "Django form field cleaning hook")
        elif status is None and "django" in detected and has_base_class(
            def_obj, DJANGO_FORM_BASES, framework
        ):
            return _suppress(def_obj)

    if def_obj.type == "parameter" and "." in def_obj.name:
        parts = def_obj.name.split(".")
        parent_method = parts[-2] if len(parts) >= 2 else ""
        if parent_method in DJANGO_COMMAND_METHODS:
            status = django_hook_ancestry(def_obj, analyzer, "command")
            if status is True:
                return _suppress(def_obj, "Django management command parameter")
            if status is None and "django" in detected and _name_parent_has_base(
                def_obj, DJANGO_COMMAND_BASES, framework
            ):
                return _suppress(def_obj, "Django management command parameter")

    if "django" not in detected:
        return None

    if def_obj.type == "variable" and simple_name in _ADMIN_ATTRS:
        if "." in def_obj.name:
            parent = def_obj.name.rsplit(".", 1)[0].split(".")[-1]
            class_defs = getattr(framework, "class_defs", {})
            if parent in class_defs:
                cls_node = class_defs[parent]
                for base in getattr(cls_node, "bases", []):
                    base_name = getattr(base, "id", None) or getattr(base, "attr", None)
                    if base_name in DJANGO_ADMIN_BASES:
                        return _suppress(def_obj)
            # ModelAdmin options also reach admin classes through project
            # base classes and third-party ModelAdmin subclasses
            # (``GuardedModelAdmin``, ``ImportExportModelAdmin``).
            if analyzer is not None:
                graph = project_class_graph(analyzer)
                owner = graph.owner_class(def_obj)
                if owner is not None and any(
                    base in DJANGO_ADMIN_BASES
                    or base.endswith(("ModelAdmin", "Inline"))
                    for base in graph.ancestor_base_names(owner)
                ):
                    return _suppress(def_obj, "Django ModelAdmin option")

    if def_obj.type == "class":
        class_defs = getattr(framework, "class_defs", {})
        cls_node = class_defs.get(simple_name)
        if cls_node is not None:
            for base in getattr(cls_node, "bases", []):
                base_name = getattr(base, "id", None) or getattr(base, "attr", None)
                if base_name in DJANGO_APPCONFIG_BASES:
                    return _suppress(def_obj)

    if simple_name in UNITTEST_METHODS and has_base_class(
        def_obj,
        _DJANGO_TEST_BASES,
        framework,
    ):
        return _suppress(def_obj)

    return None


def _drf_validation_field_is_declared(def_obj, graph, owner):
    field_name = def_obj.simple_name.removeprefix("validate_")
    ancestors, _ = graph.ancestry(owner)
    for candidate in (owner, *ancestors):
        node = getattr(candidate, "node", None)
        if not isinstance(node, ast.ClassDef):
            continue
        for statement in reversed(node.body):
            if isinstance(statement, ast.Assign):
                targets, value = statement.targets, statement.value
            elif isinstance(statement, ast.AnnAssign):
                targets, value = [statement.target], statement.value
            else:
                targets, value = (), None
            if not any(
                isinstance(target, ast.Name) and target.id == field_name
                for target in targets
            ):
                if field_name in bound_names([statement]).counts:
                    return False
                continue
            if not isinstance(value, ast.Call) or not isinstance(
                value.func, (ast.Name, ast.Attribute)
            ):
                return False
            reference = ast.unparse(value.func)
            root = reference.split(".", 1)[0]
            if root in bound_names(node.body[: node.body.index(statement)]).counts:
                return False
            module = candidate.name.rsplit(".", 1)[0]
            while getattr(graph.defs.get(module), "type", None) == "class":
                module = module.rsplit(".", 1)[0]
            binding = graph.defs.get(f"{module}.{root}")
            if binding is not None and binding.type != "import":
                return False
            provider = graph.resolve_reference(candidate.filename, reference)
            return provider.startswith(
                (
                    "rest_framework.serializers.",
                    "rest_framework.fields.",
                    "rest_framework.relations.",
                )
            ) and provider.rsplit(".", 1)[-1].endswith("Field")
    return False


def _drf_dispatch_hook_reason(def_obj, analyzer):
    """Prove DRF dispatch separately from a method's reporting confidence."""
    if def_obj.type != "method":
        return None
    name = def_obj.simple_name
    serializer_hook = name in DRF_SERIALIZER_METHODS or name.startswith("validate_")
    roles = []
    if serializer_hook:
        roles.append((DRF_SERIALIZER_BASES, "DRF serializer hook"))
    if name in DRF_VIEWSET_METHODS:
        roles.append((DRF_VIEWSET_BASES, "DRF view hook"))
    if name in DRF_PERMISSION_METHODS:
        roles.append((DRF_PERMISSION_BASES, "DRF permission hook"))
    if name in _DRF_BACKEND_METHODS:
        roles.append((_DRF_BACKEND_BASES, "DRF backend hook"))
    if not roles:
        return None
    graph = project_class_graph(analyzer)
    owner = graph.owner_class(def_obj)
    if owner is None:
        return None
    _, external = graph.ancestry(owner)
    for qualified in external:
        if not qualified.startswith("rest_framework."):
            continue
        base = qualified.rsplit(".", 1)[-1]
        for bases, reason in roles:
            if base in bases:
                if name.startswith(
                    "validate_"
                ) and not _drf_validation_field_is_declared(def_obj, graph, owner):
                    continue
                return reason
    return None


def _check_drf_methods(def_obj, framework):
    detected = getattr(framework, "detected_frameworks", set())
    if "rest_framework" not in detected:
        return None

    simple_name = def_obj.simple_name

    if simple_name in DRF_VIEWSET_METHODS and has_base_class(
        def_obj, DRF_VIEWSET_BASES, framework
    ):
        return _suppress(def_obj)

    if simple_name in DRF_SERIALIZER_METHODS and has_base_class(
        def_obj, DRF_SERIALIZER_BASES, framework
    ):
        return _suppress(def_obj)

    if simple_name.startswith("validate_") and has_base_class(
        def_obj, DRF_SERIALIZER_BASES, framework
    ):
        return _suppress(def_obj)

    if simple_name.startswith("get_") and has_base_class(
        def_obj, DRF_SERIALIZER_BASES, framework
    ):
        return _suppress(def_obj)

    if simple_name in DRF_PERMISSION_METHODS and has_base_class(
        def_obj, DRF_PERMISSION_BASES, framework
    ):
        return _suppress(def_obj)

    if simple_name in _DRF_BACKEND_METHODS and has_base_class(
        def_obj, _DRF_BACKEND_BASES, framework
    ):
        return _suppress(def_obj)

    if def_obj.type == "variable" and simple_name in _DRF_VIEW_ATTRS:
        if "." in def_obj.name:
            return _suppress(def_obj)

    return None


def _check_web_framework_methods(def_obj, framework):
    simple_name = def_obj.simple_name

    if simple_name in STARLETTE_MIDDLEWARE_METHODS and has_base_class(
        def_obj, STARLETTE_MIDDLEWARE_BASES, framework
    ):
        return _suppress(def_obj)

    if simple_name in STARLETTE_ENDPOINT_METHODS and has_base_class(
        def_obj, STARLETTE_ENDPOINT_BASES, framework
    ):
        return _suppress(def_obj)

    if simple_name in FLASK_RESTFUL_METHODS and has_base_class(
        def_obj, FLASK_RESTFUL_BASES, framework
    ):
        return _suppress(def_obj)

    if simple_name in TORNADO_HANDLER_METHODS and has_base_class(
        def_obj, TORNADO_HANDLER_BASES, framework
    ):
        return _suppress(def_obj)

    if simple_name == "run" and has_base_class(
        def_obj, {"Thread", "threading.Thread"}, framework
    ):
        return _suppress(def_obj)

    if simple_name in CELERY_TASK_METHODS and has_base_class(
        def_obj, CELERY_TASK_BASES, framework
    ):
        return _suppress(def_obj, "Celery task method")

    if simple_name in CLICK_COMMAND_METHODS and has_base_class(
        def_obj, CLICK_COMMAND_BASES, framework
    ):
        return _suppress(def_obj, "Click command method")

    return None


def _check_pydantic_methods(def_obj, framework):
    simple_name = def_obj.simple_name

    if simple_name in PYDANTIC_MODEL_METHODS and has_base_class(
        def_obj, PYDANTIC_MODEL_BASES, framework
    ):
        return _suppress(def_obj, "Pydantic model method")

    return None


class _AbstractOverrideIndexes(NamedTuple):
    all_defs: dict
    classes_by_file_and_name: dict
    classes_by_name: dict
    methods_by_owner_and_name: dict


def _get_abstract_override_indexes(analyzer, all_defs) -> _AbstractOverrideIndexes:
    cached = getattr(analyzer, "_abstract_override_indexes", None)
    if cached and cached[0] is all_defs:
        return cached

    classes_by_file_and_name = {}
    classes_by_name = {}
    methods_by_owner_and_name = {}
    for dobj in all_defs.values():
        if dobj.type == "class":
            classes_by_file_and_name.setdefault((dobj.filename, dobj.simple_name), dobj)
            classes_by_name.setdefault(dobj.simple_name, dobj)
        elif dobj.type == "method" and "." in dobj.name:
            owner_name = dobj.name.rsplit(".", 2)[-2]
            methods_by_owner_and_name.setdefault(
                (owner_name, dobj.simple_name), []
            ).append(dobj)

    indexes = _AbstractOverrideIndexes(
        all_defs,  # the cache key
        classes_by_file_and_name,
        classes_by_name,
        methods_by_owner_and_name,
    )
    analyzer._abstract_override_indexes = indexes
    return indexes


def _check_abstract_overrides(def_obj, analyzer, framework):
    if def_obj.type != "method" or "." not in def_obj.name:
        return None

    simple_name = def_obj.simple_name
    parts = def_obj.name.split(".")

    abstract_methods = {
        **getattr(analyzer, "_global_abstract_methods", {}),
        **getattr(framework, "abstract_methods", {}),
    }
    method_name = parts[-1]
    for part in parts[:-1]:
        if part in abstract_methods and method_name in abstract_methods[part]:
            return _suppress(def_obj, f"Abstract method declaration in {part}")

    if simple_name in PROTOCOL_METHOD_TO_BASES:
        candidate_bases = PROTOCOL_METHOD_TO_BASES[simple_name]
        protocol_classes = set(getattr(analyzer, "_global_protocol_classes", set()))
        protocol_classes.update(getattr(framework, "protocol_classes", set()))
        candidate_bases = candidate_bases - protocol_classes
        if has_base_class(def_obj, candidate_bases, framework):
            return _suppress(def_obj, "protocol/ABC override", code="protocol_override")

    all_defs = getattr(analyzer, "defs", {})
    class_name = parts[-2] if len(parts) >= 2 else None
    if class_name:
        indexes = _get_abstract_override_indexes(analyzer, all_defs)
        class_def = indexes.classes_by_file_and_name.get((def_obj.filename, class_name))
        if class_def is None:
            class_def = indexes.classes_by_name.get(class_name)
        if class_def and getattr(class_def, "base_classes", None):
            has_external_base = False
            protocol_classes = set(getattr(analyzer, "_global_protocol_classes", set()))
            protocol_classes.update(getattr(framework, "protocol_classes", set()))
            for base_name in class_def.base_classes:
                base_simple = base_name.split(".")[-1]
                if base_simple in protocol_classes:
                    continue
                for dobj in indexes.methods_by_owner_and_name.get(
                    (base_simple, method_name), ()
                ):
                    if dobj is not def_obj:
                        return _suppress(
                            def_obj,
                            f"overrides {base_simple}.{method_name}",
                            code="parent_override",
                        )
                if base_simple not in indexes.classes_by_name and "." in base_name:
                    has_external_base = True
            if has_external_base and not method_name.startswith("__"):
                return -40

    return None


def _check_external_override(def_obj, analyzer):
    """A method or class attribute whose name an external ancestor (stdlib
    or an installed package, read from source) defines is an override that
    the library calls or reads: ``ast.NodeVisitor.generic_visit``,
    ``asyncio.Protocol.eof_received``, a Sphinx ``Domain.resolve_xref``."""
    if def_obj.type not in ("method", "variable") or "." not in def_obj.name:
        return None
    simple_name = def_obj.simple_name
    if simple_name.startswith("__") and simple_name.endswith("__"):
        return None
    defining = external_override_owner(def_obj, analyzer)
    if defining:
        return _suppress(
            def_obj,
            f"overrides {defining}.{simple_name}",
            code="external_override",
        )
    return None


# traitlets registers methods decorated with ``@default``, ``@validate`` and
# ``@observe`` as trait handlers, and still calls the magic
# ``_<trait>_default`` (dynamic default) and deprecated ``_<trait>_changed``
# methods of a declared trait:
# https://traitlets.readthedocs.io/en/stable/api.html#dynamic-default-values
# https://traitlets.readthedocs.io/en/stable/api.html#callbacks-when-trait-attributes-change
_TRAITLETS_HANDLER_DECORATORS = frozenset(
    {"default", "validate", "observe", "observe_compat"}
)
_TRAITLETS_MAGIC_RE = re.compile(r"^_(?P<trait>[A-Za-z_]\w*?)_(?:default|changed)$")


def _check_traitlets_hooks(def_obj, analyzer):
    if def_obj.type != "method" or "." not in def_obj.name:
        return None
    graph = project_class_graph(analyzer)
    decorators = getattr(def_obj, "decorators", None)
    if not isinstance(decorators, (list, tuple)):
        decorators = ()
    for decorator in decorators:
        resolved = graph.resolve_reference(def_obj.filename, str(decorator))
        parts = resolved.split(".")
        if (
            len(parts) > 1
            and parts[0] == "traitlets"
            and parts[-1] in _TRAITLETS_HANDLER_DECORATORS
        ):
            return _suppress(def_obj, f"traitlets @{parts[-1]} handler")

    match = _TRAITLETS_MAGIC_RE.match(def_obj.simple_name)
    if not match:
        return None
    owner = graph.owner_class(def_obj)
    if owner is None:
        return None
    _, external = graph.ancestry(owner)
    # Importing traitlets does not install trait dispatch on unrelated classes.
    # Magic defaults/notifications require its actual class ancestry.
    uses_traitlets = any(
        qname.split(".", 1)[0] == "traitlets" for qname in external
    )
    if not uses_traitlets:
        return None
    trait = match.group("trait")
    if graph.class_defines(owner, trait) or external_member_owner(
        owner, trait, analyzer
    ):
        return _suppress(def_obj, f"traitlets magic method for trait {trait}")
    return None


# Django and DRF fields merge ``default_error_messages`` up the MRO:
# https://www.django-rest-framework.org/api-guide/fields/#raising-validation-errors
# https://docs.djangoproject.com/en/stable/ref/forms/fields/#error-messages
_FIELD_FRAMEWORK_ROOTS = frozenset({"rest_framework", "django"})


def _check_drf_inherited_hooks(def_obj, analyzer):
    """DRF names read on classes that reach a DRF base only through project
    classes, where the per-file base checks cannot see it."""
    if def_obj.type not in ("method", "variable") or "." not in def_obj.name:
        return None
    simple_name = def_obj.simple_name
    is_field_hook = def_obj.type == "method" and (
        simple_name.startswith("validate_") and len(simple_name) > len("validate_")
    )
    is_error_table = (
        def_obj.type == "variable" and simple_name == "default_error_messages"
    )
    if not (is_field_hook or is_error_table):
        return None
    graph = project_class_graph(analyzer)
    owner = graph.owner_class(def_obj)
    if owner is None:
        return None
    _, external = graph.ancestry(owner)
    framework_bases = {
        qname.rsplit(".", 1)[-1]
        for qname in external
        if qname.split(".", 1)[0] in _FIELD_FRAMEWORK_ROOTS
    }
    if is_field_hook and any(
        qname.split(".", 1)[0] == "rest_framework"
        and qname.rsplit(".", 1)[-1] in DRF_SERIALIZER_BASES
        for qname in external
    ):
        # Serializer.to_internal_value calls validate_<field_name>:
        # https://www.django-rest-framework.org/api-guide/serializers/#field-level-validation
        return _suppress(def_obj, "DRF validate_<field> hook")
    if is_error_table and any(
        base.endswith("Field") or base in DRF_SERIALIZER_BASES
        for base in framework_bases
    ):
        return _suppress(def_obj, "field default_error_messages")
    return None


def _check_soft_patterns(def_obj, visitor, framework):
    detected = getattr(framework, "detected_frameworks", set())
    reduction = 0
    for pattern, red, context in SOFT_PATTERNS:
        if not matches_pattern(def_obj.simple_name, pattern):
            continue
        if context == "test_file" and not visitor.is_test_file:
            red = red // 4
        elif context == "django" and "django" not in detected:
            red = red // 4
        reduction += red
    return -reduction if reduction > 0 else None


def _check_protocol_abc(def_obj, analyzer, framework):
    simple_name = def_obj.simple_name

    if simple_name in _PYTEST_HOOKS_LOCAL:
        return _suppress(def_obj)

    if def_obj.type == "method" and "." in def_obj.name:
        class_name = def_obj.name.rsplit(".", 1)[0].split(".")[-1]
        if class_name.startswith("Base") or class_name.endswith(
            ("Base", "ABC", "Interface", "Adapter")
        ):
            return _suppress(def_obj)

    if def_obj.type == "class":
        protocol_classes = getattr(framework, "protocol_classes", set())
        if simple_name in protocol_classes:
            return _suppress(def_obj, "Protocol class")

    if def_obj.type in ("method", "class") and "." in def_obj.name:
        parts = def_obj.name.split(".")
        for part in parts[:-1]:
            if any(
                part.startswith(prefix)
                and len(part) > len(prefix)
                and part[len(prefix)].isupper()
                for prefix in ("InMemory", "Mock", "Fake", "Stub", "Dummy", "Fixed")
            ):
                return -40
            if any(
                part.endswith(suffix) for suffix in ("Mock", "Stub", "Fake", "Double")
            ):
                return -40

    if def_obj.type in ("method", "parameter") and "." in def_obj.name:
        parts = def_obj.name.split(".")
        protocol_classes = getattr(framework, "protocol_classes", set())
        for part in parts[:-1]:
            if part in protocol_classes:
                return _suppress(def_obj, "Protocol class member")

    if def_obj.type == "method" and "." in def_obj.name:
        parts = def_obj.name.split(".")
        method_name = parts[-1]
        abc_implementers = {
            **getattr(analyzer, "_global_abc_implementers", {}),
            **getattr(framework, "abc_implementers", {}),
        }
        abstract_methods = {
            **getattr(analyzer, "_global_abstract_methods", {}),
            **getattr(framework, "abstract_methods", {}),
        }
        for part in parts[:-1]:
            if part in abc_implementers:
                for parent_abc in abc_implementers[part]:
                    if parent_abc in abstract_methods:
                        if method_name in abstract_methods[parent_abc]:
                            return _suppress(
                                def_obj,
                                f"Implements abstract method from {parent_abc}",
                            )

    if def_obj.type == "method" and "." in def_obj.name:
        parts = def_obj.name.split(".")
        for part in parts[:-1]:
            if part.endswith("Mixin"):
                return -60

    return None


def _check_event_methods(def_obj):
    if def_obj.type != "method":
        return None
    simple_name = def_obj.simple_name
    if simple_name.startswith("on_") and len(simple_name) > 3:
        return -30
    if simple_name == "compose":
        return -40
    if simple_name.startswith("watch_") and len(simple_name) > 6:
        return -30
    return None


def _check_dependency_injected_parameter(def_obj, analyzer, framework):
    """FastAPI runs ``Depends()``/``Security()`` dependencies for the parameter
    even when the body never reads it (authentication, rate limits, DB
    sessions). Reporting it as unused invites deleting the guard."""
    if def_obj.type != "parameter":
        return None
    key = (def_obj.line, def_obj.simple_name)
    if key in getattr(framework, "fastapi_callback_parameters", ()):
        return _suppress(def_obj, "FastAPI callback parameter")
    precise = getattr(framework, "fastapi_dependency_parameters", None)
    if precise is not None:
        if key in precise:
            return _suppress(def_obj, "FastAPI dependency parameter (Depends/Security)")
        return None
    if key in getattr(framework, "dependency_injected_params", set()):
        return _suppress(def_obj, "FastAPI dependency parameter (Depends/Security)")
    alias = getattr(framework, "param_annotation_aliases", {}).get(key)
    if alias and (
        alias in getattr(analyzer, "_global_dependency_alias_names", set())
        or alias in getattr(framework, "dependency_alias_names", set())
    ):
        return _suppress(
            def_obj, f"FastAPI dependency parameter (annotated with {alias})"
        )
    return None


def _check_hook_override_parameters(def_obj, framework):
    """A known framework hook keeps the signature its caller uses, so its
    parameters stay even when the body ignores them (``emit(self, record)``
    on a logging Handler, ``process_bind_param(self, value, dialect)`` on a
    SQLAlchemy TypeDecorator)."""
    if def_obj.type != "parameter" or "." not in def_obj.name:
        return None
    parts = def_obj.name.split(".")
    if len(parts) < 3:
        return None
    method_name, class_name = parts[-2], parts[-3]
    candidate_bases = PROTOCOL_METHOD_TO_BASES.get(method_name)
    if not candidate_bases:
        return None
    if _class_base_names(class_name, framework) & candidate_bases:
        return _suppress(def_obj, f"Parameter of the {method_name} hook")
    return None


def _check_base_class_parameters(def_obj):
    if def_obj.type != "parameter" or "." not in def_obj.name:
        return None
    parts = def_obj.name.split(".")
    if len(parts) >= 2:
        class_name = parts[-3] if len(parts) >= 3 else ""
        if class_name.startswith("Base") or class_name.endswith(
            ("Base", "ABC", "Interface", "Adapter")
        ):
            return _suppress(def_obj)
    return None


def _check_settings_config(def_obj):
    if "." not in def_obj.name:
        return None
    owner, attr = def_obj.name.rsplit(".", 1)
    owner_simple = owner.split(".")[-1]
    if (
        owner_simple == "Settings"
        or owner_simple == "Config"
        or owner_simple.endswith("Settings")
        or owner_simple.endswith("Config")
    ):
        if attr.isupper() or not attr.startswith("_"):
            return _suppress(def_obj)
    return None


def _is_function_local(def_obj, analyzer):
    if "." not in def_obj.name:
        return False
    owner = analyzer.defs.get(def_obj.name.rsplit(".", 1)[0])
    return owner is not None and owner.type in ("function", "method")


def _check_data_model_fields(def_obj, analyzer, framework):
    simple_name = def_obj.simple_name
    _is_ts = str(def_obj.filename).endswith((".ts", ".tsx", ".js", ".jsx"))

    if def_obj.type == "variable" and simple_name == "_" and not _is_ts:
        return _suppress(def_obj)

    if def_obj.type in ("variable", "method") and "." in def_obj.name:
        prefix = def_obj.name.rsplit(".", 1)[0]
        parent_simple = prefix.split(".")[-1]
        if parent_simple in getattr(framework, "enum_classes", set()):
            return _suppress(
                def_obj,
                "Enum member" if def_obj.type == "variable" else "Enum method",
            )

    if (
        def_obj.type == "variable"
        and "." in def_obj.name
        and simple_name in DOCUTILS_DIRECTIVE_ATTRS
    ):
        prefix = def_obj.name.rsplit(".", 1)[0]
        parent_simple = prefix.split(".")[-1]
        class_bases = _class_base_names(parent_simple, framework)
        if any(base.endswith("Directive") for base in class_bases):
            return _suppress(def_obj, "docutils directive option")

    if (
        def_obj.type == "variable"
        and "." in def_obj.name
        and simple_name in SQLALCHEMY_TYPE_ATTRS
    ):
        parent_simple = def_obj.name.rsplit(".", 1)[0].split(".")[-1]
        if _class_base_names(parent_simple, framework) & SQLALCHEMY_TYPE_BASES:
            return _suppress(def_obj, "SQLAlchemy column type option")

    if def_obj.type == "variable" and "." in def_obj.name:
        parts = def_obj.name.split(".")
        var_name = parts[-1]
        if var_name.isupper() and len(var_name) > 1:
            return "cap_upper"

    if def_obj.type == "variable" and getattr(framework, "dataclass_fields", None):
        if def_obj.name in framework.dataclass_fields:
            return _suppress(def_obj)

    if def_obj.type == "variable" and def_obj.name in getattr(
        framework, "orm_declarative_fields", ()
    ):
        return _suppress(def_obj, "ORM declarative field")

    if def_obj.type == "variable" and "." in def_obj.name:
        prefix = def_obj.name.rsplit(".", 1)[0]
        parent_simple = prefix.split(".")[-1]
        if parent_simple in getattr(framework, "namedtuple_classes", set()):
            return _suppress(def_obj, "NamedTuple field")

    if def_obj.type == "variable" and "." in def_obj.name:
        prefix = def_obj.name.rsplit(".", 1)[0]
        parent_simple = prefix.split(".")[-1]
        if parent_simple in getattr(framework, "attrs_classes", set()):
            return _suppress(def_obj, "attrs field")

    if def_obj.type == "variable" and "." in def_obj.name:
        prefix = def_obj.name.rsplit(".", 1)[0]
        parent_simple = prefix.split(".")[-1]
        detected = getattr(framework, "detected_frameworks", set())
        class_bases = _class_base_names(parent_simple, framework)
        if "rest_framework" in detected and class_bases.intersection(
            DRF_SERIALIZER_BASES
        ):
            return _suppress(def_obj, "DRF serializer field")
        if "marshmallow" in detected and "Schema" in class_bases:
            return _suppress(def_obj, "Marshmallow schema field")

    if def_obj.type == "variable" and "." in def_obj.name:
        prefix = def_obj.name.rsplit(".", 1)[0]
        parent_simple = prefix.split(".")[-1]
        if parent_simple in getattr(framework, "orm_model_classes", set()):
            return _suppress(def_obj, "ORM model column")

    if def_obj.type == "variable":
        if simple_name in getattr(framework, "type_alias_names", set()):
            return _suppress(def_obj, "Type alias")

    if def_obj.type == "variable" and "." in def_obj.name:
        prefix, _ = def_obj.name.rsplit(".", 1)
        cls_def = analyzer.defs.get(prefix)
        if cls_def and cls_def.type == "class":
            cls_simple = cls_def.simple_name
            if (
                getattr(framework, "pydantic_models", None)
                and cls_simple in framework.pydantic_models
            ):
                return _suppress(def_obj)
            cls_node = getattr(framework, "class_defs", {}).get(cls_simple)
            if cls_node is not None:
                for base in cls_node.bases:
                    if isinstance(base, ast.Name) and base.id.lower().endswith(
                        ("schema", "model")
                    ):
                        return _suppress(def_obj)
                    if isinstance(base, ast.Attribute) and base.attr.lower().endswith(
                        ("schema", "model")
                    ):
                        return _suppress(def_obj)

    if def_obj.type == "variable":
        fr = getattr(framework, "first_read_lineno", {}).get(def_obj.name)
        if fr is not None and fr >= def_obj.line:
            return _suppress(def_obj)

    if def_obj.type == "variable" and _is_function_local(def_obj, analyzer):
        owner = def_obj.name.rsplit(".", 1)[0]
        if owner in getattr(framework, "dynamic_local_functions", ()):
            return _suppress(def_obj, "function reads its locals dynamically")
        return None

    if def_obj.type == "variable" and "." in def_obj.name:
        _, attr = def_obj.name.rsplit(".", 1)
        dotted_variable_counts = getattr(
            analyzer, "_dotted_variable_simple_name_counts", None
        )
        if dotted_variable_counts is not None:
            if dotted_variable_counts.get(attr, 0) > 1:
                return _suppress(def_obj)
        else:
            for other in analyzer.defs.values():
                if other is def_obj:
                    continue
                if other.type != "variable":
                    continue
                if "." not in other.name:
                    continue
                if other.simple_name != attr:
                    continue
                return _suppress(def_obj)

    return None


def _apply_standard_reductions(def_obj, analyzer, visitor, framework, confidence):
    simple_name = def_obj.simple_name
    _is_ts = str(def_obj.filename).endswith((".ts", ".tsx", ".js", ".jsx"))

    if simple_name.startswith("_") and not simple_name.startswith("__") and not _is_ts:
        confidence -= PENALTIES["private_name"]

    if simple_name.startswith("__") and simple_name.endswith("__") and not _is_ts:
        confidence -= PENALTIES["dunder_or_magic"]

    if def_obj.in_init and def_obj.type in ("function", "class"):
        confidence -= PENALTIES["in_init_file"]

    if def_obj.name.split(".")[0] in analyzer.dynamic:
        confidence -= PENALTIES["dynamic_module"]

    if def_obj.line in visitor.test_decorated_lines:
        confidence -= PENALTIES["test_related"]

    if (
        def_obj.type == "class"
        and simple_name.startswith("Test")
        and is_test_path(def_obj.filename)
    ):
        return 0

    if (
        def_obj.type in ("function", "method")
        and is_test_path(def_obj.filename)
        and "." in def_obj.name
    ):
        parts = def_obj.name.split(".")
        for part in parts[:-1]:
            if part.startswith("test_"):
                return 0

    framework_confidence = detect_framework_usage(def_obj, visitor=framework)
    if framework_confidence is not None:
        confidence = min(confidence, framework_confidence)

    if simple_name.startswith("__") and simple_name.endswith("__"):
        confidence = 0

    if def_obj.type == "parameter":
        if simple_name in ("self", "cls"):
            confidence = 0
        elif "." in def_obj.name:
            method_name = def_obj.name.split(".")[-2]
            if method_name.startswith("__") and method_name.endswith("__"):
                confidence = 0

    if def_obj.line in visitor.test_decorated_lines:
        confidence = 0

    if (
        def_obj.type == "import"
        and def_obj.name.startswith("__future__.")
        and simple_name in _FUTURE_IMPORTS
    ):
        confidence = 0

    return confidence


def _check_heuristic_refs(def_obj, analyzer, confidence):
    if def_obj.type == "method" and confidence > 0:
        method_name = def_obj.simple_name
        abstract_methods = getattr(analyzer, "_global_abstract_methods", {})
        for abc_class, methods in abstract_methods.items():
            if method_name in methods:
                confidence -= 40
                break

    if def_obj.type == "method" and "." in def_obj.name:
        parts = def_obj.name.split(".")
        duck_typed = getattr(analyzer, "_duck_typed_implementers", set())
        for part in parts[:-1]:
            if part in duck_typed:
                _suppress(def_obj, "Duck-typed Protocol implementation")
                return 0

    try:
        attr_ref_count = getattr(def_obj, "_attr_name_ref_count", 0)
        if (
            isinstance(attr_ref_count, int)
            and attr_ref_count > 0
            and def_obj.references > 0
            and def_obj.references <= attr_ref_count
        ):
            heuristic = getattr(def_obj, "heuristic_refs", {})
            if isinstance(heuristic, dict):
                same_file = heuristic.get("same_file_attr", 0.0)
                same_pkg = heuristic.get("same_pkg_attr", 0.0)
                if same_file < 1.0 and same_pkg < 0.3:
                    confidence -= 25
                    why_reduced = getattr(def_obj, "why_confidence_reduced", None)
                    if isinstance(why_reduced, list):
                        why_reduced.append("only_global_attr_match")
    except (TypeError, AttributeError):
        pass

    return confidence


def apply_penalties(
    analyzer: Any,
    def_obj: Any,
    visitor: Any,
    framework: Any,
    cfg: Optional[dict] = None,
) -> None:
    if not hasattr(def_obj, "simple_name") or not hasattr(def_obj, "filename"):
        raise ValueError("def_obj must have 'simple_name' and 'filename' attributes")

    confidence = 100

    early_checks = [
        _check_inline_ignore(def_obj, visitor),
        _check_docs_path(def_obj),
    ]
    for result in early_checks:
        if result is True:
            return

    result = _check_version_conditional(def_obj, framework)
    if isinstance(result, int):
        confidence += result

    result = _check_conditional_import(def_obj)
    if result == "cap_40":
        confidence = min(confidence, 40)

    result = _check_config_whitelist(def_obj, cfg)
    if result is True:
        return
    if isinstance(result, int):
        confidence += result

    if _check_configured_entrypoint(def_obj, analyzer, cfg) is True:
        return

    if _check_hard_entrypoint(def_obj) is True:
        return

    if _check_non_library_path(def_obj, analyzer, cfg) is True:
        return

    if _check_framework_decorations(def_obj, framework) is True:
        return

    if _check_pytest_unittest(def_obj, framework) is True:
        return

    if _check_alembic_migration(def_obj) is True:
        return

    if _check_gunicorn_config(def_obj) is True:
        return

    if _check_django_path_converter(def_obj, analyzer, framework) is True:
        return

    if _check_django_drf_structural(def_obj, framework, analyzer) is True:
        return

    if _check_django_methods(def_obj, framework, analyzer) is True:
        return

    drf_dispatch_reason = _drf_dispatch_hook_reason(def_obj, analyzer)
    if drf_dispatch_reason is not None:
        _suppress(def_obj, drf_dispatch_reason, code="drf_hook")
        return

    if _check_drf_methods(def_obj, framework) is True:
        return

    if _check_drf_inherited_hooks(def_obj, analyzer) is True:
        return

    if _check_traitlets_hooks(def_obj, analyzer) is True:
        return

    if _check_web_framework_methods(def_obj, framework) is True:
        return

    if _check_pydantic_methods(def_obj, framework) is True:
        return

    result = _check_abstract_overrides(def_obj, analyzer, framework)
    if result is True:
        return
    if _check_external_override(def_obj, analyzer) is True:
        return
    if isinstance(result, int):
        confidence += result

    result = _check_soft_patterns(def_obj, visitor, framework)
    if isinstance(result, int):
        confidence += result

    result = _check_protocol_abc(def_obj, analyzer, framework)
    if result is True:
        return
    if isinstance(result, int):
        confidence += result

    result = _check_event_methods(def_obj)
    if isinstance(result, int):
        confidence += result

    if _check_hook_override_parameters(def_obj, framework) is True:
        return

    if _check_base_class_parameters(def_obj) is True:
        return

    if _check_dependency_injected_parameter(def_obj, analyzer, framework) is True:
        return

    if _check_settings_config(def_obj) is True:
        return

    convention = documented_convention_reason(def_obj, analyzer, framework)
    if convention:
        _suppress(def_obj, convention)
        return

    result = _check_data_model_fields(def_obj, analyzer, framework)
    if result is True:
        return
    if result == "cap_upper":
        confidence -= 40
        def_obj.confidence = max(confidence, 0)
        return

    confidence = _apply_standard_reductions(
        def_obj, analyzer, visitor, framework, confidence
    )
    if confidence == 0:
        def_obj.confidence = 0
        return

    confidence = _check_heuristic_refs(def_obj, analyzer, confidence)

    def_obj.confidence = max(confidence, 0)
