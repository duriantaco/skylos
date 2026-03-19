import ast
from typing import Any, Optional
from skylos.constants import PENALTIES, get_non_library_dir_kind, is_test_path
from skylos.config import is_whitelisted
from skylos.known_patterns import (
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
    DJANGO_SIGNAL_METHODS,
    DRF_VIEWSET_METHODS,
    DRF_VIEWSET_BASES,
    DRF_SERIALIZER_METHODS,
    DRF_SERIALIZER_BASES,
    DRF_PERMISSION_METHODS,
    DRF_PERMISSION_BASES,
    STARLETTE_MIDDLEWARE_METHODS,
    STARLETTE_MIDDLEWARE_BASES,
    STARLETTE_ENDPOINT_METHODS,
    STARLETTE_ENDPOINT_BASES,
    FLASK_RESTFUL_METHODS,
    FLASK_RESTFUL_BASES,
    TORNADO_HANDLER_METHODS,
    TORNADO_HANDLER_BASES,
    SOFT_PATTERNS,
    matches_pattern,
    has_base_class,
    PROTOCOL_METHOD_TO_BASES,
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
}

_META_ATTRS = {
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


def _suppress(def_obj, reason=None, code=None, folder_role=None):
    def_obj.confidence = 0
    if reason:
        def_obj.skip_reason = reason
    if code:
        def_obj.suppression_code = code
    if folder_role:
        def_obj.folder_role = folder_role
    return True


def _check_inline_ignore(def_obj, visitor):
    if getattr(visitor, "ignore_lines", None) and def_obj.line in visitor.ignore_lines:
        return _suppress(def_obj, "inline ignore comment")
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
    if def_obj.line in getattr(framework, "framework_decorated_lines", set()):
        return _suppress(def_obj)
    return None


def _check_pytest_unittest(def_obj, framework):
    simple_name = def_obj.simple_name
    detected = getattr(framework, "detected_frameworks", set())

    if simple_name in PYTEST_HOOKS:
        if "pytest" in detected or "conftest" in str(def_obj.filename):
            return _suppress(def_obj)

    if simple_name in UNITTEST_METHODS:
        if has_base_class(def_obj, {"TestCase"}, framework):
            return _suppress(def_obj)

    return None


def _check_django_methods(def_obj, framework):
    detected = getattr(framework, "detected_frameworks", set())
    if "django" not in detected:
        return None

    simple_name = def_obj.simple_name

    _DJANGO_CHECKS = [
        (DJANGO_MODEL_METHODS, DJANGO_MODEL_BASES),
        (DJANGO_VIEW_METHODS, DJANGO_VIEW_BASES),
        (DJANGO_ADMIN_METHODS, DJANGO_ADMIN_BASES),
        (DJANGO_FORM_METHODS, DJANGO_FORM_BASES),
        (DJANGO_COMMAND_METHODS, DJANGO_COMMAND_BASES),
        (DJANGO_APPCONFIG_METHODS, DJANGO_APPCONFIG_BASES),
        (DJANGO_MIDDLEWARE_METHODS, DJANGO_MIDDLEWARE_BASES),
    ]

    for methods, bases in _DJANGO_CHECKS:
        if simple_name in methods and has_base_class(def_obj, bases, framework):
            return _suppress(def_obj)

    if simple_name.startswith("clean_") and has_base_class(
        def_obj, DJANGO_FORM_BASES, framework
    ):
        return _suppress(def_obj)

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

    if def_obj.type == "variable" and simple_name in _META_ATTRS:
        if "." in def_obj.name and "Meta" in def_obj.name:
            return _suppress(def_obj)

    if simple_name in UNITTEST_METHODS and has_base_class(
        def_obj,
        _DJANGO_TEST_BASES,
        framework,
    ):
        return _suppress(def_obj)

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

    return None


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
        if has_base_class(def_obj, candidate_bases, framework):
            return _suppress(def_obj, "protocol/ABC override", code="protocol_override")

    all_defs = getattr(analyzer, "defs", {})
    class_name = parts[-2] if len(parts) >= 2 else None
    if class_name:
        class_def = None
        for dname, dobj in all_defs.items():
            if (
                dobj.type == "class"
                and dobj.simple_name == class_name
                and dobj.filename == def_obj.filename
            ):
                class_def = dobj
                break
        if class_def is None:
            for dname, dobj in all_defs.items():
                if dobj.type == "class" and dobj.simple_name == class_name:
                    class_def = dobj
                    break
        if class_def and getattr(class_def, "base_classes", None):
            has_external_base = False
            for base_name in class_def.base_classes:
                base_simple = base_name.split(".")[-1]
                for dname, dobj in all_defs.items():
                    if (
                        dobj.type == "method"
                        and dobj.simple_name == method_name
                        and dobj is not def_obj
                        and "." in dobj.name
                        and dobj.name.split(".")[-2] == base_simple
                    ):
                        return _suppress(
                            def_obj,
                            f"overrides {base_simple}.{method_name}",
                            code="parent_override",
                        )
                base_in_project = any(
                    dobj.type == "class" and dobj.simple_name == base_simple
                    for dobj in all_defs.values()
                )
                if not base_in_project and "." in base_name:
                    has_external_base = True
            if has_external_base and not method_name.startswith("__"):
                return -40

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
        protocol_implementers = {
            **getattr(analyzer, "_global_protocol_implementers", {}),
            **getattr(framework, "protocol_implementers", {}),
        }
        for part in parts[:-1]:
            if part in protocol_implementers:
                return _suppress(def_obj, "Protocol implementer method")

    if def_obj.type == "method" and "." in def_obj.name:
        parts = def_obj.name.split(".")
        method_name = parts[-1]

        if len(parts) >= 2:
            class_name = parts[-2]
        else:
            class_name = None

        if class_name:
            protocol_method_names = getattr(
                analyzer, "_global_protocol_method_names", {}
            )
            if protocol_method_names:
                class_methods = set()
                for d in analyzer.defs.values():
                    if d.type == "method" and "." in d.name:
                        d_parts = d.name.split(".")
                        if len(d_parts) >= 2 and d_parts[-2] == class_name:
                            class_methods.add(d_parts[-1])
                for protocol_class, protocol_methods in protocol_method_names.items():
                    if protocol_methods and protocol_methods.issubset(class_methods):
                        if method_name in protocol_methods:
                            return _suppress(
                                def_obj,
                                f"Structural Protocol implementation ({protocol_class})",
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


def _check_data_model_fields(def_obj, analyzer, framework):
    simple_name = def_obj.simple_name
    _is_ts = str(def_obj.filename).endswith((".ts", ".tsx"))

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

    if def_obj.type == "variable" and "." in def_obj.name:
        parts = def_obj.name.split(".")
        var_name = parts[-1]
        if var_name.isupper() and len(var_name) > 1:
            return "cap_upper"

    if def_obj.type == "variable" and getattr(framework, "dataclass_fields", None):
        if def_obj.name in framework.dataclass_fields:
            return _suppress(def_obj)

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

    if def_obj.type == "variable" and "." in def_obj.name:
        _, attr = def_obj.name.rsplit(".", 1)
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
    _is_ts = str(def_obj.filename).endswith((".ts", ".tsx"))

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

    if _check_hard_entrypoint(def_obj) is True:
        return

    if _check_non_library_path(def_obj, analyzer, cfg) is True:
        return

    if _check_framework_decorations(def_obj, framework) is True:
        return

    if _check_pytest_unittest(def_obj, framework) is True:
        return

    if _check_django_methods(def_obj, framework) is True:
        return

    if _check_drf_methods(def_obj, framework) is True:
        return

    if _check_web_framework_methods(def_obj, framework) is True:
        return

    result = _check_abstract_overrides(def_obj, analyzer, framework)
    if result is True:
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

    if _check_base_class_parameters(def_obj) is True:
        return

    if _check_settings_config(def_obj) is True:
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
