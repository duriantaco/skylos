import ast
from skylos.constants import PENALTIES
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
    DRF_VIEWSET_METHODS,
    DRF_VIEWSET_BASES,
    DRF_SERIALIZER_METHODS,
    DRF_SERIALIZER_BASES,
    DRF_PERMISSION_METHODS,
    DRF_PERMISSION_BASES,
    SOFT_PATTERNS,
    matches_pattern,
    has_base_class,
)
from skylos.visitors.framework_aware import detect_framework_usage


def apply_penalties(analyzer, def_obj, visitor, framework, cfg=None):
    confidence = 100
    simple_name = def_obj.simple_name
    
    if (
        getattr(visitor, "ignore_lines", None)
        and def_obj.line in visitor.ignore_lines
    ):
        def_obj.confidence = 0
        def_obj.skip_reason = "inline ignore comment"
        return

    if cfg:
        is_wl, reason, conf_reduction = is_whitelisted(
            def_obj.simple_name, str(def_obj.filename), cfg
        )

        if is_wl:
            def_obj.confidence = 0
            def_obj.skip_reason = reason
            return

        if conf_reduction > 0:
            confidence -= conf_reduction

    if simple_name in HARD_ENTRYPOINTS:
        def_obj.confidence = 0
        return

    if def_obj.line in getattr(framework, "framework_decorated_lines", set()):
        def_obj.confidence = 0
        return

    detected = getattr(framework, "detected_frameworks", set())

    if simple_name in PYTEST_HOOKS:
        if "pytest" in detected or "conftest" in str(def_obj.filename):
            def_obj.confidence = 0
            return

    if simple_name in UNITTEST_METHODS:
        if has_base_class(def_obj, {"TestCase"}, framework):
            def_obj.confidence = 0
            return

    if "django" in detected:
        if simple_name in DJANGO_MODEL_METHODS and has_base_class(
            def_obj, DJANGO_MODEL_BASES, framework
        ):
            def_obj.confidence = 0
            return
        if simple_name in DJANGO_VIEW_METHODS and has_base_class(
            def_obj, DJANGO_VIEW_BASES, framework
        ):
            def_obj.confidence = 0
            return
        if simple_name in DJANGO_ADMIN_METHODS and has_base_class(
            def_obj, DJANGO_ADMIN_BASES, framework
        ):
            def_obj.confidence = 0
            return
        if simple_name in DJANGO_FORM_METHODS and has_base_class(
            def_obj, DJANGO_FORM_BASES, framework
        ):
            def_obj.confidence = 0
            return
        if simple_name in DJANGO_COMMAND_METHODS and has_base_class(
            def_obj, DJANGO_COMMAND_BASES, framework
        ):
            def_obj.confidence = 0
            return
        if simple_name in DJANGO_APPCONFIG_METHODS and has_base_class(
            def_obj, DJANGO_APPCONFIG_BASES, framework
        ):
            def_obj.confidence = 0
            return

    if "rest_framework" in detected:
        if simple_name in DRF_VIEWSET_METHODS and has_base_class(
            def_obj, DRF_VIEWSET_BASES, framework
        ):
            def_obj.confidence = 0
            return
        if simple_name in DRF_SERIALIZER_METHODS and has_base_class(
            def_obj, DRF_SERIALIZER_BASES, framework
        ):
            def_obj.confidence = 0
            return
        if simple_name in DRF_PERMISSION_METHODS and has_base_class(
            def_obj, DRF_PERMISSION_BASES, framework
        ):
            def_obj.confidence = 0
            return

    for pattern, reduction, context in SOFT_PATTERNS:
        if not matches_pattern(simple_name, pattern):
            continue

        if context == "test_file" and not visitor.is_test_file:
            reduction = reduction // 4
        elif context == "django" and "django" not in detected:
            reduction = reduction // 4

        confidence -= reduction
        break

    PYTEST_HOOKS_LOCAL = {
        "pytest_configure",
        "pytest_unconfigure",
        "pytest_addoption",
    }

    if simple_name in PYTEST_HOOKS_LOCAL:
        def_obj.confidence = 0
        return

    if def_obj.type == "method" and "." in def_obj.name:
        class_name = def_obj.name.rsplit(".", 1)[0].split(".")[-1]
        if class_name.startswith("Base") or class_name.endswith(
            ("Base", "ABC", "Interface", "Adapter")
        ):
            def_obj.confidence = 0
            return
    
    if def_obj.type == "class":
        protocol_classes = getattr(framework, 'protocol_classes', set())
        if def_obj.simple_name in protocol_classes:
            def_obj.confidence = 0
            def_obj.skip_reason = "Protocol class"
            return
        
    if def_obj.type in ("method", "class") and "." in def_obj.name:
        parts = def_obj.name.split(".")
        for part in parts[:-1]:
            if any(part.startswith(prefix) and len(part) > len(prefix) and part[len(prefix)].isupper()
                   for prefix in ("InMemory", "Mock", "Fake", "Stub", "Dummy", "Fixed")):
                confidence -= 40
                break
            if any(part.endswith(suffix) for suffix in ("Mock", "Stub", "Fake", "Double")):
                confidence -= 40
                break

    if def_obj.type in ("method", "parameter") and "." in def_obj.name:
        parts = def_obj.name.split(".")
        protocol_classes = getattr(framework, 'protocol_classes', set())
        for part in parts[:-1]:
            if part in protocol_classes:
                def_obj.confidence = 0
                def_obj.skip_reason = "Protocol class member"
                return

    if def_obj.type == "method" and "." in def_obj.name:
        parts = def_obj.name.split(".")
        method_name = parts[-1]
        
        abc_implementers = {**getattr(analyzer, '_global_abc_implementers', {}), 
                           **getattr(framework, 'abc_implementers', {})}
        abstract_methods = {**getattr(analyzer, '_global_abstract_methods', {}), 
                           **getattr(framework, 'abstract_methods', {})}
        
        for part in parts[:-1]:
            if part in abc_implementers:
                parent_abcs = abc_implementers[part]
                for parent_abc in parent_abcs:
                    if parent_abc in abstract_methods:
                        if method_name in abstract_methods[parent_abc]:
                            def_obj.confidence = 0
                            def_obj.skip_reason = f"Implements abstract method from {parent_abc}"
                            return

    if def_obj.type == "method" and "." in def_obj.name:
        parts = def_obj.name.split(".")
        protocol_implementers = {**getattr(analyzer, '_global_protocol_implementers', {}),
                                 **getattr(framework, 'protocol_implementers', {})}
        
        for part in parts[:-1]:
            if part in protocol_implementers:
                def_obj.confidence = 0
                def_obj.skip_reason = "Protocol implementer method"
                return

    if def_obj.type == "method" and "." in def_obj.name:
        parts = def_obj.name.split(".")
        for part in parts[:-1]:
            if part.endswith("Mixin"):
                confidence -= 60
                break

    if def_obj.type == "method":
        if simple_name.startswith("on_") and len(simple_name) > 3:
            confidence -= 30
        elif simple_name == "compose":
            confidence -= 40
        elif simple_name.startswith("watch_") and len(simple_name) > 6:
            confidence -= 30

    if def_obj.type == "parameter" and "." in def_obj.name:
        parts = def_obj.name.split(".")
        if len(parts) >= 2:
            if len(parts) >= 3:
                class_name = parts[-3]
            else:
                class_name = ""

            if class_name.startswith("Base") or class_name.endswith(
                ("Base", "ABC", "Interface", "Adapter")
            ):
                def_obj.confidence = 0
                return

    if "." in def_obj.name:
        owner, attr = def_obj.name.rsplit(".", 1)
        owner_simple = owner.split(".")[-1]

        if (
            owner_simple == "Settings"
            or owner_simple == "Config"
            or owner_simple.endswith("Settings")
            or owner_simple.endswith("Config")
        ):
            if attr.isupper() or not attr.startswith("_"):
                def_obj.confidence = 0
                return

    if def_obj.type == "variable" and "." in def_obj.name:
        parts = def_obj.name.split(".")
        var_name = parts[-1]
        if var_name.isupper() and len(var_name) > 1:
            def_obj.confidence = 0
            def_obj.skip_reason = "SCREAMING_CASE class constant"
            return

    if simple_name.startswith("_") and not simple_name.startswith("__"):
        confidence -= PENALTIES["private_name"]

    if simple_name.startswith("__") and simple_name.endswith("__"):
        confidence -= PENALTIES["dunder_or_magic"]

    if def_obj.in_init and def_obj.type in ("function", "class"):
        confidence -= PENALTIES["in_init_file"]

    if def_obj.name.split(".")[0] in analyzer.dynamic:
        confidence -= PENALTIES["dynamic_module"]

    if visitor.is_test_file or def_obj.line in visitor.test_decorated_lines:
        confidence -= PENALTIES["test_related"]

    if def_obj.type == "variable" and getattr(framework, "dataclass_fields", None):
        if def_obj.name in framework.dataclass_fields:
            def_obj.confidence = 0
            return

    if def_obj.type == "variable" and "." in def_obj.name:
        prefix = def_obj.name.rsplit(".", 1)[0]
        parent_simple = prefix.split(".")[-1]
        if parent_simple in getattr(framework, "namedtuple_classes", set()):
            def_obj.confidence = 0
            def_obj.skip_reason = "NamedTuple field"
            return

    if def_obj.type == "variable" and "." in def_obj.name:
        prefix = def_obj.name.rsplit(".", 1)[0]
        parent_simple = prefix.split(".")[-1]
        if parent_simple in getattr(framework, "enum_classes", set()):
            def_obj.confidence = 0
            def_obj.skip_reason = "Enum member"
            return

    if def_obj.type == "variable" and "." in def_obj.name:
        prefix = def_obj.name.rsplit(".", 1)[0]
        parent_simple = prefix.split(".")[-1]
        if parent_simple in getattr(framework, "attrs_classes", set()):
            def_obj.confidence = 0
            def_obj.skip_reason = "attrs field"
            return

    if def_obj.type == "variable" and "." in def_obj.name:
        prefix = def_obj.name.rsplit(".", 1)[0]
        parent_simple = prefix.split(".")[-1]
        if parent_simple in getattr(framework, "orm_model_classes", set()):
            def_obj.confidence = 0
            def_obj.skip_reason = "ORM model column"
            return

    if def_obj.type == "variable":
        if def_obj.simple_name in getattr(framework, "type_alias_names", set()):
            def_obj.confidence = 0
            def_obj.skip_reason = "Type alias"
            return
        
    if def_obj.type == "variable" and "." in def_obj.name:
        prefix, _ = def_obj.name.rsplit(".", 1)

        cls_def = analyzer.defs.get(prefix)
        if cls_def and cls_def.type == "class":
            cls_simple = cls_def.simple_name

            if (
                getattr(framework, "pydantic_models", None)
                and cls_simple in framework.pydantic_models
            ):
                def_obj.confidence = 0
                return

            cls_node = getattr(framework, "class_defs", {}).get(cls_simple)
            if cls_node is not None:
                schema_like = False

                for base in cls_node.bases:
                    if isinstance(base, ast.Name) and base.id.lower().endswith(
                        ("schema", "model")
                    ):
                        schema_like = True
                        break

                    if isinstance(
                        base, ast.Attribute
                    ) and base.attr.lower().endswith(("schema", "model")):
                        schema_like = True
                        break

                if schema_like:
                    def_obj.confidence = 0
                    return

    if def_obj.type == "variable":
        fr = getattr(framework, "first_read_lineno", {}).get(def_obj.name)
        if fr is not None and fr >= def_obj.line:
            def_obj.confidence = 0
            return

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

            def_obj.confidence = 0
            return

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

    if visitor.is_test_file or def_obj.line in visitor.test_decorated_lines:
        confidence = 0

    if (
        def_obj.type == "import"
        and def_obj.name.startswith("__future__.")
        and simple_name
        in (
            "annotations",
            "absolute_import",
            "division",
            "print_function",
            "unicode_literals",
            "generator_stop",
        )
    ):
        confidence = 0

    if def_obj.type == "method" and confidence > 0:
        method_name = def_obj.simple_name
        abstract_methods = getattr(analyzer, '_global_abstract_methods', {})
        
        for abc_class, methods in abstract_methods.items():
            if method_name in methods:
                confidence -= 40
                break
        
    if def_obj.type == "method" and "." in def_obj.name:
        parts = def_obj.name.split(".")
        duck_typed = getattr(analyzer, '_duck_typed_implementers', set())
        
        for part in parts[:-1]:
            if part in duck_typed:
                def_obj.confidence = 0
                def_obj.skip_reason = "Duck-typed Protocol implementation"
                return

    def_obj.confidence = max(confidence, 0)