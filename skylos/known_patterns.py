import fnmatch

HARD_ENTRYPOINTS = {
    "__new__",
    "__init__",
    "__del__",
    "__repr__",
    "__str__",
    "__bytes__",
    "__format__",
    "__lt__",
    "__le__",
    "__eq__",
    "__ne__",
    "__gt__",
    "__ge__",
    "__hash__",
    "__bool__",
    "__getattr__",
    "__getattribute__",
    "__setattr__",
    "__delattr__",
    "__dir__",
    "__get__",
    "__set__",
    "__delete__",
    "__set_name__",
    "__init_subclass__",
    "__class_getitem__",
    "__len__",
    "__length_hint__",
    "__getitem__",
    "__setitem__",
    "__delitem__",
    "__missing__",
    "__iter__",
    "__next__",
    "__reversed__",
    "__contains__",
    "__enter__",
    "__exit__",
    "__aenter__",
    "__aexit__",
    "__call__",
    "__await__",
    "__aiter__",
    "__anext__",
    "__add__",
    "__sub__",
    "__mul__",
    "__truediv__",
    "__floordiv__",
    "__mod__",
    "__pow__",
    "__matmul__",
    "__radd__",
    "__rsub__",
    "__rmul__",
    "__iadd__",
    "__neg__",
    "__pos__",
    "__abs__",
    "__invert__",
    "__int__",
    "__float__",
    "__index__",
    "__round__",
    "__reduce__",
    "__reduce_ex__",
    "__getstate__",
    "__setstate__",
    "__copy__",
    "__deepcopy__",
    "__post_init__",
    "__attrs_post_init__",
    "__attrs_pre_init__",
    "__fspath__",
}

PYTEST_HOOKS = {
    "pytest_configure",
    "pytest_unconfigure",
    "pytest_addoption",
    "pytest_collection_modifyitems",
    "pytest_collection_finish",
    "pytest_runtest_setup",
    "pytest_runtest_teardown",
    "pytest_runtest_makereport",
    "pytest_generate_tests",
    "pytest_fixture_setup",
    "pytest_sessionstart",
    "pytest_sessionfinish",
    "pytest_report_header",
    "pytest_terminal_summary",
    "pytest_runtest_protocol",
    "pytest_runtest_call",
    "pytest_pyfunc_call",
}

UNITTEST_METHODS = {
    "setUp",
    "tearDown",
    "setUpClass",
    "tearDownClass",
    "setUpModule",
    "tearDownModule",
}

DJANGO_MODEL_METHODS = {
    "save",
    "delete",
    "clean",
    "clean_fields",
    "validate_unique",
    "full_clean",
    "get_absolute_url",
}
DJANGO_MODEL_BASES = {"Model"}

DJANGO_VIEW_METHODS = {
    "dispatch",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "get_queryset",
    "get_object",
    "get_context_data",
    "get_template_names",
    "get_form",
    "get_form_class",
    "get_form_kwargs",
    "get_success_url",
    "form_valid",
    "form_invalid",
}
DJANGO_VIEW_BASES = {
    "View",
    "TemplateView",
    "ListView",
    "DetailView",
    "CreateView",
    "UpdateView",
    "DeleteView",
    "FormView",
    "RedirectView",
}

DJANGO_ADMIN_METHODS = {
    "get_list_display",
    "get_list_filter",
    "get_search_fields",
    "get_readonly_fields",
    "has_add_permission",
    "has_change_permission",
    "has_delete_permission",
    "has_view_permission",
    "save_model",
    "delete_model",
}
DJANGO_ADMIN_BASES = {"ModelAdmin"}

DJANGO_FORM_METHODS = {"clean"}
DJANGO_FORM_BASES = {"Form", "ModelForm"}

DJANGO_COMMAND_METHODS = {"add_arguments", "handle"}
DJANGO_COMMAND_BASES = {"BaseCommand"}

DJANGO_APPCONFIG_METHODS = {"ready"}
DJANGO_APPCONFIG_BASES = {"AppConfig"}

DRF_VIEWSET_METHODS = {
    "list",
    "create",
    "retrieve",
    "update",
    "partial_update",
    "destroy",
    "get_queryset",
    "get_object",
    "get_serializer",
    "get_serializer_class",
    "perform_create",
    "perform_update",
    "perform_destroy",
}
DRF_VIEWSET_BASES = {"APIView", "ViewSet", "ModelViewSet", "GenericViewSet"}

DRF_SERIALIZER_METHODS = {
    "to_representation",
    "to_internal_value",
    "validate",
    "create",
    "update",
}
DRF_SERIALIZER_BASES = {"Serializer", "ModelSerializer"}

DRF_PERMISSION_METHODS = {"has_permission", "has_object_permission"}
DRF_PERMISSION_BASES = {"BasePermission"}

SOFT_PATTERNS = [
    ("test_*", 40, "test_file"),
    ("*_test", 40, "test_file"),
    ("clean_*", 25, "django"),
    ("validate_*", 20, "django"),
    ("handle_*", 15, None),
    ("*_handler", 15, None),
    ("*_callback", 15, None),
    ("on_*", 10, None),
    ("setup_*", 15, None),
    ("teardown_*", 15, None),
    ("*Plugin", 20, None),
    ("pytest_*", 30, None),
    ("visit_*", 20, None),
    ("leave_*", 20, None),
]


def matches_pattern(name, pattern):
    return fnmatch.fnmatchcase(name, pattern)


def has_base_class(def_obj, required_bases, framework):
    if def_obj.type != "method":
        return False

    parts = def_obj.name.rsplit(".", 2)
    if len(parts) < 2:
        return False

    class_name = parts[-2]
    class_defs = getattr(framework, "class_defs", {})

    if class_name not in class_defs:
        return False

    cls_node = class_defs[class_name]
    for base in getattr(cls_node, "bases", []):
        base_name = getattr(base, "id", None) or getattr(base, "attr", None)
        if base_name in required_bases:
            return True

    return False
