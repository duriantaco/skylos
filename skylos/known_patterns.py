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
    "get_queryset",
    "natural_key",
}
DJANGO_MODEL_BASES = {"Model", "Manager", "QuerySet"}

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
    "ArchiveIndexView",
    "YearArchiveView",
    "MonthArchiveView",
    "DayArchiveView",
    "DateDetailView",
}

DJANGO_ADMIN_METHODS = {
    "get_list_display",
    "get_list_filter",
    "get_search_fields",
    "get_readonly_fields",
    "get_fieldsets",
    "get_fields",
    "get_exclude",
    "get_ordering",
    "get_prepopulated_fields",
    "get_queryset",
    "get_inline_instances",
    "get_urls",
    "get_form",
    "get_changelist",
    "get_changelist_form",
    "get_formsets_with_inlines",
    "has_add_permission",
    "has_change_permission",
    "has_delete_permission",
    "has_view_permission",
    "has_module_permission",
    "save_model",
    "delete_model",
    "save_formset",
    "save_related",
    "formfield_for_dbfield",
    "formfield_for_foreignkey",
    "formfield_for_manytomany",
    "formfield_for_choice_field",
    "response_add",
    "response_change",
    "response_delete",
    "changelist_view",
    "add_view",
    "change_view",
    "delete_view",
    "history_view",
    "lookup_allowed",
}
DJANGO_ADMIN_BASES = {"ModelAdmin", "TabularInline", "StackedInline", "InlineModelAdmin"}

DJANGO_FORM_METHODS = {"clean", "is_valid", "save"}
DJANGO_FORM_BASES = {"Form", "ModelForm", "BaseForm", "BaseModelForm"}

DJANGO_COMMAND_METHODS = {"add_arguments", "handle"}
DJANGO_COMMAND_BASES = {"BaseCommand", "Command"}

DJANGO_APPCONFIG_METHODS = {"ready"}
DJANGO_APPCONFIG_BASES = {"AppConfig"}

DJANGO_MIDDLEWARE_METHODS = {
    "process_request",
    "process_response",
    "process_view",
    "process_exception",
    "process_template_response",
}
DJANGO_MIDDLEWARE_BASES = {"MiddlewareMixin", "SecurityMiddleware", "SessionMiddleware",
                          "CommonMiddleware", "CsrfViewMiddleware", "AuthenticationMiddleware",
                          "MessageMiddleware"}

DJANGO_SIGNAL_METHODS = {
    "pre_save",
    "post_save",
    "pre_delete",
    "post_delete",
    "m2m_changed",
    "pre_init",
    "post_init",
    "pre_migrate",
    "post_migrate",
    "request_started",
    "request_finished",
    "got_request_exception",
}

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
    "get_serializer_context",
    "perform_create",
    "perform_update",
    "perform_destroy",
    "get_permissions",
    "get_throttles",
    "get_authenticators",
    "get_renderers",
    "get_parsers",
    "get_paginated_response",
    "paginate_queryset",
    "filter_queryset",
    "get_exception_handler",
    "initial",
    "finalize_response",
    "permission_denied",
    "throttled",
}
DRF_VIEWSET_BASES = {"APIView", "ViewSet", "ModelViewSet", "GenericViewSet",
                     "GenericAPIView", "CreateAPIView", "ListAPIView",
                     "RetrieveAPIView", "DestroyAPIView", "UpdateAPIView",
                     "ListCreateAPIView", "RetrieveUpdateAPIView",
                     "RetrieveDestroyAPIView", "RetrieveUpdateDestroyAPIView"}

DRF_SERIALIZER_METHODS = {
    "to_representation",
    "to_internal_value",
    "validate",
    "create",
    "update",
    "save",
    "is_valid",
    "run_validators",
    "get_fields",
    "get_validators",
    "get_initial",
    "get_value",
}
DRF_SERIALIZER_BASES = {"Serializer", "ModelSerializer", "ListSerializer",
                        "BaseSerializer", "HyperlinkedModelSerializer"}

DRF_PERMISSION_METHODS = {"has_permission", "has_object_permission"}
DRF_PERMISSION_BASES = {"BasePermission"}

STARLETTE_MIDDLEWARE_METHODS = {"dispatch"}
STARLETTE_MIDDLEWARE_BASES = {
    "BaseHTTPMiddleware",
    "HTTPMiddleware",
}

FASTAPI_CBVROUTER_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
}
FASTAPI_CBVROUTER_BASES = {"APIRouter", "CBVRouter"}

CELERY_TASK_METHODS = {"run"}
CELERY_TASK_BASES = {"Task", "BaseTask"}

CLICK_COMMAND_METHODS = {"invoke"}
CLICK_COMMAND_BASES = {"BaseCommand", "Command", "Group", "MultiCommand"}

PYDANTIC_MODEL_METHODS = {
    "model_post_init",
    "model_validate",
    "model_dump",
}
PYDANTIC_MODEL_BASES = {"BaseModel", "BaseSettings"}

PYDANTIC_VALIDATOR_DECORATORS = {
    "validator",
    "field_validator",
    "model_validator",
    "root_validator",
    "field_serializer",
    "model_serializer",
    "computed_field",
}

SQLALCHEMY_MODEL_METHODS = {
    "__tablename__",
}
SQLALCHEMY_MODEL_BASES = {"Base", "DeclarativeBase"}

FLASK_RESTFUL_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
}
FLASK_RESTFUL_BASES = {"Resource", "MethodView"}

MARSHMALLOW_METHODS = {
    "load",
    "dump",
    "dumps",
    "loads",
}
MARSHMALLOW_HOOK_DECORATORS = {
    "pre_load",
    "post_load",
    "pre_dump",
    "post_dump",
    "validates",
    "validates_schema",
}

TORNADO_HANDLER_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "prepare",
    "on_finish",
    "on_connection_close",
    "write_error",
}
TORNADO_HANDLER_BASES = {"RequestHandler", "WebSocketHandler"}

STARLETTE_ENDPOINT_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
}
STARLETTE_ENDPOINT_BASES = {"HTTPEndpoint", "WebSocketEndpoint"}

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
