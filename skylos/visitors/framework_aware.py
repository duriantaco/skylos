import ast
import fnmatch
from collections import defaultdict
from pathlib import Path
from typing import Any
from collections.abc import Iterator

FRAMEWORK_DECORATORS = [
    "@*.route",
    "@*.get",
    "@*.post",
    "@*.put",
    "@*.delete",
    "@*.patch",
    "@*.before_request",
    "@*.after_request",
    "@*.errorhandler",
    "@*.teardown_*",
    "@*.head",
    "@*.options",
    "@*.trace",
    "@*.websocket",
    "@*.middleware",
    "@*.on_event",
    "@*.exception_handler",
    "@*_required",
    "@login_required",
    "@permission_required",
    "django.views.decorators.*",
    "@*.simple_tag",
    "@*.inclusion_tag",
    "@*.filter",
    "@*.tag",
    "@*.register",
    "@validator",
    "@field_validator",
    "@model_validator",
    "@root_validator",
    "@field_serializer",
    "@model_serializer",
    "@computed_field",
    "@*.command",
    "@*.default",
    "@*.callback",
    "@*.result_callback",
    "@*.group",
    "@*.subcommand",
    "@*.main",
    "@shared_task",
    "@*.shared_task",
    "@*.task",
    "@*.signal",
    "@*.lifespan",
    "@pre_load",
    "@post_load",
    "@pre_dump",
    "@post_dump",
    "@validates",
    "@validates_schema",
    "@*.pre_load",
    "@*.post_load",
    "@*.pre_dump",
    "@*.post_dump",
    "@*.validates",
    "@*.validates_schema",
    "@*.listens_for",
    "@listens_for",
    "@*.hookimpl",
    "@hookimpl",
]

FRAMEWORK_FUNCTIONS = [
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "trace",
    "*_queryset",
    "get_queryset",
    "get_object",
    "get_context_data",
    "*_form",
    "form_valid",
    "form_invalid",
    "get_form_*",
]

ENTRY_POINT_DECORATORS = {
    "app.route",
    "app.get",
    "app.post",
    "app.put",
    "app.delete",
    "router.get",
    "router.post",
    "router.put",
    "router.delete",
    "blueprint.route",
    "blueprint.get",
    "blueprint.post",
    "celery.task",
    "shared_task",
    "task",
    "job",
    "click.command",
    "command",
    "pytest.fixture",
    "fixture",
    "receiver",
    "admin.register",
    "on_event",
    "subscriber",
    "listener",
    "handler",
    "app.before_first_request",
    "app.cli.command",
}

FRAMEWORK_IMPORTS = {
    "flask",
    "fastapi",
    "django",
    "django_filters",
    "pluggy",
    "pytest",
    "rest_framework",
    "pydantic",
    "pydantic_settings",
    "celery",
    "starlette",
    "uvicorn",
    "marshmallow",
    "tornado",
    "sanic",
    "aiohttp",
    "falcon",
    "bottle",
    "typer",
    "click",
    "sqlalchemy",
}

ROUTE_METHODS = {
    "route",
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "head",
    "options",
    "trace",
    "websocket",
}

FASTAPI_DEPENDENCY_CALLS = {"Depends", "Security"}
FASTAPI_APP_FACTORIES = {"FastAPI"}
FASTAPI_ROUTER_FACTORIES = {"APIRouter"}
ANNOTATED_NAMES = {"Annotated"}


class FrameworkAwareVisitor:
    def __init__(self, filename: str | Path | None = None) -> None:
        self.is_framework_file = False
        self.detected_frameworks = set()
        self.framework_decorated_lines = set()
        self.func_defs = {}
        self.class_defs = {}
        self.class_method_lines = {}
        self.pydantic_models = set()
        self._mark_functions = set()
        self._mark_classes = set()
        self._mark_dependency_names = set()
        self._fastapi_dependency_call_names = set(FASTAPI_DEPENDENCY_CALLS)
        self._fastapi_app_factory_names = set(FASTAPI_APP_FACTORIES)
        self._fastapi_router_factory_names = set(FASTAPI_ROUTER_FACTORIES)
        self._annotated_names = set(ANNOTATED_NAMES)
        self.declarative_classes = set()
        self._mark_cbv_http_methods = set()
        self._type_refs_in_routes = set()
        self._fastapi_dependency_aliases = defaultdict(set)
        self._fastapi_dependency_alias_refs = set()
        self.objects_with_routes = defaultdict(list)
        self.objects_passed_as_args = set()
        self.objects_created_by_call = set()
        self.django_path_converter_classes = set()
        self._django_register_converter_names = set()
        self._django_urls_aliases = set()
        self._django_root_aliases = set()
        self._function_depth = 0
        self._class_depth = 0

        if filename:
            self._check_framework_imports_in_file(filename)

    def visit(self, node: ast.AST) -> Any:
        method = "visit_" + node.__class__.__name__
        visitor = getattr(self, method, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node: ast.AST) -> None:
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.name.lower()
            bound_name = alias.asname or alias.name.split(".", 1)[0]

            if name == "django":
                self._django_root_aliases.add(bound_name)
            elif name == "django.urls":
                if alias.asname:
                    self._django_urls_aliases.add(alias.asname)
                else:
                    self._django_root_aliases.add("django")

            for fw in FRAMEWORK_IMPORTS:
                if fw in name:
                    self.is_framework_file = True
                    framework_name = name.split(".")[0]
                    self.detected_frameworks.add(framework_name)
                    break

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            module_name = node.module.split(".")[0].lower()
            if module_name in FRAMEWORK_IMPORTS:
                self.is_framework_file = True
                self.detected_frameworks.add(module_name)

            if node.module == "django.urls":
                for alias in node.names:
                    if alias.name == "register_converter":
                        self._django_register_converter_names.add(
                            alias.asname or alias.name
                        )
            elif node.module == "django":
                for alias in node.names:
                    if alias.name == "urls":
                        self._django_urls_aliases.add(alias.asname or alias.name)

            if module_name == "fastapi":
                for alias in node.names:
                    bound_name = alias.asname or alias.name
                    if alias.name in FASTAPI_DEPENDENCY_CALLS:
                        self._fastapi_dependency_call_names.add(bound_name)
                    elif alias.name in FASTAPI_APP_FACTORIES:
                        self._fastapi_app_factory_names.add(bound_name)
                    elif alias.name in FASTAPI_ROUTER_FACTORIES:
                        self._fastapi_router_factory_names.add(bound_name)

            if module_name in {"typing", "typing_extensions"}:
                for alias in node.names:
                    if alias.name in ANNOTATED_NAMES:
                        self._annotated_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.func_defs.setdefault(node.name, node.lineno)
        is_route = False

        for deco in node.decorator_list:
            d = self._normalize_decorator(deco)

            router_name = self._get_router_from_decorator(deco)
            if router_name:
                self.objects_with_routes[router_name].append(node.lineno)
                self.is_framework_file = True
                is_route = True

            if self._matches_framework_pattern(d, FRAMEWORK_DECORATORS):
                self.is_framework_file = True
                self.framework_decorated_lines.add(node.lineno)
                is_route = True

            if self._decorator_base_name_is(deco, "receiver"):
                self.framework_decorated_lines.add(node.lineno)
                self.is_framework_file = True
                is_route = True

            if isinstance(deco, ast.Call):
                dependencies = self._get_keyword_arg(deco, "dependencies")
                if dependencies is not None:
                    self._scan_for_depends(dependencies)

        args_with_defaults = self._iter_args_with_defaults(node)
        for arg, default in args_with_defaults:
            if default is not None:
                self._scan_for_depends(default, fallback=arg.annotation)
            self._scan_for_depends(arg.annotation)

            if arg.annotation:
                alias_name = self._simple_name(arg.annotation)
            else:
                alias_name = None

            if alias_name:
                self._fastapi_dependency_alias_refs.add(alias_name)

        if node.returns:
            self._scan_for_depends(node.returns)

        if is_route:
            self._collect_annotation_type_refs(node)
        self._function_depth += 1
        try:
            self.generic_visit(node)
        finally:
            self._function_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_defs[node.name] = node
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.class_method_lines[(node.name, item.name)] = item.lineno
        bases = self._base_names(node)

        is_view_like = False
        for base in bases:
            for token in ("view", "viewset", "apiview", "handler"):
                if token in base:
                    is_view_like = True
                    break
            if is_view_like:
                break

        is_pydantic = False
        for base in bases:
            if "basemodel" in base or "basesettings" in base:
                is_pydantic = True
                break

        if is_view_like:
            self.is_framework_file = True
            self._mark_cbv_http_methods.add(node.name)

        if is_pydantic:
            self.pydantic_models.add(node.name)
            self.declarative_classes.add(node.name)
            self.is_framework_file = True

        else:
            for base in bases:
                tail = base.split(".")[-1]
                if tail in ("schema", "model"):
                    self.declarative_classes.add(node.name)
                    break

        self._class_depth += 1
        try:
            self.generic_visit(node)
        finally:
            self._class_depth -= 1

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.objects_created_by_call.add(target.id)

        for target in node.targets:
            self._record_fastapi_dependency_alias(target, node.value)

        targets = []
        for t in node.targets:
            if isinstance(t, ast.Name):
                targets.append(t.id)

        if "urlpatterns" in targets:
            self.is_framework_file = True
            for elt in self._iter_list_elts(node.value):
                if isinstance(elt, ast.Call) and self._call_name_endswith(
                    elt, {"path", "re_path"}
                ):
                    view_expr = self._get_posarg(elt, 1)
                    self._mark_view_from_url_pattern(view_expr)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._record_fastapi_dependency_alias(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        route_target = self._get_imperative_route_target(node)
        if route_target is not None:
            self._mark_view_from_url_pattern(route_target)
            self.is_framework_file = True

        callback_target = self._get_imperative_callback_target(node)
        if callback_target is not None:
            self._mark_view_from_url_pattern(callback_target)
            self.is_framework_file = True

        self._scan_fastapi_call_metadata(node)

        if (
            self._function_depth == 0
            and self._class_depth == 0
            and self._is_django_register_converter_call(node.func)
            and node.args
        ):
            cls_name = self._simple_name(node.args[0])
            if cls_name:
                self.django_path_converter_classes.add(cls_name)
                self._mark_classes.add(cls_name)
                self.is_framework_file = True
                self.detected_frameworks.add("django")

        if isinstance(node.func, ast.Attribute) and node.func.attr == "register":
            if len(node.args) >= 2:
                vs = node.args[1]
                cls_name = self._simple_name(vs)
                if cls_name:
                    self._mark_classes.add(cls_name)
                    self._mark_cbv_http_methods.add(cls_name)
                    self.is_framework_file = True
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "connect"
            and node.args
        ):
            func_name = self._simple_name(node.args[0])
            if func_name:
                self._mark_functions.add(func_name)
                self.is_framework_file = True

        for arg in node.args:
            if isinstance(arg, ast.Name):
                self.objects_passed_as_args.add(arg.id)
        for kw in node.keywords:
            if isinstance(kw.value, ast.Name):
                self.objects_passed_as_args.add(kw.value.id)

        self.generic_visit(node)

    def finalize(self) -> None:
        for alias_name in self._fastapi_dependency_alias_refs:
            for dep_name in self._fastapi_dependency_aliases.get(alias_name, ()):
                self._mark_dependency_name(dep_name)

        for dep_name in self._mark_dependency_names:
            if dep_name in self.class_defs:
                self._mark_classes.add(dep_name)
            if dep_name in self.func_defs:
                self._mark_functions.add(dep_name)

        for fname in self._mark_functions:
            if fname in self.func_defs:
                self.framework_decorated_lines.add(self.func_defs[fname])
        for cname in self._mark_classes:
            cls_node = self.class_defs.get(cname)
            if cls_node is not None:
                self.framework_decorated_lines.add(cls_node.lineno)
        for cname in self._mark_cbv_http_methods:
            for meth in (
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "head",
                "options",
                "trace",
                "list",
                "create",
                "retrieve",
                "update",
                "partial_update",
                "destroy",
            ):
                lino = self.class_method_lines.get((cname, meth))
                if lino:
                    self.framework_decorated_lines.add(lino)

        for obj_name, route_lines in self.objects_with_routes.items():
            for line in route_lines:
                self.framework_decorated_lines.add(line)

        typed_models = set()
        for t in self._type_refs_in_routes:
            if t in self.pydantic_models:
                typed_models.add(t)

        self._mark_classes.update(typed_models)
        for cname in typed_models:
            cls_node = self.class_defs.get(cname)
            if cls_node is not None:
                self.framework_decorated_lines.add(cls_node.lineno)

    def _check_framework_imports_in_file(self, filename: str | Path) -> None:
        try:
            content = Path(filename).read_text(encoding="utf-8")
            tree = ast.parse(content)
            for node in ast.iter_child_nodes(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        framework = alias.name.split(".", 1)[0].lower()
                        if framework in FRAMEWORK_IMPORTS:
                            self.is_framework_file = True
                            self.detected_frameworks.add(framework)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    framework = node.module.split(".", 1)[0].lower()
                    if framework in FRAMEWORK_IMPORTS:
                        self.is_framework_file = True
                        self.detected_frameworks.add(framework)
        except (OSError, SyntaxError, UnicodeDecodeError):
            pass

    def _normalize_decorator(self, dec: ast.AST) -> str:
        if isinstance(dec, ast.Call):
            return self._normalize_decorator(dec.func)
        if isinstance(dec, ast.Name):
            return f"@{dec.id}"
        if isinstance(dec, ast.Attribute):
            return f"@{self._attr_to_str(dec)}"
        return "@unknown"

    def _matches_framework_pattern(self, text: str, patterns: list[str]) -> bool:
        text_clean = text.lstrip("@")

        for pattern in patterns:
            pattern_clean = pattern.lstrip("@")
            if fnmatch.fnmatch(text_clean, pattern_clean):
                return True

        return False

    def _decorator_base_name_is(self, dec: ast.AST, name: str) -> bool:
        if isinstance(dec, ast.Call):
            dec = dec.func
        if isinstance(dec, ast.Name):
            return dec.id == name
        if isinstance(dec, ast.Attribute):
            return dec.attr == name or self._attr_to_str(dec).endswith("." + name)
        return False

    def _attr_to_str(self, node: ast.Attribute) -> str:
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)

        parts.reverse()
        return ".".join(parts)

    def _expr_to_str(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return self._attr_to_str(node)
        return ""

    def _is_django_register_converter_call(self, func: ast.AST) -> bool:
        if isinstance(func, ast.Name):
            return func.id in self._django_register_converter_names

        if not isinstance(func, ast.Attribute) or func.attr != "register_converter":
            return False

        receiver = self._expr_to_str(func.value)
        if receiver in self._django_urls_aliases:
            return True
        if receiver == "django.urls":
            return True

        for django_alias in self._django_root_aliases:
            if receiver == f"{django_alias}.urls":
                return True
        return False

    def _base_names(self, node: ast.ClassDef) -> list[str]:
        out = []
        for b in node.bases:
            if isinstance(b, ast.Name):
                out.append(b.id.lower())
            elif isinstance(b, ast.Attribute):
                out.append(self._attr_to_str(b).lower())
        return out

    def _iter_list_elts(self, node: ast.AST) -> Iterator[ast.expr]:
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                yield elt

    def _call_name_endswith(self, call: ast.Call, names: set[str]) -> bool:
        if isinstance(call.func, ast.Name):
            return call.func.id in names
        if isinstance(call.func, ast.Attribute):
            return call.func.attr in names
        return False

    def _get_posarg(self, call: ast.Call, idx: int) -> ast.expr | None:
        return call.args[idx] if len(call.args) > idx else None

    def _iter_args_with_defaults(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> Iterator[tuple[ast.arg, ast.expr | None]]:
        positional = list(node.args.posonlyargs) + list(node.args.args)
        default_offset = len(positional) - len(node.args.defaults)
        for idx, arg in enumerate(positional):
            default_idx = idx - default_offset

            if default_idx >= 0:
                default = node.args.defaults[default_idx]
            else:
                default = None

            yield arg, default

        for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
            yield arg, default

    def _simple_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None

    def _mark_view_from_url_pattern(self, view_expr: ast.AST | None) -> None:
        if view_expr is None:
            return
        if (
            isinstance(view_expr, ast.Call)
            and isinstance(view_expr.func, ast.Attribute)
            and view_expr.func.attr == "as_view"
        ):
            cls_name = self._simple_name(view_expr.func.value)
            if cls_name:
                self._mark_classes.add(cls_name)
                self._mark_cbv_http_methods.add(cls_name)
        else:
            fname = self._simple_name(view_expr)
            if fname:
                if fname in self.class_defs:
                    self._mark_classes.add(fname)
                    self._mark_cbv_http_methods.add(fname)
                else:
                    self._mark_functions.add(fname)

    def _get_keyword_arg(self, call: ast.Call, *names: str) -> ast.expr | None:
        for kw in call.keywords:
            if kw.arg in names:
                return kw.value
        return None

    def _get_imperative_route_target(self, call: ast.Call) -> ast.expr | None:
        if not isinstance(call.func, ast.Attribute):
            return None

        attr = call.func.attr
        frameworks = self.detected_frameworks

        if attr == "add_url_rule":
            if "flask" not in frameworks:
                return None
            target = self._get_keyword_arg(call, "view_func")
            if target is None and len(call.args) >= 3:
                target = call.args[2]
            return target

        if attr in {"add_api_route", "add_api_websocket_route"}:
            if "fastapi" not in frameworks:
                return None
            target = self._get_keyword_arg(call, "endpoint")
            if target is None and len(call.args) >= 2:
                target = call.args[1]
            return target

        if attr == "add_websocket_route":
            if "starlette" not in frameworks:
                return None
            target = self._get_keyword_arg(call, "endpoint")
            if target is None and len(call.args) >= 2:
                target = call.args[1]
            return target

        if attr == "add_route":
            if not frameworks.intersection({"starlette", "sanic", "aiohttp", "falcon"}):
                return None
            target = self._get_keyword_arg(call, "endpoint", "handler", "view_func")
            if target is not None:
                return target
            if "sanic" in frameworks and call.args:
                return call.args[0]
            if len(call.args) >= 2:
                return call.args[1]

        return None

    def _get_imperative_callback_target(self, call: ast.Call) -> ast.expr | None:
        if (
            isinstance(call.func, ast.Call)
            and isinstance(call.func.func, ast.Attribute)
            and call.func.func.attr == "listens_for"
        ):
            frameworks = self.detected_frameworks
            if "sqlalchemy" in frameworks and call.args:
                return call.args[0]

        if not isinstance(call.func, ast.Attribute):
            return None

        attr = call.func.attr
        frameworks = self.detected_frameworks

        if frameworks.intersection({"fastapi", "starlette"}):
            if attr == "add_exception_handler":
                target = self._get_keyword_arg(call, "handler")
                if target is None and len(call.args) >= 2:
                    target = call.args[1]
                return target

        if "sanic" not in frameworks:
            return None

        if attr == "register_listener" and call.args:
            return call.args[0]

        if attr == "register_middleware":
            target = self._get_keyword_arg(call, "middleware")
            if target is not None:
                return target
            if call.args:
                return call.args[0]

        return None

    def _scan_fastapi_call_metadata(self, call: ast.Call) -> None:
        factory_kind = self._fastapi_factory_kind(call.func)

        if factory_kind in {"app", "router"}:
            dependencies = self._get_keyword_arg(call, "dependencies")
            if dependencies is not None:
                self._scan_for_depends(dependencies)

        if factory_kind == "app":
            for callback_kw in ("lifespan",):
                self._mark_named_keyword_callback(call, callback_kw)
            for callback_list_kw in ("on_startup", "on_shutdown"):
                self._mark_keyword_callback_list(call, callback_list_kw)
            self._mark_exception_handler_mapping(call)

        if isinstance(call.func, ast.Attribute):
            if call.func.attr == "include_router":
                dependencies = self._get_keyword_arg(call, "dependencies")
                if dependencies is not None:
                    self._scan_for_depends(dependencies)
            elif call.func.attr in {"add_api_route", "add_api_websocket_route"}:
                dependencies = self._get_keyword_arg(call, "dependencies")
                if dependencies is not None:
                    self._scan_for_depends(dependencies)

    def _mark_named_keyword_callback(self, call: ast.Call, keyword: str) -> None:
        target = self._get_keyword_arg(call, keyword)
        if target is not None:
            self._mark_view_from_url_pattern(target)
            self.is_framework_file = True

    def _mark_keyword_callback_list(self, call: ast.Call, keyword: str) -> None:
        target = self._get_keyword_arg(call, keyword)
        if target is None:
            return
        for elt in self._iter_list_elts(target):
            self._mark_view_from_url_pattern(elt)
            self.is_framework_file = True

    def _mark_exception_handler_mapping(self, call: ast.Call) -> None:
        handlers = self._get_keyword_arg(call, "exception_handlers")
        if not isinstance(handlers, ast.Dict):
            return
        for value in handlers.values:
            if value is not None:
                self._mark_view_from_url_pattern(value)
                self.is_framework_file = True

    def _scan_for_depends(
        self, node: ast.AST | None, fallback: ast.AST | None = None
    ) -> None:
        for dep_name in self._dependency_names_from_node(node, fallback=fallback):
            self._mark_dependency_name(dep_name)

    def _mark_dependency_name(self, dep_name: str | None) -> None:
        if dep_name:
            self._mark_dependency_names.add(dep_name)
            self.is_framework_file = True

    def _dependency_names_from_node(
        self, node: ast.AST | None, fallback: ast.AST | None = None
    ) -> set[str]:
        if node is None:
            return set()

        names = set()

        if isinstance(node, ast.Call) and self._is_fastapi_dependency_call(node):
            dep = None
            if node.args:
                dep = node.args[0]
            else:
                dep = self._get_keyword_arg(node, "dependency")

            if dep is not None:
                dep_name = self._simple_name(dep)
            else:
                dep_name = None

            if dep_name is None and fallback is not None:
                dep_name = self._simple_name(self._annotation_dependency_type(fallback))
            if dep_name:
                names.add(dep_name)
            return names

        if isinstance(node, ast.Subscript) and self._is_annotated_subscript(node):
            parts = self._subscript_elements(node)

            if parts:
                dependency_type = parts[0]
            else:
                dependency_type = fallback

            for meta in parts[1:]:
                names.update(
                    self._dependency_names_from_node(meta, fallback=dependency_type)
                )
            return names

        for child in ast.iter_child_nodes(node):
            names.update(self._dependency_names_from_node(child, fallback=fallback))

        return names

    def _is_fastapi_dependency_call(self, node: ast.Call) -> bool:
        if isinstance(node.func, ast.Name):
            return node.func.id in self._fastapi_dependency_call_names
        if isinstance(node.func, ast.Attribute):
            return node.func.attr in FASTAPI_DEPENDENCY_CALLS
        return False

    def _fastapi_factory_kind(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            if node.id in self._fastapi_app_factory_names:
                return "app"
            if node.id in self._fastapi_router_factory_names:
                return "router"
            return None
        if isinstance(node, ast.Attribute):
            if node.attr in FASTAPI_APP_FACTORIES:
                return "app"
            if node.attr in FASTAPI_ROUTER_FACTORIES:
                return "router"
        return None

    def _is_annotated_subscript(self, node: ast.Subscript) -> bool:
        value = node.value
        if isinstance(value, ast.Name):
            return value.id in self._annotated_names
        if isinstance(value, ast.Attribute):
            return value.attr in ANNOTATED_NAMES
        return False

    def _record_fastapi_dependency_alias(
        self, target: ast.AST, value: ast.AST | None
    ) -> None:
        if not isinstance(target, ast.Name):
            return
        if not isinstance(value, ast.Subscript) or not self._is_annotated_subscript(
            value
        ):
            return
        alias_deps = self._dependency_names_from_node(value)
        if alias_deps:
            self._fastapi_dependency_aliases[target.id].update(alias_deps)

    def _subscript_elements(self, node: ast.Subscript) -> list[ast.AST]:
        slice_node = node.slice
        if isinstance(slice_node, ast.Tuple):
            return list(slice_node.elts)
        return [slice_node]

    def _annotation_dependency_type(self, node: ast.AST) -> ast.AST:
        if isinstance(node, ast.Subscript) and self._is_annotated_subscript(node):
            parts = self._subscript_elements(node)
            if parts:
                return parts[0]
        return node

    def _collect_annotation_type_refs(self, fn: ast.FunctionDef) -> None:
        def collect(t):
            if t is None:
                return

            if isinstance(t, ast.Name):
                self._type_refs_in_routes.add(t.id)
                return

            if isinstance(t, ast.Attribute):
                self._type_refs_in_routes.add(t.attr)
                return

            if isinstance(t, ast.Subscript):
                collect(t.value)
                slice_node = t.slice
                if isinstance(slice_node, ast.Tuple):
                    for element in slice_node.elts:
                        collect(element)
                else:
                    collect(slice_node)
                return

            if isinstance(t, ast.Tuple):
                for element in t.elts:
                    collect(element)

        all_args = []
        all_args.extend(fn.args.args)
        all_args.extend(fn.args.posonlyargs)
        all_args.extend(fn.args.kwonlyargs)

        for arg in all_args:
            collect(arg.annotation)

        if fn.returns:
            collect(fn.returns)

    def _get_router_from_decorator(self, deco: ast.AST) -> str | None:
        if isinstance(deco, ast.Call):
            deco = deco.func

        if isinstance(deco, ast.Attribute):
            if deco.attr in ROUTE_METHODS:
                if isinstance(deco.value, ast.Name):
                    return deco.value.id
        return None


def detect_framework_usage(
    definition: Any, visitor: FrameworkAwareVisitor | None = None
) -> int | None:
    if not visitor:
        return None
    if definition.line in visitor.framework_decorated_lines:
        objects_with_routes = getattr(visitor, "objects_with_routes", None)
        if isinstance(objects_with_routes, dict) and objects_with_routes:
            for obj_name, route_lines in objects_with_routes.items():
                if definition.line in route_lines:
                    objects_passed = getattr(visitor, "objects_passed_as_args", set())
                    objects_created = getattr(visitor, "objects_created_by_call", set())
                    has_evidence = (
                        obj_name in objects_passed or obj_name in objects_created
                    )
                    if not has_evidence:
                        why_reduced = getattr(
                            definition, "why_confidence_reduced", None
                        )
                        if isinstance(why_reduced, list):
                            why_reduced.append("unregistered_router")
                        fw_signals = getattr(definition, "framework_signals", None)
                        if isinstance(fw_signals, list):
                            fw_signals.append(f"route_on_{obj_name}")
                        return 20
        return 0
    return None
