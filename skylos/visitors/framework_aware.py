import ast
import fnmatch
from collections import defaultdict
from pathlib import Path

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
    "@validator",
    "@field_validator",
    "@model_validator",
    "@root_validator",
    "@field_serializer",
    "@model_serializer",
    "@computed_field",
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
}

FRAMEWORK_IMPORTS = {
    "flask",
    "fastapi",
    "django",
    "rest_framework",
    "pydantic",
    "celery",
    "starlette",
    "uvicorn",
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


class FrameworkAwareVisitor:
    def __init__(self, filename=None):
        self.is_framework_file = False
        self.detected_frameworks = set()
        self.framework_decorated_lines = set()
        self.func_defs = {}
        self.class_defs = {}
        self.class_method_lines = {}
        self.pydantic_models = set()
        self._mark_functions = set()
        self._mark_classes = set()
        self.declarative_classes = set()
        self._mark_cbv_http_methods = set()
        self._type_refs_in_routes = set()
        self.objects_with_routes = defaultdict(list)
        self.objects_passed_as_args = set()
        self.objects_created_by_call = set()

        if filename:
            self._check_framework_imports_in_file(filename)

    def visit(self, node):
        method = "visit_" + node.__class__.__name__
        visitor = getattr(self, method, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node):
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.name.lower()

            for fw in FRAMEWORK_IMPORTS:
                if fw in name:
                    self.is_framework_file = True
                    framework_name = name.split(".")[0]
                    self.detected_frameworks.add(framework_name)
                    break

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            module_name = node.module.split(".")[0].lower()
            if module_name in FRAMEWORK_IMPORTS:
                self.is_framework_file = True
                self.detected_frameworks.add(module_name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
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

        defaults_to_scan = []
        if node.args.defaults:
            defaults_to_scan.extend(node.args.defaults)
        if node.args.kw_defaults:
            defaults_to_scan.extend(node.args.kw_defaults)

        for default in defaults_to_scan:
            self._scan_for_depends(default)

        if is_route:
            self._collect_annotation_type_refs(node)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef):
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
            if "basemodel" in base:
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

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        if isinstance(node.value, ast.Call):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.objects_created_by_call.add(target.id)

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

    def visit_Call(self, node: ast.Call):
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

    def finalize(self):
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

    def _check_framework_imports_in_file(self, filename):
        try:
            content = Path(filename).read_text(encoding="utf-8")

            for framework in FRAMEWORK_IMPORTS:
                import_statement = f"import {framework}"
                from_statement = f"from {framework}"

                has_import = import_statement in content
                has_from_import = from_statement in content

                if has_import or has_from_import:
                    self.is_framework_file = True
                    self.detected_frameworks.add(framework)
                    break

        except Exception:
            pass

    def _normalize_decorator(self, dec: ast.AST):
        if isinstance(dec, ast.Call):
            return self._normalize_decorator(dec.func)
        if isinstance(dec, ast.Name):
            return f"@{dec.id}"
        if isinstance(dec, ast.Attribute):
            return f"@{self._attr_to_str(dec)}"
        return "@unknown"

    def _matches_framework_pattern(self, text, patterns):
        text_clean = text.lstrip("@")

        for pattern in patterns:
            pattern_clean = pattern.lstrip("@")
            if fnmatch.fnmatch(text_clean, pattern_clean):
                return True

        return False

    def _decorator_base_name_is(self, dec: ast.AST, name):
        if isinstance(dec, ast.Call):
            dec = dec.func
        if isinstance(dec, ast.Name):
            return dec.id == name
        if isinstance(dec, ast.Attribute):
            return dec.attr == name or self._attr_to_str(dec).endswith("." + name)
        return False

    def _attr_to_str(self, node: ast.Attribute):
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)

        parts.reverse()
        return ".".join(parts)

    def _base_names(self, node: ast.ClassDef):
        out = []
        for b in node.bases:
            if isinstance(b, ast.Name):
                out.append(b.id.lower())
            elif isinstance(b, ast.Attribute):
                out.append(self._attr_to_str(b).lower())
        return out

    def _iter_list_elts(self, node: ast.AST):
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                yield elt

    def _call_name_endswith(self, call: ast.Call, names):
        if isinstance(call.func, ast.Name):
            return call.func.id in names
        if isinstance(call.func, ast.Attribute):
            return call.func.attr in names
        return False

    def _get_posarg(self, call: ast.Call, idx):
        return call.args[idx] if len(call.args) > idx else None

    def _simple_name(self, node: ast.AST):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None

    def _mark_view_from_url_pattern(self, view_expr):
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
                self._mark_functions.add(fname)

    def _scan_for_depends(self, node):
        if not isinstance(node, ast.Call):
            return
        is_depends = False
        if isinstance(node.func, ast.Name) and node.func.id == "Depends":
            is_depends = True
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "Depends":
            is_depends = True
        if not is_depends:
            return
        if node.args:
            dep = node.args[0]
            dep_name = self._simple_name(dep)
            if dep_name:
                self._mark_functions.add(dep_name)
                self.is_framework_file = True

    def _collect_annotation_type_refs(self, fn: ast.FunctionDef):
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

    def _get_router_from_decorator(self, deco):
        if isinstance(deco, ast.Call):
            deco = deco.func

        if isinstance(deco, ast.Attribute):
            if deco.attr in ROUTE_METHODS:
                if isinstance(deco.value, ast.Name):
                    return deco.value.id
        return None


def detect_framework_usage(definition, visitor=None):
    if not visitor:
        return None
    if definition.line in visitor.framework_decorated_lines:
        return 1
    return None
