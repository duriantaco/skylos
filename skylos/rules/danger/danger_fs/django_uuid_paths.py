"""Source-backed UUID values supplied by registered authentication middleware.

An annotation or an attribute named ``uuid`` is insufficient. The proof follows
an installed Starlette backend through its user wrapper to actual Django ORM
results, then checks the model's real UUIDField factory and all visible writes.
"""

from __future__ import annotations

import ast
import copy
from skylos.rules.danger.module_namespace import (
    attribute_write_names,
    module_rebinding,
    module_name_for,
)

_MODEL_BASES = {
    "django.db.models.Model",
    "django.contrib.auth.models.AbstractUser",
    "django.contrib.auth.base_user.AbstractBaseUser",
}
_QUERY = {
    "filter",
    "exclude",
    "all",
    "select_related",
    "prefetch_related",
    "order_by",
    "using",
    "select_for_update",
}
_ONE = {
    "get",
    "aget",
    "first",
    "afirst",
    "last",
    "alast",
    "create",
    "acreate",
    "create_user",
}
_PAIR = {"get_or_create", "aget_or_create", "update_or_create", "aupdate_or_create"}
_UUID = {"uuid.uuid1", "uuid.uuid3", "uuid.uuid4", "uuid.uuid5", "uuid.UUID"}


class DjangoUUIDPaths:
    def __init__(self, tracer):
        self.tracer = tracer
        self.project = tracer.project
        self.active = set()
        self.work = 0
        self._backends = None
        self._attribute_writes = None
        self._app_origins = set()
        self._uuid_names = None
        self._proved_models = set()
        self._namespace_cache = {}

    def _namespace(self, unit):
        state = self._namespace_cache.get(id(unit))
        if state is not None:
            return state
        state = unit.rebinding()
        if state[0] and any(
            isinstance(node, ast.keyword)
            and node.arg is None
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "__dict__"
            for node in ast.walk(unit.tree)
        ):
            # Expanding **obj.__dict__ copies keyword entries. It does not
            # expose the dictionary itself for mutation by the callee.
            class CopiedKeywords(ast.NodeTransformer):
                def visit_keyword(self, node):
                    if (
                        node.arg is None
                        and isinstance(node.value, ast.Attribute)
                        and node.value.attr == "__dict__"
                    ):
                        node.value = ast.copy_location(
                            ast.Dict(keys=[], values=[]), node.value
                        )
                    return self.generic_visit(node)

            tree = CopiedKeywords().visit(copy.deepcopy(unit.tree))
            state = module_rebinding(tree, module_name_for(unit.path))
        self._namespace_cache[id(unit)] = state
        return state

    def _values(self, unit, scope, expr):
        return self.project.values(unit, scope, expr)

    def _external(self, unit, scope, expr, names):
        # A class assignment's new name is unavailable while its RHS is being
        # evaluated: ``uuid = UUIDField(default=uuid.uuid4)`` reads the import.
        root = expr
        while isinstance(root, ast.Attribute):
            root = root.value
        dynamic, rebound = self._namespace(unit)
        if dynamic or (isinstance(root, ast.Name) and root.id in rebound):
            return False
        if scope.kind == "class" and isinstance(root, ast.Name):
            binds = scope.binds.get(root.id, ())
            if (
                len(binds) == 1
                and binds[0].kind == "assign"
                and expr in ast.walk(binds[0].value)
            ):
                scope = scope.parent
        values = self._values(unit, scope, expr)
        if self._attribute_writes is None:
            writes = set()
            computed = set()
            for source in self.project.units:
                if source.is_test:
                    continue
                attr_names, unknown = attribute_write_names(source.tree)
                writes.update(attr_names)
                if unknown:
                    computed.add(id(source))
            self._attribute_writes = writes, computed
        writes, computed = self._attribute_writes
        if id(unit) in computed:
            return False
        return bool(values) and all(
            value.kind == "ext"
            and value.name in names
            and value.name.rsplit(".", 1)[-1] not in writes
            and not self.tracer._external_rebound(value.name)
            for value in values
        )

    def _model(self, cls):
        order, external = self.project.mro(cls)
        provider_base = any(
            self._external(
                unit, self.project.class_info[id(base)][1], parent, _MODEL_BASES
            )
            for unit, base in order
            for parent in base.bases
        )
        return (
            provider_base
            and not any(base.decorator_list for _, base in order)
            and not any(
                any(
                    isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and n.name
                    in {
                        "__getattr__",
                        "__getattribute__",
                        "__new__",
                        "__setattr__",
                        "__init__",
                        "from_db",
                    }
                    for n in base.body
                )
                for _, base in order
            )
        )

    def _field(self, cls, name):
        order, _ = self.project.mro(cls)
        for unit, base in order:
            declared = unit.class_scopes[id(base)].binds.get(name, ())
            if declared and (len(declared) != 1 or declared[0].kind != "assign"):
                return None
            matches = []
            for node in base.body:
                targets = (
                    node.targets
                    if isinstance(node, ast.Assign)
                    else [node.target]
                    if isinstance(node, ast.AnnAssign)
                    else []
                )
                if any(
                    isinstance(target, ast.Name) and target.id == name
                    for target in targets
                ):
                    matches.append(node)
            if matches:
                if len(matches) != 1 or not isinstance(matches[0].value, ast.Call):
                    return None
                return unit, unit.scope_of(matches[0].value), matches[0].value
        return None

    def _uuid_field(self, cls, name):
        field = self._field(cls, name)
        if not field:
            return False
        unit, scope, call = field
        if not self._external(unit, scope, call.func, {"django.db.models.UUIDField"}):
            return False
        options = {kw.arg: kw.value for kw in call.keywords}
        if not (
            isinstance(options.get("editable"), ast.Constant)
            and options["editable"].value is False
        ):
            return False
        default = options.get("default")
        if not self._external(unit, scope, default, _UUID - {"uuid.UUID"}):
            return False
        # An arbitrary write would defeat the field/provider proof, including
        # an assignment between fetching the model and constructing the path.
        for (
            owner,
            target,
            value,
            statement,
            write_scope,
        ) in self.project.attr_stores.get(name, ()):
            if owner.is_test:
                continue
            if not self._uuid_value(owner, write_scope, value):
                return False
        return True

    def _uuid_value(self, unit, scope, value, depth=0):
        if depth > 8:
            return False
        if isinstance(value, ast.Call):
            return self._external(unit, scope, value.func, _UUID)
        if isinstance(value, ast.Name):
            found = unit.lookup(scope, value.id)
            if found is None:
                return False
            binds = self.tracer._visible_binds(unit, found[0], found[1], value)
            return bool(binds) and all(
                bind.kind == "assign"
                and self._uuid_value(unit, bind.scope, bind.value, depth + 1)
                for bind in binds
            )
        return False

    def _classes(self, unit, scope, expr):
        if self._namespace(unit)[0]:
            return None
        values = self._values(unit, scope, expr)
        if not values or any(
            value.kind != "cls"
            or self._namespace(value.unit)[0]
            or (
                self._attribute_writes is not None
                and value.node.name in self._attribute_writes[0]
            )
            for value in values
        ):
            return None
        return {value.node for value in values}

    def _registered_backends(self):
        if self._backends is not None:
            return self._backends
        backends = []
        for unit in self.project.units:
            if unit.is_test:
                continue
            for call, scope in unit.calls:
                if not (
                    isinstance(call.func, ast.Attribute)
                    and call.func.attr == "add_middleware"
                    and call.args
                ):
                    continue
                if not self._external(
                    unit,
                    scope,
                    call.args[0],
                    {"starlette.middleware.authentication.AuthenticationMiddleware"},
                ):
                    continue
                if "add_middleware" in self._attribute_writes[0]:
                    self._backends = []
                    return []
                applications = self._factory_origins(
                    unit,
                    scope,
                    call.func.value,
                    {"fastapi.FastAPI", "starlette.applications.Starlette"},
                )
                if not applications:
                    self._backends = []
                    return []
                self._app_origins.update(applications)
                backend = next(
                    (kw.value for kw in call.keywords if kw.arg == "backend"), None
                )
                classes = (
                    self._classes(unit, scope, backend.func)
                    if isinstance(backend, ast.Call)
                    else None
                )
                if classes is None:
                    self._backends = []
                    return []
                backends.extend(classes)
        self._backends = backends
        return backends

    def _wrapper_argument(self, unit, scope, call, field):
        classes = self._classes(unit, scope, call.func)
        if not classes or len(classes) != 1:
            return None
        cls = next(iter(classes))
        order, external = self.project.mro(cls)
        if "starlette.authentication.SimpleUser" not in external:
            return None
        stores = []
        for class_unit, base in order:
            if base.decorator_list or field in class_unit.class_scopes[id(base)].binds:
                return None
            if any(
                isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name in {"__getattr__", "__getattribute__", "__new__"}
                for n in base.body
            ):
                return None
            for target, value, statement, store_scope in class_unit.attribute_stores:
                if (
                    target.attr == field
                    and self.tracer._self_class(class_unit, store_scope, target.value)
                    is base
                ):
                    stores.append((class_unit, target, value, store_scope))
        if len(stores) != 1:
            return None
        if any(
            target is not stores[0][1]
            for source, target, _, _, _ in self.project.attr_stores.get(field, ())
            if not source.is_test
        ):
            return None
        _, _, value, store_scope = stores[0]
        fn = store_scope.node
        if fn.name != "__init__" or not isinstance(value, ast.Name):
            return None
        params = [*fn.args.posonlyargs, *fn.args.args]
        index = next(
            (i - 1 for i, param in enumerate(params) if param.arg == value.id), -1
        )
        if index < 0:
            return None
        if index < len(call.args):
            return call.args[index]
        return next((kw.value for kw in call.keywords if kw.arg == value.id), None)

    def _provided_model(self, model, field):
        if (id(model), field) in self._proved_models:
            return True
        backends = self._registered_backends()
        # A global proof must not borrow a differently configured application's
        # authentication backend. Multiple registrations require app resolution.
        if len(backends) != 1:
            return False
        backend = backends[0]
        order, external = self.project.mro(backend)
        if "starlette.authentication.AuthenticationBackend" not in external:
            return False
        if self.project.attr_stores.get("authenticate") or any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name
            in {"__new__", "__getattribute__", "__getattr__", "__setattr__"}
            for _, base in order
            for node in base.body
        ):
            return False
        methods = [
            (unit, node)
            for unit, base in order
            for node in base.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "authenticate"
        ]
        if len(methods) != 1:
            return False
        unit, fn = methods[0]
        found = False
        for returned in self.project.returned_values(fn):
            if (
                not isinstance(returned, (ast.Tuple, ast.List))
                or len(returned.elts) != 2
            ):
                if isinstance(returned, ast.Constant) and returned.value is None:
                    continue
                if isinstance(returned, ast.Call) and self._external(
                    unit,
                    unit.scope_of(returned),
                    returned.func,
                    {"fastapi.Response", "starlette.responses.Response"},
                ):
                    continue
                return False
            user = returned.elts[1]
            if not isinstance(user, ast.Call):
                return False
            if self._external(
                unit,
                unit.scope_of(user),
                user.func,
                {"starlette.authentication.UnauthenticatedUser"},
            ):
                continue
            payload = self._wrapper_argument(unit, unit.scope_of(user), user, field)
            if payload is None:
                return False
            types = self._types(unit, unit.scope_of(payload), payload)
            if not types or any(
                cls is not model or kind != "record" for cls, kind in types
            ):
                return False
            found = True
        if found:
            self._proved_models.add((id(model), field))
        return found

    def _request_model(self, unit, scope, bind):
        node = bind.node
        value = bind.value
        if not (
            isinstance(node, ast.AnnAssign)
            and isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Attribute)
            and value.value.attr == "user"
            and isinstance(value.value.value, ast.Name)
        ):
            return None
        request = value.value.value
        found = unit.lookup(scope, request.id)
        if not found or len(found[1]) != 1 or found[1][0].kind != "param":
            return None
        fn = found[0].node
        request_param = found[1][0].node
        info = self.project.function_info.get(id(fn))
        if not info or not self._external(
            unit,
            info[1],
            request_param.annotation,
            {
                "starlette.requests.Request",
                "starlette.requests.HTTPConnection",
                "fastapi.Request",
            },
        ):
            return None
        authenticated = False
        for decorator in fn.decorator_list:
            if isinstance(decorator, ast.Call) and self._external(
                unit, info[1], decorator.func, {"starlette.authentication.requires"}
            ):
                roles = decorator.args[0] if decorator.args else None
                authenticated = isinstance(roles, (ast.List, ast.Tuple)) and any(
                    isinstance(item, ast.Constant) and item.value == "authenticated"
                    for item in roles.elts
                )
                if authenticated:
                    break
        if not authenticated:
            return None
        classes = self._classes(unit, scope, node.annotation)
        if not classes or len(classes) != 1:
            return None
        model = next(iter(classes))
        if (
            self._model(model)
            and self._provided_model(model, value.attr)
            and self._route_attached(unit, info[1], fn)
        ):
            return {(model, "record")}
        return None

    def _types(self, unit, scope, expr, select=None, depth=0):
        self.work += 1
        if expr is None or depth > 40 or self.work > 2048 or self._namespace(unit)[0]:
            return None
        key = (id(expr), id(scope), select)
        if key in self.active:
            return None
        self.active.add(key)
        try:
            return self._types_inner(unit, scope, expr, select, depth)
        finally:
            self.active.remove(key)

    def _types_inner(self, unit, scope, expr, select, depth):
        if isinstance(expr, ast.Constant) and expr.value is None:
            return set()
        if isinstance(expr, ast.Await):
            return self._types(unit, scope, expr.value, select, depth + 1)
        if (
            isinstance(expr, (ast.Tuple, ast.List))
            and select is not None
            and select < len(expr.elts)
        ):
            return self._types(unit, scope, expr.elts[select], None, depth + 1)
        if isinstance(expr, ast.Name):
            found = unit.lookup(scope, expr.id)
            if not found:
                return None
            owner, binds = found
            result = set()
            for bind in self.tracer._visible_binds(unit, owner, binds, expr):
                if bind.kind in {"assign", "unpack"}:
                    request = self._request_model(unit, scope, bind)
                    if request is not None:
                        result |= request
                        continue
                    index = select
                    if bind.kind == "unpack":
                        targets = getattr(bind.node, "targets", [])
                        if len(targets) != 1 or not isinstance(
                            targets[0], (ast.Tuple, ast.List)
                        ):
                            return None
                        index = next(
                            (
                                i
                                for i, item in enumerate(targets[0].elts)
                                if isinstance(item, ast.Name) and item.id == expr.id
                            ),
                            None,
                        )
                        if index is None:
                            return None
                    types = self._types(unit, bind.scope, bind.value, index, depth + 1)
                elif bind.kind == "import":
                    classes = self._classes(unit, scope, expr)
                    types = (
                        {(cls, "class") for cls in classes or () if self._model(cls)}
                        if classes
                        else None
                    )
                else:
                    return None
                if types is None:
                    return None
                result |= types
            return result
        if isinstance(expr, ast.Attribute):
            owner = self.tracer._self_class(unit, scope, expr.value)
            if owner is not None:
                stores = [
                    (u, v, s)
                    for u, t, v, _, s in self.project.attr_stores.get(expr.attr, ())
                    if self.tracer._self_class(u, s, t.value) is owner
                ]
                if len(stores) != 1:
                    return None
                u, value, s = stores[0]
                return self._types(u, s, value, select, depth + 1)
            types = self._types(unit, scope, expr.value, None, depth + 1)
            if not types:
                return None
            result = set()
            for cls, kind in types:
                if (
                    expr.attr == "objects"
                    and kind == "class"
                    and "objects" not in self._attribute_writes[0]
                    and not any(
                        u.class_scopes[id(base)].binds.get("objects")
                        for u, base in self.project.mro(cls)[0]
                    )
                ):
                    result.add((cls, "query"))
                    continue
                field = self._field(cls, expr.attr)
                if kind != "record" or not field:
                    return None
                u, s, call = field
                if (
                    not self._external(
                        u,
                        s,
                        call.func,
                        {
                            "django.db.models.ForeignKey",
                            "django.db.models.OneToOneField",
                        },
                    )
                    or not call.args
                ):
                    return None
                targets = self._classes(u, s, call.args[0])
                if not targets or not all(self._model(target) for target in targets):
                    return None
                result.update((target, "record") for target in targets)
            return result
        if isinstance(expr, ast.Call):
            if (
                isinstance(expr.func, ast.Attribute)
                and expr.func.attr in _QUERY | _ONE | _PAIR
            ):
                receivers = self._types(unit, scope, expr.func.value, None, depth + 1)
                if receivers and all(kind == "query" for _, kind in receivers):
                    method = expr.func.attr
                    if method in self._attribute_writes[0]:
                        return None
                    if method in _PAIR and select != 0:
                        return None
                    return {
                        (cls, "query" if method in _QUERY else "record")
                        for cls, _ in receivers
                    }
            values = self._values(unit, scope, expr.func)
            if not values or any(value.kind != "fn" for value in values):
                return None
            result = set()
            for value in values:
                fn = value.node
                if fn.decorator_list:
                    return None
                for returned in self.project.returned_values(fn):
                    types = self._types(
                        value.unit,
                        value.unit.scope_of(returned),
                        returned,
                        select,
                        depth + 1,
                    )
                    if types is None:
                        return None
                    result |= types
            return result
        return None

    def _factory_origins(self, unit, scope, expr, factories, depth=0, seen=frozenset()):
        if (
            depth > 20
            or expr is None
            or (id(expr), id(scope)) in seen
            or self._namespace(unit)[0]
        ):
            return None
        seen = seen | {(id(expr), id(scope))}
        if isinstance(expr, ast.Call):
            return (
                {id(expr)}
                if self._external(unit, scope, expr.func, factories)
                else None
            )
        if isinstance(expr, ast.Name):
            found = unit.lookup(scope, expr.id)
            if not found:
                return None
            owner, binds = found
            origins = set()
            for bind in self.tracer._visible_binds(unit, owner, binds, expr):
                if bind.kind == "assign":
                    current = self._factory_origins(
                        unit, bind.scope, bind.value, factories, depth + 1, seen
                    )
                elif bind.kind == "import":
                    module, member, level = bind.value
                    targets = self.project.find_module(unit, module, level)
                    if not member or len(targets) != 1:
                        return None
                    target = targets[0]
                    synthetic = ast.Name(id=member, ctx=ast.Load())
                    current = self._factory_origins(
                        target, target.module, synthetic, factories, depth + 1, seen
                    )
                elif bind.kind == "param":
                    current = set()
                    sites = self.project.call_sites(unit, owner.node)
                    if sites.possible or not sites.resolved:
                        return None
                    for site in sites.resolved:
                        if site.unit.is_test:
                            continue
                        for value, u, s in self.project.bind_argument(
                            owner.node, site, bind.node.arg
                        ):
                            result = self._factory_origins(
                                u, s, value, factories, depth + 1, seen
                            )
                            if not result:
                                return None
                            current.update(result)
                else:
                    return None
                if not current:
                    return None
                origins.update(current)
            return origins
        return None

    def _route_attached(self, unit, scope, fn):
        if "include_router" in self._attribute_writes[0]:
            return False
        factories = {
            "fastapi.FastAPI",
            "starlette.applications.Starlette",
            "fastapi.APIRouter",
            "fastapi.routing.APIRouter",
        }
        route_origins = set()
        for decorator in fn.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr
                in {"route", "get", "post", "put", "patch", "delete", "api_route"}
            ):
                origins = self._factory_origins(
                    unit, scope, decorator.func.value, factories
                )
                if origins:
                    route_origins.update(origins)
        if not route_origins:
            return False
        if route_origins <= self._app_origins:
            return True
        attached = set()
        for source in self.project.units:
            if source.is_test:
                continue
            for call, call_scope in source.calls:
                if not (
                    isinstance(call.func, ast.Attribute)
                    and call.func.attr == "include_router"
                    and call.args
                ):
                    continue
                apps = self._factory_origins(
                    source, call_scope, call.func.value, factories
                )
                if apps and apps <= self._app_origins:
                    routers = self._factory_origins(
                        source, call_scope, call.args[0], factories
                    )
                    if routers:
                        attached.update(routers)
        return route_origins <= attached

    def proof(self, unit, scope, expr):
        if not isinstance(expr, ast.Attribute):
            return None
        if self.project.limits or self.project.truncated:
            return None
        if self._uuid_names is None:
            self._uuid_names = set()
            for source, _, class_scope in self.project.class_info.values():
                for node in class_scope.node.body:
                    value = getattr(node, "value", None)
                    if not (
                        isinstance(value, ast.Call)
                        and self._external(
                            source,
                            class_scope,
                            value.func,
                            {"django.db.models.UUIDField"},
                        )
                    ):
                        continue
                    targets = (
                        node.targets
                        if isinstance(node, ast.Assign)
                        else [node.target]
                        if isinstance(node, ast.AnnAssign)
                        else []
                    )
                    self._uuid_names.update(
                        target.id for target in targets if isinstance(target, ast.Name)
                    )
        if expr.attr not in self._uuid_names:
            return None
        self.work = 0
        types = self._types(unit, scope, expr.value)
        if not types or any(
            kind != "record" or not self._uuid_field(cls, expr.attr)
            for cls, kind in types
        ):
            return None
        return (
            f"registered authentication backend supplies Django UUIDField `{expr.attr}`"
        )
