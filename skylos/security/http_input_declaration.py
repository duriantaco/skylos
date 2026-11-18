"""Source-declared FastAPI inputs under ordinary HTTP decoding.

These facts describe a declaration in the route's own module. They cannot
establish the runtime types of Python callers or attest external framework
behavior. They are for conditional evidence, never a suppression predicate.
"""

import ast
from collections import defaultdict

from skylos.rules.danger.import_proof import _effects, provider_is_unshadowed
from skylos.rules.danger.project_imports import project_import_context

_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_MODEL_BASE = {"pydantic.BaseModel", "pydantic.main.BaseModel"}
_SCALARS = {"builtins.str", "builtins.float", "builtins.bool", "builtins.int"}
_ROUTE_OPTIONS = {"response_model", "description", "summary", "status_code", "tags"}
_MIDDLEWARE = {
    f"{package}.middleware.{group}.{component}"
    for package in ("starlette", "fastapi")
    for group, component in (
        ("cors", "CORSMiddleware"),
        ("gzip", "GZipMiddleware"),
        ("trustedhost", "TrustedHostMiddleware"),
        ("httpsredirect", "HTTPSRedirectMiddleware"),
    )
}


class _Module:
    def __init__(self, tree):
        self.tree = tree
        self.effects = _effects(tree)
        self.definitions = defaultdict(list)
        self.uses = defaultdict(list)
        self.annotations = set()
        self.field_writes = set()
        self.writers = []
        self.written_targets = None
        self.imported_uses = None
        self.dynamic_namespace_write = False
        self.models = {}
        self.apps = {}
        if self.effects is None:
            return
        for node in self.effects.nodes:
            if (
                isinstance(node, (ast.Import, ast.ImportFrom))
                and self.effects.scope(node) is None
            ):
                for alias in node.names:
                    if alias.name == "*":
                        self.dynamic_namespace_write = True
                    name = alias.asname or alias.name.split(".")[0]
                    if isinstance(node, ast.Import):
                        origin = alias.name if alias.asname else name
                    else:
                        origin = (node.module or "") + "." + alias.name
                        if node.level:
                            origin = None
                    self.definitions[name].append(origin if node in tree.body else None)
            elif isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                if self.effects.scope(node) is None:
                    self.definitions[node.name].append(
                        node if node in tree.body else None
                    )
            elif isinstance(node, ast.Name) and self.effects.lookup_key(node) == (
                None,
                node.id,
            ):
                if isinstance(node.ctx, ast.Load):
                    self.uses[node.id].append(node)
                else:
                    self.definitions[node.id].append(self.parent(node))
            if isinstance(node, ast.Attribute) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                self.field_writes.add(node.attr)
                self.writers.append(node)
            if isinstance(node, ast.Subscript) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                self.writers.append(node.value)
                if (
                    isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name)
                    and node.value.func.id in {"globals", "locals", "vars"}
                ):
                    self.dynamic_namespace_write = True
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr"}
                and len(node.args) >= 2
            ):
                self.writers.append(node.args[0])
                key = node.args[1]
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    self.field_writes.add(key.value)
                else:
                    self.field_writes.add(None)
            annotation = getattr(node, "annotation", None) or getattr(
                node, "returns", None
            )
            if annotation is not None:
                self.annotations.update(id(part) for part in ast.walk(annotation))

    def parent(self, node):
        return self.effects.parents.get(id(node))

    def definition(self, name):
        choices = self.definitions.get(name, ())
        return choices[0] if len(choices) == 1 else None

    def qualified(self, node):
        if isinstance(node, ast.Attribute):
            base = self.qualified(node.value)
            return f"{base}.{node.attr}" if base else None
        if not isinstance(node, ast.Name) or self.effects.lookup_key(node) != (
            None,
            node.id,
        ):
            return None
        definition = self.definition(node.id)
        if isinstance(definition, str):
            return definition
        if not self.definitions.get(node.id) and (
            "builtins." + node.id in _SCALARS or node.id in {"min", "max"}
        ):
            return "builtins." + node.id
        return None

    def used_imports(self):
        # An imported app/model object may cross the local source boundary
        # through aliases, containers or callbacks. A different module that
        # reads it is outside this narrow declaration check.
        if self.imported_uses is None:
            self.imported_uses = {
                name
                for node in self.effects.nodes
                if isinstance(node, (ast.Name, ast.Attribute))
                and isinstance(node.ctx, ast.Load)
                if (name := self.qualified(node))
            }
        return self.imported_uses

    def writes(self):
        """Direct/aliased mutation targets, distinct from an opaque runtime."""
        if self.written_targets is not None:
            return self.written_targets
        written = set()

        def names(node, active):
            if node is None or id(node) in active or len(active) >= 24:
                return set()
            active = active | {id(node)}
            if isinstance(node, ast.Attribute):
                return {base + "." + node.attr for base in names(node.value, active)}
            if isinstance(node, ast.Subscript):
                return names(node.value, active)
            if isinstance(node, ast.Name):
                qualified = self.qualified(node)
                if qualified:
                    return {qualified}
                bindings = self.effects.value_bindings.get(
                    self.effects.lookup_key(node), ()
                )
                return {name for binding in bindings for name in names(binding, active)}
            return set()

        for writer in self.writers:
            written.update(names(writer, set()))
        self.written_targets = written
        return written

    def member(self, annotation):
        if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
            for value, other in (
                (annotation.left, annotation.right),
                (annotation.right, annotation.left),
            ):
                if isinstance(other, ast.Constant) and other.value is None:
                    return value
            return None
        if (
            isinstance(annotation, ast.Subscript)
            and self.qualified(annotation.value) == "typing.Optional"
        ):
            return annotation.slice
        return annotation

    def plain_scalar(self, value, depth=0):
        # A named default for a different field may still have runtime hooks.
        # Support only primitive expressions and scalar environment settings.
        if depth > 12:
            return False
        if isinstance(value, ast.Constant):
            return type(value.value) in {type(None), str, bool, int, float}
        if isinstance(value, ast.Compare):
            return (
                len(value.ops) == 1
                and isinstance(value.ops[0], (ast.Eq, ast.NotEq))
                and all(
                    self.plain_scalar(part, depth + 1)
                    for part in [value.left, *value.comparators]
                )
            )
        if not isinstance(value, ast.Call) or value.keywords:
            return False
        target = self.qualified(value.func)
        if target == "os.environ.get":
            return len(value.args) == 2 and all(
                isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                for arg in value.args
            )
        return target in _SCALARS | {"builtins.min", "builtins.max"} and all(
            self.plain_scalar(arg, depth + 1) for arg in value.args
        )

    def scalar_default(self, value, *, selected):
        if value is None:
            return True
        if isinstance(value, ast.Constant):
            return (
                isinstance(value.value, str) or value.value is None
                if selected
                else True
            )
        if isinstance(value, ast.Name) and not selected:
            definition = self.definition(value.id)
            return isinstance(
                definition, (ast.Assign, ast.AnnAssign)
            ) and self.plain_scalar(definition.value)
        if not isinstance(value, ast.Call) or self.qualified(value.func) not in {
            "pydantic.Field",
            "pydantic.fields.Field",
        }:
            return False
        return not value.args and all(
            (kw.arg == "default" and self.scalar_default(kw.value, selected=selected))
            or (
                kw.arg in {"min_length", "max_length", "le", "ge", "gt", "lt"}
                and isinstance(kw.value, ast.Constant)
                and isinstance(kw.value.value, (float, int))
            )
            for kw in value.keywords
        )

    def model_field(self, model, field):
        key = (model, field)
        if key not in self.models:
            self.models[key] = self._model_field(model, field)
        return self.models[key]

    def _model_field(self, model, field):
        if not (
            isinstance(model, ast.ClassDef)
            and self.definition(model.name) is model
            and len(model.bases) == 1
            and self.qualified(model.bases[0]) in _MODEL_BASE
            and not model.keywords
            and not model.decorator_list
            and not self.field_writes.intersection({field, None})
        ):
            return False
        for use in self.uses[model.name]:
            if id(use) in self.annotations:
                continue
            parent = self.parent(use)
            if isinstance(parent, ast.Call) and parent.func is use:
                continue
            return False
        fields = []
        for item in model.body:
            if (
                isinstance(item, ast.Expr)
                and isinstance(item.value, ast.Constant)
                and isinstance(item.value.value, str)
            ):
                continue
            if (
                isinstance(item, ast.Assign)
                and len(item.targets) == 1
                and isinstance(item.targets[0], ast.Name)
                and item.targets[0].id == "model_config"
            ):
                value = item.value
                if (
                    isinstance(value, ast.Call)
                    and self.qualified(value.func) == "pydantic.ConfigDict"
                    and not value.args
                    and all(
                        kw.arg == "extra"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value == "forbid"
                        for kw in value.keywords
                    )
                ):
                    continue
            if not isinstance(item, ast.AnnAssign) or not isinstance(
                item.target, ast.Name
            ):
                return False
            name = item.target.id
            typ = self.qualified(self.member(item.annotation))
            if (
                name.startswith("_")
                or typ not in _SCALARS
                or not self.scalar_default(item.value, selected=name == field)
            ):
                return False
            if name == field:
                fields.append(typ)
        return fields == ["builtins.str"]

    def ordinary_app(self, receiver):
        if not isinstance(receiver, ast.Name):
            return False
        if receiver.id not in self.apps:
            self.apps[receiver.id] = self._ordinary_app(receiver)
        return self.apps[receiver.id]

    def _ordinary_app(self, receiver):
        declaration = self.definition(receiver.id)
        if not (
            isinstance(declaration, ast.Assign)
            and declaration in self.tree.body
            and len(declaration.targets) == 1
            and isinstance(declaration.targets[0], ast.Name)
        ):
            return False
        initial = declaration.value
        if not (
            isinstance(initial, ast.Call)
            and self.qualified(initial.func)
            in {"fastapi.FastAPI", "fastapi.applications.FastAPI"}
            and not initial.args
            and all(
                kw.arg in {"title", "version", "description"}
                and isinstance(kw.value, ast.Constant)
                and isinstance(kw.value.value, str)
                for kw in initial.keywords
            )
        ):
            return False
        for use in self.uses[receiver.id]:
            attr = self.parent(use)
            if (
                isinstance(attr, ast.Call)
                and self.qualified(attr.func) == "uvicorn.run"
                and attr.args == [use]
            ):
                continue
            call = self.parent(attr)
            if not (
                isinstance(attr, ast.Attribute)
                and isinstance(call, ast.Call)
                and call.func is attr
            ):
                return False
            if attr.attr in _METHODS | {"on_event", "websocket"}:
                if call not in getattr(self.parent(call), "decorator_list", ()):
                    return False
                continue
            if (
                attr.attr == "add_middleware"
                and len(call.args) == 1
                and self.qualified(call.args[0]) in _MIDDLEWARE
            ):
                continue
            if (
                attr.attr == "mount"
                and len(call.args) == 2
                and isinstance(call.args[1], ast.Call)
                and self.qualified(call.args[1].func)
                in {
                    "fastapi.staticfiles.StaticFiles",
                    "starlette.staticfiles.StaticFiles",
                }
            ):
                continue
            return False
        return True


def _module(tree):
    index = getattr(tree, "_skylos_declared_http_inputs", None)
    if index is None:
        index = _Module(tree)
        tree._skylos_declared_http_inputs = index
    return index


def _providers_declared(tree, filename, project_root, protected):
    """Reject concrete shadowing or provider writes even for a scoped claim."""
    providers = {
        "fastapi",
        "pydantic",
        "pydantic_core",
        "starlette",
        "builtins",
        "json",
        "typing",
        "uvicorn",
    }
    watched = {*providers, "os.environ.get"}
    indices = [_module(tree)]
    if filename is not None:
        context = project_import_context(tree, filename, project_root)
        if context is None:
            return False
        key = ("declared-http-providers", tuple(sorted(protected)))
        if key in context.provider_results:
            return context.provider_results[key]
        if providers.intersection(context.modules) or not all(
            provider_is_unshadowed(provider, filename, project_root)
            for provider in providers
        ):
            return False
        for source in context.names[context.source]:
            watched.update(f"{source}.{symbol}" for symbol in protected)
        indices = []
        for path, parsed in context.entries:
            index = _module(parsed)
            if path != context.source and (
                index.effects is None
                or index.used_imports().intersection(
                    watched - providers - {"os.environ.get"}
                )
            ):
                context.provider_results[key] = False
                return False
            indices.append(index)
    ok = all(
        idx.effects is not None
        and bool(idx.effects.nodes)
        and not idx.dynamic_namespace_write
        and not any(
            name == symbol or name.startswith(symbol + ".")
            for name in idx.writes()
            for symbol in watched
        )
        for idx in indices
    )
    if filename is not None:
        context.provider_results[key] = ok
    return ok


def declared_model_string_field(
    tree, model, field, *, filename=None, project_root=None
):
    """True for a locally declared ordinary model's string/optional string field."""
    module = _module(tree)
    return (
        module.effects is not None
        and module.model_field(model, field)
        and _providers_declared(tree, filename, project_root, {model.name})
    )


def declared_http_string_input(
    tree, route, parameter, field=None, *, filename=None, project_root=None
):
    """True for a string declaration on this ordinary HTTP entry point only."""
    if (
        not isinstance(route, (ast.FunctionDef, ast.AsyncFunctionDef))
        or route not in tree.body
        or len(route.decorator_list) != 1
    ):
        return False
    module = _module(tree)
    if module.effects is None or module.definition(route.name) is not route:
        return False
    registration = route.decorator_list[0]
    if not (
        isinstance(registration, ast.Call)
        and isinstance(registration.func, ast.Attribute)
        and registration.func.attr in _METHODS
        and len(registration.args) == 1
        and isinstance(registration.args[0], ast.Constant)
        and isinstance(registration.args[0].value, str)
        and all(kw.arg in _ROUTE_OPTIONS for kw in registration.keywords)
        and module.ordinary_app(registration.func.value)
    ):
        return False
    name = parameter.arg if isinstance(parameter, ast.arg) else parameter
    positionals = [*route.args.posonlyargs, *route.args.args]
    args = [*positionals, *route.args.kwonlyargs]
    defaults = [None] * (len(positionals) - len(route.args.defaults)) + [
        *route.args.defaults,
        *route.args.kw_defaults,
    ]
    for arg, default in zip(args, defaults, strict=True):
        if arg.arg != name:
            continue
        ann = module.member(arg.annotation)
        protected = {registration.func.value.id, route.name}
        if field is None:
            return (
                _providers_declared(tree, filename, project_root, protected)
                and module.qualified(ann) == "builtins.str"
                and (
                    default is None
                    or isinstance(default, ast.Constant)
                    and isinstance(default.value, str)
                )
            )
        if default is not None and not (
            isinstance(default, ast.Constant)
            and default.value is None
            or isinstance(default, ast.Call)
            and module.qualified(default.func)
            in {"fastapi.Body", "fastapi.param_functions.Body"}
            and not default.args
            and all(
                kw.arg == "default"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is None
                for kw in default.keywords
            )
        ):
            return False
        return (
            isinstance(ann, ast.Name)
            and module.model_field(module.definition(ann.id), field)
            and _providers_declared(tree, filename, project_root, protected | {ann.id})
        )
    return False
