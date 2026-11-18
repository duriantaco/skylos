"""Source-attested absence of modeled HTTP validation/provider mutation.

This is necessary, not sufficient, for a native HTTP scalar contract. Callers
must separately prove the actual app, route, parameter and invocation domain.
No installed framework or scanned module is imported/executed by this proof.
"""

from __future__ import annotations

import ast

from skylos.rules.danger.builtin_bindings import builtin_references
from skylos.rules.danger.import_proof import (
    _effects,
    project_provider_effects_are_stable,
    provider_binding_is_stable,
)
from skylos.rules.danger.project_imports import project_import_context


def native_http_pipeline_is_intact(
    tree, filename, project_root, *, max_work=4096, accepts_model_field=None
):
    work = 0

    def tick():
        nonlocal work
        work += 1
        return work <= max_work

    context = project_import_context(tree, filename, project_root)
    if context is None:
        return False
    # The context reattests the source snapshot before this lookup. Results
    # belong to that snapshot, rather than merely to a caller's AST identity.
    cache_key = ("native-http-pipeline-v5", max_work)
    if accepts_model_field is None and cache_key in context.provider_results:
        return context.provider_results[cache_key]

    result = _pipeline_intact(context, tick, accepts_model_field)
    if accepts_model_field is None:
        context.provider_results[cache_key] = result
    return result


def _pipeline_intact(context, tick, accepts_model_field):
    roots = {"fastapi", "starlette", "pydantic", "pydantic_core", "json"}
    app_constructors = {"fastapi.FastAPI", "fastapi.applications.FastAPI"}
    reflectors = {
        "exec",
        "eval",
        "compile",
        "__import__",
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "delattr",
    }
    qualified_reflectors = {"builtins." + name for name in reflectors}
    registration_receivers = {}
    namespace_nodes = {}
    namespace_names = {}
    effect_entries = []
    for path, parsed in context.entries:
        effects = _effects(parsed)
        if effects is None or not effects.complete:
            return False
        effect_entries.append((path, parsed, effects))
        for candidate in effects.nodes:
            if isinstance(
                candidate, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                kind = (
                    "@class:" if isinstance(candidate, ast.ClassDef) else "@function:"
                )
                namespace_nodes[kind + str(id(candidate))] = (effects, candidate)
                if effects.scope(candidate) is None:
                    for module in context.names.get(path, ()):
                        if module:
                            namespace_names[module + "." + candidate.name] = (
                                effects,
                                candidate,
                            )
    middleware = {
        f"{package}.middleware.{module}.{name}"
        for package in ("starlette", "fastapi")
        for module, name in (
            ("cors", "CORSMiddleware"),
            ("gzip", "GZipMiddleware"),
            ("trustedhost", "TrustedHostMiddleware"),
            ("httpsredirect", "HTTPSRedirectMiddleware"),
        )
    }

    def capability(names):
        return any(
            name.split(".", 1)[0] in roots
            or name == "builtins"
            or name.startswith("builtins.__")
            for name in names
        )

    def namespace_targets(names):
        found = []
        for name in names:
            target = namespace_names.get(name) or namespace_nodes.get(name)
            if target is None and name.startswith("@class:"):
                base, _, member = name.partition(".")
                parent = namespace_nodes.get(base)
                if parent is not None:
                    source_effects, candidate = parent
                    found.extend(
                        namespace_targets(
                            source_effects.aliases.get((candidate, member), ())
                        )
                    )
            if target is not None:
                found.append(target)
        return found

    def namespace_value(effects, expression, active=()):
        """Known Python callables/instances expose their module globals.

        Keep that authority through ordinary aliases, containers and bounded
        source factories. Giving their object away differs from a direct call.
        """
        if expression is None:
            return False
        key = (id(effects), id(expression))
        if key in active or len(active) >= 24:
            return True
        active = (*active, key)
        if isinstance(expression, ast.Lambda) or namespace_targets(
            effects.refs(expression)
        ):
            return True
        if isinstance(expression, ast.Name):
            source = effects.literal_source(expression)
            return (
                source is not None
                and source is not expression
                and namespace_value(effects, source, active)
            )
        if isinstance(expression, ast.Call):
            callees = effects.refs(expression.func)
            # The application owns route registration and validation. An opaque
            # consumer of this instance can change subsequent request handling.
            if callees & app_constructors:
                return True
            for source_effects, candidate in namespace_targets(callees):
                if not tick() or isinstance(candidate, ast.ClassDef):
                    return True
                if any(
                    isinstance(returned, ast.Return)
                    and source_effects.scope(returned) is candidate
                    and namespace_value(source_effects, returned.value, active)
                    for returned in ast.walk(candidate)
                ):
                    return True
        if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
            return any(
                namespace_value(effects, item, active) for item in expression.elts
            )
        if isinstance(expression, ast.Dict):
            return any(
                namespace_value(effects, item, active)
                for item in [*expression.keys, *expression.values]
                if item is not None
            )
        if isinstance(expression, ast.IfExp):
            return any(
                namespace_value(effects, item, active)
                for item in (expression.body, expression.orelse)
            )
        if isinstance(expression, ast.BoolOp):
            return any(
                namespace_value(effects, item, active) for item in expression.values
            )
        return False

    def namespace_read(effects, call, kind):
        """Only an immediate, constant-key read of an unrelated namespace.

        Returning or aliasing globals/locals/vars can expose provider bindings.
        A native namespace's immediate ``.get`` of an unrelated binding does
        not expose the namespace itself. Writes and dynamic keys stay unknown.
        """
        if call.args or call.keywords or kind == "vars":
            return False
        attribute = effects.parents.get(id(call))
        read = effects.parents.get(id(attribute))
        indexed = isinstance(attribute, ast.Subscript) and (
            attribute.value is call
            and isinstance(attribute.ctx, ast.Load)
            and isinstance(attribute.slice, ast.Constant)
            and isinstance(attribute.slice.value, str)
        )
        if indexed:
            name = attribute.slice.value
        elif (
            isinstance(attribute, ast.Attribute)
            and attribute.value is call
            and attribute.attr == "get"
            and isinstance(read, ast.Call)
            and read.func is attribute
            and 1 <= len(read.args) <= 2
            and not read.keywords
            and isinstance(read.args[0], ast.Constant)
            and isinstance(read.args[0].value, str)
            and (len(read.args) == 1 or isinstance(read.args[1], ast.Constant))
        ):
            name = read.args[0].value
        else:
            return False
        if name == "__builtins__":
            return False
        scope = None if kind == "globals" else effects.scope(call)
        for _ in range(64):
            scope = effects.binding_scope(scope, name)
            names = effects.aliases.get((scope, name), ())
            if capability(names) or any(
                value.startswith(("@function:", "@class:")) for value in names
            ):
                return False
            if name in effects.bindings.get(scope, ()) or scope is None:
                if indexed:
                    values = effects.value_bindings.get((scope, name), ())
                    return bool(values) and all(
                        effects.scalar_literal(value)
                        or isinstance(value, (ast.BinOp, ast.UnaryOp))
                        and effects.scalar_operator_tree(value)
                        for value in values
                    )
                return True
            scope = effects.scope(scope)
        return False

    def native_app_method(effects, call):
        if not isinstance(call.func, ast.Attribute):
            return False
        receiver = call.func.value
        constructor = effects.literal_source(receiver)
        if not isinstance(receiver, ast.Name) or not isinstance(constructor, ast.Call):
            return False
        callees = effects.refs(constructor.func)
        if len(callees) != 1 or callees.isdisjoint(app_constructors):
            return False
        receiver_key = (id(effects), id(constructor))
        if receiver_key not in registration_receivers:
            stable = True
            for use in effects.nodes:
                if (
                    isinstance(use, (ast.Attribute, ast.Subscript))
                    and isinstance(use.ctx, (ast.Store, ast.Del))
                    and effects.literal_source(use.value) is constructor
                ):
                    stable = False
                    break
                if isinstance(use, ast.Call) and use.args:
                    function = use.func
                    reflective = (
                        isinstance(function, ast.Name)
                        and (
                            function.id in {"setattr", "delattr"}
                            or effects.lookup(function)
                            & {"builtins.setattr", "builtins.delattr"}
                        )
                        or isinstance(function, ast.Attribute)
                        and function.attr in {"setattr", "delattr"}
                        and effects.refs(function)
                        & {"builtins.setattr", "builtins.delattr"}
                    )
                    if (
                        reflective
                        and effects.literal_source(use.args[0]) is constructor
                    ):
                        stable = False
                        break
            registration_receivers[receiver_key] = stable
        return registration_receivers[receiver_key]

    def registration_argument(effects, call, argument, names):
        if not native_app_method(effects, call):
            return False
        if call.func.attr == "add_middleware":
            component = call.args[0] if call.args else None
            for keyword in call.keywords:
                if keyword.arg == "middleware_class":
                    component = keyword.value
            return argument is component and bool(names) and names <= middleware
        if call.func.attr not in {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "head",
            "options",
        }:
            return False
        return any(
            keyword.arg == "response_model" and keyword.value is argument
            for keyword in call.keywords
        ) and all(
            name in {"pydantic.BaseModel", "pydantic.main.BaseModel"}
            or name.startswith("@class:")
            for name in names
        )

    def native_model_class(effects, names):
        if not names or not names & {"pydantic.BaseModel", "pydantic.main.BaseModel"}:
            return False
        for name in names:
            if name in {"pydantic.BaseModel", "pydantic.main.BaseModel"}:
                continue
            candidate = effects.class_nodes.get(name)
            if (
                candidate is None
                or not tick()
                or candidate.keywords
                or candidate.decorator_list
                or any(
                    isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and member.name in {"__instancecheck__", "__subclasscheck__"}
                    for member in candidate.body
                )
            ):
                return False
        return True

    def native_plain_class(names, active=()):
        targets = namespace_targets(names)
        if not targets or len(targets) != len(names):
            return False
        for effects, candidate in targets:
            if (
                not tick()
                or not isinstance(candidate, ast.ClassDef)
                or candidate in active
                or len(active) >= 24
                or candidate.keywords
                or candidate.decorator_list
            ):
                return False
            if any(
                not native_plain_class(effects.refs(base), (*active, candidate))
                for base in candidate.bases
            ):
                return False
        return True

    def plain_instance_store(call, argument, object_refs, effects, source, tree):
        # Native object storage with a literal value has no callback when
        # the class has no descriptors, bases or class mutation.
        if not (
            len(call.args) == 3
            and not call.keywords
            and call.args[0] is argument
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "__setattr__"
            and id(call.func.value) in object_refs
            and isinstance(call.args[1], ast.Constant)
            and isinstance(call.args[1].value, str)
            and call.args[1].value.isidentifier()
            and not call.args[1].value.startswith("_")
            and isinstance(call.args[2], ast.Constant)
        ):
            return False
        instance = effects.literal_source(argument)
        if not isinstance(instance, ast.Call) or instance.args or instance.keywords:
            return False
        targets = namespace_targets(effects.refs(instance.func))
        if len(targets) != 1:
            return False
        _owner, cls = targets[0]
        if not (
            isinstance(cls, ast.ClassDef)
            and not cls.bases
            and not cls.keywords
            and not cls.decorator_list
            and all(isinstance(stmt, ast.Pass) for stmt in cls.body)
        ):
            return False
        qualified = next(
            (name for name, (_, node) in namespace_names.items() if node is cls), None
        )
        return (
            bool(qualified)
            and provider_binding_is_stable(
                "builtins.object", tree, source, context.root
            )
            and project_provider_effects_are_stable(
                qualified, tree, source, context.root
            )
        )

    def accepts_decorated_namespace(decorator, effects, descriptors, source, tree):
        # Python passes the newly created object to a decorator, even though
        # that argument has no Call node in the AST.
        if isinstance(decorator, ast.Name) and id(decorator) in descriptors:
            return provider_binding_is_stable(
                "builtins." + decorator.id, tree, source, context.root
            )
        if not isinstance(decorator, ast.Call) or not native_app_method(
            effects, decorator
        ):
            return False
        return decorator.func.attr in {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "head",
            "options",
            "websocket",
            "on_event",
        }

    for source, parsed, effects in effect_entries:
        instance_checks = builtin_references(parsed, {"isinstance"})
        object_refs = builtin_references(parsed, {"object"})
        descriptors = builtin_references(
            parsed, {"staticmethod", "classmethod", "property"}
        )
        for node in effects.nodes:
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ) and any(
                not tick()
                or not accepts_decorated_namespace(
                    decorator, effects, descriptors, source, parsed
                )
                for decorator in node.decorator_list
            ):
                return False
            reflection = None
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                if node.id in reflectors:
                    # A rebound/unknown reflective function cannot prove the
                    # absence of namespace effects either.
                    reflection = node.id
                else:
                    aliases = effects.lookup(node) & qualified_reflectors
                    if aliases:
                        if len(aliases) != 1:
                            return False
                        reflection = next(iter(aliases)).split(".")[-1]
            elif (
                isinstance(node, ast.Attribute)
                and isinstance(node.ctx, ast.Load)
                and node.attr in reflectors
                and effects.refs(node) & qualified_reflectors
            ):
                reflection = node.attr
            if reflection is not None:
                # Inspect operations which can expose or rewrite a dependency;
                # unrelated arithmetic/container AST nodes use no proof budget.
                # Traversal itself is capped by the attested project and the
                # existing per-module effects node limit.
                if not tick():
                    return False
                parent = effects.parents.get(id(node))
                if not isinstance(parent, ast.Call) or parent.func is not node:
                    return False
                if reflection in {"exec", "eval", "compile", "__import__"}:
                    return False
                if reflection in {"globals", "locals", "vars"} and not namespace_read(
                    effects, parent, reflection
                ):
                    return False
            if (
                isinstance(node, ast.Name)
                and node.id == "__builtins__"
                or isinstance(node, ast.Attribute)
                and node.attr
                in {
                    "__code__",
                    "__globals__",
                    "__dict__",
                    "__closure__",
                    "__getattribute__",
                }
            ):
                return False
            if (
                isinstance(node, (ast.Attribute, ast.Subscript))
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and (
                    capability(effects.refs(node))
                    or isinstance(node, ast.Attribute)
                    and node.attr == "isinstance"
                )
            ):
                return False
            if isinstance(node, ast.Call):
                functions = effects.refs(node.func)
                if (
                    len(node.args) >= 2
                    and (
                        isinstance(node.func, ast.Name)
                        and node.func.id in {"setattr", "delattr"}
                        or functions & {"builtins.setattr", "builtins.delattr"}
                    )
                    and not (
                        isinstance(node.args[1], ast.Constant)
                        and isinstance(node.args[1].value, str)
                        and node.args[1].value != "isinstance"
                    )
                ):
                    return False
                if functions & {
                    "builtins.exec",
                    "builtins.eval",
                    "builtins.compile",
                    "builtins.__import__",
                    "types.FunctionType",
                    "types.CodeType",
                } or any(function.startswith("importlib.") for function in functions):
                    return False
                for kind in ("globals", "locals", "vars"):
                    if "builtins." + kind in functions and (
                        not tick() or not namespace_read(effects, node, kind)
                    ):
                        return False
                if capability(functions) and any(
                    part in {"__dict__", "__globals__", "__setattr__", "__setitem__"}
                    for function in functions
                    for part in function.split(".")
                ):
                    return False
                for argument in [
                    *node.args,
                    *[keyword.value for keyword in node.keywords],
                ]:
                    names = effects.refs(argument)
                    namespace = namespace_value(effects, argument)
                    if (
                        (capability(names) or namespace)
                        and id(node.func) in instance_checks
                        and len(node.args) == 2
                        and not node.keywords
                        and argument is node.args[1]
                        and (
                            names
                            <= {
                                "fastapi.HTTPException",
                                "fastapi.exceptions.HTTPException",
                                "starlette.exceptions.HTTPException",
                            }
                            or native_model_class(effects, names)
                            or native_plain_class(names)
                        )
                    ):
                        # Builtin identity is local, while the same complete
                        # context audit rejects builtin/module namespace writes
                        # and escapes which could replace this reader.
                        continue
                    if namespace and not capability(names):
                        if plain_instance_store(
                            node, argument, object_refs, effects, source, parsed
                        ):
                            continue
                        if accepts_model_field is not None and isinstance(
                            node.func, ast.Name
                        ):
                            field = next(
                                (
                                    kw.arg
                                    for kw in node.keywords
                                    if kw.value is argument
                                ),
                                None,
                            )
                            if (
                                field
                                and tick()
                                and accepts_model_field(source, node, field)
                            ):
                                continue
                    if (capability(names) or namespace) and (
                        not tick()
                        or not registration_argument(effects, node, argument, names)
                    ):
                        return False
            if not effects.complete:
                return False
    return True
