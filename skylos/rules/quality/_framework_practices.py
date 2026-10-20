"""Source evidence for framework-specific advice, independent of route spelling."""

import ast

from skylos.rules.quality.logic_maintainability import _TypingLiteralCalls
from skylos.rules.quality._overload_groups import _mutated_names


_FASTAPI_PROVIDERS = {"fastapi", "fastapi.applications", "fastapi.routing"}
_FASTAPI_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "options",
    "head",
    "trace",
    "api_route",
    "websocket",
}


class FrameworkResponseContracts:
    def __init__(self, module, context):
        self.facts = _TypingLiteralCalls(
            module,
            _FASTAPI_PROVIDERS,
            context.get("filename"),
            context.get("project_root"),
        )
        self.mutated = _mutated_names(module)

    def is_fastapi_route(self, decorator):
        if not (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr in _FASTAPI_METHODS
            and isinstance(decorator.func.value, ast.Name)
        ):
            return False
        receiver = decorator.func.value
        return self._instance(receiver)

    def _instance(self, receiver, seen=()):
        if not isinstance(receiver, ast.Name) or len(seen) >= 8:
            return False
        scopes = self.facts.scopes
        scope = scopes.resolve(receiver.id, scopes.scope_of.get(receiver))
        key = (scope, receiver.id)
        if (
            scopes.binding_counts[key] != 1
            or "*" in self.mutated
            or scopes.aliases.get(key)
            or key in seen
        ):
            return False
        values = scopes.assigned.get(key, ())
        if len(values) != 1 or not isinstance(values[0], ast.Call):
            return False
        constructor = values[0]
        if constructor.lineno >= receiver.lineno:
            return False
        # A named receiver may be modified after it escapes. Attribute calls
        # retain its local dispatch; passed/stored receiver values do not.
        for reference in scopes.value_refs.get(key, ()):
            parent = scopes.parents.get(reference)
            if (
                isinstance(parent, ast.Attribute)
                and parent.value is reference
                and isinstance(scopes.parents.get(parent), ast.Call)
                and scopes.parents[parent].func is parent
            ):
                continue
            if (
                isinstance(parent, ast.Call)
                and isinstance(parent.func, ast.Attribute)
                and parent.func.attr == "include_router"
                and parent.args
                and parent.args[0] is reference
                and self._instance(parent.func.value, (*seen, key))
            ):
                continue
            return False
        return self.facts.member(constructor.func, _FASTAPI_PROVIDERS) in {
            "FastAPI",
            "APIRouter",
        }
