"""Describe filename guards on the ordinary HTTP decoding path.

A declaration describes one input contract. It cannot certify all Python
callers or runtime framework behavior and must never produce a SAFE fact.
"""

import ast
from dataclasses import replace

from skylos.security.http_input_declaration import (
    declared_http_string_input,
    declared_model_string_field,
)

from .path_provenance import _MAX_SITES, _env_lookup, _step


class HTTPFilenameInput:
    def __init__(self, tracer):
        self.tracer = tracer
        self.project = tracer.project
        self.http_seen = False
        self.work = 0

    def matches(self, unit, scope, node, env=None, field=None, active=frozenset()):
        self.work += 1
        key = (id(node), id(scope), field)
        if self.work > 512 or len(active) >= 32 or key in active:
            return False
        active = active | {key}
        if isinstance(node, ast.Name):
            found = unit.lookup(scope, node.id)
            if not found:
                return False
            owner, binds = found
            visible = self.tracer._visible_binds(unit, owner, binds, node)
            if not visible:
                return False
            for bind in visible:
                if bind.kind == "param" and owner.kind == "function":
                    if not self._parameter(unit, owner, bind.node, env, field, active):
                        return False
                elif bind.kind == "assign":
                    if not self.matches(
                        unit, bind.scope, bind.value, env, field, active
                    ):
                        return False
                else:
                    return False
            return True
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            return all(
                self.matches(unit, scope, part, env, field, active)
                for part in node.values
            )
        if isinstance(node, ast.IfExp):
            return all(
                self.matches(unit, scope, part, env, field, active)
                for part in (node.body, node.orelse)
            )
        if field:
            return self._model_constructor(unit, scope, node, env, field, active)
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            return self.matches(unit, scope, node.value, env, node.attr, active)
        if isinstance(node, ast.Constant):
            return isinstance(node.value, str)
        if self.tracer._clock_format(unit, scope, node) is not None:
            return True
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            return False
        if node.func.attr in {"strip", "lstrip", "rstrip", "lower", "upper", "replace"}:
            return (
                not node.keywords
                and all(
                    isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                    for arg in node.args
                )
                and self.matches(unit, scope, node.func.value, env, None, active)
            )
        return False

    def _parameter(self, unit, owner, parameter, env, field, active):
        fn = owner.node
        binding = _env_lookup(env, id(fn))
        if binding and binding[0] is not None:
            site, parent_env = binding
            return self.arguments(fn, site, parameter.arg, parent_env, field, active)
        sites = self.project.call_sites(unit, fn)
        if len(sites.resolved) > _MAX_SITES:
            return False
        declaration = self._declared(unit, fn, parameter, field)
        decorator = None
        if declaration:
            dec = fn.decorator_list[0]
            decorator = _step(
                unit,
                dec,
                f"decorated with `{ast.unparse(dec.func)}`; the wrapper's callers are not visible",
            )
        if declaration and sites.unresolved_refs:
            # Unresolved references from a different entry point cannot change
            # the HTTP argument delivered to this route. The underlying trace
            # retains those possible Python callers as independent unknowns.
            process = self.project.process_units((unit,))
            outside = {
                step for step, source in sites.unresolved_refs if source not in process
            }
            sites = replace(
                sites, escapes=[step for step in sites.escapes if step not in outside]
            )
        if not self.tracer._hidden_callers(unit, sites, decorator, []):
            return False
        if not declaration and (sites.entries or not sites.resolved):
            return False
        if declaration:
            self.http_seen = True
        return all(
            self.arguments(fn, site, parameter.arg, None, field, active)
            for site in sites.resolved
        )

    def arguments(self, fn, site, name, env, field, active):
        values = list(self.project.bind_argument(fn, site, name))
        return bool(values) and all(
            self.matches(unit, scope, expr, env, field, active)
            for expr, unit, scope in values
        )

    def _declared(self, unit, fn, parameter, field):
        cache = self.tracer.http_string_declarations
        key = (id(fn), parameter.arg, field)
        if key not in cache:
            cache[key] = declared_http_string_input(
                unit.tree,
                fn,
                parameter,
                field,
                filename=unit.path,
                project_root=self.project.root,
            )
            if field and cache[key]:
                scope = self.project.function_info[id(fn)][2]
                members = self.tracer._annotation_members(
                    unit, scope, parameter.annotation
                )
                models = [
                    value
                    for part in members or ()
                    for value in self.project.values(unit, scope, part) or ()
                ]
                cache[key] = bool(models) and all(
                    value.kind == "cls"
                    and field not in self.tracer._project_attribute_writes(value.node)
                    for value in models
                )
        return cache[key]

    def _model_constructor(self, unit, scope, node, env, field, active):
        if (
            not isinstance(node, ast.Call)
            or node.args
            or any(kw.arg != field for kw in node.keywords)
        ):
            return False
        types = self.project.values(unit, scope, node.func)
        if not types or any(value.kind != "cls" for value in types):
            return False
        for value in types:
            key = (id(value.node), field)
            cache = self.tracer.http_string_declarations
            if key not in cache:
                cache[key] = field not in self.tracer._project_attribute_writes(
                    value.node
                ) and declared_model_string_field(
                    value.unit.tree,
                    value.node,
                    field,
                    filename=value.unit.path,
                    project_root=self.project.root,
                )
            if not cache[key]:
                return False
        return all(
            self.matches(unit, scope, kw.value, env, None, active)
            for kw in node.keywords
        )
