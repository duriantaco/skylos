"""Backward data predecessors; no execution, sanitizer guesses or safety verdicts."""

from __future__ import annotations

import ast


class PredecessorWalker:
    def __init__(self, index, graph):
        self.index = index
        self.graph = graph
        self.actual_contexts = []

    def walk(self, unit, scope, expression, destination, depth=0, trail=()):
        if expression is None or destination is None:
            return
        if depth >= self.index.limits.max_depth:
            self.graph.unknown(
                unit, expression, destination, "Trace depth budget reached."
            )
            return
        identity = (unit.path, id(expression), id(scope.node))
        if identity in trail:
            self.graph.unknown(
                unit,
                expression,
                destination,
                "Recursive or cyclic data dependency remains unknown.",
            )
            return
        trail = (*trail, identity)
        source = self._source(unit, scope, expression)
        if source:
            step = self.graph.add("source", unit, expression, source)
            self.graph.connect(step, destination)
            self.graph.found_source = True
            return
        if isinstance(expression, ast.Constant):
            step = self.graph.add(
                "literal", unit, expression, "Literal value (content withheld)."
            )
            self.graph.connect(step, destination)
        elif isinstance(expression, ast.Name):
            self._name(unit, scope, expression, destination, depth, trail)
        elif isinstance(expression, ast.Call):
            self._call(unit, scope, expression, destination, depth, trail)
        elif isinstance(expression, (ast.Attribute, ast.Subscript)):
            step = self.graph.add(
                "access",
                unit,
                expression,
                "Attribute/subscript access; contents are not evaluated.",
            )
            self.graph.connect(step, destination)
            self.walk(unit, scope, expression.value, step, depth + 1, trail)
            if isinstance(expression, ast.Subscript):
                self.walk(unit, scope, expression.slice, step, depth + 1, trail)
            else:
                self.graph.limit(
                    "Attribute/property provider or runtime value is not established by its spelling."
                )
        else:
            step = self.graph.add(
                "expression",
                unit,
                expression,
                "Static expression combines predecessor values.",
            )
            self.graph.connect(step, destination)
            handled = False
            for child in ast.iter_child_nodes(expression):
                if isinstance(child, ast.expr):
                    handled = True
                    self.walk(unit, scope, child, step, depth + 1, trail)
            if not handled:
                self.graph.limit("Expression semantics are not modeled by this trace.")

    def _name(self, unit, scope, expression, destination, depth, trail):
        name = expression.id
        binding = unit.strict_binding(scope, name)
        if binding is None:
            self.graph.unknown(
                unit,
                expression,
                destination,
                "Name has no single stable source binding: " + name,
            )
            return
        if binding.kind == "parameter":
            step = self.graph.add(
                "parameter", unit, binding.node, "Function parameter: " + name
            )
            self.graph.connect(step, destination)
            self._parameter(unit, binding.owner, name, step, depth, trail)
        elif binding.kind == "assignment":
            if (
                getattr(binding.node, "lineno", 0) >= getattr(expression, "lineno", 0)
                and scope is not unit.module
            ):
                self.graph.unknown(
                    unit,
                    expression,
                    destination,
                    "Assignment does not precede this use: " + name,
                )
                return
            step = self.graph.add(
                "assignment", unit, binding.node, "Assignment provides: " + name
            )
            self.graph.connect(step, destination)
            self.walk(unit, binding.owner, binding.value, step, depth + 1, trail)
        elif binding.kind == "import":
            step = self.graph.add(
                "import", unit, binding.node, "Import binding: " + str(binding.value)
            )
            self.graph.connect(step, destination)
        else:
            self.graph.unknown(
                unit,
                expression,
                destination,
                "Binding is not a modeled data value: " + name,
            )

    def _parameter(self, unit, scope, name, destination, depth, trail):
        if not isinstance(
            scope.node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
        ):
            self.graph.unknown(
                unit,
                scope.node,
                destination,
                "Parameter owner is not a known function.",
            )
            return
        entrypoint = self._entrypoint(unit, scope)
        if entrypoint:
            step = self.graph.add(
                "entrypoint",
                unit,
                scope.node,
                "Declared entry-point parameter; runtime binding is not evaluated: "
                + entrypoint,
            )
            self.graph.connect(step, destination)
            self.graph.limit(
                "Framework argument binding is not a proof of attacker control."
            )
        callers = self.index.callers.get(id(scope.node), [])
        for context in reversed(self.actual_contexts):
            if context[0] == id(scope.node):
                callers = [context[1:]]
                break
        if len(callers) > self.index.limits.max_callers:
            self.graph.limit(
                "Caller branch budget reached; additional callers are unknown."
            )
        for caller_unit, caller_scope, call, bound in callers[
            : max(0, self.index.limits.max_callers)
        ]:
            step = self.graph.add(
                "call",
                caller_unit,
                call,
                "Observed call to: " + scope.name,
                token=unit.path + ":" + str(scope.node.lineno) + ":" + name,
            )
            self.graph.connect(step, destination, "argument")
            actual = self._actual_argument(scope.node, name, call, bound)
            if actual is None:
                self.graph.unknown(
                    caller_unit,
                    call,
                    step,
                    "Argument mapping is omitted, starred or ambiguous.",
                )
            else:
                self.walk(caller_unit, caller_scope, actual, step, depth + 1, trail)
        if not callers and not entrypoint:
            self.graph.unknown(
                unit,
                scope.node,
                destination,
                "No source-resolved project callers; external/dynamic callers remain unknown.",
            )

    def _actual_argument(self, function, name, call, bound):
        for argument in call.args:
            if isinstance(argument, ast.Starred):
                return None
        for keyword in call.keywords:
            if keyword.arg is None:
                return None
            if keyword.arg == name:
                return keyword.value
        arguments = [*function.args.posonlyargs, *function.args.args]
        if bound and arguments:
            arguments = arguments[1:]
        for position, argument in enumerate(arguments):
            if argument.arg == name:
                if position < len(call.args):
                    return call.args[position]
                return None
        return None

    def _call(self, unit, scope, call, destination, depth, trail):
        target, bound = self.index.resolve_call(unit, scope, call)
        step = self.graph.add(
            "call",
            unit,
            call,
            "Call expression; implementation is followed only when source-resolved.",
        )
        self.graph.connect(step, destination)
        if target is None:
            self.graph.limit(
                "Call return/provider is unresolved; no sanitizer or return-value guarantee is assumed."
            )
            for argument in call.args:
                self.walk(unit, scope, argument, step, depth + 1, trail)
            for keyword in call.keywords:
                self.walk(unit, scope, keyword.value, step, depth + 1, trail)
            return
        returned = False
        stack = list(target.node.body)
        self.actual_contexts.append((id(target.node), unit, scope, call, bound))
        while stack:
            node = stack.pop(0)
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                continue
            if isinstance(node, ast.Return) and node.value is not None:
                returned = True
                return_step = self.graph.add(
                    "return",
                    target.unit,
                    node,
                    "Source-resolved function return: " + target.name,
                )
                self.graph.connect(return_step, step, "return")
                self.walk(
                    target.unit, target, node.value, return_step, depth + 1, trail
                )
            children = list(ast.iter_child_nodes(node))
            stack[0:0] = children
        self.actual_contexts.pop()
        if not returned:
            self.graph.unknown(
                target.unit,
                target.node,
                step,
                "No modeled return expression in the source-resolved call.",
            )

    def _source(self, unit, scope, node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "input":
                if (
                    unit.strict_binding(scope, "input") is None
                    and not self._has_binding(scope, "input")
                    and "builtins" not in unit.mutated_roots
                ):
                    return "Unshadowed built-in input call."
            qualified = unit.imported_name(scope, node.func)
            if qualified and self.index.project_provider(qualified, unit):
                return None
            if qualified == "builtins.input":
                return "Imported built-in input call."
            if qualified in {"flask.request.get_json", "flask.request.get_data"}:
                return "Imported Flask request input call: " + qualified
            for collection in ("args", "form", "values", "headers", "cookies", "files"):
                prefix = "flask.request." + collection
                if qualified in {prefix + ".get", prefix + ".getlist"}:
                    return "Imported Flask request input call: " + qualified
            if qualified in {
                "os.getenv",
                "os.environ.get",
                "sys.stdin.read",
                "sys.stdin.readline",
                "sys.stdin.readlines",
            }:
                return "Imported process-input call: " + qualified
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            root = node
            while isinstance(root, ast.Subscript):
                root = root.value
            qualified = unit.imported_name(scope, root)
            if qualified and self.index.project_provider(qualified, unit):
                return None
            if qualified:
                for prefix in ("sys.argv", "sys.stdin", "os.environ", "flask.request"):
                    if qualified == prefix or qualified.startswith(prefix + "."):
                        return "Imported external-input provider: " + prefix
        return None

    def _has_binding(self, scope, name):
        for current in scope.unit.lexical_scopes(scope):
            if current.dynamic or name in current.bindings:
                return True
        return False

    def _entrypoint(self, unit, scope):
        function = scope.node
        for decorator in getattr(function, "decorator_list", []):
            if isinstance(decorator, ast.Call):
                target = decorator.func
            else:
                target = decorator
            qualified = unit.imported_name(scope.parent, target)
            if qualified in {
                "click.command",
                "click.group",
                "click.option",
                "click.argument",
            }:
                return qualified
            if not isinstance(target, ast.Attribute) or not isinstance(
                target.value, ast.Name
            ):
                continue
            if target.attr not in {
                "route",
                "get",
                "post",
                "put",
                "delete",
                "patch",
                "websocket",
                "api_route",
            }:
                continue
            binding = unit.strict_binding(scope.parent, target.value.id)
            if (
                binding is None
                or binding.kind != "assignment"
                or not isinstance(binding.value, ast.Call)
            ):
                continue
            provider = unit.imported_name(scope.parent, binding.value.func)
            if provider and self.index.project_provider(provider, unit):
                continue
            if provider in {
                "flask.Flask",
                "flask.Blueprint",
                "fastapi.FastAPI",
                "fastapi.APIRouter",
            }:
                return provider + "." + target.attr
        return None


def observed_guards(unit, node, graph, destination):
    parent = unit.parents.get(id(node))
    while parent is not None:
        if isinstance(parent, (ast.If, ast.Try, ast.With, ast.AsyncWith, ast.Match)):
            kind = type(parent).__name__
            step = graph.add(
                "guard",
                unit,
                parent,
                "Observed " + kind + " syntax; safety/reachability is not established.",
            )
            graph.connect(step, destination, "observed_guard")
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            break
        parent = unit.parents.get(id(parent))
