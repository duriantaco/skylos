"""Source proofs that a wide signature represents named input or a record.

These exemptions describe how parameters are bound, rather than guessing from
function names or treating every decorated callable as a framework callback.
"""

import ast

from skylos.rules.quality._overload_groups import _mutated_names
from skylos.rules.quality._provider_context import project_local_provider
from skylos.rules.quality._receivers import _scope_bindings, method_receiver


_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_CLICK_MARKERS = frozenset({"command", "group", "option", "argument"})
_CLICK_INJECTORS = frozenset({"pass_context", "pass_obj"})


class ParameterContext:
    def __init__(self, module, methods, *, filename=None, project_root=None):
        self.module = module
        self.methods = methods
        self.aliases = {}
        self.alias_lines = {}
        self.groups = set()
        self.group_lines = {}
        self.owners = {}
        if not isinstance(module, ast.Module):
            return
        self.bindings = _scope_bindings(module)
        self.mutated = _mutated_names(module)
        for statement in module.body:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    if alias.name == "click":
                        self.aliases[alias.asname or alias.name] = "click"
                        self.alias_lines[alias.asname or alias.name] = statement.lineno
            elif (
                isinstance(statement, ast.ImportFrom)
                and not statement.level
                and statement.module == "click"
            ):
                for alias in statement.names:
                    if alias.name in _CLICK_MARKERS | _CLICK_INJECTORS:
                        self.aliases[alias.asname or alias.name] = "click." + alias.name
                        self.alias_lines[alias.asname or alias.name] = statement.lineno
            elif isinstance(statement, ast.ClassDef):
                self.owners.update(
                    (method, statement)
                    for method in statement.body
                    if isinstance(method, _FUNCTIONS)
                )
        self.aliases = {
            name: value for name, value in self.aliases.items() if self._stable(name)
        }
        if self.aliases and project_local_provider("click", filename, project_root):
            self.aliases.clear()
        for statement in module.body:
            if isinstance(statement, _FUNCTIONS) and self._stable(statement.name):
                if self._known_decorators(statement) and any(
                    isinstance(decorator, ast.Call)
                    and self._qualified(decorator.func) == "click.group"
                    for decorator in statement.decorator_list
                ):
                    self.groups.add(statement.name)
                    self.group_lines[statement.name] = statement.lineno

    @staticmethod
    def _standard_class(call):
        return all(
            keyword.arg is not None
            and (
                keyword.arg != "cls"
                or (
                    isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is None
                )
            )
            for keyword in call.keywords
        )

    def _known_decorators(self, function):
        for decorator in function.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            marker = self._qualified(target)
            if marker not in {
                "click." + name for name in _CLICK_MARKERS | _CLICK_INJECTORS
            }:
                return False
            if isinstance(decorator, ast.Call) and not self._standard_class(decorator):
                return False
        return True

    def _stable(self, name):
        return (
            self.bindings.counts[name] == 1
            and name not in self.mutated
            and "*" not in self.bindings.names
            and "*" not in self.mutated
        )

    def _qualified(self, node):
        if isinstance(node, ast.Name):
            return (
                self.aliases.get(node.id)
                if self.alias_lines.get(node.id, float("inf")) < node.lineno
                else None
            )
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if (
                self.aliases.get(node.value.id) == "click"
                and self.alias_lines[node.value.id] < node.lineno
            ):
                return "click." + node.attr
            if (
                node.value.id in self.groups
                and self.group_lines[node.value.id] < node.lineno
                and node.attr in {"command", "group"}
            ):
                return "click." + node.attr
        return None

    @staticmethod
    def _cli_parameter(decorator, marker):
        # Click consumes declaration strings, using an explicit destination
        # when given, otherwise preferring a long option to its short alias.
        if not decorator.args or any(
            not isinstance(value, ast.Constant) or not isinstance(value.value, str)
            for value in decorator.args
        ):
            return None
        if any(
            kw.arg is None
            or (
                kw.arg == "expose_value"
                and not (isinstance(kw.value, ast.Constant) and kw.value.value is True)
            )
            for kw in decorator.keywords
        ):
            return None
        if not ParameterContext._standard_class(decorator):
            return None
        declarations = [value.value for value in decorator.args]
        if marker == "click.option" and not any(
            value.startswith("-") for value in declarations
        ):
            return None
        named = [value for value in declarations if value.isidentifier()]
        if len(named) == 1:
            return named[0]
        if named or marker == "click.argument":
            return None
        options = [value.split("/", 1)[0] for value in declarations]
        long_options = [value for value in options if value.startswith("--")]
        selected = long_options[0] if long_options else options[0]
        if selected.startswith("---"):
            return None
        name = selected.lstrip("-").replace("-", "_").lower()
        return name if name.isidentifier() else None

    def _click_callback(self, function):
        if not isinstance(self.module, ast.Module) or function not in self.module.body:
            return False
        if not self._known_decorators(function):
            return False
        registered = False
        injected = set()
        receiver_injected = False
        for decorator in function.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            marker = self._qualified(target)
            if marker in {"click.command", "click.group"}:
                registered = True
            elif marker in {"click.argument", "click.option"}:
                if not isinstance(decorator, ast.Call):
                    return False
                name = self._cli_parameter(decorator, marker)
                if name is None or name in injected:
                    return False
                injected.add(name)
            elif marker in {"click.pass_context", "click.pass_obj"}:
                if isinstance(decorator, ast.Call) or receiver_injected:
                    return False
                receiver_injected = True
            else:
                return False
        if not registered:
            return False
        positional = [*function.args.posonlyargs, *function.args.args]
        if function.args.posonlyargs:
            # Click binds declarations by name. An incompatible signature is
            # not evidence that the callback is safe from positional mistakes.
            return False
        if receiver_injected:
            if not positional:
                return False
            if positional[0].arg in injected:
                return False
            injected.add(positional[0].arg)
        parameters = {arg.arg for arg in (*positional, *function.args.kwonlyargs)}
        return bool(parameters) and parameters == injected

    def _record_constructor(self, function):
        owner = self.owners.get(function)
        if (
            owner is None
            or function.name != "__init__"
            or function.decorator_list
            or owner.decorator_list
            or owner.keywords
            or not self._stable(owner.name)
            or _scope_bindings(owner).names
            & {"__setattr__", "__new__", "__getattribute__", "__getattr__"}
            or any(
                not isinstance(base, ast.Name)
                or base.id != "object"
                or "object" in self.bindings.names
                or "object" in self.mutated
                for base in owner.bases
            )
        ):
            return False
        for statement in owner.body:
            if isinstance(statement, _FUNCTIONS):
                if statement.decorator_list:
                    return False
                continue
            if isinstance(statement, ast.Pass):
                continue
            if (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            ):
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                if value is None or all(
                    isinstance(
                        node,
                        (
                            ast.Constant,
                            ast.Tuple,
                            ast.List,
                            ast.Set,
                            ast.Dict,
                            ast.Load,
                        ),
                    )
                    for node in ast.walk(value)
                ):
                    continue
            return False
        receiver = method_receiver(function, kinds=self.methods)
        if receiver is None:
            return False
        parameters = {
            arg.arg
            for arg in (
                *function.args.posonlyargs,
                *function.args.args,
                *function.args.kwonlyargs,
            )
            if arg.arg != receiver
        }
        if function.args.vararg or function.args.kwarg or not parameters:
            return False
        fields = set()
        consumed = set()
        body = list(function.body)
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body = body[1:]
        for statement in body:
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                target = statement.targets[0]
                value = statement.value
            elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
                target, value = statement.target, statement.value
            else:
                return False
            if not (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == receiver
                and isinstance(value, ast.Name)
                and value.id in parameters
                and target.attr not in fields
                and value.id not in consumed
                and not (target.attr.startswith("__") and target.attr.endswith("__"))
            ):
                return False
            # A local property/descriptor with this name introduces behavior.
            if any(
                getattr(member, "name", None) == target.attr
                for member in owner.body
                if member is not function
            ):
                return False
            for member in owner.body:
                if isinstance(member, ast.Assign):
                    targets = member.targets
                    declaration = member.value
                elif isinstance(member, ast.AnnAssign):
                    targets = [member.target]
                    declaration = member.value
                else:
                    continue
                if (
                    any(
                        isinstance(item, ast.Name) and item.id == target.attr
                        for binding in targets
                        for item in ast.walk(binding)
                    )
                    and declaration is not None
                    and not isinstance(declaration, ast.Constant)
                ):
                    return False
            fields.add(target.attr)
            consumed.add(value.id)
        return consumed == parameters

    def exempts(self, function):
        return self._click_callback(function) or self._record_constructor(function)
