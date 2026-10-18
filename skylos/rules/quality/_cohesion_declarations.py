"""Bounded source-declaration proof for implementation cohesion."""

import ast

from skylos.rules.quality._ast_visit import IterativeNodeVisitor


def declaration_method_ids(node: ast.Module | ast.ClassDef) -> set[int]:
    """Identify source declarations without treating implemented ABCs as interfaces.

    Empty bodies are declarations regardless of a framework's naming convention.
    A NotImplementedError marker additionally needs a complete module and a
    lexical builtin lookup; custom exceptions and effectful arguments stay code.
    """

    class Bindings(IterativeNodeVisitor):
        def __init__(self):
            self.names = set()
            self.globals = set()

        def visit_Name(self, item):
            if isinstance(item.ctx, (ast.Store, ast.Del)):
                self.names.add(item.id)

        def visit_Global(self, item):
            self.globals.update(item.names)

        def visit_FunctionDef(self, item):
            self.names.add(item.name)
            for expression in [
                *item.decorator_list,
                *item.args.defaults,
                *[default for default in item.args.kw_defaults if default is not None],
            ]:
                self.visit(expression)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, item):
            self.names.add(item.name)
            for expression in [
                *item.decorator_list,
                *item.bases,
                *[keyword.value for keyword in item.keywords],
            ]:
                self.visit(expression)

        def visit_Lambda(self, item):
            for expression in [
                *item.args.defaults,
                *[default for default in item.args.kw_defaults if default is not None],
            ]:
                self.visit(expression)

        def visit_Import(self, item):
            self.names.update(a.asname or a.name.split(".")[0] for a in item.names)

        def visit_ImportFrom(self, item):
            self.names.update(a.asname or a.name for a in item.names)
            if any(a.name == "*" for a in item.names):
                self.names.add("NotImplementedError")

        def visit_ExceptHandler(self, item):
            if item.name:
                self.names.add(item.name)
            self.generic_visit(item)

        def visit_MatchAs(self, item):
            if item.name:
                self.names.add(item.name)
            self.generic_visit(item)

        visit_MatchStar = visit_MatchAs

        def visit_MatchMapping(self, item):
            if item.rest:
                self.names.add(item.rest)
            self.generic_visit(item)

    def bindings(scope):
        found = Bindings()
        for statement in scope.body:
            found.visit(statement)
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = scope.args
            found.names.update(
                arg.arg for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]
            )
            if args.vararg:
                found.names.add(args.vararg.arg)
            if args.kwarg:
                found.names.add(args.kwarg.arg)
            found.names.update(
                parameter.name for parameter in getattr(scope, "type_params", ())
            )
        return found

    complete_module = isinstance(node, ast.Module)
    module_shadow = "NotImplementedError" in bindings(node).names
    builtin_modules = {"__builtins__"}
    namespace_functions = {"exec", "eval", "globals"}
    for item in ast.walk(node):
        if isinstance(item, ast.Import):
            builtin_modules.update(
                alias.asname or alias.name
                for alias in item.names
                if alias.name == "builtins"
            )
        elif isinstance(item, ast.ImportFrom) and item.module == "builtins":
            namespace_functions.update(
                alias.asname or alias.name
                for alias in item.names
                if alias.name in {"exec", "eval", "globals"}
            )
    # Track simple namespace/function aliases before checking for escaping
    # mutable namespace handles. A read of an unrelated object's own fields
    # does not establish a builtin mutation.
    changed = True
    while changed:
        changed = False
        for item in ast.walk(node):
            if not isinstance(item, (ast.Assign, ast.AnnAssign)):
                continue
            value = item.value
            if not isinstance(value, ast.Name):
                continue
            targets = item.targets if isinstance(item, ast.Assign) else [item.target]
            for names in (builtin_modules, namespace_functions):
                if value.id in names:
                    aliases = {t.id for t in targets if isinstance(t, ast.Name)}
                    changed |= not aliases.issubset(names)
                    names.update(aliases)
    # A global write in another function or an explicit builtin mutation also
    # prevents claiming the exception still has its builtin identity.
    for item in ast.walk(node):
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found = bindings(item)
            if "NotImplementedError" in found.globals & found.names:
                module_shadow = True
        elif (
            isinstance(item, ast.Attribute)
            and item.attr == "NotImplementedError"
            and isinstance(item.ctx, (ast.Store, ast.Del))
            and isinstance(item.value, ast.Name)
            and item.value.id in builtin_modules
        ):
            module_shadow = True
        elif (
            isinstance(item, ast.Name)
            and isinstance(item.ctx, ast.Load)
            and item.id in namespace_functions | {"__builtins__"}
        ):
            module_shadow = True
        elif isinstance(item, ast.Attribute) and isinstance(item.value, ast.Name):
            if item.value.id in builtin_modules and item.attr in {
                "__dict__", "exec", "eval", "globals", "locals", "vars"
            }:
                module_shadow = True
        elif isinstance(item, ast.Call) and any(
            isinstance(argument, ast.Name) and argument.id in builtin_modules
            for argument in [*item.args, *[keyword.value for keyword in item.keywords]]
        ):
            # An unknown callee can mutate the module or retain its namespace.
            module_shadow = True

    declarations = set()

    def is_declaration(function, shadowed):
        body = list(function.body)
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body = body[1:]
        if all(
            isinstance(statement, ast.Pass)
            or (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and statement.value.value is Ellipsis
            )
            for statement in body
        ):
            return True
        if not complete_module or shadowed or len(body) != 1:
            return False
        statement = body[0]
        if not isinstance(statement, ast.Raise) or statement.cause is not None:
            return False
        exception = statement.exc
        if isinstance(exception, ast.Call):
            if exception.keywords or not all(
                isinstance(arg, ast.Constant) for arg in exception.args
            ):
                return False
            exception = exception.func
        return isinstance(exception, ast.Name) and exception.id == "NotImplementedError"

    pending = [(node, module_shadow)]
    while pending:
        item, shadowed = pending.pop()
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found = bindings(item)
            local_shadow = (
                module_shadow
                if "NotImplementedError" in found.globals
                else shadowed or "NotImplementedError" in found.names
            )
            if is_declaration(item, local_shadow):
                declarations.add(id(item))
            pending.extend((statement, local_shadow) for statement in item.body)
        else:
            # Class namespaces are not enclosing lexical scopes of method bodies.
            # Generic class type parameters do have an enclosing annotation scope.
            if isinstance(item, ast.ClassDef) and any(
                parameter.name == "NotImplementedError"
                for parameter in getattr(item, "type_params", ())
            ):
                shadowed = True
            pending.extend((child, shadowed) for child in ast.iter_child_nodes(item))
    return declarations
