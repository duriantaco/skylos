import ast
from typing import cast

_PROTOCOL_MODULES = frozenset({"typing", "typing_extensions"})


def _protocol_import_bindings(module: ast.Module) -> tuple[set[str], set[str]]:
    protocol_names: set[str] = set()
    protocol_modules: set[str] = set()

    for stmt in module.body:
        if isinstance(stmt, ast.ImportFrom) and stmt.module in _PROTOCOL_MODULES:
            for imported in stmt.names:
                if imported.name == "Protocol":
                    protocol_names.add(imported.asname or imported.name)
        elif isinstance(stmt, ast.Import):
            for imported in stmt.names:
                if imported.name in _PROTOCOL_MODULES:
                    protocol_modules.add(imported.asname or imported.name)

    return protocol_names, protocol_modules


def _is_protocol_base(
    base: ast.expr,
    protocol_names: set[str],
    protocol_modules: set[str],
) -> bool:
    if isinstance(base, ast.Subscript):
        base = base.value
    if isinstance(base, ast.Name):
        return base.id in protocol_names
    return (
        isinstance(base, ast.Attribute)
        and base.attr == "Protocol"
        and isinstance(base.value, ast.Name)
        and base.value.id in protocol_modules
    )


def _protocol_classes(module: ast.Module) -> list[ast.ClassDef]:
    protocol_names, protocol_modules = _protocol_import_bindings(module)
    if not protocol_names and not protocol_modules:
        return []

    return [
        candidate
        for candidate in ast.walk(module)
        if isinstance(candidate, ast.ClassDef)
        and any(
            _is_protocol_base(base, protocol_names, protocol_modules)
            for base in candidate.bases
        )
    ]


def protocol_class_ids(module: ast.Module) -> set[int]:
    return {id(candidate) for candidate in _protocol_classes(module)}


def protocol_method_ids(module: ast.Module) -> set[int]:
    return {
        id(stmt)
        for candidate in _protocol_classes(module)
        for stmt in candidate.body
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _type_checking_guard_branch(
    test: ast.expr,
    type_checking_names: set[str],
    typing_modules: set[str],
) -> bool | None:
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        branch = _type_checking_guard_branch(
            test.operand,
            type_checking_names,
            typing_modules,
        )
        return None if branch is None else not branch
    if isinstance(test, ast.Name):
        return True if test.id in type_checking_names else None
    if (
        isinstance(test, ast.Attribute)
        and test.attr == "TYPE_CHECKING"
        and isinstance(test.value, ast.Name)
        and test.value.id in typing_modules
    ):
        return True
    return None


def type_checking_function_ids(module: ast.Module) -> set[int]:
    _, function_ids = _collect_type_checking_context(
        module,
        functions_only=True,
    )
    return function_ids


def type_checking_context(module: ast.Module) -> tuple[dict[int, bool], set[int]]:
    return _collect_type_checking_context(module, functions_only=False)


def type_checking_guard_branches(module: ast.Module) -> dict[int, bool]:
    guard_branches, _ = _collect_type_checking_context(
        module,
        functions_only=None,
    )
    return guard_branches


def _collect_type_checking_context(
    module: ast.Module,
    *,
    functions_only: bool | None,
) -> tuple[dict[int, bool], set[int]]:
    has_candidate_import = any(
        (
            isinstance(node, ast.ImportFrom)
            and node.module in _PROTOCOL_MODULES
            and any(imported.name == "TYPE_CHECKING" for imported in node.names)
        )
        or (
            isinstance(node, ast.Import)
            and any(imported.name in _PROTOCOL_MODULES for imported in node.names)
        )
        for node in ast.walk(module)
    )
    if not has_candidate_import:
        return {}, set()

    guard_branches: dict[int, bool] = {}
    context_ids: set[int] = set()

    def mutated_type_checking_module(node: ast.Call) -> str | None:
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in {"setattr", "delattr"}
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == "TYPE_CHECKING"
        ):
            return node.args[0].id
        return None

    class BindingCollector(ast.NodeVisitor):
        def __init__(self) -> None:
            self.names: set[str] = set()

        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                self.names.add(node.id)

        def visit_Attribute(self, node: ast.Attribute) -> None:
            if (
                node.attr == "TYPE_CHECKING"
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and isinstance(node.value, ast.Name)
            ):
                self.names.add(node.value.id)
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            mutated_module = mutated_type_checking_module(node)
            if mutated_module is not None:
                self.names.add(mutated_module)
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            if node.value is not None:
                self.visit(node.target)
                self.visit(node.value)
            self.visit(node.annotation)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.names.add(node.name)
            self._visit_function_header(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.names.add(node.name)
            self._visit_function_header(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.names.add(node.name)
            for decorator in node.decorator_list:
                self.visit(decorator)
            for base in node.bases:
                self.visit(base)
            for keyword in node.keywords:
                self.visit(keyword.value)

        def _visit_function_header(
            self,
            node: ast.FunctionDef | ast.AsyncFunctionDef,
        ) -> None:
            for decorator in node.decorator_list:
                self.visit(decorator)
            for default in node.args.defaults:
                self.visit(default)
            for default in node.args.kw_defaults:
                if default is not None:
                    self.visit(default)

        def visit_Import(self, node: ast.Import) -> None:
            self.names.update(
                imported.asname or imported.name.split(".", 1)[0]
                for imported in node.names
            )

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            self.names.update(
                imported.asname or imported.name for imported in node.names
            )

        def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
            if node.name is not None:
                self.names.add(node.name)
            self.generic_visit(node)

        def visit_MatchAs(self, node: ast.MatchAs) -> None:
            if node.name is not None:
                self.names.add(node.name)
            self.generic_visit(node)

        def visit_MatchStar(self, node: ast.MatchStar) -> None:
            if node.name is not None:
                self.names.add(node.name)

        def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
            if node.rest is not None:
                self.names.add(node.rest)
            self.generic_visit(node)

        def visit_ListComp(self, node: ast.ListComp) -> None:
            self._visit_comprehension(node.generators, node.elt)

        def visit_SetComp(self, node: ast.SetComp) -> None:
            self._visit_comprehension(node.generators, node.elt)

        def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
            self._visit_comprehension(node.generators, node.elt)

        def visit_DictComp(self, node: ast.DictComp) -> None:
            self._visit_comprehension(node.generators, node.key, node.value)

        def _visit_comprehension(
            self,
            generators: list[ast.comprehension],
            *values: ast.expr,
        ) -> None:
            for generator in generators:
                self.visit(generator.iter)
                for condition in generator.ifs:
                    self.visit(condition)
            for value in values:
                self.visit(value)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            for default in node.args.defaults:
                self.visit(default)
            for default in node.args.kw_defaults:
                if default is not None:
                    self.visit(default)

    class FunctionBindingCollector(BindingCollector):
        def __init__(self) -> None:
            super().__init__()
            self.global_names: set[str] = set()
            self.nonlocal_names: set[str] = set()

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            # A bare annotation makes a simple name local for the whole
            # function, even though it does not bind a value at runtime.
            if isinstance(node.target, ast.Name):
                self.names.add(node.target.id)
            elif node.value is not None:
                self.visit(node.target)
            self.visit(node.annotation)
            if node.value is not None:
                self.visit(node.value)

        def visit_Global(self, node: ast.Global) -> None:
            self.global_names.update(node.names)

        def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
            self.nonlocal_names.update(node.names)

    class ClosureAliasCollector(BindingCollector):
        def __init__(self) -> None:
            super().__init__()
            self.typing_kinds: dict[str, set[str]] = {}

        def _record_typing_kind(self, name: str, kind: str) -> None:
            self.typing_kinds.setdefault(name, set()).add(kind)

        def visit_Import(self, node: ast.Import) -> None:
            for imported in node.names:
                local_name = imported.asname or imported.name.split(".", 1)[0]
                if imported.name in _PROTOCOL_MODULES:
                    self._record_typing_kind(local_name, "module")
                else:
                    self.names.add(local_name)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            for imported in node.names:
                local_name = imported.asname or imported.name
                if (
                    node.module in _PROTOCOL_MODULES
                    and imported.name == "TYPE_CHECKING"
                ):
                    self._record_typing_kind(local_name, "sentinel")
                else:
                    self.names.add(local_name)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            super().visit_ClassDef(node)
            self.names.update(class_external_names(node))

    def bound_names(node: ast.AST) -> set[str]:
        collector = BindingCollector()
        collector.visit(node)
        return collector.names

    def type_parameter_names(
        node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
    ) -> set[str]:
        return {
            type_parameter.name
            for type_parameter in getattr(node, "type_params", [])
            if isinstance(getattr(type_parameter, "name", None), str)
        }

    def function_scope_bindings(
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> tuple[set[str], set[str]]:
        collector = FunctionBindingCollector()
        collector.names.update(
            argument.arg
            for argument in (
                *function.args.posonlyargs,
                *function.args.args,
                *function.args.kwonlyargs,
            )
        )
        if function.args.vararg is not None:
            collector.names.add(function.args.vararg.arg)
        if function.args.kwarg is not None:
            collector.names.add(function.args.kwarg.arg)
        collector.names.update(type_parameter_names(function))
        for child_statement in function.body:
            collector.visit(child_statement)
        local_names = collector.names - (
            collector.global_names | collector.nonlocal_names
        )
        external_names = collector.global_names | collector.nonlocal_names
        return local_names, external_names

    def class_external_names(class_node: ast.ClassDef) -> set[str]:
        class ExternalCollector(ast.NodeVisitor):
            def __init__(self) -> None:
                self.names: set[str] = set()

            def visit_Global(self, node: ast.Global) -> None:
                self.names.update(node.names)

            def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
                self.names.update(node.names)

            def visit_Attribute(self, node: ast.Attribute) -> None:
                if (
                    node.attr == "TYPE_CHECKING"
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                    and isinstance(node.value, ast.Name)
                ):
                    self.names.add(node.value.id)
                self.generic_visit(node)

            def visit_Call(self, node: ast.Call) -> None:
                mutated_module = mutated_type_checking_module(node)
                if mutated_module is not None:
                    self.names.add(mutated_module)
                self.generic_visit(node)

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                return

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                return

            def visit_Lambda(self, node: ast.Lambda) -> None:
                return

        collector = ExternalCollector()
        for child_statement in class_node.body:
            collector.visit(child_statement)
        return collector.names

    def closure_unsafe_names(
        statements: list[ast.stmt],
        parameters: set[str] | None = None,
    ) -> set[str]:
        collector = ClosureAliasCollector()
        if parameters:
            collector.names.update(parameters)
        for statement in statements:
            collector.visit(statement)
        collector.names.update(
            name
            for name, kinds in collector.typing_kinds.items()
            if len(kinds) != 1
        )
        return collector.names

    def discard_bindings(
        names: set[str],
        type_checking_names: set[str],
        typing_modules: set[str],
    ) -> None:
        type_checking_names.difference_update(names)
        typing_modules.difference_update(names)

    def scan_statements(
        statements: list[ast.stmt],
        type_checking_names: set[str],
        typing_modules: set[str],
        *,
        scope_kind: str,
        class_function_type_checking_names: set[str] | None = None,
        class_function_typing_modules: set[str] | None = None,
        nested_function_unsafe_names: set[str] | None = None,
    ) -> None:
        def scan_branch(
            branch: list[ast.stmt],
            shadowed_names: set[str] | None = None,
        ) -> None:
            branch_type_checking_names = set(type_checking_names)
            branch_typing_modules = set(typing_modules)
            if shadowed_names:
                discard_bindings(
                    shadowed_names,
                    branch_type_checking_names,
                    branch_typing_modules,
                )
            scan_statements(
                branch,
                branch_type_checking_names,
                branch_typing_modules,
                scope_kind=scope_kind,
                class_function_type_checking_names=(
                    class_function_type_checking_names
                ),
                class_function_typing_modules=class_function_typing_modules,
                nested_function_unsafe_names=nested_function_unsafe_names,
            )

        for statement in statements:
            if isinstance(statement, ast.Import):
                for imported in statement.names:
                    local_name = imported.asname or imported.name.split(".", 1)[0]
                    discard_bindings(
                        {local_name}, type_checking_names, typing_modules
                    )
                    if imported.name in _PROTOCOL_MODULES:
                        typing_modules.add(local_name)
                continue

            if isinstance(statement, ast.ImportFrom):
                for imported in statement.names:
                    local_name = imported.asname or imported.name
                    discard_bindings(
                        {local_name}, type_checking_names, typing_modules
                    )
                    if (
                        statement.module in _PROTOCOL_MODULES
                        and imported.name == "TYPE_CHECKING"
                    ):
                        type_checking_names.add(local_name)
                continue

            if isinstance(statement, ast.If):
                type_checking_branch = _type_checking_guard_branch(
                    statement.test,
                    type_checking_names,
                    typing_modules,
                )
                if type_checking_branch is not None:
                    guard_branches[id(statement)] = type_checking_branch
                    guarded_branch = (
                        statement.body if type_checking_branch else statement.orelse
                    )
                    runtime_branch = (
                        statement.orelse if type_checking_branch else statement.body
                    )
                    if functions_only is not None:
                        for child_statement in guarded_branch:
                            context_ids.update(
                                id(child)
                                for child in ast.walk(child_statement)
                                if not functions_only
                                or isinstance(
                                    child,
                                    (ast.FunctionDef, ast.AsyncFunctionDef),
                                )
                            )
                    scan_branch(guarded_branch, bound_names(statement.test))
                    scan_branch(runtime_branch, bound_names(statement.test))
                else:
                    scan_branch(statement.body, bound_names(statement.test))
                    scan_branch(statement.orelse, bound_names(statement.test))
                discard_bindings(
                    bound_names(statement),
                    type_checking_names,
                    typing_modules,
                )
                continue

            if isinstance(statement, (ast.For, ast.AsyncFor)):
                body_bindings = set().union(
                    *(bound_names(child) for child in statement.body)
                )
                loop_bindings = (
                    bound_names(statement.target)
                    | bound_names(statement.iter)
                    | body_bindings
                )
                scan_branch(statement.body, loop_bindings)
                scan_branch(statement.orelse, loop_bindings)
                discard_bindings(
                    bound_names(statement),
                    type_checking_names,
                    typing_modules,
                )
                continue

            if isinstance(statement, ast.While):
                loop_bindings = bound_names(statement.test) | set().union(
                    *(bound_names(child) for child in statement.body)
                )
                scan_branch(statement.body, loop_bindings)
                scan_branch(statement.orelse, loop_bindings)
                discard_bindings(
                    bound_names(statement),
                    type_checking_names,
                    typing_modules,
                )
                continue

            if isinstance(statement, (ast.With, ast.AsyncWith)):
                with_bindings: set[str] = set()
                for item in statement.items:
                    with_bindings.update(bound_names(item.context_expr))
                    if item.optional_vars is not None:
                        with_bindings.update(bound_names(item.optional_vars))
                scan_branch(statement.body, with_bindings)
                discard_bindings(
                    bound_names(statement),
                    type_checking_names,
                    typing_modules,
                )
                continue

            if isinstance(statement, ast.Try) or type(statement).__name__ == "TryStar":
                try_statement = cast(ast.Try, statement)
                is_try_star = type(statement).__name__ == "TryStar"
                scan_branch(try_statement.body)
                body_bindings = set().union(
                    *(bound_names(child) for child in try_statement.body)
                )
                handler_body_bindings: set[str] = set()
                prior_handler_type_bindings: set[str] = set()
                prior_star_handler_bindings: set[str] = set()
                for handler in try_statement.handlers:
                    handler_bindings = (
                        {handler.name} if handler.name is not None else set()
                    )
                    handler_type_bindings: set[str] = set()
                    if handler.type is not None:
                        handler_type_bindings = bound_names(handler.type)
                        handler_bindings.update(handler_type_bindings)
                    scan_branch(
                        handler.body,
                        body_bindings
                        | prior_handler_type_bindings
                        | prior_star_handler_bindings
                        | handler_bindings,
                    )
                    handler_effect_bindings = set().union(
                        *(bound_names(child) for child in handler.body)
                    )
                    handler_body_bindings.update(handler_bindings)
                    handler_body_bindings.update(handler_effect_bindings)
                    prior_handler_type_bindings.update(handler_type_bindings)
                    if is_try_star:
                        prior_star_handler_bindings.update(handler_bindings)
                        prior_star_handler_bindings.update(
                            handler_effect_bindings
                        )
                scan_branch(try_statement.orelse, body_bindings)
                else_bindings = set().union(
                    *(bound_names(child) for child in try_statement.orelse)
                )
                scan_branch(
                    try_statement.finalbody,
                    body_bindings | handler_body_bindings | else_bindings,
                )
                discard_bindings(
                    bound_names(statement),
                    type_checking_names,
                    typing_modules,
                )
                continue

            if isinstance(statement, ast.Match):
                subject_bindings = bound_names(statement.subject)
                prior_case_bindings = set(subject_bindings)
                for case in statement.cases:
                    case_bindings = prior_case_bindings | bound_names(case.pattern)
                    if case.guard is not None:
                        case_bindings.update(bound_names(case.guard))
                    scan_branch(case.body, case_bindings)
                    prior_case_bindings.update(bound_names(case.pattern))
                    if case.guard is not None:
                        prior_case_bindings.update(bound_names(case.guard))
                discard_bindings(
                    bound_names(statement),
                    type_checking_names,
                    typing_modules,
                )
                continue

            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_local_names, function_external_names = (
                    function_scope_bindings(statement)
                )
                if scope_kind == "class":
                    function_type_checking_names = set(
                        class_function_type_checking_names or set()
                    )
                    function_typing_modules = set(
                        class_function_typing_modules or set()
                    )
                else:
                    function_type_checking_names = set(type_checking_names)
                    function_typing_modules = set(typing_modules)
                    discard_bindings(
                        nested_function_unsafe_names or set(),
                        function_type_checking_names,
                        function_typing_modules,
                    )
                discard_bindings(
                    function_local_names
                    | function_external_names
                    | {statement.name},
                    function_type_checking_names,
                    function_typing_modules,
                )
                scan_statements(
                    statement.body,
                    function_type_checking_names,
                    function_typing_modules,
                    scope_kind="function",
                    nested_function_unsafe_names=closure_unsafe_names(
                        statement.body,
                        {
                            argument.arg
                            for argument in (
                                *statement.args.posonlyargs,
                                *statement.args.args,
                                *statement.args.kwonlyargs,
                            )
                        }
                        | (
                            {statement.args.vararg.arg}
                            if statement.args.vararg is not None
                            else set()
                        )
                        | (
                            {statement.args.kwarg.arg}
                            if statement.args.kwarg is not None
                            else set()
                        ),
                    ),
                )

            if isinstance(statement, ast.ClassDef):
                if scope_kind == "class":
                    nested_class_type_checking_names = set(
                        class_function_type_checking_names or set()
                    )
                    nested_class_typing_modules = set(
                        class_function_typing_modules or set()
                    )
                    nested_class_function_type_checking_names = set(
                        class_function_type_checking_names or set()
                    )
                    nested_class_function_typing_modules = set(
                        class_function_typing_modules or set()
                    )
                else:
                    nested_class_type_checking_names = set(type_checking_names)
                    nested_class_typing_modules = set(typing_modules)
                    nested_class_function_type_checking_names = set(
                        type_checking_names
                    )
                    nested_class_function_typing_modules = set(typing_modules)
                    discard_bindings(
                        nested_function_unsafe_names or set(),
                        nested_class_function_type_checking_names,
                        nested_class_function_typing_modules,
                    )
                class_type_parameter_names = type_parameter_names(statement)
                discard_bindings(
                    class_type_parameter_names,
                    nested_class_type_checking_names,
                    nested_class_typing_modules,
                )
                discard_bindings(
                    class_type_parameter_names,
                    nested_class_function_type_checking_names,
                    nested_class_function_typing_modules,
                )
                scan_statements(
                    statement.body,
                    nested_class_type_checking_names,
                    nested_class_typing_modules,
                    scope_kind="class",
                    class_function_type_checking_names=(
                        nested_class_function_type_checking_names
                    ),
                    class_function_typing_modules=(
                        nested_class_function_typing_modules
                    ),
                )

            statement_bindings = bound_names(statement)
            if isinstance(statement, ast.ClassDef):
                statement_bindings.update(class_external_names(statement))
            discard_bindings(
                statement_bindings,
                type_checking_names,
                typing_modules,
            )

    scan_statements(
        module.body,
        set(),
        set(),
        scope_kind="module",
        nested_function_unsafe_names=closure_unsafe_names(module.body),
    )
    return guard_branches, context_ids
