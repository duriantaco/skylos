import ast

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


def _is_type_checking_guard(
    test: ast.expr,
    type_checking_names: set[str],
    typing_modules: set[str],
) -> bool:
    if isinstance(test, ast.Name):
        return test.id in type_checking_names
    return (
        isinstance(test, ast.Attribute)
        and test.attr == "TYPE_CHECKING"
        and isinstance(test.value, ast.Name)
        and test.value.id in typing_modules
    )


def type_checking_function_ids(module: ast.Module) -> set[int]:
    function_ids: set[int] = set()

    class BindingCollector(ast.NodeVisitor):
        def __init__(self) -> None:
            self.names: set[str] = set()

        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                self.names.add(node.id)

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
            self.nonlocal_names: set[str] = set()

        def visit_Global(self, node: ast.Global) -> None:
            self.nonlocal_names.update(node.names)

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

    def bound_names(node: ast.AST) -> set[str]:
        collector = BindingCollector()
        collector.visit(node)
        return collector.names

    def function_local_names(
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> set[str]:
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
        for child_statement in function.body:
            collector.visit(child_statement)
        return collector.names - collector.nonlocal_names

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
                is_type_checking = _is_type_checking_guard(
                    statement.test,
                    type_checking_names,
                    typing_modules,
                )
                if is_type_checking:
                    for child_statement in statement.body:
                        function_ids.update(
                            id(child)
                            for child in ast.walk(child_statement)
                            if isinstance(
                                child, (ast.FunctionDef, ast.AsyncFunctionDef)
                            )
                        )
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
                loop_bindings = bound_names(statement.target) | bound_names(
                    statement.iter
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
                test_bindings = bound_names(statement.test)
                scan_branch(statement.body, test_bindings)
                scan_branch(statement.orelse, test_bindings)
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

            if isinstance(statement, ast.Try):
                scan_branch(statement.body)
                body_bindings = set().union(
                    *(bound_names(child) for child in statement.body)
                )
                handler_body_bindings: set[str] = set()
                for handler in statement.handlers:
                    handler_bindings = (
                        {handler.name} if handler.name is not None else set()
                    )
                    scan_branch(
                        handler.body,
                        body_bindings | handler_bindings,
                    )
                    handler_body_bindings.update(handler_bindings)
                    handler_body_bindings.update(
                        *(bound_names(child) for child in handler.body)
                    )
                scan_branch(statement.orelse, body_bindings)
                else_bindings = set().union(
                    *(bound_names(child) for child in statement.orelse)
                )
                scan_branch(
                    statement.finalbody,
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
                for case in statement.cases:
                    case_bindings = subject_bindings | bound_names(case.pattern)
                    if case.guard is not None:
                        case_bindings.update(bound_names(case.guard))
                    scan_branch(case.body, case_bindings)
                discard_bindings(
                    bound_names(statement),
                    type_checking_names,
                    typing_modules,
                )
                continue

            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
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
                    function_local_names(statement) | {statement.name},
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

            discard_bindings(
                bound_names(statement),
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
    return function_ids
