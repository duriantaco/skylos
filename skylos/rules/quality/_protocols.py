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
