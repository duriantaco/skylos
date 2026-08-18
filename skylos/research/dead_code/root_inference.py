from __future__ import annotations

import ast
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from skylos.research.dead_code.binding import (
    ModuleBindings,
    collect_bindings,
    dotted_name,
)
from skylos.research.dead_code.evidence import SymbolKey
from skylos.research.dead_code.frameworks import (
    CONFIDENCE_EXACT,
    CONFIDENCE_FRAMEWORK_PACKAGE,
    CONFIDENCE_UNKNOWN_THIRD_PARTY,
    CONFIDENCE_UNRESOLVED,
    is_known_framework_origin,
    lookup_origin,
    top_level_package,
)
from skylos.research.dead_code.public_api import PublicApi, collect_public_api
from skylos.research.dead_code.roots import InferredRoot, RootKind, RootSet


_ROUTE_DECORATOR_NAMES = {
    "route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "trace",
    "websocket",
}
_CLI_DECORATOR_NAMES = {
    "command",
    "group",
    "callback",
    "result_callback",
    "default",
    "subcommand",
    "main",
}
_TASK_DECORATOR_NAMES = {"task", "shared_task"}
_VALIDATOR_DECORATOR_NAMES = {
    "validator",
    "field_validator",
    "model_validator",
    "root_validator",
    "validates",
    "validates_schema",
}
_SERIALIZER_DECORATOR_NAMES = {
    "field_serializer",
    "model_serializer",
    "computed_field",
    "pre_load",
    "post_load",
    "pre_dump",
    "post_dump",
}
_PLUGIN_DECORATOR_NAMES = {"hookimpl", "register", "receiver", "subscriber", "listener"}


@dataclass(frozen=True)
class RootInferenceConfig:
    include_tests: bool = True
    include_package_entrypoints: bool = True
    resolve_imports: bool = True
    include_public_exports: bool = True


def infer_roots(
    project_root: str | Path,
    *,
    config: RootInferenceConfig | None = None,
) -> RootSet:
    cfg = config or RootInferenceConfig()
    root = Path(project_root).resolve()
    roots = RootSet()

    python_files = list(_iter_python_files(root))
    first_party = _first_party_packages(root, python_files)

    trees: dict[Path, ast.Module] = {}
    module_names: dict[Path, str] = {}
    for path in python_files:
        try:
            trees[path] = ast.parse(
                path.read_text(encoding="utf-8"), filename=str(path)
            )
        except (OSError, SyntaxError, ValueError):
            continue
        module_names[path] = _module_name(root, path)

    public_api = (
        collect_public_api(module_names, trees)
        if cfg.include_public_exports
        else PublicApi()
    )

    for path, tree in trees.items():
        _infer_python_file_roots(
            root,
            path,
            roots,
            tree=tree,
            module=module_names[path],
            include_tests=cfg.include_tests,
            resolve_imports=cfg.resolve_imports,
            first_party=first_party,
            include_public_exports=cfg.include_public_exports,
            public_api=public_api,
        )

    if cfg.include_package_entrypoints:
        _infer_pyproject_roots(root, roots)

    return roots


def _iter_python_files(project_root: Path) -> Iterable[Path]:
    ignored = {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".skylos",
        ".venv",
        "__pycache__",
        "node_modules",
        "venv",
    }
    for path in project_root.rglob("*.py"):
        if any(part in ignored for part in path.parts):
            continue
        yield path


def _first_party_packages(project_root: Path, paths: list[Path]) -> frozenset[str]:
    """Top-level package/module names that this project defines itself.

    A decorator resolving into one of these is project-local, so it carries no
    framework registration semantics and must not rescue the symbol it wraps.
    """
    names: set[str] = set()
    for path in paths:
        module = _module_name(project_root, path)
        if module:
            names.add(module.split(".", 1)[0])
    return frozenset(names)


def _infer_python_file_roots(
    project_root: Path,
    path: Path,
    roots: RootSet,
    *,
    tree: ast.Module,
    module: str,
    include_tests: bool,
    resolve_imports: bool = True,
    first_party: frozenset[str] = frozenset(),
    include_public_exports: bool = True,
    public_api: PublicApi | None = None,
) -> None:
    bindings = collect_bindings(tree, module) if resolve_imports else ModuleBindings()
    visitor = _RootVisitor(
        project_root,
        path,
        module,
        roots,
        include_tests=include_tests,
        is_test_file=_is_test_file(project_root, path),
        resolve_imports=resolve_imports,
        bindings=bindings,
        first_party=first_party,
        public_api=public_api or PublicApi(),
    )
    visitor.visit(tree)

    if include_public_exports:
        _infer_public_export_roots(path, tree, module, roots)


def _infer_public_export_roots(
    path: Path, tree: ast.Module, module: str, roots: RootSet
) -> None:
    """Record ``__all__`` entries as externally consumable API.

    A name a module explicitly exports is part of a contract with callers this
    analysis cannot see.  Reporting it dead on in-repo evidence alone is
    unsound for libraries, so it is recorded as uncertainty.
    """
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "__all__"
            for target in node.targets
        ):
            continue
        if not isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
            continue
        for element in node.value.elts:
            if not isinstance(element, ast.Constant) or not isinstance(
                element.value, str
            ):
                continue
            roots.add(
                InferredRoot(
                    symbol=SymbolKey(
                        file=str(path),
                        qualified_name=(
                            f"{module}.{element.value}" if module else element.value
                        ),
                        kind="symbol",
                        line=getattr(node, "lineno", 0),
                    ),
                    kind=RootKind.PUBLIC_EXPORT,
                    reason=f"declared in __all__ of {module or path.name}",
                    source="python_ast",
                )
            )


def _infer_pyproject_roots(project_root: Path, roots: RootSet) -> None:
    pyproject = project_root / "pyproject.toml"
    if not pyproject.exists():
        return

    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return

    project = data.get("project", {})
    scripts = {}
    if isinstance(project, dict):
        raw_scripts = project.get("scripts", {})
        raw_gui_scripts = project.get("gui-scripts", {})
        if isinstance(raw_scripts, dict):
            scripts.update(raw_scripts)
        if isinstance(raw_gui_scripts, dict):
            scripts.update(raw_gui_scripts)

    poetry_scripts = (
        data.get("tool", {})
        .get("poetry", {})
        .get("scripts", {})
        if isinstance(data.get("tool"), dict)
        else {}
    )
    if isinstance(poetry_scripts, dict):
        scripts.update(poetry_scripts)

    for command_name, target in scripts.items():
        if not isinstance(command_name, str) or not isinstance(target, str):
            continue
        module_name, _, symbol_name = target.partition(":")
        if not module_name or not symbol_name:
            continue
        roots.add(
            InferredRoot(
                symbol=SymbolKey(
                    file=str(project_root / (module_name.replace(".", "/") + ".py")),
                    qualified_name=f"{module_name}.{symbol_name}",
                    kind="function",
                    line=0,
                ),
                kind=RootKind.PACKAGE_ENTRYPOINT,
                reason=f"pyproject script {command_name}",
                source="pyproject.toml",
            )
        )


class _RootVisitor(ast.NodeVisitor):
    def __init__(
        self,
        project_root: Path,
        path: Path,
        module: str,
        roots: RootSet,
        *,
        include_tests: bool,
        is_test_file: bool,
        resolve_imports: bool = True,
        bindings: ModuleBindings | None = None,
        first_party: frozenset[str] = frozenset(),
        public_api: PublicApi | None = None,
    ) -> None:
        self.project_root = project_root
        self.path = path
        self.module = module
        self.roots = roots
        self.include_tests = include_tests
        self.is_test_file = is_test_file
        self.resolve_imports = resolve_imports
        self.bindings = bindings or ModuleBindings()
        self.first_party = first_party
        self.public_api = public_api or PublicApi()
        self.class_stack: list[str] = []

    def generic_visit(self, node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qualified_class = self._qualified_name(node.name)
        if self.public_api.covers_class(qualified_class):
            self._add_public_method_roots(node, qualified_class)
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def _add_public_method_roots(
        self, node: ast.ClassDef, qualified_class: str
    ) -> None:
        """Public methods of an exported class are callable by downstream code."""
        for statement in node.body:
            if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if statement.name.startswith("_"):
                continue
            self._add_root(
                f"{qualified_class}.{statement.name}",
                "method",
                RootKind.PUBLIC_EXPORT,
                reason=f"public method of exported class {qualified_class}",
                source="python_ast",
                line=statement.lineno,
            )

    def visit_Call(self, node: ast.Call) -> None:
        target = self._imperative_registration_target(node)
        if target:
            self._add_named_root(
                target,
                RootKind.FRAMEWORK_ROUTE,
                reason=f"imperative registration via {_call_name(node.func)}",
                source="python_ast",
                line=getattr(node, "lineno", 0),
            )
        self.generic_visit(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qname = self._qualified_name(node.name)
        for decorator in node.decorator_list:
            resolved = self._resolve_decorator_root(decorator)
            if resolved is None:
                continue
            kind, confidence, reason = resolved
            self._add_root(
                qname,
                "method" if self.class_stack else "function",
                kind,
                reason=reason,
                source="python_ast",
                line=node.lineno,
                confidence=confidence,
            )

        if self.include_tests and self.is_test_file:
            if node.name.startswith("test_") or self._is_pytest_fixture(node):
                self._add_root(
                    qname,
                    "method" if self.class_stack else "function",
                    RootKind.TEST,
                    reason="pytest test or fixture entrypoint",
                    source="python_ast",
                    line=node.lineno,
                )
        self.generic_visit(node)

    def _qualified_name(self, name: str) -> str:
        parts = [self.module, *self.class_stack, name]
        return ".".join(part for part in parts if part)

    def _add_named_root(
        self,
        name: str,
        kind: RootKind,
        *,
        reason: str,
        source: str,
        line: int,
    ) -> None:
        self._add_root(
            self._qualified_name(name),
            "function",
            kind,
            reason=reason,
            source=source,
            line=line,
        )

    def _add_root(
        self,
        qname: str,
        symbol_kind: str,
        kind: RootKind,
        *,
        reason: str,
        source: str,
        line: int,
        confidence: float = CONFIDENCE_EXACT,
    ) -> None:
        self.roots.add(
            InferredRoot(
                symbol=SymbolKey(
                    file=str(self.path),
                    qualified_name=qname,
                    kind=symbol_kind,
                    line=line,
                ),
                kind=kind,
                reason=reason,
                source=source,
                confidence=confidence,
            )
        )

    def _resolve_decorator_root(
        self, decorator: ast.AST
    ) -> tuple[RootKind, float, str] | None:
        """Map a decorator to a root kind and a confidence in that mapping.

        Returns ``None`` when the decorator carries no registration evidence at
        all -- most importantly when it resolves to a first-party definition,
        which is an ordinary function and must be left to reachability.
        """
        dotted = dotted_name(decorator)
        if not dotted:
            return None

        if not self.resolve_imports:
            kind = _legacy_root_kind_for_name(dotted)
            if kind is None:
                return None
            return kind, CONFIDENCE_EXACT, f"decorator {dotted}"

        origin = self.bindings.resolve(dotted)
        if origin is None:
            if _legacy_root_kind_for_name(dotted) is None:
                return None
            return (
                RootKind.FRAMEWORK_DECORATOR,
                CONFIDENCE_UNRESOLVED,
                f"unresolved decorator {dotted}",
            )

        registered = lookup_origin(origin)
        if registered is not None:
            return registered, CONFIDENCE_EXACT, f"decorator {dotted} -> {origin}"

        if top_level_package(origin) in self.first_party:
            return None

        if is_known_framework_origin(origin):
            return (
                RootKind.FRAMEWORK_DECORATOR,
                CONFIDENCE_FRAMEWORK_PACKAGE,
                f"decorator {dotted} -> {origin} (known framework package)",
            )

        return (
            RootKind.FRAMEWORK_DECORATOR,
            CONFIDENCE_UNKNOWN_THIRD_PARTY,
            f"decorator {dotted} -> {origin} (unknown third party)",
        )

    def _is_pytest_fixture(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> bool:
        for decorator in node.decorator_list:
            dotted = dotted_name(decorator)
            if not self.resolve_imports:
                if dotted.rsplit(".", 1)[-1].endswith("fixture"):
                    return True
                continue
            origin = self.bindings.resolve(dotted)
            if origin is not None and lookup_origin(origin) is RootKind.TEST:
                return True
            if origin is None and dotted.rsplit(".", 1)[-1].endswith("fixture"):
                return True
        return False

    def _imperative_registration_target(self, node: ast.Call) -> str | None:
        name = _call_name(node.func)
        if not name:
            return None

        if name.endswith(".add_url_rule"):
            target = _keyword_value(node, "view_func")
            if target is None and len(node.args) >= 3:
                target = node.args[2]
            return _simple_name(target)

        if name.endswith(".add_api_route") or name.endswith(".add_route"):
            target = _keyword_value(node, "endpoint", "handler", "view_func")
            if target is None and len(node.args) >= 2:
                target = node.args[1]
            return _simple_name(target)

        return None


def _module_name(project_root: Path, path: Path) -> str:
    rel = path.resolve().relative_to(project_root.resolve())
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    if parts and parts[0] == "src":
        parts = parts[1:]
    return ".".join(parts)


def _is_test_file(project_root: Path, path: Path) -> bool:
    rel = path.resolve().relative_to(project_root.resolve())
    if path.name == "conftest.py":
        return True
    if path.name.startswith("test_") or path.name.endswith("_test.py"):
        return True
    return any(part in {"test", "tests"} for part in rel.parts[:-1])


def _legacy_root_kind_for_name(name: str) -> RootKind | None:
    """Name-only decorator matching retained as the ablation baseline."""
    if not name:
        return None
    base = name.rsplit(".", 1)[-1]

    if base in _ROUTE_DECORATOR_NAMES:
        return RootKind.FRAMEWORK_ROUTE
    if base in _CLI_DECORATOR_NAMES:
        return RootKind.CLI_COMMAND
    if base in _TASK_DECORATOR_NAMES:
        return RootKind.TASK
    if base in _VALIDATOR_DECORATOR_NAMES:
        return RootKind.VALIDATOR
    if base in _SERIALIZER_DECORATOR_NAMES:
        return RootKind.SERIALIZER
    if base in _PLUGIN_DECORATOR_NAMES:
        return RootKind.PLUGIN_HOOK
    return None


def _decorator_name(decorator: ast.AST) -> str:
    if isinstance(decorator, ast.Call):
        return _decorator_name(decorator.func)
    return _call_name(decorator)


def _call_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _keyword_value(node: ast.Call, *names: str) -> ast.AST | None:
    wanted = set(names)
    for keyword in node.keywords:
        if keyword.arg in wanted:
            return keyword.value
    return None


def _simple_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None
