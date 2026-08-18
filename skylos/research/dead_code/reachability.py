from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from skylos.research.dead_code.evidence import (
    CandidateClassification,
    EvidenceEvent,
    EvidenceKind,
    EvidenceLedger,
    SymbolKey,
)
from skylos.research.dead_code.root_inference import infer_roots
from skylos.research.dead_code.roots import RootSet


@dataclass
class FunctionGraph:
    symbols: dict[str, SymbolKey] = field(default_factory=dict)
    calls: dict[str, set[str]] = field(default_factory=dict)
    class_names: set[str] = field(default_factory=set)
    protocol_classes: set[str] = field(default_factory=set)
    variable_names: set[str] = field(default_factory=set)
    abstract_methods: set[str] = field(default_factory=set)
    interface_stub_methods: set[str] = field(default_factory=set)
    registry_metaclasses: set[str] = field(default_factory=set)
    registry_side_effect_classes: set[str] = field(default_factory=set)
    suppressed_symbols: set[str] = field(default_factory=set)
    type_alias_variables: set[str] = field(default_factory=set)
    action_blocking_references: set[str] = field(default_factory=set)
    ambiguous_reference_names: set[str] = field(default_factory=set)
    class_metaclasses: dict[str, str] = field(default_factory=dict)
    import_aliases: dict[str, str] = field(default_factory=dict)
    factory_returns: dict[str, str] = field(default_factory=dict)
    param_method_uses: dict[str, set[tuple[int, str]]] = field(default_factory=dict)
    top_level_calls: set[str] = field(default_factory=set)

    def add_symbol(self, symbol: SymbolKey) -> None:
        self.symbols[symbol.qualified_name] = symbol
        self.calls.setdefault(symbol.qualified_name, set())

    def add_class(self, symbol: SymbolKey) -> None:
        self.class_names.add(symbol.qualified_name)
        self.add_symbol(symbol)

    def add_protocol_class(self, symbol: SymbolKey) -> None:
        self.protocol_classes.add(symbol.qualified_name)
        self.add_class(symbol)

    def add_variable(self, symbol: SymbolKey) -> None:
        self.variable_names.add(symbol.qualified_name)
        self.add_symbol(symbol)

    def add_abstract_method(self, qname: str) -> None:
        self.abstract_methods.add(qname)

    def add_interface_stub_method(self, qname: str) -> None:
        self.interface_stub_methods.add(qname)

    def add_registry_metaclass(self, qname: str) -> None:
        self.registry_metaclasses.add(qname)

    def add_registry_side_effect_class(self, qname: str) -> None:
        self.registry_side_effect_classes.add(qname)

    def add_suppressed_symbol(self, qname: str) -> None:
        self.suppressed_symbols.add(qname)

    def add_type_alias_variable(self, qname: str) -> None:
        self.type_alias_variables.add(qname)

    def add_action_blocking_reference(self, qname: str) -> None:
        self.action_blocking_references.add(self.resolve_alias(qname))

    def add_ambiguous_reference_name(self, name: str) -> None:
        self.ambiguous_reference_names.add(name)

    def set_class_metaclass(self, class_qname: str, metaclass_qname: str) -> None:
        self.class_metaclasses[class_qname] = metaclass_qname

    def add_call(self, caller: str, callee: str) -> None:
        self.calls.setdefault(caller, set()).add(self.resolve_alias(callee))

    def add_import_alias(self, alias_qname: str, target_qname: str) -> None:
        self.import_aliases[alias_qname] = target_qname

    def resolve_alias(self, qname: str) -> str:
        seen: set[str] = set()
        current = qname
        while current in self.import_aliases and current not in seen:
            seen.add(current)
            current = self.import_aliases[current]
        return current

    def add_factory_return(self, function_qname: str, class_qname: str) -> None:
        self.factory_returns[function_qname] = class_qname

    def add_param_method_use(
        self,
        function_qname: str,
        param_index: int,
        method_name: str,
    ) -> None:
        self.param_method_uses.setdefault(function_qname, set()).add(
            (param_index, method_name)
        )

    def add_top_level_call(self, callee: str) -> None:
        self.top_level_calls.add(self.resolve_alias(callee))

    def initializer_for(self, class_qname: str) -> str | None:
        init_qname = f"{class_qname}.__init__"
        return init_qname if init_qname in self.symbols else None


@dataclass
class ReachabilityResult:
    graph: FunctionGraph
    roots: RootSet
    reachable: set[str]
    ledger: EvidenceLedger

    def symbol(self, qualified_name: str) -> SymbolKey:
        return self.graph.symbols[qualified_name]

    def is_reachable(self, qualified_name: str) -> bool:
        return qualified_name in self.reachable

    def classify(self, qualified_name: str) -> CandidateClassification:
        return self.ledger.classify(self.symbol(qualified_name))


def analyze_reachability(
    project_root: str | Path,
    *,
    roots: RootSet | None = None,
    include_top_level: bool = False,
    include_factory_returns: bool = False,
    include_general_action_edges: bool = False,
) -> ReachabilityResult:
    root_path = Path(project_root).resolve()
    graph = build_function_graph(
        root_path,
        include_factory_returns=include_factory_returns,
        include_general_action_edges=include_general_action_edges,
    )
    root_set = roots or infer_roots(root_path)
    ledger = EvidenceLedger()
    reachable: set[str] = set()

    for root in root_set.roots:
        root_qname = root.symbol.qualified_name
        symbol = graph.symbols.get(root_qname, root.symbol)
        ledger.add(symbol, root.to_evidence())

    for root in root_set.roots:
        root_qname = root.symbol.qualified_name
        if root_qname not in graph.symbols:
            continue
        _walk_from_root(root_qname, graph, reachable, ledger)

    if include_top_level:
        for qname in sorted(graph.top_level_calls):
            symbol = graph.symbols.get(qname)
            if symbol is None:
                continue
            ledger.add(
                symbol,
                EvidenceEvent(
                    kind=EvidenceKind.TOP_LEVEL_EXECUTION,
                    reason="called during module top-level execution",
                    source="python_ast",
                ),
            )
            _walk_from_root(qname, graph, reachable, ledger)

    return ReachabilityResult(
        graph=graph,
        roots=root_set,
        reachable=reachable,
        ledger=ledger,
    )


def build_function_graph(
    project_root: str | Path,
    *,
    include_factory_returns: bool = False,
    include_general_action_edges: bool = False,
) -> FunctionGraph:
    root_path = Path(project_root).resolve()
    graph = FunctionGraph()
    parsed_files: list[tuple[Path, str, ast.Module]] = []

    for path in _iter_python_files(root_path):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError):
            continue
        parsed_files.append((path, _module_name(root_path, path), tree))

    for path, module, tree in parsed_files:
        _DefinitionVisitor(path, module, graph).visit(tree)

    aliases_by_module: dict[str, dict[str, str]] = {}
    for path, module, tree in parsed_files:
        aliases = _ImportAliasVisitor(
            module,
            is_package_module=path.name == "__init__.py",
        ).collect(tree)
        aliases_by_module[module] = aliases
        for local, target in aliases.items():
            alias_qname = f"{module}.{local}" if module else local
            graph.add_import_alias(alias_qname, target)

    for path, module, tree in parsed_files:
        aliases = aliases_by_module[module]
        if include_factory_returns:
            _ReturnTypeSummaryVisitor(module, aliases, graph).visit(tree)

    for path, module, tree in parsed_files:
        aliases = aliases_by_module[module]
        _CallEdgeVisitor(
            path,
            module,
            aliases,
            graph,
            include_factory_returns=include_factory_returns,
            include_general_action_edges=include_general_action_edges,
        ).visit(tree)
        _TopLevelExecutionVisitor(
            module,
            aliases,
            graph,
            include_factory_returns=include_factory_returns,
            include_general_action_edges=include_general_action_edges,
        ).visit(tree)

    return graph


def _walk_from_root(
    root_qname: str,
    graph: FunctionGraph,
    reachable: set[str],
    ledger: EvidenceLedger,
) -> None:
    stack: list[tuple[str, str | None]] = [(root_qname, None)]
    while stack:
        current, caller = stack.pop()
        if current in reachable:
            continue
        reachable.add(current)

        symbol = graph.symbols.get(current)
        if symbol is not None and caller is not None:
            ledger.add(
                symbol,
                EvidenceEvent(
                    kind=EvidenceKind.REACHABLE_FROM_ROOT,
                    reason=f"reachable from root {root_qname}",
                    source="reachability",
                    details={"root": root_qname, "caller": caller},
                ),
            )

        for callee in sorted(graph.calls.get(current, set()), reverse=True):
            if callee in graph.symbols and callee not in reachable:
                stack.append((callee, current))


class _DefinitionVisitor(ast.NodeVisitor):
    def __init__(self, path: Path, module: str, graph: FunctionGraph) -> None:
        self.path = path
        self.module = module
        self.graph = graph
        self.class_stack: list[str] = []
        try:
            self.lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            self.lines = []

    def generic_visit(self, node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qname = _qualified_name(self.module, self.class_stack, node.name)
        symbol = SymbolKey(
            file=str(self.path),
            qualified_name=qname,
            kind="class",
            line=node.lineno,
        )
        if any(_base_name(base) == "Protocol" for base in node.bases):
            self.graph.add_protocol_class(symbol)
        else:
            self.graph.add_class(symbol)
        if _is_registry_metaclass(node):
            self.graph.add_registry_metaclass(qname)
        if self._line_has_dead_code_suppression(node.lineno):
            self.graph.add_suppressed_symbol(qname)
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        if not self.class_stack:
            is_type_alias = _is_type_alias_value(node.value)
            for target in node.targets:
                self._add_variable_target(
                    target,
                    getattr(node, "lineno", 0),
                    is_type_alias=is_type_alias,
                )
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if not self.class_stack:
            self._add_variable_target(
                node.target,
                getattr(node, "lineno", 0),
                is_type_alias=_is_type_alias_annotation(node.annotation)
                or (node.value is not None and _is_type_alias_value(node.value)),
            )
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._add_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._add_function(node)

    def _add_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qname = _qualified_name(self.module, self.class_stack, node.name)
        is_method = bool(self.class_stack)
        self.graph.add_symbol(
            SymbolKey(
                file=str(self.path),
                qualified_name=qname,
                kind="method" if is_method else "function",
                line=node.lineno,
            )
        )
        if self._line_has_dead_code_suppression(node.lineno):
            self.graph.add_suppressed_symbol(qname)
        if is_method and _has_decorator_named(node, "abstractmethod"):
            self.graph.add_abstract_method(qname)
        if is_method and _body_raises_not_implemented(node):
            self.graph.add_interface_stub_method(qname)
        self.class_stack.append(node.name)
        for stmt in node.body:
            self.visit(stmt)
        self.class_stack.pop()

    def _add_variable_target(
        self,
        target: ast.AST,
        line: int,
        *,
        is_type_alias: bool,
    ) -> None:
        if isinstance(target, ast.Name):
            qname = _qualified_name(self.module, [], target.id)
            self.graph.add_variable(
                SymbolKey(
                    file=str(self.path),
                    qualified_name=qname,
                    kind="variable",
                    line=line,
                )
            )
            if self._line_has_dead_code_suppression(line):
                self.graph.add_suppressed_symbol(qname)
            if is_type_alias:
                self.graph.add_type_alias_variable(qname)

    def _line_has_dead_code_suppression(self, line: int) -> bool:
        if line <= 0 or line > len(self.lines):
            return False
        return _line_has_dead_code_suppression(self.lines[line - 1])


class _ImportAliasVisitor(ast.NodeVisitor):
    def __init__(self, module: str, *, is_package_module: bool = False) -> None:
        self.module = module
        self.is_package_module = is_package_module
        self.aliases: dict[str, str] = {}

    def collect(self, tree: ast.Module) -> dict[str, str]:
        self.visit(tree)
        return dict(self.aliases)

    def generic_visit(self, node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".", 1)[0]
            self.aliases[local] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = _resolve_from_module(
            self.module,
            node.module,
            node.level,
            is_package_module=self.is_package_module,
        )
        for alias in node.names:
            if alias.name == "*":
                continue
            local = alias.asname or alias.name
            self.aliases[local] = f"{base}.{alias.name}" if base else alias.name


class _ReturnTypeSummaryVisitor(ast.NodeVisitor):
    def __init__(
        self,
        module: str,
        aliases: dict[str, str],
        graph: FunctionGraph,
    ) -> None:
        self.module = module
        self.aliases = aliases
        self.graph = graph
        self.class_stack: list[str] = []
        self.function_stack: list[str] = []

    def generic_visit(self, node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Return(self, node: ast.Return) -> None:
        if not self.function_stack or node.value is None:
            return
        class_qname = self._constructor_qname(node.value)
        if class_qname:
            self.graph.add_factory_return(self.function_stack[-1], class_qname)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qname = _qualified_name(self.module, self.class_stack, node.name)
        self.function_stack.append(qname)
        self.class_stack.append(node.name)
        for stmt in node.body:
            self.visit(stmt)
        self.class_stack.pop()
        self.function_stack.pop()

    def _constructor_qname(self, node: ast.AST) -> str | None:
        if not isinstance(node, ast.Call):
            return None
        return self._resolve_class(node.func)

    def _resolve_class(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            imported = self.aliases.get(node.id)
            if imported:
                imported = self.graph.resolve_alias(imported)
            if imported in self.graph.class_names:
                return imported
            local = f"{self.module}.{node.id}" if self.module else node.id
            return local if local in self.graph.class_names else None

        if isinstance(node, ast.Attribute):
            parts = _attribute_parts(node)
            if not parts:
                return None
            head = parts[0]
            imported = self.aliases.get(head)
            if imported:
                imported = self.graph.resolve_alias(imported)
                qname = ".".join([imported, *parts[1:]])
                qname = self.graph.resolve_alias(qname)
                return qname if qname in self.graph.class_names else None
            local = ".".join([self.module, *parts]) if self.module else ".".join(parts)
            return local if local in self.graph.class_names else None

        return None


class _CallEdgeVisitor(ast.NodeVisitor):
    def __init__(
        self,
        path: Path,
        module: str,
        aliases: dict[str, str],
        graph: FunctionGraph,
        *,
        include_factory_returns: bool,
        include_general_action_edges: bool,
    ) -> None:
        self.path = path
        self.module = module
        self.aliases = aliases
        self.graph = graph
        self.include_factory_returns = include_factory_returns
        self.include_general_action_edges = include_general_action_edges
        self.class_stack: list[str] = []
        self.function_stack: list[str] = []
        self.type_scopes: list[dict[str, str]] = [{}]
        self.string_scopes: list[dict[str, str]] = [{}]
        self.callable_scopes: list[dict[str, str]] = [{}]
        self.param_scopes: list[dict[str, int]] = [{}]
        self.globals_scopes: list[set[str]] = [set()]
        self.direct_call_targets: set[int] = set()

    def generic_visit(self, node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Call(self, node: ast.Call) -> None:
        callee: str | None = None
        if self.function_stack:
            caller = self.function_stack[-1]
            callee = self._resolve_callee(node.func)
            if callee and callee in self.graph.symbols:
                self._add_call(caller, callee)
                self._add_argument_method_edges(caller, callee, node.args)
            self._record_param_method_use(node.func)
        if self.include_general_action_edges and callee is None:
            self._record_unknown_attribute_name(node.func)
        self.direct_call_targets.add(id(node.func))
        try:
            self.generic_visit(node)
        finally:
            self.direct_call_targets.discard(id(node.func))

    def visit_Name(self, node: ast.Name) -> None:
        if self.function_stack and isinstance(node.ctx, ast.Load):
            if self.include_general_action_edges and id(node) not in self.direct_call_targets:
                self._record_action_reference(node)
            variable = self._resolve_variable(node.id)
            if variable:
                self.graph.add_call(self.function_stack[-1], variable)
            if self.include_general_action_edges:
                class_qname = self._resolve_class(node)
                if class_qname:
                    self.graph.add_call(self.function_stack[-1], class_qname)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if self.function_stack and isinstance(node.ctx, ast.Load):
            if self.include_general_action_edges and id(node) not in self.direct_call_targets:
                self._record_action_reference(node)
            variable = self._resolve_attribute_variable(node)
            if variable:
                self.graph.add_call(self.function_stack[-1], variable)
            if self.include_general_action_edges:
                class_qname = self._resolve_attribute_class(node)
                if class_qname:
                    self.graph.add_call(self.function_stack[-1], class_qname)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        is_globals_alias = _is_globals_call(node.value)
        class_qname = self._assigned_class_qname(node.value)
        if class_qname:
            for target in node.targets:
                self._assign_type(target, class_qname)
        string_value = self._string_value(node.value)
        if string_value is not None:
            for target in node.targets:
                self._assign_string(target, string_value)
        callable_qname = self._dynamic_function_qname(node.value)
        if callable_qname:
            for target in node.targets:
                self._assign_callable(target, callable_qname)
        if self.include_general_action_edges and is_globals_alias:
            for target in node.targets:
                self._assign_globals_alias(target)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            is_globals_alias = _is_globals_call(node.value)
            class_qname = self._assigned_class_qname(node.value)
            if class_qname:
                self._assign_type(node.target, class_qname)
            string_value = self._string_value(node.value)
            if string_value is not None:
                self._assign_string(node.target, string_value)
            callable_qname = self._dynamic_function_qname(node.value)
            if callable_qname:
                self._assign_callable(node.target, callable_qname)
            if self.include_general_action_edges and is_globals_alias:
                self._assign_globals_alias(node.target)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if self.function_stack and node.value is not None:
            callee = self._resolve_returned_symbol(node.value)
            if callee:
                self.graph.add_call(self.function_stack[-1], callee)
        self.generic_visit(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qname = _qualified_name(self.module, self.class_stack, node.name)
        self.function_stack.append(qname)
        self.type_scopes.append({})
        self.string_scopes.append({})
        self.callable_scopes.append({})
        self.param_scopes.append({})
        self.globals_scopes.append(set())
        self._record_parameters(node)
        self.class_stack.append(node.name)
        for stmt in node.body:
            self.visit(stmt)
        self.class_stack.pop()
        self.globals_scopes.pop()
        self.param_scopes.pop()
        self.callable_scopes.pop()
        self.string_scopes.pop()
        self.type_scopes.pop()
        self.function_stack.pop()

    def _record_parameters(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        args = [*node.args.posonlyargs, *node.args.args]
        for index, arg in enumerate(args):
            self.param_scopes[-1][arg.arg] = index
            class_qname = self._annotation_class_qname(arg.annotation)
            if class_qname:
                self.type_scopes[-1][arg.arg] = class_qname

    def _add_call(self, caller: str, callee: str) -> None:
        resolved = self.graph.resolve_alias(callee)
        self.graph.add_call(caller, resolved)
        if resolved in self.graph.class_names:
            init_qname = self.graph.initializer_for(resolved)
            if init_qname:
                self.graph.add_call(caller, init_qname)

    def _add_argument_method_edges(
        self,
        caller: str,
        callee: str,
        args: list[ast.expr],
    ) -> None:
        for index, method_name in self.graph.param_method_uses.get(callee, set()):
            if index >= len(args):
                continue
            class_qname = self._argument_class_qname(args[index])
            if not class_qname:
                continue
            method_qname = f"{class_qname}.{method_name}"
            if method_qname in self.graph.symbols:
                self.graph.add_call(caller, method_qname)

    def _record_param_method_use(self, func: ast.AST) -> None:
        if not self.function_stack or not isinstance(func, ast.Attribute):
            return
        if not isinstance(func.value, ast.Name):
            return
        param_index = self.param_scopes[-1].get(func.value.id)
        if param_index is None:
            return
        self.graph.add_param_method_use(
            self.function_stack[-1],
            param_index,
            func.attr,
        )

    def _resolve_callee(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            callable_qname = self.callable_scopes[-1].get(node.id)
            if callable_qname in self.graph.symbols:
                return callable_qname
            imported = self.aliases.get(node.id)
            if imported:
                imported = self.graph.resolve_alias(imported)
            if imported in self.graph.symbols:
                return imported
            for local in self._lexical_qname_candidates(node.id):
                if local in self.graph.symbols:
                    return local
            return None

        if isinstance(node, (ast.Call, ast.Subscript)):
            return self._dynamic_function_qname(node)

        if isinstance(node, ast.Attribute):
            constructed = self._constructor_qname(node.value)
            if constructed:
                method = f"{constructed}.{node.attr}"
                return method if method in self.graph.symbols else None

            parts = _attribute_parts(node)
            if not parts:
                return None

            head = parts[0]
            typed = self.type_scopes[-1].get(head)
            if typed and len(parts) > 1:
                method = ".".join([typed, *parts[1:]])
                return method if method in self.graph.symbols else None

            if head in {"self", "cls"} and self.class_stack:
                method = ".".join([self.module, self.class_stack[0], *parts[1:]])
                return method if method in self.graph.symbols else None

            imported = self.aliases.get(head)
            if imported:
                imported = self.graph.resolve_alias(imported)
                qname = ".".join([imported, *parts[1:]])
                qname = self.graph.resolve_alias(qname)
                return qname if qname in self.graph.symbols else None

            local = ".".join([self.module, *parts]) if self.module else ".".join(parts)
            local = self.graph.resolve_alias(local)
            return local if local in self.graph.symbols else None

        return None

    def _constructor_qname(self, node: ast.AST) -> str | None:
        if not isinstance(node, ast.Call):
            return None
        return self._resolve_class(node.func)

    def _assigned_class_qname(self, node: ast.AST) -> str | None:
        return self._constructor_qname(node) or self._factory_return_qname(node)

    def _argument_class_qname(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.type_scopes[-1].get(node.id)
        return self._assigned_class_qname(node)

    def _annotation_class_qname(self, node: ast.AST | None) -> str | None:
        if node is None:
            return None
        return self._resolve_class(node)

    def _factory_return_qname(self, node: ast.AST) -> str | None:
        if not self.include_factory_returns or not isinstance(node, ast.Call):
            return None
        callee = self._resolve_callee(node.func)
        if callee is None:
            return None
        return self.graph.factory_returns.get(callee)

    def _resolve_class(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            imported = self.aliases.get(node.id)
            if imported:
                imported = self.graph.resolve_alias(imported)
            if imported in self.graph.class_names:
                return imported
            for local in self._lexical_qname_candidates(node.id):
                if local in self.graph.class_names:
                    return local
            return None

        if isinstance(node, ast.Attribute):
            parts = _attribute_parts(node)
            if not parts:
                return None
            head = parts[0]
            imported = self.aliases.get(head)
            if imported:
                imported = self.graph.resolve_alias(imported)
                qname = ".".join([imported, *parts[1:]])
                qname = self.graph.resolve_alias(qname)
                return qname if qname in self.graph.class_names else None
            local = ".".join([self.module, *parts]) if self.module else ".".join(parts)
            local = self.graph.resolve_alias(local)
            return local if local in self.graph.class_names else None

        return None

    def _assign_type(self, target: ast.AST, class_qname: str) -> None:
        if isinstance(target, ast.Name):
            self.type_scopes[-1][target.id] = class_qname

    def _assign_string(self, target: ast.AST, value: str) -> None:
        if isinstance(target, ast.Name):
            self.string_scopes[-1][target.id] = value

    def _assign_callable(self, target: ast.AST, qname: str) -> None:
        if isinstance(target, ast.Name):
            self.callable_scopes[-1][target.id] = qname

    def _assign_globals_alias(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.globals_scopes[-1].add(target.id)

    def _resolve_variable(self, name: str) -> str | None:
        imported = self.aliases.get(name)
        if imported:
            imported = self.graph.resolve_alias(imported)
        if imported in self.graph.variable_names:
            return imported
        local = f"{self.module}.{name}" if self.module else name
        local = self.graph.resolve_alias(local)
        return local if local in self.graph.variable_names else None

    def _resolve_attribute_variable(self, node: ast.Attribute) -> str | None:
        parts = _attribute_parts(node)
        if not parts:
            return None
        head = parts[0]
        imported = self.aliases.get(head)
        if imported:
            imported = self.graph.resolve_alias(imported)
            qname = self.graph.resolve_alias(".".join([imported, *parts[1:]]))
            return qname if qname in self.graph.variable_names else None
        local = ".".join([self.module, *parts]) if self.module else ".".join(parts)
        local = self.graph.resolve_alias(local)
        return local if local in self.graph.variable_names else None

    def _resolve_attribute_class(self, node: ast.Attribute) -> str | None:
        parts = _attribute_parts(node)
        if not parts:
            return None
        head = parts[0]
        imported = self.aliases.get(head)
        if imported:
            imported = self.graph.resolve_alias(imported)
            return imported if imported in self.graph.class_names else None
        local = f"{self.module}.{head}" if self.module else head
        local = self.graph.resolve_alias(local)
        return local if local in self.graph.class_names else None

    def _resolve_returned_symbol(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self._resolve_callee(node)
        return None

    def _record_action_reference(self, node: ast.AST) -> None:
        qname = self._resolve_symbol_reference(node)
        if qname:
            self.graph.add_action_blocking_reference(qname)
        self._record_unknown_attribute_name(node)

    def _resolve_symbol_reference(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self._resolve_callee(node) or self._resolve_class(node) or self._resolve_variable(node.id)
        if isinstance(node, ast.Attribute):
            return self._resolve_callee(node) or self._resolve_attribute_variable(node)
        return None

    def _record_unknown_attribute_name(self, node: ast.AST) -> None:
        if not isinstance(node, ast.Attribute):
            return
        parts = _attribute_parts(node)
        if len(parts) < 2:
            return
        head = parts[0]
        if head in {"self", "cls"}:
            if len(parts) > 2:
                self.graph.add_ambiguous_reference_name(node.attr)
            return
        if head in self.aliases or head in self.type_scopes[-1]:
            return
        local = f"{self.module}.{head}" if self.module else head
        if self.graph.resolve_alias(local) in self.graph.symbols:
            return
        self.graph.add_ambiguous_reference_name(node.attr)

    def _dynamic_function_qname(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Call) and _call_name(node.func) == "getattr":
            if len(node.args) < 2:
                return None
            name = self._string_value(node.args[1])
            if not name:
                return None
            if self.include_general_action_edges:
                method = self._method_named_on_value(node.args[0], name)
                if method:
                    return method
            return self._function_named(name)
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Call):
            if _call_name(node.value.func) != "globals":
                return None
            name = self._string_value(node.slice)
            return self._function_named(name) if name else None
        if (
            self.include_general_action_edges
            and isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id in self.globals_scopes[-1]
        ):
            name = self._string_value(node.slice)
            return self._function_named(name) if name else None
        return None

    def _function_named(self, name: str) -> str | None:
        for local in self._lexical_qname_candidates(name):
            if local in self.graph.symbols:
                return local
        return None

    def _method_named_on_value(self, value: ast.AST, name: str) -> str | None:
        class_qname: str | None = None
        if isinstance(value, ast.Name):
            class_qname = self.type_scopes[-1].get(value.id)
        if class_qname is None:
            class_qname = self._assigned_class_qname(value)
        if class_qname is None:
            return None
        method_qname = f"{class_qname}.{name}"
        return method_qname if method_qname in self.graph.symbols else None

    def _string_value(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return self.string_scopes[-1].get(node.id)
        return None

    def _lexical_qname_candidates(self, name: str) -> list[str]:
        candidates = []
        for depth in range(len(self.class_stack), -1, -1):
            qname = _qualified_name(self.module, self.class_stack[:depth], name)
            if qname:
                candidates.append(qname)
        return candidates


class _TopLevelExecutionVisitor(ast.NodeVisitor):
    def __init__(
        self,
        module: str,
        aliases: dict[str, str],
        graph: FunctionGraph,
        *,
        include_factory_returns: bool,
        include_general_action_edges: bool,
    ) -> None:
        self.module = module
        self.aliases = aliases
        self.graph = graph
        self.include_factory_returns = include_factory_returns
        self.include_general_action_edges = include_general_action_edges
        self.type_env: dict[str, str] = {}
        self.string_env: dict[str, str] = {}
        self.callable_env: dict[str, str] = {}
        self.globals_env: set[str] = set()
        self.class_stack: list[str] = []
        self.direct_call_targets: set[int] = set()

    def generic_visit(self, node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for decorator in node.decorator_list:
            self._record_decorator_reference(decorator)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self._record_decorator_reference(decorator)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if self.include_general_action_edges:
            self._record_class_definition_references(node)
        for decorator in node.decorator_list:
            self._record_decorator_reference(decorator)
        self.class_stack.append(node.name)
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in stmt.decorator_list:
                    self._record_decorator_reference(decorator)
                continue
            self.visit(stmt)
        self.class_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        is_globals_alias = _is_globals_call(node.value)
        class_qname = self._assigned_class_qname(node.value)
        if class_qname:
            for target in node.targets:
                self._assign_type(target, class_qname)
                self._record_constructed_target(target)
        string_value = self._string_value(node.value)
        if string_value is not None:
            for target in node.targets:
                self._assign_string(target, string_value)
        callable_qname = self._dynamic_function_qname(node.value)
        if callable_qname:
            for target in node.targets:
                self._assign_callable(target, callable_qname)
        if self.include_general_action_edges and is_globals_alias:
            for target in node.targets:
                self._assign_globals_alias(target)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            is_globals_alias = _is_globals_call(node.value)
            class_qname = self._assigned_class_qname(node.value)
            if class_qname:
                self._assign_type(node.target, class_qname)
                self._record_constructed_target(node.target)
            string_value = self._string_value(node.value)
            if string_value is not None:
                self._assign_string(node.target, string_value)
            callable_qname = self._dynamic_function_qname(node.value)
            if callable_qname:
                self._assign_callable(node.target, callable_qname)
            if self.include_general_action_edges and is_globals_alias:
                self._assign_globals_alias(node.target)
            self.visit(node.value)

    def visit_Call(self, node: ast.Call) -> None:
        callee = self._resolve_callee(node.func)
        if callee and callee in self.graph.symbols:
            self._add_top_level_call(callee)
            self._add_argument_method_calls(callee, node.args)
        elif self.include_general_action_edges:
            self._record_unknown_attribute_name(node.func)
        self.direct_call_targets.add(id(node.func))
        try:
            self.generic_visit(node)
        finally:
            self.direct_call_targets.discard(id(node.func))

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            if self.include_general_action_edges and id(node) not in self.direct_call_targets:
                self._record_action_reference(node)
            variable = self._resolve_variable(node.id)
            if variable:
                self.graph.add_top_level_call(variable)
            if self.include_general_action_edges:
                class_qname = self._resolve_class(node)
                if class_qname:
                    self.graph.add_top_level_call(class_qname)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, ast.Load):
            if self.include_general_action_edges and id(node) not in self.direct_call_targets:
                self._record_action_reference(node)
            variable = self._resolve_attribute_variable(node)
            if variable:
                self.graph.add_top_level_call(variable)
            if self.include_general_action_edges:
                class_qname = self._resolve_attribute_class(node)
                if class_qname:
                    self.graph.add_top_level_call(class_qname)
        self.generic_visit(node)

    def _add_top_level_call(self, callee: str) -> None:
        resolved = self.graph.resolve_alias(callee)
        self.graph.add_top_level_call(resolved)
        if resolved in self.graph.class_names:
            init_qname = self.graph.initializer_for(resolved)
            if init_qname:
                self.graph.add_top_level_call(init_qname)

    def _add_argument_method_calls(self, callee: str, args: list[ast.expr]) -> None:
        for index, method_name in self.graph.param_method_uses.get(callee, set()):
            if index >= len(args):
                continue
            class_qname = self._argument_class_qname(args[index])
            if not class_qname:
                continue
            method_qname = f"{class_qname}.{method_name}"
            if method_qname in self.graph.symbols:
                self.graph.add_top_level_call(method_qname)

    def _resolve_callee(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            callable_qname = self.callable_env.get(node.id)
            if callable_qname in self.graph.symbols:
                return callable_qname
            imported = self.aliases.get(node.id)
            if imported:
                imported = self.graph.resolve_alias(imported)
            if imported in self.graph.symbols:
                return imported
            for local in self._lexical_qname_candidates(node.id):
                local = self.graph.resolve_alias(local)
                if local in self.graph.symbols:
                    return local
            return None

        if isinstance(node, (ast.Call, ast.Subscript)):
            return self._dynamic_function_qname(node)

        if isinstance(node, ast.Attribute):
            constructed = self._constructor_qname(node.value)
            if constructed:
                method = f"{constructed}.{node.attr}"
                return method if method in self.graph.symbols else None

            parts = _attribute_parts(node)
            if not parts:
                return None
            head = parts[0]
            typed = self.type_env.get(head)
            if typed and len(parts) > 1:
                method = ".".join([typed, *parts[1:]])
                return method if method in self.graph.symbols else None

            imported = self.aliases.get(head)
            if imported:
                imported = self.graph.resolve_alias(imported)
                qname = ".".join([imported, *parts[1:]])
                qname = self.graph.resolve_alias(qname)
                return qname if qname in self.graph.symbols else None

            local = ".".join([self.module, *parts]) if self.module else ".".join(parts)
            local = self.graph.resolve_alias(local)
            return local if local in self.graph.symbols else None

        return None

    def _constructor_qname(self, node: ast.AST) -> str | None:
        if not isinstance(node, ast.Call):
            return None
        return self._resolve_class(node.func)

    def _assigned_class_qname(self, node: ast.AST) -> str | None:
        return self._constructor_qname(node) or self._factory_return_qname(node)

    def _argument_class_qname(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.type_env.get(node.id)
        return self._assigned_class_qname(node)

    def _factory_return_qname(self, node: ast.AST) -> str | None:
        if not self.include_factory_returns or not isinstance(node, ast.Call):
            return None
        callee = self._resolve_callee(node.func)
        if callee is None:
            return None
        return self.graph.factory_returns.get(callee)

    def _resolve_class(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            imported = self.aliases.get(node.id)
            if imported:
                imported = self.graph.resolve_alias(imported)
            if imported in self.graph.class_names:
                return imported
            for local in self._lexical_qname_candidates(node.id):
                local = self.graph.resolve_alias(local)
                if local in self.graph.class_names:
                    return local
            return None

        if isinstance(node, ast.Attribute):
            parts = _attribute_parts(node)
            if not parts:
                return None
            head = parts[0]
            imported = self.aliases.get(head)
            if imported:
                imported = self.graph.resolve_alias(imported)
                qname = ".".join([imported, *parts[1:]])
                qname = self.graph.resolve_alias(qname)
                return qname if qname in self.graph.class_names else None
            local = ".".join([self.module, *parts]) if self.module else ".".join(parts)
            local = self.graph.resolve_alias(local)
            return local if local in self.graph.class_names else None

        return None

    def _assign_type(self, target: ast.AST, class_qname: str) -> None:
        if isinstance(target, ast.Name):
            self.type_env[target.id] = class_qname

    def _record_constructed_target(self, target: ast.AST) -> None:
        if not isinstance(target, ast.Name):
            return
        qname = self._resolve_variable(target.id)
        if qname:
            self.graph.add_top_level_call(qname)

    def _assign_string(self, target: ast.AST, value: str) -> None:
        if isinstance(target, ast.Name):
            self.string_env[target.id] = value

    def _assign_callable(self, target: ast.AST, qname: str) -> None:
        if isinstance(target, ast.Name):
            self.callable_env[target.id] = qname

    def _assign_globals_alias(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.globals_env.add(target.id)

    def _resolve_variable(self, name: str) -> str | None:
        imported = self.aliases.get(name)
        if imported:
            imported = self.graph.resolve_alias(imported)
        if imported in self.graph.variable_names:
            return imported
        local = f"{self.module}.{name}" if self.module else name
        local = self.graph.resolve_alias(local)
        return local if local in self.graph.variable_names else None

    def _resolve_attribute_variable(self, node: ast.Attribute) -> str | None:
        parts = _attribute_parts(node)
        if not parts:
            return None
        head = parts[0]
        imported = self.aliases.get(head)
        if imported:
            imported = self.graph.resolve_alias(imported)
            qname = self.graph.resolve_alias(".".join([imported, *parts[1:]]))
            return qname if qname in self.graph.variable_names else None
        local = ".".join([self.module, *parts]) if self.module else ".".join(parts)
        local = self.graph.resolve_alias(local)
        return local if local in self.graph.variable_names else None

    def _resolve_attribute_class(self, node: ast.Attribute) -> str | None:
        parts = _attribute_parts(node)
        if not parts:
            return None
        head = parts[0]
        imported = self.aliases.get(head)
        if imported:
            imported = self.graph.resolve_alias(imported)
            return imported if imported in self.graph.class_names else None
        local = f"{self.module}.{head}" if self.module else head
        local = self.graph.resolve_alias(local)
        return local if local in self.graph.class_names else None

    def _record_decorator_reference(self, decorator: ast.AST) -> None:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        qname = self._resolve_callee(target)
        if qname and qname in self.graph.symbols:
            self._add_top_level_call(qname)
        self.visit(decorator)

    def _record_class_definition_references(self, node: ast.ClassDef) -> None:
        class_qname = f"{self.module}.{node.name}" if self.module else node.name
        base_qnames = []
        for base in node.bases:
            base_qname = self._resolve_class(base)
            if base_qname:
                base_qnames.append(base_qname)
                self._add_top_level_call(base_qname)

        metaclass_qname = self._explicit_metaclass_qname(node)
        if metaclass_qname is None:
            metaclass_qname = self._inherited_metaclass_qname(base_qnames)
        if metaclass_qname is None:
            return

        self.graph.set_class_metaclass(class_qname, metaclass_qname)
        self._add_top_level_call(metaclass_qname)
        for method_name in ("__new__", "__init__", "__call__"):
            method_qname = f"{metaclass_qname}.{method_name}"
            if method_qname in self.graph.symbols:
                self._add_top_level_call(method_qname)
        if metaclass_qname in self.graph.registry_metaclasses and base_qnames:
            self.graph.add_registry_side_effect_class(class_qname)

    def _explicit_metaclass_qname(self, node: ast.ClassDef) -> str | None:
        for keyword in node.keywords:
            if keyword.arg == "metaclass":
                return self._resolve_class(keyword.value)
        return None

    def _inherited_metaclass_qname(self, base_qnames: list[str]) -> str | None:
        for base_qname in base_qnames:
            metaclass_qname = self.graph.class_metaclasses.get(base_qname)
            if metaclass_qname:
                return metaclass_qname
        return None

    def _dynamic_function_qname(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Call) and _call_name(node.func) == "getattr":
            if len(node.args) < 2:
                return None
            name = self._string_value(node.args[1])
            if not name:
                return None
            if self.include_general_action_edges:
                method = self._method_named_on_value(node.args[0], name)
                if method:
                    return method
            return self._function_named(name)
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Call):
            if _call_name(node.value.func) != "globals":
                return None
            name = self._string_value(node.slice)
            return self._function_named(name) if name else None
        if (
            self.include_general_action_edges
            and isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id in self.globals_env
        ):
            name = self._string_value(node.slice)
            return self._function_named(name) if name else None
        return None

    def _function_named(self, name: str) -> str | None:
        for local in self._lexical_qname_candidates(name):
            local = self.graph.resolve_alias(local)
            if local in self.graph.symbols:
                return local
        return None

    def _record_action_reference(self, node: ast.AST) -> None:
        qname = self._resolve_symbol_reference(node)
        if qname:
            self.graph.add_action_blocking_reference(qname)
        self._record_unknown_attribute_name(node)

    def _resolve_symbol_reference(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self._resolve_callee(node) or self._resolve_class(node) or self._resolve_variable(node.id)
        if isinstance(node, ast.Attribute):
            return self._resolve_callee(node) or self._resolve_attribute_variable(node)
        return None

    def _record_unknown_attribute_name(self, node: ast.AST) -> None:
        if not isinstance(node, ast.Attribute):
            return
        parts = _attribute_parts(node)
        if len(parts) < 2:
            return
        head = parts[0]
        if head in {"self", "cls"}:
            if len(parts) > 2:
                self.graph.add_ambiguous_reference_name(node.attr)
            return
        if head in self.aliases or head in self.type_env:
            return
        local = f"{self.module}.{head}" if self.module else head
        if self.graph.resolve_alias(local) in self.graph.symbols:
            return
        self.graph.add_ambiguous_reference_name(node.attr)

    def _lexical_qname_candidates(self, name: str) -> list[str]:
        candidates = []
        for depth in range(len(self.class_stack), -1, -1):
            qname = _qualified_name(self.module, self.class_stack[:depth], name)
            if qname:
                candidates.append(qname)
        return candidates

    def _method_named_on_value(self, value: ast.AST, name: str) -> str | None:
        class_qname: str | None = None
        if isinstance(value, ast.Name):
            class_qname = self.type_env.get(value.id)
        if class_qname is None:
            class_qname = self._assigned_class_qname(value)
        if class_qname is None:
            return None
        method_qname = f"{class_qname}.{name}"
        return method_qname if method_qname in self.graph.symbols else None

    def _string_value(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return self.string_env.get(node.id)
        return None


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


def _module_name(project_root: Path, path: Path) -> str:
    rel = path.resolve().relative_to(project_root.resolve())
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    if parts and parts[0] == "src":
        parts = parts[1:]
    return ".".join(parts)


def _qualified_name(module: str, class_stack: list[str], name: str) -> str:
    parts = [module, *class_stack, name]
    return ".".join(part for part in parts if part)


def _resolve_from_module(
    current_module: str,
    imported_module: str | None,
    level: int,
    *,
    is_package_module: bool = False,
) -> str:
    if level <= 0:
        return imported_module or ""

    package_parts = current_module.split(".")
    if not is_package_module:
        package_parts = package_parts[:-1]
    if level > 1:
        package_parts = package_parts[: -(level - 1)]
    if imported_module:
        package_parts.extend(imported_module.split("."))
    return ".".join(part for part in package_parts if part)


def _attribute_parts(node: ast.Attribute) -> list[str]:
    parts = [node.attr]
    current = node.value
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    else:
        return []
    return list(reversed(parts))


def _base_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        return _base_name(node.value)
    return ""


def _has_decorator_named(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    name: str,
) -> bool:
    return any(_base_name(decorator) == name for decorator in node.decorator_list)


def _body_raises_not_implemented(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    meaningful = [
        stmt
        for stmt in node.body
        if not isinstance(stmt, (ast.Expr))
        or not isinstance(getattr(stmt, "value", None), ast.Constant)
        or not isinstance(stmt.value.value, str)
    ]
    if len(meaningful) != 1:
        return False
    stmt = meaningful[0]
    if not isinstance(stmt, ast.Raise) or stmt.exc is None:
        return False
    return _exception_name(stmt.exc) == "NotImplementedError"


def _exception_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return _call_name(node)


def _is_globals_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _call_name(node.func) == "globals"


def _is_type_alias_annotation(node: ast.AST | None) -> bool:
    return node is not None and _base_name(node) == "TypeAlias"


def _is_type_alias_value(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    return _call_name(node.func) in {
        "NewType",
        "typing.NewType",
        "TypeAliasType",
        "typing_extensions.TypeAliasType",
    }


def _line_has_dead_code_suppression(line: str) -> bool:
    comment = line.split("#", 1)[1].strip().lower() if "#" in line else ""
    return "pragma: no" in comment or "noqa" in comment


def _is_registry_metaclass(node: ast.ClassDef) -> bool:
    if not any(_base_name(base) in {"type", "ABCMeta"} for base in node.bases):
        return False

    registry_attrs = {
        target.id
        for stmt in node.body
        if isinstance(stmt, ast.Assign) and _is_empty_collection_literal(stmt.value)
        for target in stmt.targets
        if isinstance(target, ast.Name)
    }
    if not registry_attrs:
        return False

    for stmt in node.body:
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if stmt.name not in {"__new__", "__init__", "__call__"}:
            continue
        class_object_names = _class_object_local_names(stmt)
        for child in ast.walk(stmt):
            if not isinstance(child, ast.Assign):
                continue
            if not isinstance(child.value, ast.Name):
                continue
            if child.value.id not in class_object_names:
                continue
            if any(_is_registry_subscript(target, registry_attrs) for target in child.targets):
                return True
    return False


def _class_object_local_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names = {"cls"}
    for child in ast.walk(node):
        if not isinstance(child, ast.Assign):
            continue
        if not isinstance(child.value, ast.Call):
            continue
        if not _call_name(child.value.func).endswith("__new__"):
            continue
        for target in child.targets:
            if isinstance(target, ast.Name):
                names.add(target.id)
    return names


def _is_registry_subscript(node: ast.AST, registry_attrs: set[str]) -> bool:
    if not isinstance(node, ast.Subscript):
        return False
    value = node.value
    return (
        isinstance(value, ast.Attribute)
        and isinstance(value.value, ast.Name)
        and value.attr in registry_attrs
    )


def _is_empty_collection_literal(node: ast.AST) -> bool:
    return isinstance(node, (ast.Dict, ast.List, ast.Set)) and not any(
        ast.iter_child_nodes(node)
    )


def _call_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""
