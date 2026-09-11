"""AST source ownership, with explicit boundaries for deferred execution."""

from __future__ import annotations
import ast
import re
from skylos.deadcode._reachability_bindings import (
    MODULE_BINDING,
    Binding,
    Bindings,
    FunctionNode,
    ModuleInfo,
    argument_nodes,
    bound_names,
    default_expressions,
    import_bindings,
)
from skylos.deadcode._reachability_receivers import (
    CLASS_BINDING,
    RECEIVER_BINDINGS,
    function_receivers,
)
from skylos.deadcode._reachability_graph import (
    ReferenceGraph,
    SourceIndex,
    SourceReference,
)

_EXPORT_LIST = "__all__"

_DYNAMIC_NAMES = {
    "eval",
    "exec",
    "globals",
    "locals",
    "__import__",
    "__builtins__",
    "getattr",
    "setattr",
    "delattr",
    "vars",
}
_DYNAMIC_ATTRIBUTES = {
    "import_module",
    "__getattribute__",
    "__dict__",
    "__globals__",
    "__builtins__",
}


class SourceVisitor(ast.NodeVisitor):
    def __init__(
        self, index: SourceIndex, graph: ReferenceGraph, module: ModuleInfo
    ) -> None:
        self.index = index
        self.graph = graph
        self.module = module
        self.local: Bindings = {}
        self.owner: str | None = None
        self.proven_context = True

    def _protect_binding(
        self, binding: Binding | None, *, retain_class: bool = False
    ) -> None:
        targets = self.index.escaped_symbols(binding)
        self.graph.protect(targets, self.owner)
        if binding and (
            binding[0] == "instance" or (binding[0] == CLASS_BINDING and retain_class)
        ):
            destination = (
                self.graph.receiver_roots
                if self.owner is None
                else self.graph.receiver_edges[self.owner]
            )
            destination.update(targets)

    def _protect_value(self, expression: ast.AST, *, retain_class: bool = True) -> None:
        # Result-carrying expressions can hide instances: conditionals,
        # comprehensions, boolean expressions, and callbacks all escape their
        # possible receiver constituents when the whole value escapes.
        pending = [expression]
        while pending:
            part = pending.pop()
            binding = self.index.resolve(part, self.module, self.local)
            if binding and binding[0] in RECEIVER_BINDINGS:
                self._protect_binding(binding, retain_class=retain_class)
            if isinstance(part, ast.Call):
                # Calling a method does not by itself pass its receiver as the
                # returned value. Its body records any actual receiver return.
                pending.extend(part.args)
                pending.extend(kw.value for kw in part.keywords)
            elif not isinstance(part, ast.Attribute):
                pending.extend(ast.iter_child_nodes(part))

    def _binding_is_ambiguous(self, name: str) -> bool:
        return self.index.resolve(ast.Name(id=name), self.module, self.local) is None

    def visit_Constant(self, node: ast.Constant) -> None:
        if not isinstance(node.value, str):
            return
        if len(node.value) > 65_536:
            self._opaque()
            self.graph.references[self.module.path, node.lineno].append(
                SourceReference("*", None, self.owner)
            )
            return
        for name in set(re.findall(r"\w+", node.value)):
            binding = self.index.resolve(ast.Name(id=name), self.module, self.local)
            if binding and binding[0] in RECEIVER_BINDINGS:
                self._protect_binding(binding)
            if name in self.index.by_simple_name:
                self.graph.record(
                    self.index, self.module, node, name, None, owner=self.owner
                )

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            if node.id in _DYNAMIC_NAMES:
                self._opaque()
            binding = self.index.resolve(node, self.module, self.local)
            self.graph.record(
                self.index,
                self.module,
                node,
                node.id,
                binding,
                owner=self.owner,
                proven=self.proven_context,
            )
            if binding and binding[0] in {MODULE_BINDING, *RECEIVER_BINDINGS}:
                self._protect_binding(binding)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, ast.Load):
            if node.attr in _DYNAMIC_ATTRIBUTES:
                self._opaque()
            binding = self.index.resolve(node, self.module, self.local)
            self.graph.record(
                self.index,
                self.module,
                node,
                node.attr,
                binding,
                owner=self.owner,
                proven=self.proven_context,
            )
        # Looking up a resolved module attribute does not itself pass the
        # module object to unknown code. A standalone module value does.
        base = self.index.resolve(node.value, self.module, self.local)
        if base and base[0] in RECEIVER_BINDINGS:
            if not isinstance(node.ctx, ast.Load) and (
                base[0] == CLASS_BINDING
                or node.attr in self.index.classes[base[1]].methods
                or node.attr in {"__class__", "__dict__"}
            ):
                self._protect_binding(base, retain_class=True)
            self._visit_receiver_value(node.value)
            return
        if isinstance(node.value, ast.Name) and base and base[0] == MODULE_BINDING:
            return
        self.generic_visit(node)

    def _visit_receiver_value(self, node: ast.AST) -> None:
        """A resolved receiver lookup/alias doesn't itself expose the object."""
        if isinstance(node, ast.Name):
            return
        self.visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            binding = import_bindings(node, self.module).get(
                alias.asname or alias.name.split(".")[0]
            )
            self.graph.record(
                self.index,
                self.module,
                alias,
                alias.name,
                binding,
                owner=self.owner,
                import_only=True,
            )
            if self._binding_is_ambiguous(alias.asname or alias.name.split(".")[0]):
                self._protect_binding(binding)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if any(alias.name == "*" for alias in node.names):
            self._opaque()
        bindings = import_bindings(node, self.module)
        for alias in node.names:
            self._visit_import_alias(node, alias, bindings)

    def _visit_import_alias(
        self, node: ast.ImportFrom, alias: ast.alias, bindings: Bindings
    ) -> None:
        if node.module in {"builtins", "importlib"} and alias.name in (
            _DYNAMIC_NAMES | _DYNAMIC_ATTRIBUTES
        ):
            self._opaque()
        binding = bindings.get(alias.asname or alias.name)
        if binding and binding[0] == "qualified":
            binding = self.index.qualified(binding[1])
        self.graph.record(
            self.index,
            self.module,
            alias,
            alias.name,
            binding,
            owner=self.owner,
            import_only=binding is not None,
        )
        if self._binding_is_ambiguous(alias.asname or alias.name):
            self._protect_binding(binding)

    def _opaque(self) -> None:
        if self.owner is None:
            self.graph.uncertain_roots.update(self.index.candidates)
        else:
            self.graph.opaque_owners.add(self.owner)

    def visit_Call(self, node: ast.Call) -> None:
        for argument in [*node.args, *(kw.value for kw in node.keywords)]:
            self._protect_value(argument)
        constructor = self.index.resolve(node.func, self.module, self.local)
        if constructor and constructor[0] == CLASS_BINDING:
            self._visit_constructor(node, constructor[1])
            return
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == _EXPORT_LIST
            and not all(
                isinstance(argument, ast.Constant) and isinstance(argument.value, str)
                for argument in node.args
            )
        ):
            for identity in self.module.names:
                self._protect_binding((MODULE_BINDING, identity))
        self.generic_visit(node)

    def _visit_constructor(self, node: ast.Call, class_key: str) -> None:
        info = self.index.classes[class_key]
        initializer = info.methods.get("__init__")
        if initializer is not None:
            self.graph.record(
                self.index,
                self.module,
                node,
                "__init__",
                ("symbol", initializer),
                owner=self.owner,
                proven=self.proven_context,
            )
        self._visit_receiver_value(node.func)
        for argument in [*node.args, *(kw.value for kw in node.keywords)]:
            self.visit(argument)

    def visit_Return(self, node: ast.Return | ast.Yield | ast.YieldFrom) -> None:
        if node.value is not None:
            self._protect_value(node.value)
            self.visit(node.value)

    visit_Yield = visit_Return
    visit_YieldFrom = visit_Return

    def visit_List(self, node: ast.List | ast.Tuple | ast.Set) -> None:
        for item in node.elts:
            self._protect_value(item, retain_class=False)
        self.generic_visit(node)

    visit_Tuple = visit_List
    visit_Set = visit_List

    def visit_Dict(self, node: ast.Dict) -> None:
        for item in [*node.keys, *node.values]:
            if item is not None:
                self._protect_value(item, retain_class=False)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if any(
            isinstance(target, ast.Name) and target.id == _EXPORT_LIST
            for target in node.targets
        ):
            self._check_exports(node.value)
        if self._receiver_assignment(node.targets, node.value):
            return
        self.generic_visit(node)

    def _receiver_assignment(
        self, targets: list[ast.expr], value: ast.expr | None
    ) -> bool:
        if value is None:
            return False
        binding = self.index.resolve(value, self.module, self.local)
        if not binding or binding[0] not in RECEIVER_BINDINGS:
            self._protect_value(value, retain_class=False)
            return False
        # Only stable, direct aliases avoid an escape. Container/attribute
        # storage and unresolved/reassigned targets retain every possible member.
        if not all(
            isinstance(target, ast.Name)
            and self.index.resolve(target, self.module, self.local) == binding
            for target in targets
        ):
            self._protect_binding(binding)
        self._visit_receiver_value(value)
        for target in targets:
            self.visit(target)
        return True

    def visit_AnnAssign(self, node: ast.AnnAssign | ast.AugAssign) -> None:
        if isinstance(node.target, ast.Name) and node.target.id == _EXPORT_LIST:
            self._check_exports(node.value)
        if isinstance(node, ast.AnnAssign) and self._receiver_assignment(
            [node.target], node.value
        ):
            if node.annotation is not None:
                self.visit(node.annotation)
            return
        self.generic_visit(node)

    visit_AugAssign = visit_AnnAssign

    def _check_exports(self, expression: ast.AST | None) -> None:
        if not (
            isinstance(expression, (ast.List, ast.Tuple, ast.Set))
            and all(
                isinstance(item, ast.Constant) and isinstance(item.value, str)
                for item in expression.elts
            )
        ):
            for identity in self.module.names:
                self._protect_binding((MODULE_BINDING, identity))

    def visit_FunctionDef(self, node: FunctionNode) -> None:
        self._visit_function_header(node)
        previous = self.owner, self.local, self.proven_context
        self.owner = self.module.functions.get(node.lineno)
        self.proven_context = self.owner is not None
        bindings, scope_writes = function_receivers(self.index, self.module, node)
        # Methods use module globals, not their class's execution namespace.
        self.local = (
            bindings
            if self.owner in self.index.method_classes
            else {**self.local, **bindings}
        )
        if scope_writes:
            self._opaque()
        for statement in node.body:
            self.visit(statement)
        self.owner, self.local, self.proven_context = previous

    def _visit_function_header(self, node: FunctionNode) -> None:
        expressions = [*node.decorator_list, *default_expressions(node.args)]
        expressions.extend(
            arg.annotation
            for arg in argument_nodes(node.args)
            if arg.annotation is not None
        )
        if node.returns is not None:
            expressions.append(node.returns)
        for expression in expressions:
            self.visit(expression)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in [
            *node.decorator_list,
            *node.bases,
            *(item.value for item in node.keywords),
        ]:
            self.visit(expression)
        previous = self.local
        self.local = {
            **previous,
            **{name: None for name in bound_names(node.body).counts},
        }
        for statement in node.body:
            self.visit(statement)
        self.local = previous

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for expression in default_expressions(node.args):
            self.visit(expression)
        previous = self.owner, self.local, self.proven_context
        self.owner = None
        self.proven_context = False
        self.local = {
            **self.local,
            **dict.fromkeys(arg.arg for arg in argument_nodes(node.args)),
        }
        self.visit(node.body)
        self.owner, self.local, self.proven_context = previous
