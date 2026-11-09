"""Where one Python file uses third-party modules.

Import aliases, ``from x import y``, attribute chains, keyword arguments and
simple assignments are followed. A parameter, local or rebinding that shadows a
name is not the package. Uses already guarded against a removal (``except
ImportError``, ``hasattr``, ``getattr`` with a default) are marked ``guarded``.
"""

from __future__ import annotations

import ast
import builtins
import sys
import warnings
from collections import Counter
from dataclasses import dataclass, field

from skylos.rules.ai_defect.api_signature_hallucination import (
    _IMPORT_ERROR_NAMES,
    _binding_counts,
    _contextlib_suppress_names,
    _safe_member_name,
    _safe_module_name,
    _scope_nodes,
    _suppresses_import_error,
)

_ATTRIBUTE_ERROR_NAMES = frozenset({"AttributeError", "Exception", "BaseException"})
_TYPE_ERROR_NAMES = frozenset({"TypeError", "Exception", "BaseException"})
_TRY_NODES = (ast.Try, ast.TryStar)
_BUILTIN_NAMES = frozenset(dir(builtins))
_Resolved = tuple[str, tuple[str, ...]]


@dataclass(frozen=True)
class Reference:
    file: str
    line: int
    module: str
    path: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    guarded: bool = False
    star: bool = False
    snippet: str = ""


@dataclass
class _Frame:
    counts: Counter
    is_class: bool = False
    tracked: dict[str, _Resolved] = field(default_factory=dict)
    known: Counter = field(default_factory=Counter)
    conflicted: set[str] = field(default_factory=set)


@dataclass
class _Guards:
    imports: set[int] = field(default_factory=set)
    attributes: set[int] = field(default_factory=set)
    keywords: set[int] = field(default_factory=set)


def _caught_names(handlers: list[ast.ExceptHandler]) -> set[str]:
    names: set[str] = set()
    for handler in handlers:
        if handler.type is None:
            names.add("*")
            continue
        candidates = [handler.type]
        if isinstance(handler.type, ast.Tuple):
            candidates = handler.type.elts
        for candidate in candidates:
            if isinstance(candidate, ast.Name):
                names.add(candidate.id)
            elif isinstance(candidate, ast.Attribute):
                names.add(candidate.attr)
    return names


def _catches(names: set[str], wanted: frozenset[str]) -> bool:
    return "*" in names or bool(names & wanted)


def _hasattr_guard(test: ast.expr) -> str | None:
    if (
        isinstance(test, ast.Call)
        and isinstance(test.func, ast.Name)
        and test.func.id == "hasattr"
        and len(test.args) == 2
        and isinstance(test.args[1], ast.Constant)
        and isinstance(test.args[1].value, str)
    ):
        return test.args[1].value
    return None


def _mark_imports(guards: _Guards, statements: list[ast.stmt]) -> None:
    for statement in statements:
        for child in ast.walk(statement):
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                guards.imports.add(id(child))


def _mark_try(guards: _Guards, node: ast.Try) -> None:
    names = _caught_names(node.handlers)
    if _catches(names, _IMPORT_ERROR_NAMES):
        _mark_imports(guards, node.body)
    attributes = _catches(names, _ATTRIBUTE_ERROR_NAMES)
    keywords = _catches(names, _TYPE_ERROR_NAMES)
    for statement in node.body:
        for child in ast.walk(statement):
            if attributes and isinstance(child, ast.Attribute):
                guards.attributes.add(id(child))
            elif keywords and isinstance(child, ast.Call):
                guards.keywords.add(id(child))


def _mark_hasattr(guards: _Guards, node: ast.If) -> None:
    guarded = _hasattr_guard(node.test)
    if guarded is None:
        return
    for statement in node.body:
        for child in ast.walk(statement):
            if isinstance(child, ast.Attribute) and child.attr == guarded:
                guards.attributes.add(id(child))


def _guards_of(tree: ast.Module) -> _Guards:
    guards = _Guards()
    suppress_names = _contextlib_suppress_names(tree)
    for node in ast.walk(tree):
        if isinstance(node, _TRY_NODES):
            _mark_try(guards, node)
        elif isinstance(node, ast.If):
            _mark_hasattr(guards, node)
        elif isinstance(node, (ast.With, ast.AsyncWith)) and any(
            _suppresses_import_error(item.context_expr, suppress_names)
            for item in node.items
        ):
            _mark_imports(guards, node.body)
    return guards


def _is_stdlib(module: str) -> bool:
    return module.split(".", 1)[0] in sys.stdlib_module_names


def _dynamic_import(node: ast.Call) -> str | None:
    func = node.func
    name = ""
    if isinstance(func, ast.Name):
        name = func.id
    elif isinstance(func, ast.Attribute):
        name = func.attr
    if name not in {"import_module", "__import__"} or not node.args:
        return None
    first = node.args[0]
    if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
        return None
    module = _safe_module_name(first.value)
    if module is None or _is_stdlib(module):
        return None
    if name == "__import__":
        return module.split(".", 1)[0]
    return module


class _ReferenceVisitor(ast.NodeVisitor):
    def __init__(self, file: str, lines: list[str], guards: _Guards):
        self.file = file
        self.lines = lines
        self.guards = guards
        self.references: dict[str, set[Reference]] = {}
        self.frames: list[_Frame] = []
        self.star_modules: list[str] = []

    def _push(
        self, node: ast.AST, *, is_class: bool = False, parameters: bool = False
    ) -> None:
        frame = _Frame(
            _binding_counts(node, include_parameters=parameters), is_class=is_class
        )
        self.frames.append(frame)
        for child in _scope_nodes(node):
            if id(child) in self.guards.imports:
                continue
            if isinstance(child, ast.Import):
                self._prebind_import(frame, child)
            elif isinstance(child, ast.ImportFrom):
                self._prebind_import_from(frame, child)

    def _prebind(self, frame: _Frame, local: str, value: _Resolved) -> None:
        frame.known[local] += 1
        previous = frame.tracked.get(local)
        if previous is not None and previous != value:
            frame.conflicted.add(local)
        frame.tracked[local] = value

    def _prebind_import(self, frame: _Frame, node: ast.Import) -> None:
        for alias in node.names:
            module = _safe_module_name(alias.name)
            if module is None or _is_stdlib(module):
                continue
            if alias.asname:
                self._prebind(frame, alias.asname, (module, ()))
            else:
                root = module.split(".", 1)[0]
                self._prebind(frame, root, (root, ()))

    def _prebind_import_from(self, frame: _Frame, node: ast.ImportFrom) -> None:
        module = _safe_module_name(node.module)
        if node.level or module is None or _is_stdlib(module):
            return
        for alias in node.names:
            member = _safe_member_name(alias.name)
            if member is not None:
                self._prebind(frame, alias.asname or member, (module, (member,)))

    def _lookup(self, name: str) -> _Resolved | None:
        top = len(self.frames) - 1
        for index in range(top, -1, -1):
            frame = self.frames[index]
            if frame.is_class and index != top:
                continue
            if frame.counts[name] <= 0 and name not in frame.tracked:
                continue
            if name in frame.conflicted or frame.known[name] != frame.counts[name]:
                return None
            return frame.tracked.get(name)
        return None

    def _bound_anywhere(self, name: str) -> bool:
        return any(
            frame.counts[name] > 0 or name in frame.tracked for frame in self.frames
        )

    def _emit(
        self,
        node: ast.AST,
        module: str,
        path: tuple[str, ...] = (),
        *,
        keywords: tuple[str, ...] = (),
        guarded: bool = False,
        star: bool = False,
    ) -> None:
        line = int(getattr(node, "lineno", 1) or 1)
        snippet = ""
        if 0 < line <= len(self.lines):
            snippet = self.lines[line - 1].strip()[:200]
        root = module.split(".", 1)[0]
        self.references.setdefault(root, set()).add(
            Reference(self.file, line, module, path, keywords, guarded, star, snippet)
        )

    def visit_Module(self, node: ast.Module) -> None:
        self._push(node)
        self.generic_visit(node)
        self.frames.pop()

    def visit_Import(self, node: ast.Import) -> None:
        guarded = id(node) in self.guards.imports
        for alias in node.names:
            module = _safe_module_name(alias.name)
            if module is not None and not _is_stdlib(module):
                self._emit(alias, module, guarded=guarded)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = _safe_module_name(node.module)
        if node.level or module is None or _is_stdlib(module):
            return
        guarded = id(node) in self.guards.imports
        for alias in node.names:
            if alias.name == "*":
                if not guarded:
                    self.star_modules.append(module)
                self._emit(alias, module, guarded=guarded)
                continue
            member = _safe_member_name(alias.name)
            if member is not None:
                self._emit(alias, module, (member,), guarded=guarded)

    def _visit_function(self, node: ast.AST) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        self.visit(node.args)
        if node.returns is not None:
            self.visit(node.returns)
        self._push(node, parameters=True)
        for statement in node.body:
            self.visit(statement)
        self.frames.pop()

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.visit(node.args)
        self._push(node, parameters=True)
        self.visit(node.body)
        self.frames.pop()

    def _visit_comprehension(self, node: ast.AST) -> None:
        self._push(node)
        self.generic_visit(node)
        self.frames.pop()

    visit_ListComp = _visit_comprehension
    visit_SetComp = _visit_comprehension
    visit_DictComp = _visit_comprehension
    visit_GeneratorExp = _visit_comprehension

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for part in (*node.decorator_list, *node.bases, *node.keywords):
            self.visit(part)
        self._push(node, is_class=True)
        for statement in node.body:
            self.visit(statement)
        self.frames.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node)
        value = self._resolve(node.value)
        if value is not None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._prebind(self.frames[-1], target.id, value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.generic_visit(node)
        if node.value is not None and isinstance(node.target, ast.Name):
            value = self._resolve(node.value)
            if value is not None:
                self._prebind(self.frames[-1], node.target.id, value)

    def visit_withitem(self, node: ast.withitem) -> None:
        self.generic_visit(node)
        if isinstance(node.optional_vars, ast.Name):
            value = self._resolve(node.context_expr)
            if value is not None:
                self._prebind(self.frames[-1], node.optional_vars.id, value)

    def _resolve(self, expression: ast.AST) -> _Resolved | None:
        if isinstance(expression, ast.Name):
            return self._lookup(expression.id)
        if isinstance(expression, ast.Attribute):
            base = self._resolve(expression.value)
            if base is not None:
                return base[0], (*base[1], expression.attr)
            return None
        if isinstance(expression, ast.Call):
            return self._resolve_call(expression)
        return None

    def _resolve_call(self, expression: ast.Call) -> _Resolved | None:
        dynamic = _dynamic_import(expression)
        if dynamic is not None:
            return dynamic, ()
        base = self._resolve(expression.func)
        if base is None:
            return None
        return base[0], (*base[1], "()")

    def _visit_inner_calls(self, expression: ast.AST | None) -> None:
        current = expression
        while isinstance(current, ast.Attribute):
            current = current.value
        if isinstance(current, ast.Call):
            self.visit(current)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        target = None
        if isinstance(node.ctx, ast.Load):
            target = self._resolve(node)
        if target is None:
            self.generic_visit(node)
            return
        self._emit(
            node, target[0], target[1], guarded=id(node) in self.guards.attributes
        )
        self._visit_inner_calls(node.value)

    def visit_Name(self, node: ast.Name) -> None:
        if not isinstance(node.ctx, ast.Load):
            return
        target = self._lookup(node.id)
        if target is not None:
            if target[1]:
                self._emit(node, target[0], target[1])
            return
        if (
            self.star_modules
            and node.id not in _BUILTIN_NAMES
            and not self._bound_anywhere(node.id)
        ):
            for module in self.star_modules:
                self._emit(node, module, (node.id,), star=True)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        dynamic = _dynamic_import(node)
        if dynamic is not None:
            self._emit(node, dynamic)
            return
        if isinstance(func, ast.Name) and func.id == "getattr" and self._getattr(node):
            return
        target = self._resolve(func)
        if target is None:
            self.generic_visit(node)
            return
        keywords = {keyword.arg for keyword in node.keywords if keyword.arg is not None}
        self._emit(
            node,
            target[0],
            target[1],
            keywords=tuple(sorted(keywords)),
            guarded=id(node) in self.guards.keywords
            or id(func) in self.guards.attributes,
        )
        self._visit_inner_calls(getattr(func, "value", None))
        for argument in (*node.args, *node.keywords):
            self.visit(argument)

    def _getattr(self, node: ast.Call) -> bool:
        """``getattr(alias, "name")``: a reference when it has no default."""
        if len(node.args) < 2 or not isinstance(node.args[1], ast.Constant):
            return False
        name = node.args[1].value
        base = self._resolve(node.args[0])
        if base is None or not isinstance(name, str) or not name.isidentifier():
            return False
        self._emit(
            node,
            base[0],
            (*base[1], name),
            guarded=len(node.args) > 2 or id(node) in self.guards.attributes,
        )
        return True


def references_in_source(file: str, source: str) -> dict[str, set[Reference]]:
    """Third-party references of one file, by top-level module."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        tree = ast.parse(source)
    visitor = _ReferenceVisitor(file, source.splitlines(), _guards_of(tree))
    visitor.visit(tree)
    return visitor.references
