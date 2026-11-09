from __future__ import annotations

import ast
import textwrap

SAME_DOCS = "same_docs"
SAME_RENAMED = "same_renamed"

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _parse_one(code: str):
    try:
        tree = ast.parse(textwrap.dedent(code))
    except (SyntaxError, ValueError, RecursionError):
        return None
    if len(tree.body) != 1:
        return None
    node = tree.body[0]
    if not isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
        return None
    return node


def _strip_docstring(node) -> None:
    body = node.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        node.body = body[1:] or [ast.Pass()]


def _class_shell(node: ast.ClassDef) -> ast.ClassDef:
    kept = [child for child in node.body if not isinstance(child, _FUNCTIONS)]
    return ast.ClassDef(
        name=node.name,
        bases=node.bases,
        keywords=node.keywords,
        body=kept or [ast.Pass()],
        decorator_list=node.decorator_list,
        type_params=getattr(node, "type_params", []),
    )


def _dump(node) -> str:
    return ast.dump(node, annotate_fields=False, include_attributes=False)


def _params(node) -> list[str]:
    args = node.args
    names = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
    if args.vararg:
        names.append("*" + args.vararg.arg)
    if args.kwarg:
        names.append("**" + args.kwarg.arg)
    return names


def _declared(node) -> set[str]:
    names = set()
    for child in ast.walk(node):
        if isinstance(child, (ast.Global, ast.Nonlocal)):
            names.update(child.names)
    return names


_DYNAMIC_CALLS = frozenset({"locals", "vars", "eval", "exec", "_getframe", "currentframe", "stack", "getframeinfo"})
_DYNAMIC_ATTRIBUTES = frozenset({"f_locals", "co_varnames", "__code__"})


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _reads_names_at_runtime(node) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and _call_name(child) in _DYNAMIC_CALLS:
            return True
        if isinstance(child, ast.Attribute) and child.attr in _DYNAMIC_ATTRIBUTES:
            return True
        if isinstance(child, (*_FUNCTIONS, ast.ClassDef, ast.Lambda)) and child is not node:
            return True
    return False


def _bound(node) -> set[str]:
    names = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
            names.add(child.id)
        elif isinstance(child, ast.ExceptHandler) and child.name:
            names.add(child.name)
        elif isinstance(child, ast.alias) and child.asname:
            names.add(child.asname)
    return names


class _Renamer(ast.NodeTransformer):
    def __init__(self, local: set[str]):
        self.local = local
        self.mapping: dict[str, str] = {}

    def _name(self, name: str) -> str:
        if name not in self.local:
            return name
        if name not in self.mapping:
            self.mapping[name] = f"_local{len(self.mapping)}"
        return self.mapping[name]

    def visit_Name(self, node: ast.Name):
        node.id = self._name(node.id)
        return node

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.name:
            node.name = self._name(node.name)
        self.generic_visit(node)
        return node

def _canonical(node, params: set[str]) -> str:
    local = (_bound(node) - params) - _declared(node)
    if node.args.vararg:
        local.discard(node.args.vararg.arg)
    if node.args.kwarg:
        local.discard(node.args.kwarg.arg)
    renamer = _Renamer(local)
    top_args = node.args
    node.args = ast.arguments(posonlyargs=[], args=[], vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[])
    renamed = renamer.visit(node)
    renamed.args = top_args
    return _dump(renamed)


def same_logic(before: dict | None, after: dict | None) -> str | None:
    if not before or not after:
        return None
    if before.get("truncated") or after.get("truncated"):
        return None
    old = _parse_one(before.get("code") or "")
    new = _parse_one(after.get("code") or "")
    if old is None or new is None or type(old) is not type(new):
        return None
    if _dump(old) == _dump(new):
        return None
    _strip_docstring(old)
    _strip_docstring(new)
    if _dump(old) == _dump(new):
        return SAME_DOCS
    if isinstance(old, ast.ClassDef):
        if _dump(_class_shell(old)) == _dump(_class_shell(new)):
            return SAME_DOCS
        return None
    if old.name != new.name or _params(old) != _params(new):
        return None
    if _dump(old.args) != _dump(new.args):
        return None
    if _reads_names_at_runtime(old) or _reads_names_at_runtime(new):
        return None
    params = set(a.lstrip("*") for a in _params(old))
    if _canonical(old, params) == _canonical(new, params):
        return SAME_RENAMED
    return None
