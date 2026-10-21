"""Bounded, data-only Python source effects for cross-language reference proofs.

Unknown providers, roots and source effects remain unknown; target code is never
imported or executed.
"""

from __future__ import annotations

import ast
import os
from collections import defaultdict
from pathlib import Path

_JS_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")


class _ScopeBindings(dict):
    def __init__(self, values=()):
        super().__init__(values)
        self.providers = dict(getattr(values, "providers", {}))


def _scope_nodes(scope: ast.AST):
    """Executable nodes of one owner, excluding docstrings and nested bodies."""
    pending = []
    body = getattr(scope, "body", ())
    for index, node in enumerate(body):
        if (
            index == 0
            and isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            continue
        pending.append(node)
    while pending:
        node = pending.pop()
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, (ast.Constant, ast.JoinedStr))
            and (
                isinstance(node.value, ast.JoinedStr)
                or isinstance(node.value.value, str)
            )
        ):
            continue
        yield node
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        if isinstance(node, (ast.If, ast.While)) and isinstance(
            node.test, ast.Constant
        ):
            if not node.test.value:
                pending.extend(node.orelse)
                continue
            if isinstance(node, ast.If):
                pending.extend(node.body)
                continue
        if (
            isinstance(node, ast.For)
            and isinstance(node.iter, (ast.Tuple, ast.List, ast.Set))
            and not node.iter.elts
        ):
            pending.extend(node.orelse)
            continue
        pending.extend(ast.iter_child_nodes(node))


class _PythonReferenceProof:
    """Small source-only proofs shared by Python-to-browser reference checks."""

    def __init__(self, tree: ast.Module, root: Path, source_file: Path):
        self.tree = tree
        self.root = root.resolve()
        self.source_file = source_file.resolve()
        self.imports = {}
        self.functions = {}
        self.invalid = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    provider = alias.name if alias.asname else name
                    if name in self.imports:
                        self.invalid.add(name)
                    self.imports[name] = provider
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for alias in node.names:
                    name = alias.asname or alias.name
                    if name in self.imports:
                        self.invalid.add(name)
                    self.imports[name] = node.module + "." + alias.name
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in self.functions or node.name in self.imports:
                    self.invalid.add(node.name)
                self.functions[node.name] = node
            elif isinstance(node, ast.ClassDef):
                if node.name in self.imports:
                    self.invalid.add(node.name)
        for name, provider in self.imports.items():
            package = provider.split(".")[0]
            for directory in {self.root, self.source_file.parent}:
                if (directory / (package + ".py")).exists() or (
                    directory / package / "__init__.py"
                ).exists():
                    self.invalid.add(name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                if node.id in self.imports or node.id in self.functions:
                    self.invalid.add(node.id)
            elif isinstance(node, ast.Attribute) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                base = node.value
                while isinstance(base, ast.Attribute):
                    base = base.value
                if isinstance(base, ast.Name):
                    self.invalid.add(base.id)
            elif isinstance(node, ast.Subscript) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                base = node.value
                while isinstance(base, (ast.Attribute, ast.Subscript)):
                    base = base.value
                if isinstance(base, ast.Name):
                    self.invalid.add(base.id)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr"}
                and node.args
            ):
                base = node.args[0]
                while isinstance(base, ast.Attribute):
                    base = base.value
                if isinstance(base, ast.Name):
                    self.invalid.add(base.id)
        self.globals = self.bindings(tree, {})

    def bindings(self, scope, parameters):
        values = defaultdict(list)
        providers = dict(getattr(parameters, "providers", {}))
        for node in _scope_nodes(scope):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        values[target.id].append(node.value)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                values[node.target.id].append(node.value)
            elif isinstance(node, (ast.AugAssign, ast.NamedExpr)):
                if isinstance(node.target, ast.Name):
                    values[node.target.id].extend([None, None])
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    providers[alias.asname or alias.name.split(".")[0]] = (
                        alias.name if alias.asname else alias.name.split(".")[0]
                    )
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for alias in node.names:
                    providers[alias.asname or alias.name] = (
                        node.module + "." + alias.name
                    )
        result = _ScopeBindings(parameters)
        result.providers = providers
        for name, assignments in values.items():
            result[name] = assignments[0] if len(assignments) == 1 else None
        return result

    def call_bindings(self, call, caller):
        if not isinstance(call.func, ast.Name) or call.func.id in self.invalid:
            return None
        function = self.functions.get(call.func.id)
        if (
            function is None
            or function.decorator_list
            or isinstance(function, ast.AsyncFunctionDef)
        ):
            return None
        args = function.args
        if (
            args.vararg
            or args.kwarg
            or any(keyword.arg is None for keyword in call.keywords)
            or any(isinstance(argument, ast.Starred) for argument in call.args)
        ):
            return None
        positional = args.posonlyargs + args.args
        if len(call.args) > len(positional):
            return None
        parameters = {}
        for argument, value in zip(positional, call.args):
            parameters[argument.arg] = self.substitute(value, caller)
        for keyword in call.keywords:
            if keyword.arg in parameters:
                return None
            parameters[keyword.arg] = self.substitute(keyword.value, caller)
        defaults = {}
        if args.defaults:
            default_names = [
                argument.arg for argument in positional[-len(args.defaults) :]
            ]
            defaults.update(zip(default_names, args.defaults))
        defaults.update(zip([arg.arg for arg in args.kwonlyargs], args.kw_defaults))
        declared = positional + args.kwonlyargs
        if set(parameters) - {argument.arg for argument in declared}:
            return None
        for argument in declared:
            if argument.arg not in parameters:
                if argument.arg not in defaults or defaults[argument.arg] is None:
                    return None
                parameters[argument.arg] = defaults[argument.arg]
        local = _ScopeBindings(self.globals)
        bound = self.bindings(function, parameters)
        local.update(bound)
        local.providers.update(bound.providers)
        return function, local

    def substitute(self, node, bindings, seen=frozenset()):
        if isinstance(node, ast.Name) and node.id in bindings and node.id not in seen:
            return self.substitute(bindings[node.id], bindings, seen | {node.id})
        return node

    def contexts(self):
        pending = [(self.tree, self.globals)]
        seen = set()
        while pending and len(seen) < 64:
            scope, bindings = pending.pop()
            bound_values = []
            for name, value in sorted(bindings.items()):
                if isinstance(value, ast.AST):
                    spelling = ast.dump(value)
                else:
                    spelling = "?"
                bound_values.append((name, spelling))
            key = (id(scope), tuple(bound_values))
            if key in seen:
                continue
            seen.add(key)
            yield scope, bindings
            for node in _scope_nodes(scope):
                if isinstance(node, ast.Call):
                    called = self.call_bindings(node, bindings)
                    if called is not None:
                        pending.append(called)

    def qualified(self, node, bindings):
        if isinstance(node, ast.Name):
            if node.id in bindings or node.id in self.invalid:
                return ""
            provider = getattr(bindings, "providers", {}).get(
                node.id
            ) or self.imports.get(node.id, "")
            package = provider.split(".")[0]
            if package:
                for directory in {self.root, self.source_file.parent}:
                    if (directory / (package + ".py")).exists() or (
                        directory / package / "__init__.py"
                    ).exists():
                        return ""
            return provider
        if isinstance(node, ast.Attribute):
            base = self.qualified(node.value, bindings)
            if base:
                return base + "." + node.attr
        return ""

    def text(self, node, bindings):
        node = self.substitute(node, bindings)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def path(self, node, bindings, depth=0):
        if depth > 12:
            return None
        if isinstance(node, ast.Name) and node.id in self.invalid:
            return None
        resolved = self.substitute(node, bindings)
        if resolved is not node:
            return self.path(resolved, bindings, depth + 1)
        if isinstance(node, ast.Name) and node.id == "__file__":
            return self.source_file
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if "\x00" in node.value or ":" in node.value or "\\" in node.value:
                return None
            candidate = Path(node.value)
            if not candidate.is_absolute():
                candidate = self.root / candidate
        elif isinstance(node, ast.Attribute) and node.attr == "parent":
            parent = self.path(node.value, bindings, depth + 1)
            if parent is None:
                return None
            candidate = parent.parent
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            parent = self.path(node.left, bindings, depth + 1)
            tail = self.text(node.right, bindings)
            if parent is None or tail is None:
                return None
            candidate = parent / tail
        elif isinstance(node, ast.Call):
            provider = self.qualified(node.func, bindings)
            if (
                provider in {"pathlib.Path", "os.path.join"}
                and node.args
                and not node.keywords
            ):
                parent = self.path(node.args[0], bindings, depth + 1)
                tails = [self.text(value, bindings) for value in node.args[1:]]
                if parent is None or any(tail is None for tail in tails):
                    return None
                candidate = parent.joinpath(*tails)
            elif (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {"resolve", "absolute"}
                and not node.args
                and not node.keywords
            ):
                return self.path(node.func.value, bindings, depth + 1)
            else:
                return None
        else:
            return None
        candidate = Path(os.path.abspath(candidate))
        try:
            candidate.relative_to(self.root)
        except ValueError:
            return None
        return candidate

    def loops(self, scope, bindings):
        result = {}
        walk_files = {}
        for node in _scope_nodes(scope):
            if isinstance(node, ast.For) and isinstance(node.target, ast.Name):
                if node.target.id in result:
                    result[node.target.id] = None
                else:
                    result[node.target.id] = node.iter
            elif isinstance(node, ast.For) and isinstance(
                node.target, (ast.Tuple, ast.List)
            ):
                names = node.target.elts
                if len(names) == 3 and all(
                    isinstance(name, ast.Name) for name in names
                ):
                    variable_names = {name.id for name in names}
                    if variable_names & (self.invalid | set(bindings)):
                        continue
                    mutated = False
                    for child in _scope_nodes(scope):
                        if (
                            isinstance(child, ast.Call)
                            and isinstance(child.func, ast.Attribute)
                            and isinstance(child.func.value, ast.Name)
                            and child.func.value.id in variable_names
                        ):
                            mutated = True
                            break
                    if mutated:
                        continue
                    walk_files[names[2].id] = (node.iter, names[0].id)
        for name, iterable in list(result.items()):
            if isinstance(iterable, ast.Name) and iterable.id in walk_files:
                walk_call, root_name = walk_files[iterable.id]
                result[name] = (walk_call, root_name)
        return result

    def listing(self, iterable, bindings, depth=0):
        if depth > 12:
            return None
        iterable = self.substitute(iterable, bindings)
        if not isinstance(iterable, ast.Call):
            return None
        provider = self.qualified(iterable.func, bindings)
        if (
            provider in {"os.listdir", "os.scandir", "os.walk"}
            and len(iterable.args) == 1
            and not iterable.keywords
        ):
            folder = self.path(iterable.args[0], bindings)
            if folder is not None:
                mode = {
                    "os.listdir": "names",
                    "os.scandir": "entries",
                    "os.walk": "walk",
                }[provider]
                return folder, "*", provider == "os.walk", mode
        if (
            provider in {"glob.glob", "glob.iglob"}
            and len(iterable.args) == 1
            and not iterable.keywords
        ):
            value = self.text(iterable.args[0], bindings)
            if value is not None:
                parent, pattern = os.path.split(value)
                folder = self.path(ast.Constant(parent or "."), bindings)
                if (
                    folder is not None
                    and "**" not in value
                    and "*" not in parent
                    and "?" not in parent
                ):
                    return folder, pattern, False, "paths"
        if isinstance(iterable.func, ast.Attribute):
            method = iterable.func.attr
            folder = self.path(iterable.func.value, bindings)
            if (
                folder is not None
                and method == "iterdir"
                and not iterable.args
                and not iterable.keywords
            ):
                return folder, "*", False, "paths"
            if (
                folder is not None
                and method in {"glob", "rglob"}
                and len(iterable.args) == 1
                and not iterable.keywords
            ):
                pattern = self.text(iterable.args[0], bindings)
                if pattern is not None and "/" not in pattern and "**" not in pattern:
                    return folder, pattern, method == "rglob", "paths"
        called = self.call_bindings(iterable, bindings)
        if called is None:
            return None
        function, local = called
        body = []
        for index, node in enumerate(function.body):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            if (
                index == 0
                and isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                continue
            body.append(node)
        if len(body) != 1 or not isinstance(body[0], ast.Return):
            return None
        value = body[0].value
        if (
            isinstance(value, (ast.ListComp, ast.GeneratorExp))
            and len(value.generators) == 1
        ):
            generator = value.generators[0]
            if (
                not isinstance(generator.target, ast.Name)
                or generator.is_async
                or generator.ifs
            ):
                return None
            listing = self.listing(generator.iter, local, depth + 1)
            if listing is None:
                return None
            item = value.elt
            if isinstance(item, ast.Name) and item.id == generator.target.id:
                return listing
            if (
                isinstance(item, ast.Attribute)
                and item.attr == "path"
                and isinstance(item.value, ast.Name)
                and item.value.id == generator.target.id
                and listing[3] == "entries"
            ):
                return listing[0], listing[1], listing[2], "paths"
            if self.joined_item(item, generator.target.id, listing, local):
                folder, pattern, recursive, _ = listing
                return folder, pattern, recursive, "paths"
            return None
        return self.listing(value, local, depth + 1)

    def joined_item(self, expression, name, listing, bindings):
        folder, _, _, mode = listing
        if mode != "names":
            return False
        if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Div):
            return (
                self.path(expression.left, bindings) == folder
                and isinstance(expression.right, ast.Name)
                and expression.right.id == name
            )
        if (
            isinstance(expression, ast.Call)
            and self.qualified(expression.func, bindings) == "os.path.join"
            and len(expression.args) == 2
            and not expression.keywords
        ):
            return (
                self.path(expression.args[0], bindings) == folder
                and isinstance(expression.args[1], ast.Name)
                and expression.args[1].id == name
            )
        return False

    def script_values(self, expression, bindings, loops, prefix="", depth=0):
        if depth > 12:
            return
        resolved = self.substitute(expression, bindings)
        if resolved is not expression:
            yield from self.script_values(resolved, bindings, loops, prefix, depth + 1)
            return
        path = self.path(expression, bindings)
        if path is not None:
            if prefix:
                value = self.text(expression, bindings)
                if value is not None:
                    path = self.path(ast.Constant(prefix + value), bindings)
                else:
                    path = None
            if path is not None and str(path).lower().endswith(_JS_EXTENSIONS):
                yield "path", str(path)
            return
        item = expression
        entry_path = False
        if isinstance(item, ast.Attribute) and item.attr == "path":
            item = item.value
            entry_path = True
        for name, iterable in loops.items():
            walk_root = None
            if isinstance(iterable, tuple):
                iterable, walk_root = iterable
            listing = self.listing(iterable, bindings)
            if listing is None:
                continue
            folder, pattern, recursive, mode = listing
            direct_item = isinstance(item, ast.Name) and item.id == name
            joined = self.joined_item(expression, name, listing, bindings)
            if mode == "walk":
                if walk_root is None or walk_root in bindings:
                    continue
                if (
                    isinstance(expression, ast.Call)
                    and self.qualified(expression.func, bindings) == "os.path.join"
                    and len(expression.args) == 2
                    and not expression.keywords
                ):
                    left, right = expression.args
                    joined = (
                        isinstance(left, ast.Name)
                        and left.id == walk_root
                        and isinstance(right, ast.Name)
                        and right.id == name
                    )
                if not joined or prefix or entry_path:
                    continue
                yield "folder", (str(folder), pattern, recursive)
                continue
            if not direct_item and not joined:
                continue
            if prefix:
                if (
                    self.path(ast.Constant(prefix), bindings) != folder
                    or mode != "names"
                ):
                    continue
            elif mode == "names" and not joined:
                continue
            if entry_path and mode != "entries":
                continue
            if mode == "entries" and not entry_path:
                continue
            yield "folder", (str(folder), pattern, recursive)
