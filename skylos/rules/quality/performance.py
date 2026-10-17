from __future__ import annotations
import ast
from pathlib import Path
from skylos.rules.base import SkylosRule


def _target_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return set().union(*(_target_names(item) for item in target.elts))
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return set()


class _ScopeBindings(ast.NodeVisitor):
    """Bindings in one lexical scope, optionally before a source location."""

    def __init__(
        self, before_line: int | None = None, *, track_mutations=False, ignored_calls=()
    ):
        self.names: set[str] = set()
        self.mutated_names: set[str] = set()
        self.global_names: set[str] = set()
        self.before_line = before_line
        self.track_mutations = track_mutations
        self.ignored_calls = ignored_calls

    def _add(self, node: ast.AST, name: str):
        if self.before_line is None or getattr(node, "lineno", 0) < self.before_line:
            self.names.add(name)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._add(node, node.id)

    def visit_Global(self, node):
        self.global_names.update(node.names)

    def _mutated_receiver(self, node):
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        if isinstance(node, ast.Name):
            self._add(node, node.id)
            if self.before_line is None or node.lineno < self.before_line:
                self.mutated_names.add(node.id)

    def visit_Call(self, node):
        if self.track_mutations and node not in self.ignored_calls:
            # Unknown methods and callees can resize a mutable literal alias.
            # A prior list initializer alone cannot establish a fixed count.
            if isinstance(node.func, ast.Attribute):
                self._mutated_receiver(node.func.value)
            for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                self._mutated_receiver(arg)
        self.generic_visit(node)

    def visit_Subscript(self, node):
        if self.track_mutations and isinstance(node.ctx, (ast.Store, ast.Del)):
            self._mutated_receiver(node.value)
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if self.track_mutations and isinstance(node.ctx, (ast.Store, ast.Del)):
            self._mutated_receiver(node.value)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self._add(node, node.name)
        # Function creation evaluates these in the enclosing scope. A walrus
        # in a default/decorator can replace an outer item or a builtin name.
        for expression in [
            *node.decorator_list,
            *node.args.defaults,
            *node.args.kw_defaults,
        ]:
            if expression is not None:
                self.visit(expression)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self._add(node, node.name)
        for expression in [*node.bases, *node.keywords, *node.decorator_list]:
            self.visit(expression)

    def visit_Lambda(self, node):
        for expression in [*node.args.defaults, *node.args.kw_defaults]:
            if expression is not None:
                self.visit(expression)

    def visit_ListComp(self, node):
        # Comprehension targets have their own scope. Walrus expressions can
        # bind in the surrounding scope, so retain those bindings.
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr):
                self.visit(child.target)
            elif self.track_mutations and isinstance(
                child, (ast.Call, ast.Attribute, ast.Subscript)
            ):
                # Comprehension-local targets do not leak, but evaluated
                # callbacks and writes can grow an enclosing mutable source.
                self.visit(child)

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_Import(self, node):
        for alias in node.names:
            self._add(node, alias.asname or alias.name.split(".")[0])

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self._add(node, alias.asname or alias.name)

    def visit_ExceptHandler(self, node):
        if node.name:
            self._add(node, node.name)
        self.generic_visit(node)


def _os_walk_partition_names(outer: ast.For) -> set[str]:
    """Names bound to the per-directory children returned by ``os.walk``."""
    iterator = outer.iter
    target = outer.target
    if not (
        isinstance(iterator, ast.Call)
        and isinstance(iterator.func, ast.Attribute)
        and isinstance(iterator.func.value, ast.Name)
        and iterator.func.value.id == "os"
        and iterator.func.attr == "walk"
        and isinstance(target, (ast.Tuple, ast.List))
        and len(target.elts) == 3
    ):
        return set()
    return {element.id for element in target.elts[1:] if isinstance(element, ast.Name)}


def _is_file_read_context(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return True

    receiver = node.func.value

    if isinstance(receiver, ast.Name):
        name = receiver.id.lower()

        non_file_hints = (
            "response",
            "resp",
            "reply",
            "buf",
            "buffer",
            "stringio",
            "bytesio",
            "stream",
            "bio",
            "sio",
            "stdin",
            "stdout",
            "stderr",
        )
        if any(hint in name for hint in non_file_hints):
            return False

    return True


def _qualified_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _call_chain_has_limiter(node: ast.AST) -> bool:
    current = node
    while isinstance(current, ast.Call):
        func = current.func
        if isinstance(func, ast.Attribute) and func.attr in {
            "first",
            "get",
            "head",
            "limit",
            "one",
            "one_or_none",
            "paginate",
            "take",
        }:
            return True
        current = func.value if isinstance(func, ast.Attribute) else func
    if isinstance(current, ast.Attribute):
        return _call_chain_has_limiter(current.value)
    return False


def _looks_like_orm_query(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute):
        if node.attr == "query":
            return True
        return _looks_like_orm_query(node.value)
    if isinstance(node, ast.Call):
        func_name = _qualified_name(node.func)
        if func_name.endswith((".query", ".select")):
            return True
        if isinstance(node.func, ast.Attribute):
            return _looks_like_orm_query(node.func.value)
    return False


def _is_unbounded_orm_all(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "all":
        return False
    if node.args or node.keywords:
        return False
    receiver = node.func.value
    return _looks_like_orm_query(receiver) and not _call_chain_has_limiter(receiver)


def _is_bounded_read(node: ast.Call) -> bool:
    """``f.read(1024 * 1024)`` / ``f.readlines(hint)`` read a bounded chunk
    (usually in a ``while chunk := f.read(n)`` loop); only ``read()``,
    ``read(-1)`` and ``read(None)`` load the whole file."""
    size = node.args[0] if node.args else None
    if size is None:
        for kw in node.keywords:
            if kw.arg in {"size", "n", "hint"}:
                size = kw.value
                break
    if size is None:
        return False
    if isinstance(size, ast.Constant):
        return size.value is not None and not (
            isinstance(size.value, (int, float)) and size.value < 0
        )
    if isinstance(size, ast.UnaryOp) and isinstance(size.op, ast.USub):
        return False
    return True


class PerformanceRule(SkylosRule):
    rule_id = "SKY-P401"
    name = "Performance Checks"

    def __init__(self, ignore_list=None):
        self.ignore_list = ignore_list or []
        self._parents: dict[ast.AST, ast.AST] = {}
        self._global_writes: set[str] = set()

    def _is_builtin(self, node: ast.AST, name: str) -> bool:
        if name in self._global_writes:
            return False
        current = node
        in_function = False
        while current in self._parents:
            current = self._parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                in_function = True
                args = current.args
                parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
                if args.vararg:
                    parameters.append(args.vararg)
                if args.kwarg:
                    parameters.append(args.kwarg)
                if any(arg.arg == name for arg in parameters):
                    return False
            if isinstance(current, ast.ClassDef) and in_function:
                continue
            if isinstance(
                current,
                (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                bindings = _ScopeBindings()
                for stmt in current.body:
                    bindings.visit(stmt)
                if name in bindings.names or "*" in bindings.names:
                    return False
        return True

    def _constant_iteration_count(self, node: ast.AST, seen=None) -> bool:
        """Whether iteration count is independent of runtime input sizes."""
        if seen is None:
            seen = set()
        if isinstance(node, ast.Name):
            if node.id in seen or len(seen) >= 8:
                return False
            if self._may_change_in_enclosing_loop(node, node.id):
                return False
            value = self._preceding_value(node, node.id)
            if value is None:
                return False
            return self._constant_iteration_count(value, seen | {node.id})
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return not any(isinstance(item, ast.Starred) for item in node.elts)
        if isinstance(node, ast.Dict):
            return all(key is not None for key in node.keys)
        if isinstance(node, ast.Constant):
            return isinstance(node.value, (str, bytes))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            for sequence, count in ((node.left, node.right), (node.right, node.left)):
                if isinstance(count, ast.Constant) and type(count.value) is int:
                    return self._constant_iteration_count(sequence, seen)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"items", "keys", "values"}
            and not node.args
            and not node.keywords
        ):
            receiver = node.func.value
            if isinstance(receiver, ast.Name):
                if self._may_change_in_enclosing_loop(
                    receiver, receiver.id, ignore_call=node
                ):
                    return False
                receiver = self._preceding_value(receiver, receiver.id)
            # These builtin dictionary views preserve its known upper bound.
            # An arbitrary object's similarly named method proves nothing.
            return isinstance(receiver, ast.Dict) and all(
                key is not None for key in receiver.keys
            )
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            return False
        if not self._is_builtin(node, node.func.id) or node.keywords:
            return False
        if node.func.id == "range" and 1 <= len(node.args) <= 3:
            for arg in node.args:
                if isinstance(arg, ast.UnaryOp) and isinstance(
                    arg.op, (ast.USub, ast.UAdd)
                ):
                    arg = arg.operand
                if not isinstance(arg, ast.Constant) or type(arg.value) is not int:
                    return False
            return True
        if node.func.id in {
            "list",
            "tuple",
            "set",
            "iter",
            "reversed",
            "sorted",
            "enumerate",
        }:
            return len(node.args) == 1 and self._constant_iteration_count(
                node.args[0], seen
            )
        return False

    def _may_change_in_enclosing_loop(
        self, node: ast.AST, name: str, *, ignore_call=None
    ) -> bool:
        """Later mutations can affect the next iteration despite source order."""
        current = node
        while current in self._parents:
            current = self._parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                break
            if isinstance(current, (ast.For, ast.AsyncFor, ast.While)):
                bindings = _ScopeBindings(
                    track_mutations=True, ignored_calls={ignore_call}
                )
                for statement in current.body:
                    bindings.visit(statement)
                if name in bindings.names:
                    return True
        return False

    def _preceding_value(self, node: ast.AST, name: str) -> ast.AST | None:
        """Resolve only direct, unambiguously bound preceding assignments."""
        current = node
        in_function = False
        while current in self._parents:
            current = self._parents[current]
            if isinstance(current, ast.ClassDef) and in_function:
                continue
            if not isinstance(
                current,
                (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue
            if isinstance(current, ast.Module) and name in self._global_writes:
                return None
            in_function |= isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef))
            found = False
            value = None
            for stmt in current.body:
                bindings = _ScopeBindings(before_line=node.lineno, track_mutations=True)
                bindings.visit(stmt)
                if name not in bindings.names:
                    continue
                found, value = True, None
                targets = (
                    stmt.targets
                    if isinstance(stmt, ast.Assign)
                    else ([stmt.target] if isinstance(stmt, ast.AnnAssign) else [])
                )
                if any(
                    isinstance(target, ast.Name) and target.id == name
                    for target in targets
                ):
                    value = stmt.value
            if found:
                return value
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = current.args
                params = [
                    *args.posonlyargs,
                    *args.args,
                    *args.kwonlyargs,
                    args.vararg,
                    args.kwarg,
                ]
                if any(param is not None and param.arg == name for param in params):
                    return None
                bindings = _ScopeBindings()
                for stmt in current.body:
                    bindings.visit(stmt)
                if name in bindings.names:
                    return None
        return None

    def _repeats_shared_elements(self, iterator: ast.AST) -> bool:
        """Sequence multiplication repeats references, not child collections."""
        seen = set()
        for _ in range(8):
            if isinstance(iterator, ast.Name) and iterator.id not in seen:
                seen.add(iterator.id)
                value = self._preceding_value(iterator, iterator.id)
                if value is None:
                    break
                iterator = value
            elif (
                isinstance(iterator, ast.Call)
                and isinstance(iterator.func, ast.Attribute)
                and iterator.func.attr in {"items", "keys", "values"}
                and not iterator.args
                and not iterator.keywords
            ):
                iterator = iterator.func.value
            elif (
                isinstance(iterator, ast.Call)
                and isinstance(iterator.func, ast.Name)
                and iterator.func.id
                in {"list", "tuple", "set", "iter", "reversed", "sorted"}
                and self._is_builtin(iterator, iterator.func.id)
                and len(iterator.args) == 1
                and not iterator.keywords
            ):
                iterator = iterator.args[0]
            else:
                break
        if isinstance(
            iterator, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            produced = (
                iterator.value if isinstance(iterator, ast.DictComp) else iterator.elt
            )
            targets = set().union(
                *(_target_names(generator.target) for generator in iterator.generators)
            )
            # Reading the index does not prove disjointness: overlapping
            # slices and ``items if index else items`` still repeat input.
            # Only identity forwarding preserves the source's row structure.
            if isinstance(produced, ast.Name) and produced.id in targets:
                return any(
                    self._repeats_shared_elements(generator.iter)
                    for generator in iterator.generators
                )
            return not self._constant_iteration_count(produced)
        return (
            not self._constant_iteration_count(iterator)
            and isinstance(iterator, ast.BinOp)
            and isinstance(iterator.op, ast.Mult)
            and (
                isinstance(iterator.left, (ast.List, ast.Tuple))
                or isinstance(iterator.right, (ast.List, ast.Tuple))
            )
        )

    def _walks_outer_partition(self, outer: ast.For, inner: ast.For) -> bool:
        if self._repeats_shared_elements(outer.iter):
            return False
        names = self._partition_names_before(outer, inner)
        iterator = inner.iter
        while isinstance(iterator, ast.Call):
            if isinstance(iterator.func, ast.Name):
                if (
                    iterator.func.id
                    not in {
                        "list",
                        "tuple",
                        "set",
                        "iter",
                        "reversed",
                        "sorted",
                        "enumerate",
                    }
                    or not self._is_builtin(iterator, iterator.func.id)
                    or len(iterator.args) != 1
                    or iterator.keywords
                ):
                    break
                iterator = iterator.args[0]
            else:
                break
        # Properties, subscriptions and arbitrary methods may expose a shared
        # global collection. Only the yielded binding itself is evidence here.
        if isinstance(iterator, ast.Name) and iterator.id in names:
            return not self._iteration_sources_mutated(outer, {iterator.id})
        if (
            isinstance(iterator, ast.Call)
            and self._is_stdlib_callable(iterator.func, "itertools", "chain")
            and iterator.args
            and not iterator.keywords
            and all(
                isinstance(arg, ast.Name) and arg.id in names for arg in iterator.args
            )
        ):
            return not self._iteration_sources_mutated(
                outer, {arg.id for arg in iterator.args}
            )
        # An arbitrary mapping protocol can yield the same backing collection
        # for every key. Forwarding __iter__/__getitem__ alone proves no bound.
        return False

    def _iteration_sources_mutated(self, outer, names: set[str]) -> bool:
        """Reject consumption proofs when a source escapes or is replenished.

        Follow shared aliases through the whole scan, including aliases created
        inside it. Rebinding an alias is not itself a mutation; method calls and
        passing the collection to an unknown callee can change its contents.
        """
        names = set(names)
        body = outer.body
        nodes = [child for statement in body for child in ast.walk(statement)]
        aliases = []

        class Aliases(_ScopeBindings):
            def visit_Assign(visitor, node):
                value = node.value
                if isinstance(value, ast.Call) and (
                    isinstance(value.func, ast.Name)
                    and value.func.id in {"iter", "enumerate", "reversed"}
                    and self._is_builtin(value, value.func.id)
                    and len(value.args) == 1
                    and not value.keywords
                ):
                    value = value.args[0]
                if isinstance(value, ast.Name):
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else [node.target]
                    )
                    aliases.extend(
                        (target.id, value.id)
                        for target in targets
                        if isinstance(target, ast.Name)
                    )
                visitor.generic_visit(node)

            visit_AnnAssign = visit_Assign

        scope = outer
        while scope in self._parents:
            scope = self._parents[scope]
            if isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
                break
        visitor = Aliases()
        for statement in scope.body:
            visitor.visit(statement)
        while True:
            expanded = names | {
                right if left in names else left
                for left, right in aliases
                if left in names or right in names
            }
            if expanded == names:
                break
            names = expanded
        pure_calls = {
            node
            for node in nodes
            if isinstance(node, ast.Call)
            and (
                self._is_partition_expression(node, names)
                or self._is_builtin_type_check(node)
            )
        }
        effects = _ScopeBindings(track_mutations=True, ignored_calls=pure_calls)
        for statement in body:
            effects.visit(statement)
        # Comprehension targets are local, but evaluated calls can still
        # mutate an outer source; the ordinary scope visitor skips those calls.
        for node in nodes:
            if isinstance(node, ast.Call):
                effects.visit(node)
        return bool(names & effects.mutated_names)

    def _is_partition_expression(self, node: ast.AST, names: set[str]) -> bool:
        if isinstance(node, ast.Name):
            return node.id in names
        if isinstance(
            node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            # Filtering or mapping one source produces at most one output per
            # source item. Additional generators can multiply the work.
            return (
                len(node.generators) == 1
                and not node.generators[0].is_async
                and self._is_partition_expression(node.generators[0].iter, names)
            )
        if isinstance(node, ast.IfExp):
            return self._is_partition_expression(
                node.body, names
            ) and self._is_partition_expression(node.orelse, names)
        if not isinstance(node, ast.Call) or node.keywords:
            return False
        if (
            isinstance(node.func, ast.Name)
            and node.func.id
            in {"list", "tuple", "set", "iter", "reversed", "sorted", "enumerate"}
            and self._is_builtin(node, node.func.id)
            and len(node.args) == 1
        ):
            return self._is_partition_expression(node.args[0], names)
        return (
            self._is_stdlib_callable(node.func, "itertools", "chain")
            and bool(node.args)
            and all(self._is_partition_expression(arg, names) for arg in node.args)
        )

    def _partition_effects(self, node: ast.AST, names: set[str]) -> set[str]:
        # Proven wrappers read their source rather than extending it. Other
        # calls may mutate passed collections, including a callback supplied
        # by the caller; an escaped mutable alias loses its partition proof.
        pure_calls = {
            child
            for child in ast.walk(node)
            if isinstance(child, ast.Call)
            and (
                self._is_partition_expression(child, names)
                or self._is_builtin_type_check(child)
            )
        }
        bindings = _ScopeBindings(track_mutations=True, ignored_calls=pure_calls)
        bindings.visit(node)
        # _ScopeBindings omits comprehension-local bindings. Calls in their
        # evaluated expressions still matter to the enclosing collections.
        for expression in ast.walk(node):
            if isinstance(
                expression, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
            ):
                for child in ast.walk(expression):
                    if isinstance(child, ast.Call):
                        bindings.visit(child)
        return names - bindings.names

    def _is_builtin_type_check(self, node: ast.Call) -> bool:
        if not (
            isinstance(node.func, ast.Name)
            and node.func.id == "isinstance"
            and self._is_builtin(node, "isinstance")
            and len(node.args) == 2
            and not node.keywords
        ):
            return False
        classes = (
            node.args[1].elts if isinstance(node.args[1], ast.Tuple) else [node.args[1]]
        )
        return all(
            isinstance(cls, ast.Name)
            and cls.id
            in {
                "list",
                "tuple",
                "dict",
                "set",
                "frozenset",
                "str",
                "bytes",
                "int",
                "float",
                "bool",
            }
            and self._is_builtin(cls, cls.id)
            for cls in classes
        )

    def _partition_names_before(self, outer: ast.For, inner: ast.For) -> set[str]:
        """Propagate bounded aliases and intersect alternative control paths."""
        ancestors = set()
        current = inner
        while current in self._parents and current is not outer:
            current = self._parents[current]
            ancestors.add(current)

        # Track explicit shared-object aliases. Mutating a mapping key does
        # not invalidate a separately yielded value, while passing a direct
        # alias to a callback invalidates both names for that object.
        aliases = []
        for statement in ast.walk(outer):
            if getattr(statement, "lineno", inner.lineno) >= inner.lineno:
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                sources = [value] if isinstance(value, ast.Name) else []
                if isinstance(value, ast.GeneratorExp) and len(value.generators) == 1:
                    sources = [value.generators[0].iter]
                elif isinstance(value, ast.Call) and (
                    (
                        isinstance(value.func, ast.Name)
                        and value.func.id in {"iter", "enumerate", "reversed"}
                        and self._is_builtin(value, value.func.id)
                    )
                    or self._is_stdlib_callable(value.func, "itertools", "chain")
                ):
                    sources = value.args
                targets = (
                    statement.targets
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
                aliases.extend(
                    (target.id, source.id)
                    for target in targets
                    if isinstance(target, ast.Name)
                    for source in sources
                    if isinstance(source, ast.Name)
                )

        def effects(expression, names):
            changed = names - self._partition_effects(expression, names)
            while True:
                expanded = changed | {
                    right if left in changed else left
                    for left, right in aliases
                    if left in changed or right in changed
                }
                if expanded == changed:
                    return names - changed
                changed = expanded

        def transfer(body, names):
            names = set(names)
            for statement in body:
                if statement is inner:
                    return names
                if isinstance(statement, ast.If):
                    names = effects(statement.test, names)
                    if statement in ancestors:
                        branch = (
                            statement.body
                            if any(
                                child is inner or child in ancestors
                                for child in statement.body
                            )
                            else statement.orelse
                        )
                        return transfer(branch, names)
                    names = transfer(statement.body, names) & transfer(
                        statement.orelse, names
                    )
                    continue
                if statement in ancestors:
                    if isinstance(statement, (ast.With, ast.AsyncWith)):
                        for item in statement.items:
                            names = effects(item.context_expr, names)
                            if item.optional_vars is not None:
                                names -= _target_names(item.optional_vars)
                        return transfer(statement.body, names)
                    # Try/finally and intervening loops need their own flow
                    # model; they do not inherit an unproven alias fact.
                    return set()
                if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                    value = statement.value
                    if value is None:
                        continue
                    names = effects(value, names)
                    partition = self._is_partition_expression(value, names)
                    targets = (
                        statement.targets
                        if isinstance(statement, ast.Assign)
                        else [statement.target]
                    )
                    for target in targets:
                        names -= _target_names(target)
                    if partition:
                        names.update(
                            target.id
                            for target in targets
                            if isinstance(target, ast.Name)
                        )
                else:
                    names = effects(statement, names)
            return names

        return transfer(
            outer.body, _os_walk_partition_names(outer) or _target_names(outer.target)
        )

    def _is_stdlib_callable(self, node: ast.AST, module: str, symbol: str) -> bool:
        """Resolve an explicit import, rejecting shadowing and unknown bindings."""
        if isinstance(node, ast.Name):
            name, expected = node.id, f"{module}.{symbol}"
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.attr == symbol
        ):
            name, expected = node.value.id, module
        else:
            return False
        if name in self._global_writes:
            return False
        current, in_function = node, False
        while current in self._parents:
            current = self._parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                in_function = True
                args = current.args
                parameters = [
                    *args.posonlyargs,
                    *args.args,
                    *args.kwonlyargs,
                    args.vararg,
                    args.kwarg,
                ]
                if any(arg is not None and arg.arg == name for arg in parameters):
                    return False
            if isinstance(current, ast.ClassDef) and in_function:
                continue
            if not isinstance(
                current,
                (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue
            matches = []
            other = _ScopeBindings()
            for statement in current.body:
                resolved = None
                if isinstance(statement, ast.ImportFrom) and not statement.level:
                    for alias in statement.names:
                        if (alias.asname or alias.name) == name:
                            resolved = f"{statement.module}.{alias.name}"
                elif isinstance(statement, ast.Import):
                    for alias in statement.names:
                        if (alias.asname or alias.name.split(".")[0]) == name:
                            resolved = alias.name
                if resolved is not None:
                    matches.append(resolved)
                else:
                    other.visit(statement)
            if name in other.names or "*" in other.names:
                return False
            if matches:
                return matches == [expected]
        return False

    def _iterator_origin(self, node: ast.AST, seen=None) -> ast.AST | None:
        """Find an explicitly created single-pass iterator, following aliases.

        Merely iterating the same collection twice is not evidence: lists,
        ranges and mappings restart. Builtin iterator producers and generator
        expressions instead retain their position between the two loops.
        """
        seen = set() if seen is None else seen
        if isinstance(node, ast.Name):
            if node.id in seen or len(seen) >= 8:
                return None
            value = self._preceding_value(node, node.id)
            if value is not None:
                return self._iterator_origin(value, seen | {node.id})
            return None
        if isinstance(node, ast.GeneratorExp):
            return node
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and self._is_builtin(node, node.func.id)
            and node.func.id
            in {"iter", "enumerate", "reversed", "zip", "map", "filter"}
        ):
            return node
        return None

    def _consumes_shared_iterator(self, outer: ast.For, inner: ast.For) -> bool:
        origin = self._iterator_origin(outer.iter)
        if origin is None:
            return False
        iterator = inner.iter
        # A materializing wrapper also consumes the remaining iterator once.
        while (
            isinstance(iterator, ast.Call)
            and isinstance(iterator.func, ast.Name)
            and iterator.func.id
            in {"list", "tuple", "set", "sorted", "iter", "enumerate"}
            and self._is_builtin(iterator, iterator.func.id)
            and len(iterator.args) == 1
            and not iterator.keywords
        ):
            iterator = iterator.args[0]
        if self._iterator_origin(iterator) is not origin:
            return False
        source_names = {
            node.id
            for node in ast.walk(origin)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        }
        if isinstance(outer.iter, ast.Name):
            source_names.add(outer.iter.id)
        # A list iterator has retained position but can still run forever if
        # the body grows its backing list. Single-pass is not a bound then.
        return not self._iteration_sources_mutated(outer, source_names)

    def _nearest_loop(self, node: ast.AST) -> ast.AST | None:
        while node in self._parents:
            node = self._parents[node]
            if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                return node
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                break
        return None

    def _block_outcomes(self, body: list[ast.stmt], loop: ast.For) -> set[str]:
        """Normal control-flow outcomes, with break/continue relative to a loop."""
        outcomes = {"normal"}
        for statement in body:
            if "normal" not in outcomes:
                break
            outcomes.remove("normal")
            outcomes.update(self._statement_outcomes(statement, loop))
        return outcomes

    def _statement_outcomes(self, node: ast.stmt, loop: ast.For) -> set[str]:
        if isinstance(node, ast.Return):
            return {"return"}
        if isinstance(node, ast.Raise):
            return {"raise"}
        if isinstance(node, (ast.Break, ast.Continue)):
            if self._nearest_loop(node) is loop:
                return {"break" if isinstance(node, ast.Break) else "continue"}
            return {"normal"}
        if isinstance(node, ast.If):
            return self._block_outcomes(node.body, loop) | self._block_outcomes(
                node.orelse, loop
            )
        if isinstance(node, (ast.With, ast.AsyncWith)):
            outcomes = self._block_outcomes(node.body, loop)
            if "raise" in outcomes:
                outcomes.add("normal")  # __exit__ may suppress the exception.
            return outcomes
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            # A nested loop may execute zero times or run to completion.
            return (
                {"normal"}
                | self._block_outcomes(node.body, loop)
                | self._block_outcomes(node.orelse, loop)
            )
        if isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            outcomes = self._block_outcomes(node.body, loop)
            if "normal" in outcomes:
                outcomes.remove("normal")
                outcomes.update(self._block_outcomes(node.orelse, loop))
            # Calls in the try body may enter any handler, even without an
            # explicit raise. Do not prove an exit from its happy path alone.
            for handler in node.handlers:
                outcomes.update(self._block_outcomes(handler.body, loop))
            final = self._block_outcomes(node.finalbody, loop)
            return (outcomes if "normal" in final else set()) | (final - {"normal"})
        if isinstance(node, ast.Match):
            outcomes = {"normal"}
            for case in node.cases:
                outcomes.update(self._block_outcomes(case.body, loop))
            return outcomes
        return {"normal"}

    def _leaves_outer_after_scan(self, outer: ast.For, inner: ast.For) -> bool:
        """The nested scan can complete only once before the outer loop exits."""
        path = []
        current = inner
        while current in self._parents:
            parent = self._parents[current]
            path.append((current, parent))
            if parent is outer:
                break
            # A handler/finally can retry or replace an exit. An intervening
            # input-dependent loop can repeat the scan before its own exit.
            if isinstance(parent, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                # The try's handlers do not catch exceptions from one another,
                # and without finally they cannot replace a handler's break.
                if parent.finalbody or not (
                    isinstance(current, ast.ExceptHandler) or current in parent.orelse
                ):
                    return False
            if isinstance(parent, ast.While):
                return False
            if isinstance(
                parent, (ast.For, ast.AsyncFor)
            ) and not self._constant_iteration_count(parent.iter):
                return False
            current = parent
        else:
            return False
        outcomes = {"normal"}
        for current, parent in path:
            for field in ("body", "orelse", "finalbody"):
                body = getattr(parent, field, None)
                if isinstance(body, list) and current in body and "normal" in outcomes:
                    outcomes.remove("normal")
                    outcomes.update(
                        self._block_outcomes(body[body.index(current) + 1 :], outer)
                    )
                    break
            if outcomes and outcomes <= {"return", "break"}:
                return True
        return False

    def _is_repeated_scan(self, outer: ast.For, inner: ast.For) -> bool:
        return not (
            self._constant_iteration_count(outer.iter)
            or self._constant_iteration_count(inner.iter)
            or self._walks_outer_partition(outer, inner)
            or self._consumes_shared_iterator(outer, inner)
            or self._leaves_outer_after_scan(outer, inner)
            or self._block_outcomes(inner.body, inner) <= {"break", "return"}
        )

    def _is_pandas_read(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "read_csv":
            return True
        return False

    def _find_nested_loops(self, outer: ast.For, body: list[ast.stmt]) -> list[ast.For]:
        findings_list = []
        for child in body:
            if isinstance(child, ast.For):
                if self._is_repeated_scan(outer, child):
                    findings_list.append(child)
                elif self._constant_iteration_count(child.iter):
                    # A fixed wrapper does not hide a repeated scan further
                    # inside: rows -> range(2) -> rows is still quadratic.
                    findings_list.extend(self._find_nested_loops(outer, child.body))
                if child.orelse:
                    findings_list.extend(self._find_nested_loops(outer, child.orelse))
            elif isinstance(child, ast.If):
                findings_list.extend(self._find_nested_loops(outer, child.body))
                if child.orelse:
                    findings_list.extend(self._find_nested_loops(outer, child.orelse))
            elif isinstance(child, ast.With):
                findings_list.extend(self._find_nested_loops(outer, child.body))
            elif isinstance(child, ast.Try):
                findings_list.extend(self._find_nested_loops(outer, child.body))
                for handler in child.handlers:
                    findings_list.extend(self._find_nested_loops(outer, handler.body))
                if child.orelse:
                    findings_list.extend(self._find_nested_loops(outer, child.orelse))
                if child.finalbody:
                    findings_list.extend(
                        self._find_nested_loops(outer, child.finalbody)
                    )
        return findings_list

    def visit_node(self, node, context):
        findings = []

        if isinstance(node, ast.Module):
            self._parents = {
                child: parent
                for parent in ast.walk(node)
                for child in ast.iter_child_nodes(parent)
            }
            self._global_writes = set()
            for scope in ast.walk(node):
                if isinstance(
                    scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    bindings = _ScopeBindings()
                    for statement in scope.body:
                        bindings.visit(statement)
                    self._global_writes.update(bindings.global_names & bindings.names)
            return None

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in (
                "read",
                "readlines",
            ):
                if "SKY-P401" not in self.ignore_list:
                    if _is_file_read_context(node) and not _is_bounded_read(node):
                        findings.append(
                            {
                                "rule_id": "SKY-P401",
                                "kind": "performance",
                                "severity": "LOW",
                                "type": "function",
                                "name": node.func.attr,
                                "simple_name": node.func.attr,
                                "value": "memory_load",
                                "threshold": 0,
                                "message": f"Potential Memory Risk: '{node.func.attr}()' loads entire file into RAM. Consider iterating line-by-line for large files.",
                                "file": context.get("filename"),
                                "basename": Path(context.get("filename", "")).name,
                                "line": node.lineno,
                                "col": node.col_offset,
                            }
                        )

            if self._is_pandas_read(node):
                if "SKY-P402" not in self.ignore_list:
                    has_chunk = False
                    for kw in node.keywords:
                        if kw.arg == "chunksize":
                            has_chunk = True
                            break

                    if not has_chunk:
                        findings.append(
                            {
                                "rule_id": "SKY-P402",
                                "kind": "performance",
                                "severity": "LOW",
                                "type": "function",
                                "name": "read_csv",
                                "simple_name": "read_csv",
                                "value": "no_chunk",
                                "threshold": 0,
                                "message": "Pandas Memory Risk: read_csv used without 'chunksize'. Large files may crash RAM.",
                                "file": context.get("filename"),
                                "basename": Path(context.get("filename", "")).name,
                                "line": node.lineno,
                                "col": node.col_offset,
                            }
                        )

            if _is_unbounded_orm_all(node):
                if "SKY-P404" not in self.ignore_list:
                    findings.append(
                        {
                            "rule_id": "SKY-P404",
                            "kind": "performance",
                            "severity": "MEDIUM",
                            "type": "function",
                            "name": "all",
                            "simple_name": "all",
                            "value": "unbounded_query",
                            "threshold": 0,
                            "message": "Unbounded ORM .all() call may load an entire table. Add a limit, pagination, or streaming boundary.",
                            "file": context.get("filename"),
                            "basename": Path(context.get("filename", "")).name,
                            "line": node.lineno,
                            "col": node.col_offset,
                        }
                    )

        if isinstance(node, ast.For):
            if "SKY-P403" not in self.ignore_list:
                suspect_loops = self._find_nested_loops(node, node.body)
                for inner_loop in suspect_loops:
                    findings.append(
                        {
                            "rule_id": "SKY-P403",
                            "kind": "performance",
                            "severity": "LOW",
                            "type": "loop",
                            "name": "nested_loop",
                            "simple_name": "for",
                            "value": "repeated_scan",
                            "threshold": 0,
                            "message": (
                                "Input-dependent nested iteration can repeat work for "
                                "each outer item. Work may scale with both iteration "
                                "counts; review whether all pairs are required."
                            ),
                            "evidence": {
                                "outer_iterable": ast.unparse(node.iter),
                                "inner_iterable": ast.unparse(inner_loop.iter),
                                "outer_line": node.lineno,
                                "bounded_iteration_proven": False,
                                "single_pass_consumption_proven": False,
                            },
                            "file": context.get("filename"),
                            "basename": Path(context.get("filename", "")).name,
                            "line": inner_loop.lineno,
                            "col": inner_loop.col_offset,
                        }
                    )

        return findings if findings else None
