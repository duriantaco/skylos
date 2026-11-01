"""Intra-function value facts with sound branch joins.

``ValueFlow`` walks one function (or module) body in execution order and keeps,
for each local name, the union of the labels its possible values carry. The
joins follow the branch handling of ``danger_redirect/redirect_flow.py``:
if/elif/else and match cases join every branch that continues; loops join the
zero-iteration path, the end of the body and every ``continue``, and leave
through the normal exit or a ``break``; a ``with`` body may be cut short by a
suppressed exception; ``try`` handlers start from every state the body could
raise in, and ``finally`` sees normal, exceptional and abrupt
(return/raise/break/continue) paths. Loops are iterated to a fixed point and
widened to ``top`` when they do not settle. ``+=`` reads the old value, and a
store into a container adds the stored value to the container; a literal key
of a dict display stays precise until the dict is changed in a way that is
not tracked.

The client turns expressions into labels (``evaluate``) and says what a name
bound outside the scope may hold (``outer``) and what an unknown value is
(``top``). Work is bounded: a run that exceeds its budget returns None.
"""

from __future__ import annotations

import ast

MAX_STEPS = 60000
MAX_LOOP_PASSES = 5

_READ_ONLY_METHODS = frozenset(
    {
        "__contains__",
        "capitalize",
        "casefold",
        "copy",
        "count",
        "decode",
        "encode",
        "endswith",
        "find",
        "format",
        "get",
        "hex",
        "index",
        "isalnum",
        "isalpha",
        "isdigit",
        "islower",
        "isupper",
        "items",
        "join",
        "keys",
        "lower",
        "lstrip",
        "replace",
        "rfind",
        "rsplit",
        "rstrip",
        "split",
        "splitlines",
        "startswith",
        "strip",
        "title",
        "upper",
        "values",
    }
)

_TRY_NODES = tuple(
    node for node in (ast.Try, getattr(ast, "TryStar", None)) if node is not None
)


class FlowBudgetExceeded(Exception):
    """The run needed more work than its budget allows."""


def _literal_key(node: ast.AST):
    if isinstance(node, ast.Constant) and isinstance(
        node.value, (str, bytes, int, bool, type(None))
    ):
        return True, node.value
    return False, None


def _irrefutable(pattern: ast.AST) -> bool:
    if isinstance(pattern, ast.MatchAs):
        return pattern.pattern is None or _irrefutable(pattern.pattern)
    if isinstance(pattern, ast.MatchOr):
        return any(_irrefutable(item) for item in pattern.patterns)
    return False


def _root_name(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred)):
        node = node.value
    if isinstance(node, ast.Name):
        return node.id
    return None


def _skip_nested(node: ast.AST) -> bool:
    return isinstance(
        node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
    )


def _scope_children(node: ast.AST):
    """Nodes of ``node`` outside nested function, lambda and class bodies;
    nested definitions themselves are yielded."""
    pending = list(ast.iter_child_nodes(node))
    while pending:
        current = pending.pop()
        yield current
        if not _skip_nested(current):
            pending.extend(ast.iter_child_nodes(current))


def _pattern_names(pattern: ast.AST) -> list[str]:
    names = []
    for part in ast.walk(pattern):
        if isinstance(part, (ast.MatchAs, ast.MatchStar)) and part.name:
            names.append(part.name)
        elif isinstance(part, ast.MatchMapping) and part.rest:
            names.append(part.rest)
    return names


def _written_names(node: ast.AST) -> set[str]:
    """Names a statement can rebind or mutate, outside nested scopes."""
    written = set()
    for part in [node, *_scope_children(node)]:
        if isinstance(part, ast.Name) and isinstance(part.ctx, (ast.Store, ast.Del)):
            written.add(part.id)
        elif isinstance(part, (ast.Attribute, ast.Subscript)) and isinstance(
            part.ctx, (ast.Store, ast.Del)
        ):
            root = _root_name(part)
            if root:
                written.add(root)
        elif isinstance(part, ast.Call) and isinstance(part.func, ast.Attribute):
            root = _root_name(part.func.value)
            if root:
                written.add(root)
        elif isinstance(part, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            written.add(part.name)
        elif isinstance(part, (ast.Import, ast.ImportFrom)):
            for alias in part.names:
                written.add(alias.asname or alias.name.split(".", 1)[0])
        elif isinstance(part, ast.ExceptHandler) and part.name:
            written.add(part.name)
        elif isinstance(part, ast.match_case):
            written.update(_pattern_names(part.pattern))
    return written


def _scope_bindings(scope: ast.AST) -> tuple[frozenset[str], frozenset[str]]:
    """``(locals, declared)``: names bound in a function scope, and names it
    declares ``global`` or ``nonlocal``. Comprehension targets are their own
    scope; walrus targets inside comprehensions bind in the function."""
    bound = set()
    declared = set()
    comprehension_targets = set()
    for part in _scope_children(scope):
        if isinstance(part, ast.comprehension):
            for target in ast.walk(part.target):
                comprehension_targets.add(id(target))
    for part in _scope_children(scope):
        if isinstance(part, (ast.Global, ast.Nonlocal)):
            declared.update(part.names)
        elif isinstance(part, ast.Name) and isinstance(part.ctx, (ast.Store, ast.Del)):
            if id(part) not in comprehension_targets:
                bound.add(part.id)
        elif isinstance(part, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(part.name)
        elif isinstance(part, (ast.Import, ast.ImportFrom)):
            for alias in part.names:
                bound.add(alias.asname or alias.name.split(".", 1)[0])
        elif isinstance(part, ast.ExceptHandler) and part.name:
            bound.add(part.name)
        elif isinstance(part, ast.match_case):
            bound.update(_pattern_names(part.pattern))
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        arguments = scope.args
        for argument in [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            arguments.vararg,
            arguments.kwarg,
        ]:
            if argument is not None:
                bound.add(argument.arg)
    return frozenset(bound - declared), frozenset(declared)


class _State:
    __slots__ = ("names", "items", "displays")

    def __init__(self, names=None, items=None, displays=frozenset()):
        self.names = {}
        self.items = {}
        if names is not None:
            self.names = names
        if items is not None:
            self.items = items
        self.displays = displays

    def copy(self):
        return _State(dict(self.names), dict(self.items), self.displays)

    def same(self, other) -> bool:
        return (
            self.names == other.names
            and self.items == other.items
            and self.displays == other.displays
        )

    def forget(self, name: str) -> None:
        for key in [key for key in self.items if key[0] == name]:
            del self.items[key]


class _Join:
    """States reaching one program point, merged as they arrive."""

    __slots__ = ("state", "count")

    def __init__(self):
        self.state = None
        self.count = 0

    def add(self, flow, state) -> None:
        self.count += 1
        if self.state is None:
            self.state = state.copy()
            return
        self.state = flow.merge([self.state, state])


class ValueFlow:
    """Labels of chosen expressions in one scope, over every path.

    ``evaluate(node, value)`` returns the labels of an expression the engine
    does not handle itself; ``value`` evaluates a child in the current state.
    The engine handles names, walrus, ``IfExp``, ``BoolOp``, comprehensions,
    lambdas and reads of a literal key from a tracked dict display.
    ``outer(name)`` gives the labels of a name bound outside the scope;
    ``top`` the labels of an unknown value (parameters, exception objects,
    imports, nested definitions, widened loop names). ``element(labels)``
    gives the labels of items iterated or unpacked from a value. ``collect``
    gives the labels of a comprehension from its element labels. ``read``
    may adjust the labels of a name read in this scope and ``read_item`` those
    of a precise per-key fact. Aliases are not tracked: names in ``opaque``
    (aliased, escaped or shared with nested scopes) never keep per-key facts.
    """

    def __init__(
        self,
        scope,
        evaluate,
        *,
        outer,
        top,
        element=None,
        collect=None,
        read=None,
        read_item=None,
        opaque=frozenset(),
        max_steps=MAX_STEPS,
    ):
        self.scope = scope
        self._evaluate = evaluate
        self._outer = outer
        self.top = frozenset(top)
        self._element = element
        self._collect = collect
        self._read = read
        self._read_item = read_item
        self._opaque = frozenset(opaque)
        self._max_steps = max_steps
        self._steps = 0
        self._function = isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
        if self._function:
            self._locals, self._declared = _scope_bindings(scope)
        else:
            self._locals, self._declared = frozenset(), frozenset()
        self.state = _State()
        self._overlays = []
        self._handlers = []
        self._finals = []
        self._loops = []
        self._watched = frozenset()
        self._results = {}

    def run(self, watched) -> dict[int, frozenset] | None:
        """Labels of each watched expression (by ``id``) over every path that
        reaches it; watched nodes on no reachable path are absent. None when
        the budget is exceeded."""
        self._watched = frozenset(id(node) for node in watched)
        self._results = {}
        self._steps = 0
        self.state = _State()
        try:
            if self._function:
                arguments = self.scope.args
                for argument in [
                    *arguments.posonlyargs,
                    *arguments.args,
                    *arguments.kwonlyargs,
                    arguments.vararg,
                    arguments.kwarg,
                ]:
                    if argument is not None and argument.arg not in self._declared:
                        self.state.names[argument.arg] = self.top
            self._block(self.scope.body)
        except (FlowBudgetExceeded, RecursionError):
            return None
        return self._results

    def _tick(self, amount: int = 1) -> None:
        self._steps += amount
        if self._steps > self._max_steps:
            raise FlowBudgetExceeded

    def _absent(self, name: str) -> frozenset:
        if self._function and name in self._locals:
            return frozenset()
        return frozenset(self._outer(name))

    def merge(self, states):
        states = [state for state in states if state is not None]
        if not states:
            return _State()
        if len(states) == 1:
            return states[0].copy()
        names = {}
        every = set()
        for state in states:
            every.update(state.names)
        self._tick(len(every) + 1)
        for name in every:
            labels = frozenset()
            for state in states:
                if name in state.names:
                    labels |= state.names[name]
                else:
                    labels |= self._absent(name)
            names[name] = labels
        displays = states[0].displays
        for state in states[1:]:
            displays &= state.displays
        items = {}
        for key, labels in states[0].items.items():
            if key[0] not in displays:
                continue
            if all(key in state.items for state in states[1:]):
                for state in states[1:]:
                    labels |= state.items[key]
                items[key] = labels
        return _State(names, items, displays)

    def _current(self, name: str) -> frozenset:
        if name in self.state.names:
            return self.state.names[name]
        return self._absent(name)

    def _name(self, name: str) -> frozenset:
        for overlay in reversed(self._overlays):
            if name in overlay:
                return overlay[name]
        if name in self._declared:
            labels = frozenset(self._outer(name))
        else:
            labels = self._current(name)
        if self._read is not None:
            labels = frozenset(self._read(name, labels))
        return labels

    def _elements(self, labels: frozenset) -> frozenset:
        if self._element is None:
            return labels
        return frozenset(self._element(labels))

    def _item(self, name: str, key_node: ast.AST):
        if name in self._opaque or name in self._declared:
            return None
        if any(name in overlay for overlay in self._overlays):
            return None
        if name not in self.state.displays:
            return None
        known, key = _literal_key(key_node)
        if not known:
            return None
        fact = self.state.items.get((name, key))
        if fact is None or self._read_item is None:
            return fact
        return frozenset(self._read_item(name, fact))

    def value(self, node: ast.AST | None) -> frozenset:
        """Labels of ``node`` in the current state."""
        self._tick()
        if node is None:
            return frozenset()
        if isinstance(node, ast.Name):
            return self._name(node.id)
        if isinstance(node, ast.NamedExpr):
            return self.value(node.value)
        if isinstance(node, ast.IfExp):
            return self.value(node.body) | self.value(node.orelse)
        if isinstance(node, ast.BoolOp):
            labels = frozenset()
            for item in node.values:
                labels |= self.value(item)
            return labels
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and isinstance(node.ctx, ast.Load)
        ):
            fact = self._item(node.value.id, node.slice)
            if fact is not None:
                return fact
        if isinstance(
            node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
        ):
            return self._comprehension_value(node)
        if isinstance(node, ast.Lambda):
            return self.top
        return frozenset(self._evaluate(node, self.value))

    def _comprehension_value(self, node) -> frozenset:
        overlay = {}
        self._overlays.append(overlay)
        try:
            for generator in node.generators:
                elements = self._elements(self.value(generator.iter))
                self._bind_overlay(generator.target, elements, overlay)
            if isinstance(node, ast.DictComp):
                labels = self.value(node.key) | self.value(node.value)
            else:
                labels = self.value(node.elt)
        finally:
            self._overlays.pop()
        if self._collect is None:
            return labels
        return frozenset(self._collect(node, labels))

    def _bind_overlay(self, target, labels, overlay) -> None:
        if isinstance(target, ast.Name):
            overlay[target.id] = labels
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._bind_overlay(item, self._elements(labels), overlay)
        elif isinstance(target, ast.Starred):
            self._bind_overlay(target.value, labels | self.top, overlay)

    def _record(self, node) -> None:
        labels = self.value(node)
        self._results[id(node)] = self._results.get(id(node), frozenset()) | labels

    def _record_unknown(self, node) -> None:
        for part in ast.walk(node):
            if id(part) in self._watched:
                self._results[id(part)] = (
                    self._results.get(id(part), frozenset()) | self.top
                )

    def _note_exception_point(self) -> None:
        for join in self._handlers:
            join.add(self, self.state)
        for join in self._finals:
            join.add(self, self.state)

    def _bind(self, name: str, labels: frozenset) -> None:
        if name in self._declared:
            return
        self.state.names[name] = frozenset(labels)
        self.state.forget(name)
        self.state.displays = self.state.displays - {name}

    def _weak(self, name: str, labels: frozenset) -> None:
        if name in self._declared:
            return
        self.state.names[name] = self._current(name) | labels
        self.state.forget(name)

    def _bind_walrus(self, name: str, labels: frozenset, conditional: bool) -> None:
        if conditional:
            self._weak(name, labels)
            self.state.displays = self.state.displays - {name}
        else:
            self._bind(name, labels)
        if self._handlers or self._finals:
            self._note_exception_point()

    def _effects(self, node, conditional: bool = False) -> None:
        """Walk an expression in evaluation order: apply walrus bindings and
        receiver mutations, and record watched expressions."""
        if node is None:
            return
        self._tick()
        if isinstance(node, ast.NamedExpr):
            self._effects(node.value, conditional)
            self._bind_walrus(node.target.id, self.value(node.value), conditional)
        elif isinstance(node, ast.BoolOp):
            self._effects(node.values[0], conditional)
            for item in node.values[1:]:
                self._effects(item, True)
        elif isinstance(node, ast.IfExp):
            self._effects(node.test, conditional)
            self._effects(node.body, True)
            self._effects(node.orelse, True)
        elif isinstance(
            node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
        ):
            self._comprehension_effects(node, conditional)
        elif isinstance(node, ast.Lambda):
            for default in [*node.args.defaults, *node.args.kw_defaults]:
                self._effects(default, conditional)
            self._record_unknown(node.body)
        elif isinstance(node, ast.Call):
            self._effects(node.func, conditional)
            for argument in node.args:
                self._effects(argument, conditional)
            for keyword in node.keywords:
                self._effects(keyword.value, conditional)
            self._call_mutation(node)
        else:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.expr, ast.keyword)):
                    self._effects(child, conditional)
        if id(node) in self._watched:
            self._record(node)

    def _comprehension_effects(self, node, conditional: bool) -> None:
        generators = node.generators
        self._effects(generators[0].iter, conditional)
        overlay = {}
        self._overlays.append(overlay)
        try:
            for index, generator in enumerate(generators):
                if index:
                    self._effects(generator.iter, True)
                elements = self._elements(self.value(generator.iter))
                self._bind_overlay(generator.target, elements, overlay)
                for condition in generator.ifs:
                    self._effects(condition, True)
            if isinstance(node, ast.DictComp):
                self._effects(node.key, True)
                self._effects(node.value, True)
            else:
                self._effects(node.elt, True)
        finally:
            self._overlays.pop()

    def _call_mutation(self, node: ast.Call) -> None:
        """``receiver.method(args)`` may store its arguments in the receiver."""
        if not isinstance(node.func, ast.Attribute):
            return
        if node.func.attr in _READ_ONLY_METHODS:
            return
        root = _root_name(node.func.value)
        if root is None or any(root in overlay for overlay in self._overlays):
            return
        labels = frozenset()
        for argument in node.args:
            labels |= self.value(argument)
        for keyword in node.keywords:
            labels |= self.value(keyword.value)
        self._weak(root, labels)

    def _target_effects(self, target) -> None:
        if isinstance(target, (ast.Attribute, ast.Subscript)):
            self._effects(target.value)
            if isinstance(target, ast.Subscript):
                self._effects(target.slice)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._target_effects(item)
        elif isinstance(target, ast.Starred):
            self._target_effects(target.value)

    def _assign(self, target, labels: frozenset, value_node=None) -> None:
        if isinstance(target, ast.Name):
            self._bind(target.id, labels)
            if isinstance(value_node, ast.Dict) and target.id not in self._declared:
                self._track_display(target.id, value_node)
        elif isinstance(target, (ast.Tuple, ast.List)):
            values = None
            if (
                isinstance(value_node, (ast.Tuple, ast.List))
                and len(value_node.elts) == len(target.elts)
                and not any(
                    isinstance(item, ast.Starred)
                    for item in [*target.elts, *value_node.elts]
                )
            ):
                values = value_node.elts
            for index, item in enumerate(target.elts):
                if values is not None:
                    self._assign(item, self.value(values[index]), values[index])
                elif isinstance(item, ast.Starred):
                    self._assign(item.value, self._elements(labels) | self.top)
                else:
                    self._assign(item, self._elements(labels))
        elif isinstance(target, ast.Subscript):
            self._store_item(target, labels)
        elif isinstance(target, ast.Attribute):
            root = _root_name(target.value)
            if root is not None:
                self._weak(root, labels)
        elif isinstance(target, ast.Starred):
            self._assign(target.value, self._elements(labels) | self.top)

    def _track_display(self, name: str, display: ast.Dict) -> None:
        if name in self._opaque or any(key is None for key in display.keys):
            return
        facts = {}
        for key, item in zip(display.keys, display.values):
            known, literal = _literal_key(key)
            if not known:
                return
            facts[(name, literal)] = self.value(item)
        self.state.items.update(facts)
        self.state.displays = self.state.displays | {name}

    def _store_item(self, target: ast.Subscript, labels: frozenset) -> None:
        if not isinstance(target.value, ast.Name):
            root = _root_name(target.value)
            if root is not None:
                self._weak(root, labels)
            return
        name = target.value.id
        if name in self._declared:
            return
        tracked = name in self.state.displays
        self.state.names[name] = self._current(name) | labels
        known, key = _literal_key(target.slice)
        if tracked and known:
            self.state.items[(name, key)] = labels
        else:
            self.state.forget(name)

    def _block(self, statements) -> bool:
        """Visit statements; whether a path reaches the end of the block."""
        for statement in statements:
            self._tick()
            continues = self._statement(statement)
            if self._handlers or self._finals:
                self._note_exception_point()
            if continues is False:
                return False
        return True

    def _statement(self, node) -> bool:
        if isinstance(node, ast.Expr):
            self._effects(node.value)
            return True
        if isinstance(node, ast.Assign):
            self._effects(node.value)
            labels = self.value(node.value)
            for target in node.targets:
                self._target_effects(target)
                self._assign(target, labels, node.value)
            return True
        if isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self._effects(node.value)
                self._target_effects(node.target)
                self._assign(node.target, self.value(node.value), node.value)
            return True
        if isinstance(node, ast.AugAssign):
            return self._augmented(node)
        if isinstance(node, ast.Delete):
            for target in node.targets:
                self._delete(target)
            return True
        if isinstance(node, ast.Return):
            self._effects(node.value)
            self._note_exception_point()
            return False
        if isinstance(node, ast.Raise):
            self._effects(node.exc)
            self._effects(node.cause)
            self._note_exception_point()
            return False
        if isinstance(node, (ast.Break, ast.Continue)):
            if self._loops:
                breaks, continues = self._loops[-1]
                if isinstance(node, ast.Break):
                    breaks.add(self, self.state)
                else:
                    continues.add(self, self.state)
            self._note_exception_point()
            return False
        if isinstance(node, ast.If):
            return self._if(node)
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            return self._loop(node)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            return self._with(node)
        if _TRY_NODES and isinstance(node, _TRY_NODES):
            return self._try(node)
        if isinstance(node, ast.Match):
            return self._match(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for expression in [
                *node.decorator_list,
                *node.args.defaults,
                *node.args.kw_defaults,
            ]:
                self._effects(expression)
            self._bind(node.name, self.top)
            return True
        if isinstance(node, ast.ClassDef):
            for expression in [
                *node.decorator_list,
                *node.bases,
                *(keyword.value for keyword in node.keywords),
            ]:
                self._effects(expression)
            self._bind(node.name, self.top)
            return True
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name != "*":
                    self._bind(alias.asname or alias.name.split(".", 1)[0], self.top)
            return True
        if isinstance(node, (ast.Global, ast.Nonlocal, ast.Pass)):
            return True
        alias_node = getattr(ast, "TypeAlias", None)
        if alias_node is not None and isinstance(node, alias_node):
            if isinstance(node.name, ast.Name):
                self._bind(node.name.id, self.top)
            return True
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self._effects(child)
        return True

    def _augmented(self, node: ast.AugAssign) -> bool:
        self._effects(node.value)
        self._target_effects(node.target)
        target = node.target
        if isinstance(target, ast.Name):
            load = ast.Name(id=target.id, ctx=ast.Load())
        elif isinstance(target, ast.Subscript):
            load = ast.Subscript(value=target.value, slice=target.slice, ctx=ast.Load())
        else:
            load = ast.Attribute(value=target.value, attr=target.attr, ctx=ast.Load())
        combined = ast.BinOp(left=load, op=node.op, right=node.value)
        labels = self.value(combined)
        if isinstance(target, ast.Name):
            if target.id in self._declared:
                return True
            self.state.names[target.id] = labels
            self.state.forget(target.id)
        else:
            self._assign(target, labels)
        return True

    def _delete(self, target) -> None:
        if isinstance(target, ast.Name):
            if target.id in self._declared:
                return
            self.state.names.pop(target.id, None)
            self.state.forget(target.id)
            self.state.displays = self.state.displays - {target.id}
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            self._effects(target.slice)
            known, key = _literal_key(target.slice)
            if known:
                self.state.items.pop((target.value.id, key), None)
            else:
                self.state.forget(target.value.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._delete(item)
        else:
            self._target_effects(target)

    def _if(self, node: ast.If) -> bool:
        self._effects(node.test)
        entry = self.state.copy()
        arrivals = []
        for statements in (node.body, node.orelse):
            self.state = entry.copy()
            if self._block(statements):
                arrivals.append(self.state)
        if not arrivals:
            return False
        self.state = self.merge(arrivals)
        return True

    def _loop(self, node) -> bool:
        is_while = isinstance(node, ast.While)
        if not is_while:
            self._effects(node.iter)
        entry = self.state.copy()
        head = entry
        written = None
        widened = False
        passes = 0
        while True:
            passes += 1
            breaks = _Join()
            continues = _Join()
            self.state = head.copy()
            if is_while:
                self._effects(node.test)
                normal_exit = self.state.copy()
            else:
                normal_exit = head.copy()
                elements = self._elements(self.value(node.iter))
                self._target_effects(node.target)
                self._assign(node.target, elements)
            self._loops.append((breaks, continues))
            body_continues = self._block(node.body)
            self._loops.pop()
            arrivals = [entry]
            if body_continues:
                arrivals.append(self.state)
            if continues.state is not None:
                arrivals.append(continues.state)
            if widened:
                break
            grown = self.merge([head, *arrivals])
            if grown.same(head):
                break
            if passes >= MAX_LOOP_PASSES:
                if written is None:
                    written = _written_names(node)
                head = self._widen(grown, written)
                widened = True
                continue
            head = grown
        arrivals = []
        self.state = normal_exit
        if self._block(node.orelse):
            arrivals.append(self.state)
        if breaks.state is not None:
            arrivals.append(breaks.state)
        if not arrivals:
            return False
        self.state = self.merge(arrivals)
        return True

    def _widen(self, state, written) -> _State:
        widened = state.copy()
        for name in written:
            if name in self._declared:
                continue
            if name in widened.names:
                widened.names[name] = widened.names[name] | self.top
            else:
                widened.names[name] = self._absent(name) | self.top
            widened.forget(name)
        widened.displays = widened.displays - written
        return widened

    def _with(self, node) -> bool:
        for item in node.items:
            self._effects(item.context_expr)
            if item.optional_vars is not None:
                self._target_effects(item.optional_vars)
                self._assign(
                    item.optional_vars, self.value(item.context_expr) | self.top
                )
        suppressed = _Join()
        suppressed.add(self, self.state)
        self._handlers.append(suppressed)
        body_continues = self._block(node.body)
        self._handlers.pop()
        if body_continues:
            suppressed.add(self, self.state)
        self.state = suppressed.state.copy()
        return True

    def _marks(self):
        joins = [*self._handlers, *self._finals]
        for breaks, continues in self._loops:
            joins.extend((breaks, continues))
        return [(join, join.count) for join in joins]

    def _try(self, node) -> bool:
        raised = _Join()
        raised.add(self, self.state)
        finals = None
        marks = None
        if node.finalbody:
            marks = self._marks()
            finals = _Join()
            finals.add(self, self.state)
            self._finals.append(finals)
        self._handlers.append(raised)
        body_continues = self._block(node.body)
        self._handlers.pop()
        arrivals = []
        if body_continues and self._block(node.orelse):
            arrivals.append(self.state.copy())
        star = type(node).__name__ == "TryStar"
        handled = []
        for handler in node.handlers:
            self.state = self.merge([raised.state, *handled])
            self._effects(handler.type)
            if handler.name:
                self._bind(handler.name, self.top)
            if self._block(handler.body):
                arrivals.append(self.state.copy())
                if star:
                    handled.append(self.state.copy())
        if finals is None:
            if not arrivals:
                return False
            self.state = self.merge(arrivals)
            return True
        self._finals.pop()
        self.state = self.merge([*arrivals, finals.state, raised.state])
        if not self._block(node.finalbody):
            return False
        for join, count in marks:
            if join.count > count:
                join.add(self, self.state)
        return bool(arrivals)

    def _match(self, node: ast.Match) -> bool:
        self._effects(node.subject)
        subject = self.value(node.subject)
        entry = self.state.copy()
        arrivals = []
        falls_through = True
        for case in node.cases:
            self.state = entry.copy()
            self._bind_pattern(case.pattern, subject)
            if case.guard is not None:
                self._effects(case.guard)
            entry = self.merge([entry, self.state])
            if self._block(case.body):
                arrivals.append(self.state)
            if case.guard is None and _irrefutable(case.pattern):
                falls_through = False
                break
        if falls_through:
            arrivals.append(entry)
        if not arrivals:
            return False
        self.state = self.merge(arrivals)
        return True

    def _bind_pattern(self, pattern, subject: frozenset) -> None:
        roots = [pattern]
        if isinstance(pattern, ast.MatchOr):
            roots = list(pattern.patterns)
        direct = set()
        for root in roots:
            if isinstance(root, ast.MatchAs) and root.name:
                direct.add(id(root))
        nested = self._elements(subject) | self.top
        for part in ast.walk(pattern):
            if isinstance(part, (ast.MatchAs, ast.MatchStar)) and part.name:
                if id(part) in direct:
                    self._bind(part.name, subject)
                else:
                    self._bind(part.name, nested)
            elif isinstance(part, ast.MatchMapping) and part.rest:
                self._bind(part.rest, nested)
