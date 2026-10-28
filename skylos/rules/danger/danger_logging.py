"""Track proven credential values into Python console and logging output.

This is a local source-to-sink analysis. A variable called ``password`` is not
itself evidence: supported sources are credential-labelled environment reads,
credential prompts, and getpass. Container and string operations preserve the
source; literal replacement and projections onto public fields do not.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import re
import string

from .untrusted_sources import UntrustedSourceIndex


_SECRET_WORDS = re.compile(
    r"(?:^|[^a-z0-9])(?:password|passwd|secret|token|credential|credentials|"
    r"api[ _-]?key|private[ _-]?key|access[ _-]?key)(?:$|[^a-z0-9])",
    re.IGNORECASE,
)
_LOG_METHODS = {
    "debug",
    "info",
    "warning",
    "warn",
    "error",
    "exception",
    "critical",
    "fatal",
    "log",
}
_BUILTINS = {
    "print",
    "input",
    "str",
    "repr",
    "ascii",
    "list",
    "tuple",
    "set",
    "dict",
    "len",
    "bool",
}
_TRY_NODES = (ast.Try,) + ((ast.TryStar,) if hasattr(ast, "TryStar") else ())


@dataclass(frozen=True)
class _Value:
    sources: frozenset[str] = frozenset()
    api: str | None = None
    literal: str | int | None = None
    items: tuple[_Value, ...] | None = None
    pairs: tuple[tuple[str | int, _Value], ...] | None = None
    fields: tuple[tuple[str, _Value], ...] | None = None


_UNKNOWN = _Value()


def _combined(values):
    return _Value(sources=frozenset().union(*(v.sources for v in values)))


def _sequence(values):
    values = tuple(values)
    return _Value(sources=_combined(values).sources, items=values)


def _mapping(pairs):
    pairs = tuple(dict(pairs).items())
    return _Value(sources=_combined(v for _, v in pairs).sources, pairs=pairs)


def _joined(left, right):
    if left == right:
        return left
    if left.fields is not None or right.fields is not None:
        left_fields, right_fields = dict(left.fields or ()), dict(right.fields or ())
        left_unknown = _Value(sources=left.sources) if left.fields is None else _UNKNOWN
        right_unknown = (
            _Value(sources=right.sources) if right.fields is None else _UNKNOWN
        )
        fields = tuple(
            (
                name,
                _joined(
                    left_fields.get(name, left_unknown),
                    right_fields.get(name, right_unknown),
                ),
            )
            for name in sorted(left_fields.keys() | right_fields.keys())
        )
        return _Value(sources=left.sources | right.sources, fields=fields)
    return _Value(sources=left.sources | right.sources)


class _LocalNames(ast.NodeVisitor):
    def __init__(self):
        self.names = set()

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_Import(self, node):
        self.names.update(a.asname or a.name.split(".")[0] for a in node.names)

    def visit_ImportFrom(self, node):
        self.names.update(a.asname or a.name for a in node.names)

    def visit_FunctionDef(self, node):
        self.names.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef

    def visit_Lambda(self, node):
        pass


class _LoggingFlow:
    def __init__(self, filename, tree):
        self.filename = str(filename)
        self.values = {}
        self.symbol = "<module>"
        self.findings = {}
        self.imports = UntrustedSourceIndex(tree)
        self.function = None
        self._call_refs = []
        declared = _LocalNames()
        for statement in tree.body:
            declared.visit(statement)
        self.builtin_shadows = declared.names & _BUILTINS

    def _name(self, name):
        return self.values.get(
            name,
            _Value(api="builtins." + name)
            if name in _BUILTINS and name not in self.builtin_shadows
            else _UNKNOWN,
        )

    def _replace(self, previous, replacement):
        if previous is _UNKNOWN:
            return
        # A list or mapping stores the object identity, not a snapshot of its
        # fields. Keep those aliases in sync after a field write or redaction.
        cache = {id(previous): replacement}
        remaining = 10_000

        def replace_container(value, depth=0):
            nonlocal remaining
            if id(value) in cache:
                return cache[id(value)]
            if depth >= 24 or remaining <= 0:
                return value
            remaining -= 1
            updated = value
            if value.items is not None:
                items = tuple(
                    replace_container(item, depth + 1) for item in value.items
                )
                if any(new is not old for new, old in zip(items, value.items)):
                    updated = _sequence(items)
            elif value.pairs is not None:
                pairs = tuple(
                    (key, replace_container(item, depth + 1))
                    for key, item in value.pairs
                )
                if any(
                    new is not old for (_, new), (_, old) in zip(pairs, value.pairs)
                ):
                    updated = _mapping(pairs)
            cache[id(value)] = updated
            return updated

        for name, value in list(self.values.items()):
            self.values[name] = replace_container(value)
        for reference in self._call_refs:
            reference[0] = replace_container(reference[0])

    def _assign(self, target, value):
        if isinstance(target, ast.Name):
            self.values[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for index, element in enumerate(target.elts):
                part = (
                    value.items[index]
                    if value.items is not None and index < len(value.items)
                    else _Value(sources=value.sources)
                )
                self._assign(element, part)
        elif isinstance(target, ast.Starred):
            self._assign(target.value, value)
        elif isinstance(target, ast.Attribute):
            base = self.expr(target.value)
            if base.api:
                self.values[base.api + "." + target.attr] = value
            elif base is not _UNKNOWN:
                fields = dict(base.fields or ())
                inherited = base.sources - _combined(fields.values()).sources
                fields[target.attr] = value
                self._replace(
                    base,
                    _Value(
                        sources=inherited | _combined(fields.values()).sources,
                        fields=tuple(fields.items()),
                    ),
                )
        elif isinstance(target, ast.Subscript):
            base, key = self.expr(target.value), self.expr(target.slice).literal
            if base.pairs is not None and key is not None:
                fields = dict(base.pairs)
                fields[key] = value
                self._replace(base, _mapping(fields.items()))
            elif (
                base.items is not None
                and isinstance(key, int)
                and -len(base.items) <= key < len(base.items)
            ):
                elements = list(base.items)
                elements[key] = value
                self._replace(base, _sequence(elements))
            else:
                self._replace(base, _combined([base, value]))

    def expr(self, node):
        if node is None:
            return _UNKNOWN
        if isinstance(node, ast.Name):
            return self._name(node.id)
        if isinstance(node, ast.Constant):
            return (
                _Value(literal=node.value)
                if isinstance(node.value, (str, int))
                else _UNKNOWN
            )
        if isinstance(node, ast.Attribute):
            base = self.expr(node.value)
            return self._member(base, node.attr)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return _sequence(self.expr(x) for x in node.elts)
        if isinstance(node, ast.Dict):
            pairs = [
                (self.expr(k).literal, self.expr(v))
                for k, v in zip(node.keys, node.values)
            ]
            if all(k is not None for k, _ in pairs):
                return _mapping(pairs)
            return _combined(v for _, v in pairs)
        if isinstance(node, ast.Subscript):
            base, key = self.expr(node.value), self.expr(node.slice).literal
            if (
                base.api == "os.environ"
                and isinstance(key, str)
                and _SECRET_WORDS.search(key)
            ):
                return _Value(sources=frozenset({"environment variable " + key}))
            if base.items is not None and isinstance(key, int):
                return (
                    base.items[key]
                    if -len(base.items) <= key < len(base.items)
                    else _UNKNOWN
                )
            if base.pairs is not None and key is not None:
                return dict(base.pairs).get(key, _UNKNOWN)
            return _Value(sources=base.sources)
        if isinstance(node, ast.NamedExpr):
            value = self.expr(node.value)
            self._assign(node.target, value)
            return value
        if isinstance(node, ast.IfExp):
            self.expr(node.test)
            return _joined(self.expr(node.body), self.expr(node.orelse))
        if isinstance(node, ast.BoolOp):
            return _combined(self.expr(x) for x in node.values)
        if isinstance(node, ast.BinOp):
            return _combined([self.expr(node.left), self.expr(node.right)])
        if isinstance(node, ast.JoinedStr):
            return _combined(self.expr(x) for x in node.values)
        if isinstance(node, ast.FormattedValue):
            return self.expr(node.value)
        if isinstance(node, ast.Call):
            return self._call(node)
        if isinstance(node, ast.Starred):
            return self.expr(node.value)
        if isinstance(
            node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
        ):
            saved = self.values.copy()
            for generator in node.generators:
                iterable = self.expr(generator.iter)
                self._assign(generator.target, _Value(sources=iterable.sources))
                for condition in generator.ifs:
                    self.expr(condition)
            value = (
                _combined([self.expr(node.key), self.expr(node.value)])
                if isinstance(node, ast.DictComp)
                else self.expr(node.elt)
            )
            self.values = saved
            return _Value(sources=value.sources)
        # Conditions and unsupported expressions can contain output calls, but
        # their boolean results do not themselves disclose the credential.
        for child in ast.iter_child_nodes(node):
            self.expr(child)
        return _UNKNOWN

    def _member(self, base, name):
        if base.api:
            qualified = base.api + "." + name
            return self.values.get(qualified, _Value(api=qualified))
        if base.fields is not None:
            return dict(base.fields).get(
                name,
                _Value(
                    sources=base.sources
                    - _combined(value for _, value in base.fields).sources
                ),
            )
        return _Value(sources=base.sources)

    def _call_inputs(self, node):
        # Python binds a method before evaluating arguments. Retain that
        # object even if an argument rebinds its name, while _replace refreshes
        # its fields when an argument mutates the same object in place.
        start = len(self._call_refs)

        def retain(value):
            reference = [value]
            self._call_refs.append(reference)
            return reference

        try:
            receiver = None
            if isinstance(node.func, ast.Attribute):
                receiver = retain(self.expr(node.func.value))
                func = self._member(receiver[0], node.func.attr)
            else:
                func = self.expr(node.func)
            arguments = [retain(self.expr(arg)) for arg in node.args]
            keywords = [(kw.arg, retain(self.expr(kw.value))) for kw in node.keywords]
            return (
                func,
                [value[0] for value in arguments],
                [(name, value[0]) for name, value in keywords],
                receiver[0] if receiver is not None else None,
            )
        finally:
            del self._call_refs[start:]

    def _call(self, node):
        func, args, keyword_args, base = self._call_inputs(node)
        keywords = dict(keyword_args)
        api = func.api or ""
        if api in {"os.getenv", "os.environ.get"}:
            key = args[0].literal if args else keywords.get("key", _UNKNOWN).literal
            if isinstance(key, str) and _SECRET_WORDS.search(key):
                return _Value(sources=frozenset({"environment variable " + key}))
        if api == "getpass.getpass":
            return _Value(sources=frozenset({"getpass credential input"}))
        if api == "builtins.input":
            prompt = (
                args[0].literal if args else keywords.get("prompt", _UNKNOWN).literal
            )
            if isinstance(prompt, str) and _SECRET_WORDS.search(prompt):
                return _Value(sources=frozenset({"credential input prompt"}))
        if api == "logging.getLogger":
            return _Value(api="logging.Logger")
        if api == "logging.LoggerAdapter":
            if args and args[0].api == "logging.Logger":
                return _Value(api="logging.Logger")
        if api == "builtins.print":
            self._emit(
                node, args + [v for k, v in keywords.items() if k in {"sep", "end"}]
            )
            return _UNKNOWN
        if (
            api.rpartition(".")[0] in {"logging", "logging.Logger"}
            and api.rpartition(".")[2] in _LOG_METHODS
        ):
            logged = args[1:] if api.endswith(".log") else args
            self._emit(
                node,
                logged
                + [v for k, v in keywords.items() if k in {"msg", "args", "extra"}],
            )
            return _UNKNOWN
        if api in {"builtins.len", "builtins.bool"}:
            return _UNKNOWN
        if api in {"builtins.str", "builtins.repr", "builtins.ascii", "json.dumps"}:
            return _combined(args[:1])
        if api == "builtins.dict":
            result = _mapping(())
            for value in args:
                result = self._mapping_update(result, value)
            for key, value in keyword_args:
                result = self._mapping_update(
                    result, value if key is None else _mapping([(key, value)])
                )
            return result
        if api in {"builtins.list", "builtins.tuple", "builtins.set"}:
            return _combined(args + list(keywords.values()))
        if isinstance(node.func, ast.Attribute):
            method = node.func.attr
            if base.pairs is not None and method == "update":
                updated = base
                for value in args:
                    updated = self._mapping_update(updated, value)
                for key, value in keyword_args:
                    updated = self._mapping_update(
                        updated,
                        value if key is None else _mapping([(key, value)]),
                    )
                self._replace(base, updated)
                # dict.update mutates its receiver and returns None. Its
                # arguments are not the value of the call expression.
                return _UNKNOWN
            if base.pairs is not None and method == "setdefault" and args:
                fields = dict(base.pairs)
                key = args[0].literal
                default = args[1] if len(args) > 1 else _UNKNOWN
                if key is not None:
                    if key in fields:
                        return fields[key]
                    fields[key] = default
                    self._replace(base, _mapping(fields.items()))
                    return default
                # An unknown key may select an existing value or insert the
                # default. Neither alternative justifies dropping sources.
                value = _combined([base] + args)
                self._replace(base, value)
                return value
            if method == "get" and base.pairs is not None and args:
                return dict(base.pairs).get(
                    args[0].literal, args[1] if len(args) > 1 else _UNKNOWN
                )
            if method in {"append", "extend", "insert"} and base.items is not None:
                value = args[-1] if args else _UNKNOWN
                elements = list(base.items)
                if method == "extend" and value.items is not None:
                    elements.extend(value.items)
                elif method == "append":
                    elements.append(value)
                else:
                    self._replace(base, _combined([base, value]))
                    return _UNKNOWN
                self._replace(base, _sequence(elements))
                return _UNKNOWN
            if method == "join":
                return _combined([base] + args[:1])
            if method == "format" and isinstance(base.literal, str):
                used = []
                try:
                    automatic = 0
                    for _, field, _, _ in string.Formatter().parse(base.literal):
                        if field is None:
                            continue
                        key = field.split(".", 1)[0].split("[", 1)[0]
                        if not key:
                            key, automatic = str(automatic), automatic + 1
                        used.append(
                            args[int(key)]
                            if key.isdigit() and int(key) < len(args)
                            else keywords.get(key, _UNKNOWN)
                        )
                except ValueError:
                    return _UNKNOWN
                return _combined(used)
            if method in {
                "encode",
                "decode",
                "strip",
                "lstrip",
                "rstrip",
                "lower",
                "upper",
            }:
                return _Value(sources=base.sources)
            return _combined([base] + args + list(keywords.values()))
        # A helper called redact(), hash(), or sanitize() is not proof that its
        # result omits the credential. Keep unknown transforms reviewable.
        return _combined(args + list(keywords.values()))

    def _mapping_update(self, base, value):
        pairs = value.pairs
        if pairs is None and value.items is not None:
            entries = []
            for item in value.items:
                if (
                    item.items is None
                    or len(item.items) != 2
                    or item.items[0].literal is None
                ):
                    break
                entries.append((item.items[0].literal, item.items[1]))
            else:
                pairs = tuple(entries)
        if base.pairs is None or pairs is None:
            return _combined([base, value])
        fields = dict(base.pairs)
        fields.update(pairs)
        return _mapping(fields.items())

    def _emit(self, node, values):
        sources = _combined(values).sources
        if sources:
            labels = sorted(sources)
            sink = self.expr(node.func).api or "console/log output"
            self.findings[(node.lineno, node.col_offset)] = {
                "rule_id": "SKY-D251",
                "severity": "HIGH",
                "message": "Sensitive data from "
                + ", ".join(sorted(sources))
                + " reaches console/log output. Remove or redact it before logging.",
                "file": self.filename,
                "line": node.lineno,
                "col": node.col_offset,
                "symbol": self.symbol,
                "metadata": {
                    "security_evidence": {
                        "evidence_kind": "source_to_sink",
                        "source": labels[0],
                        "sources": labels,
                        "sink": sink,
                        "path": [
                            "credential value from " + labels[0],
                            "local assignments, containers or formatting preserve the value",
                            "reaches " + sink,
                        ],
                        "guards_seen": [],
                        "guards_missing": ["remove or redact credential before output"],
                        "analysis_complete": False,
                    }
                },
            }

    def block(self, statements):
        for node in statements:
            if not self.statement(node):
                return False
        return True

    def _branches(self, branches):
        saved, continuing = self.values.copy(), []
        for body in branches:
            self.values = saved.copy()
            if self.block(body):
                continuing.append(self.values)
        if continuing:
            names = set().union(*(state.keys() for state in continuing))
            self.values = {
                name: _joined_states(
                    [state.get(name, _UNKNOWN) for state in continuing]
                )
                for name in names
            }
        else:
            self.values = saved
        return bool(continuing)

    def statement(self, node):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                self.values[name] = _Value(
                    api=self.imports.resolved_import(self.function, name)
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module and not node.level:
                for alias in node.names:
                    name = alias.asname or alias.name
                    self.values[name] = _Value(
                        api=self.imports.resolved_import(self.function, name)
                    )
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = self.expr(node.value)
            for target in (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            ):
                self._assign(target, value)
        elif isinstance(node, ast.AugAssign):
            self._assign(
                node.target, _combined([self.expr(node.target), self.expr(node.value)])
            )
        elif isinstance(node, ast.Expr):
            self.expr(node.value)
        elif isinstance(node, ast.If):
            self.expr(node.test)
            return self._branches([node.body, node.orelse])
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            saved = self.values.copy()
            if isinstance(node, ast.While):
                self.expr(node.test)
            else:
                self._assign(node.target, _Value(sources=self.expr(node.iter).sources))
            self.block(node.body)
            for name in self.values.keys() | saved.keys():
                self.values[name] = _joined(
                    self.values.get(name, _UNKNOWN), saved.get(name, _UNKNOWN)
                )
            self.block(node.orelse)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                self.expr(decorator)
            for default in node.args.defaults + node.args.kw_defaults:
                self.expr(default)
            self.values[node.name] = _UNKNOWN
            saved, symbol = self.values.copy(), self.symbol
            previous_function, self.function = self.function, node
            local = _LocalNames()
            for statement in node.body:
                local.visit(statement)
            parameters = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
            parameters += [p for p in [node.args.vararg, node.args.kwarg] if p]
            for name in local.names | {p.arg for p in parameters}:
                # Parameters are not credential sources. Distinct identities
                # let a local field write be tracked without contaminating
                # unrelated parameters or relying on an attribute's spelling.
                self.values[name] = _Value()
            self.symbol = node.name
            self.block(node.body)
            self.values, self.symbol = saved, symbol
            self.function = previous_function
        elif isinstance(node, ast.ClassDef):
            saved, symbol = self.values.copy(), self.symbol
            self.symbol = node.name
            self.block(node.body)
            self.values, self.symbol = saved, symbol
            self.values[node.name] = _UNKNOWN
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                value = self.expr(item.context_expr)
                if item.optional_vars:
                    self._assign(item.optional_vars, value)
            return self.block(node.body)
        elif isinstance(node, _TRY_NODES):
            self._branches([node.body + node.orelse] + [h.body for h in node.handlers])
            return self.block(node.finalbody)
        elif isinstance(node, (ast.Return, ast.Raise)):
            self.expr(getattr(node, "value", None) or getattr(node, "exc", None))
            return False
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                self._assign(target, _UNKNOWN)
        else:
            for child in ast.iter_child_nodes(node):
                self.expr(child)
        return True


def _joined_states(values):
    result = values[0]
    for value in values[1:]:
        result = _joined(result, value)
    return result


def scan(tree, context):
    """Return D251 findings without executing or importing the scanned source."""
    checker = _LoggingFlow(
        context.get("filename", context.get("file_path", "<unknown>")), tree
    )
    checker.block(tree.body)
    return list(checker.findings.values())
