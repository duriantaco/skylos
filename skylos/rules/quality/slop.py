"""Roundabout Python that a direct form replaces.

Every check here reports only what the syntax proves, and only when the
suggested rewrite keeps the behaviour. A builtin counts only when the name
resolves to the builtin in that scope (``builtin_references``); an import
counts only when it runs unconditionally and nothing in the file rebinds it
(``stable_module_imports``). Anything the file cannot prove is not reported.
The checks share one walk of the module per file.
"""

from __future__ import annotations

import ast
import io
import tokenize
from collections import defaultdict
from pathlib import Path

from skylos.rules.base import SkylosRule
from skylos.rules.danger.builtin_bindings import builtin_references
from skylos.rules.quality._import_bindings import (
    import_bindings,
    project_submodule,
    stable_module_imports,
)
from skylos.rules.quality._lint_ignores import ruff_ignores
from skylos.rules.quality._receivers import _bound_names, _parameters, _scope_bindings
from skylos.rules.quality._scope import is_non_production_python
from skylos.rules.quality._test_code import is_python_golden_fixture

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_BUILTIN_NAMES = frozenset(
    {
        "all",
        "any",
        "ascii",
        "bool",
        "callable",
        "hasattr",
        "isinstance",
        "issubclass",
        "repr",
        "str",
    }
)
_CONVERSION_FLAGS = {"str": "s", "repr": "r", "ascii": "a"}


class _ModuleFacts:
    """One walk of a module: parents, nearest scopes, node index and bindings."""

    def __init__(self, module: ast.Module, context):
        self.module = module
        self.filename = context.get("filename")
        self.project_root = context.get("project_root")
        self.source = context.get("source")
        self._comment_lines = None
        self._comments_read = False
        self.parents: dict[int, ast.AST] = {}
        self.scope_of: dict[int, ast.AST] = {}
        self.by_type: dict[type, list[ast.AST]] = defaultdict(list)
        pending = [(module, module)]
        while pending:
            node, scope = pending.pop()
            self.by_type[type(node)].append(node)
            self.scope_of[id(node)] = scope
            inner = scope
            if isinstance(node, _SCOPES):
                inner = node
            for child in ast.iter_child_nodes(node):
                self.parents[id(child)] = node
                pending.append((child, inner))
        for nodes in self.by_type.values():
            nodes.sort(key=_position)
        try:
            self.builtin_loads = builtin_references(module, _BUILTIN_NAMES)
        except RecursionError:
            self.builtin_loads = frozenset()
        self.imports = stable_module_imports(module)
        self._production = None
        self._golden_fixture = None
        self._ruff_ignored: dict[tuple[str, ...], bool] = {}
        self._bound: dict[int, set[str]] = {}

    @property
    def production(self) -> bool:
        if self._production is None:
            self._production = not is_non_production_python(
                self.filename, self.project_root
            )
        return self._production

    @property
    def golden_fixture(self) -> bool:
        """Test data a test reads as text (input and expected output)."""
        if self._golden_fixture is None:
            self._golden_fixture = bool(
                self.filename
                and self.project_root is not None
                and is_python_golden_fixture(self.filename, self.project_root)
            )
        return self._golden_fixture

    @property
    def comment_lines(self) -> frozenset[int] | None:
        """Lines holding a comment, or None when the source cannot be read."""
        if self._comments_read:
            return self._comment_lines
        self._comments_read = True
        if not isinstance(self.source, str):
            return None
        try:
            tokens = tokenize.generate_tokens(io.StringIO(self.source).readline)
            self._comment_lines = frozenset(
                token.start[0] for token in tokens if token.type == tokenize.COMMENT
            )
        except (tokenize.TokenError, SyntaxError):
            self._comment_lines = None
        return self._comment_lines

    def reads_function_source(self) -> bool:
        """Whether the file reads function source text to run it elsewhere."""
        return any(
            _call_name(call.func) in _SOURCE_READERS for call in self.nodes(ast.Call)
        )

    def ruff_ignored(self, codes: tuple[str, ...]) -> bool:
        """Whether the project's ruff configuration turns these rules off here."""
        if codes not in self._ruff_ignored:
            self._ruff_ignored[codes] = ruff_ignores(
                self.filename, self.project_root, codes
            )
        return self._ruff_ignored[codes]

    def nodes(self, *kinds):
        found = []
        for kind in kinds:
            found.extend(self.by_type.get(kind, ()))
        found.sort(key=_position)
        return found

    def parent(self, node):
        return self.parents.get(id(node))

    def scope(self, node):
        return self.scope_of.get(id(node), self.module)

    def builtin(self, node, name: str) -> bool:
        if isinstance(node, ast.Name):
            return node.id == name and id(node) in self.builtin_loads
        if isinstance(node, ast.Attribute) and node.attr == name:
            owner = node.value
            if isinstance(owner, ast.Name):
                binding = self.imports.get(owner.id)
                return (
                    binding is not None
                    and not binding.from_import
                    and binding.module == "builtins"
                )
        return False

    def builtin_name(self, node, names) -> str | None:
        for name in names:
            if self.builtin(node, name):
                return name
        return None

    def bound_in(self, scope) -> set[str]:
        """Names a function or lambda binds locally, parameters included."""
        key = id(scope)
        if key not in self._bound:
            if isinstance(scope, _FUNCTIONS):
                self._bound[key] = _bound_names(scope)
            elif isinstance(scope, ast.Lambda):
                self._bound[key] = _parameters(scope)
            else:
                self._bound[key] = set()
        return self._bound[key]

    def enclosing_functions(self, node):
        scope = self.scope(node)
        while scope is not self.module and scope is not None:
            if isinstance(scope, (*_FUNCTIONS, ast.Lambda)):
                yield scope
            scope = self.scope(scope)


_SOURCE_READERS = frozenset({"getsource", "getsourcelines"})


def _call_name(func) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _position(node):
    return (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))


def module_facts(module: ast.Module, context) -> _ModuleFacts:
    """Share one walk of the module across the checks in this file."""
    cached = context.get("_slop_module_facts")
    if cached is None or cached[0] is not module:
        cached = (module, _ModuleFacts(module, context))
        context["_slop_module_facts"] = cached
    return cached[1]


def _short(node, limit: int = 60) -> str:
    try:
        text = ast.unparse(node)
    except RecursionError:
        return "expression"
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def _scope_nodes(scope):
    """Nodes whose nearest scope is ``scope``; nested scopes are not entered."""
    pending = list(reversed(scope.body))
    while pending:
        node = pending.pop()
        yield node
        if isinstance(node, _SCOPES):
            continue
        pending.extend(reversed(list(ast.iter_child_nodes(node))))


class _SlopRule(SkylosRule):
    kind = "logic"
    severity = "LOW"
    finding_type_name = "expression"
    ruff_codes: tuple[str, ...] = ()

    def _finding(self, node, context, *, name, value, message, evidence=None):
        filename = context.get("filename")
        finding = {
            "rule_id": self.rule_id,
            "kind": self.kind,
            "severity": self.severity,
            "type": self.finding_type_name,
            "name": name,
            "simple_name": name,
            "value": value,
            "threshold": 0,
            "message": message,
            "file": filename,
            "basename": Path(filename or "").name,
            "line": node.lineno,
            "col": node.col_offset,
        }
        if evidence:
            finding["evidence"] = evidence
        return finding

    def visit_node(self, node, context):
        if not isinstance(node, ast.Module):
            return None
        facts = module_facts(node, context)
        if facts.golden_fixture:
            return None
        if self.ruff_codes and facts.ruff_ignored(self.ruff_codes):
            return None
        findings = self.check(facts, context)
        return findings or None

    def check(self, facts: _ModuleFacts, context) -> list[dict]:
        raise NotImplementedError


class RepeatedFunctionImportRule(_SlopRule):
    """A function repeats an import the module already ran unconditionally."""

    rule_id = "SKY-L036"
    name = "Import repeated inside function"
    finding_type_name = "import"

    def check(self, facts, context):
        if not facts.imports or not facts.production:
            return []
        if facts.reads_function_source():
            return []
        findings = []
        for position, statement in enumerate(facts.module.body):
            for function in _subtree_functions(statement):
                findings.extend(
                    self._function_findings(facts, context, function, position)
                )
        return findings

    def _function_findings(self, facts, context, function, position):
        bindings = None
        findings = []
        for statement in _scope_nodes(function):
            if not isinstance(statement, (ast.Import, ast.ImportFrom)):
                continue
            for local in import_bindings(statement):
                held = facts.imports.get(local.name)
                if held is None or held.position >= position:
                    continue
                if not held.covers(local):
                    continue
                if local.from_import and not project_submodule(
                    held, facts.filename, facts.project_root
                ):
                    continue
                if bindings is None:
                    bindings = _scope_bindings(function)
                if (
                    bindings.counts[local.name] != 1
                    or local.name in bindings.nonlocals
                    or local.name in _parameters(function)
                ):
                    continue
                if any(
                    local.name in facts.bound_in(outer)
                    for outer in facts.enclosing_functions(function)
                ):
                    continue
                findings.append(
                    self._finding(
                        statement,
                        context,
                        name=local.name,
                        value=local.statement_text(),
                        message=(
                            f"'{local.statement_text()}' repeats the module-level "
                            f"import on line {held.line}, which already binds "
                            f"'{local.name}' for this function. Keep one import."
                        ),
                        evidence={
                            "module_import_line": held.line,
                            "module_import": held.statement_text(),
                        },
                    )
                )
        return findings


def _subtree_functions(statement):
    for node in ast.walk(statement):
        if isinstance(node, _FUNCTIONS):
            yield node


def _bool_constant(node):
    if isinstance(node, ast.Constant) and type(node.value) is bool:
        return node.value
    return None


def _opposite_bools(first, second) -> bool | None:
    """The first value when the two nodes are opposite bool literals."""
    left = _bool_constant(first)
    right = _bool_constant(second)
    if left is None or right is None or left == right:
        return None
    return left


def _single_return_bool(body):
    if len(body) == 1 and isinstance(body[0], ast.Return) and body[0].value is not None:
        return body[0].value
    return None


def _single_assignment(body):
    if (
        len(body) == 1
        and isinstance(body[0], ast.Assign)
        and len(body[0].targets) == 1
        and isinstance(body[0].targets[0], ast.Name)
    ):
        return body[0].targets[0].id, body[0].value
    return None


def _is_elif(facts, node: ast.If) -> bool:
    parent = facts.parent(node)
    return isinstance(parent, ast.If) and parent.orelse == [node]


_ALWAYS_BOOL_COMPARISONS = (ast.Is, ast.IsNot, ast.In, ast.NotIn)
_BOOL_BUILTINS = (
    "isinstance",
    "issubclass",
    "callable",
    "hasattr",
    "any",
    "all",
    "bool",
)


def _yields_bool(facts, test) -> bool:
    """Tests whose value is a bool whatever the operands overload."""
    if isinstance(test, ast.UnaryOp):
        return isinstance(test.op, ast.Not)
    if isinstance(test, ast.Compare):
        return all(isinstance(op, _ALWAYS_BOOL_COMPARISONS) for op in test.ops)
    if isinstance(test, ast.Call):
        return facts.builtin_name(test.func, _BOOL_BUILTINS) is not None
    if isinstance(test, ast.BoolOp):
        return all(_yields_bool(facts, value) for value in test.values)
    return False


def _overloadable_comparison(facts, test) -> bool:
    """A comparison whose negation has no exact, lint-clean spelling.

    ``not (a == b)`` keeps the meaning but is itself a lint finding, and
    ``a != b`` or ``a >= b`` need not mean the same for overloaded operands.
    """
    return isinstance(test, ast.Compare) and not _yields_bool(facts, test)


class BooleanLiteralConditionalRule(_SlopRule):
    """A conditional whose two outcomes are the literals True and False."""

    rule_id = "SKY-L037"
    ruff_codes = ("SIM103", "SIM210", "SIM211")
    name = "Conditional returning bool literals"

    def check(self, facts, context):
        findings = []
        for node in facts.nodes(ast.IfExp, ast.If):
            if isinstance(node, ast.If) and _is_elif(facts, node):
                continue
            first = self._first_outcome(node)
            if first is None:
                continue
            if first is False and _overloadable_comparison(facts, node.test):
                continue
            findings.append(self._report(facts, node, context, first))
        return findings

    def _first_outcome(self, node):
        if isinstance(node, ast.IfExp):
            return _opposite_bools(node.body, node.orelse)
        body_return = _single_return_bool(node.body)
        else_return = _single_return_bool(node.orelse)
        if body_return is not None and else_return is not None:
            return _opposite_bools(body_return, else_return)
        body_assign = _single_assignment(node.body)
        else_assign = _single_assignment(node.orelse)
        if body_assign is None or else_assign is None:
            return None
        if body_assign[0] != else_assign[0]:
            return None
        return _opposite_bools(body_assign[1], else_assign[1])

    def _report(self, facts, node, context, first):
        condition = _short(node.test)
        if first:
            shape, replacement = _bool_replacement(facts, node.test)
        else:
            shape, replacement = _negated_replacement(facts, node.test)
        suggestion = f"'{replacement}'"
        if len(replacement) > _SHOWN_REPLACEMENT:
            suggestion = _REPLACEMENT_SHAPES[shape]
        form = "conditional expression"
        if isinstance(node, ast.If):
            form = "if/else"
        return self._finding(
            node,
            context,
            name="bool literal conditional",
            value=replacement,
            message=(
                f"This {form} only turns '{condition}' into "
                f"{first} or {not first}; write {suggestion} instead."
            ),
        )


_INVERSE_COMPARISONS = {
    ast.Is: ast.IsNot,
    ast.IsNot: ast.Is,
    ast.In: ast.NotIn,
    ast.NotIn: ast.In,
}
_BARE_OPERANDS = (ast.Name, ast.Attribute, ast.Call, ast.Subscript)


_SHOWN_REPLACEMENT = 60
_REPLACEMENT_SHAPES = {
    "same": "the condition itself (already a bool)",
    "bool": "bool() around the condition",
    "not": "'not' before the condition",
    "inverse": "the condition with its 'is' or 'in' test inverted",
}


def _source(node) -> str:
    try:
        return ast.unparse(node)
    except RecursionError:
        return "expression"


def _bool_replacement(facts, test) -> tuple[str, str]:
    """The test itself only when its value is a bool whatever it compares."""
    if _yields_bool(facts, test):
        return "same", _source(test)
    return "bool", f"bool({_source(test)})"


def _negated_replacement(facts, test) -> tuple[str, str]:
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _bool_replacement(facts, test.operand)
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        inverse = _INVERSE_COMPARISONS.get(type(test.ops[0]))
        if inverse is not None:
            flipped = ast.Compare(
                left=test.left, ops=[inverse()], comparators=test.comparators
            )
            return "inverse", _source(flipped)
    if isinstance(test, _BARE_OPERANDS):
        return "not", f"not {_source(test)}"
    return "not", f"not ({_source(test)})"


class FormattedConversionCallRule(_SlopRule):
    """``str()``/``repr()``/``ascii()`` called inside an f-string field."""

    rule_id = "SKY-L038"
    ruff_codes = ("RUF010",)
    name = "Conversion call inside f-string"

    def check(self, facts, context):
        findings = []
        for field in facts.nodes(ast.FormattedValue):
            if field.conversion != -1:
                continue
            call = field.value
            if (
                not isinstance(call, ast.Call)
                or len(call.args) != 1
                or call.keywords
                or isinstance(call.args[0], ast.Starred)
            ):
                continue
            converter = facts.builtin_name(call.func, _CONVERSION_FLAGS)
            if converter is None:
                continue
            flag = _CONVERSION_FLAGS[converter]
            argument = _short(call.args[0], 40)
            findings.append(
                self._finding(
                    call,
                    context,
                    name=f"{converter}() in f-string",
                    value=f"!{flag}",
                    message=(
                        f"'{{{_short(call, 50)}}}' calls {converter}() inside the "
                        f"f-string; the field '{{{argument}!{flag}}}' does the same."
                    ),
                )
            )
        return findings


def _reraises_only(handler: ast.ExceptHandler) -> bool:
    if len(handler.body) != 1 or not isinstance(handler.body[0], ast.Raise):
        return False
    statement = handler.body[0]
    if statement.cause is not None:
        return False
    if statement.exc is None:
        return True
    return (
        handler.name is not None
        and isinstance(statement.exc, ast.Name)
        and statement.exc.id == handler.name
    )


class ReraiseOnlyHandlerRule(_SlopRule):
    """Trailing except clauses whose only statement re-raises the exception."""

    rule_id = "SKY-L039"
    ruff_codes = ("TRY203", "TRY302")
    name = "Except clause that only re-raises"
    finding_type_name = "block"

    def check(self, facts, context):
        findings = []
        for node in facts.nodes(ast.Try):
            first = None
            for index in range(len(node.handlers) - 1, -1, -1):
                if not _reraises_only(node.handlers[index]):
                    break
                first = index
            if first is None:
                continue
            if _documented(facts, node.handlers[first], node.handlers[-1]):
                continue
            findings.append(self._report(node, first, context))
        return findings

    def _report(self, node, first, context):
        handler = node.handlers[first]
        if first == 0 and not node.finalbody:
            message = (
                "Every except clause here only re-raises, so the try statement "
                "changes nothing; remove it."
            )
        elif first == 0:
            message = (
                "Every except clause here only re-raises; a plain try/finally "
                "behaves the same."
            )
        else:
            message = (
                "This except clause and any after it only re-raise; removing "
                "them lets the exception propagate exactly as it does now."
            )
        return self._finding(
            handler,
            context,
            name="except",
            value="reraise_only",
            message=message,
        )


def _documented(facts, first, last) -> bool:
    """A comment inside the clauses marks a deliberate placeholder.

    Without readable source no comment can be ruled out.
    """
    lines = facts.comment_lines
    if lines is None:
        return True
    end = getattr(last, "end_lineno", None) or last.lineno
    return any(line in lines for line in range(first.lineno, end + 1))
