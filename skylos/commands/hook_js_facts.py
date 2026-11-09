"""JS/TS source facts for the hook's blocking policy, the counterpart of its Python AST check.

Verify's JS/TS taint rules report every plausible sink, and their findings carry
no source. The hook blocks only when request or process input reaches the sink's
arguments, following simple assignments. Receiver names are required, so a local
``query`` or ``db.query(...)`` is never a source. A file that does not parse
proves nothing.
"""

from __future__ import annotations

import re
from pathlib import Path

JS_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
_FUNCTIONS = frozenset(
    {
        "arrow_function",
        "function",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)
_SIMPLE_STATEMENTS = frozenset(
    {
        "expression_statement",
        "lexical_declaration",
        "variable_declaration",
        "return_statement",
        "throw_statement",
    }
)
_SCALAR_TYPES = frozenset({"number", "boolean", "bigint"})
_LITERALS = frozenset({"string", "number", "true", "false", "null", "undefined"})
_EXEC_CALLEE = re.compile(r"(?:^|\.)(?:eval|Function|exec|execSync|spawn|spawnSync)$")
_SOURCE = re.compile(
    r"\b(?:req|request|ctx|context)\."
    r"(?:query|body|params|headers|cookies|url|originalUrl|path|hostname|ip|"
    r"files?|rawBody|nextUrl|json|formData|text|param|get|request)\b"
    r"|\bc\.req\b"
    r"|\bevent\.(?:queryStringParameters|pathParameters|body|headers)\b"
    r"|\bprocess\.(?:argv|env)\b"
    r"|\bsearchParams\b"
    r"|\bformData\b"
    r"|\blocation\.(?:search|hash|href)\b"
    r"|\bdocument\.(?:cookie|URL|referrer)\b"
)
_GUARDS = (
    re.compile(
        r"!\s*(?P<collection>[\w$.]+)\.(?:includes|has)\(\s*(?P<name>[\w$]+)\s*\)"
    ),
    re.compile(
        r"(?P<collection>[\w$.]+)\.indexOf\(\s*(?P<name>[\w$]+)\s*\)\s*"
        r"(?:===?\s*-1|<\s*0)"
    ),
)
_CONSTANT_LOOKUP = re.compile(r"[A-Z][A-Z0-9_]*\[[^\]]+\]")
_SOURCE_DECORATOR = re.compile(
    r"^@(?:Param|Params|Query|Body|Headers|Req|Request|Ip|Session|Cookies|"
    r"UploadedFile|UploadedFiles)\b"
)


class JsFacts:
    def __init__(self, path: Path, text: str):
        self.source = text.encode("utf-8", errors="surrogatepass")
        self.root = _parse_root(path, text)

    def _text(self, node) -> str:
        return self.source[node.start_byte : node.end_byte].decode(
            "utf-8", errors="replace"
        )

    def _covering(self, line: int) -> list:
        """Nodes containing ``line``, outermost first."""
        row = line - 1
        chain = []
        node = self.root
        while node is not None:
            chain.append(node)
            inner = None
            for child in node.named_children:
                if child.start_point[0] <= row <= child.end_point[0]:
                    inner = child
                    break
            node = inner
        return chain

    def _calls_starting_on(self, line: int) -> list:
        row = line - 1
        found = []
        stack = [self.root]
        while stack:
            node = stack.pop()
            if node.start_point[0] > row or node.end_point[0] < row:
                continue
            if node.type in {"call_expression", "new_expression"}:
                if node.start_point[0] == row:
                    found.append(node)
                else:
                    callee = _callee(node)
                    if callee is not None and callee.end_point[0] == row:
                        found.append(node)
            stack.extend(node.named_children)
        return found

    def _untrusted_names(self, scope) -> set[str]:
        names: set[str] = set()
        nodes = _walk(scope)
        for node in nodes:
            if node.type in {"required_parameter", "optional_parameter"}:
                decorators = [c for c in node.named_children if c.type == "decorator"]
                if any(_SOURCE_DECORATOR.match(self._text(d)) for d in decorators):
                    names.update(_pattern_names(node.child_by_field_name("pattern")))
        pairs = _assignment_pairs(nodes)
        for _ in range(4):
            changed = False
            for target, value in pairs:
                if target is None or value is None:
                    continue
                if value.type in _FUNCTIONS:
                    continue
                if not self._mentions_source(self._text(value), names):
                    continue
                for name in _pattern_names(target):
                    if name not in names:
                        names.add(name)
                        changed = True
            if not changed:
                break
        return names

    @staticmethod
    def _mentions_source(text: str, names: set[str]) -> bool:
        return bool(_SOURCE.search(text)) or _mentions_name(text, names)

    def _proven_fixed_names(
        self, functions: list, line: int, tainted: set[str]
    ) -> set[str]:
        """Names a top-level guard before ``line`` proved to be in a fixed collection."""
        fixed: set[str] = set()
        for function in functions:
            body = function.child_by_field_name("body")
            if body is None or body.type != "statement_block":
                continue
            for statement in body.named_children:
                if statement.start_point[0] >= line - 1:
                    break
                if statement.type != "if_statement":
                    continue
                if statement.child_by_field_name("alternative") is not None:
                    continue
                consequence = statement.child_by_field_name("consequence")
                condition = statement.child_by_field_name("condition")
                if consequence is None or condition is None:
                    continue
                last = consequence
                if consequence.type == "statement_block":
                    if not consequence.named_children:
                        continue
                    last = consequence.named_children[-1]
                if last.type not in {"return_statement", "throw_statement"}:
                    continue
                text = self._text(condition).strip()
                if text.startswith("(") and text.endswith(")"):
                    text = text[1:-1]
                for term in text.split("||"):
                    for pattern in _GUARDS:
                        match = pattern.fullmatch(term.strip())
                        if match is None:
                            continue
                        collection = match.group("collection").split(".")[0]
                        if collection not in tainted:
                            fixed.add(match.group("name"))
        return fixed

    def line_uses_untrusted(
        self, line: int, col: int | None = None, *, sql: bool = False
    ) -> bool:
        if self.root is None:
            return False
        chain = self._covering(line)
        scope = self.root
        for node in chain:
            if node.type in _FUNCTIONS:
                scope = node
                break
        names = self._untrusted_names(scope)
        if sql:
            functions = [node for node in chain if node.type in _FUNCTIONS]
            names = names - self._proven_fixed_names(functions, line, names)
        calls = self._calls_starting_on(line)
        exact = [call for call in calls if call.start_point[1] == col]
        if exact:
            calls = exact
        if calls:
            return any(
                self._mentions_source(self._text(argument), names)
                for call in calls
                for argument in _arguments(call)
                if argument.type not in _FUNCTIONS
            )
        for node in reversed(chain):
            if node.type in _SIMPLE_STATEMENTS:
                return self._mentions_source(self._text(node), names)
        return False

    def line_interpolates_parameter(self, line: int, col: int | None = None) -> bool:
        """Text built from a parameter reaches a call here. Tagged templates bind values."""
        if self.root is None:
            return False
        functions = [n for n in self._covering(line) if n.type in _FUNCTIONS]
        if not functions:
            return False
        derived: set[str] = set()
        for function in functions:
            derived.update(_parameter_names(function))
        derived -= self._proven_fixed_names(functions, line, derived)
        if not derived:
            return False
        built: set[str] = set()
        pairs = _assignment_pairs(_walk(functions[0]))
        for _ in range(4):
            before = len(derived) + len(built)
            for target, value in pairs:
                if target is None or value is None or value.type in _FUNCTIONS:
                    continue
                text = self._text(value)
                if _CONSTANT_LOOKUP.fullmatch(text):
                    continue
                if _mentions_name(text, derived):
                    derived.update(_pattern_names(target))
                if self._builds_text(value, derived) or _mentions_name(text, built):
                    built.update(_pattern_names(target))
            if len(derived) + len(built) == before:
                break
        calls = self._calls_starting_on(line)
        exact = [call for call in calls if call.start_point[1] == col]
        if exact:
            calls = exact
        for call in calls:
            for argument in _arguments(call):
                if argument.type in _FUNCTIONS:
                    continue
                if self._builds_text(argument, derived):
                    return True
                if argument.type == "identifier" and self._text(argument) in built:
                    return True
        return False

    def _builds_text(self, node, names: set[str]) -> bool:
        for inner in _walk(node):
            if inner.type == "template_string":
                parent = inner.parent
                if (
                    parent is not None
                    and parent.type == "call_expression"
                    and parent.child_by_field_name("arguments") == inner
                ):
                    continue
                for child in inner.named_children:
                    if child.type == "template_substitution" and _mentions_name(
                        self._text(child), names
                    ):
                        return True
            elif inner.type == "binary_expression":
                operator = inner.child_by_field_name("operator")
                if operator is None or self._text(operator) != "+":
                    continue
                has_text = any(
                    c.type in {"string", "template_string"} for c in _walk(inner)
                )
                if has_text and _mentions_name(self._text(inner), names):
                    return True
        return False

    def call_has_non_constant_args(self, line: int) -> bool:
        if self.root is None:
            return False
        for call in self._calls_starting_on(line):
            callee = _callee(call)
            if callee is None or not _EXEC_CALLEE.search(self._text(callee)):
                continue
            if any(not _is_constant(argument) for argument in _arguments(call)):
                return True
        return False

    def statement_span(self, line: int) -> tuple[int, int] | None:
        """1-based span of the simple statement starting on ``line``, up to a nested body."""
        if self.root is None:
            return None
        for node in self._covering(line):
            if node.type not in _SIMPLE_STATEMENTS:
                continue
            if node.start_point[0] != line - 1:
                return None
            end = node.end_point[0]
            for inner in _walk(node):
                if inner.type in _FUNCTIONS:
                    end = min(end, inner.start_point[0])
            return node.start_point[0] + 1, end + 1
        return None


def _mentions_name(text: str, names: set[str]) -> bool:
    return any(
        re.search(rf"(?<![\w.$]){re.escape(name)}(?![\w$])", text) for name in names
    )


def _assignment_pairs(nodes: list) -> list[tuple]:
    pairs = []
    for node in nodes:
        if node.type == "variable_declarator":
            pairs.append(
                (node.child_by_field_name("name"), node.child_by_field_name("value"))
            )
        elif node.type == "assignment_expression":
            pairs.append(
                (node.child_by_field_name("left"), node.child_by_field_name("right"))
            )
    return pairs


def _parameter_names(function) -> set[str]:
    single = function.child_by_field_name("parameter")
    if single is not None:
        return _pattern_names(single)
    parameters = function.child_by_field_name("parameters")
    if parameters is None:
        return set()
    names: set[str] = set()
    for parameter in parameters.named_children:
        if parameter.type not in {"required_parameter", "optional_parameter"}:
            names.update(_pattern_names(parameter))
            continue
        annotation = parameter.child_by_field_name("type")
        if annotation is not None:
            shown = annotation.text.decode("utf-8", errors="replace").lstrip(": ")
            if shown in _SCALAR_TYPES:
                continue
        names.update(_pattern_names(parameter.child_by_field_name("pattern")))
    return names


def _parse_root(path: Path, text: str):
    from skylos.done.js_inventory import _parse

    root = _parse(str(path), text)
    if root is None or root.has_error:
        return None
    return root


def _walk(node) -> list:
    found = []
    stack = [node]
    while stack:
        current = stack.pop()
        found.append(current)
        stack.extend(current.named_children)
    return found


def _callee(call):
    return call.child_by_field_name("function") or call.child_by_field_name(
        "constructor"
    )


def _arguments(call) -> list:
    node = call.child_by_field_name("arguments")
    if node is None:
        return []
    return [child for child in node.named_children if child.type != "comment"]


def _is_constant(node) -> bool:
    if node.type in _LITERALS:
        return True
    if node.type == "template_string":
        return not any(c.type == "template_substitution" for c in node.named_children)
    return False


def _pattern_names(node) -> set[str]:
    if node is None:
        return set()
    if node.type == "identifier":
        return {node.text.decode("utf-8", errors="replace")}
    names = set()
    for inner in _walk(node):
        if inner.type in {"identifier", "shorthand_property_identifier_pattern"}:
            names.add(inner.text.decode("utf-8", errors="replace"))
    return names
