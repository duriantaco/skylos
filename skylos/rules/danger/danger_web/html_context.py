"""Where interpolated values land in an HTML string, and how much escaping
each landing spot needs.

A value's level says how far it has been made safe, from ``RAW`` (attacker
text) to ``CLEAN`` (not attacker text, or a number). Each spot in HTML needs a
level: element text needs ``&``, ``<`` and ``>`` escaped; a quoted attribute
value also needs quotes escaped; a URL attribute also needs a scheme that
cannot run script; an event handler, a ``style`` attribute, a script block,
a tag or an unquoted attribute value needs a value that is not attacker text.
Only attributes a browser follows as a link, form target or frame need the
scheme check; media ``src`` and similar never run a ``javascript:`` URL.

``split_parts`` flattens an f-string, a ``+`` chain, ``literal % values`` or
``literal.format(...)`` into ``("text", str)`` and
``("value", (nodes...), numeric)`` parts, where ``numeric`` means the
formatting directive only accepts numbers. ``hole_requirements`` runs the text
parts through a small HTML tokenizer and gives each value part the level its
spot needs and a description of the spot."""

from __future__ import annotations

import ast
import re
import string

RAW = 0
TEXT_SAFE = 1
ATTR_SAFE = 2
URL_SAFE = 3
CLEAN = 4

_NUMERIC_FORMAT_SPEC = re.compile(
    r"(?:.?[<>=^])?[+\- ]?z?#?0?\d*[,_]?(?:\.\d+)?[bdoxXeEfFgGn%]", re.S
)
_NUMERIC_PERCENT_KINDS = frozenset("diouxXeEfFgG")
_PERCENT_DIRECTIVE = re.compile(
    r"%(?:\((?P<key>[^)]*)\))?[#0\- +]*(?P<width>\*|\d+)?"
    r"(?:\.(?P<precision>\*|\d+))?[hlL]?(?P<kind>[diouxXeEfFgGcrsa%])"
)
_FIELD_HEAD = re.compile(r"[^.\[]*")

_SPACE = " \t\n\r\f"
_UNKNOWN = "\x01"
_SCRIPT_ELEMENTS = frozenset({"script", "style"})
_RAW_TEXT_ELEMENTS = frozenset(
    {
        "script",
        "style",
        "xmp",
        "iframe",
        "noembed",
        "noframes",
        "noscript",
        "textarea",
        "title",
    }
)
_NAVIGATION_ATTRIBUTES = frozenset({"href", "xlink:href", "action", "formaction"})
_FRAME_ELEMENTS = frozenset({"iframe", "frame"})
_CODE_ATTRIBUTES = frozenset({"style", "srcdoc"})
_RESOURCE_ELEMENTS = frozenset({"script", "base", "embed", "object", "applet"})
_RESOURCE_ATTRIBUTES = frozenset(
    {"src", "href", "xlink:href", "data", "codebase", "classid", "archive"}
)
_DANGEROUS_SCHEMES = ("javascript", "vbscript", "data", "livescript", "mocha")
_SCHEME_CHARS = frozenset(string.ascii_letters + string.digits + "+-.")
_URL_LEADING_JUNK = "".join(chr(code) for code in range(33))
_ORIGIN_FIXED = re.compile(
    r"[A-Za-z][A-Za-z0-9+.\-]*://[^/\\?#]+[/\\?#]"
    r"|[/\\][^/\\]"
    r"|\.{1,2}[/\\]"
    r"|[?#]"
    r"|[^:/\\?#&]+[/\\?#]"
)
_TEXT_STATES = frozenset({"text", "comment", "bogus_comment", "plaintext"})
_QUOTED_STATES = frozenset({"double_quoted", "single_quoted"})


def _text(value: str):
    return ("text", value)


def _hole(nodes, numeric: bool = False):
    return ("value", tuple(nodes), numeric)


def _is_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_literal_format(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and _is_literal(node.func.value)
    )


def _numeric_spec(spec: ast.AST | None) -> bool:
    if not isinstance(spec, ast.JoinedStr):
        return False
    if not all(_is_literal(value) for value in spec.values):
        return False
    text = "".join(value.value for value in spec.values)
    return bool(_NUMERIC_FORMAT_SPEC.fullmatch(text))


def _joined_parts(node: ast.JoinedStr):
    parts = []
    for value in node.values:
        if _is_literal(value):
            parts.append(_text(value.value))
        elif isinstance(value, ast.FormattedValue):
            numeric = value.conversion == -1 and _numeric_spec(value.format_spec)
            parts.append(_hole([value.value], numeric))
    return parts


def _percent_operands(operand: ast.AST):
    """(positional values, keyed values) of the right side of ``%``."""
    positional = None
    if isinstance(operand, ast.Tuple) and not any(
        isinstance(element, ast.Starred) for element in operand.elts
    ):
        positional = list(operand.elts)
    keyed = None
    if isinstance(operand, ast.Dict) and all(_is_literal(key) for key in operand.keys):
        keyed = {key.value: value for key, value in zip(operand.keys, operand.values)}
    return positional, keyed


def _percent_parts(template: str, operand: ast.AST):
    positional, keyed = _percent_operands(operand)
    parts = []
    index = 0
    position = 0
    for match in _PERCENT_DIRECTIVE.finditer(template):
        literal = template[position : match.start()]
        if "%" in literal:
            return [_text(template), _hole([operand])]
        parts.append(_text(literal))
        position = match.end()
        kind = match.group("kind")
        if kind == "%":
            parts.append(_text("%"))
            continue
        index += [match.group("width"), match.group("precision")].count("*")
        key = match.group("key")
        node = operand
        if key is not None and keyed is not None:
            node = keyed.get(key, operand)
        elif key is None and positional is not None and index < len(positional):
            node = positional[index]
        index += 1
        parts.append(_hole([node], kind in _NUMERIC_PERCENT_KINDS))
    if "%" in template[position:]:
        return [_text(template), _hole([operand])]
    parts.append(_text(template[position:]))
    return parts


def _unstarred(arg: ast.AST) -> ast.AST:
    if isinstance(arg, ast.Starred):
        return arg.value
    return arg


def _format_field_node(head: str, automatic: int, call: ast.Call):
    args = call.args
    if head == "" and automatic < len(args):
        return args[automatic]
    if head.isdigit() and int(head) < len(args):
        return args[int(head)]
    for kw in call.keywords:
        if head and kw.arg == head:
            return kw.value
    return None


def _numeric_field(spec: str | None, conversion: str | None) -> bool:
    return (
        conversion is None
        and bool(spec)
        and "{" not in spec
        and bool(_NUMERIC_FORMAT_SPEC.fullmatch(spec))
    )


def _format_parts(template: str, call: ast.Call):
    every = [_unstarred(arg) for arg in call.args] + [kw.value for kw in call.keywords]
    splatted = any(isinstance(arg, ast.Starred) for arg in call.args) or any(
        kw.arg is None for kw in call.keywords
    )
    try:
        fields = list(string.Formatter().parse(template))
    except ValueError:
        return [_text(template), _hole(every)]
    parts = []
    automatic = 0
    for literal, field, spec, conversion in fields:
        if literal:
            parts.append(_text(literal))
        if field is None:
            continue
        head = _FIELD_HEAD.match(field).group(0)
        node = _format_field_node(head, automatic, call)
        if head == "":
            automatic += 1
        nodes = every
        if node is not None and not splatted:
            nodes = [node]
        parts.append(_hole(nodes, _numeric_field(spec, conversion)))
    return parts


def _builds_string(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.JoinedStr)
        or (isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)))
        or _is_literal_format(node)
    )


def _expand(item: ast.AST, stack: list):
    """Parts ``item`` contributes now; operands still to flatten go on ``stack``."""
    if _is_literal(item):
        return [_text(item.value)]
    if isinstance(item, ast.JoinedStr):
        return _joined_parts(item)
    if _is_literal_format(item):
        return _format_parts(item.func.value.value, item)
    if isinstance(item, ast.BinOp) and isinstance(item.op, ast.Mod):
        if _is_literal(item.left):
            return _percent_parts(item.left.value, item.right)
        stack.append(_hole([item.right]))
        stack.append(item.left)
        return []
    if isinstance(item, ast.BinOp) and isinstance(item.op, ast.Add):
        stack.append(item.right)
        stack.append(item.left)
        return []
    return [_hole([item])]


def split_parts(node: ast.AST):
    """``node`` as text and value parts when it builds a string, else None."""
    if not _builds_string(node):
        return None
    parts = []
    stack = [node]
    while stack:
        item = stack.pop()
        if isinstance(item, tuple):
            parts.append(item)
        else:
            parts.extend(_expand(item, stack))
    return parts


def _url_start(value: str) -> str:
    """What a browser parses a URL from: tabs and newlines removed, leading
    control characters and spaces stripped."""
    cleaned = value.replace("\t", "").replace("\n", "").replace("\r", "")
    return cleaned.lstrip(_URL_LEADING_JUNK)


def safe_url_prefix(prefix: str) -> bool:
    """No URL that starts with ``prefix`` can use a script-running scheme."""
    text = _url_start(prefix)
    if not text or text[0] == "&":
        return False
    if not (text[0].isascii() and text[0].isalpha()):
        return True
    end = 0
    while end < len(text) and text[end] in _SCHEME_CHARS:
        end += 1
    scheme = text[:end].lower()
    if end == len(text):
        return not any(danger.startswith(scheme) for danger in _DANGEROUS_SCHEMES)
    if text[end] == ":":
        return scheme not in _DANGEROUS_SCHEMES
    return text[end] != "&"


class _HtmlScanner:
    """Follows the HTML tokenizer states that decide what a hole can break."""

    def __init__(self):
        self.state = "text"
        self.tag = ""
        self.attribute = ""
        self.value = ""
        self.end_name = ""
        self.tail = ""
        self._handlers = {
            "text": self._on_text,
            "tag_open": self._on_tag_open,
            "end_tag_open": self._on_end_tag_open,
            "end_tag": self._on_tag_end,
            "bogus_comment": self._on_tag_end,
            "declaration": self._on_declaration,
            "comment": self._on_comment,
            "tag_name": self._on_tag_name,
            "before_attribute": self._on_between_attributes,
            "after_attribute": self._on_between_attributes,
            "attribute_name": self._on_attribute_name,
            "before_value": self._on_before_value,
            "double_quoted": self._on_double_quoted,
            "single_quoted": self._on_single_quoted,
            "unquoted": self._on_unquoted,
            "raw_text": self._on_raw_text,
        }

    def feed(self, text: str) -> None:
        for char in text:
            handler = self._handlers.get(self.state)
            if handler is not None:
                handler(char)

    def _close_start_tag(self) -> None:
        self.tail = ""
        self.end_name = self.tag
        if self.tag in _RAW_TEXT_ELEMENTS:
            self.state = "raw_text"
        elif self.tag == "plaintext":
            self.state = "plaintext"
        else:
            self.state = "text"

    def _on_text(self, char: str) -> None:
        if char == "<":
            self.state = "tag_open"

    def _on_tag_open(self, char: str) -> None:
        if char.isascii() and char.isalpha():
            self.tag = char.lower()
            self.state = "tag_name"
        elif char == "/":
            self.state = "end_tag_open"
        elif char == "!":
            self.tail = ""
            self.state = "declaration"
        elif char == "?":
            self.state = "bogus_comment"
        elif char != "<":
            self.state = "text"

    def _on_end_tag_open(self, char: str) -> None:
        if char == ">":
            self.state = "text"
        else:
            self.state = "end_tag"

    def _on_tag_end(self, char: str) -> None:
        if char == ">":
            self.state = "text"

    def _on_declaration(self, char: str) -> None:
        self.tail += char
        if self.tail == "--":
            self.tail = ""
            self.state = "comment"
        elif not "--".startswith(self.tail):
            self.state = "bogus_comment"
            self._on_tag_end(char)

    def _on_comment(self, char: str) -> None:
        self.tail = (self.tail + char)[-4:]
        if self.tail.endswith("-->") or self.tail.endswith("--!>"):
            self.state = "text"

    def _on_tag_name(self, char: str) -> None:
        if char in _SPACE or char == "/":
            self.state = "before_attribute"
        elif char == ">":
            self._close_start_tag()
        else:
            self.tag += char.lower()

    def _on_between_attributes(self, char: str) -> None:
        if char in _SPACE:
            return
        if char == "/":
            self.state = "before_attribute"
        elif char == ">":
            self._close_start_tag()
        elif char == "=" and self.state == "after_attribute":
            self.state = "before_value"
        else:
            self.attribute = char.lower()
            self.state = "attribute_name"

    def _on_attribute_name(self, char: str) -> None:
        if char in _SPACE:
            self.state = "after_attribute"
        elif char == "/":
            self.state = "before_attribute"
        elif char == "=":
            self.state = "before_value"
        elif char == ">":
            self._close_start_tag()
        else:
            self.attribute += char.lower()

    def _on_before_value(self, char: str) -> None:
        if char in _SPACE:
            return
        self.value = ""
        if char == '"':
            self.state = "double_quoted"
        elif char == "'":
            self.state = "single_quoted"
        elif char == ">":
            self._close_start_tag()
        else:
            self.value = char
            self.state = "unquoted"

    def _on_double_quoted(self, char: str) -> None:
        if char == '"':
            self.state = "before_attribute"
        else:
            self.value += char

    def _on_single_quoted(self, char: str) -> None:
        if char == "'":
            self.state = "before_attribute"
        else:
            self.value += char

    def _on_unquoted(self, char: str) -> None:
        if char in _SPACE:
            self.state = "before_attribute"
        elif char == ">":
            self._close_start_tag()
        else:
            self.value += char

    def _on_raw_text(self, char: str) -> None:
        marker = "</" + self.end_name
        if self.tail.lower() == marker and (char in _SPACE or char in "/>"):
            self.tail = ""
            self.state = "end_tag"
            self._on_tag_end(char)
            return
        self.tail = (self.tail + char)[-len(marker) :]

    def _resource_requirement(self):
        if _UNKNOWN in self.value or _ORIGIN_FIXED.match(_url_start(self.value)):
            return ATTR_SAFE, "a URL attribute"
        return CLEAN, "a URL that loads script or sets the base URL"

    def _url_requirement(self):
        if _UNKNOWN in self.value or safe_url_prefix(self.value):
            return ATTR_SAFE, "a URL attribute"
        return URL_SAFE, "a URL attribute without a scheme allowlist"

    def _attribute_requirement(self):
        name = self.attribute
        if _UNKNOWN in name:
            return CLEAN, "an attribute with a computed name"
        if name.startswith("on"):
            return CLEAN, "an event handler attribute"
        if name in _CODE_ATTRIBUTES:
            return CLEAN, f"a {name} attribute"
        resource = self.tag in _RESOURCE_ELEMENTS or _UNKNOWN in self.tag
        if resource and name in _RESOURCE_ATTRIBUTES:
            return self._resource_requirement()
        if name in _NAVIGATION_ATTRIBUTES or (name == "src" and self.tag in _FRAME_ELEMENTS):
            return self._url_requirement()
        return ATTR_SAFE, "an attribute value"

    def requirement(self):
        if self.state in _TEXT_STATES:
            return TEXT_SAFE, "element text"
        if self.state == "raw_text" and self.end_name in _SCRIPT_ELEMENTS:
            return CLEAN, "a script or style block"
        if self.state == "raw_text":
            return TEXT_SAFE, "element text"
        if self.state in _QUOTED_STATES:
            return self._attribute_requirement()
        return CLEAN, "a tag or an unquoted attribute value"

    def skip_hole(self) -> None:
        """Move past a value of unknown text at the current position."""
        state = self.state
        if state == "tag_open":
            self.tag = _UNKNOWN
            self.state = "tag_name"
        elif state == "tag_name":
            self.tag += _UNKNOWN
        elif state == "end_tag_open":
            self.state = "end_tag"
        elif state in ("before_attribute", "after_attribute", "attribute_name"):
            self.attribute = _UNKNOWN
            self.state = "attribute_name"
        elif state == "before_value":
            self.value = _UNKNOWN
            self.state = "unquoted"
        elif state in ("double_quoted", "single_quoted", "unquoted"):
            self.value += _UNKNOWN
        elif state == "declaration":
            self.state = "bogus_comment"
        elif state == "raw_text":
            self.tail = ""


def hole_requirements(parts):
    """``(level needed, description)`` for each value part, in order."""
    scanner = _HtmlScanner()
    requirements = []
    for part in parts:
        if part[0] == "text":
            scanner.feed(part[1])
        else:
            requirements.append(scanner.requirement())
            scanner.skip_hole()
    return requirements
