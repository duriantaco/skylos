"""Read tool configuration files as data, without running any project code.

JSON, JSONC, YAML, TOML and ``package.json`` keys are parsed. A JS/TS config
is read only when its exported value is a static literal: the evaluator
follows ``export default`` / ``module.exports``, unwraps one
``defineConfig(...)``-style call (or an arrow function that returns an
object), follows top-level ``const`` bindings, and folds strings, numbers,
booleans, arrays, objects, spreads of readable values, ``a + b`` string
concatenation, ``path.join``/``path.resolve(__dirname, ...)`` and
``fileURLToPath(new URL("./x", import.meta.url))``.

Anything else evaluates to :data:`UNKNOWN`. Unknowns are kept per key, so a
config with one computed key still yields its literal keys; an object that
spreads an unknown value is *open* (a missing key may still be set by the
spread), and :func:`lookup` reports such a key as UNKNOWN, never as absent.
Callers must treat UNKNOWN as "may be anything": keep the tool's default
entries and widen abstention. An unreadable config never removes an entry.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
from functools import lru_cache
from pathlib import Path

from skylos.core.safe_cache_io import read_text_no_symlink

MAX_CONFIG_BYTES = 512 * 1024
_MAX_DEPTH = 24

_JS_SUFFIXES = (".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx")
_YAML_SUFFIXES = (".yml", ".yaml")
_STRING_FRAGMENTS = frozenset({"string_fragment", "escape_sequence"})
_DEFINE_CALL_RE = re.compile(r"^(?:[A-Za-z_$][\w$]*\.)?define[A-Z][\w$]*$")
_WRAPPER_NODES = frozenset(
    {
        "parenthesized_expression",
        "as_expression",
        "satisfies_expression",
        "non_null_expression",
        "type_assertion",
    }
)
_PATH_JOIN_CALLS = frozenset({"path.join", "join", "path.posix.join", "posix.join"})
_PATH_RESOLVE_CALLS = frozenset(
    {"path.resolve", "resolve", "path.posix.resolve", "posix.resolve"}
)
_DIRNAME = "\0dirname"


class _Unknown:
    __slots__ = ()

    def __repr__(self) -> str:
        return "UNKNOWN"

    def __bool__(self) -> bool:
        return False


class _Absent:
    __slots__ = ()

    def __repr__(self) -> str:
        return "ABSENT"

    def __bool__(self) -> bool:
        return False


UNKNOWN = _Unknown()
ABSENT = _Absent()


class OpenDict(dict):
    """An object literal that also spreads a value the reader cannot see."""


class JsRegex:
    """A regular-expression literal (``/^@types\\//``) kept as data."""

    __slots__ = ("flags", "pattern")

    def __init__(self, pattern: str, flags: str) -> None:
        self.pattern = pattern
        self.flags = flags

    def __repr__(self) -> str:
        return f"/{self.pattern}/{self.flags}"

    def __eq__(self, other) -> bool:
        return isinstance(other, JsRegex) and (self.pattern, self.flags) == (other.pattern, other.flags)

    def __hash__(self) -> int:
        return hash((self.pattern, self.flags))

    def compile(self):
        """The Python regex, or None when the JS syntax has no equivalent."""
        if set(self.flags) - set("gimsuy"):
            return None
        flags = re.IGNORECASE if "i" in self.flags else 0
        flags |= re.MULTILINE if "m" in self.flags else 0
        flags |= re.DOTALL if "s" in self.flags else 0
        try:
            return re.compile(self.pattern, flags)
        except (re.error, RecursionError):
            return None


def is_unknown(value) -> bool:
    return value is UNKNOWN


def lookup(value, dotted: str):
    """``value[a][b]...`` for ``"a.b"``: the value, ABSENT or UNKNOWN."""
    current = value
    for segment in dotted.split("."):
        if current is UNKNOWN:
            return UNKNOWN
        if not isinstance(current, dict):
            return ABSENT
        if segment in current:
            current = current[segment]
            continue
        return UNKNOWN if isinstance(current, OpenDict) else ABSENT
    return current


def string_values(value) -> tuple[list[str], bool]:
    """Strings of a string or (nested) list value, and whether it was complete.

    An object (``{ import: "./x" }``) contributes its string leaves. Anything
    UNKNOWN anywhere makes the result incomplete.
    """
    found: list[str] = []
    complete = True
    stack = [value]
    seen = 0
    while stack:
        item = stack.pop()
        seen += 1
        if seen > 4096:
            return found, False
        if item is UNKNOWN:
            complete = False
        elif isinstance(item, str):
            found.append(item)
        elif isinstance(item, list):
            stack.extend(reversed(item))
        elif isinstance(item, dict):
            if isinstance(item, OpenDict):
                complete = False
            stack.extend(reversed(list(item.values())))
        elif item is None or isinstance(item, (bool, int, float)):
            continue
        else:
            complete = False
    return found, complete


# ----------------------------------------------------------------- data files


def _strip_jsonc(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments and trailing commas outside strings."""
    out: list[str] = []
    index, length = 0, len(text)
    in_string = False
    while index < length:
        char = text[index]
        if in_string:
            out.append(char)
            if char == "\\" and index + 1 < length:
                out.append(text[index + 1])
                index += 2
                continue
            if char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            index = length if end == -1 else end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = length if end == -1 else end + 2
            continue
        out.append(char)
        index += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _parse_json(text: str):
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        pass
    try:
        return json.loads(_strip_jsonc(text))
    except (ValueError, RecursionError):
        return UNKNOWN


def _parse_yaml(text: str):
    import yaml

    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    try:
        documents = [doc for doc in yaml.load_all(text, Loader=loader) if doc is not None]
    except (yaml.YAMLError, RecursionError, ValueError):
        return UNKNOWN
    if len(documents) != 1:
        return UNKNOWN if documents else {}
    return documents[0]


def _parse_toml(text: str):
    import tomllib

    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError, ValueError):
        return UNKNOWN


def parse_data_config(path: str, text: str):
    """Parse a JSON/JSONC/YAML/TOML config by name; UNKNOWN when it fails."""
    name = os.path.basename(path).lower()
    if name.endswith(".toml"):
        return _parse_toml(text)
    if name.endswith(_YAML_SUFFIXES):
        return _parse_yaml(text)
    if name.endswith((".json", ".jsonc", ".json5")):
        return _parse_json(text)
    # Extensionless rc files (``.mocharc``, ``.babelrc``) are JSON or YAML.
    value = _parse_json(text)
    if value is UNKNOWN:
        value = _parse_yaml(text)
    return value


# -------------------------------------------------------------- JS/TS configs


@lru_cache(maxsize=4)
def _parser(tsx: bool):
    import tree_sitter_typescript as tsts
    from tree_sitter import Language, Parser

    language = Language(tsts.language_tsx() if tsx else tsts.language_typescript())
    return Parser(language)


class _JsEvaluator:
    def __init__(self, source: bytes, root) -> None:
        self.source = source
        self.root = root
        self.bindings: dict[str, object] = {}
        self.imported: set[str] = set()
        self._active: set[str] = set()
        for statement in root.named_children:
            node = statement
            if node.type == "export_statement":
                declaration = node.child_by_field_name("declaration")
                node = declaration if declaration is not None else node
            if node.type in {"lexical_declaration", "variable_declaration"}:
                for declarator in node.named_children:
                    if declarator.type != "variable_declarator":
                        continue
                    name = declarator.child_by_field_name("name")
                    value = declarator.child_by_field_name("value")
                    if name is not None and name.type == "identifier":
                        self.bindings[self.text(name)] = value
            elif node.type == "import_statement":
                for child in _walk(node):
                    if child.type == "identifier":
                        self.imported.add(self.text(child))
        # A binding changed after its declaration (``config.entry = ...``,
        # ``Object.assign(config, ...)``, ``module.exports.x = ...``) is open:
        # its literal shows only part of the final value.
        self.mutated: set[str] = set()
        for node in _walk(root):
            target = None
            if node.type in {"assignment_expression", "augmented_assignment_expression"}:
                left = node.child_by_field_name("left")
                if left is not None and left.type in {"member_expression", "subscript_expression"}:
                    target = left
            elif node.type == "call_expression":
                function = node.child_by_field_name("function")
                arguments = node.child_by_field_name("arguments")
                if (
                    function is not None
                    and self.text(function).replace(" ", "") in {"Object.assign", "Object.defineProperty"}
                    and arguments is not None
                    and arguments.named_children
                ):
                    target = arguments.named_children[0]
            while target is not None and target.type in {"member_expression", "subscript_expression"}:
                if self.text(target).replace(" ", "") == "module.exports":
                    self.mutated.add("module.exports")
                    break
                target = target.child_by_field_name("object")
            if target is not None and target.type == "identifier":
                self.mutated.add(self.text(target))

    def text(self, node) -> str:
        return self.source[node.start_byte : node.end_byte].decode(
            "utf-8", errors="replace"
        )

    # -- exported value

    def exported_node(self):
        candidates = []
        for statement in self.root.named_children:
            if statement.type == "export_statement":
                children = statement.children
                if any(child.type == "default" for child in children):
                    value = statement.child_by_field_name("value")
                    if value is None:
                        named = [c for c in statement.named_children if c.type not in {"comment"}]
                        value = named[-1] if named else None
                    candidates.append(value)
                elif any(child.type == "=" for child in children):
                    # ``export = {...}``
                    named = statement.named_children
                    candidates.append(named[-1] if named else None)
            elif statement.type == "expression_statement":
                expression = statement.named_children[0] if statement.named_children else None
                if expression is None or expression.type != "assignment_expression":
                    continue
                left = expression.child_by_field_name("left")
                if left is not None and self.text(left).replace(" ", "") == "module.exports":
                    candidates.append(expression.child_by_field_name("right"))
        if len(candidates) != 1:
            return None
        return candidates[0]

    def exported_value(self):
        node = self.exported_node()
        if node is None:
            return UNKNOWN
        value = self.evaluate(node)
        if "module.exports" in self.mutated:
            return OpenDict(value) if isinstance(value, dict) else UNKNOWN
        return value

    # -- evaluation

    def evaluate(self, node, depth: int = 0):
        if node is None or depth > _MAX_DEPTH:
            return UNKNOWN
        kind = node.type
        if kind in _WRAPPER_NODES:
            inner = node.named_children[0] if node.named_children else None
            return self.evaluate(inner, depth + 1)
        if kind == "string":
            return "".join(
                self.text(child) for child in node.named_children if child.type in _STRING_FRAGMENTS
            ) if node.named_children else self.text(node)[1:-1]
        if kind == "template_string":
            if any(child.type == "template_substitution" for child in node.named_children):
                return UNKNOWN
            return self.text(node)[1:-1]
        if kind == "number":
            text = self.text(node).replace("_", "")
            try:
                return int(text, 0)
            except ValueError:
                try:
                    return float(text)
                except ValueError:
                    return UNKNOWN
        if kind in {"true", "false"}:
            return kind == "true"
        if kind in {"null", "undefined"}:
            return None
        if kind == "array":
            return self._array(node, depth)
        if kind == "object":
            return self._object(node, depth)
        if kind == "identifier":
            return self._identifier(node, depth)
        if kind == "member_expression":
            return self._member(node, depth)
        if kind == "binary_expression":
            return self._binary(node, depth)
        if kind == "call_expression":
            return self._call(node, depth)
        if kind in {"arrow_function", "function_expression", "function"}:
            return self._function_result(node, depth)
        if kind == "new_expression":
            return self._new_url(node, depth)
        if kind == "regex":
            pattern = node.child_by_field_name("pattern")
            flags = node.child_by_field_name("flags")
            if pattern is None:
                return UNKNOWN
            return JsRegex(self.text(pattern), self.text(flags) if flags is not None else "")
        return UNKNOWN

    def _array(self, node, depth):
        values: list = []
        for child in node.named_children:
            if child.type == "comment":
                continue
            if child.type == "spread_element":
                inner = self.evaluate(child.named_children[0] if child.named_children else None, depth + 1)
                if isinstance(inner, list):
                    values.extend(inner)
                else:
                    values.append(UNKNOWN)
                continue
            values.append(self.evaluate(child, depth + 1))
        return values

    def _object(self, node, depth):
        result: dict = {}
        open_object = False
        for child in node.named_children:
            if child.type == "comment":
                continue
            if child.type == "pair":
                key_node = child.child_by_field_name("key")
                key = self._key(key_node, depth)
                if key is UNKNOWN:
                    open_object = True
                    continue
                result[key] = self.evaluate(child.child_by_field_name("value"), depth + 1)
            elif child.type == "shorthand_property_identifier":
                name = self.text(child)
                result[name] = self._binding(name, depth)
            elif child.type == "spread_element":
                inner = self.evaluate(child.named_children[0] if child.named_children else None, depth + 1)
                if isinstance(inner, dict):
                    open_object = open_object or isinstance(inner, OpenDict)
                    result.update(inner)
                else:
                    open_object = True
            elif child.type == "method_definition":
                key = self._key(child.child_by_field_name("name"), depth)
                if key is UNKNOWN:
                    open_object = True
                else:
                    result[key] = UNKNOWN
            else:
                open_object = True
        return OpenDict(result) if open_object else result

    def _key(self, node, depth):
        if node is None:
            return UNKNOWN
        if node.type in {"property_identifier", "identifier"}:
            return self.text(node)
        if node.type == "string":
            value = self.evaluate(node, depth + 1)
            return value if isinstance(value, str) else UNKNOWN
        if node.type == "number":
            return self.text(node)
        if node.type == "computed_property_name":
            inner = node.named_children[0] if node.named_children else None
            value = self.evaluate(inner, depth + 1)
            return value if isinstance(value, str) else UNKNOWN
        return UNKNOWN

    def _binding(self, name, depth):
        if name == "__dirname":
            return _DIRNAME
        if name == "undefined":
            return None
        if name in self._active or name not in self.bindings or name in self.imported:
            return UNKNOWN
        self._active.add(name)
        try:
            value = self.evaluate(self.bindings[name], depth + 1)
        finally:
            self._active.discard(name)
        if name in self.mutated:
            return OpenDict(value) if isinstance(value, dict) else UNKNOWN
        return value

    def _identifier(self, node, depth):
        return self._binding(self.text(node), depth)

    def _member(self, node, depth):
        text = self.text(node).replace(" ", "")
        if text in {"import.meta.dirname"}:
            return _DIRNAME
        if text == "import.meta.url":
            return UNKNOWN
        target = self.evaluate(node.child_by_field_name("object"), depth + 1)
        prop = node.child_by_field_name("property")
        if prop is None or prop.type != "property_identifier":
            return UNKNOWN
        name = self.text(prop)
        if name == "pathname" and isinstance(target, str) and target.startswith("\0url:"):
            return target[len("\0url:") :]
        if isinstance(target, dict):
            value = lookup(target, name)
            return UNKNOWN if value is ABSENT else value
        return UNKNOWN

    def _binary(self, node, depth):
        operator = node.child_by_field_name("operator")
        if operator is None or self.text(operator) != "+":
            return UNKNOWN
        left = self.evaluate(node.child_by_field_name("left"), depth + 1)
        right = self.evaluate(node.child_by_field_name("right"), depth + 1)
        if left == _DIRNAME and isinstance(right, str) and right.startswith("/"):
            return "." + right
        if isinstance(left, str) and isinstance(right, str) and _DIRNAME not in (left, right):
            return left + right
        return UNKNOWN

    def _arguments(self, node):
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            return []
        return [child for child in arguments.named_children if child.type != "comment"]

    def _call(self, node, depth):
        function = node.child_by_field_name("function")
        if function is None:
            return UNKNOWN
        name = self.text(function).replace(" ", "")
        arguments = self._arguments(node)
        if _DEFINE_CALL_RE.match(name) and len(arguments) == 1:
            return self.evaluate(arguments[0], depth + 1)
        if name in _PATH_JOIN_CALLS or name in _PATH_RESOLVE_CALLS:
            values = [self.evaluate(argument, depth + 1) for argument in arguments]
            if not values or not all(isinstance(value, str) for value in values):
                return UNKNOWN
            if values[0] != _DIRNAME:
                if name in _PATH_RESOLVE_CALLS or any(_DIRNAME in v for v in values):
                    return UNKNOWN
                return posixpath.normpath(posixpath.join(*values))
            rest = values[1:]
            if any(value == _DIRNAME or value.startswith("/") for value in rest):
                return UNKNOWN
            joined = posixpath.normpath(posixpath.join(".", *rest)) if rest else "."
            return joined if joined.startswith(".") else "./" + joined
        if name in {"fileURLToPath", "url.fileURLToPath"} and len(arguments) == 1:
            value = self.evaluate(arguments[0], depth + 1)
            if isinstance(value, str) and value.startswith("\0url:"):
                return value[len("\0url:") :]
            return UNKNOWN
        return UNKNOWN

    def _function_result(self, node, depth):
        body = node.child_by_field_name("body")
        if body is None:
            return UNKNOWN
        if body.type != "statement_block":
            return self.evaluate(body, depth + 1)
        statements = [child for child in body.named_children if child.type != "comment"]
        if len(statements) == 1 and statements[0].type == "return_statement":
            value = statements[0].named_children
            return self.evaluate(value[0] if value else None, depth + 1)
        return UNKNOWN

    def _new_url(self, node, depth):
        """``new URL("./x", import.meta.url)``: a path relative to the config."""
        constructor = node.child_by_field_name("constructor")
        if constructor is None or self.text(constructor) != "URL":
            return UNKNOWN
        values = self._arguments(node)
        if len(values) != 2 or self.text(values[1]).replace(" ", "") != "import.meta.url":
            return UNKNOWN
        first = self.evaluate(values[0], depth + 1)
        if not isinstance(first, str) or not first.startswith("."):
            return UNKNOWN
        return "\0url:" + first


def _walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(current.named_children)


def evaluate_js_config(path: str, source: bytes):
    """The static value a JS/TS config exports, or UNKNOWN."""
    from .core import parse_typescript_source

    suffix = Path(path).suffix.lower()
    tsx = suffix in {".js", ".jsx", ".tsx", ".mjs", ".cjs"}
    try:
        parser = _parser(tsx)
        tree = parse_typescript_source(parser, source, file_path=str(path), jsx=tsx)
    except Exception:  # noqa: BLE001 - a parser failure is an unknown config
        return UNKNOWN
    evaluator = _JsEvaluator(source, tree.root_node)
    return _finalise(evaluator.exported_value())


def _finalise(value):
    """Drop internal markers that escaped into the result."""
    if isinstance(value, str):
        if value == _DIRNAME:
            return "."
        if value.startswith("\0"):
            return UNKNOWN
        return value
    if isinstance(value, list):
        return [_finalise(item) for item in value]
    if isinstance(value, OpenDict):
        return OpenDict({key: _finalise(item) for key, item in value.items()})
    if isinstance(value, dict):
        return {key: _finalise(item) for key, item in value.items()}
    return value


# ------------------------------------------------------------------ entry point


@lru_cache(maxsize=2048)
def _read_cached(path: str, mtime_ns: int, size: int, package_json_key: str | None):
    if size > MAX_CONFIG_BYTES:
        return UNKNOWN
    text = read_text_no_symlink(path, max_bytes=MAX_CONFIG_BYTES, errors="replace")
    if text is None:
        return UNKNOWN
    name = os.path.basename(path)
    if name == "package.json":
        data = _parse_json(text)
        if not isinstance(data, dict):
            return UNKNOWN
        if package_json_key is None:
            return data
        return lookup(data, package_json_key)
    if name.lower().endswith(_JS_SUFFIXES):
        return evaluate_js_config(path, text.encode("utf-8"))
    return parse_data_config(path, text)


def read_static_config(path: str | os.PathLike[str], package_json_key: str | None = None):
    """The config's value as plain data, ABSENT for a missing package.json
    key, or UNKNOWN when it cannot be read without running code."""
    path = os.fspath(path)
    try:
        stat = os.stat(path)
    except OSError:
        return UNKNOWN
    return _read_cached(path, stat.st_mtime_ns, stat.st_size, package_json_key)
