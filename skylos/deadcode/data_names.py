from __future__ import annotations

import csv
import io
import re
from html.parser import HTMLParser

_NAME_PATH_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:[.:][A-Za-z_][A-Za-z0-9_]*)*")
_ESCAPE_RE = re.compile(
    r"\\(?:u\{([0-9A-Fa-f]{1,6})\}|u([0-9A-Fa-f]{4})|x([0-9A-Fa-f]{2})|(.))", re.S
)
_QUOTED_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"|\'((?:[^\'\\\n]|\\.)*)\'')
_TEMPLATE_TAG_RE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.S)
_INI_ENTRY_RE = re.compile(r"\s*([^=:#;\s][^=:]*?)\s*[=:]\s*(.*)")
_TOML_KEY_RE = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*=", re.M)
_TOML_TABLE_RE = re.compile(r"^\s*\[+\s*([A-Za-z0-9_.-]+)\s*\]+", re.M)
_REGEX_PRECEDERS = frozenset("(,=:[!&|?{};+-*%<>~^")

_JSON_SUFFIXES = frozenset({".json", ".jsonc", ".json5"})
_YAML_SUFFIXES = frozenset({".yaml", ".yml"})
_INI_SUFFIXES = frozenset({".ini", ".cfg", ".conf"})
_MARKUP_SUFFIXES = frozenset(
    {".html", ".htm", ".jinja", ".jinja2", ".j2", ".vue", ".svelte"}
)
_SCRIPT_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"})


def names_in_value(value: str) -> set[str]:
    names = set()
    for item in value.split(","):
        item = item.strip()
        if _NAME_PATH_RE.fullmatch(item):
            names.add(re.split(r"[.:]", item)[-1])
    return names


_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def names_in_data(suffix: str, text: str) -> set[str]:
    try:
        return _names_in_data(suffix.lower(), text)
    except (ValueError, RecursionError, UnicodeError):
        return set(_WORD_RE.findall(text))


def _names_in_data(suffix: str, text: str) -> set[str]:
    if suffix in _JSON_SUFFIXES:
        return _names_in_values(_quoted_strings(text))
    if suffix in _YAML_SUFFIXES:
        return _names_in_values(_yaml_scalars(text))
    if suffix == ".toml":
        return _names_in_values(_toml_values(text))
    if suffix in _INI_SUFFIXES:
        return _names_in_values(_ini_values(text))
    if suffix == ".csv":
        return _names_in_values(_csv_cells(text))
    if suffix == ".xml":
        return _names_in_values(_markup_values(text, include_text=True))
    if suffix in _MARKUP_SUFFIXES:
        return _names_in_values(_markup_values(text, include_text=False))
    if suffix in _SCRIPT_SUFFIXES:
        return _names_in_values(script_strings(text))
    return set()


def _names_in_values(values) -> set[str]:
    names: set[str] = set()
    for value in values:
        names |= names_in_value(value)
    return names


def _quoted_strings(text: str) -> list[str]:
    return [
        _unescaped(double or single) for double, single in _QUOTED_RE.findall(text)
    ]


def _unescaped(value: str) -> str:
    if "\\" not in value:
        return value
    return _ESCAPE_RE.sub(_escape_value, value)


def _escape_value(match: re.Match) -> str:
    code = match.group(1) or match.group(2) or match.group(3)
    if code is None:
        return match.group(4)
    point = int(code, 16)
    if point > 0x10FFFF:
        return match.group(0)
    return chr(point)


def _yaml_scalars(text: str) -> list[str]:
    import yaml

    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    values = []
    try:
        for token in yaml.scan(text, Loader=loader):
            if isinstance(token, yaml.ScalarToken):
                values.append(token.value)
    except (yaml.YAMLError, ValueError, RecursionError):
        pass
    return values


def _toml_parser():
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib
        except ModuleNotFoundError:
            return None
    return tomllib


def _toml_values(text: str) -> list[str]:
    parser = _toml_parser()
    if parser is not None:
        try:
            return list(_toml_strings(parser.loads(text)))
        except (ValueError, RecursionError):
            pass
    return (
        _quoted_strings(text)
        + _TOML_KEY_RE.findall(text)
        + _TOML_TABLE_RE.findall(text)
    )


def _toml_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _toml_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _toml_strings(item)


def _ini_values(text: str) -> list[str]:
    values = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped[0] in "#;":
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            values.append(stripped[1:-1])
            continue
        entry = _INI_ENTRY_RE.fullmatch(line)
        if entry is not None and not line[:1].isspace():
            values.append(entry.group(1))
            values.append(_unquoted(entry.group(2)))
        else:
            values.append(_unquoted(stripped))
    return values


def _unquoted(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _csv_cells(text: str) -> list[str]:
    cells = []
    try:
        for row in csv.reader(io.StringIO(text)):
            cells.extend(row)
    except csv.Error:
        pass
    return cells


class _MarkupValues(HTMLParser):
    def __init__(self, include_text: bool) -> None:
        super().__init__(convert_charrefs=True)
        self.include_text = include_text
        self.values: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        self._in_script = tag.lower() == "script"
        for _name, value in attrs:
            if value is not None:
                self.values.append(value)
                self.values.extend(script_strings(value))

    def handle_endtag(self, tag):
        if tag.lower() == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self.values.extend(script_strings(data))
        elif self.include_text:
            self.values.append(data)


def _markup_values(text: str, *, include_text: bool) -> list[str]:
    parser = _MarkupValues(include_text)
    try:
        parser.feed(text)
        parser.close()
    except (ValueError, RecursionError, AssertionError):
        pass
    values = parser.values
    for tag in _TEMPLATE_TAG_RE.findall(text):
        values.extend(_quoted_strings(tag))
    return values


def script_strings(text: str) -> list[str]:
    strings = []
    index = 0
    previous = ""
    length = len(text)
    while index < length:
        char = text[index]
        if text.startswith("//", index):
            end = text.find("\n", index)
            if end < 0:
                break
            index = end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                break
            index = end + 2
            continue
        if char in "\"'":
            end = _string_end(text, index + 1, char)
            strings.append(_unescaped(text[index + 1 : end - 1]))
            index = end
            previous = char
            continue
        if char == "`":
            end = _string_end(text, index + 1, "`")
            body = text[index + 1 : end - 1]
            if "${" not in body:
                strings.append(_unescaped(body))
            index = end
            previous = char
            continue
        if char == "/" and (not previous or previous in _REGEX_PRECEDERS):
            index = _regex_end(text, index + 1)
            previous = "/"
            continue
        if not char.isspace():
            previous = char
        index += 1
    return strings


def _string_end(text: str, index: int, quote: str) -> int:
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == quote:
            return index + 1
        if char == "\n" and quote != "`":
            return index + 1
        index += 1
    return len(text)


def _regex_end(text: str, index: int) -> int:
    in_class = False
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == "\n":
            return index
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            return index + 1
        index += 1
    return len(text)
