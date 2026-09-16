"""Bounded, source-set-local Java Properties.load(InputStream) resources.

Resource contents are static evidence, not classpath or deployment guarantees.
Unsupported layouts, unreadable inputs, and exhausted budgets stay unknown.
"""

from __future__ import annotations

from pathlib import Path
import re

from skylos.core.safe_cache_io import read_project_text_no_symlink


MAX_PROPERTY_FILES = 16
MAX_PROPERTY_FILE_BYTES = 64 * 1024
MAX_PROPERTY_TOTAL_BYTES = 512 * 1024
MAX_PROPERTY_ENTRIES = 2048
MAX_PROPERTY_COMPONENT_CHARS = 4096
MAX_PROPERTY_LOGICAL_LINE_CHARS = 16 * 1024
MAX_PROPERTY_NATURAL_LINES = 8192
MAX_RESOURCE_NAME_CHARS = 1024
MAX_RESOURCE_SEGMENTS = 64
MAX_CALLER_ANCESTORS = 64

_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_HEX = frozenset("0123456789abcdefABCDEF")
_WHITESPACE = " \t\f"
_PROJECT_MARKERS = (
    ".git",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
)


def _decode_component(raw: str) -> str:
    result = []
    position = 0
    while position < len(raw):
        char = raw[position]
        position += 1
        if char == "\\":
            if position == len(raw):
                raise ValueError("Dangling properties escape")
            char = raw[position]
            position += 1
            if char == "u":
                digits = raw[position : position + 4]
                if len(digits) != 4 or any(digit not in _HEX for digit in digits):
                    raise ValueError("Malformed properties Unicode escape")
                char = chr(int(digits, 16))
                position += 4
            else:
                char = {"t": "\t", "r": "\r", "n": "\n", "f": "\f"}.get(char, char)
        result.append(char)
        if len(result) > MAX_PROPERTY_COMPONENT_CHARS:
            raise ValueError("Properties component limit exceeded")
    return "".join(result)


def _logical_lines(text: str):
    # Only CR/LF terminate Java properties lines; str.splitlines() also splits
    # form feed and Latin-1 NEL, which are data here.
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if len(lines) > MAX_PROPERTY_NATURAL_LINES:
        raise ValueError("Properties natural-line limit exceeded")
    fragments: list[str] = []
    size = 0
    for index, natural in enumerate(lines):
        part = natural.lstrip(_WHITESPACE)
        if size == 0 and (not part or part.startswith(("#", "!"))):
            fragments.clear()
            continue
        slashes = len(part) - len(part.rstrip("\\"))
        continued = bool(slashes % 2)
        if continued:
            part = part[:-1]
        fragments.append(part)
        size += len(part)
        if size > MAX_PROPERTY_LOGICAL_LINE_CHARS:
            raise ValueError("Properties logical-line limit exceeded")
        at_end = index == len(lines) - 1 or (index == len(lines) - 2 and not lines[-1])
        if continued and not at_end:
            continue
        yield "".join(fragments)
        fragments.clear()
        size = 0


def _parse_properties(text: str) -> dict[str, str] | None:
    """Parse all input or return unknown; never return a partial property map."""
    if len(text) > MAX_PROPERTY_FILE_BYTES:
        return None
    properties: dict[str, str] = {}
    records = 0
    try:
        for line in _logical_lines(text):
            records += 1
            if records > MAX_PROPERTY_ENTRIES:
                raise ValueError("Properties entry limit exceeded")
            key_end = 0
            escaped = False
            while key_end < len(line):
                char = line[key_end]
                if not escaped and char in "=:" + _WHITESPACE:
                    break
                escaped = char == "\\" and not escaped
                key_end += 1
            value_start = key_end
            while value_start < len(line) and line[value_start] in _WHITESPACE:
                value_start += 1
            if value_start < len(line) and line[value_start] in "=:":
                value_start += 1
            while value_start < len(line) and line[value_start] in _WHITESPACE:
                value_start += 1
            key = _decode_component(line[:key_end])
            properties[key] = _decode_component(line[value_start:])
    except ValueError:
        return None
    return properties


def _has_project_marker(directory: Path) -> bool:
    return any(
        (directory / marker).exists() or (directory / marker).is_symlink()
        for marker in _PROJECT_MARKERS
    )


class JavaPropertyResources:
    """Resolve exact ClassLoader resource names from one verified source set."""

    def __init__(self, file_path: str, package_name: str) -> None:
        self._source_set: Path | None = None
        self._cache: dict[str, dict[str, str] | None] = {}
        self._bytes_read = 0
        self.limit_reached = False
        try:
            self._source_set = self._verified_source_set(file_path, package_name)
        except (OSError, RuntimeError, ValueError):
            pass

    @staticmethod
    def _verified_source_set(file_path: str, package_name: str) -> Path | None:
        if not isinstance(package_name, str) or len(package_name) > 1024:
            return None
        parts = package_name.split(".") if package_name else []
        if len(parts) > MAX_CALLER_ANCESTORS - 4 or any(
            _IDENTIFIER.fullmatch(part) is None for part in parts
        ):
            return None
        caller = Path(file_path).absolute()
        if (
            caller.suffix != ".java"
            or ".." in caller.parts
            or caller.is_symlink()
            or not caller.is_file()
        ):
            return None
        current = caller.parent
        for component in reversed(parts):
            if (
                current.name != component
                or current.is_symlink()
                or _has_project_marker(current)
            ):
                return None
            current = current.parent
        if not (
            current.name == "java"
            and current.parent.name in {"main", "test"}
            and current.parent.parent.name == "src"
        ):
            return None
        source_set = current.parent
        for directory in (current, source_set, source_set.parent):
            if directory.is_symlink() or _has_project_marker(directory):
                return None
        if source_set.parent.parent.is_symlink():
            return None
        return source_set.resolve(strict=True)

    def load(self, resource_name: str) -> dict[str, str] | None:
        """Return a fresh map, valid empty map, or unknown (None)."""
        if self._source_set is None or not isinstance(resource_name, str):
            return None
        if (
            not resource_name
            or len(resource_name) > MAX_RESOURCE_NAME_CHARS
            or any(char in resource_name for char in ("\\", "\0", ":"))
        ):
            return None
        parts = resource_name.split("/")
        if len(parts) > MAX_RESOURCE_SEGMENTS or any(
            part in {"", ".", ".."} for part in parts
        ):
            return None
        if resource_name in self._cache:
            cached = self._cache[resource_name]
            return None if cached is None else dict(cached)
        if len(self._cache) >= MAX_PROPERTY_FILES:
            self.limit_reached = True
            return None
        # Negative lookups consume the same bounded file budget as successes.
        self._cache[resource_name] = None
        remaining = MAX_PROPERTY_TOTAL_BYTES - self._bytes_read
        if remaining <= 0:
            self.limit_reached = True
            return None
        try:
            current = self._source_set / "resources"
            for component in (None, *parts[:-1]):
                if component is not None:
                    current = current / component
                if (
                    current.is_symlink()
                    or not current.is_dir()
                    or _has_project_marker(current)
                ):
                    return None
            candidate = current / parts[-1]
            text = read_project_text_no_symlink(
                self._source_set,
                candidate,
                max_bytes=min(MAX_PROPERTY_FILE_BYTES, remaining),
                encoding="latin-1",
                newline="",
            )
        except (OSError, RuntimeError, ValueError):
            return None
        if text is None:
            return None
        self._bytes_read += len(text)
        properties = _parse_properties(text)
        self._cache[resource_name] = properties
        return None if properties is None else dict(properties)
