"""Bounded, source-only summaries for directly referenced local Java helpers.

Only exact imports, qualified names, and same-package classes beneath a
package-verified source root are considered. Unknown helpers never prove safety.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
from typing import TYPE_CHECKING

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.visitors.languages.java.core import JAVA_LANG, _get_parser

if TYPE_CHECKING:
    from skylos.visitors.languages.java.flow import JavaHelperSummary


MAX_HELPER_FILES = 32
MAX_HELPER_SOURCE_BYTES = 256 * 1024
MAX_HELPER_TOTAL_BYTES = 2 * 1024 * 1024
MAX_HELPER_METHODS = 256
MAX_HELPER_FIELDS = 128
MAX_HELPER_NODES = 50_000
MAX_HELPER_IMPORTS = 256
MAX_HELPER_TYPES = 128
MAX_QUALIFIED_NAME_CHARS = 1024
MAX_PACKAGE_SEGMENTS = 64
MAX_SOURCE_ROOT_ANCESTORS = 64

_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_TYPE_DECLARATIONS = {
    "class_declaration",
    "interface_declaration",
    "enum_declaration",
    "record_declaration",
    "annotation_type_declaration",
}
_PROJECT_MARKERS = (
    ".git",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
)


def _qualified_parts(name: str) -> tuple[str, ...] | None:
    if not name or len(name) > MAX_QUALIFIED_NAME_CHARS:
        return None
    parts = tuple(name.split("."))
    if len(parts) > MAX_PACKAGE_SEGMENTS or any(
        _IDENTIFIER.fullmatch(part) is None for part in parts
    ):
        return None
    return parts


def _text(source: bytes, node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="strict")


def _package_name(root_node, source: bytes) -> str | None:
    declarations = [
        node for node in root_node.named_children if node.type == "package_declaration"
    ]
    if not declarations:
        return ""
    if len(declarations) != 1:
        return None
    names = [
        node
        for node in declarations[0].named_children
        if node.type in {"identifier", "scoped_identifier"}
    ]
    if len(names) != 1:
        return None
    name = _text(source, names[0])
    return name if _qualified_parts(name) is not None else None


def _bounded_nodes(root_node):
    stack = [root_node]
    count = 0
    while stack:
        node = stack.pop()
        count += 1
        if count > MAX_HELPER_NODES:
            raise ValueError("Java helper node limit exceeded")
        yield node
        stack.extend(reversed(node.named_children))


class JavaSourceHelpers:
    def __init__(self, root_node, file_path: str, source_bytes: bytes) -> None:
        self.package_name: str | None = None
        self._root: Path | None = None
        self._caller_path: Path | None = None
        self._same_package_only = False
        self._imports: dict[str, set[str]] = {}
        self._blocked_names: set[str] = set()
        self._local_types: Counter[str] = Counter()
        self._top_level_types: set[str] = set()
        self._cache: dict[str, dict[tuple[str, int], JavaHelperSummary]] = {}
        self._bytes_read = 0
        self.limit_reached = False
        self._names_valid = False
        if root_node is None or root_node.has_error:
            return
        try:
            self.package_name = _package_name(root_node, source_bytes)
            if self.package_name is None:
                return
            self._collect_names(root_node, source_bytes)
            self._names_valid = True
            self._root, self._caller_path = self._source_root(file_path)
        except (OSError, UnicodeError, ValueError):
            self._root = None
            self._imports.clear()
            self._blocked_names.clear()
            self._local_types.clear()
            self._top_level_types.clear()
            self._names_valid = False

    def matches_type(self, raw_type: str, qualified_name: str) -> bool:
        """Match an exact imported/qualified type without simple-name guessing."""
        return self._names_valid and self._resolve_type(raw_type) == qualified_name

    def local_type_name(self, raw_type: str) -> str | None:
        """Resolve only unambiguous types declared in the caller source file."""
        parts = _qualified_parts(raw_type)
        if parts is None:
            return None
        simple_name = parts[-1]
        if self._local_types[simple_name] != 1:
            return None
        if len(parts) == 1:
            return simple_name
        if simple_name not in self._top_level_types:
            return None
        qualified_name = (
            f"{self.package_name}.{simple_name}" if self.package_name else simple_name
        )
        return simple_name if raw_type == qualified_name else None

    def summary(
        self, raw_type: str, method: str, arity: int
    ) -> JavaHelperSummary | None:
        """Return positive local-source evidence, never an external safety proof."""
        if self._root is None or arity < 0 or _IDENTIFIER.fullmatch(method) is None:
            return None
        qualified_name = self._resolve_type(raw_type)
        if qualified_name is None:
            return None
        if (
            self._same_package_only
            and qualified_name.rpartition(".")[0] != self.package_name
        ):
            return None
        if qualified_name not in self._cache:
            if len(self._cache) >= MAX_HELPER_FILES:
                self.limit_reached = True
                return None
            # Cache failed lookups as well, and never recursively resolve helpers.
            self._cache[qualified_name] = {}
            self._cache[qualified_name] = self._load_summaries(qualified_name)
        return self._cache[qualified_name].get((method, arity))

    def _collect_names(self, root_node, source: bytes) -> None:
        import_count = 0
        for node in root_node.named_children:
            if node.type in _TYPE_DECLARATIONS:
                name_node = node.child_by_field_name("name")
                if name_node is not None:
                    self._top_level_types.add(_text(source, name_node))
            if node.type != "import_declaration":
                continue
            import_count += 1
            if import_count > MAX_HELPER_IMPORTS:
                raise ValueError("Java helper import limit exceeded")
            if any(child.type == "asterisk" for child in node.named_children):
                continue
            names = [
                child
                for child in node.named_children
                if child.type in {"identifier", "scoped_identifier"}
            ]
            if len(names) != 1:
                raise ValueError("Ambiguous Java import")
            qualified_name = _text(source, names[0])
            parts = _qualified_parts(qualified_name)
            if parts is None or len(parts) < 2:
                raise ValueError("Unsupported Java import")
            if any(child.type == "static" for child in node.children):
                self._blocked_names.add(parts[-1])
                continue
            self._imports.setdefault(parts[-1], set()).add(qualified_name)
        for node in _bounded_nodes(root_node):
            if node.type not in _TYPE_DECLARATIONS:
                continue
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                self._local_types[_text(source, name_node)] += 1
            if self._local_types.total() > MAX_HELPER_TYPES:
                raise ValueError("Java helper type limit exceeded")

    def _source_root(self, file_path: str) -> tuple[Path | None, Path | None]:
        caller = Path(file_path).absolute()
        if caller.suffix != ".java" or ".." in caller.parts:
            return None, None
        package_parts = self.package_name.split(".") if self.package_name else []
        current = caller.parent
        if caller.is_symlink() or not caller.is_file():
            return None, None
        for component in reversed(package_parts):
            if current.name != component or current.is_symlink():
                return None, None
            current = current.parent
        if current.is_symlink() or current.parent == current:
            return None, None
        root = current.resolve(strict=True)
        boundary = self._source_boundary(caller.parent)
        if boundary is not None:
            try:
                root.relative_to(boundary.resolve(strict=True))
            except ValueError:
                return None, None
        # Package text alone is not authority to search across a repository or
        # filesystem. Without an anchor, only the caller's sibling source files
        # are eligible. Default-package helpers likewise stay in one directory.
        self._same_package_only = boundary is None or not self.package_name
        return root, root.joinpath(*package_parts, caller.name)

    @staticmethod
    def _source_boundary(directory: Path) -> Path | None:
        current = directory
        for _ in range(MAX_SOURCE_ROOT_ANCESTORS):
            if (
                current.name == "java"
                and current.parent.name in {"main", "test"}
                and current.parent.parent.name == "src"
            ):
                return current
            if any(
                (current / marker).is_file() or (current / marker).is_dir()
                for marker in _PROJECT_MARKERS
            ):
                return current
            if current.parent == current:
                return None
            current = current.parent
        return None

    def _resolve_type(self, raw_type: str) -> str | None:
        parts = _qualified_parts(raw_type)
        if parts is None:
            return None
        if len(parts) > 1:
            # A leading local type makes this a nested-type reference, not a
            # package-qualified class. Nested ownership is outside this slice.
            if parts[0] in self._local_types or parts[0] in self._imports:
                return None
            return raw_type
        simple_name = parts[0]
        if simple_name in self._local_types or simple_name in self._blocked_names:
            return None
        imports = self._imports.get(simple_name, set())
        if imports:
            return next(iter(imports)) if len(imports) == 1 else None
        return (
            f"{self.package_name}.{simple_name}" if self.package_name else simple_name
        )

    def _load_summaries(self, qualified_name: str) -> dict:
        parts = _qualified_parts(qualified_name)
        if parts is None or self._root is None or JAVA_LANG is None:
            return {}
        candidate = self._root.joinpath(*parts[:-1], f"{parts[-1]}.java")
        if candidate == self._caller_path:
            return {}
        boundary = self._source_boundary(candidate.parent)
        if boundary is not None:
            try:
                self._root.relative_to(boundary)
            except ValueError:
                return {}
        remaining = MAX_HELPER_TOTAL_BYTES - self._bytes_read
        if remaining <= 0:
            self.limit_reached = True
            return {}
        source_text = read_project_text_no_symlink(
            self._root,
            candidate,
            max_bytes=min(MAX_HELPER_SOURCE_BYTES, remaining),
            encoding="utf-8",
        )
        if source_text is None:
            return {}
        source = source_text.encode("utf-8")
        self._bytes_read += len(source)
        try:
            root_node = _get_parser(JAVA_LANG).parse(source).root_node
            if root_node.has_error or _package_name(root_node, source) != ".".join(
                parts[:-1]
            ):
                return {}
            if not self._valid_helper(root_node, source, parts[-1]):
                return {}
            from skylos.visitors.languages.java.flow import JavaSecurityFlowAnalyzer

            analyzer = JavaSecurityFlowAnalyzer(
                root_node, str(candidate), source, enable_source_helpers=False
            )
            signatures: Counter[tuple[str, int]] = Counter()
            for method_node in analyzer._method_nodes():
                if (
                    method_node.type != "method_declaration"
                    or analyzer._class_name_for_node(method_node) != parts[-1]
                ):
                    continue
                method_name = analyzer._method_name(method_node)
                if method_name:
                    signatures[
                        (method_name, len(analyzer._formal_parameters(method_node)))
                    ] += 1
            summaries = analyzer._collect_helper_summaries()
            # Argument-only propagation is already covered by the normal call
            # fallback. Returning such a summary would discard receiver taint
            # and could turn this source lookup into an unintended safety proof.
            return {
                (method, arity): summary
                for (class_name, method, arity), summary in summaries.items()
                if class_name == parts[-1]
                and signatures[(method, arity)] == 1
                and summary.returns_request_source
            }
        except (RecursionError, UnicodeError, ValueError):
            return {}

    @staticmethod
    def _valid_helper(root_node, source: bytes, expected_name: str) -> bool:
        matches = []
        methods = 0
        fields = 0
        for node in _bounded_nodes(root_node):
            if node.type == "method_declaration":
                methods += 1
            elif node.type == "field_declaration":
                fields += len(node.children_by_field_name("declarator"))
            elif node.type in _TYPE_DECLARATIONS:
                name_node = node.child_by_field_name("name")
                if name_node is not None and _text(source, name_node) == expected_name:
                    matches.append(node)
            if methods > MAX_HELPER_METHODS or fields > MAX_HELPER_FIELDS:
                return False
        return len(matches) == 1 and matches[0].parent == root_node
