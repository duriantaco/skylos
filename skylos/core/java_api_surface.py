from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from skylos.core.file_discovery import should_exclude_path
from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.visitors.languages.java.core import JAVA_LANG, _get_parser


MAX_JAVA_SOURCE_BYTES = 2 * 1024 * 1024
MAX_JAVA_SURFACE_FILES = 5_000

_SKIP_DIRECTORIES = {
    ".git",
    ".gradle",
    ".idea",
    "build",
    "node_modules",
    "out",
    "target",
    "vendor",
}

_TYPE_NODE_TYPES = {
    "annotation_type_declaration",
    "class_declaration",
    "enum_declaration",
    "interface_declaration",
    "record_declaration",
}

_INHERITANCE_NODE_TYPES = {
    "extends_interfaces",
    "super_interfaces",
    "superclass",
}

_KNOWN_CODEGEN_ANNOTATIONS = {
    "AutoValue",
    "Builder",
    "Data",
    "GenerateImmutable",
    "Immutable",
    "UtilityClass",
    "Value",
}

_JAVA_BUILD_MARKERS = {
    "build.gradle",
    "build.gradle.kts",
    "pom.xml",
    "settings.gradle",
    "settings.gradle.kts",
}

_JAVA_TEST_SOURCE_SETS = {
    "androidtest",
    "functionaltest",
    "integrationtest",
    "test",
    "testfixtures",
}


@dataclass(frozen=True)
class JavaParsedFile:
    path: Path
    source: bytes
    root_node: Any
    package_name: str
    source_set: str
    module_root: Path


@dataclass(frozen=True)
class JavaMemberSurface:
    name: str
    kind: str
    visibility: str
    file: Path
    line: int


@dataclass(frozen=True)
class JavaTypeSurface:
    qualified_name: str
    simple_name: str
    package_name: str
    source_set: str
    module_root: Path
    file: Path
    members: dict[str, tuple[JavaMemberSurface, ...]]
    complete: bool
    incomplete_reasons: tuple[str, ...]


@dataclass(frozen=True)
class JavaSurfaceIndex:
    types: dict[str, JavaTypeSurface]
    packages: frozenset[str]
    global_reasons: tuple[str, ...]
    ambiguous_types: frozenset[str]

    def type_surface(self, qualified_name: str) -> JavaTypeSurface | None:
        return self.types.get(qualified_name)

    def package_is_local(self, package_name: str) -> bool:
        return package_name in self.packages

    def proof_reason(self, surface: JavaTypeSurface | None = None) -> str | None:
        if self.global_reasons:
            return self.global_reasons[0]
        if surface is not None and not surface.complete:
            return surface.incomplete_reasons[0]
        return None


def java_source_sets_compatible(importer: str, surface: str) -> bool:
    if importer == "test":
        return surface in {"main", "test"}
    return importer == "main" and surface == "main"


def java_module_roots_compatible(importer: Path, surface: Path) -> bool:
    return importer == surface


def safe_java_files(root: Path, files: Iterable[str | Path]) -> list[Path]:
    selected: set[Path] = set()
    for value in files:
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved = _safe_contained_file(root, candidate)
        if resolved is not None and resolved.suffix == ".java":
            selected.add(resolved)
    return sorted(selected, key=str)


def parse_java_file(
    path: Path,
    *,
    root: Path | None = None,
) -> tuple[JavaParsedFile | None, str | None]:
    if JAVA_LANG is None:
        return None, "parser_unavailable"
    source_text = read_text_no_symlink(
        path,
        max_bytes=MAX_JAVA_SOURCE_BYTES,
        encoding="utf-8",
        errors="replace",
    )
    if source_text is None:
        return None, "source_unreadable"
    source = source_text.encode("utf-8", errors="replace")
    root_node = _get_parser(JAVA_LANG).parse(source).root_node
    if root_node.has_error:
        return None, "parse_error"
    return (
        JavaParsedFile(
            path=path,
            source=source,
            root_node=root_node,
            package_name=_package_name(root_node, source),
            source_set=_java_source_set(root or path.parent, path),
            module_root=_java_module_root(root or path.parent, path),
        ),
        None,
    )


def build_java_surface_index(
    root: Path,
    selected_files: Iterable[Path],
    *,
    discover_workspace: bool = True,
    exclude_folders: Sequence[str] | None = None,
) -> JavaSurfaceIndex:
    files, discovery_reason = _discover_java_files(
        root,
        selected_files,
        discover_workspace=discover_workspace,
        exclude_folders=exclude_folders,
    )
    surfaces: dict[str, JavaTypeSurface] = {}
    packages: set[str] = set()
    ambiguous: set[str] = set()
    global_reasons: set[str] = set()
    if discovery_reason:
        global_reasons.add(discovery_reason)

    for path in files:
        parsed, reason = parse_java_file(path, root=root)
        if parsed is None:
            global_reasons.add(reason or "parse_error")
            continue
        packages.add(parsed.package_name)
        for surface in _file_type_surfaces(parsed):
            if surface.qualified_name in surfaces:
                ambiguous.add(surface.qualified_name)
                continue
            surfaces[surface.qualified_name] = surface

    for qualified_name in ambiguous:
        surfaces.pop(qualified_name, None)
    return JavaSurfaceIndex(
        types=surfaces,
        packages=frozenset(packages),
        global_reasons=tuple(sorted(global_reasons)),
        ambiguous_types=frozenset(ambiguous),
    )


def node_text(parsed: JavaParsedFile, node: Any) -> str:
    return parsed.source[node.start_byte : node.end_byte].decode(
        "utf-8", errors="replace"
    )


def iter_nodes(node: Any) -> Iterable[Any]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def _discover_java_files(
    root: Path,
    selected_files: Iterable[Path],
    *,
    discover_workspace: bool,
    exclude_folders: Sequence[str] | None,
) -> tuple[list[Path], str | None]:
    discovered = set(safe_java_files(root, selected_files))
    if not discover_workspace:
        return sorted(discovered, key=str), None
    discovery_reason = "excluded_workspace_paths" if exclude_folders else None
    for directory, names, files in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        names[:] = [
            name
            for name in names
            if name not in _SKIP_DIRECTORIES
            and not (directory_path / name).is_symlink()
            and not should_exclude_path(
                directory_path / name,
                root,
                exclude_folders,
            )
        ]
        for name in files:
            if not name.endswith(".java"):
                continue
            if should_exclude_path(directory_path / name, root, exclude_folders):
                continue
            resolved = _safe_contained_file(root, directory_path / name)
            if resolved is not None:
                discovered.add(resolved)
            if len(discovered) > MAX_JAVA_SURFACE_FILES:
                return sorted(discovered, key=str), "source_file_limit"
    return sorted(discovered, key=str), discovery_reason


def _file_type_surfaces(parsed: JavaParsedFile) -> list[JavaTypeSurface]:
    surfaces = []
    for node in parsed.root_node.named_children:
        if node.type not in _TYPE_NODE_TYPES:
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        simple_name = node_text(parsed, name_node)
        qualified_name = (
            f"{parsed.package_name}.{simple_name}"
            if parsed.package_name
            else simple_name
        )
        members, reasons = _type_members(parsed, node)
        surfaces.append(
            JavaTypeSurface(
                qualified_name=qualified_name,
                simple_name=simple_name,
                package_name=parsed.package_name,
                source_set=parsed.source_set,
                module_root=parsed.module_root,
                file=parsed.path,
                members=members,
                complete=not reasons,
                incomplete_reasons=tuple(sorted(reasons)),
            )
        )
    return surfaces


def _type_members(
    parsed: JavaParsedFile,
    type_node: Any,
) -> tuple[dict[str, tuple[JavaMemberSurface, ...]], set[str]]:
    members: dict[str, list[JavaMemberSurface]] = {}
    reasons: set[str] = set()
    if any(child.type in _INHERITANCE_NODE_TYPES for child in type_node.named_children):
        reasons.add("inherited_members")
    if _type_uses_codegen_annotation(parsed, type_node):
        reasons.add("generated_members")
    body = type_node.child_by_field_name("body")
    if body is None:
        return members, reasons
    for declaration in body.named_children:
        _collect_static_declaration(parsed, type_node, declaration, members)
    return {name: tuple(values) for name, values in members.items()}, reasons


def _collect_static_declaration(
    parsed: JavaParsedFile,
    type_node: Any,
    declaration: Any,
    members: dict[str, list[JavaMemberSurface]],
) -> None:
    if declaration.type == "method_declaration":
        if _member_is_static(parsed, type_node, declaration):
            _add_named_member(parsed, type_node, declaration, members, kind="method")
        return
    if declaration.type == "field_declaration":
        if not _member_is_static(parsed, type_node, declaration):
            return
        for child in declaration.named_children:
            if child.type == "variable_declarator":
                _add_named_member(
                    parsed,
                    type_node,
                    child,
                    members,
                    kind="field",
                    modifiers_node=declaration,
                )
        return
    if declaration.type == "enum_constant":
        _add_named_member(
            parsed,
            type_node,
            declaration,
            members,
            kind="field",
            implicit_public=True,
        )
        return
    if declaration.type in _TYPE_NODE_TYPES and _member_is_static(
        parsed, type_node, declaration
    ):
        _add_named_member(parsed, type_node, declaration, members, kind="type")


def _member_is_static(parsed: JavaParsedFile, type_node: Any, declaration: Any) -> bool:
    if declaration.type in {
        "annotation_type_declaration",
        "enum_declaration",
        "interface_declaration",
        "record_declaration",
    }:
        return True
    if type_node.type in {"annotation_type_declaration", "interface_declaration"}:
        return declaration.type != "method_declaration" or "static" in _modifier_text(
            parsed, declaration
        )
    return "static" in _modifier_text(parsed, declaration)


def _modifier_text(parsed: JavaParsedFile, node: Any) -> str:
    for child in node.named_children:
        if child.type == "modifiers":
            return node_text(parsed, child)
    return ""


def _add_named_member(
    parsed: JavaParsedFile,
    type_node: Any,
    declaration: Any,
    members: dict[str, list[JavaMemberSurface]],
    *,
    kind: str,
    modifiers_node: Any | None = None,
    implicit_public: bool = False,
) -> None:
    name_node = declaration.child_by_field_name("name")
    if name_node is None:
        return
    name = node_text(parsed, name_node)
    members.setdefault(name, []).append(
        JavaMemberSurface(
            name=name,
            kind=kind,
            visibility=_member_visibility(
                parsed,
                type_node,
                modifiers_node or declaration,
                implicit_public=implicit_public,
            ),
            file=parsed.path,
            line=int(name_node.start_point[0]) + 1,
        )
    )


def _member_visibility(
    parsed: JavaParsedFile,
    type_node: Any,
    declaration: Any,
    *,
    implicit_public: bool,
) -> str:
    modifiers = _modifier_text(parsed, declaration).split()
    for visibility in ("public", "protected", "private"):
        if visibility in modifiers:
            return visibility
    if implicit_public or type_node.type in {
        "annotation_type_declaration",
        "interface_declaration",
    }:
        return "public"
    return "package"


def _type_uses_codegen_annotation(parsed: JavaParsedFile, node: Any) -> bool:
    modifiers = next(
        (child for child in node.named_children if child.type == "modifiers"),
        None,
    )
    if modifiers is None:
        return False
    text = node_text(parsed, modifiers)
    return any(
        re.search(
            rf"@(?:[A-Za-z_$][\w$]*\.)*{re.escape(name)}\b",
            text,
        )
        is not None
        for name in _KNOWN_CODEGEN_ANNOTATIONS
    )


def _java_source_set(root: Path, path: Path) -> str:
    try:
        relative = path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except (OSError, ValueError):
        relative = Path(path.name)
    parts = [part.lower() for part in relative.parts]
    if any(
        part in {"generated", "generated-sources", "generated-test-sources"}
        for part in parts
    ):
        return "generated"
    for index, part in enumerate(parts[:-1]):
        if part == "src" and parts[index + 1] in _JAVA_TEST_SOURCE_SETS:
            return "test"
    return "main"


def _java_module_root(root: Path, path: Path) -> Path:
    resolved_root = root.resolve(strict=False)
    resolved_path = path.resolve(strict=False)
    current = resolved_path.parent
    while True:
        if any((current / marker).is_file() for marker in _JAVA_BUILD_MARKERS):
            return current
        if current == resolved_root or current.parent == current:
            break
        try:
            current.parent.relative_to(resolved_root)
        except ValueError:
            break
        current = current.parent
    try:
        relative = resolved_path.relative_to(resolved_root)
    except ValueError:
        return resolved_root
    parts = relative.parts
    for index, part in enumerate(parts[:-1]):
        if part.lower() == "src":
            return resolved_root.joinpath(*parts[:index])
    return resolved_root


def _package_name(root_node: Any, source: bytes) -> str:
    for child in root_node.named_children:
        if child.type != "package_declaration" or not child.named_children:
            continue
        name_node = child.named_children[0]
        return source[name_node.start_byte : name_node.end_byte].decode(
            "utf-8", errors="replace"
        )
    return ""


def _safe_contained_file(root: Path, candidate: Path) -> Path | None:
    try:
        if candidate.is_symlink():
            return None
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    return resolved if resolved.is_file() else None
