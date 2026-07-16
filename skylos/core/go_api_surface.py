from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from tree_sitter import Parser, Query, QueryCursor

from skylos.core.go_module_manifest import (
    MAX_GO_MANIFEST_BYTES,
    GoModule,
    GoReplacement,
    go_work_use_paths,
    module_from_manifest,
)
from skylos.core.file_discovery import should_exclude_path
from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.visitors.languages.go.quality import GO_LANG


MAX_GO_SOURCE_BYTES = 2 * 1024 * 1024
MAX_GO_PACKAGE_FILES = 500

_GO_BUILD_SUFFIXES = {
    "386",
    "aix",
    "amd64",
    "amd64p32",
    "android",
    "arm",
    "arm64",
    "darwin",
    "dragonfly",
    "freebsd",
    "hurd",
    "illumos",
    "ios",
    "js",
    "linux",
    "loong64",
    "mips",
    "mips64",
    "mips64le",
    "mipsle",
    "netbsd",
    "openbsd",
    "plan9",
    "ppc64",
    "ppc64le",
    "riscv64",
    "s390x",
    "solaris",
    "sparc64",
    "wasip1",
    "wasm",
    "windows",
}

_SURFACE_PATTERN = """
(function_declaration name: (identifier) @member)
(type_spec name: (type_identifier) @member)
(const_spec name: (identifier) @member)
(var_spec name: (identifier) @member)
"""


@dataclass(frozen=True)
class GoParsedFile:
    path: Path
    source: bytes
    root_node: Any
    package_name: str
    build_conditional: bool


@dataclass(frozen=True)
class GoPackageSurface:
    import_path: str
    directory: Path
    package_name: str | None
    members: dict[str, dict[str, Any]]
    complete: bool
    incomplete_reasons: tuple[str, ...]


def safe_go_files(root: Path, files: Iterable[str | Path]) -> list[Path]:
    selected: set[Path] = set()
    for value in files:
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved = _safe_contained_file(root, candidate)
        if resolved is not None and resolved.suffix == ".go":
            selected.add(resolved)
    return sorted(selected, key=str)


def parse_go_file(path: Path) -> tuple[GoParsedFile | None, str | None]:
    if GO_LANG is None:
        return None, "parser_unavailable"
    source_text = read_text_no_symlink(
        path,
        max_bytes=MAX_GO_SOURCE_BYTES,
        encoding="utf-8",
        errors="replace",
    )
    if source_text is None:
        return None, "source_unreadable"
    source = source_text.encode("utf-8", errors="replace")
    root_node = Parser(GO_LANG).parse(source).root_node
    if root_node.has_error:
        return None, "parse_error"
    package_name = _package_name(root_node, source)
    if not package_name:
        return None, "package_clause_missing"
    return (
        GoParsedFile(
            path=path,
            source=source,
            root_node=root_node,
            package_name=package_name,
            build_conditional=(
                _has_build_constraint(source_text)
                or _has_build_constrained_filename(path.name)
            ),
        ),
        None,
    )


def discover_go_modules(root: Path, files: Iterable[Path]) -> list[GoModule]:
    modules, _ = discover_go_modules_with_reasons(root, files)
    return modules


def discover_go_modules_with_reasons(
    root: Path,
    files: Iterable[Path],
    *,
    exclude_folders: Sequence[str] | None = None,
) -> tuple[list[GoModule], tuple[str, ...]]:
    manifests: set[Path] = set()
    reasons: set[str] = set()
    for file_path in files:
        manifest = _nearest_go_mod(root, file_path.parent)
        if manifest is not None:
            manifests.add(manifest)
    workspace_manifests, workspace_reasons = _go_work_manifests(
        root,
        exclude_folders=exclude_folders,
    )
    manifests.update(workspace_manifests)
    reasons.update(workspace_reasons)

    modules = []
    seen_paths: set[str] = set()
    for manifest in sorted(manifests, key=str):
        module = module_from_manifest(root, manifest)
        if module is None:
            reasons.add("module_manifest_invalid")
            continue
        module, excluded_replacement = _without_excluded_replacements(
            module,
            root,
            exclude_folders,
        )
        if excluded_replacement:
            reasons.add("excluded_workspace_paths")
        if module.module_path in seen_paths:
            continue
        modules.append(module)
        seen_paths.add(module.module_path)
    return (
        sorted(modules, key=lambda item: (-len(item.module_path), item.module_path)),
        tuple(sorted(reasons)),
    )


def resolve_go_import(
    import_path: str,
    modules: Iterable[GoModule],
) -> tuple[GoModule | None, Path | None, bool]:
    for module in modules:
        resolved = _resolve_module_import(import_path, module)
        if resolved is not None:
            return module, resolved, True
        replacement = _resolve_replacement_import(import_path, module.replacements)
        if replacement is not None:
            return module, replacement, True
        if _matches_import_prefix(import_path, module.unresolved_replacements):
            return module, None, True
    return None, None, False


def inspect_go_package_surface(
    module: GoModule,
    import_path: str,
    directory: Path,
    *,
    allowed_files: frozenset[Path] | None = None,
    exclude_folders: Sequence[str] | None = None,
) -> GoPackageSurface:
    try:
        if directory.is_symlink():
            raise ValueError
        resolved_directory = directory.resolve(strict=True)
        resolved_directory.relative_to(module.scan_root)
    except (OSError, ValueError):
        return _incomplete_surface(import_path, directory, "unsafe_package_path")
    if resolved_directory.is_symlink() or not resolved_directory.is_dir():
        return _incomplete_surface(import_path, directory, "unsafe_package_path")

    paths = _package_go_files(
        resolved_directory,
        allowed_files=allowed_files,
        scan_root=module.scan_root,
        exclude_folders=exclude_folders,
    )
    if paths is None:
        return _incomplete_surface(
            import_path, resolved_directory, "package_file_limit"
        )
    if not paths:
        return _incomplete_surface(
            import_path, resolved_directory, "package_surface_empty"
        )

    members: dict[str, dict[str, Any]] = {}
    package_names: set[str] = set()
    reasons: set[str] = set()
    for path in paths:
        parsed, reason = parse_go_file(path)
        if parsed is None:
            reasons.add(reason or "parse_error")
            continue
        package_names.add(parsed.package_name)
        if parsed.build_conditional:
            reasons.add("build_conditional_surface")
        _collect_exported_members(parsed, members, reasons)

    if len(package_names) > 1:
        reasons.add("ambiguous_package_name")
    package_name = next(iter(package_names)) if len(package_names) == 1 else None
    return GoPackageSurface(
        import_path=import_path,
        directory=resolved_directory,
        package_name=package_name,
        members=members,
        complete=not reasons,
        incomplete_reasons=tuple(sorted(reasons)),
    )


def node_text(parsed: GoParsedFile, node: Any) -> str:
    return parsed.source[node.start_byte : node.end_byte].decode(
        "utf-8", errors="replace"
    )


def iter_nodes(node: Any) -> Iterable[Any]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def _safe_contained_file(root: Path, candidate: Path) -> Path | None:
    try:
        if candidate.is_symlink():
            return None
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    return resolved if resolved.is_file() else None


def _nearest_go_mod(root: Path, start: Path) -> Path | None:
    current = start
    while True:
        candidate = current / "go.mod"
        if _safe_contained_file(root, candidate) is not None:
            return candidate.resolve()
        if current == root or current.parent == current:
            return None
        try:
            current.parent.relative_to(root)
        except ValueError:
            return None
        current = current.parent


def _go_work_manifests(
    root: Path,
    *,
    exclude_folders: Sequence[str] | None = None,
) -> tuple[set[Path], set[str]]:
    work_file = _safe_contained_file(root, root / "go.work")
    if work_file is None:
        return set(), set()
    text = read_text_no_symlink(
        work_file,
        max_bytes=MAX_GO_MANIFEST_BYTES,
        encoding="utf-8",
        errors="replace",
    )
    if text is None:
        return set(), {"go_work_unreadable"}
    manifests: set[Path] = set()
    reasons: set[str] = set()
    for value in go_work_use_paths(text):
        directory = (root / value).resolve(strict=False)
        try:
            directory.relative_to(root)
        except ValueError:
            reasons.add("unsafe_workspace_path")
            continue
        if should_exclude_path(directory, root, exclude_folders):
            reasons.add("excluded_workspace_paths")
            continue
        manifest = _safe_contained_file(root, directory / "go.mod")
        if manifest is not None:
            manifests.add(manifest)
        else:
            reasons.add("workspace_module_manifest_missing")
    return manifests, reasons


def _resolve_module_import(import_path: str, module: GoModule) -> Path | None:
    if import_path == module.module_path:
        return module.root
    prefix = f"{module.module_path}/"
    if import_path.startswith(prefix):
        return module.root / import_path[len(prefix) :]
    return None


def _resolve_replacement_import(
    import_path: str,
    replacements: Iterable[GoReplacement],
) -> Path | None:
    for replacement in replacements:
        if import_path == replacement.import_path:
            return replacement.directory
        prefix = f"{replacement.import_path}/"
        if import_path.startswith(prefix):
            return replacement.directory / import_path[len(prefix) :]
    return None


def _matches_import_prefix(import_path: str, prefixes: Iterable[str]) -> bool:
    return any(
        import_path == prefix or import_path.startswith(f"{prefix}/")
        for prefix in prefixes
    )


def _package_go_files(
    directory: Path,
    *,
    allowed_files: frozenset[Path] | None,
    scan_root: Path,
    exclude_folders: Sequence[str] | None,
) -> list[Path] | None:
    if allowed_files is not None:
        return _selected_package_go_files(
            directory,
            allowed_files,
            scan_root,
            exclude_folders,
        )
    return _discovered_package_go_files(
        directory,
        scan_root,
        exclude_folders,
    )


def _selected_package_go_files(
    directory: Path,
    allowed_files: frozenset[Path],
    scan_root: Path,
    exclude_folders: Sequence[str] | None,
) -> list[Path] | None:
    paths = [
        path
        for path in allowed_files
        if path.parent == directory
        and _is_package_go_file(path)
        and not should_exclude_path(path, scan_root, exclude_folders)
    ]
    return _bounded_package_files(paths)


def _discovered_package_go_files(
    directory: Path,
    scan_root: Path,
    exclude_folders: Sequence[str] | None,
) -> list[Path] | None:
    try:
        entries = list(directory.iterdir())
    except OSError:
        return []
    paths: list[Path] = []
    for path in entries:
        if not _is_package_go_file(path):
            continue
        resolved = _safe_contained_file(directory, path)
        if resolved is None or should_exclude_path(
            resolved,
            scan_root,
            exclude_folders,
        ):
            continue
        paths.append(resolved)
    return _bounded_package_files(paths)


def _is_package_go_file(path: Path) -> bool:
    return path.suffix == ".go" and not path.name.endswith("_test.go")


def _bounded_package_files(paths: Iterable[Path]) -> list[Path] | None:
    selected = sorted(paths, key=str)
    if len(selected) > MAX_GO_PACKAGE_FILES:
        return None
    return selected


def _without_excluded_replacements(
    module: GoModule,
    root: Path,
    exclude_folders: Sequence[str] | None,
) -> tuple[GoModule, bool]:
    if not exclude_folders:
        return module, False
    replacements = []
    unresolved = set(module.unresolved_replacements)
    excluded = False
    for replacement in module.replacements:
        if should_exclude_path(replacement.directory, root, exclude_folders):
            unresolved.add(replacement.import_path)
            excluded = True
            continue
        replacements.append(replacement)
    return (
        GoModule(
            module_path=module.module_path,
            root=module.root,
            scan_root=module.scan_root,
            replacements=tuple(replacements),
            unresolved_replacements=tuple(sorted(unresolved)),
        ),
        excluded,
    )


def _collect_exported_members(
    parsed: GoParsedFile,
    members: dict[str, dict[str, Any]],
    reasons: set[str],
) -> None:
    try:
        captures = QueryCursor(Query(GO_LANG, _SURFACE_PATTERN)).captures(
            parsed.root_node
        )
    except Exception:
        reasons.add("surface_query_error")
        return
    for node in captures.get("member", []):
        name = node_text(parsed, node)
        if not name[:1].isupper():
            continue
        members.setdefault(
            name,
            {
                "file": str(parsed.path),
                "line": int(node.start_point[0]) + 1,
            },
        )


def _package_name(root_node: Any, source: bytes) -> str | None:
    for child in root_node.named_children:
        if child.type != "package_clause":
            continue
        for name_node in child.named_children:
            if name_node.type == "package_identifier":
                return source[name_node.start_byte : name_node.end_byte].decode(
                    "utf-8", errors="replace"
                )
    return None


def _has_build_constraint(source: str) -> bool:
    for line in source.splitlines()[:20]:
        stripped = line.strip()
        if stripped.startswith("//go:build ") or stripped.startswith("// +build "):
            return True
        if stripped.startswith("package "):
            return False
    return False


def _has_build_constrained_filename(filename: str) -> bool:
    stem = Path(filename).stem
    suffix = stem.rsplit("_", 1)[-1]
    return suffix in _GO_BUILD_SUFFIXES


def _incomplete_surface(
    import_path: str,
    directory: Path,
    reason: str,
) -> GoPackageSurface:
    return GoPackageSurface(
        import_path=import_path,
        directory=directory,
        package_name=None,
        members={},
        complete=False,
        incomplete_reasons=(reason,),
    )
