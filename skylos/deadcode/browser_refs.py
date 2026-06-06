from __future__ import annotations

import re
from pathlib import Path

from skylos.core.file_discovery import discover_source_files
from skylos.core.safe_cache_io import read_text_no_symlink

_JS_SOURCE_SUFFIXES = {
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mts",
    ".cts",
    ".mjs",
    ".cjs",
}
_HTML_TEMPLATE_SUFFIXES = {
    ".html",
    ".htm",
    ".vue",
    ".svelte",
    ".astro",
}
_MDX_SUFFIXES = {
    ".mdx",
}

_QUOTED_EVENT_HANDLER_RE = re.compile(
    r"""\bon[a-zA-Z]+\s*=\s*\\?(?P<quote>["'])(?P<handler>.*?)\\?(?P=quote)""",
    re.DOTALL,
)
_UNQUOTED_EVENT_HANDLER_RE = re.compile(
    r"""\bon[a-zA-Z]+\s*=\s*(?P<handler>[^\s>]+)""",
    re.DOTALL,
)
_WINDOW_CALL_RE = re.compile(r"""\bwindow\s*\.\s*(?P<name>[A-Za-z_$][\w$]*)\s*\(""")
_DIRECT_CALL_RE = re.compile(r"""(?<![.\w$])(?P<name>[A-Za-z_$][\w$]*)\s*\(""")
_WINDOW_LITERAL_DISPATCH_RE = re.compile(
    r"""\bwindow\s*\[\s*(?P<quote>["'])(?P<name>[A-Za-z_$][\w$]*)(?P=quote)\s*\]\s*\("""
)
_LEGACY_STRING_DISPATCH_RE = re.compile(
    r"""\b(?:callLegacy|legacyClick|legacyKeyDown)\s*\(\s*(?P<quote>["'])(?P<name>[A-Za-z_$][\w$]*)(?P=quote)"""
)
_ACTION_PROPERTY_RE = re.compile(
    r"""\b[A-Za-z_$][\w$]*Action\s*:\s*(?P<quote>["'])(?P<name>[A-Za-z_$][\w$]*)(?P=quote)"""
)
_MDX_IMPORT_RE = re.compile(
    r"""^\s*import\s+(?P<clause>[\s\S]*?)\s+from\s+"""
    r"""(?P<quote>["'])(?P<source>[^"']+)(?P=quote)\s*;?""",
    re.MULTILINE,
)
_MDX_NAMED_IMPORT_RE = re.compile(r"""\{(?P<body>[^}]*)\}""", re.DOTALL)
_MDX_NAMESPACE_IMPORT_RE = re.compile(
    r"""\*\s+as\s+(?P<name>[A-Za-z_$][\w$]*)"""
)
_MDX_COMPONENT_TAG_RE = re.compile(
    r"""</?\s*(?P<name>[A-Z][A-Za-z0-9_$]*)(?:\s|/|>|[.])"""
)
_MARKDOWN_CODE_BLOCK_RE = re.compile(
    r"""(```[\s\S]*?```|~~~[\s\S]*?~~~)"""
)
_MARKDOWN_INLINE_CODE_RE = re.compile(r"""`[^`\n]*`""")
_SCRIPT_TAG_RE = re.compile(r"""<script\b(?P<attrs>[^>]*)>""", re.IGNORECASE)
_SRC_ATTR_RE = re.compile(
    r"""\bsrc\s*=\s*(?P<quote>["'])(?P<value>.*?)(?P=quote)""",
    re.IGNORECASE | re.DOTALL,
)
_TYPE_ATTR_RE = re.compile(
    r"""\btype\s*=\s*(?P<quote>["'])(?P<value>.*?)(?P=quote)""",
    re.IGNORECASE | re.DOTALL,
)
_JS_CONTROL_WORDS = {
    "catch",
    "do",
    "for",
    "function",
    "if",
    "switch",
    "while",
    "with",
}
_MAX_REFERENCE_FILE_BYTES = 512_000


def extract_browser_event_handler_names(source: str) -> set[str]:
    names: set[str] = set()

    for handler in _iter_event_handler_values(source):
        normalized = _normalize_handler_source(handler)
        for name in _extract_call_names(normalized):
            names.add(name)

    for name in _extract_string_dispatch_names(source):
        names.add(name)

    return names


def extract_mdx_component_refs(
    root: Path,
    mdx_file: Path,
    source: str,
    monorepo_resolver,
) -> list[tuple[str, Path]]:
    clean_source = _strip_markdown_code(source)
    rendered_components = _extract_mdx_rendered_components(clean_source)
    if not rendered_components:
        return []

    imported_components = _extract_mdx_imported_components(clean_source)
    refs: list[tuple[str, Path]] = []
    seen: set[tuple[str, Path]] = set()
    for name in sorted(rendered_components):
        imported = imported_components.get(name)
        if not imported:
            continue
        import_source, exported_name = imported

        target_file = _resolve_mdx_component_file(
            root,
            mdx_file,
            import_source,
            monorepo_resolver,
        )
        if target_file is None:
            continue

        key = (exported_name, target_file)
        if key in seen:
            continue
        seen.add(key)
        refs.append(key)
    return refs


def collect_mdx_ts_imports(
    project_root: Path,
    source_files,
    *,
    exclude_folders=None,
) -> dict[Path, list[dict[str, object]]]:
    root = Path(project_root).resolve()
    source_cache: dict[Path, str] = {}
    raw_imports: dict[Path, list[dict[str, object]]] = {}

    for file_path in _iter_mdx_reference_files(root, source_files, exclude_folders):
        source = _read_text(root, file_path, source_cache)
        if source is None:
            continue

        clean_source = _strip_markdown_code(source)
        rendered_components = _extract_mdx_rendered_components(clean_source)
        if not rendered_components:
            continue

        imported_components = _extract_mdx_imported_components(clean_source)
        imports_by_source: dict[str, list[str]] = {}
        for local_name in sorted(rendered_components):
            imported = imported_components.get(local_name)
            if not imported:
                continue
            import_source, exported_name = imported
            imports_by_source.setdefault(import_source, []).append(exported_name)

        entries: list[dict[str, object]] = []
        for import_source, names in imports_by_source.items():
            entries.append(
                {
                    "source": import_source,
                    "names": names,
                    "line": 1,
                }
            )
        if entries:
            raw_imports[file_path] = entries

    return raw_imports


def collect_browser_event_handler_refs(
    project_root: Path,
    source_files,
    *,
    exclude_folders=None,
) -> list[tuple[str, str]]:
    root = Path(project_root).resolve()
    refs: list[tuple[str, str]] = []
    seen_refs: set[tuple[str, str]] = set()
    seen_names: set[str] = set()
    source_cache: dict[Path, str] = {}
    template_files: list[Path] = []
    monorepo_resolver = _build_ts_monorepo_resolver(root)

    reference_files = list(
        _iter_browser_reference_files(root, source_files, exclude_folders)
    )
    for file_path in reference_files:
        source = _read_text(root, file_path, source_cache)
        if source is None:
            continue

        if file_path.suffix.lower() in _HTML_TEMPLATE_SUFFIXES:
            template_files.append(file_path)

        if file_path.suffix.lower() in _MDX_SUFFIXES:
            for name, target_file in extract_mdx_component_refs(
                root,
                file_path,
                source,
                monorepo_resolver,
            ):
                _append_ref(refs, seen_refs, name, target_file)

        for name in extract_browser_event_handler_names(source):
            seen_names.add(name)
            _append_ref(refs, seen_refs, name, file_path)

    global_scripts = _collect_non_module_script_files(root, template_files, source_cache)
    for script_file in global_scripts:
        source = _read_text(root, script_file, source_cache)
        if source is None:
            continue
        for name in seen_names:
            if _source_defines_top_level_browser_name(source, name):
                _append_ref(refs, seen_refs, name, script_file)

    return refs


def _strip_markdown_code(source: str) -> str:
    without_blocks = _MARKDOWN_CODE_BLOCK_RE.sub("", source)
    return _MARKDOWN_INLINE_CODE_RE.sub("", without_blocks)


def _extract_mdx_rendered_components(source: str) -> set[str]:
    names: set[str] = set()
    for match in _MDX_COMPONENT_TAG_RE.finditer(source):
        names.add(match.group("name"))
    return names


def _extract_mdx_imported_components(source: str) -> dict[str, tuple[str, str]]:
    imported: dict[str, tuple[str, str]] = {}
    for match in _MDX_IMPORT_RE.finditer(source):
        clause = match.group("clause").strip()
        import_source = match.group("source").strip()
        for local_name, exported_name in _extract_import_clause_local_names(
            clause
        ).items():
            imported[local_name] = (import_source, exported_name)
    return imported


def _extract_import_clause_local_names(clause: str) -> dict[str, str]:
    names: dict[str, str] = {}

    namespace_match = _MDX_NAMESPACE_IMPORT_RE.search(clause)
    if namespace_match:
        namespace_name = namespace_match.group("name")
        names[namespace_name] = namespace_name

    named_spans: list[tuple[int, int]] = []
    for match in _MDX_NAMED_IMPORT_RE.finditer(clause):
        named_spans.append(match.span())
        for part in match.group("body").split(","):
            parsed = _names_from_import_part(part)
            if parsed:
                local_name, exported_name = parsed
                names[local_name] = exported_name

    default_clause = clause
    for start, end in reversed(named_spans):
        default_clause = default_clause[:start] + default_clause[end:]
    default_clause = default_clause.split(",", 1)[0].strip()
    if default_clause and not default_clause.startswith("*"):
        parsed = _names_from_import_part(default_clause)
        if parsed:
            local_name, exported_name = parsed
            names[local_name] = exported_name

    return names


def _names_from_import_part(part: str) -> tuple[str, str] | None:
    cleaned = part.strip()
    if not cleaned:
        return None

    pieces = re.split(r"\s+as\s+", cleaned)
    exported_name = pieces[0].strip()
    local_name = pieces[-1].strip()
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", exported_name):
        return None
    if re.fullmatch(r"[A-Za-z_$][\w$]*", local_name):
        return local_name, exported_name
    return None


def _resolve_mdx_component_file(
    root: Path,
    mdx_file: Path,
    import_source: str,
    monorepo_resolver,
) -> Path | None:
    if import_source.startswith(("http://", "https://", "//")):
        return None

    try:
        from skylos.visitors.languages.typescript.analysis import resolve_ts_module
    except ImportError:
        return None

    resolved = resolve_ts_module(
        import_source,
        str(mdx_file),
        monorepo_resolver=monorepo_resolver,
    )
    if not resolved:
        return None

    target_file = Path(resolved)
    if target_file.suffix.lower() not in _JS_SOURCE_SUFFIXES:
        return None
    return _resolve_readable_project_file(root, target_file)


def _build_ts_monorepo_resolver(root: Path):
    try:
        from skylos.visitors.languages.typescript.resolve import MonorepoResolver
    except ImportError:
        return None
    return MonorepoResolver(str(root))


def _iter_event_handler_values(source: str):
    quoted_spans: list[tuple[int, int]] = []

    for match in _QUOTED_EVENT_HANDLER_RE.finditer(source):
        quoted_spans.append(match.span())
        yield match.group("handler")

    for match in _UNQUOTED_EVENT_HANDLER_RE.finditer(source):
        if _span_overlaps(match.span(), quoted_spans):
            continue
        yield match.group("handler")


def _normalize_handler_source(handler: str) -> str:
    return (
        handler.replace(r"\"", '"')
        .replace(r"\'", "'")
        .replace("&quot;", '"')
        .replace("&#34;", '"')
        .replace("&#39;", "'")
        .replace("&apos;", "'")
    )


def _extract_call_names(handler: str) -> set[str]:
    names: set[str] = set()

    for match in _WINDOW_CALL_RE.finditer(handler):
        names.add(match.group("name"))

    for match in _DIRECT_CALL_RE.finditer(handler):
        name = match.group("name")
        if name in _JS_CONTROL_WORDS:
            continue
        names.add(name)

    return names


def _extract_string_dispatch_names(source: str) -> set[str]:
    names: set[str] = set()

    for match in _WINDOW_LITERAL_DISPATCH_RE.finditer(source):
        names.add(match.group("name"))

    for match in _LEGACY_STRING_DISPATCH_RE.finditer(source):
        names.add(match.group("name"))

    if _source_uses_legacy_dispatch(source):
        for match in _ACTION_PROPERTY_RE.finditer(source):
            names.add(match.group("name"))

    return names


def _source_uses_legacy_dispatch(source: str) -> bool:
    for helper in ("callLegacy", "legacyClick", "legacyKeyDown"):
        if helper in source:
            return True
    return False


def _append_ref(
    refs: list[tuple[str, str]],
    seen_refs: set[tuple[str, str]],
    name: str,
    file_path: Path,
) -> None:
    ref = (name, str(file_path))
    if ref in seen_refs:
        return
    seen_refs.add(ref)
    refs.append(ref)


def _read_text(
    root: Path,
    file_path: Path,
    source_cache: dict[Path, str],
) -> str | None:
    resolved = _resolve_readable_project_file(root, file_path)
    if resolved is None:
        return None
    if resolved in source_cache:
        return source_cache[resolved]
    source = read_text_no_symlink(
        resolved,
        max_bytes=_MAX_REFERENCE_FILE_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if source is None:
        return None
    source_cache[resolved] = source
    return source


def _resolve_readable_project_file(root: Path, file_path: Path) -> Path | None:
    try:
        if file_path.is_symlink():
            return None
        resolved = file_path.resolve(strict=True)
        resolved.relative_to(root)
        stat_result = resolved.stat()
    except (OSError, ValueError):
        return None

    if not resolved.is_file():
        return None
    if stat_result.st_size > _MAX_REFERENCE_FILE_BYTES:
        return None
    return resolved


def _collect_non_module_script_files(
    root: Path,
    template_files: list[Path],
    source_cache: dict[Path, str],
) -> set[Path]:
    script_files: set[Path] = set()

    for template_file in template_files:
        source = _read_text(root, template_file, source_cache)
        if source is None:
            continue

        for match in _SCRIPT_TAG_RE.finditer(source):
            attrs = match.group("attrs")
            if _script_attrs_are_module(attrs):
                continue
            src = _script_src(attrs)
            if not src:
                continue
            script_file = _resolve_script_src(root, template_file.parent, src)
            if script_file is not None:
                script_files.add(script_file)

    return script_files


def _script_attrs_are_module(attrs: str) -> bool:
    match = _TYPE_ATTR_RE.search(attrs)
    if not match:
        return False
    return match.group("value").strip().lower() == "module"


def _script_src(attrs: str) -> str | None:
    match = _SRC_ATTR_RE.search(attrs)
    if not match:
        return None
    return match.group("value").strip()


def _resolve_script_src(root: Path, template_dir: Path, src: str) -> Path | None:
    clean_src = src.split("#", 1)[0].split("?", 1)[0].strip()
    if not clean_src:
        return None
    if clean_src.startswith(("http://", "https://", "//")):
        return None
    if ":" in clean_src:
        return None

    if clean_src.startswith("/"):
        candidate = root / clean_src.lstrip("/")
    else:
        candidate = template_dir / clean_src

    if candidate.suffix.lower() not in _JS_SOURCE_SUFFIXES:
        return None

    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None

    if not resolved.is_file():
        return None
    return resolved


def _source_defines_top_level_browser_name(source: str, name: str) -> bool:
    escaped = re.escape(name)
    patterns = (
        rf"^(?:export\s+)?(?:async\s+)?function\s+{escaped}\b",
        rf"^(?:export\s+)?(?:const|let|var)\s+{escaped}\s*=",
    )
    for pattern in patterns:
        if re.search(pattern, source, re.MULTILINE):
            return True
    return False


def _span_overlaps(span: tuple[int, int], occupied: list[tuple[int, int]]) -> bool:
    start, end = span
    for occupied_start, occupied_end in occupied:
        if start < occupied_end and end > occupied_start:
            return True
    return False


def _iter_browser_reference_files(
    root: Path,
    source_files,
    exclude_folders,
):
    seen: set[Path] = set()

    for raw_file in source_files:
        file_path = Path(raw_file).resolve()
        if file_path.suffix.lower() not in _JS_SOURCE_SUFFIXES:
            continue
        if file_path in seen:
            continue
        seen.add(file_path)
        yield file_path

    if not root.exists() or not root.is_dir():
        return

    template_files = discover_source_files(
        root,
        _HTML_TEMPLATE_SUFFIXES,
        exclude_folders=exclude_folders,
    )
    for file_path in template_files:
        if file_path in seen:
            continue
        seen.add(file_path)
        yield file_path

    for file_path in _iter_mdx_reference_files(root, source_files, exclude_folders):
        if file_path in seen:
            continue
        seen.add(file_path)
        yield file_path


def _iter_mdx_reference_files(
    root: Path,
    source_files,
    exclude_folders,
):
    seen: set[Path] = set()

    for raw_file in source_files:
        file_path = Path(raw_file).resolve()
        if file_path.suffix.lower() not in _MDX_SUFFIXES:
            continue
        if file_path in seen:
            continue
        seen.add(file_path)
        yield file_path

    if not root.exists() or not root.is_dir():
        return

    mdx_files = discover_source_files(
        root,
        _MDX_SUFFIXES,
        exclude_folders=exclude_folders,
    )
    for file_path in mdx_files:
        if file_path in seen:
            continue
        seen.add(file_path)
        yield file_path
