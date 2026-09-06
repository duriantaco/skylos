from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

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
_SCRIPT_ATTR_RE = re.compile(
    r"""(?P<name>[^\s=/>]+)(?:\s*=\s*(?:"(?P<double>[^"]*)"|'(?P<single>[^']*)'|(?P<bare>[^\s>]+)))?""",
    re.DOTALL,
)
_DJANGO_STATIC_TAG_RE = re.compile(
    r"""^\s*{%\s*static\s+(?P<quote>["'])(?P<path>[^"']+)(?P=quote)\s*%}\s*$""",
    re.DOTALL,
)
_HTML_COMMENT_RE = re.compile(r"""<!--[\s\S]*?-->""")
_DJANGO_SHORT_COMMENT_RE = re.compile(r"""{#[\s\S]*?#}""")
_DJANGO_COMMENT_BLOCK_RE = re.compile(
    r"""{%\s*comment(?:\s+[^%]*?)?\s*%}[\s\S]*?{%\s*endcomment\s*%}""",
    re.IGNORECASE,
)
_CLASSIC_SCRIPT_TYPES = {
    "",
    # https://mimesniff.spec.whatwg.org/#javascript-mime-type
    "application/ecmascript",
    "application/javascript",
    "application/x-ecmascript",
    "application/x-javascript",
    "text/ecmascript",
    "text/javascript",
    "text/javascript1.0",
    "text/javascript1.1",
    "text/javascript1.2",
    "text/javascript1.3",
    "text/javascript1.4",
    "text/javascript1.5",
    "text/jscript",
    "text/livescript",
    "text/x-ecmascript",
    "text/x-javascript",
}
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
    template_names: dict[Path, set[str]] = {}
    monorepo_resolver = _build_ts_monorepo_resolver(root)
    source_files = list(source_files)
    scanned_scripts = _scanned_js_files(root, source_files)
    static_asset_index = _build_static_asset_index(root, scanned_scripts)

    reference_files = list(
        _iter_browser_reference_files(root, source_files, exclude_folders)
    )
    for file_path in reference_files:
        source = _read_text(root, file_path, source_cache)
        if source is None:
            continue

        if file_path.suffix.lower() in _HTML_TEMPLATE_SUFFIXES:
            template_files.append(file_path)
            source = _strip_template_comments(source)

        if file_path.suffix.lower() in _MDX_SUFFIXES:
            for name, target_file in extract_mdx_component_refs(
                root,
                file_path,
                source,
                monorepo_resolver,
            ):
                _append_ref(refs, seen_refs, name, target_file)

        handler_names = extract_browser_event_handler_names(source)
        if file_path.suffix.lower() in _HTML_TEMPLATE_SUFFIXES:
            template_names[file_path] = handler_names
        else:
            seen_names.update(handler_names)
        for name in handler_names:
            _append_ref(refs, seen_refs, name, file_path)

    script_names: dict[Path, set[str]] = {}
    for template_file in template_files:
        global_scripts = _collect_template_script_files(
            root,
            [template_file],
            source_cache,
            include_modules=False,
            static_asset_index=static_asset_index,
            allowed_files=scanned_scripts,
        )
        for script_file in global_scripts:
            script_names.setdefault(script_file, set()).update(
                template_names.get(template_file, set())
            )
    for script_file, names in script_names.items():
        source = _read_text(root, script_file, source_cache)
        if source is None:
            continue
        for name in names | seen_names:
            if _source_defines_top_level_browser_name(source, name):
                _append_ref(refs, seen_refs, name, script_file)

    return refs


def collect_browser_script_entry_files(
    project_root: Path,
    source_files,
    *,
    exclude_folders=None,
) -> set[Path]:
    """Find loaded script files, without treating their exports as consumed.

    Literal Django static paths must map to one scanned asset. Finder ordering
    and custom STATICFILES_DIRS require configuration not inferred here.
    """
    root = Path(project_root).resolve()
    scanned_scripts = _scanned_js_files(root, source_files)
    if not scanned_scripts:
        return set()
    template_files = discover_source_files(
        root,
        _HTML_TEMPLATE_SUFFIXES,
        exclude_folders=exclude_folders,
    )
    return _collect_template_script_files(
        root,
        list(template_files),
        {},
        include_modules=True,
        static_asset_index=_build_static_asset_index(root, scanned_scripts),
        allowed_files=scanned_scripts,
    )


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


def _collect_template_script_files(
    root: Path,
    template_files: list[Path],
    source_cache: dict[Path, str],
    *,
    include_modules: bool,
    static_asset_index: dict[str, set[Path]],
    allowed_files: set[Path],
) -> set[Path]:
    script_files: set[Path] = set()

    for template_file in template_files:
        source = _read_text(root, template_file, source_cache)
        if source is None:
            continue

        for match in _SCRIPT_TAG_RE.finditer(_strip_template_comments(source)):
            attrs = match.group("attrs")
            script_type = (_script_attribute(attrs, "type") or "").strip().lower()
            if script_type not in _CLASSIC_SCRIPT_TYPES and not (
                include_modules and script_type == "module"
            ):
                continue
            src = _script_attribute(attrs, "src")
            if not src:
                continue
            script_file = _resolve_script_src(
                root, template_file.parent, src, static_asset_index=static_asset_index
            )
            if script_file in allowed_files:
                script_files.add(script_file)

    return script_files


def _strip_template_comments(source: str) -> str:
    without_blocks = _DJANGO_COMMENT_BLOCK_RE.sub("", source)
    without_short_comments = _DJANGO_SHORT_COMMENT_RE.sub("", without_blocks)
    return _HTML_COMMENT_RE.sub("", without_short_comments)


def _script_attribute(attrs: str, name: str) -> str | None:
    for match in _SCRIPT_ATTR_RE.finditer(attrs):
        if match.group("name").lower() == name:
            return (
                match.group("double")
                or match.group("single")
                or match.group("bare")
                or ""
            )
    return None


def _resolve_script_src(
    root: Path,
    template_dir: Path,
    src: str,
    *,
    static_asset_index: dict[str, set[Path]],
) -> Path | None:
    static_asset_path = _django_static_asset_path(src)
    if static_asset_path is not None:
        matches = static_asset_index.get(static_asset_path, set())
        return next(iter(matches)) if len(matches) == 1 else None

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

    return _resolve_readable_project_file(root, candidate)


def _django_static_asset_path(src: str) -> str | None:
    match = _DJANGO_STATIC_TAG_RE.fullmatch(src)
    if match is None:
        return None
    raw_path = match.group("path").strip()
    if not raw_path or raw_path.startswith("/"):
        return None
    if any(
        character in raw_path for character in ("\\", "\x00", ":", "{", "}", "?", "#")
    ):
        return None
    parts = raw_path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return None
    normalized = PurePosixPath(*parts)
    return (
        normalized.as_posix()
        if normalized.suffix.lower() in _JS_SOURCE_SUFFIXES
        else None
    )


def _scanned_js_files(root: Path, source_files) -> set[Path]:
    scripts: set[Path] = set()
    for raw_file in source_files:
        file_path = Path(raw_file)
        if file_path.suffix.lower() not in _JS_SOURCE_SUFFIXES:
            continue
        resolved = _resolve_readable_project_file(root, file_path)
        if resolved is not None:
            scripts.add(resolved)
    return scripts


def _build_static_asset_index(
    root: Path, script_files: set[Path]
) -> dict[str, set[Path]]:
    index: dict[str, set[Path]] = {}
    for script_file in script_files:
        parts = script_file.relative_to(root).parts
        if root.name == "static":
            index.setdefault(PurePosixPath(*parts).as_posix(), set()).add(script_file)
        for position, part in enumerate(parts[:-1]):
            if part == "static":
                key = PurePosixPath(*parts[position + 1 :]).as_posix()
                index.setdefault(key, set()).add(script_file)
    return index


def _source_defines_top_level_browser_name(source: str, name: str) -> bool:
    escaped = re.escape(name)
    patterns = (
        rf"^(?:async\s+)?function\s+{escaped}\b",
        rf"^(?:const|let|var)\s+{escaped}\s*=",
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
