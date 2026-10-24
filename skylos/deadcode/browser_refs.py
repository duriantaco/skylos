from __future__ import annotations

import ast
import io
import re
import tokenize
from html.parser import HTMLParser
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
_MDX_NAMESPACE_IMPORT_RE = re.compile(r"""\*\s+as\s+(?P<name>[A-Za-z_$][\w$]*)""")
_MDX_COMPONENT_TAG_RE = re.compile(
    r"""</?\s*(?P<name>[A-Z][A-Za-z0-9_$]*)(?:\s|/|>|[.])"""
)
_MARKDOWN_CODE_BLOCK_RE = re.compile(r"""(```[\s\S]*?```|~~~[\s\S]*?~~~)""")
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
# ``{{ 'js/app.js'|url }}``: one quoted path plus template filters.
_TEMPLATE_LITERAL_SRC_RE = re.compile(
    r"""^\s*{{\s*(?P<quote>["'])(?P<path>[^"'{}]+)(?P=quote)"""
    r"""(?:\s*\|\s*[A-Za-z_]\w*(?:\([^(){}]*\))?)*\s*}}\s*$"""
)
# ``{{ url_for('static', filename='js/app.js') }}``.
_URL_FOR_STATIC_SRC_RE = re.compile(
    r"""^\s*{{\s*url_for\(\s*["']static["']\s*,\s*filename\s*=\s*"""
    r"""(?P<quote>["'])(?P<path>[^"'{}]+)(?P=quote)\s*\)\s*}}\s*$"""
)
_PYTHON_SOURCE_SUFFIXES = {".py", ".pyw"}
# DOM event attributes; Python sources are only searched for these names.
_DOM_EVENT_ATTRIBUTES = (
    "abort|animationend|beforeunload|blur|change|click|contextmenu|copy|cut|"
    "dblclick|drag|dragend|dragenter|dragleave|dragover|dragstart|drop|error|"
    "focus|focusin|focusout|hashchange|input|invalid|keydown|keypress|keyup|"
    "load|mousedown|mouseenter|mouseleave|mousemove|mouseout|mouseover|"
    "mouseup|paste|pointerdown|pointerup|popstate|reset|resize|scroll|"
    "search|select|submit|toggle|touchend|touchmove|touchstart|transitionend|"
    "unload|wheel"
)
_PYTHON_EVENT_HANDLER_RE = re.compile(
    rf"""\bon(?:{_DOM_EVENT_ATTRIBUTES})\s*=\s*\\?"""
    r"""(?:"(?P<double>[^"\n]*?)\\?"|'(?P<single>[^'\n]*?)\\?')""",
    re.IGNORECASE,
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
    external_summaries = {}
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
        _, inline_refs = _template_inline_script_effects(
            root,
            template_file,
            source_cache,
            scanned_scripts,
            static_asset_index,
            external_summaries,
        )
        for name, target in inline_refs:
            _append_ref(refs, seen_refs, name, target)
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

    # Python strings count only in JavaScript-consuming positions, and only
    # for classic scripts that the project actually loads into a page.
    names, patterns = _python_string_browser_names(root, source_files, source_cache)
    project_index = None
    if any(
        Path(path).suffix.lower() in _PYTHON_SOURCE_SUFFIXES for path in source_files
    ):
        from skylos.deadcode.python_browser_effects import project_browser_names
        from skylos.deadcode.python_project_sources import ProjectSourceIndex

        project_index = ProjectSourceIndex(root, source_files)
        project_names, project_patterns = project_browser_names(project_index)
        names.update(project_names)
        patterns.update(project_patterns)
    if names or patterns:
        loaded_scripts = _python_loaded_classic_scripts(
            root,
            source_files,
            source_cache,
            scanned_scripts,
            static_asset_index,
            template_files,
        )
        if project_index is not None:
            from skylos.deadcode.python_browser_effects import (
                project_script_entry_files,
            )

            loaded_scripts.update(
                project_script_entry_files(project_index, classic_only=True)
                & scanned_scripts
            )
        globals_by_name: dict[str, list[Path]] = {}
        for script_file in sorted(loaded_scripts):
            if script_file.suffix.lower() in _MODULE_ONLY_SUFFIXES:
                continue
            source = _read_text(root, script_file, source_cache)
            if source is None or not _is_classic_script(source):
                continue
            for name in _top_level_browser_names(source):
                globals_by_name.setdefault(name, []).append(script_file)
        matcher = _compile_name_patterns(patterns)
        for name, script_files in sorted(globals_by_name.items()):
            if len(script_files) != 1:
                continue
            if name in names or (matcher is not None and matcher.fullmatch(name)):
                _append_ref(refs, seen_refs, name, script_files[0])

    return refs


_MODULE_ONLY_SUFFIXES = {".mjs", ".cjs", ".mts", ".cts"}
_JS_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][\w$]*")
# A computed part of a Python string; never valid in a JS identifier.
_PLACEHOLDER = "\x00"
_TEMPLATE_TOKEN_RE = re.compile(
    r"(?<![.\w$\x00])(?P<name>[A-Za-z_$\x00][\w$\x00]*)\s*\("
)
_TEMPLATE_WINDOW_CALL_RE = re.compile(
    r"\bwindow\s*\.\s*(?P<name>[A-Za-z_$\x00][\w$\x00]*)\s*\("
)
_TEMPLATE_NAME_RE = re.compile(r"[A-Za-z_$\x00][\w$\x00]*")
_MIN_PATTERN_LITERAL = 3
_ES_MODULE_RE = re.compile(r"^\s*(?:import\s*(?:[\w${*]|[\"'])|export\s)", re.MULTILINE)
_COMMONJS_EXPORT_RE = re.compile(r"\b(?:module\.exports|exports\.[A-Za-z_$][\w$]*)\s*=")
_TOP_LEVEL_BROWSER_NAME_RES = (
    re.compile(
        r"^(?:async\s+)?function\s*\*?\s*(?P<name>[A-Za-z_$][\w$]*)", re.MULTILINE
    ),
    re.compile(r"^(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=", re.MULTILINE),
)


def _is_classic_script(source: str) -> bool:
    """No ES module or CommonJS export syntax: its top level is page-global."""
    return not _ES_MODULE_RE.search(source) and not _COMMONJS_EXPORT_RE.search(source)


def _top_level_browser_names(source: str) -> set[str]:
    names = set()
    for pattern in _TOP_LEVEL_BROWSER_NAME_RES:
        for match in pattern.finditer(source):
            names.add(match.group("name"))
    return names


def _python_string_browser_names(
    root: Path, source_files, source_cache: dict[Path, str]
) -> tuple[set[str], set[str]]:
    names: set[str] = set()
    patterns: set[str] = set()
    for raw_file in source_files:
        file_path = Path(raw_file)
        if file_path.suffix.lower() not in _PYTHON_SOURCE_SUFFIXES:
            continue
        source = _read_text(root, file_path, source_cache)
        if not source:
            continue
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            continue
        from skylos.deadcode.python_source_proofs import (
            _PythonReferenceProof,
        )

        proof = _PythonReferenceProof(tree, root, file_path)
        for scope, bindings in proof.contexts():
            for template in _python_string_templates(scope):
                parser = _PythonBrowserCode()
                try:
                    parser.feed(template)
                    parser.close()
                except (ValueError, RecursionError):
                    continue
                for code in parser.code:
                    _template_browser_names(code, names, patterns, allow_bare=False)
    return names, patterns


def _python_string_templates(tree: ast.AST):
    """Each string a Python expression builds, computed parts as placeholders.

    A bare string statement (a docstring) is not a value and is skipped.
    """
    from skylos.deadcode.python_source_proofs import _scope_nodes

    nodes = list(_scope_nodes(tree))
    skipped: set[int] = set()
    for node in nodes:
        if isinstance(node, ast.Expr) and _string_parts(node.value) is not None:
            skipped.update(id(part) for part in _string_nodes(node.value))
    for node in nodes:
        if id(node) in skipped:
            continue
        parts = _string_parts(node)
        if parts is None:
            continue
        skipped.update(id(part) for part in _string_nodes(node))
        yield "".join(parts)


def _string_parts(node: ast.AST) -> list[str] | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue) and (
                value.conversion != -1 or value.format_spec is not None
            ):
                return None
            else:
                parts.append(_PLACEHOLDER)
        return parts
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _string_parts(node.left), _string_parts(node.right)
        if left is None and right is None:
            return None
        return (left or [_PLACEHOLDER]) + (right or [_PLACEHOLDER])
    return None


def _string_nodes(node: ast.AST):
    """The string-building nodes a template consumed (not computed parts)."""
    if isinstance(node, (ast.Constant, ast.JoinedStr)):
        yield node
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.Constant):
                    yield value
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        yield node
        for side in (node.left, node.right):
            if _string_parts(side) is not None:
                yield from _string_nodes(side)


def _template_browser_names(
    template: str, names: set[str], patterns: set[str], *, allow_bare: bool = True
) -> None:
    def add(token: str) -> None:
        if _PLACEHOLDER not in token:
            if token not in _JS_CONTROL_WORDS:
                names.add(token)
            return
        if len(token.replace(_PLACEHOLDER, "")) >= _MIN_PATTERN_LITERAL:
            patterns.add(token)

    stripped = template.strip()
    if (
        allow_bare
        and _TEMPLATE_NAME_RE.fullmatch(stripped)
        and stripped != _PLACEHOLDER
    ):
        add(stripped)
    for token in _javascript_global_calls(template):
        add(token)


def _javascript_global_calls(source):
    """Calls in JS syntax, excluding comments, string data and local bindings."""
    from skylos.visitors.languages.typescript.file_references import _TS_PARSER

    if _TS_PARSER is None:
        return set()
    marker = "_SKYLOS_DYNAMIC_"
    while marker in source:
        marker += "X"
    text = source.replace(_PLACEHOLDER, marker).encode("utf-8")
    try:
        root = _TS_PARSER.parse(text).root_node
    except (ValueError, RecursionError):
        return set()
    nodes = [root]
    calls = []
    bound = set()
    while nodes:
        node = nodes.pop()
        nodes.extend(node.named_children)
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function is not None:
                calls.append(function)
        elif node.type in {
            "variable_declarator",
            "function_declaration",
            "class_declaration",
        }:
            name = node.child_by_field_name("name")
            if name is not None and name.type == "identifier":
                bound.add(text[name.start_byte : name.end_byte].decode("utf-8"))
        elif node.type in {"formal_parameters", "catch_clause"}:
            pending = list(node.named_children)
            while pending:
                child = pending.pop()
                if child.type == "identifier":
                    bound.add(text[child.start_byte : child.end_byte].decode("utf-8"))
                else:
                    pending.extend(child.named_children)
    names = set()
    for function in calls:
        name = None
        if function.type == "identifier":
            name = text[function.start_byte : function.end_byte].decode("utf-8")
        elif function.type == "member_expression" and "window" not in bound:
            receiver = function.child_by_field_name("object")
            attribute = function.child_by_field_name("property")
            if (
                receiver is not None
                and attribute is not None
                and text[receiver.start_byte : receiver.end_byte] == b"window"
            ):
                name = text[attribute.start_byte : attribute.end_byte].decode("utf-8")
        if name is not None and name not in bound:
            names.add(name.replace(marker, _PLACEHOLDER))
    return names


class _PythonBrowserCode(HTMLParser):
    """JavaScript positions in HTML, excluding prose and data scripts."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.code = []
        self.in_script = False

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "script":
            script_type = (attributes.get("type") or "").strip().lower()
            self.in_script = (
                script_type in _CLASSIC_SCRIPT_TYPES and not attributes.get("src")
            )
        for name, value in attrs:
            if not value:
                continue
            if name.startswith("on") and name[2:] in _DOM_EVENT_ATTRIBUTES.split("|"):
                self.code.append(value)
            elif name in {
                "href",
                "src",
                "action",
            } and value.lstrip().lower().startswith("javascript:"):
                self.code.append(value.lstrip()[len("javascript:") :])

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False

    def handle_data(self, data):
        if self.in_script:
            self.code.append(data)


_GRADIO_COMPONENTS = {
    "Button",
    "Checkbox",
    "CheckboxGroup",
    "ColorPicker",
    "Dataframe",
    "Dropdown",
    "File",
    "Gallery",
    "HTML",
    "Image",
    "Markdown",
    "Number",
    "Radio",
    "Slider",
    "State",
    "Textbox",
    "Video",
    "Audio",
    "Blocks",
    "Interface",
    "Tab",
    "Tabs",
    "Row",
    "Column",
    "Group",
    "Accordion",
}
_GRADIO_EVENTS = {
    "click",
    "change",
    "input",
    "submit",
    "select",
    "load",
    "release",
    "upload",
    "clear",
    "play",
    "pause",
    "stop",
    "end",
    "blur",
    "focus",
    "then",
    "success",
}
_SELENIUM_DRIVERS = {"Chrome", "Firefox", "Safari", "Edge", "Ie", "Remote"}


def _browser_api_arguments(call, bindings, proof):
    provider = proof.qualified(call.func, bindings)
    if provider == "nicegui.ui.run_javascript":
        if call.args:
            yield call.args[0]
        return
    if not isinstance(call.func, ast.Attribute):
        return
    receiver = proof.substitute(call.func.value, bindings)
    if isinstance(call.func.value, ast.Name) and call.func.value.id in proof.invalid:
        return
    while (
        isinstance(receiver, ast.Call)
        and isinstance(receiver.func, ast.Attribute)
        and receiver.func.attr in _GRADIO_EVENTS
    ):
        receiver = proof.substitute(receiver.func.value, bindings)
    if not isinstance(receiver, ast.Call):
        return
    constructor = proof.qualified(receiver.func, bindings)
    package, _, component = constructor.rpartition(".")
    if (
        package in {"gradio", "gradio.components", "gradio.layouts"}
        and component in _GRADIO_COMPONENTS
        and call.func.attr in _GRADIO_EVENTS
    ):
        for keyword in call.keywords:
            if keyword.arg in {"_js", "js"}:
                yield keyword.value
    elif (
        package == "selenium.webdriver"
        and component in _SELENIUM_DRIVERS
        and call.func.attr in {"execute_script", "execute_async_script"}
    ):
        if call.args:
            yield call.args[0]


def _python_loaded_classic_scripts(
    root, source_files, source_cache, scanned_scripts, static_asset_index, templates
):
    loaded = _collect_template_script_files(
        root,
        templates,
        source_cache,
        include_modules=False,
        static_asset_index=static_asset_index,
        allowed_files=scanned_scripts,
    )
    return loaded


def _compile_name_patterns(patterns: set[str]):
    if not patterns:
        return None
    alternatives = []
    for pattern in sorted(patterns):
        parts = []
        for char in pattern:
            if char == _PLACEHOLDER:
                parts.append("[\\w$]*")
            else:
                parts.append(re.escape(char))
        alternatives.append("(?:" + "".join(parts) + ")")
    return re.compile("|".join(alternatives))


def _python_event_handler_names(
    root: Path, source_files, source_cache: dict[Path, str]
) -> set[str]:
    names: set[str] = set()
    for raw_file in source_files:
        file_path = Path(raw_file)
        if file_path.suffix.lower() not in _PYTHON_SOURCE_SUFFIXES:
            continue
        source = _read_text(root, file_path, source_cache)
        if not source or not _PYTHON_EVENT_HANDLER_RE.search(source):
            continue
        for match in _PYTHON_EVENT_HANDLER_RE.finditer(
            _without_python_comments(source)
        ):
            handler = match.group("double")
            if handler is None:
                handler = match.group("single")
            names.update(_extract_call_names(_normalize_handler_source(handler)))
    return names


def _without_python_comments(source: str) -> str:
    """Blank ``#`` comments: a commented-out handler does not name a function."""
    try:
        comments = [
            token.start
            for token in tokenize.generate_tokens(io.StringIO(source).readline)
            if token.type == tokenize.COMMENT
        ]
    except (tokenize.TokenError, SyntaxError):
        return source
    if not comments:
        return source
    lines = source.splitlines(keepends=True)
    for row, col in comments:
        line = lines[row - 1]
        lines[row - 1] = line[:col] + line[len(line.rstrip("\r\n")) :]
    return "".join(lines)


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
    source_cache: dict[Path, str] = {}
    static_asset_index = _build_static_asset_index(root, scanned_scripts)
    external_summaries = {}
    entries = _collect_template_script_files(
        root,
        list(template_files),
        source_cache,
        include_modules=True,
        static_asset_index=static_asset_index,
        allowed_files=scanned_scripts,
    )
    for template_file in template_files:
        inline_entries, _ = _template_inline_script_effects(
            root,
            template_file,
            source_cache,
            scanned_scripts,
            static_asset_index,
            external_summaries,
        )
        entries.update(inline_entries)
    return entries


class _TemplateScripts(HTMLParser):
    """Keep executable inline bodies separate from text and inert markup."""

    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.scripts = []
        self.current = None
        self.inert_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"template", "noscript"}:
            self.inert_depth += 1
        if tag != "script" or self.inert_depth:
            return
        names = [name for name, _ in attrs]
        if len(names) != len(set(names)):
            return
        attributes = dict(attrs)
        self.current = (attributes, [])

    def handle_endtag(self, tag):
        if tag == "script" and self.current is not None:
            attributes, chunks = self.current
            self.scripts.append((attributes, "".join(chunks)))
            self.current = None
        if tag in {"template", "noscript"} and self.inert_depth:
            self.inert_depth -= 1

    def handle_data(self, data):
        if self.current is not None:
            self.current[1].append(data)


class _InlineScriptConsumers:
    """Prove calls and DOM callbacks without walking uninvoked callables."""

    _CALLABLES = {
        "function_declaration",
        "function_expression",
        "arrow_function",
    }
    _GENERATORS = {"generator_function_declaration", "generator_function"}
    _BLOCK_SCOPES = {
        "statement_block",
        "for_statement",
        "for_in_statement",
        "catch_clause",
        "switch_statement",
    }

    def __init__(self, source, resolve_import, inherited_bindings):
        from skylos.visitors.languages.typescript.file_references import _TS_PARSER

        self.text = source.encode("utf-8")
        self.root = None
        self.imports = {}
        self.import_bound = set()
        self.entries = set()
        self.names = set()
        self.refs = set()
        self.writes = set()
        self.visited = {}
        self.module_syntax = False
        self.supported = False
        self.inherited_bindings = inherited_bindings
        if _TS_PARSER is None:
            return
        try:
            root = _TS_PARSER.parse(self.text).root_node
        except (ValueError, RecursionError):
            return
        if root.has_error:
            return
        self.root = root
        self.supported = not self.unmodeled_completion(root)
        for statement in root.named_children:
            if statement.type in {"import_statement", "export_statement"}:
                self.module_syntax = True
            if statement.type != "import_statement":
                continue
            source_node = statement.child_by_field_name("source")
            if source_node is None or source_node.type != "string":
                continue
            literal = self.value(source_node)
            if len(literal) < 2 or "\\" in literal:
                continue
            target = resolve_import(literal[1:-1])
            if target is not None:
                self.entries.add(target)
            pending = list(statement.named_children)
            while pending:
                child = pending.pop()
                if child.type == "import_specifier":
                    name = child.child_by_field_name("name")
                    alias = child.child_by_field_name("alias")
                    if name is None:
                        continue
                    if alias is None:
                        alias = name
                    local = self.value(alias)
                    self.import_bound.add(local)
                    if target is not None:
                        self.imports[local] = (target, self.value(name))
                elif child.type == "namespace_import":
                    identifiers = [
                        node
                        for node in child.named_children
                        if node.type == "identifier"
                    ]
                    if identifiers:
                        local = self.value(identifiers[-1])
                        self.import_bound.add(local)
                        if target is not None:
                            self.imports[local] = (target, "*")
                elif child.type == "import_clause":
                    for node in child.named_children:
                        if node.type == "identifier":
                            self.import_bound.add(self.value(node))
                    pending.extend(child.named_children)
                else:
                    pending.extend(child.named_children)

    def value(self, node):
        return self.text[node.start_byte : node.end_byte].decode("utf-8")

    def unmodeled_completion(self, root):
        """Decline call-use proof where completion paths are not modeled.

        Static import declarations still prove file loading. A direct function
        return is handled by the sequence walker; nested returns, exceptions,
        switch dispatch and loop jumps retain the prior static findings.
        """
        pending = [root]
        while pending:
            node = pending.pop()
            if node.type in self._GENERATORS | {"class", "class_declaration"}:
                continue
            if node.type in {
                "try_statement",
                "switch_statement",
                "throw_statement",
                "break_statement",
                "continue_statement",
            }:
                return True
            if node.type == "return_statement":
                parent = node.parent
                if parent is None or parent.type != "statement_block":
                    return True
                function = parent.parent
                if function is None or function.type not in self._CALLABLES:
                    return True
            pending.extend(node.named_children)
        return False

    def bindings(self, scope):
        bound = set()
        callables = {}
        if scope.type == "catch_clause":
            bound.update(self.written_names(scope.child_by_field_name("parameter")))
        pending = list(scope.named_children)
        while pending:
            node = pending.pop()
            if node.type in self._BLOCK_SCOPES:
                continue
            if (
                node.type in self._CALLABLES | self._GENERATORS
                or node.type == "class_declaration"
            ):
                name = node.child_by_field_name("name")
                if name is not None:
                    bound.add(self.value(name))
                    if node.type in self._CALLABLES:
                        callables[self.value(name)] = node
                continue
            if node.type == "variable_declarator":
                name = node.child_by_field_name("name")
                if name is not None and name.type == "identifier":
                    bound.add(self.value(name))
                elif name is not None:
                    children = list(name.named_children)
                    while children:
                        child = children.pop()
                        if child.type in {
                            "identifier",
                            "shorthand_property_identifier_pattern",
                        }:
                            bound.add(self.value(child))
                        children.extend(child.named_children)
            pending.extend(node.named_children)
        return bound, callables

    def written_names(self, node):
        if node is None:
            return set()
        if node.type == "identifier":
            return {self.value(node)}
        if node.type == "member_expression":
            receiver = node.child_by_field_name("object")
            attribute = node.child_by_field_name("property")
            if (
                receiver is not None
                and attribute is not None
                and self.value(receiver) == "window"
            ):
                return {self.value(attribute), self.value(node)}
            return {self.value(node)}
        if node.type == "subscript_expression":
            receiver = node.child_by_field_name("object")
            index = node.child_by_field_name("index")
            if (
                receiver is not None
                and index is not None
                and self.value(receiver) == "window"
                and index.type == "string"
            ):
                literal = self.value(index)
                if "\\" not in literal and len(literal) > 2:
                    return {literal[1:-1]}
            return set()
        names = set()
        for child in node.named_children:
            names.update(self.written_names(child))
        return names

    def consume(self, node, bound, callables, *, deferred=False):
        if node.type == "parenthesized_expression" and len(node.named_children) == 1:
            self.consume(node.named_children[0], bound, callables, deferred=deferred)
            return
        if node.type in self._CALLABLES:
            self.invoke(node, bound, callables, propagate=not deferred)
            return
        if node.type == "identifier":
            name = self.value(node)
            if name in callables:
                self.invoke(callables[name], bound, callables, propagate=not deferred)
            elif name not in bound:
                if name in self.imports:
                    target, exported = self.imports[name]
                    if exported != "*":
                        self.refs.add((exported, str(target)))
                elif name not in self.import_bound:
                    self.names.add(name)
            return
        if node.type != "member_expression":
            return
        if self.value(node) in bound:
            return
        receiver = node.child_by_field_name("object")
        attribute = node.child_by_field_name("property")
        if receiver is None or attribute is None or receiver.type != "identifier":
            return
        owner = self.value(receiver)
        name = self.value(attribute)
        if owner in bound:
            return
        if owner == "window" and owner not in self.import_bound and name not in bound:
            self.names.add(name)
        elif owner in self.imports:
            target, exported = self.imports[owner]
            if exported == "*":
                self.refs.add((name, str(target)))

    def invoke(self, node, bound, callables, *, propagate=True):
        identity = (node.start_byte, node.end_byte, frozenset(bound), propagate)
        if identity in self.visited:
            if propagate:
                bound.update(self.visited[identity])
            return
        # Repeated/recursive local calls cannot turn a bounded template read
        # into an unbounded call-graph exploration.
        if len(self.visited) >= 128:
            return
        self.visited[identity] = set()
        body = node.child_by_field_name("body")
        if body is None:
            return
        local, functions = self.bindings(body)
        parameters = node.child_by_field_name("parameters")
        if parameters is None:
            parameters = node.child_by_field_name("parameter")
        if parameters is not None:
            pending = [parameters]
            while pending:
                child = pending.pop()
                if child.type == "identifier":
                    local.add(self.value(child))
                pending.extend(child.named_children)
        inherited = {
            name: function for name, function in callables.items() if name not in local
        }
        inherited.update(functions)
        nested = bound | local
        self.walk(body, nested, inherited)
        self.visited[identity] = nested - local
        if propagate:
            bound.update(nested - local)

    def dom_listener(self, function, bound):
        if function.type != "member_expression":
            return False
        if self.value(function) in bound:
            return False
        receiver = function.child_by_field_name("object")
        attribute = function.child_by_field_name("property")
        if (
            receiver is None
            or attribute is None
            or self.value(attribute) != "addEventListener"
        ):
            return False
        if receiver.type == "identifier":
            name = self.value(receiver)
            return (
                name in {"document", "window"} and name not in bound | self.import_bound
            )
        if receiver.type != "call_expression":
            return False
        selector = receiver.child_by_field_name("function")
        if selector is None or selector.type != "member_expression":
            return False
        owner = selector.child_by_field_name("object")
        method = selector.child_by_field_name("property")
        return (
            owner is not None
            and method is not None
            and self.value(owner) == "document"
            and "document" not in bound | self.import_bound
            and self.value(method) in {"getElementById", "querySelector"}
            and self.value(selector) not in bound
        )

    def truth(self, node):
        if node is None:
            return None
        if node.type == "parenthesized_expression" and len(node.named_children) == 1:
            return self.truth(node.named_children[0])
        if node.type == "true":
            return True
        if node.type in {"false", "null"}:
            return False
        if node.type == "number":
            literal = self.value(node).replace("_", "").removesuffix("n")
            try:
                return bool(int(literal, 0))
            except ValueError:
                try:
                    return bool(float(literal))
                except ValueError:
                    return None
        if node.type == "string":
            literal = self.value(node)
            if "\\" not in literal:
                return len(literal) > 2
        if node.type == "unary_expression":
            operator = node.child_by_field_name("operator")
            argument = node.child_by_field_name("argument")
            value = self.truth(argument)
            if value is not None and operator is not None:
                if operator.type == "!":
                    return not value
                if operator.type in {"+", "-"}:
                    return value
        return None

    @staticmethod
    def join(bound, callables, alternatives):
        bound.clear()
        bound.update(set.intersection(*(state[0] for state in alternatives)))
        common = dict(alternatives[0][1])
        for _, functions in alternatives[1:]:
            common = {
                name: node
                for name, node in common.items()
                if functions.get(name) == node
            }
        callables.clear()
        callables.update(common)

    def walk_loop(self, node, bound, callables):
        local, functions = self.bindings(node)
        loop_bound = bound | local
        loop_functions = {
            name: function for name, function in callables.items() if name not in local
        }
        loop_functions.update(functions)
        initializer = node.child_by_field_name("initializer")
        condition = node.child_by_field_name("condition")
        body = node.child_by_field_name("body")
        increment = node.child_by_field_name("increment")
        if node.type == "for_in_statement":
            initializer = node.child_by_field_name("right")
            loop_bound.update(self.written_names(node.child_by_field_name("left")))
        if initializer is not None:
            self.walk(initializer, loop_bound, loop_functions)
        if condition is not None:
            self.walk(condition, loop_bound, loop_functions)
        if self.truth(condition) is False:
            bound.update(loop_bound - local)
            return
        zero = (set(loop_bound), dict(loop_functions))
        if body is not None:
            self.walk(body, loop_bound, loop_functions)
        if increment is not None:
            self.walk(increment, loop_bound, loop_functions)
        self.join(
            loop_bound, loop_functions, [zero, (set(loop_bound), dict(loop_functions))]
        )
        bound.update(loop_bound - local)
        for name in list(callables):
            if name not in local and name not in loop_functions:
                callables.pop(name, None)

    def walk(self, node, bound, callables):
        if node.type in self._CALLABLES | self._GENERATORS or node.type in {
            "class_declaration",
            "class",
        }:
            return
        if node.type == "binary_expression":
            operator = node.child_by_field_name("operator")
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if (
                operator is not None
                and operator.type in {"&&", "||"}
                and left is not None
                and right is not None
            ):
                self.walk(left, bound, callables)
                known = self.truth(left)
                if (operator.type == "&&" and known is False) or (
                    operator.type == "||" and known is True
                ):
                    return
                if known is None:
                    skipped = (set(bound), dict(callables))
                    self.walk(right, bound, callables)
                    self.join(
                        bound, callables, [skipped, (set(bound), dict(callables))]
                    )
                else:
                    self.walk(right, bound, callables)
                return
        if node.type == "if_statement":
            condition = node.child_by_field_name("condition")
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")
            if condition is not None:
                self.walk(condition, bound, callables)
            known = self.truth(condition)
            if known is not None:
                selected = consequence
                if known is False:
                    selected = alternative
                if selected is not None:
                    self.walk(selected, bound, callables)
                return
            states = []
            for branch in (consequence, alternative):
                nested = set(bound)
                functions = dict(callables)
                if branch is not None:
                    self.walk(branch, nested, functions)
                states.append((nested, functions))
            self.join(bound, callables, states)
            return
        if node.type in {"while_statement", "for_statement", "for_in_statement"}:
            self.walk_loop(node, bound, callables)
            return
        if node.type in self._BLOCK_SCOPES:
            local, functions = self.bindings(node)
            nested = bound | local
            inherited = {
                name: function
                for name, function in callables.items()
                if name not in local
            }
            inherited.update(functions)
            for child in node.named_children:
                self.walk(child, nested, inherited)
                if child.type in {"return_statement", "throw_statement"}:
                    break
            bound.update(nested - local)
            for name in list(callables):
                if name not in local and name not in inherited:
                    callables.pop(name, None)
            return
        if node.type in {
            "variable_declarator",
            "assignment_expression",
            "augmented_assignment_expression",
        }:
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name is None:
                name = node.child_by_field_name("left")
                value = node.child_by_field_name("right")
            if value is not None:
                self.walk(value, bound, callables)
                for written in self.written_names(name):
                    bound.add(written)
                    callables.pop(written, None)
                    if node.type != "variable_declarator":
                        self.writes.add(written)
                if (
                    name is not None
                    and name.type == "identifier"
                    and value.type in self._CALLABLES
                ):
                    callables[self.value(name)] = value
            return
        if node.type == "update_expression":
            argument = node.child_by_field_name("argument")
            for written in self.written_names(argument):
                bound.add(written)
                callables.pop(written, None)
                self.writes.add(written)
            return
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            if function is not None:
                self.consume(function, bound, callables)
                if arguments is not None and self.dom_listener(function, bound):
                    values = arguments.named_children
                    if len(values) >= 2 and values[0].type == "string":
                        self.consume(values[1], bound, callables, deferred=True)
        for child in node.named_children:
            self.walk(child, bound, callables)
            if node.type in {"program", "statement_block"} and child.type in {
                "return_statement",
                "throw_statement",
            }:
                break

    def collect(self):
        if self.root is None or not self.supported:
            return set()
        bound, functions = self.bindings(self.root)
        active = bound | (self.inherited_bindings - self.import_bound)
        self.walk(self.root, active, functions)
        return active


def _external_classic_summary(source):
    """Immutable source facts; resolution and inline page state stay separate."""
    if not _is_classic_script(source):
        return True, frozenset(), frozenset()
    external = _InlineScriptConsumers(source, lambda path: None, set())
    if not external.supported:
        return False, frozenset(), frozenset()
    try:
        external.collect()
    except RecursionError:
        return None
    return (
        True,
        frozenset(_top_level_browser_names(source) - external.writes),
        frozenset(external.writes),
    )


def _template_inline_script_effects(
    root,
    template_file,
    source_cache,
    scanned_scripts,
    static_asset_index,
    external_summaries,
):
    # Component single-file formats compile their scripts as modules, rather
    # than executing them with the browser's HTML script-tag semantics.
    if template_file.suffix.lower() not in {".html", ".htm"}:
        return set(), set()
    source = _read_text(root, template_file, source_cache)
    if source is None:
        return set(), set()
    parser = _TemplateScripts()
    try:
        parser.feed(_strip_template_comments(source))
        parser.close()
    except (ValueError, RecursionError):
        return set(), set()
    entries = set()
    refs = set()
    globals_by_name = {}
    page_bindings = set()

    def resolve_import(path):
        resolved = _resolve_script_src(
            root, template_file.parent, path, static_asset_index=static_asset_index
        )
        if resolved in scanned_scripts:
            return resolved
        return None

    for attributes, code in parser.scripts:
        script_type = (attributes.get("type") or "").strip().lower()
        is_module = script_type == "module"
        if not is_module and script_type not in _CLASSIC_SCRIPT_TYPES:
            continue
        if "src" in attributes:
            if is_module or "defer" in attributes or "async" in attributes:
                continue
            target = resolve_import(attributes["src"] or "")
            if target is None:
                continue
            script_source = _read_text(root, target, source_cache)
            if script_source is not None:
                if target not in external_summaries:
                    external_summaries[target] = _external_classic_summary(
                        script_source
                    )
                summary = external_summaries[target]
                if summary is None:
                    continue
                supported, names, writes = summary
                if not supported:
                    globals_by_name.clear()
                    continue
                for name in writes:
                    globals_by_name.pop(name, None)
                page_bindings.update(writes)
                for name in names:
                    globals_by_name.setdefault(name, set()).add(target)
            continue
        proof = _InlineScriptConsumers(code, resolve_import, page_bindings)
        if not is_module and proof.module_syntax:
            continue
        try:
            bindings = proof.collect()
        except RecursionError:
            continue
        if is_module:
            entries.update(proof.entries)
            refs.update(proof.refs)
        else:
            page_bindings.update(bindings)
        for name in proof.names:
            targets = globals_by_name.get(name, set())
            if len(targets) == 1:
                refs.add((name, str(next(iter(targets)))))
    return entries, refs


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

    literal = _template_literal_script_path(src)
    if literal is not None:
        literal_path, static_only = literal
        if not static_only:
            # Theme-style templates name assets relative to their own folder.
            candidate = _resolve_readable_project_file(
                root, template_dir / literal_path
            )
            if candidate is not None:
                return candidate
        matches = static_asset_index.get(literal_path, set())
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


def _template_literal_script_path(src: str) -> tuple[str, bool] | None:
    """The script path inside a template expression that only quotes it.

    Returns the path and whether it names a static asset (``url_for``).
    """
    static_only = False
    match = _TEMPLATE_LITERAL_SRC_RE.fullmatch(src)
    if match is None:
        match = _URL_FOR_STATIC_SRC_RE.fullmatch(src)
        static_only = True
    if match is None:
        return None
    raw_path = match.group("path").strip().lstrip("/")
    if not raw_path or any(
        character in raw_path for character in ("\\", "\x00", ":", "?", "#")
    ):
        return None
    parts = raw_path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return None
    normalized = PurePosixPath(*parts)
    if normalized.suffix.lower() not in _JS_SOURCE_SUFFIXES:
        return None
    return normalized.as_posix(), static_only


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
