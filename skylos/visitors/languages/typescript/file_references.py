"""JS/TS files that another repository file names by path.

The import graph sees ``import``/``require`` only. Build tools, test runners,
templates, CI jobs and other languages load JS/TS files by path instead:
``tsconfig.json`` ``files``, ``mkdocs.yml`` ``extra_javascript``,
``<script src="{{ 'js/app.js'|url }}">``, ``node scripts/build.js`` in a
workflow, ``subprocess.run(["node", here / "build.js"])`` in Python or
``new Worker("search/worker.js")`` in another script.

A reference counts only in a loading position: a runtime's script operand,
an evidenced subprocess call, a script src, a browser worker/importScripts
argument, or a supported configuration's file-loading field. Its path must
resolve to exactly one scanned file:

* relative to the referencing file's directory or to the project root, with
  or without the file extension, or as a directory ``index`` file;
* else as the trailing path segments (``search/worker.js``) of exactly one
  scanned file, because deployed URLs keep the source tree's tail but drop
  its prefix. A bare file name (``worker.js``) is accepted this way only from
  another JS/TS file, whose own liveness then decides the target's.

References in comments, docstrings and Markdown prose are ignored: a mention
is not a load. A reference from an analysed JS/TS file is an edge (the target
lives only while the referencing file does); one from any other file is a
root.
"""

from __future__ import annotations

import ast
import fnmatch
import json
import os
import re
import shlex
from collections import defaultdict
from html.parser import HTMLParser
from pathlib import Path

import yaml

from skylos.core.file_discovery import discover_source_files
from skylos.deadcode.python_source_proofs import _PythonReferenceProof, _scope_nodes
from skylos.core.safe_cache_io import read_text_no_symlink

_JS_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")
_MAX_REFERENCE_FILE_BYTES = 512 * 1024
_MAX_REFERENCE_FILES = 20_000

_STRUCTURED_SUFFIXES = (".json", ".jsonc", ".json5")
_HASH_COMMENT_SUFFIXES = (
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".sh",
    ".bash",
    ".zsh",
)
_TEMPLATE_SUFFIXES = (
    ".html",
    ".htm",
    ".jinja",
    ".jinja2",
    ".j2",
    ".njk",
    ".hbs",
    ".handlebars",
    ".ejs",
    ".liquid",
    ".vue",
    ".svelte",
    ".astro",
)
_PYTHON_SUFFIXES = (".py",)
_REFERENCE_SUFFIXES = (
    *_STRUCTURED_SUFFIXES,
    *_HASH_COMMENT_SUFFIXES,
    *_TEMPLATE_SUFFIXES,
    *_PYTHON_SUFFIXES,
)
# Extension-less files whose commands run scripts by path.
_COMMAND_FILE_NAMES = frozenset(
    {"Makefile", "makefile", "GNUmakefile", "Dockerfile", "Procfile", "justfile"}
)
# Lock files list packages, not the project's own files. ``package.json``
# entry fields and scripts are resolved by the package-entry discovery, which
# also decides whether that package is part of the analysed workspace.
_SKIPPED_FILE_NAMES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lock",
        "composer.lock",
        "poetry.lock",
        "Pipfile.lock",
        "uv.lock",
        "Cargo.lock",
    }
)

# Characters accepted in a complete static path operand. Unknown placeholders
# and prose are not converted into evidence by extracting a matching fragment.
_PATH_TOKEN_RE = re.compile(r"[A-Za-z0-9_@~+.\-/]+")
_TEMPLATE_LITERAL_PATH_RE = re.compile(
    r"""^\{\{-?\s*(["'])(?P<path>.*?)\1(?:\s*\|\s*(?:url|relative_url|asset_url|safe))*\s*-?\}\}$"""
)
_TEMPLATE_COMMENT_RES = (
    re.compile(r"<!--[\s\S]*?-->"),
    re.compile(r"{#[\s\S]*?#}"),
    re.compile(r"{%-?\s*comment\s*-?%}[\s\S]*?{%-?\s*endcomment\s*-?%}"),
)
_SCRIPT_RUNNERS = frozenset({"node", "nodejs", "tsx", "ts-node", "bun", "deno", "k6"})
_PYTHON_PROCESS_CALLS = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "os.system",
        "os.popen",
    }
)


class _ScriptSources(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.paths = []
        self.sources = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            values = [value for name, value in attrs if name == "src" and value]
            if len(values) == 1:
                self.paths.append(values[0])
                self.sources.append((values[0], attrs))


_MODULE_SPECIFIER_CALLS = frozenset({"require", "import"})
_JS_STRING_NODE_TYPES = frozenset({"string", "template_string"})
_JS_STRING_TEXT_TYPES = frozenset({"string_fragment"})

try:
    import tree_sitter_typescript as _tsts
    from tree_sitter import Language, Parser

    _TS_PARSER: Parser | None = Parser(Language(_tsts.language_typescript()))
    _TSX_PARSER: Parser | None = Parser(Language(_tsts.language_tsx()))
except Exception:  # pragma: no cover - grammar packages ship with skylos
    _TS_PARSER = None
    _TSX_PARSER = None


class _FileIndex:
    """Scanned JS/TS files by name, for resolving references to them."""

    def __init__(self, project_root: str, js_files: set[str]) -> None:
        self.root = project_root
        self.by_basename: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for real_path in js_files:
            try:
                relative = os.path.relpath(real_path, project_root)
            except ValueError:
                continue
            relative = relative.replace(os.sep, "/")
            if relative.startswith("../"):
                continue
            self.by_basename[os.path.basename(real_path)].append((relative, real_path))

    def unique_suffix_match(self, suffix: str) -> str | None:
        basename = suffix.rsplit("/", 1)[-1]
        matches = [
            real_path
            for relative, real_path in self.by_basename.get(basename, ())
            if relative == suffix or relative.endswith("/" + suffix)
        ]
        return matches[0] if len(matches) == 1 else None


def _inside(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _exact_candidates(base_dir: str, relative: str, has_extension: bool):
    target = os.path.normpath(os.path.join(base_dir, relative))
    if has_extension:
        yield target
        return
    for extension in _JS_EXTENSIONS:
        yield target + extension
    for extension in _JS_EXTENSIONS:
        yield os.path.join(target, "index" + extension)


def _resolve_token(
    token: str,
    ref_dir: str,
    index: _FileIndex,
    targets: set[str],
    *,
    allow_bare_name: bool,
) -> str | None:
    if token.startswith("//"):
        # Protocol-relative or ``scheme://`` URL: another host's file.
        return None
    relative = token.lstrip("/")
    while relative.startswith("./"):
        relative = relative[2:]
    if not relative or relative.endswith("/"):
        return None
    basename = relative.rsplit("/", 1)[-1]
    has_extension = basename.lower().endswith(_JS_EXTENSIONS)
    has_directory = "/" in relative
    if not has_extension and not has_directory:
        # A bare word is not a path.
        return None

    for base_dir in (ref_dir, index.root):
        for candidate in _exact_candidates(base_dir, relative, has_extension):
            real_candidate = os.path.realpath(candidate)
            if real_candidate in targets and _inside(real_candidate, index.root):
                return real_candidate

    if not has_extension:
        return None
    segments = [part for part in relative.split("/") if part not in {"", "."}]
    while segments and segments[0] == "..":
        segments.pop(0)
    if not segments or ".." in segments:
        return None
    if len(segments) == 1 and not allow_bare_name:
        return None
    match = index.unique_suffix_match("/".join(segments))
    if match in targets:
        return match
    return None


def _tokens(text: str, names: frozenset[str]):
    """A complete path operand, never a path-shaped word inside prose."""
    token = text.strip()
    template = _TEMPLATE_LITERAL_PATH_RE.fullmatch(token)
    if template is not None:
        token = template.group("path")
    if "://" in token or token.startswith("//"):
        return
    token = token.split("?", 1)[0].split("#", 1)[0]
    if _PATH_TOKEN_RE.fullmatch(token) is None:
        return
    last = token.rstrip("/").rsplit("/", 1)[-1]
    if last in names:
        yield token
        return
    stem = last
    for extension in _JS_EXTENSIONS:
        if stem.endswith(extension):
            stem = stem[: -len(extension)]
            break
    if stem in names and "/" in token:
        yield token


def _command_paths(command):
    """Only script operands of a known runtime command, never echo/prose."""
    if isinstance(command, str):
        try:
            tokens = shlex.split(command, comments=True)
        except ValueError:
            return
    else:
        tokens = command
    if not tokens or not isinstance(tokens[0], str):
        return
    runner = os.path.basename(tokens[0])
    if runner not in _SCRIPT_RUNNERS:
        return
    position = 1
    if (
        runner in {"bun", "deno", "k6"}
        and position < len(tokens)
        and tokens[position] == "run"
    ):
        position += 1
    while position < len(tokens):
        token = tokens[position]
        position += 1
        if not isinstance(token, str):
            return
        if token in {"-e", "--eval", "-p", "--print"}:
            return
        if token in {
            "-r",
            "--require",
            "--import",
            "--loader",
            "--experimental-loader",
        }:
            if position < len(tokens) and isinstance(tokens[position], str):
                yield tokens[position]
            position += 1
            continue
        if token in {"--conditions", "--inspect-port", "--title"}:
            position += 1
            continue
        if token.startswith("-"):
            continue
        yield token
        return  # later operands are the script's data, not more entry files


def _shell_load_paths(source: str):
    for line in source.splitlines():
        line = line.strip()
        if line.startswith(("#", "//")):
            continue
        line = re.sub(r"^(?:RUN|CMD|ENTRYPOINT)\s+", "", line)
        line = re.sub(r"^[A-Za-z_][\w-]*:\s+", "", line)
        if line.startswith("["):
            try:
                yield from _command_paths(json.loads(line))
            except (ValueError, TypeError):
                pass
            continue
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            continue
        command = []
        for token in (*tokens, ";"):
            if token in {";", "&&", "||", "|", "&"}:
                yield from _command_paths(command)
                command = []
            else:
                command.append(token)


def _python_load_paths(source: str):
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return
    imports = {}
    assignments = {}
    rebound = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                imports[alias.asname or alias.name] = node.module + "." + alias.name
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append(node.value)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            rebound.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            rebound.add(node.name)
        elif isinstance(node, ast.arg):
            rebound.add(node.arg)

    def dotted(node):
        if isinstance(node, ast.Name):
            return imports.get(node.id, "") if node.id not in rebound else ""
        if isinstance(node, ast.Attribute):
            return dotted(node.value) + "." + node.attr
        return ""

    def literals(node, seen=frozenset()):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.value
        elif isinstance(node, ast.Name) and node.id not in seen and len(seen) < 16:
            values = assignments.get(node.id, ())
            if len(values) == 1:
                yield from literals(values[0], seen | {node.id})
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            yield from literals(node.left, seen)
            yield from literals(node.right, seen)
        elif isinstance(node, ast.Call) and (
            dotted(node.func) in {"os.path.join", "pathlib.Path"}
            or isinstance(node.func, ast.Name)
            and node.func.id == "str"
            and "str" not in rebound
        ):
            for child in node.args:
                yield from literals(child, seen)
        elif isinstance(node, ast.Attribute) and node.attr == "parent":
            yield from literals(node.value, seen)
        elif isinstance(node, (ast.List, ast.Tuple)):
            for child in ast.iter_child_nodes(node):
                yield from literals(child, seen)

    for node in ast.walk(tree):
        if (
            not isinstance(node, ast.Call)
            or dotted(node.func) not in _PYTHON_PROCESS_CALLS
        ):
            continue
        command = (
            node.args[0]
            if node.args
            else next(
                (item.value for item in node.keywords if item.arg == "args"), None
            )
        )
        if isinstance(command, (ast.List, ast.Tuple)):
            args = [list(literals(value)) for value in command.elts]
            yield from _command_paths(
                [os.path.join(*values) if values else None for values in args]
            )
        elif isinstance(command, ast.Constant) and isinstance(command.value, str):
            yield from _command_paths(command.value)


def _config_load_paths(path: Path, source: str):
    if path.suffix.lower() in _STRUCTURED_SUFFIXES:
        # Compilation roots are actual files entries. A notes field, excluded
        # file or commented-out entry is not a load.
        if not re.fullmatch(r"tsconfig(?:\.[\w-]+)?\.jsonc?", path.name, re.IGNORECASE):
            return
        from .workspace import _strip_json_comments, _strip_trailing_commas

        try:
            data = json.loads(_strip_trailing_commas(_strip_json_comments(source)))
        except (ValueError, RecursionError):
            return
        if isinstance(data, dict) and isinstance(data.get("files"), list):
            yield from (value for value in data["files"] if isinstance(value, str))
        return
    try:
        data = yaml.safe_load(source)
    except (yaml.YAMLError, RecursionError):
        return
    if not isinstance(data, dict):
        return
    if path.name.lower() in {"mkdocs.yml", "mkdocs.yaml"}:
        for value in data.get("extra_javascript") or ():
            if isinstance(value, str):
                yield value
            elif isinstance(value, dict) and isinstance(value.get("path"), str):
                yield value["path"]
        return
    normalized = path.as_posix()
    is_ci = (
        "/.github/workflows/" in normalized
        or "/.circleci/" in normalized
        or path.name
        in {
            ".gitlab-ci.yml",
            ".travis.yml",
            "azure-pipelines.yml",
            "bitbucket-pipelines.yml",
        }
    )
    if not is_ci:
        return
    pending, seen = [data], set()
    while pending:
        value = pending.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"run", "script", "before_script", "after_script"}:
                    for command in child if isinstance(child, list) else [child]:
                        if isinstance(command, str):
                            yield from _shell_load_paths(command)
                elif isinstance(child, (dict, list)):
                    pending.append(child)
        elif isinstance(value, list):
            pending.extend(value)


def _python_script_tag_loads(
    source: str, *, root: Path, source_file: Path, classic_only: bool = False
):
    """Resolve rendered script sources through actual directory-producing code.

    Unknown providers, arguments, owners and roots produce no load evidence.
    This deliberately does not infer a directory from a helper's spelling or
    from arbitrary string arguments to that helper.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return
    proof = _PythonReferenceProof(tree, root, source_file)
    for scope, bindings in proof.contexts():
        loops = proof.loops(scope, bindings)
        for node in _scope_nodes(scope):
            if not isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Constant)):
                continue
            for kind, value in _script_tag_sources(node, classic_only=classic_only):
                if kind == "path":
                    path = proof.path(ast.Constant(value), bindings)
                    if path is not None:
                        yield "path", str(path)
                    continue
                expression, prefix = value
                yield from proof.script_values(expression, bindings, loops, prefix)


def _script_tag_sources(node: ast.AST, *, classic_only: bool = False):
    from skylos.deadcode.browser_refs import _CLASSIC_SCRIPT_TYPES

    parts: list[ast.AST] = []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        parts = [node]
    elif isinstance(node, ast.JoinedStr):
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                if value.conversion != -1 or value.format_spec is not None:
                    parts.append(value)
                else:
                    parts.append(value.value)
            else:
                parts.append(value)
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        pending = [node]
        while pending:
            current = pending.pop()
            if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
                pending.extend([current.right, current.left])
            else:
                parts.append(current)
    text = ""
    expressions = {}
    for part in parts:
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            if "\x00" in part.value:
                return
            text += part.value
            continue
        marker = "\x00" + str(len(expressions)) + "\x00"
        expressions[marker] = part
        text += marker
    if "<script" not in text.lower():
        return
    parser = _ScriptSources()
    try:
        parser.feed(text)
        parser.close()
    except (ValueError, RecursionError):
        return
    for value, attrs in parser.sources:
        if classic_only:
            types = [value for name, value in attrs if name == "type"]
            if len(types) > 1:
                continue
            script_type = ""
            if types:
                script_type = (types[0] or "").strip().lower()
            if script_type not in _CLASSIC_SCRIPT_TYPES:
                continue
        matched = [marker for marker in expressions if marker in value]
        if not matched:
            yield "path", value
        elif len(matched) == 1 and value.count(matched[0]) == 1:
            marker = matched[0]
            prefix, suffix = value.split(marker)
            if not suffix:
                yield "expression", (expressions[marker], prefix)


def _reference_texts(path: Path, source: str):
    suffix = path.suffix.lower()
    if suffix in _PYTHON_SUFFIXES:
        yield from _python_load_paths(source)
        return
    if suffix in _TEMPLATE_SUFFIXES:
        for pattern in _TEMPLATE_COMMENT_RES:
            source = pattern.sub("", source)
        parser = _ScriptSources()
        parser.feed(source)
        yield from parser.paths
        return
    if suffix in _STRUCTURED_SUFFIXES or suffix in {".yaml", ".yml"}:
        yield from _config_load_paths(path, source)
        return
    if suffix in {".sh", ".bash", ".zsh"} or path.name in _COMMAND_FILE_NAMES:
        yield from _shell_load_paths(source)
        return


def _is_module_specifier(source: bytes, node) -> bool:
    """``import ... from "x"``, ``export ... from "x"``, ``require("x")``."""
    parent = node.parent
    if parent is None:
        return False
    if parent.type in {"import_statement", "export_statement", "import_require_clause"}:
        return True
    if parent.type != "arguments":
        return False
    call = parent.parent
    if call is None or call.type != "call_expression":
        return False
    function = call.child_by_field_name("function")
    if function is None:
        return False
    if function.type == "import":
        return True
    return (
        function.type == "identifier"
        and source[function.start_byte : function.end_byte].decode("utf-8", "replace")
        in _MODULE_SPECIFIER_CALLS
    )


def _js_string_values(path: str, source: bytes):
    suffix = os.path.splitext(path)[1].lower()
    parser = (
        _TSX_PARSER if suffix in {".js", ".jsx", ".tsx", ".mjs", ".cjs"} else _TS_PARSER
    )
    if parser is None:
        return
    root = parser.parse(source).root_node
    bindings = set()
    pending = [root]
    while pending:
        node = pending.pop()
        if node.type in {
            "variable_declarator",
            "function_declaration",
            "class_declaration",
        }:
            name = node.child_by_field_name("name")
            if name is not None:
                bindings.add(
                    source[name.start_byte : name.end_byte].decode("utf-8", "replace")
                )
        elif node.type in {"formal_parameters", "import_statement"}:
            names = list(node.named_children)
            while names:
                name = names.pop()
                if name.type == "identifier":
                    bindings.add(
                        source[name.start_byte : name.end_byte].decode(
                            "utf-8", "replace"
                        )
                    )
                names.extend(name.named_children)
        pending.extend(node.named_children)

    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.named_children)
        field = "constructor" if node.type == "new_expression" else "function"
        callee = node.child_by_field_name(field)
        arguments = node.child_by_field_name("arguments")
        if (
            node.type not in {"new_expression", "call_expression"}
            or callee is None
            or arguments is None
        ):
            continue
        name = source[callee.start_byte : callee.end_byte].decode("utf-8", "replace")
        first = name.split(".", 1)[0]
        if first in bindings:
            continue
        if node.type == "new_expression":
            loads = name in {
                "Worker",
                "SharedWorker",
                "globalThis.Worker",
                "globalThis.SharedWorker",
            }
        else:
            loads = name in {
                "importScripts",
                "self.importScripts",
                "globalThis.importScripts",
                "navigator.serviceWorker.register",
            }
        if not loads:
            continue
        values = list(arguments.named_children)
        if name.rsplit(".", 1)[-1] != "importScripts":
            values = values[:1]  # Worker options and service-worker scope are data
        yield from _js_path_strings(values, source)


def _js_path_strings(stack, source: bytes):
    while stack:
        node = stack.pop()
        if node.type in {
            "arrow_function",
            "function_expression",
            "function_declaration",
        }:
            continue
        if node.type in _JS_STRING_NODE_TYPES:
            if node.type == "string" and _is_module_specifier(source, node):
                continue
            if node.type == "template_string" and any(
                child.type == "template_substitution" for child in node.children
            ):
                continue  # an interpolated URL is not this exact source path
            for child in node.children:
                if child.type in _JS_STRING_TEXT_TYPES:
                    from .build_configs import _js_unescape

                    yield _js_unescape(
                        source[child.start_byte : child.end_byte].decode(
                            "utf-8", "replace"
                        )
                    )
            # Template substitutions may hold nested strings.
            stack.extend(
                child
                for child in node.children
                if child.type == "template_substitution"
            )
            continue
        stack.extend(node.named_children)


def _target_names(targets: set[str]) -> frozenset[str]:
    names: set[str] = set()
    for target in targets:
        basename = os.path.basename(target)
        names.add(basename)
        stem, _extension = os.path.splitext(basename)
        if stem and stem != "index":
            names.add(stem)
    return frozenset(names)


def _iter_reference_files(project_root: Path, js_files: set[str], exclude_folders):
    files = discover_source_files(
        project_root, _REFERENCE_SUFFIXES, exclude_folders=exclude_folders
    )
    directories = {str(project_root)}
    count = 0
    for file_path in files:
        if file_path.name in _SKIPPED_FILE_NAMES:
            continue
        count += 1
        if count > _MAX_REFERENCE_FILES:
            break
        directories.add(str(file_path.parent))
        yield file_path
    directories.update(os.path.dirname(path) for path in js_files)
    # Command files (``Makefile``, ``Dockerfile``) sit beside the sources or
    # configs they run, so only the directories already discovered are read.
    for directory in sorted(directories):
        for name in sorted(_COMMAND_FILE_NAMES):
            candidate = Path(directory) / name
            if candidate.is_file():
                yield candidate


def _folder_targets(
    root: str, targets: set[str], folder: str, pattern: str, recursive: bool
):
    """Match only files under the directory the source actually enumerates."""
    directory = Path(folder)
    try:
        directory.relative_to(root)
    except ValueError:
        return set()
    found = set()
    for target in targets:
        try:
            relative = Path(target).relative_to(directory)
        except ValueError:
            continue
        if not recursive and len(relative.parts) != 1:
            continue
        if not fnmatch.fnmatchcase(relative.name, pattern):
            continue
        found.add(target)
    return found


def collect_ts_path_references(
    project_root: str | os.PathLike[str],
    js_files: set[str],
    targets: set[str],
    *,
    exclude_folders=None,
) -> tuple[set[str], dict[str, set[str]]]:
    """Return ``(roots, edges)`` for ``targets`` named by path elsewhere.

    ``js_files`` are the analysed JS/TS files (real paths). ``roots`` are the
    targets that a non-JS/TS file names; ``edges`` maps a target to the
    analysed JS/TS files that name it outside an import specifier.
    """
    roots: set[str] = set()
    edges: dict[str, set[str]] = defaultdict(set)
    if not targets:
        return roots, edges
    try:
        root_path = Path(project_root).resolve(strict=True)
    except OSError:
        return roots, edges
    if not root_path.is_dir():
        return roots, edges
    root = str(root_path)
    index = _FileIndex(root, js_files)
    names = _target_names(targets)

    reference_files = list(_iter_reference_files(root_path, js_files, exclude_folders))
    python_files = [
        path for path in reference_files if path.suffix.lower() in _PYTHON_SUFFIXES
    ]
    if python_files:
        from skylos.deadcode.python_browser_effects import project_script_entry_files
        from skylos.deadcode.python_project_sources import ProjectSourceIndex

        project_index = ProjectSourceIndex(root_path, python_files)
        roots.update(
            str(path)
            for path in project_script_entry_files(project_index)
            if str(path) in targets
        )
    for file_path in reference_files:
        source = read_text_no_symlink(
            file_path,
            max_bytes=_MAX_REFERENCE_FILE_BYTES,
            encoding="utf-8",
            errors="ignore",
        )
        if not source:
            continue
        ref_dir = os.path.dirname(os.path.realpath(file_path))
        if not any(name in source for name in names):
            continue
        for text in _reference_texts(file_path, source):
            for token in _tokens(text, names):
                target = _resolve_token(
                    token, ref_dir, index, targets, allow_bare_name=False
                )
                if target is not None:
                    roots.add(target)

    for js_file in sorted(js_files):
        source = read_text_no_symlink(
            js_file,
            max_bytes=_MAX_REFERENCE_FILE_BYTES,
            encoding="utf-8",
            errors="ignore",
        )
        if not source or not any(name in source for name in names):
            continue
        ref_dir = os.path.dirname(js_file)
        for text in _js_string_values(js_file, source.encode("utf-8")):
            for token in _tokens(text, names):
                target = _resolve_token(
                    token, ref_dir, index, targets, allow_bare_name=True
                )
                if target is not None and target != js_file:
                    edges[target].add(js_file)

    return roots, edges
