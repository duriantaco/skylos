"""JS/TS files that another repository file names by path.

The import graph sees ``import``/``require`` only. Build tools, test runners,
templates, CI jobs and other languages load JS/TS files by path instead:
``tsconfig.json`` ``files``, ``mkdocs.yml`` ``extra_javascript``,
``<script src="{{ 'js/app.js'|url }}">``, ``node scripts/build.js`` in a
workflow, ``subprocess.run(["node", here / "build.js"])`` in Python or
``new Worker("search/worker.js")`` in another script.

A reference counts only in a loading position: a runtime's script operand,
an evidenced subprocess call, a script src, a browser worker/importScripts
argument, or a supported configuration's file-loading field. Further loading
positions:

* a run instruction in Markdown: a line of a fenced shell code block that is
  a runtime command (``bun run src/evals/run.ts``);
* a ``tsconfig`` ``include`` entry that names one file (no wildcard);
* ``path.join`` / ``path.resolve`` from ``node:path`` with literal segments:
  anchored at ``__dirname`` it names exactly that file, with another base its
  literal tail must contain a directory;
* a runtime command built in JS/TS (a string or template literal such as
  ``node ${join(dir, 'hook.js')}``): the literal tail of its script operand,
  which may be a bare file name because it is being run;
* a path string with a directory in a tool configuration file
  (``forge.config.ts`` ``extraResource``, ``webpack.config.js`` ``entry``),
  resolved against the configuration's folder or the project root only;
  strings under an ``ignore``/``exclude`` key name what the tool skips.

Its path must resolve to exactly one scanned file:

* relative to the referencing file's directory or to the project root, with
  or without the file extension, or as a directory ``index`` file;
* else as the trailing path segments (``search/worker.js``) of exactly one
  scanned file, because deployed URLs keep the source tree's tail but drop
  its prefix. A bare file name (``worker.js``) is accepted this way only from
  another JS/TS file, whose own liveness then decides the target's.

References in comments, docstrings, Markdown prose, inline code spans and
Markdown links are ignored: a mention is not a load. A well-formed Internet
Explorer conditional comment (``<!--[if lt IE 9]>...<![endif]-->``) is markup
that matching browsers execute, so a script tag inside it is a load. A reference from an analysed JS/TS file is an edge (the target
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
_MARKDOWN_SUFFIXES = (".md", ".mdx", ".markdown")
_REFERENCE_SUFFIXES = (
    *_STRUCTURED_SUFFIXES,
    *_HASH_COMMENT_SUFFIXES,
    *_TEMPLATE_SUFFIXES,
    *_PYTHON_SUFFIXES,
    *_MARKDOWN_SUFFIXES,
)
_MARKDOWN_SHELL_BLOCKS = frozenset(
    {
        "",
        "sh",
        "bash",
        "shell",
        "zsh",
        "console",
        "terminal",
        "shell-session",
        "shellsession",
        "cmd",
        "powershell",
        "ps1",
        "bat",
        "text",
        "txt",
    }
)
_MARKDOWN_FENCE_RE = re.compile(r"^ {0,3}(?P<fence>`{3,}|~{3,})(?P<info>[^`]*)$")
_MARKDOWN_PROMPTS = ("$ ", "> ", "% ")
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
_CONDITIONAL_COMMENT_RE = re.compile(
    r"<!--\[if\b[^\]>]*\]>(?P<body>[\s\S]*?)<!\[endif\]-->"
)
_SCRIPT_RUNNERS = frozenset({"node", "nodejs", "tsx", "ts-node", "bun", "deno", "k6"})
_PACKAGE_LAUNCHERS = frozenset({"yarn", "pnpm", "bunx", "pnpx"})
_LAUNCHER_SUBCOMMANDS = frozenset({"exec", "dlx", "run"})
_PATH_MODULES = frozenset(
    {"path", "node:path", "path/posix", "node:path/posix", "pathe", "upath"}
)
_PATH_JOIN_FUNCTIONS = frozenset({"join", "resolve"})
_MODULE_DIRECTORY_EXPRESSIONS = frozenset(
    {"__dirname", "import.meta.dirname", "import.meta.dir"}
)
_COMMAND_PLACEHOLDER = "SKYLOS_DYNAMIC_PATH"
_NON_LOADING_KEY_RE = re.compile(r"ignore|exclude", re.IGNORECASE)
_COMMAND_STRING_RE = re.compile(r"^\s*(?:node|nodejs|tsx|ts-node|bun|deno)\s+\S")
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
    allow_suffix: bool = True,
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

    if not has_extension or not allow_suffix:
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
    if runner in _PACKAGE_LAUNCHERS:
        position = 1
        if position < len(tokens) and tokens[position] in _LAUNCHER_SUBCOMMANDS:
            position += 1
        if (
            position >= len(tokens)
            or not isinstance(tokens[position], str)
            or tokens[position] not in _SCRIPT_RUNNERS
        ):
            return
        tokens = tokens[position:]
        runner = tokens[0]
    if runner == "npx":
        # npx is a package launcher, not itself a JavaScript runtime. Only a
        # known runtime command (and, if supplied, its matching package) proves
        # which following operand is a script. Arbitrary npx tools take data.
        position, package = 1, None
        while position < len(tokens):
            option = tokens[position]
            if not isinstance(option, str):
                return
            if option in {"--yes", "-y", "--no", "--no-install", "--quiet", "-q"}:
                position += 1
            elif option.startswith("--package="):
                if package is not None:
                    return
                package = option.partition("=")[2]
                position += 1
            elif option in {"--package", "-p"}:
                if package is not None or position + 1 >= len(tokens):
                    return
                package = tokens[position + 1]
                position += 2
            elif option == "--":
                position += 1
                break
            elif option.startswith("-"):
                return
            else:
                break
        if position >= len(tokens) or tokens[position] not in _SCRIPT_RUNNERS:
            return
        runner = tokens[position]
        if package is not None and (
            not isinstance(package, str)
            or re.fullmatch(
                re.escape(runner) + r"(?:@[A-Za-z0-9_.+^~<>=|*-]+)?", package
            )
            is None
        ):
            return
        tokens = tokens[position:]
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
        if token in {
            "--conditions",
            "--inspect-port",
            "--title",
            "--project",
            "-P",
            "--tsconfig",
            "--compiler",
            "--compiler-options",
            "-O",
        }:
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
        if isinstance(data, dict) and isinstance(data.get("include"), list):
            yield from (
                value
                for value in data["include"]
                if isinstance(value, str)
                and "*" not in value
                and "?" not in value
                and value.lower().endswith(_JS_EXTENSIONS)
            )
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


def _conditional_comment_body(match) -> str:
    return match.group("body")


def _markdown_commands(source: str):
    """Lines of fenced shell code blocks; never prose, code spans or links."""
    source = _TEMPLATE_COMMENT_RES[0].sub("", source)
    fence = None
    shell = False
    for line in source.splitlines():
        opening = _MARKDOWN_FENCE_RE.match(line)
        if fence is None:
            if opening is not None:
                fence = opening.group("fence")
                info = opening.group("info").strip().split(" ", 1)[0].lower()
                shell = info in _MARKDOWN_SHELL_BLOCKS
            continue
        stripped = line.strip()
        if (
            len(stripped) >= len(fence)
            and stripped[0] == fence[0]
            and set(stripped) == {fence[0]}
        ):
            fence = None
            continue
        if not shell:
            continue
        if stripped.startswith(_MARKDOWN_PROMPTS):
            stripped = stripped[2:]
        yield stripped


def _reference_texts(path: Path, source: str):
    suffix = path.suffix.lower()
    if suffix in _PYTHON_SUFFIXES:
        yield from _python_load_paths(source)
        return
    if suffix in _MARKDOWN_SUFFIXES:
        for command in _markdown_commands(source):
            yield from _shell_load_paths(command)
        return
    if suffix in _TEMPLATE_SUFFIXES:
        source = _CONDITIONAL_COMMENT_RE.sub(_conditional_comment_body, source)
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


_LAST_JS_PARSE: list = [None, None, None]


def _parse_js(path: str, source: bytes):
    if _LAST_JS_PARSE[0] == path and _LAST_JS_PARSE[1] == source:
        return _LAST_JS_PARSE[2]
    parser = _TS_PARSER
    if os.path.splitext(path)[1].lower() in {".js", ".jsx", ".tsx", ".mjs", ".cjs"}:
        parser = _TSX_PARSER
    if parser is None:
        return None
    tree = parser.parse(source)
    _LAST_JS_PARSE[:] = [path, source, tree]
    return tree


def _js_string_values(path: str, source: bytes):
    tree = _parse_js(path, source)
    if tree is None:
        return
    root = tree.root_node
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


def _node_text(source: bytes, node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _static_string(source: bytes, node) -> str | None:
    if node.type not in _JS_STRING_NODE_TYPES:
        return None
    if any(child.type == "template_substitution" for child in node.children):
        return None
    from .build_configs import _js_unescape

    return "".join(
        _js_unescape(_node_text(source, child))
        for child in node.children
        if child.type in _JS_STRING_TEXT_TYPES
    )


def _require_specifier(source: bytes, node) -> str | None:
    if node is None or node.type != "call_expression":
        return None
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if (
        function is None
        or arguments is None
        or function.type != "identifier"
        or _node_text(source, function) != "require"
        or len(arguments.named_children) != 1
    ):
        return None
    return _static_string(source, arguments.named_children[0])


def path_module_bindings(source: bytes, root) -> tuple[set[str], set[str]]:
    """Local names bound to ``node:path`` and to its ``join``/``resolve``."""
    namespaces: set[str] = set()
    functions: set[str] = set()
    pending = [root]
    while pending:
        node = pending.pop()
        pending.extend(node.named_children)
        if node.type == "import_statement":
            specifier = node.child_by_field_name("source")
            if (
                specifier is None
                or _static_string(source, specifier) not in _PATH_MODULES
            ):
                continue
            for clause in node.named_children:
                if clause.type != "import_clause":
                    continue
                for child in clause.named_children:
                    if child.type == "identifier":
                        namespaces.add(_node_text(source, child))
                    elif child.type == "namespace_import":
                        namespaces.update(
                            _node_text(source, name)
                            for name in child.named_children
                            if name.type == "identifier"
                        )
                    elif child.type == "named_imports":
                        for specifier_node in child.named_children:
                            name = specifier_node.child_by_field_name("name")
                            alias = specifier_node.child_by_field_name("alias")
                            if (
                                name is not None
                                and _node_text(source, name) in _PATH_JOIN_FUNCTIONS
                            ):
                                functions.add(_node_text(source, alias or name))
        elif node.type == "variable_declarator":
            if (
                _require_specifier(source, node.child_by_field_name("value"))
                not in _PATH_MODULES
            ):
                continue
            name = node.child_by_field_name("name")
            if name is None:
                continue
            if name.type == "identifier":
                namespaces.add(_node_text(source, name))
            elif name.type == "object_pattern":
                for member in name.named_children:
                    if member.type == "shorthand_property_identifier_pattern":
                        if _node_text(source, member) in _PATH_JOIN_FUNCTIONS:
                            functions.add(_node_text(source, member))
                    elif member.type == "pair_pattern":
                        key = member.child_by_field_name("key")
                        value = member.child_by_field_name("value")
                        if (
                            key is not None
                            and value is not None
                            and value.type == "identifier"
                            and _node_text(source, key) in _PATH_JOIN_FUNCTIONS
                        ):
                            functions.add(_node_text(source, value))
    return namespaces, functions


def _is_path_join_call(source: bytes, node, namespaces, functions) -> bool:
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    if function is None or node.child_by_field_name("arguments") is None:
        return False
    if function.type == "identifier":
        return _node_text(source, function) in functions
    if function.type != "member_expression":
        return False
    owner = function.child_by_field_name("object")
    member = function.child_by_field_name("property")
    return (
        owner is not None
        and member is not None
        and owner.type == "identifier"
        and _node_text(source, owner) in namespaces
        and _node_text(source, member) in _PATH_JOIN_FUNCTIONS
    )


def static_path_join(source: bytes, node, namespaces, functions):
    """``(anchored, segments)`` of a ``path.join``/``path.resolve`` call.

    ``anchored`` means every argument is literal after a leading module
    directory (``__dirname``). Otherwise ``segments`` is the literal tail
    after the last non-literal argument.
    """
    if not _is_path_join_call(source, node, namespaces, functions):
        return None
    anchored = False
    segments: list[str] = []
    for index, argument in enumerate(
        node.child_by_field_name("arguments").named_children
    ):
        literal = _static_string(source, argument)
        if literal is not None:
            segments.append(literal)
            continue
        if index == 0 and _node_text(source, argument) in _MODULE_DIRECTORY_EXPRESSIONS:
            anchored = True
            segments = []
            continue
        nested = static_path_join(source, argument, namespaces, functions)
        if nested is not None and index == 0:
            anchored, segments = nested[0], list(nested[1])
            continue
        anchored = False
        segments = []
    if any(os.path.isabs(segment) for segment in segments):
        return None
    return anchored, segments


def _literal_argument_tail(source: bytes, node) -> list[str]:
    if node.type != "call_expression":
        return []
    arguments = node.child_by_field_name("arguments")
    if arguments is None:
        return []
    tail: list[str] = []
    for argument in reversed(arguments.named_children):
        literal = _static_string(source, argument)
        if literal is None:
            break
        tail.insert(0, literal)
    return tail


def _command_template_text(source: bytes, node, namespaces, functions) -> str | None:
    parts: list[str] = []
    for child in node.children:
        if child.type in _JS_STRING_TEXT_TYPES:
            parts.append(_node_text(source, child))
        elif child.type == "template_substitution":
            segments: list[str] = []
            if child.named_children:
                segments = _literal_argument_tail(source, child.named_children[0])
            tail = ""
            if segments and not any(os.path.isabs(part) for part in segments):
                tail = "/" + "/".join(segments)
            parts.append(_COMMAND_PLACEHOLDER + tail)
        elif child.type == "escape_sequence":
            return None
    text = "".join(parts)
    if _COMMAND_STRING_RE.match(text) is None:
        return None
    return text


def _under_non_loading_key(source: bytes, node) -> bool:
    current = node.parent
    while current is not None:
        if current.type == "pair":
            key = current.child_by_field_name("key")
            if key is not None and _NON_LOADING_KEY_RE.search(_node_text(source, key)):
                return True
        current = current.parent
    return False


def _js_path_references(path: str, source: bytes, *, tool_config: bool):
    """``(kind, text)`` path references outside import specifiers.

    ``exact`` is an absolute path, ``relative`` a literal tail that holds a
    directory, ``command`` the script operand of a runtime command, ``config``
    a path string of a tool configuration file.
    """
    tree = _parse_js(path, source)
    if tree is None:
        return
    root = tree.root_node
    namespaces, functions = path_module_bindings(source, root)
    directory = os.path.dirname(path)
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "comment":
            continue
        joined = None
        if namespaces or functions:
            joined = static_path_join(source, node, namespaces, functions)
        if joined is not None:
            anchored, segments = joined
            if anchored and segments:
                yield (
                    "exact",
                    os.path.normpath(os.path.join(directory, *segments)),
                )
            elif segments:
                tail = "/".join(segments)
                if "/" in tail.strip("/"):
                    yield "relative", tail
            continue
        if node.type in _JS_STRING_NODE_TYPES:
            if node.type == "string" and _is_module_specifier(source, node):
                continue
            command = _command_template_text(source, node, namespaces, functions)
            if command is not None:
                for operand in _shell_load_paths(command):
                    tail = operand.rsplit(_COMMAND_PLACEHOLDER, 1)[-1].lstrip("/")
                    if tail:
                        yield "command", tail
            elif tool_config and not _under_non_loading_key(source, node):
                literal = _static_string(source, node)
                if literal is not None and "/" in literal:
                    yield "config", literal
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


def _is_tool_configuration(path: str) -> bool:
    from .conventions import convention_reason
    from .tool_configs import is_tool_config_file

    return is_tool_config_file(path) or convention_reason(path) in {
        "tool-config",
        "rc-config",
        "conf-config",
        "storybook-config",
    }


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
        source_bytes = source.encode("utf-8")
        for text in _js_string_values(js_file, source_bytes):
            for token in _tokens(text, names):
                target = _resolve_token(
                    token, ref_dir, index, targets, allow_bare_name=True
                )
                if target is not None and target != js_file:
                    edges[target].add(js_file)
        for kind, text in _js_path_references(
            js_file, source_bytes, tool_config=_is_tool_configuration(js_file)
        ):
            if kind == "exact":
                target = os.path.realpath(text)
                if target in targets and target != js_file and _inside(target, root):
                    edges[target].add(js_file)
                continue
            for token in _tokens(text, names):
                target = _resolve_token(
                    token,
                    ref_dir,
                    index,
                    targets,
                    allow_bare_name=kind == "command",
                    allow_suffix=kind != "config",
                )
                if target is not None and target != js_file:
                    edges[target].add(js_file)

    return roots, edges
