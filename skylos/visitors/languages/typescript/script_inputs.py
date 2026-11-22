"""One command model for package scripts, CI workflows and git hooks.

Skylos reads every command a project runs (package.json scripts, GitHub
Actions ``run:`` steps, git hooks) through one shell model and then reads
each binary's arguments with a per-binary specification: which flag names a
configuration file, which flag names a ``tsconfig`` project, which flags load
a module first, and which positionals are entry files. The specifications
are data, on top of the shell model in :mod:`skylos.rules.quality.npm_commands`
that already feeds the dependency rules, so file liveness and dependency checks read a command the same way.

Nothing is executed. Every input is an existing file the command names; an
argument the model does not understand produces no input, so this module can
only add entry files, never remove one.
"""

from __future__ import annotations

import glob
import json
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

_SOURCE_SUFFIXES = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
_MAX_COMMAND_SOURCES = 512
_MAX_BUNDLER_SCRIPT_BYTES = 1_000_000


@dataclass(frozen=True)
class ArgSpec:
    """How one binary's arguments name files.

    ``config``: flags whose value is the tool's configuration file;
    ``project``: flags whose value is a ``tsconfig`` file or its folder;
    ``build``: flags (``tsc --build``) whose positionals are projects, with
    ``tsconfig.json`` in the working directory when none is given;
    ``require``: flags whose value is a module loaded before the program;
    ``entries``: every positional that names a source file is an entry.
    """

    config: tuple = ()
    project: tuple = ()
    build: tuple = ()
    require: tuple = ()
    entries: bool = False


_TYPECHECK = ArgSpec(project=("-p", "--project"), build=("-b", "--build"))
_CONFIG = ArgSpec(config=("-c", "--config"))
_RUNTIME = ArgSpec(
    require=("-r", "--require", "--import", "--loader", "--experimental-loader")
)

# Per-binary argument specifications: which flags and positionals name files.
ARG_SPECS = {
    "tsc": _TYPECHECK,
    "tsgo": _TYPECHECK,
    "vue-tsc": _TYPECHECK,
    "ngc": ArgSpec(project=("-p", "--project")),
    "svelte-check": ArgSpec(project=("--tsconfig",)),
    "vite": _CONFIG,
    "vitest": _CONFIG,
    "playwright": _CONFIG,
    "jest": _CONFIG,
    "webpack": _CONFIG,
    "webpack-cli": _CONFIG,
    "webpack-dev-server": _CONFIG,
    "rollup": _CONFIG,
    "rolldown": _CONFIG,
    "tsup": ArgSpec(config=("-c", "--config"), entries=True),
    "tsdown": ArgSpec(config=("-c", "--config"), entries=True),
    "esbuild": ArgSpec(entries=True),
    "cypress": ArgSpec(config=("-C", "--config-file")),
    "mocha": ArgSpec(config=("--config",), require=("-r", "--require")),
    "node": _RUNTIME,
    "nodejs": _RUNTIME,
    "tsx": _RUNTIME,
    "ts-node": _RUNTIME,
    "ts-node-esm": _RUNTIME,
    "vite-node": _RUNTIME,
    "babel-node": _RUNTIME,
    "bun": _RUNTIME,
}

# Type-check binaries: ``-p X`` is a project the package compiles.
TYPECHECK_TOOLS = frozenset({"tsc", "tsgo", "vue-tsc", "ngc", "svelte-check"})

# Wrappers that run the rest of their words as a command (``c8 node x.js``).
_WRAPPERS = frozenset({"c8", "nyc"})

# ``node node_modules/typescript/lib/tsc.js -p x`` runs the ``tsc`` binary.
_INSTALLED_BIN_SCRIPT = re.compile(
    r"(?:^|/)node_modules/(?:.+/)?(?P<stem>[\w.-]+?)(?:\.[cm]?js)?$"
)

_BUNDLER_HINT = re.compile(
    rb"webpack|rollup|rolldown|react-scripts|rspack|parcel|\bvite\b|esbuild"
)


@dataclass
class ScriptInputs:
    """Files that commands name, by how they are loaded."""

    entries: dict = field(default_factory=dict)  # path -> reason
    configs: dict = field(default_factory=dict)  # path -> (tool, cwd)
    projects: dict = field(default_factory=dict)  # tsconfig -> (tool, cwd)
    executed: dict = field(default_factory=dict)  # script path -> cwd


def _existing(base: str, value: str) -> str | None:
    if not value or "$" in value or "://" in value or value.startswith("-"):
        return None
    candidate = os.path.normpath(os.path.join(base, value))
    return candidate if os.path.exists(candidate) else None


def _project_config(base: str, value: str) -> str | None:
    found = _existing(base, value)
    if found is None:
        return None
    if os.path.isdir(found):
        found = os.path.join(found, "tsconfig.json")
    return os.path.realpath(found) if os.path.isfile(found) else None


def _source_file(path: str | None) -> str | None:
    if path and os.path.isfile(path) and path.endswith(_SOURCE_SUFFIXES):
        return os.path.realpath(path)
    return None


def _installed_binary(script: str | None) -> str | None:
    """``node .../node_modules/typescript/lib/tsc.js`` runs ``tsc``."""
    if not script:
        return None
    match = _INSTALLED_BIN_SCRIPT.search(script.replace(os.sep, "/"))
    if match is None:
        return None
    stem = match.group("stem")
    return stem if stem in ARG_SPECS and stem not in _RUNTIME_NAMES else None


_RUNTIME_NAMES = frozenset(name for name, spec in ARG_SPECS.items() if spec is _RUNTIME)


def read_arguments(tool: str, args, cwd: str, inputs: ScriptInputs) -> None:
    """Record the files one binary's arguments name."""
    spec = ARG_SPECS.get(tool)
    if spec is None:
        return
    args = list(args)
    build = False
    positionals = []
    index = 0
    while index < len(args):
        token = args[index]
        index += 1
        if token == "--":
            positionals.extend(args[index:])
            break
        if not token.startswith("-") or token == "-":
            positionals.append(token)
            continue
        flag, has_value, value = token.partition("=")
        if flag in spec.build:
            build = True
            continue
        kind = (
            "config"
            if flag in spec.config
            else "project"
            if flag in spec.project
            else "require"
            if flag in spec.require
            else None
        )
        if kind is None:
            continue
        if not has_value:
            if index >= len(args):
                continue
            value = args[index]
            index += 1
        if kind == "project":
            config = _project_config(cwd, value)
            if config:
                inputs.projects.setdefault(config, (tool, cwd))
        elif kind == "config":
            config = _existing(cwd, value)
            if config and os.path.isfile(config):
                inputs.configs.setdefault(os.path.realpath(config), (tool, cwd))
        else:
            source = _source_file(_existing(cwd, value))
            if source:
                inputs.entries.setdefault(source, "command-preload")
    if build:
        projects = [_project_config(cwd, value) for value in positionals]
        projects = [project for project in projects if project]
        if not positionals:
            default = _project_config(cwd, "tsconfig.json")
            projects = [default] if default else []
        for project in projects:
            inputs.projects.setdefault(project, (tool, cwd))
    if spec.entries:
        for value in positionals:
            source = _source_file(_existing(cwd, value))
            if source:
                inputs.entries.setdefault(source, "command-entry")


def read_command_line(
    text: str, cwd: str, inputs: ScriptInputs, *, lenient: bool, script_names=()
) -> None:
    """Parse one shell line into commands and record their inputs."""
    from skylos.rules.quality.npm_commands import _script_commands

    commands, _unknown = _script_commands(text, script_names, lenient=lenient)
    for command in commands:
        _record_command(command, cwd, inputs, depth=0)


def _record_command(command, cwd: str, inputs: ScriptInputs, depth: int) -> None:
    from skylos.rules.quality.npm_commands import _script_commands

    name, script, args = command.name, command.script, tuple(command.args)
    if command.target is not None and command.target[0] == "cwd":
        target = _existing(cwd, command.target[1])
        if target is None or not os.path.isdir(target):
            return
        cwd = target
    elif command.target is not None:
        return  # Another workspace's script or binary; read with that package.
    if name in _WRAPPERS and args and depth < 2:
        found, _unknown = _script_commands(" ".join(args), (), lenient=False)
        for inner in found:
            _record_command(inner, cwd, inputs, depth + 1)
        return
    if script is not None and name in ARG_SPECS:
        binary = _installed_binary(script)
        tail = args[args.index(script) + 1 :] if script in args else ()
        if binary is not None:
            read_arguments(binary, tail, cwd, inputs)
            return
        head = args[: args.index(script)] if script in args else args
        read_arguments(name, head, cwd, inputs)
        source = _source_file(_existing(cwd, script))
        if source:
            inputs.entries.setdefault(source, "package-script")
            inputs.executed.setdefault(source, cwd)
        return
    if name is not None:
        read_arguments(name, args, cwd, inputs)


@lru_cache(maxsize=4096)
def _manifest_scripts(path: str, mtime_ns: int) -> tuple:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, RecursionError):
        return (), ()
    if not isinstance(data, dict):
        return (), ()
    scripts = data.get("scripts")
    commands = (
        tuple(
            (name, value)
            for name, value in scripts.items()
            if isinstance(name, str) and isinstance(value, str)
        )
        if isinstance(scripts, dict)
        else ()
    )
    hooks = data.get("simple-git-hooks")
    hook_commands = (
        tuple(value for value in hooks.values() if isinstance(value, str))
        if isinstance(hooks, dict)
        else ()
    )
    return commands, hook_commands


def _mtime(path: str) -> int | None:
    try:
        return os.stat(path).st_mtime_ns
    except OSError:
        return None


def package_script_inputs(package_root: str, inputs: ScriptInputs) -> None:
    manifest = os.path.join(package_root, "package.json")
    mtime = _mtime(manifest)
    if mtime is None:
        return
    scripts, hooks = _manifest_scripts(manifest, mtime)
    names = tuple(name for name, _ in scripts)
    for _name, command in scripts:
        read_command_line(
            command, package_root, inputs, lenient=False, script_names=names
        )
    for command in hooks:
        read_command_line(
            command, package_root, inputs, lenient=True, script_names=names
        )


@lru_cache(maxsize=1024)
def _command_file(root: str, path: str, mtime_ns: int) -> tuple:
    from skylos.rules.quality.npm_commands import _command_file_lines, _command_lines

    lines = _command_file_lines(Path(root), Path(path))
    if lines is None:
        return ()
    found = []
    for text, cwd in lines:
        if text is None:
            continue
        text = re.sub(r"\$\{\{.*?\}\}", "$GHA", text, flags=re.DOTALL)
        for line in _command_lines(text):
            found.append((line, str(cwd)))
    return tuple(found)


@lru_cache(maxsize=1024)
def _hook_file(path: str, mtime_ns: int) -> tuple:
    from skylos.rules.quality.npm_commands import _command_lines

    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ()
    if len(text) > _MAX_BUNDLER_SCRIPT_BYTES:
        return ()
    return tuple(_command_lines(text))


@lru_cache(maxsize=256)
def _lefthook_commands(path: str, mtime_ns: int) -> tuple:
    import yaml

    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError, RecursionError):
        return ()
    found = []
    for hook in data.values() if isinstance(data, dict) else ():
        if not isinstance(hook, dict):
            continue
        for group in ("commands", "jobs"):
            entries = hook.get(group)
            items = (
                entries.values()
                if isinstance(entries, dict)
                else entries
                if isinstance(entries, list)
                else ()
            )
            for item in items:
                if isinstance(item, dict) and isinstance(item.get("run"), str):
                    found.append(item["run"])
    return tuple(found)


def repository_command_inputs(project_root: str, inputs: ScriptInputs) -> None:
    """GitHub Actions run steps and git hooks of the repository."""
    root = os.path.realpath(project_root)
    command_files = sorted(
        {
            *glob.glob(os.path.join(root, ".github", "workflows", "*.yml")),
            *glob.glob(os.path.join(root, ".github", "workflows", "*.yaml")),
            *glob.glob(os.path.join(root, ".github", "actions", "*", "action.yml")),
            *glob.glob(os.path.join(root, ".github", "actions", "*", "action.yaml")),
        }
    )[:_MAX_COMMAND_SOURCES]
    for path in command_files:
        mtime = _mtime(path)
        if mtime is None or os.path.islink(path):
            continue
        for line, cwd in _command_file(root, path, mtime):
            read_command_line(line, cwd, inputs, lenient=True)
    hook_dir = os.path.join(root, ".husky")
    if os.path.isdir(hook_dir) and not os.path.islink(hook_dir):
        for name in sorted(os.listdir(hook_dir))[:_MAX_COMMAND_SOURCES]:
            path = os.path.join(hook_dir, name)
            if name.startswith((".", "_")) or not os.path.isfile(path):
                continue
            mtime = _mtime(path)
            if mtime is None or os.path.islink(path):
                continue
            for line in _hook_file(path, mtime):
                read_command_line(line, root, inputs, lenient=True)
    for name in ("lefthook.yml", "lefthook.yaml", ".lefthook.yml", ".lefthook.yaml"):
        path = os.path.join(root, name)
        mtime = _mtime(path)
        if mtime is None or os.path.islink(path):
            continue
        for command in _lefthook_commands(path, mtime):
            read_command_line(command, root, inputs, lenient=True)


def collect_script_inputs(package_roots, project_root: str | None) -> ScriptInputs:
    """Inputs of every package script, CI step and git hook."""
    inputs = ScriptInputs()
    roots = {os.path.realpath(str(root)) for root in package_roots}
    if project_root:
        roots.add(os.path.realpath(str(project_root)))
    for package_root in sorted(roots)[:4096]:
        package_script_inputs(package_root, inputs)
    if project_root:
        repository_command_inputs(str(project_root), inputs)
    return inputs


# --- Bundler entries in build scripts -------------------------------------

_ENTRY_KEYS = frozenset({"entry", "input"})


def _string_values(source: bytes, node, depth: int = 0) -> list[str]:
    if node is None or depth > 3:
        return []
    if node.type == "string":
        parts = [
            source[child.start_byte : child.end_byte].decode("utf-8", "replace")
            for child in node.children
            if child.type in {"string_fragment", "escape_sequence"}
        ]
        return ["".join(parts)]
    if node.type == "template_string":
        if any(child.type == "template_substitution" for child in node.children):
            return []
        text = source[node.start_byte : node.end_byte].decode("utf-8", "replace")
        return [text.strip("`")]
    if node.type == "array":
        values = []
        for child in node.named_children:
            values.extend(_string_values(source, child, depth + 1))
        return values
    if node.type == "object":
        values = []
        for child in node.named_children:
            if child.type == "pair":
                values.extend(
                    _string_values(
                        source, child.child_by_field_name("value"), depth + 1
                    )
                )
        return values
    return []


def _key_name(source: bytes, node) -> str | None:
    if node is None:
        return None
    text = source[node.start_byte : node.end_byte].decode("utf-8", "replace")
    if node.type in {"property_identifier", "identifier"}:
        return text
    if node.type == "string":
        return text.strip("'\"")
    return None


@lru_cache(maxsize=1024)
def _bundler_entry_strings(path: str, mtime_ns: int, size: int) -> tuple:
    """String values of ``entry``/``input`` keys and ``x.entry = ...``."""
    if size > _MAX_BUNDLER_SCRIPT_BYTES:
        return ()
    from .analysis import _iter_ts_nodes, _load_entry_config_ast

    source, root = _load_entry_config_ast(path)
    if source is None or root is None or not _BUNDLER_HINT.search(source):
        return ()
    values = []
    for node in _iter_ts_nodes(root):
        if node.type == "pair":
            if _key_name(source, node.child_by_field_name("key")) in _ENTRY_KEYS:
                values.extend(_string_values(source, node.child_by_field_name("value")))
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            if left is not None and left.type == "member_expression":
                prop = left.child_by_field_name("property")
                if _key_name(source, prop) in _ENTRY_KEYS:
                    values.extend(
                        _string_values(source, node.child_by_field_name("right"))
                    )
    return tuple(dict.fromkeys(value for value in values if value))


def bundler_script_entries(script: str, cwd: str, ts_files: set[str]) -> set[str]:
    """Analysed files a build script hands to webpack/rollup as entries.

    ``config.entry = "../packages/app/index-node"`` in a script that a
    package script runs: each literal is resolved against the script's folder
    and the folder the command runs in, the way bundlers resolve an entry
    against their context.
    """
    from .resolve import _resolve_path_target

    try:
        stat = os.stat(script)
    except OSError:
        return set()
    found = set()
    for value in _bundler_entry_strings(script, stat.st_mtime_ns, stat.st_size):
        if "*" in value or "://" in value or "\n" in value:
            continue
        if not value.startswith((".", "/")) and "/" not in value:
            continue  # A bare name is a package, not a project file.
        for base in (os.path.dirname(script), cwd):
            resolved = _resolve_path_target(base, value)
            if resolved and os.path.realpath(resolved) in ts_files:
                found.add(os.path.realpath(resolved))
                break
    return found


# --- tsconfig projects that a type-check command compiles -------------------

_TS_SUFFIXES = (".ts", ".tsx", ".mts", ".cts")
_JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs")
_MAX_EXTENDS_DEPTH = 8


@dataclass
class TsconfigProject:
    """The parts of a ``tsconfig`` that decide which files it compiles.

    ``include``/``exclude``/``files`` are absolute, each resolved against
    the config that declares it (TypeScript's rule for ``extends``).
    ``local_include`` keeps only the ``include`` patterns that stay inside
    their declaring config's folder: patterns that climb out (``../../src``)
    type-check another package's sources as a side effect.
    ``emits_declarations`` is True only when the merged options are known to
    emit ``.d.ts`` files (``declaration``, ``composite`` or
    ``emitDeclarationOnly``, and no ``noEmit``).
    """

    path: str
    files: list | None = None
    include: list | None = None
    local_include: list | None = None
    exclude: list | None = None
    options: dict = field(default_factory=dict)
    options_complete: bool = True
    references: list = field(default_factory=list)

    @property
    def emits_declarations(self) -> bool:
        options = self.options
        if not self.options_complete or options.get("noEmit") is True:
            return False
        return any(
            options.get(key) is True
            for key in ("declaration", "composite", "emitDeclarationOnly")
        )


def _local_pattern(pattern: str) -> bool:
    return not any(part == ".." for part in pattern.replace("\\", "/").split("/"))


def read_tsconfig_project(path: str, _depth: int = 0) -> TsconfigProject | None:
    from .resolve import _resolve_extends_path
    from .workspace import _load_jsonc

    if _depth > _MAX_EXTENDS_DEPTH:
        return None
    data = _load_jsonc(Path(path))
    if not data:
        return None
    directory = os.path.dirname(path)
    project = TsconfigProject(path)
    parents = data.get("extends")
    parents = [parents] if isinstance(parents, str) else parents
    if parents is not None and not isinstance(parents, list):
        return None
    for parent in parents or ():
        if not isinstance(parent, str):
            return None
        parent_path = _resolve_extends_path(directory, parent)
        if parent_path is None:
            project.options_complete = False  # An uninstalled shared base.
            continue
        inherited = read_tsconfig_project(parent_path, _depth + 1)
        if inherited is None:
            return None
        project.options.update(inherited.options)
        project.options_complete &= inherited.options_complete
        for key in ("files", "include", "local_include", "exclude"):
            if getattr(inherited, key) is not None:
                setattr(project, key, getattr(inherited, key))
    options = data.get("compilerOptions", {})
    if not isinstance(options, dict):
        return None
    project.options.update(options)
    for key in ("files", "include", "exclude"):
        if key not in data:
            continue
        values = data[key]
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            return None
        absolute = [os.path.normpath(os.path.join(directory, v)) for v in values]
        setattr(project, key, absolute)
        if key == "include":
            project.local_include = [
                os.path.normpath(os.path.join(directory, v))
                for v in values
                if _local_pattern(v)
            ]
    references = data.get("references")
    if isinstance(references, list):
        for reference in references:
            target = reference.get("path") if isinstance(reference, dict) else None
            if isinstance(target, str):
                found = _project_config(directory, target)
                if found:
                    project.references.append(found)
    if project.include is None and project.files is None:
        # TypeScript's default: every source under the config's folder.
        project.include = [os.path.join(directory, "**", "*")]
        project.local_include = list(project.include)
    return project


@lru_cache(maxsize=4096)
def _glob_regex(pattern: str):
    text = pattern.replace(os.sep, "/")
    out = []
    index = 0
    while index < len(text):
        if text.startswith("**/", index):
            out.append("(?:[^/]+/)*")
            index += 3
        elif text[index] == "*":
            out.append("[^/]*")
            index += 1
        elif text[index] == "?":
            out.append("[^/]")
            index += 1
        else:
            out.append(re.escape(text[index]))
            index += 1
    return re.compile("".join(out))


def _include_matches(path: str, pattern: str) -> bool:
    normalized = path.replace(os.sep, "/")
    target = pattern.replace(os.sep, "/")
    has_wildcard = any(char in target for char in "*?")
    if not has_wildcard:
        if normalized == target:
            return True
        if not os.path.splitext(target)[1]:
            # A folder name selects everything below it.
            return normalized.startswith(target.rstrip("/") + "/")
        return False
    return _glob_regex(target).fullmatch(normalized) is not None


def _excluded(path: str, patterns) -> bool:
    normalized = path.replace(os.sep, "/")
    for pattern in patterns or ():
        target = pattern.replace(os.sep, "/")
        if any(char in target for char in "*?"):
            if _glob_regex(target).fullmatch(normalized):
                return True
        elif normalized == target or normalized.startswith(target.rstrip("/") + "/"):
            return True
    return False


def _literal_prefix(pattern: str) -> str:
    """The folder part of a pattern before its first wildcard."""
    head = re.split(r"[*?]", pattern.replace(os.sep, "/"), maxsplit=1)[0]
    if any(char in pattern for char in "*?"):
        return head.rsplit("/", 1)[0] + "/"
    return head


def project_source_files(
    project: TsconfigProject,
    ts_files: set[str],
    *,
    local_only: bool,
    include: bool = True,
) -> tuple[set[str], set[str]]:
    """``(files, included)``: analysed files the project names and selects."""
    suffixes = _TS_SUFFIXES
    if project.options.get("allowJs") is True or project.options.get("checkJs") is True:
        suffixes = _TS_SUFFIXES + _JS_SUFFIXES
    listed = set()
    for value in project.files or ():
        for candidate in (value, *(value + suffix for suffix in _TS_SUFFIXES)):
            real = os.path.realpath(candidate)
            if real in ts_files:
                listed.add(real)
                break
    patterns = (project.local_include if local_only else project.include) or []
    included = set()
    if include and patterns:
        prefixes = tuple(_literal_prefix(pattern) for pattern in patterns)
        for path in ts_files:
            normalized = path.replace(os.sep, "/")
            if (
                not normalized.startswith(prefixes)
                or not path.endswith(suffixes)
                or "/node_modules/" in normalized
            ):
                continue
            if any(
                _include_matches(path, pattern) for pattern in patterns
            ) and not _excluded(path, project.exclude):
                included.add(path)
    return listed, included
