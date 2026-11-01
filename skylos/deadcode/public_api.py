"""Names a Python library declares public through accepted conventions.

A library is open-world: code outside the repository imports its public API,
so a public name with no caller inside the repository is not dead. Python has
no ``pub`` keyword. This pass recognizes a conservative static subset of common
documentation, typing and lazy-export declarations:

* a module-level attribute docstring or ``#:`` doc comment on a public name;
* a Sphinx object directive, ``automodule :members:``, ``autosummary`` entry or
  cross-reference role, in reST or MyST, and mkdocstrings ``:::`` entries;
* a sibling ``.pyi`` stub declaring the name, and stub re-exports;
* a PEP 562 getter that returns a resolved import, or a canonical
  ``lazy_loader.attach`` / ``attach_stub`` declaration.

``__all__`` always wins: a module that declares it is already exact, so implicit
documentation never widens it. Private names, private modules, tests, scripts
and changelog mentions never declare public API.
"""

from __future__ import annotations

import ast
import os
import re
import stat
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skylos.deadcode.python_ast import ParsedPythonFile
from skylos.core.safe_cache_io import read_project_text_no_symlink

DOC_SUFFIXES = {".rst", ".md", ".txt"}
IGNORED_DIRS = {
    ".git",
    ".hg",
    ".nox",
    ".tox",
    ".venv",
    "venv",
    "__pycache__",
    "_build",
    "build",
    "dist",
    "node_modules",
    "site-packages",
}
CHANGELOG_PREFIXES = (
    "changelog",
    "changes",
    "history",
    "news",
    "release",
    "whatsnew",
    "whats_new",
    "whats-new",
    "upgrading",
    "migration",
)
TEST_DIRS = {"test", "tests", "testing"}
TOP_LEVEL_SUPPORT_DIRS = {
    "benchmark",
    "benchmarks",
    "ci",
    "demo",
    "demos",
    "doc",
    "docs",
    "example",
    "examples",
    "script",
    "scripts",
    "tools",
}
MODULE_LEVEL_TYPES = {"function", "class", "variable"}
OBJECT_TYPES = {"function", "class", "variable", "method"}
MAX_DOC_FILE_BYTES = 1_000_000
MAX_DOC_TOTAL_BYTES = 12_000_000
MAX_STUB_FILE_BYTES = 1_000_000
MAX_STUB_TOTAL_BYTES = 12_000_000
MAX_DOC_FILES = 4096
MAX_DISCOVERY_ENTRIES = 50_000
RST_DIRECTIVE = re.compile(
    r"^(?P<indent>[ \t]*)\.\.[ \t]+(?P<name>(?:py:)?[a-z-]+)::[ \t]*(?P<arg>.*?)[ \t]*$"
)
MYST_DIRECTIVE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<fence>`{3,}|~{3,}|:{3,})\{(?P<name>(?:py:)?[a-z-]+)\}[ \t]*(?P<arg>.*?)[ \t]*$"
)
OPTION_LINE = re.compile(r"^[ \t]*:(?P<key>[\w-]+):[ \t]*(?P<value>.*?)[ \t]*$")
ROLE_KINDS = r"(?:func|class|data|const|obj|exc|attr|meth|property)"
RST_ROLE = re.compile(r":(?:py:)?" + ROLE_KINDS + r":`(?P<target>[^`]+)`")
MYST_ROLE = re.compile(r"\{(?:py:)?" + ROLE_KINDS + r"\}`(?P<target>[^`]+)`")
MKDOCSTRINGS = re.compile(
    r"^(?P<indent>[ \t]*):::[ \t]+(?P<target>[A-Za-z_][\w.]*)[ \t]*$"
)
OBJECT_DIRECTIVES = {
    "autoattribute",
    "autoclass",
    "autodata",
    "autodecorator",
    "autoexception",
    "autofunction",
    "automethod",
    "autoproperty",
    "attribute",
    "class",
    "data",
    "decorator",
    "exception",
    "function",
    "method",
    "property",
}
CONTEXT_DIRECTIVES = {"currentmodule", "module"}
HANDLED_DIRECTIVES = OBJECT_DIRECTIVES | {"automodule", "autosummary"}
PRIVATE_MARKERS = (":meta private:", "@private")


@dataclass
class _Module:
    name: str
    path: Path
    tree: ast.Module
    public: bool
    has_all: bool
    package: str
    members: dict[str, list[Any]] = field(default_factory=dict)
    documented: set[str] = field(default_factory=set)
    private_marked: set[str] = field(default_factory=set)
    root: Path | None = None
    symbols: dict[str, list[Any]] = field(default_factory=dict)
    class_paths: set[str] = field(default_factory=set)
    all_names: set[str] | None = None
    lazy_provider_shadowed: bool = False
    lazy_stub_exports: set[str] = field(default_factory=set)


@dataclass
class _ModuleDirective:
    target: str
    members: set[str] | None
    undocumented: bool
    excluded: set[str]
    filters: tuple[str, ...] = ()
    selection_known: bool = True


@dataclass
class _DocReferences:
    objects: set[str] = field(default_factory=set)
    suffixes: set[str] = field(default_factory=set)
    modules: list[_ModuleDirective] = field(default_factory=list)


def find_declared_public_api_targets(
    definitions: dict[str, Any],
    parsed_files: Iterable[ParsedPythonFile],
    project_root: str | Path,
    module_names: dict[Any, str] | None = None,
) -> list[tuple[Any, str]]:
    root = Path(project_root).resolve()
    modules = _modules(definitions, parsed_files, root, module_names)
    if not modules:
        return []
    by_name = _NameIndex()
    for definition in definitions.values():
        if getattr(definition, "type", None) in OBJECT_TYPES and _is_python(definition):
            by_name.add(definition)

    found: dict[int, tuple[Any, str]] = {}
    public_files: dict[str, bool] = {}
    owners_by_path = {_path_key(module.path): module for module in modules.values()}

    def keep(definition: Any, reason: str, *, public_file: bool = True) -> None:
        if not _definition_allowed(definition, owners_by_path):
            return
        if public_file:
            path = str(definition.filename)
            if path not in public_files:
                public_files[path] = _is_public_module(Path(path), root)
            if not public_files[path]:
                return
        found.setdefault(id(definition), (definition, reason))

    for module in modules.values():
        if not module.public or module.has_all:
            continue
        for name in module.documented - module.private_marked:
            for definition in module.members.get(name, ()):
                if definition.type == "variable":
                    keep(definition, "documented_attribute")

    references = _doc_references(root)
    for target in sorted(references.objects):
        for definition in _resolve_object(target, by_name):
            if not _private_marked(definition, modules):
                keep(definition, "api_docs_reference")
    for suffix in sorted(references.suffixes):
        matches = _resolve_suffix(suffix, by_name)
        if len(matches) == 1 and not _private_marked(matches[0], modules):
            keep(matches[0], "api_docs_reference")
    for directive in references.modules:
        for module in _resolve_module(directive.target, modules):
            for definition in _module_directive_members(module, directive):
                keep(definition, "api_docs_module")

    for definition in _stub_declared(modules):
        keep(definition, "stub_declared", public_file=False)
    for definition in _lazy_exports(modules):
        keep(definition, "lazy_export", public_file=False)
    return list(found.values())


def _is_python(definition: Any) -> bool:
    return str(getattr(definition, "filename", "")).endswith(".py")


def _is_public_name(name: str) -> bool:
    return bool(name) and not name.startswith("_")


def _path_key(path: Any) -> str:
    return os.path.normcase(os.path.realpath(str(path)))


def _modules(
    definitions: dict[str, Any],
    parsed_files: Iterable[ParsedPythonFile],
    root: Path,
    module_names: dict[Any, str] | None,
) -> dict[str, _Module]:
    names_by_path = {}
    for path, name in (module_names or {}).items():
        names_by_path[_path_key(path)] = name
    members_by_path: dict[str, list[Any]] = defaultdict(list)
    for definition in definitions.values():
        if definition.type in OBJECT_TYPES and _is_python(definition):
            members_by_path[_path_key(definition.filename)].append(definition)

    modules: dict[str, _Module] = {}
    for parsed in parsed_files:
        if parsed.path.suffix != ".py":
            continue
        key = _path_key(parsed.path)
        name = names_by_path.get(key) or _fallback_module_name(parsed.path, root)
        if not name:
            continue
        package = name
        if parsed.path.name != "__init__.py":
            package = name.rpartition(".")[0]
        module = _Module(
            name=name,
            path=parsed.path,
            tree=parsed.tree,
            public=_is_public_module(parsed.path, root),
            has_all=_defines_all(parsed.tree),
            package=package,
            root=root,
        )
        _, module.all_names = _all_info(parsed.tree)
        for definition in members_by_path.get(key, ()):
            prefix = name + "."
            if definition.name.startswith(prefix):
                short = definition.name[len(prefix) :]
                module.symbols.setdefault(short, []).append(definition)
            if definition.name == f"{name}.{definition.simple_name}":
                module.members.setdefault(definition.simple_name, []).append(definition)
        _collect_class_policy(module, parsed.tree.body)
        _collect_documentation(module)
        modules[name] = module
    shadowed = any(name in modules for name in ("importlib", "lazy_loader", "builtins"))
    for module in modules.values():
        module.lazy_provider_shadowed = shadowed
    return modules


def _fallback_module_name(path: Path, root: Path) -> str:
    try:
        parts = list(path.resolve().relative_to(root).with_suffix("").parts)
    except ValueError:
        return ""
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _is_public_module(path: Path, root: Path) -> bool:
    try:
        parts = path.resolve().relative_to(root).parts
    except ValueError:
        return False
    if not parts:
        return False
    package_parts = parts[1:] if parts[0] == "src" else parts
    if package_parts and package_parts[0].lower() in TOP_LEVEL_SUPPORT_DIRS:
        return False
    stem = Path(parts[-1]).stem
    if stem == "__main__" or stem == "conftest" or stem == "setup":
        return False
    if stem.startswith("test_") or stem.endswith("_test"):
        return False
    for part in parts[:-1]:
        if part.lower() in TEST_DIRS:
            return False
        if part.startswith("_"):
            return False
    if stem.startswith("_") and stem != "__init__":
        return False
    if (path.parent / "__init__.py").exists():
        return True
    return "src" in parts[:-1]


def _defines_all(tree: ast.Module) -> bool:
    return _all_info(tree)[0]


def _module_statements(body: list[ast.stmt], *, conditional: bool = False):
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node, conditional
            continue
        yield node, conditional
        if isinstance(node, ast.If) and isinstance(node.test, ast.Constant):
            branch = node.body if node.test.value else node.orelse
            yield from _module_statements(branch, conditional=conditional)
            continue
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                statements = [item for item in value if isinstance(item, ast.stmt)]
                yield from _module_statements(statements, conditional=True)
                for item in value:
                    if isinstance(item, (ast.ExceptHandler, ast.match_case)):
                        yield from _module_statements(item.body, conditional=True)


def _target_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return {name for element in target.elts for name in _target_names(element)}
    return set()


def _all_info(tree: ast.Module) -> tuple[bool, set[str] | None]:
    found = False
    names: set[str] | None = None
    for node, conditional in _module_statements(tree.body):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == "__all__":
                found, names = True, None
        if isinstance(node, ast.AnnAssign) and node.value is None:
            continue
        modeled_call = (
            node.value
            if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and isinstance(node.value.func.value, ast.Name)
            and node.value.func.value.id == "__all__"
            else None
        )
        pending = [
            child
            for child in ast.iter_child_nodes(node)
            if not isinstance(child, ast.stmt)
        ]
        while pending:
            expression = pending.pop()
            if isinstance(expression, ast.Lambda):
                continue
            if (
                isinstance(expression, (ast.MatchAs, ast.MatchStar, ast.ExceptHandler))
                and expression.name == "__all__"
            ) or (
                isinstance(expression, ast.MatchMapping)
                and expression.rest == "__all__"
            ):
                found, names = True, None
            if (
                isinstance(expression, ast.Name)
                and expression.id == "__all__"
                and not (isinstance(node, ast.AugAssign) and expression is node.target)
                and not (
                    modeled_call is not None and expression is modeled_call.func.value
                )
            ):
                # A borrowed list may be changed through an alias or container.
                # Only the direct, literal updates modeled below retain proof.
                found, names = True, None
            pending.extend(
                child
                for child in ast.iter_child_nodes(expression)
                if not isinstance(child, ast.stmt)
            )
        assigned = set().union(*(_target_names(t) for t in _assignment_targets(node)))
        if "__all__" in assigned:
            value = _literal_names(getattr(node, "value", None))
            if conditional:
                names = None
            elif isinstance(node, ast.AugAssign):
                names = (
                    names | value
                    if isinstance(node.op, ast.Add)
                    and names is not None
                    and value is not None
                    else None
                )
            elif any(
                isinstance(t, (ast.Tuple, ast.List)) for t in _assignment_targets(node)
            ):
                names = None
            else:
                names = value
            found = True
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            if any((alias.asname or alias.name) == "__all__" for alias in node.names):
                found, names = True, None
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            if (
                isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "__all__"
            ):
                found = True
                if not conditional and names is not None and not call.keywords:
                    if (
                        call.func.attr == "append"
                        and len(call.args) == 1
                        and isinstance(call.args[0], ast.Constant)
                        and isinstance(call.args[0].value, str)
                    ):
                        names.add(call.args[0].value)
                        continue
                    if call.func.attr == "extend" and len(call.args) == 1:
                        extra = _literal_names(call.args[0])
                        if extra is not None:
                            names.update(extra)
                            continue
                names = None
    return found, names


def _api_name_allowed(module: _Module, name: str) -> bool:
    parts = name.split(".")
    if not module.public or any(not _is_public_name(part) for part in parts):
        return False
    for size in range(1, len(parts) + 1):
        if ".".join(parts[:size]) in module.private_marked:
            return False
    if any(
        ".".join(parts[:size]) not in module.class_paths
        for size in range(1, len(parts))
    ):
        return False
    if module.has_all:
        if module.all_names is not None:
            return parts[0] in module.all_names
        if module.lazy_provider_shadowed:
            return False
        if parts[0] in module.lazy_stub_exports and _lazy_stub_attached(
            module.tree, require_all=True
        ):
            return True
        return _lazy_allows_export(module.tree, parts[0])
    return True


def _definition_allowed(definition: Any, owners_by_path: dict[str, _Module]) -> bool:
    name = str(getattr(definition, "name", ""))
    owner = owners_by_path.get(_path_key(definition.filename))
    if owner is None or not name.startswith(owner.name + "."):
        return False
    return _api_name_allowed(owner, name[len(owner.name) + 1 :])


def _collect_class_policy(
    module: _Module, body: list[ast.stmt], prefix: str = ""
) -> None:
    for node in body:
        if not isinstance(node, ast.ClassDef):
            continue
        name = prefix + node.name
        module.class_paths.add(name)
        if _has_private_marker(ast.get_docstring(node) or ""):
            module.private_marked.add(name)
        for child in node.body:
            if isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and _has_private_marker(ast.get_docstring(child) or ""):
                module.private_marked.add(name + "." + child.name)
        _collect_class_policy(module, node.body, name + ".")


def _assignment_targets(node: ast.stmt) -> list[ast.expr]:
    if isinstance(node, ast.Assign):
        return list(node.targets)
    if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        return [node.target]
    return []


def _collect_documentation(module: _Module) -> None:
    lines: list[str] | None = None
    body = module.tree.body
    for index, node in enumerate(body):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc = ast.get_docstring(node)
            if doc:
                module.documented.add(node.name)
                if _has_private_marker(doc):
                    module.private_marked.add(node.name)
            continue
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        names = [t.id for t in _assignment_targets(node) if isinstance(t, ast.Name)]
        if not names:
            continue
        doc = _following_docstring(body, index)
        if doc is None:
            if lines is None:
                lines = _source_lines(module.path, module.root or module.path.parent)
            doc = _doc_comment(node, lines)
        if doc is None:
            continue
        if not doc.strip():
            continue
        module.documented.update(names)
        if _has_private_marker(doc):
            module.private_marked.update(names)


def _following_docstring(body: list[ast.stmt], index: int) -> str | None:
    if index + 1 >= len(body):
        return None
    following = body[index + 1]
    if not isinstance(following, ast.Expr):
        return None
    value = following.value
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return None


def _read_input_text(root: Path, path: Path, max_bytes: int) -> str | None:
    try:
        relative = path.absolute().relative_to(root.resolve())
        if any(part in {".", ".."} for part in relative.parts):
            return None
        current = root.resolve()
        for part in relative.parts[:-1]:
            current /= part
            if not stat.S_ISDIR(current.lstat().st_mode):
                return None
        mode = path.lstat()
        if not stat.S_ISREG(mode.st_mode) or mode.st_size > max_bytes:
            return None
    except (OSError, RuntimeError, ValueError):
        return None
    return read_project_text_no_symlink(root, path, max_bytes=max_bytes)


def _source_lines(path: Path, root: Path) -> list[str]:
    text = _read_input_text(root, path, MAX_DOC_FILE_BYTES)
    return text.splitlines() if text is not None else []


def _doc_comment(node: ast.stmt, lines: list[str]) -> str | None:
    above = node.lineno - 2
    if 0 <= above < len(lines) and lines[above].lstrip().startswith("#:"):
        comments = []
        while above >= 0 and lines[above].lstrip().startswith("#:"):
            comments.append(lines[above].lstrip()[2:])
            above -= 1
        return "\n".join(reversed(comments))
    end_line = getattr(node, "end_lineno", None)
    end_col = getattr(node, "end_col_offset", None)
    if end_line is None or end_col is None or end_line - 1 >= len(lines):
        return None
    trailing = lines[end_line - 1].encode("utf-8")[end_col:].decode("utf-8")
    marker = trailing.find("#:")
    if marker >= 0 and not trailing[:marker].strip():
        return trailing[marker + 2 :]
    return None


def _has_private_marker(doc: str) -> bool:
    return any(marker in doc for marker in PRIVATE_MARKERS)


def _private_marked(definition: Any, modules: dict[str, _Module]) -> bool:
    module_name = str(definition.name).rpartition(".")[0]
    module = modules.get(module_name)
    if module is None:
        return False
    return definition.simple_name in module.private_marked


def _doc_files(root: Path) -> list[Path]:
    files: list[Path] = []
    visited = 0
    for directory, subdirs, names in os.walk(root):
        visited += 1 + len(subdirs) + len(names)
        if visited > MAX_DISCOVERY_ENTRIES:
            break
        subdirs[:] = sorted(
            d
            for d in subdirs
            if d not in IGNORED_DIRS
            and not d.startswith(".")
            and not _is_changelog_name(d)
            and d.lower() not in TEST_DIRS
            and not (Path(directory) / d).is_symlink()
        )
        for name in sorted(names):
            path = Path(directory) / name
            if path.suffix.lower() not in DOC_SUFFIXES or _is_changelog_name(name):
                continue
            files.append(path)
            if len(files) >= MAX_DOC_FILES:
                files.sort(key=lambda path: (not _under_docs(path, root), str(path)))
                return files
    files.sort(key=lambda path: (not _under_docs(path, root), str(path)))
    return files


def _under_docs(path: Path, root: Path) -> bool:
    try:
        first = path.relative_to(root).parts[0].lower()
    except (ValueError, IndexError):
        return False
    return first in {"doc", "docs", "documentation"}


def _is_changelog_name(name: str) -> bool:
    return Path(name).stem.lower().startswith(CHANGELOG_PREFIXES)


def _doc_references(root: Path) -> _DocReferences:
    references = _DocReferences()
    total = 0
    for path in _doc_files(root):
        remaining = MAX_DOC_TOTAL_BYTES - total
        if remaining <= 0:
            break
        text = _read_input_text(root, path, min(MAX_DOC_FILE_BYTES, remaining))
        if text is None:
            continue
        total += len(text.encode("utf-8"))
        _parse_doc(text, references, doc_format=path.suffix.lower().lstrip("."))
    return references


def _parse_doc(
    text: str, references: _DocReferences, *, doc_format: str = "rst"
) -> None:
    _parse_doc_lines(text.splitlines(), references, doc_format=doc_format)


def _parse_doc_lines(
    lines: list[str],
    references: _DocReferences,
    *,
    doc_format: str,
    context: str = "",
    _depth: int = 0,
) -> str:
    if _depth > 16:
        return context
    if doc_format.lower().lstrip(".") in {"md", "markdown"}:
        return _parse_markdown(lines, references, context, _depth)
    index = 0
    while index < len(lines):
        line = lines[index]
        directive = _directive(line, doc_format="rst")
        if directive is not None:
            indent, name, argument, _ = directive
            block, index = _directive_block(lines, index, indent)
            if name in CONTEXT_DIRECTIVES:
                context = _context_value(argument)
            elif name in HANDLED_DIRECTIVES:
                _record_directive(name, argument, block, context, references)
                context = _parse_doc_lines(
                    _dedent(_directive_body(block)),
                    references,
                    doc_format="rst",
                    context=context,
                    _depth=_depth + 1,
                )
            elif name in _PARSED_DOC_CONTAINERS:
                _add_roles(argument, context, references, doc_format="rst")
                context = _parse_doc_lines(
                    _dedent(_directive_body(block)),
                    references,
                    doc_format="rst",
                    context=context,
                    _depth=_depth + 1,
                )
            continue
        if re.match(r"^[ \t]*\.\.(?:[ \t]|$)", line):
            index = _indented_block_end(lines, index + 1, _indent(line))
            continue
        if line.rstrip().endswith("::") and not _escaped(
            line.rstrip(), len(line.rstrip()) - 2
        ):
            _add_roles(line[:-2], context, references, doc_format="rst")
            index = _literal_block_end(lines, index + 1, _indent(line))
            continue
        _add_roles(line, context, references, doc_format="rst")
        index += 1
    return context


def _markdown_role_rule(state, silent: bool) -> bool:
    # The standard parser calls this at an inline backtick, after plain text
    # has accumulated. Exact raw offsets keep escaped prefixes distinct from
    # identically spelled roles in link titles or code examples elsewhere.
    if state.src[state.pos] != "`" or state.linkLevel:
        return False
    start = state.src.rfind("{", max(0, state.pos - 32), state.pos)
    if start < 0 or _escaped(state.src, start):
        return False
    match = MYST_ROLE.match(state.src, start)
    prefix = state.src[start : state.pos]
    if (
        match is None
        or match.end() > state.posMax
        or match.start("target") != state.pos + 1
        or not state.pending.endswith(prefix)
    ):
        return False
    if not silent:
        state.pending = state.pending[: -len(prefix)]
        token = state.push("skylos_api_role", "", 0)
        token.content = match.group("target")
    state.pos = match.end()
    return True


def _markdown_directive_rule(state, start: int, end: int, silent: bool) -> bool:
    if state.sCount[start] - state.blkIndent >= 4:
        return False
    position = state.bMarks[start] + state.tShift[start]
    directive = _directive(state.src[position : state.eMarks[start]], doc_format="md")
    if directive is None:
        return False
    _, name, argument, fence = directive
    if silent:
        return True
    closing = start + 1
    closed = False
    while closing < end:
        position = state.bMarks[closing] + state.tShift[closing]
        text = state.src[position : state.eMarks[closing]]
        if text and state.sCount[closing] < state.blkIndent:
            break
        if (
            state.sCount[closing] - state.blkIndent < 4
            and len(text.rstrip()) >= len(fence)
            and set(text.rstrip()) == {fence[0]}
        ):
            closed = True
            break
        closing += 1
    state.line = closing + int(closed)
    token = state.push("skylos_doc_directive", "", 0)
    token.content = state.getLines(start + 1, closing, state.sCount[start], True)
    token.meta = {"name": name, "argument": argument, "closed": closed}
    token.map = [start, state.line]
    return True


def _markdown_mkdocstrings_rule(state, start: int, end: int, silent: bool) -> bool:
    if state.sCount[start] - state.blkIndent >= 4:
        return False
    position = state.bMarks[start] + state.tShift[start]
    match = MKDOCSTRINGS.match(state.src[position : state.eMarks[start]])
    if match is None:
        return False
    if silent:
        return True
    following = start + 1
    while following < end:
        position = state.bMarks[following] + state.tShift[following]
        if (
            state.src[position : state.eMarks[following]].strip()
            and state.sCount[following] <= state.sCount[start]
        ):
            break
        following += 1
    state.line = following
    token = state.push("skylos_mkdocstrings", "", 0)
    token.content = state.getLines(start + 1, following, state.sCount[start], True)
    token.meta = {
        "target": match.group("target"),
        "supported": state.parentType == "root",
    }
    token.map = [start, following]
    return True


def _markdown_roles(tokens, context: str, references: _DocReferences) -> None:
    for token in tokens:
        if token.type != "skylos_api_role":
            continue
        target = token.content.strip()
        if target.endswith(">") and "<" in target:
            target = target[target.rfind("<") + 1 : -1]
        if not target.startswith("!"):
            _add_object(target, context, references)


def _parse_markdown(lines, references, context: str, depth: int) -> str:
    from markdown_it import MarkdownIt

    parser = MarkdownIt("commonmark", {"html": True, "maxNesting": 32})
    parser.inline.ruler.before("backticks", "skylos_api_role", _markdown_role_rule)
    alternatives = {"alt": ["paragraph", "reference", "blockquote", "list"]}
    parser.block.ruler.before(
        "fence", "skylos_doc_directive", _markdown_directive_rule, alternatives
    )
    parser.block.ruler.before(
        "fence", "skylos_mkdocstrings", _markdown_mkdocstrings_rule, alternatives
    )
    try:
        tokens = parser.parse("\n".join(lines))
    except (ValueError, RecursionError):
        return context
    for token in tokens:
        if token.type == "inline":
            _markdown_roles(token.children or [], context, references)
        elif token.type == "skylos_mkdocstrings":
            if token.meta["supported"]:
                _add_mkdocstrings(
                    token.meta["target"], token.content.splitlines(), references
                )
        elif token.type == "skylos_doc_directive" and token.meta["closed"]:
            name, argument = token.meta["name"], token.meta["argument"]
            block = token.content.splitlines()
            if name == "eval-rst":
                context = _parse_doc_lines(
                    block,
                    references,
                    doc_format="rst",
                    context=context,
                    _depth=depth + 1,
                )
            elif name in CONTEXT_DIRECTIVES:
                context = _context_value(argument)
            elif name in HANDLED_DIRECTIVES or name in _PARSED_DOC_CONTAINERS:
                if name in HANDLED_DIRECTIVES:
                    _record_directive(name, argument, block, context, references)
                else:
                    for title in parser.parseInline(argument):
                        _markdown_roles(title.children or [], context, references)
                context = _parse_doc_lines(
                    _dedent(_directive_body(block)),
                    references,
                    doc_format="md",
                    context=context,
                    _depth=depth + 1,
                )
    return context


_PARSED_DOC_CONTAINERS = {
    "admonition",
    "attention",
    "caution",
    "danger",
    "error",
    "hint",
    "important",
    "note",
    "tip",
    "warning",
    "seealso",
    "versionadded",
    "versionchanged",
    "deprecated",
    "rubric",
}


def _indent(line: str) -> int:
    return len(line.expandtabs(8)) - len(line.expandtabs(8).lstrip())


def _dedent(lines: list[str]) -> list[str]:
    nonblank = [line for line in lines if line.strip()]
    if not nonblank:
        return []
    indentation = min(_indent(line) for line in nonblank)
    return [line.expandtabs(8)[indentation:] for line in lines]


def _indented_block_end(lines: list[str], index: int, indent: int) -> int:
    while index < len(lines):
        if lines[index].strip() and _indent(lines[index]) <= indent:
            break
        index += 1
    return index


def _literal_block_end(lines: list[str], index: int, indent: int) -> int:
    first = index
    while first < len(lines) and not lines[first].strip():
        first += 1
    if first == len(lines):
        return first
    if _indent(lines[first]) > indent:
        return _indented_block_end(lines, first, indent)
    stripped = lines[first].lstrip()
    if stripped and not stripped[0].isalnum() and stripped[0] not in {"_", "\\"}:
        quote = stripped[0]
        position = first
        while position < len(lines) and lines[position].lstrip().startswith(quote):
            position += 1
        return position
    return index


def _directive(
    line: str, *, doc_format: str = "rst"
) -> tuple[int, str, str, str] | None:
    markdown = doc_format == "md"
    match = MYST_DIRECTIVE.match(line) if markdown else RST_DIRECTIVE.match(line)
    if match is None:
        return None
    fence = match.group("fence") if markdown else ""
    name = match.group("name").removeprefix("py:")
    return len(match.group("indent")), name, match.group("arg"), fence


def _directive_block(
    lines: list[str], index: int, indent: int
) -> tuple[list[str], int]:
    position = _indented_block_end(lines, index + 1, indent)
    return lines[index + 1 : position], position


def _context_value(argument: str) -> str:
    value = argument.strip()
    return "" if value == "None" else value


def _object_name(argument: str) -> str:
    name = argument.strip().split("(", 1)[0].strip()
    return name.split()[0] if name else ""


def _option_prefix(block: list[str]) -> tuple[dict[str, str], int, bool]:
    options: dict[str, str] = {}
    position = 0
    while position < len(block) and not block[position].strip():
        position += 1
    while position < len(block):
        match = OPTION_LINE.match(block[position])
        if match is None:
            break
        key = match.group("key")
        if key in options:
            return {}, position, False
        options[key] = match.group("value")
        position += 1
    return options, position, True


def _directive_body(block: list[str]) -> list[str]:
    _, position, valid = _option_prefix(block)
    return block[position:] if valid else []


def _automodule(argument: str, block: list[str]) -> _ModuleDirective:
    options, _, valid = _option_prefix(block)
    members: set[str] | None = set()
    if "members" in options:
        members = _split_names(options["members"]) or None
    return _ModuleDirective(
        target=argument.strip(),
        members=members,
        undocumented="undoc-members" in options,
        excluded=_split_names(options.get("exclude-members", "")),
        selection_known=valid,
    )


def _record_directive(
    name: str, argument: str, block: list[str], context: str, references: _DocReferences
) -> None:
    if name == "automodule":
        references.modules.append(_automodule(argument, block))
    elif name == "autosummary":
        for entry in _autosummary_entries(block):
            _add_object(entry, context, references)
    else:
        _add_object(_object_name(argument), context, references)


def _split_names(value: str) -> set[str]:
    return {part.strip() for part in value.split(",") if part.strip()}


def _autosummary_entries(block: list[str]) -> list[str]:
    entries = []
    for line in _directive_body(block):
        stripped = line.strip()
        if not stripped:
            continue
        if not re.fullmatch(r"~?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", stripped):
            return []
        entries.append(stripped.lstrip("~"))
    return entries


def _add_object(name: str, context: str, references: _DocReferences) -> None:
    name = name.strip().lstrip("~!").removesuffix("()")
    if not name:
        return
    if name.startswith("."):
        references.suffixes.add(name.lstrip("."))
        return
    if "." in name:
        references.objects.add(name)
    if context:
        references.objects.add(f"{context}.{name}")


def _escaped(text: str, index: int) -> bool:
    position = index - 1
    while position >= 0 and text[position] == "\\":
        position -= 1
    return (index - position - 1) % 2 == 1


def _inline_literal_end(text: str, index: int) -> int:
    end = index
    while end < len(text) and text[end] == "`":
        end += 1
    run = text[index:end]
    position = end
    while position < len(text):
        found = text.find(run, position)
        if found < 0:
            return len(text)
        after = found + len(run)
        if (found == 0 or text[found - 1] != "`") and (
            after == len(text) or text[after] != "`"
        ):
            return after
        position = after
    return len(text)


def _add_roles(
    text: str, context: str, references: _DocReferences, *, doc_format: str = "rst"
) -> None:
    if (doc_format == "md" and "{" not in text) or (
        doc_format != "md" and ":" not in text
    ):
        return
    pattern = MYST_ROLE if doc_format == "md" else RST_ROLE
    suffix = re.compile(r"`(?P<target>[^`]+)`:(?:py:)?" + ROLE_KINDS + r":")
    index = 0
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        match = pattern.match(text, index)
        if match is None and doc_format != "md" and text[index] == "`":
            match = suffix.match(text, index)
        if match:
            target = match.group("target").strip()
            if target.endswith(">") and "<" in target:
                target = target[target.rfind("<") + 1 : -1]
            if not target.startswith("!"):
                _add_object(target, context, references)
            index = match.end()
            continue
        if text[index] == "`":
            index = _inline_literal_end(text, index)
        else:
            index += 1


def _add_mkdocstrings(
    target: str, block: list[str], references: _DocReferences
) -> None:
    members, show_undocumented, filters, known = _mkdocstrings_options(block)
    if not known:
        return
    references.objects.add(target)
    if members is False:
        return
    references.modules.append(
        _ModuleDirective(
            target=target,
            members=members if isinstance(members, set) else None,
            undocumented=show_undocumented,
            excluded=set(),
            filters=filters,
            selection_known=known,
        )
    )


def _safe_doc_yaml(block: list[str]) -> dict[str, Any] | None:
    import yaml
    from yaml.nodes import MappingNode, ScalarNode, SequenceNode
    from yaml.tokens import AliasToken, AnchorToken, TagToken

    text = "\n".join(_dedent(block))
    if len(block) > 256 or len(text.encode("utf-8")) > 32_768:
        return None
    try:
        for count, token in enumerate(yaml.scan(text)):
            if count >= 256 or isinstance(token, (AliasToken, AnchorToken, TagToken)):
                return None
        tree = yaml.compose(text, Loader=yaml.SafeLoader)
        budget = [256]

        def bounded(node: Any, depth: int = 0) -> bool:
            budget[0] -= 1
            if budget[0] < 0 or depth > 12:
                return False
            if isinstance(node, MappingNode):
                seen = set()
                for key, value in node.value:
                    if (
                        not isinstance(key, ScalarNode)
                        or key.tag != "tag:yaml.org,2002:str"
                        or key.value in seen
                    ):
                        return False
                    seen.add(key.value)
                    if not bounded(value, depth + 1):
                        return False
            elif isinstance(node, SequenceNode):
                return all(bounded(child, depth + 1) for child in node.value)
            return True

        if tree is not None and not bounded(tree):
            return None
        value = yaml.safe_load(text)
    except (yaml.YAMLError, ValueError, TypeError, RecursionError):
        return None
    if value is None:
        return {}
    return value if isinstance(value, dict) else None


def _mkdocstrings_options(
    block: list[str],
) -> tuple[set[str] | bool | None, bool, tuple[str, ...], bool]:
    config = _safe_doc_yaml(block)
    invalid = (False, False, (), False)
    if config is None or config.get("handler", "python") != "python":
        return invalid
    if any(key not in {"handler", "options"} for key in config):
        return invalid
    options = config.get("options")
    if options is None:
        options = {}
    if not isinstance(options, dict):
        return invalid
    members = options.get("members")
    if isinstance(members, list):
        if not all(isinstance(name, str) and name.isidentifier() for name in members):
            return invalid
        members = set(members)
    elif members is not None and not isinstance(members, bool):
        return invalid
    undocumented = options.get("show_if_no_docstring", False)
    if not isinstance(undocumented, bool):
        return invalid
    if members is True:
        undocumented = True
    filters = options.get("filters", ())
    if filters in (None, "public"):
        filters = ()
    if not isinstance(filters, (list, tuple)) or len(filters) > 16:
        return invalid
    if not all(
        isinstance(pattern, str) and _supported_doc_filter(pattern)
        for pattern in filters
    ):
        return invalid
    # An explicit member list is authoritative for this level; filters still
    # apply to lower descendants, which this parser does not promote.
    if members is not None:
        filters = ()
    return members, undocumented, tuple(filters), True


def _supported_doc_filter(pattern: str) -> bool:
    pattern = pattern.removeprefix("!")
    if len(pattern) > 128:
        return False
    if pattern in {".*", "^.*$", "^_[^_]"}:
        return True
    literal = pattern.removeprefix("^").removesuffix("$")
    return not any(character in r".[]{}()|*+?\\^$" for character in literal)


def _doc_filter_matches(name: str, pattern: str) -> bool:
    if pattern in {".*", "^.*$"}:
        return True
    if pattern == "^_[^_]":
        return len(name) > 1 and name.startswith("_") and name[1] != "_"
    literal = pattern.removeprefix("^").removesuffix("$")
    if pattern.startswith("^") and pattern.endswith("$"):
        return name == literal
    if pattern.startswith("^"):
        return name.startswith(literal)
    if pattern.endswith("$"):
        return name.endswith(literal)
    return literal in name


def _matches_doc_filters(name: str, filters: tuple[str, ...]) -> bool:
    if len(name) > 256:
        return False
    if not filters:
        return True
    selected = any(pattern.startswith("!") for pattern in filters)
    for pattern in filters:
        negative = pattern.startswith("!")
        if _doc_filter_matches(name, pattern.removeprefix("!")):
            selected = not negative
    return selected


class _NameIndex:
    def __init__(self) -> None:
        self.exact: dict[str, list[Any]] = defaultdict(list)
        self.by_leaf: dict[str, list[Any]] = defaultdict(list)

    def add(self, definition: Any) -> None:
        name = str(getattr(definition, "name", ""))
        self.exact[name].append(definition)
        self.by_leaf[name.rpartition(".")[2]].append(definition)


def _resolve_object(target: str, by_name: _NameIndex) -> list[Any]:
    exact = by_name.exact.get(target)
    if exact:
        return list(exact)
    return []


def _resolve_suffix(suffix: str, by_name: _NameIndex) -> list[Any]:
    ending = "." + suffix
    leaf = suffix.rpartition(".")[2]
    return [
        definition
        for definition in by_name.by_leaf.get(leaf, ())
        if str(definition.name).endswith(ending)
    ]


def _resolve_module(target: str, modules: dict[str, _Module]) -> list[_Module]:
    module = modules.get(target)
    if module is not None:
        return [module]
    if not target.startswith("."):
        return []
    ending = "." + target.lstrip(".")
    matches = [module for name, module in modules.items() if name.endswith(ending)]
    return matches if len(matches) == 1 else []


def _module_directive_members(
    module: _Module, directive: _ModuleDirective
) -> list[Any]:
    if not directive.selection_known:
        return []
    if directive.members is not None and not directive.members:
        return []
    result: list[Any] = []
    for name, definitions in module.members.items():
        if name in directive.excluded or not _api_name_allowed(module, name):
            continue
        if directive.members is not None:
            if name in directive.members:
                result.extend(definitions)
            continue
        if _matches_doc_filters(name, directive.filters) and (
            directive.undocumented or name in module.documented
        ):
            result.extend(definitions)
    return result


def _stub_declared(modules: dict[str, _Module]) -> list[Any]:
    found: list[Any] = []
    total = 0
    for module in modules.values():
        stub_path = module.path.with_suffix(".pyi")
        if not module.public or total >= MAX_STUB_TOTAL_BYTES:
            continue
        source = _read_input_text(
            module.root or module.path.parent,
            stub_path,
            min(MAX_STUB_FILE_BYTES, MAX_STUB_TOTAL_BYTES - total),
        )
        if source is None:
            continue
        total += len(source.encode("utf-8"))
        try:
            stub = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            continue
        declared = _stub_names(stub)
        lazy_stub = (
            module.path.name == "__init__.py"
            and not module.lazy_provider_shadowed
            and _calls_attach_stub(module.tree)
        )
        reexports = (
            _stub_reexports(stub, module.package, lazy_stub)
            if module.path.name == "__init__.py"
            else []
        )
        if lazy_stub:
            module.lazy_stub_exports = {name for name, _ in reexports}
        for name in declared:
            if _api_name_allowed(module, name):
                found.extend(module.symbols.get(name, ()))
        if module.path.name == "__init__.py" and module.public:
            bound = {
                name for node in module.tree.body for name in _stub_bound_names(node)
            }
            for alias, target in reexports:
                if not _api_name_allowed(module, alias):
                    continue
                if lazy_stub and alias in bound:
                    # Existing attributes prevent Python from invoking __getattr__.
                    found.extend(module.symbols.get(alias, ()))
                    continue
                owners = sorted(
                    (
                        item
                        for item in modules.values()
                        if target.startswith(item.name + ".")
                    ),
                    key=lambda item: -len(item.name),
                )
                if owners:
                    owner = owners[0]
                    found.extend(owner.symbols.get(target[len(owner.name) + 1 :], ()))
    return found


def _stub_names(stub: ast.Module) -> set[str]:
    declared: set[str] = set()

    def collect(body: list[ast.stmt], prefix: str = "") -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if _is_public_name(node.name) and not _has_private_marker(
                    ast.get_docstring(node) or ""
                ):
                    declared.add(prefix + node.name)
                    if isinstance(node, ast.ClassDef):
                        collect(node.body, prefix + node.name + ".")
                continue
            for target in _assignment_targets(node):
                for name in _target_names(target):
                    if _is_public_name(name):
                        declared.add(prefix + name)

    collect(stub.body)
    has_all, exported = _all_info(stub)
    if has_all:
        return {
            name
            for name in declared
            if exported is not None and name.split(".")[0] in exported
        }
    return declared


def _literal_names(node: ast.expr | None) -> set[str] | None:
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return None
    names: set[str] = set()
    for element in node.elts:
        if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
            return None
        names.add(element.value)
    return names


def _calls_attach_stub(tree: ast.Module) -> bool:
    return _lazy_stub_attached(tree)


def _stub_reexports(
    stub: ast.Module, package: str, lazy_stub: bool
) -> list[tuple[str, str]]:
    if lazy_stub and any(
        node.level != 1
        or any(
            alias.name == "*" or alias.asname not in {None, alias.name}
            for alias in node.names
        )
        for node in ast.walk(stub)
        if isinstance(node, ast.ImportFrom)
    ):
        return []
    bindings: dict[str, str | None] = {}
    has_all, exported = _all_info(stub)
    for node in stub.body:
        for name in _stub_bound_names(node):
            bindings[name] = None
        if not isinstance(node, ast.ImportFrom):
            continue
        if any(alias.name == "*" for alias in node.names):
            # Without importing the target, a star import may replace any alias.
            bindings.clear()
            continue
        if lazy_stub and not node.level:
            continue
        base = package if node.level else ""
        for _ in range(node.level - 1):
            base = base.rpartition(".")[0]
        module = base
        if node.module and base:
            module = f"{base}.{node.module}"
        elif node.module:
            module = node.module
        for alias in node.names:
            if alias.name == "*":
                continue
            exposed = alias.asname or alias.name
            if not _is_public_name(exposed) or exposed == "__all__":
                continue
            if has_all and (exported is None or exposed not in exported):
                continue
            if (
                lazy_stub
                or alias.asname == alias.name
                or (has_all and exported is not None and exposed in exported)
            ):
                bindings[exposed] = f"{module}.{alias.name}"
    return [(name, target) for name, target in bindings.items() if target is not None]


def _stub_bound_names(node: ast.AST) -> set[str]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return {alias.asname or alias.name.split(".")[0] for alias in node.names}
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return {node.id}
    if isinstance(node, (ast.MatchAs, ast.MatchStar, ast.ExceptHandler)):
        own = {node.name} if node.name else set()
        return own | {
            name
            for child in ast.iter_child_nodes(node)
            for name in _stub_bound_names(child)
        }
    if isinstance(node, ast.MatchMapping) and node.rest:
        return {node.rest} | {
            name
            for child in ast.iter_child_nodes(node)
            for name in _stub_bound_names(child)
        }
    return {
        name
        for child in ast.iter_child_nodes(node)
        for name in _stub_bound_names(child)
    }


def _call_leaf(func: ast.expr) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


_LAZY_UNKNOWN = object()


@dataclass(frozen=True)
class _LazyModuleValue:
    name: str


@dataclass(frozen=True)
class _LazyExport:
    public_name: str
    owner: str
    target: str


def _lazy_exports(modules: dict[str, _Module]) -> list[Any]:
    found = []
    for module in modules.values():
        if not module.public or _lazy_module_replaced(module.tree):
            continue
        # A project file can shadow an otherwise canonical absolute import.
        if any(name in modules for name in ("importlib", "lazy_loader", "builtins")):
            continue
        for export in _lazy_table_strings(module.tree, module.name, module.package):
            if not _api_name_allowed(module, export.public_name):
                continue
            for owner in _entry_owners({export.owner}, module, modules):
                found.extend(owner.members.get(export.target, ()))
    return found


def _entry_owners(entry_modules, lazy_module, module_targets):
    # Entries already name the module actually imported by the getter.
    # An unresolved owner supplies no evidence about any other package module.
    return [
        module_targets[name] for name in sorted(entry_modules) if name in module_targets
    ]


def _lazy_table_strings(tree: ast.Module, module_name="", package=""):
    candidates = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "__getattr__"
    ]
    attach_nodes = _lazy_attach_assignments(tree)
    if not candidates and not attach_nodes:
        return []
    proof = _LazyProof(tree, module_name, package)
    exports = []
    for call, targets in attach_nodes:
        if proof.canonical(None, call.func) != "lazy_loader.attach":
            continue
        for name, owner in _lazy_attach_members(proof, call).items():
            if name not in proof.bound:
                exports.append(_LazyExport(name, owner, name))
        if targets[2] == "__all__":
            for name in _lazy_attach_public_names(proof, call):
                if name in proof.bound:
                    exports.append(_LazyExport(name, module_name, name))
    if len(candidates) != 1 or not _lazy_getter_is_current(tree, candidates[0]):
        return exports
    getter = candidates[0]
    args = [*getter.args.posonlyargs, *getter.args.args]
    if (
        getter.decorator_list
        or len(args) != 1
        or getter.args.vararg
        or getter.args.kwarg
    ):
        return exports
    if len(list(ast.walk(getter))) > 512:
        return exports
    # Candidate strings alone establish nothing. Each must travel through the
    # actual getter's supported control flow into a returned module attribute.
    names = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.isidentifier()
        and _is_public_name(node.value)
    }
    if len(names) > 2048:
        return exports
    for name in sorted(names):
        if name in proof.bound:
            continue
        env = dict(proof.values)
        env[args[0].arg] = name
        value = _lazy_return(getter.body, env, proof, getter, [512])
        if isinstance(value, _LazyExport):
            exports.append(_LazyExport(name, value.owner, value.target))
    return exports


def _lazy_getter_is_current(tree, getter):
    if _lazy_symbol_modified(tree, "__getattr__"):
        return False
    for node in ast.walk(tree):
        if node is getter:
            continue
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == "__getattr__"
        ):
            return False
        if (
            isinstance(node, ast.Name)
            and node.id == "__getattr__"
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            return False
    return True


def _lazy_attach_assignments(tree):
    matches = []
    writes = []
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        for target in node.targets:
            if isinstance(target, (ast.Tuple, ast.List)):
                names = [
                    part.id if isinstance(part, ast.Name) else ""
                    for part in target.elts
                ]
                if (
                    len(names) == 3
                    and names[0] == "__getattr__"
                    and all(names)
                    and "__getattr__" not in names[1:]
                ):
                    if isinstance(node.value, ast.Call):
                        matches.append((node.value, names))
                        writes.append(id(target.elts[0]))
    if len(matches) != 1:
        return []
    if _lazy_symbol_modified(tree, "__getattr__", frozenset(writes)):
        return []
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == "__getattr__"
        ):
            return []
        if (
            isinstance(node, ast.Name)
            and node.id == "__getattr__"
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and id(node) not in writes
        ):
            return []
    return matches


def _lazy_call_arg(call, name, position):
    value = call.args[position] if position < len(call.args) else None
    for keyword in call.keywords:
        if keyword.arg is None:
            return _LAZY_UNKNOWN
        if keyword.arg == name:
            if value is not None:
                return _LAZY_UNKNOWN
            value = keyword.value
    return value


def _lazy_attach_data(proof, call):
    if len(call.args) > 3 or any(
        keyword.arg not in {"package_name", "submodules", "submod_attrs"}
        for keyword in call.keywords
    ):
        return None
    module_arg = _lazy_call_arg(call, "package_name", 0)
    if (
        isinstance(module_arg, ast.Name)
        and module_arg.id == "__name__"
        and "__name__" not in proof.bound
    ):
        package = proof.module_name or "__current__"
    else:
        package = proof.value(module_arg, proof.values, None)
        if (
            not isinstance(package, str)
            or not _looks_like_module(package)
            or package.startswith(".")
        ):
            return None
    submodules = _lazy_call_arg(call, "submodules", 1)
    submodules = (
        [] if submodules is None else proof.value(submodules, proof.values, None)
    )
    if not isinstance(submodules, (list, tuple, set)) or any(
        not isinstance(name, str) for name in submodules
    ):
        return None
    attrs = _lazy_call_arg(call, "submod_attrs", 2)
    value = {} if attrs is None else proof.value(attrs, proof.values, None)
    if not isinstance(value, dict):
        return None
    for owner, names in value.items():
        if (
            not isinstance(owner, str)
            or not _looks_like_module(owner)
            or owner.startswith(".")
        ):
            return None
        if not isinstance(names, (list, tuple, set)) or any(
            not isinstance(name, str) or not name.isidentifier() for name in names
        ):
            return None
    return package, submodules, value


def _lazy_attach_members(proof, call):
    metadata = _lazy_attach_data(proof, call)
    if metadata is None:
        return {}
    package, _, attrs = metadata
    found = {}
    for owner, names in attrs.items():
        for name in names:
            if _is_public_name(name):
                found[name] = f"{package}.{owner}"
    return found


def _lazy_allows_export(tree, name):
    assignments = _lazy_attach_assignments(tree)
    if not assignments:
        return False
    call, names = assignments[0]
    if not _lazy_factory_all_current(tree, call, names):
        return False
    proof = _LazyProof(tree)
    return proof.canonical(
        None, call.func
    ) == "lazy_loader.attach" and name in _lazy_attach_public_names(proof, call)


def _lazy_factory_all_current(tree, call, names):
    if names[2] != "__all__":
        return False
    allowed_all = {
        id(target)
        for node in tree.body
        if isinstance(node, ast.Assign) and node.value is call
        for target in _flatten_targets(node.targets[0])
        if isinstance(target, ast.Name) and target.id == "__all__"
    }
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id == "__all__"
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and id(node) not in allowed_all
        ):
            return False
    if _lazy_symbol_modified(tree, "__all__", frozenset(allowed_all)):
        return False
    return True


def _lazy_attach_public_names(proof, call):
    metadata = _lazy_attach_data(proof, call)
    if metadata is None:
        return set()
    _, submodules, attrs = metadata
    return {name for names in attrs.values() for name in names} | set(submodules)


def _lazy_stub_attached(tree, *, require_all=False):
    assignments = _lazy_attach_assignments(tree)
    if not assignments:
        return False
    call, names = assignments[0]
    if require_all and not _lazy_factory_all_current(tree, call, names):
        return False
    if len(call.args) > 2 or any(
        keyword.arg not in {"package_name", "filename"} for keyword in call.keywords
    ):
        return False
    proof = _LazyProof(tree)
    if proof.canonical(None, call.func) != "lazy_loader.attach_stub":
        return False
    package = _lazy_call_arg(call, "package_name", 0)
    filename = _lazy_call_arg(call, "filename", 1)
    return (
        isinstance(package, ast.Name)
        and package.id == "__name__"
        and "__name__" not in proof.bound
        and isinstance(filename, ast.Name)
        and filename.id == "__file__"
        and "__file__" not in proof.bound
    )


def _flatten_targets(target):
    if isinstance(target, (ast.Tuple, ast.List)):
        return [item for part in target.elts for item in _flatten_targets(part)]
    return [target]


def _lazy_symbol_modified(tree, name, allowed=frozenset()):
    aliases = {name}
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)]
    for _ in range(min(len(assignments) + 1, 64)):
        previous = set(aliases)
        for node in assignments:
            if isinstance(node.value, ast.Name) and node.value.id in aliases:
                aliases.update(
                    target.id for target in node.targets if isinstance(target, ast.Name)
                )
        if aliases == previous:
            break
    else:
        return True
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and id(node) not in allowed
        ):
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                base = node.func.value
                while isinstance(base, (ast.Attribute, ast.Subscript)):
                    base = base.value
                if isinstance(base, ast.Name) and base.id in aliases:
                    return True
            if any(
                isinstance(argument, ast.Name) and argument.id in aliases
                for argument in [
                    *node.args,
                    *(keyword.value for keyword in node.keywords),
                ]
            ):
                return True
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            base = node.value
            while isinstance(base, (ast.Attribute, ast.Subscript)):
                base = base.value
            if isinstance(base, ast.Name) and base.id in aliases:
                return True
    return False


def _lazy_literal(node, values):
    if isinstance(node, ast.Constant) and isinstance(
        node.value, (str, bool, int, type(None))
    ):
        return node.value
    if isinstance(node, ast.Name):
        return values.get(node.id, _LAZY_UNKNOWN)
    if isinstance(node, ast.Dict):
        pairs = [
            (_lazy_literal(key, values), _lazy_literal(value, values))
            for key, value in zip(node.keys, node.values)
        ]
        if any(key is _LAZY_UNKNOWN or value is _LAZY_UNKNOWN for key, value in pairs):
            return _LAZY_UNKNOWN
        try:
            return dict(pairs)
        except TypeError:
            return _LAZY_UNKNOWN
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        items = [_lazy_literal(item, values) for item in node.elts]
        if any(item is _LAZY_UNKNOWN for item in items):
            return _LAZY_UNKNOWN
        if isinstance(node, ast.Set):
            try:
                return set(items)
            except TypeError:
                return _LAZY_UNKNOWN
        return tuple(items) if isinstance(node, ast.Tuple) else items
    if isinstance(node, ast.Subscript):
        owner = _lazy_literal(node.value, values)
        key = _lazy_literal(node.slice, values)
        if isinstance(owner, (dict, tuple, list)) and key is not _LAZY_UNKNOWN:
            try:
                return owner[key]
            except (KeyError, IndexError, TypeError):
                pass
    return _LAZY_UNKNOWN


class _LazyProof:
    def __init__(self, tree, module_name="", package=""):
        from skylos.rules.danger.untrusted_sources import UntrustedSourceIndex
        from skylos.rules.danger.builtin_bindings import builtin_references

        self.tree = tree
        self.module_name = module_name
        self.package = package
        self.index = UntrustedSourceIndex(tree)
        self.star_import = any(
            isinstance(node, ast.ImportFrom)
            and any(alias.name == "*" for alias in node.names)
            for node in ast.walk(tree)
        )
        self.builtins = builtin_references(tree, {"getattr", "__import__"})
        self.values = {"__name__": module_name}
        self.bound = set()
        versions = defaultdict(list)
        initial_targets = set()
        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = _lazy_literal(node.value, self.values)
                for target in _assignment_targets(node):
                    for part in _flatten_targets(target):
                        if isinstance(part, ast.Name):
                            self.values[part.id] = value
                            versions[part.id].append(value)
                            self.bound.add(part.id)
                            initial_targets.add(id(part))
            elif isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                self.bound.add(node.name)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                self.bound.update(
                    alias.asname or alias.name.split(".")[0] for alias in node.names
                )
        invalid = set()
        safe_attach_calls = {id(call) for call, _ in _lazy_attach_assignments(tree)}
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and id(node) not in initial_targets
            ):
                invalid.add(node.id)
            elif isinstance(node, (ast.Subscript, ast.Attribute)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                base = node.value
                while isinstance(base, (ast.Subscript, ast.Attribute)):
                    base = base.value
                if isinstance(base, ast.Name):
                    invalid.add(base.id)
            elif isinstance(node, ast.Call):
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.attr not in {"get", "keys", "items"}
                ):
                    invalid.add(node.func.value.id)
                if id(node) not in safe_attach_calls:
                    for argument in [
                        *node.args,
                        *(keyword.value for keyword in node.keywords),
                    ]:
                        if isinstance(argument, ast.Name) and any(
                            _lazy_mutables(value)
                            for value in versions.get(argument.id, ())
                        ):
                            invalid.add(argument.id)
        identities = {
            identity
            for name in invalid
            for value in versions.get(name, ())
            for identity in _lazy_mutables(value)
        }
        for name, value in self.values.items():
            if name in invalid or _lazy_mutables(value) & identities:
                self.values[name] = _LAZY_UNKNOWN

    def canonical(self, getter, node):
        if self.star_import:
            return None
        dotted = _lazy_dotted(node)
        if isinstance(node, ast.Name) and id(node) in self.builtins:
            return "builtins." + node.id
        return self.index.resolved_import(getter, dotted)

    def value(self, node, env, getter):
        literal = _lazy_literal(node, env)
        if literal is not _LAZY_UNKNOWN:
            return literal
        if isinstance(node, ast.Attribute):
            module = self.value(node.value, env, getter)
            if isinstance(module, _LazyModuleValue):
                return _LazyExport("", module.name, node.attr)
        if (
            isinstance(node, ast.Compare)
            and len(node.ops) == len(node.comparators) == 1
        ):
            left = self.value(node.left, env, getter)
            right = self.value(node.comparators[0], env, getter)
            if not _lazy_concrete(left) or not _lazy_concrete(right):
                return _LAZY_UNKNOWN
            operation = node.ops[0]
            try:
                if isinstance(operation, ast.Eq):
                    return left == right
                if isinstance(operation, ast.NotEq):
                    return left != right
                if isinstance(operation, ast.In):
                    return left in right
                if isinstance(operation, ast.NotIn):
                    return left not in right
            except TypeError:
                pass
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self.value(node.operand, env, getter)
            return not value if _lazy_concrete(value) else _LAZY_UNKNOWN
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.value(node.left, env, getter)
            right = self.value(node.right, env, getter)
            if (
                isinstance(left, str)
                and isinstance(right, str)
                and len(left + right) <= 1024
            ):
                return left + right
        if isinstance(node, ast.JoinedStr):
            parts = []
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    parts.append(part.value)
                elif (
                    isinstance(part, ast.FormattedValue)
                    and part.conversion == -1
                    and part.format_spec is None
                ):
                    value = self.value(part.value, env, getter)
                    if not isinstance(value, str):
                        return _LAZY_UNKNOWN
                    parts.append(value)
                else:
                    return _LAZY_UNKNOWN
            return "".join(parts) if sum(map(len, parts)) <= 1024 else _LAZY_UNKNOWN
        if not isinstance(node, ast.Call):
            return _LAZY_UNKNOWN
        canonical = self.canonical(getter, node.func)
        if canonical == "importlib.import_module":
            if len(node.args) > 2 or any(
                keyword.arg not in {"name", "package"} for keyword in node.keywords
            ):
                return _LAZY_UNKNOWN
            name = _lazy_call_arg(node, "name", 0)
            package = _lazy_call_arg(node, "package", 1)
            imported = self.value(name, env, getter)
            parent = self.value(package, env, getter) if package is not None else ""
            resolved = _lazy_import_name(imported, parent)
            return _LazyModuleValue(resolved) if resolved else _LAZY_UNKNOWN
        if canonical == "builtins.__import__":
            if len(node.args) > 5 or any(
                keyword.arg not in {"name", "globals", "locals", "fromlist", "level"}
                for keyword in node.keywords
            ):
                return _LAZY_UNKNOWN
            name = self.value(_lazy_call_arg(node, "name", 0), env, getter)
            fromlist = _lazy_call_arg(node, "fromlist", 3)
            fromlist = self.value(fromlist, env, getter) if fromlist is not None else []
            if not isinstance(fromlist, (tuple, list)) or any(
                not isinstance(value, str) for value in fromlist
            ):
                return _LAZY_UNKNOWN
            for argument_name, position in (("globals", 1), ("locals", 2)):
                argument = _lazy_call_arg(node, argument_name, position)
                if (
                    argument is not None
                    and self.value(argument, env, getter) is _LAZY_UNKNOWN
                ):
                    return _LAZY_UNKNOWN
            level = _lazy_call_arg(node, "level", 4)
            if level is not None and self.value(level, env, getter) != 0:
                return _LAZY_UNKNOWN
            if (
                isinstance(name, str)
                and _looks_like_module(name)
                and not name.startswith(".")
            ):
                return _LazyModuleValue(name if fromlist else name.split(".")[0])
        if (
            canonical == "builtins.getattr"
            and len(node.args) in {2, 3}
            and not node.keywords
        ):
            if (
                len(node.args) == 3
                and self.value(node.args[2], env, getter) is _LAZY_UNKNOWN
            ):
                return _LAZY_UNKNOWN
            module = self.value(node.args[0], env, getter)
            name = self.value(node.args[1], env, getter)
            if (
                isinstance(module, _LazyModuleValue)
                and isinstance(name, str)
                and name.isidentifier()
            ):
                return _LazyExport("", module.name, name)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and len(node.args) in {1, 2}
            and not node.keywords
        ):
            value = self.value(node.func.value, env, getter)
            key = self.value(node.args[0], env, getter)
            default = (
                self.value(node.args[1], env, getter) if len(node.args) == 2 else None
            )
            if isinstance(value, dict) and key is not _LAZY_UNKNOWN:
                try:
                    return value.get(key, default)
                except TypeError:
                    pass
        return _LAZY_UNKNOWN


def _lazy_mutables(value):
    if isinstance(value, dict):
        return {id(value)} | {
            identity for child in value.values() for identity in _lazy_mutables(child)
        }
    if isinstance(value, (list, tuple, set)):
        own = {id(value)} if isinstance(value, (list, set)) else set()
        return own | {identity for child in value for identity in _lazy_mutables(child)}
    return set()


def _lazy_concrete(value):
    if isinstance(value, (str, bool, int, type(None))):
        return True
    if isinstance(value, dict):
        return all(
            _lazy_concrete(key) and _lazy_concrete(child)
            for key, child in value.items()
        )
    if isinstance(value, (tuple, list, set)):
        return all(_lazy_concrete(child) for child in value)
    return False


def _lazy_module_replaced(tree):
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            continue
        for target in _assignment_targets(node):
            if isinstance(target, ast.Attribute):
                target = target.value
            if (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Attribute)
                and target.value.attr == "modules"
                and isinstance(target.slice, ast.Name)
                and target.slice.id == "__name__"
            ):
                return True
    return False


def _lazy_dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _lazy_dotted(node.value)
        return f"{base}.{node.attr}" if base else ""
    return ""


def _lazy_import_name(name, package):
    if not isinstance(name, str) or not _looks_like_module(name):
        return ""
    if not name.startswith("."):
        return name
    if not isinstance(package, str) or not package:
        return ""
    depth = len(name) - len(name.lstrip("."))
    parts = package.split(".")
    if depth > len(parts):
        return ""
    prefix = ".".join(parts[: len(parts) - depth + 1])
    suffix = name.lstrip(".")
    return f"{prefix}.{suffix}" if suffix else prefix


def _lazy_bind(target, value, env):
    if isinstance(target, ast.Name):
        env[target.id] = value
        return True
    if (
        isinstance(target, (ast.Tuple, ast.List))
        and isinstance(value, (list, tuple))
        and len(target.elts) == len(value)
    ):
        return all(
            _lazy_bind(part, item, env) for part, item in zip(target.elts, value)
        )
    return False


def _lazy_return(statements, env, proof, getter, budget):
    for index, node in enumerate(statements):
        budget[0] -= 1
        if budget[0] < 0:
            return None
        if isinstance(node, ast.Return):
            value = proof.value(node.value, env, getter)
            return value if isinstance(value, _LazyExport) else None
        if isinstance(node, ast.Raise):
            return None
        if isinstance(node, ast.If):
            test = proof.value(node.test, env, getter)
            if not _lazy_concrete(test):
                return None
            branch = node.body if test else node.orelse
            return _lazy_return(
                [*branch, *statements[index + 1 :]], env, proof, getter, budget
            )
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = proof.value(node.value, env, getter)
            if value is _LAZY_UNKNOWN:
                return None
            if not all(
                _lazy_bind(target, value, env) for target in _assignment_targets(node)
            ):
                return None
        elif isinstance(node, (ast.Import, ast.ImportFrom, ast.Pass)):
            continue
        elif (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            continue
        else:
            return None
    return None


def _looks_like_module(text: str) -> bool:
    stripped = text.lstrip(".")
    return bool(stripped) and all(part.isidentifier() for part in stripped.split("."))
