"""Names a Python library declares public through accepted conventions.

A library is open-world: code outside the repository imports its public API,
so a public name with no caller inside the repository is not dead. Python has
no ``pub`` keyword; the conventions honoured here are the ones mainstream tools
define (PEP 8, the typing specification, Sphinx autodoc, mkdocstrings/Griffe
and Pyright's ``--verifytypes``):

* a module-level attribute docstring or ``#:`` doc comment on a public name;
* a Sphinx object directive, ``automodule :members:``, ``autosummary`` entry or
  cross-reference role, in reST or MyST, and mkdocstrings ``:::`` entries;
* a sibling ``.pyi`` stub declaring the name, and stub re-exports;
* a PEP 562 ``__getattr__``, ``lazy_loader`` or lazy ``sys.modules`` table that
  names the export.

``__all__`` always wins: a module that declares it is already exact, so implicit
documentation never widens it. Private names, private modules, tests, scripts
and changelog mentions never declare public API.
"""

from __future__ import annotations

import ast
import os
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skylos.deadcode.python_ast import ParsedPythonFile

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
RST_DIRECTIVE = re.compile(
    r"^(?P<indent>[ \t]*)\.\.[ \t]+(?P<name>(?:py:)?[a-z]+)::[ \t]*(?P<arg>.*?)[ \t]*$"
)
MYST_DIRECTIVE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<fence>`{3,}|:{3,})\{(?P<name>(?:py:)?[a-z-]+)\}[ \t]*(?P<arg>.*?)[ \t]*$"
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
LAZY_IMPORT_CALLS = {"import_module", "__import__"}
LAZY_ATTACH_CALLS = {"attach", "attach_stub"}


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


@dataclass
class _ModuleDirective:
    target: str
    members: set[str] | None
    undocumented: bool
    excluded: set[str]


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

    def keep(definition: Any, reason: str, *, public_file: bool = True) -> None:
        if not _is_public_name(getattr(definition, "simple_name", "")):
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
        if definition.type in MODULE_LEVEL_TYPES and _is_python(definition):
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
        )
        for definition in members_by_path.get(key, ()):
            if definition.name == f"{name}.{definition.simple_name}":
                module.members.setdefault(definition.simple_name, []).append(definition)
        _collect_documentation(module)
        modules[name] = module
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
    if parts[0].lower() in TOP_LEVEL_SUPPORT_DIRS:
        return False
    stem = Path(parts[-1]).stem
    if stem == "__main__" or stem == "conftest" or stem == "setup":
        return False
    if stem.startswith("test_") or stem.endswith("_test"):
        return False
    for part in parts[:-1]:
        if part.lower() in TEST_DIRS:
            return False
        if part.startswith("_") and not part.startswith("__"):
            return False
    if stem.startswith("_") and stem != "__init__":
        return False
    if (path.parent / "__init__.py").exists():
        return True
    return "src" in parts[:-1]


def _defines_all(tree: ast.Module) -> bool:
    for node in tree.body:
        for target in _assignment_targets(node):
            if isinstance(target, ast.Name) and target.id == "__all__":
                return True
    return False


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
                lines = _source_lines(module.path)
            doc = _doc_comment(node, lines)
        if doc is None:
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


def _source_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []


def _doc_comment(node: ast.stmt, lines: list[str]) -> str | None:
    above = node.lineno - 2
    if 0 <= above < len(lines) and lines[above].lstrip().startswith("#:"):
        return lines[above].lstrip()[2:]
    end_line = getattr(node, "end_lineno", None)
    end_col = getattr(node, "end_col_offset", None)
    if end_line is None or end_col is None or end_line - 1 >= len(lines):
        return None
    trailing = lines[end_line - 1][end_col:]
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
    for directory, subdirs, names in os.walk(root):
        subdirs[:] = sorted(
            d
            for d in subdirs
            if d not in IGNORED_DIRS
            and not d.startswith(".")
            and not _is_changelog_name(d)
            and d.lower() not in TEST_DIRS
        )
        for name in sorted(names):
            path = Path(directory) / name
            if path.suffix.lower() not in DOC_SUFFIXES or _is_changelog_name(name):
                continue
            files.append(path)
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
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > MAX_DOC_FILE_BYTES:
            continue
        if total + size > MAX_DOC_TOTAL_BYTES:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        total += size
        _parse_doc(text, references)
    return references


def _parse_doc(text: str, references: _DocReferences) -> None:
    lines = text.splitlines()
    context = ""
    index = 0
    while index < len(lines):
        line = lines[index]
        directive = _directive(line)
        if directive is not None and directive[1] in CONTEXT_DIRECTIVES:
            context = _context_value(directive[2])
            index += 1
            continue
        if directive is not None and directive[1] in HANDLED_DIRECTIVES:
            indent, name, argument, fence = directive
            block, index = _directive_block(lines, index, indent, fence)
            if name == "automodule":
                references.modules.append(_automodule(argument, block))
            elif name == "autosummary":
                for entry in _autosummary_entries(block):
                    _add_object(entry, context, references)
            else:
                _add_object(_object_name(argument), context, references)
            _add_roles("\n".join(block), context, references)
            continue
        mkdocs = MKDOCSTRINGS.match(line)
        if mkdocs is not None:
            block, index = _directive_block(
                lines, index, len(mkdocs.group("indent")), ""
            )
            _add_mkdocstrings(mkdocs.group("target"), block, references)
            continue
        _add_roles(line, context, references)
        index += 1


def _directive(line: str) -> tuple[int, str, str, str] | None:
    match = RST_DIRECTIVE.match(line)
    fence = ""
    if match is None:
        match = MYST_DIRECTIVE.match(line)
        if match is None:
            return None
        fence = match.group("fence")
    name = match.group("name").removeprefix("py:")
    return len(match.group("indent")), name, match.group("arg"), fence


def _directive_block(
    lines: list[str], index: int, indent: int, fence: str
) -> tuple[list[str], int]:
    block: list[str] = []
    position = index + 1
    while position < len(lines):
        line = lines[position]
        if fence:
            if line.strip() == fence:
                return block, position + 1
            block.append(line)
            position += 1
            continue
        stripped = line.strip()
        if stripped and len(line) - len(line.lstrip()) <= indent:
            break
        block.append(line)
        position += 1
    return block, position


def _context_value(argument: str) -> str:
    value = argument.strip()
    if value == "None":
        return ""
    return value


def _object_name(argument: str) -> str:
    name = argument.strip().split("(", 1)[0].strip()
    if not name:
        return ""
    return name.split()[0]


def _options(block: list[str]) -> dict[str, str]:
    options: dict[str, str] = {}
    for line in block:
        match = OPTION_LINE.match(line)
        if match is not None:
            options[match.group("key")] = match.group("value")
    return options


def _automodule(argument: str, block: list[str]) -> _ModuleDirective:
    options = _options(block)
    members: set[str] | None = set()
    if "members" in options:
        members = None
        listed = _split_names(options["members"])
        if listed:
            members = listed
    return _ModuleDirective(
        target=argument.strip(),
        members=members,
        undocumented="undoc-members" in options,
        excluded=_split_names(options.get("exclude-members", "")),
    )


def _split_names(value: str) -> set[str]:
    return {part.strip() for part in value.split(",") if part.strip()}


def _autosummary_entries(block: list[str]) -> list[str]:
    entries: list[str] = []
    for line in block:
        stripped = line.strip()
        if not stripped or OPTION_LINE.match(line) or stripped.startswith(".."):
            continue
        entries.append(stripped.split()[0].lstrip("~"))
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


def _add_roles(text: str, context: str, references: _DocReferences) -> None:
    for pattern in (RST_ROLE, MYST_ROLE):
        for match in pattern.finditer(text):
            target = match.group("target").strip()
            if target.endswith(">") and "<" in target:
                target = target[target.rfind("<") + 1 : -1]
            _add_object(target, context, references)


def _add_mkdocstrings(
    target: str, block: list[str], references: _DocReferences
) -> None:
    members, show_undocumented = _mkdocstrings_options(block)
    references.objects.add(target)
    if members is False:
        return
    listed = None
    if isinstance(members, set):
        listed = members
    references.modules.append(
        _ModuleDirective(
            target=target,
            members=listed,
            undocumented=show_undocumented,
            excluded=set(),
        )
    )


def _mkdocstrings_options(block: list[str]) -> tuple[set[str] | bool | None, bool]:
    members: set[str] | bool | None = None
    show_undocumented = False
    collecting = False
    for line in block:
        stripped = line.strip()
        if collecting and isinstance(members, set) and stripped.startswith("- "):
            members.add(stripped[2:].strip().strip("'\""))
            continue
        collecting = False
        if stripped.startswith("show_if_no_docstring:"):
            show_undocumented = stripped.split(":", 1)[1].strip().lower() == "true"
        elif stripped.startswith("members:"):
            value = stripped.split(":", 1)[1].strip()
            if value.lower() == "false":
                members = False
            elif value.lower() == "true":
                members = None
            elif value.startswith("["):
                members = {
                    part.strip().strip("'\"")
                    for part in value.strip("[]").split(",")
                    if part.strip()
                }
            elif not value:
                members = set()
                collecting = True
    return members, show_undocumented


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
    if "." not in target:
        return []
    return _resolve_suffix(target, by_name)


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
    if "." not in target:
        return []
    ending = "." + target
    return [module for name, module in modules.items() if name.endswith(ending)]


def _module_directive_members(
    module: _Module, directive: _ModuleDirective
) -> list[Any]:
    if directive.members is not None and not directive.members:
        return []
    if module.has_all and directive.members is None:
        return []
    result: list[Any] = []
    for name, definitions in module.members.items():
        if name in directive.excluded or name in module.private_marked:
            continue
        if directive.members is not None:
            if name in directive.members:
                result.extend(definitions)
            continue
        if directive.undocumented or name in module.documented:
            result.extend(definitions)
    return result


def _stub_declared(modules: dict[str, _Module]) -> list[Any]:
    found: list[Any] = []
    for module in modules.values():
        stub_path = module.path.with_suffix(".pyi")
        if not stub_path.exists():
            continue
        try:
            stub = ast.parse(stub_path.read_text(encoding="utf-8", errors="ignore"))
        except (SyntaxError, ValueError, OSError):
            continue
        if module.public:
            for name in _stub_names(stub):
                found.extend(module.members.get(name, ()))
        if module.path.name == "__init__.py" and module.public:
            lazy_stub = _calls_attach_stub(module.tree)
            for target in _stub_reexports(stub, module.package, lazy_stub):
                owner, _, name = target.rpartition(".")
                if owner in modules:
                    found.extend(modules[owner].members.get(name, ()))
    return found


def _stub_names(stub: ast.Module) -> set[str]:
    declared: set[str] = set()
    exported: set[str] | None = None
    for node in stub.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            declared.add(node.name)
            continue
        for target in _assignment_targets(node):
            if not isinstance(target, ast.Name):
                continue
            if target.id == "__all__":
                exported = _literal_names(getattr(node, "value", None))
            else:
                declared.add(target.id)
    if exported is not None:
        return declared & exported
    return {name for name in declared if _is_public_name(name)}


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
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_leaf(node.func) == "attach_stub":
            return True
    return False


def _stub_reexports(stub: ast.Module, package: str, lazy_stub: bool) -> list[str]:
    targets: list[str] = []
    for node in stub.body:
        if not isinstance(node, ast.ImportFrom) or not node.level:
            continue
        base = package
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
            if lazy_stub or alias.asname == alias.name:
                targets.append(f"{module}.{alias.name}")
    return targets


def _call_leaf(func: ast.expr) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _lazy_exports(modules: dict[str, _Module]) -> list[Any]:
    found: list[Any] = []
    by_package: dict[str, list[_Module]] = defaultdict(list)
    for module in modules.values():
        prefix = module.name.split(".")
        for size in range(1, len(prefix)):
            by_package[".".join(prefix[:size])].append(module)
    for module in modules.values():
        strings = _lazy_table_strings(module.tree)
        if not strings:
            continue
        subtree = [
            candidate
            for candidate in by_package.get(module.package, ())
            if candidate is not module
        ]
        if not subtree:
            continue
        module_targets = {candidate.name: candidate for candidate in subtree}
        for entry_names, entry_modules in strings:
            owners = _entry_owners(entry_modules, module, module_targets)
            if not owners:
                owners = subtree
            for name in entry_names:
                if not _is_public_name(name):
                    continue
                for owner in owners:
                    found.extend(owner.members.get(name, ()))
    return found


def _entry_owners(
    entry_modules: set[str], lazy_module: _Module, module_targets: dict[str, _Module]
) -> list[_Module]:
    owners: list[_Module] = []
    for value in entry_modules:
        candidates = [value.strip(".")]
        if value.startswith("."):
            candidates = [f"{lazy_module.package}.{value.lstrip('.')}"]
        else:
            candidates.append(f"{lazy_module.package}.{value}")
        for candidate in candidates:
            owner = module_targets.get(candidate)
            if owner is not None and owner not in owners:
                owners.append(owner)
    return owners


def _lazy_table_strings(tree: ast.Module) -> list[tuple[set[str], set[str]]]:
    getter = None
    attach_calls: list[ast.Call] = []
    lazy_module = False
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "__getattr__":
            getter = node
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            names = {
                t.id
                for target in node.targets
                for t in _flatten_targets(target)
                if isinstance(t, ast.Name)
            }
            if (
                "__getattr__" in names
                and _call_leaf(node.value.func) in LAZY_ATTACH_CALLS
            ):
                attach_calls.append(node.value)
            if any(_is_sys_modules_self(target) for target in node.targets):
                lazy_module = True
                attach_calls.append(node.value)
    importing_getter = getter is not None and _performs_import(getter)
    if not importing_getter and not attach_calls and not lazy_module:
        return []
    entries: list[tuple[set[str], set[str]]] = []
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            if any(
                isinstance(t, ast.Name) and t.id == "__all__"
                for t in _assignment_targets(node)
            ):
                entries.append((_identifier_strings(node.value), set()))
                continue
            entries.extend(_container_entries(node.value))
    for call in attach_calls:
        for argument in [*call.args, *(keyword.value for keyword in call.keywords)]:
            entries.extend(_container_entries(argument))
    if importing_getter:
        for node in ast.walk(getter):
            if isinstance(node, ast.Compare):
                for comparator in node.comparators:
                    entries.extend(_container_entries(comparator))
                    if isinstance(comparator, ast.Constant) and isinstance(
                        comparator.value, str
                    ):
                        entries.append((_identifier_strings(comparator), set()))
            elif isinstance(node, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
                entries.extend(_container_entries(node))
    return [entry for entry in entries if entry[0]]


def _flatten_targets(target: ast.expr) -> list[ast.expr]:
    if isinstance(target, (ast.Tuple, ast.List)):
        flattened: list[ast.expr] = []
        for element in target.elts:
            flattened.extend(_flatten_targets(element))
        return flattened
    return [target]


def _is_sys_modules_self(target: ast.expr) -> bool:
    if not isinstance(target, ast.Subscript):
        return False
    value = target.value
    if not (
        isinstance(value, ast.Attribute)
        and value.attr == "modules"
        and isinstance(value.value, ast.Name)
        and value.value.id == "sys"
    ):
        return False
    key = target.slice
    return isinstance(key, ast.Name) and key.id == "__name__"


def _performs_import(getter: ast.FunctionDef) -> bool:
    for node in ast.walk(getter):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            return True
        if isinstance(node, ast.Call) and _call_leaf(node.func) in LAZY_IMPORT_CALLS:
            return True
    return False


def _container_entries(node: ast.expr) -> list[tuple[set[str], set[str]]]:
    if isinstance(node, ast.Dict):
        entries: list[tuple[set[str], set[str]]] = []
        for key, value in zip(node.keys, node.values):
            names: set[str] = set()
            module_hints: set[str] = set()
            for part in (key, value):
                if part is None:
                    continue
                for text in _all_strings(part):
                    if text.isidentifier():
                        names.add(text)
                        module_hints.add(text)
                    elif _looks_like_module(text):
                        module_hints.add(text)
            entries.append((names, module_hints))
        return entries
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [(_identifier_strings(node), set())]
    return []


def _all_strings(node: ast.expr) -> list[str]:
    texts: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            texts.append(child.value)
    return texts


def _identifier_strings(node: ast.expr) -> set[str]:
    return {text for text in _all_strings(node) if text.isidentifier()}


def _looks_like_module(text: str) -> bool:
    stripped = text.lstrip(".")
    if not stripped:
        return False
    return all(part.isidentifier() for part in stripped.split("."))
