"""Members that project classes inherit from classes outside the project.

A method or class attribute whose name is defined on an external base class
(``ast.NodeVisitor.generic_visit``, ``asyncio.Protocol.eof_received``, a
Sphinx ``Domain.resolve_xref``, a Pygments ``Style.styles``) is an override:
the library calls or reads it, so it has no reference inside the project.

The external MRO is read from source, never imported. Modules are located by
file lookup in the running interpreter's standard-library directory and one
project virtualenv, preferring ``.venv``, ``venv``, ``env``, then ``.env``.
When no project virtualenv is found, ``site-packages``/``dist-packages`` entries
on ``sys.path`` outside the scan root are used instead. Project dependency
sources take precedence over the scanner's installed dependency versions.
A class's bases are followed through its module's imports, re-exports and
simple aliases, with depth, file-size and file-count limits and a
per-search-path cache. A base that cannot be found stays unresolved and
callers keep their previous behaviour for it (see also curated framework
class attributes in ``documented_conventions``).

A few documented hooks belong to classes implemented in C, which have no
source to read; they are listed in ``_NATIVE_CLASS_MEMBERS``.
"""

from __future__ import annotations

import ast
import builtins
import os
import sys
import sysconfig
import warnings
from pathlib import Path
from typing import Any, Optional

_MAX_FILE_BYTES = 2_000_000
_MAX_PARSED_FILES = 600
_MAX_CLASS_DEPTH = 32
_MAX_ALIAS_HOPS = 8
_MAX_PROJECT_DEPTH = 32

# Documented subclass hooks of C-implemented classes (no Python source).
# ctypes structures, unions, arrays and pointers:
# https://docs.python.org/3/library/ctypes.html#structured-data-types
_CTYPES_LAYOUT = frozenset({"_fields_", "_pack_", "_anonymous_", "_align_", "_layout_"})
_NATIVE_CLASS_MEMBERS = {
    "_ctypes.Structure": _CTYPES_LAYOUT,
    "_ctypes.Union": _CTYPES_LAYOUT,
    "_ctypes.Array": frozenset({"_type_", "_length_"}),
    "_ctypes._Pointer": frozenset({"_type_"}),
    "_ctypes._SimpleCData": frozenset({"_type_"}),
}

_COMPOUND = (ast.If, ast.Try, ast.With, ast.AsyncWith)
if hasattr(ast, "TryStar"):
    _COMPOUND = (*_COMPOUND, ast.TryStar)


def _child_blocks(stmt: ast.stmt):
    for field in ("body", "orelse", "finalbody"):
        block = getattr(stmt, field, None)
        if block:
            yield block
    for handler in getattr(stmt, "handlers", ()) or ():
        yield handler.body


def _iter_flat(body):
    """Statements of a block, descending into if/try/with but not into
    functions or classes."""
    stack = [list(body)]
    while stack:
        block = stack.pop()
        for stmt in block:
            if isinstance(stmt, _COMPOUND):
                stack.extend(_child_blocks(stmt))
            else:
                yield stmt


def _target_names(target, out: set[str]) -> None:
    if isinstance(target, ast.Name):
        out.add(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            _target_names(elt, out)
    elif isinstance(target, ast.Starred):
        _target_names(target.value, out)


def _class_body_names(node: ast.ClassDef) -> set[str]:
    names: set[str] = set()
    for stmt in _iter_flat(node.body):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(stmt.name)
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                _target_names(target, names)
        elif isinstance(stmt, ast.AnnAssign):
            _target_names(stmt.target, names)
    return names


def _base_exprs(base: ast.expr) -> list:
    while isinstance(base, ast.Subscript):
        base = base.value
    if isinstance(base, (ast.Name, ast.Attribute)):
        return [base]
    # ``six.with_metaclass(Meta, Base)`` / ``with_metaclass(Meta, Base)``
    if isinstance(base, ast.Call):
        func = base.func
        name = getattr(func, "id", None) or getattr(func, "attr", None)
        if name and name.endswith("with_metaclass"):
            return [
                arg
                for arg in base.args[1:]
                if isinstance(arg, (ast.Name, ast.Attribute))
            ]
    return []


class _ClassRecord:
    """What a class statement declares: member names, base expressions and
    nested classes. The module's AST is not kept."""

    __slots__ = ("name", "members", "bases", "nested")

    def __init__(self, node: ast.ClassDef) -> None:
        self.name = node.name
        self.members = frozenset(_class_body_names(node))
        self.bases = tuple(expr for base in node.bases for expr in _base_exprs(base))
        self.nested = {
            stmt.name: _ClassRecord(stmt)
            for stmt in _iter_flat(node.body)
            if isinstance(stmt, ast.ClassDef)
        }


class _Module:
    __slots__ = ("name", "package", "bindings", "star_imports")

    def __init__(self, name: str, is_package: bool, tree: ast.Module) -> None:
        self.name = name
        self.package = name if is_package else name.rpartition(".")[0]
        self.bindings: dict[str, list[tuple]] = {}
        self.star_imports: list[str] = []
        for stmt in _iter_flat(tree.body):
            self._record(stmt)

    def _bind(self, name: str, binding: tuple) -> None:
        self.bindings.setdefault(name, []).append(binding)

    def _absolute(self, module: Optional[str], level: int) -> Optional[str]:
        if not level:
            return module
        parts = self.package.split(".") if self.package else []
        up = level - 1
        if up > len(parts):
            return None
        base = ".".join(parts[: len(parts) - up])
        if module:
            return f"{base}.{module}" if base else module
        return base or None

    def _record(self, stmt: ast.stmt) -> None:
        if isinstance(stmt, ast.ClassDef):
            self._bind(stmt.name, ("class", _ClassRecord(stmt)))
        elif isinstance(stmt, ast.Import):
            for alias in stmt.names:
                if alias.asname:
                    self._bind(alias.asname, ("module", alias.name))
                else:
                    head = alias.name.split(".", 1)[0]
                    self._bind(head, ("module", head))
        elif isinstance(stmt, ast.ImportFrom):
            source = self._absolute(stmt.module, stmt.level or 0)
            if not source:
                return
            for alias in stmt.names:
                if alias.name == "*":
                    self.star_imports.append(source)
                else:
                    self._bind(alias.asname or alias.name, ("from", source, alias.name))
        elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if isinstance(target, ast.Name) and isinstance(
                stmt.value, (ast.Name, ast.Attribute, ast.Subscript)
            ):
                self._bind(target.id, ("expr", stmt.value))


class _Class:
    """A resolved external class: its members and its bases."""

    __slots__ = ("qualname", "members", "bases")

    def __init__(self, qualname: str, members, bases) -> None:
        self.qualname = qualname
        self.members = frozenset(members)
        self.bases = bases


class ExternalClassIndex:
    """Reads external classes from source and answers "does this class, or
    any class in its MRO, define ``name``?"."""

    def __init__(self, search_dirs) -> None:
        self.search_dirs = tuple(search_dirs)
        self._files: dict[str, Optional[tuple[Path, bool]]] = {}
        self._modules: dict[str, Optional[_Module]] = {}
        self._classes: dict[Any, Optional[_Class]] = {}
        self._mro_members: dict[str, Optional[dict[str, str]]] = {}
        self._parsed = 0

    # -- module lookup -------------------------------------------------
    def _module_file(self, name: str) -> Optional[tuple[Path, bool]]:
        if name in self._files:
            return self._files[name]
        found = None
        if name and all(part.isidentifier() for part in name.split(".")):
            rel = name.replace(".", os.sep)
            for directory in self.search_dirs:
                package_init = directory / rel / "__init__.py"
                if package_init.is_file():
                    found = (package_init, True)
                    break
                module_file = directory / (rel + ".py")
                if module_file.is_file():
                    found = (module_file, False)
                    break
        self._files[name] = found
        return found

    def _module(self, name: str) -> Optional[_Module]:
        if name in self._modules:
            return self._modules[name]
        module = None
        located = self._module_file(name)
        if located is not None and self._parsed < _MAX_PARSED_FILES:
            path, is_package = located
            try:
                if path.stat().st_size <= _MAX_FILE_BYTES:
                    self._parsed += 1
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        tree = ast.parse(path.read_bytes(), filename=str(path))
                    module = _Module(name, is_package, tree)
            except (OSError, SyntaxError, ValueError, RecursionError, MemoryError):
                module = None
        self._modules[name] = module
        return module

    # -- name resolution -------------------------------------------------
    def _lookup(self, module_name: str, name: str, hops: int):
        """Resolve ``name`` in a module's namespace to ("class", module,
        node, qualname), ("module", name), ("native", qualname), ("builtin",
        type) or None."""
        if hops > _MAX_ALIAS_HOPS:
            return None
        qualname = f"{module_name}.{name}"
        if qualname in _NATIVE_CLASS_MEMBERS:
            return ("native", qualname)
        module = self._module(module_name)
        if module is None:
            if self._module_file(qualname) is not None:
                return ("module", qualname)
            return None
        for binding in module.bindings.get(name, ()):
            resolved = self._resolve_binding(module, binding, hops)
            if resolved is not None:
                return resolved
        if self._module_file(qualname) is not None:
            return ("module", qualname)
        for star in module.star_imports:
            resolved = self._lookup(star, name, hops + 1)
            if resolved is not None:
                return resolved
        return None

    def _resolve_binding(self, module: _Module, binding: tuple, hops: int):
        kind = binding[0]
        if kind == "class":
            record = binding[1]
            return ("class", module.name, record, f"{module.name}.{record.name}")
        if kind == "module":
            target = binding[1]
            return ("module", target) if self._module_file(target) else None
        if kind == "from":
            source, name = binding[1], binding[2]
            if source == module.name:
                # ``from . import sub`` inside a package's ``__init__``.
                submodule = f"{source}.{name}"
                return ("module", submodule) if self._module_file(submodule) else None
            return self._lookup(source, name, hops + 1)
        if kind == "expr":
            return self._resolve_expr(module, binding[1], hops + 1)
        return None

    def _resolve_expr(self, module: _Module, expr: ast.expr, hops: int):
        while isinstance(expr, ast.Subscript):
            expr = expr.value
        if isinstance(expr, ast.Name):
            if expr.id in module.bindings or module.star_imports:
                resolved = self._lookup(module.name, expr.id, hops)
                if resolved is not None:
                    return resolved
            builtin = getattr(builtins, expr.id, None)
            if isinstance(builtin, type):
                return ("builtin", builtin)
            return None
        if isinstance(expr, ast.Attribute):
            head = self._resolve_expr(module, expr.value, hops)
            return self._attribute(head, expr.attr, hops)
        return None

    def _attribute(self, target, attr: str, hops: int):
        if target is None:
            return None
        if target[0] == "module":
            return self._lookup(target[1], attr, hops + 1)
        if target[0] == "class":
            _, module_name, record, qualname = target
            nested = record.nested.get(attr)
            if nested is not None:
                return ("class", module_name, nested, f"{qualname}.{attr}")
        return None

    def resolve(self, dotted: str):
        """Resolve an absolute dotted name such as ``asyncio.Protocol``."""
        parts = dotted.split(".")
        if len(parts) == 1:
            builtin = getattr(builtins, dotted, None)
            return ("builtin", builtin) if isinstance(builtin, type) else None
        if parts[0] == "builtins" and len(parts) == 2:
            builtin = getattr(builtins, parts[1], None)
            return ("builtin", builtin) if isinstance(builtin, type) else None
        for split in range(len(parts) - 1, 0, -1):
            module_name = ".".join(parts[:split])
            if self._module_file(module_name) is None:
                continue
            target = ("module", module_name)
            for attr in parts[split:]:
                target = self._attribute(target, attr, 0)
                if target is None:
                    break
            if target is not None:
                return target
            return None
        return None

    # -- class members ---------------------------------------------------
    def _class(self, target) -> Optional[_Class]:
        if target is None:
            return None
        kind = target[0]
        key = (
            ("builtin", target[1].__name__)
            if kind == "builtin"
            else (kind, target[-1] if kind != "class" else target[3])
        )
        if key in self._classes:
            return self._classes[key]
        result = None
        if kind == "builtin":
            result = _Class(f"builtins.{target[1].__name__}", dir(target[1]), ())
        elif kind == "native":
            result = _Class(target[1], _NATIVE_CLASS_MEMBERS[target[1]], ())
        elif kind == "class":
            _, module_name, record, qualname = target
            module = self._module(module_name)
            bases = tuple((module, base) for base in record.bases) if module else ()
            result = _Class(qualname, record.members, bases)
        self._classes[key] = result
        return result

    def mro_members(self, dotted: str) -> Optional[dict[str, str]]:
        """Member name -> defining class for ``dotted`` and its external
        ancestors, or None when ``dotted`` cannot be found."""
        if dotted in self._mro_members:
            return self._mro_members[dotted]
        root = self._class(self.resolve(dotted))
        members: Optional[dict[str, str]] = None
        if root is not None:
            members = {}
            seen = set()
            queue = [(root, 0)]
            while queue:
                cls, depth = queue.pop(0)
                if cls.qualname in seen or depth > _MAX_CLASS_DEPTH:
                    continue
                seen.add(cls.qualname)
                for name in cls.members:
                    members.setdefault(name, cls.qualname)
                for module, base in cls.bases:
                    parent = self._class(self._resolve_expr(module, base, 0))
                    if parent is not None:
                        queue.append((parent, depth + 1))
        self._mro_members[dotted] = members
        return members

    def defining_class(self, dotted: str, member: str) -> Optional[str]:
        members = self.mro_members(dotted)
        if not members:
            return None
        return members.get(member)


_VENV_DIR_NAMES = (".venv", "venv", "env", ".env")


def _venv_site_packages(scan_roots) -> list[Path]:
    """``site-packages`` from the first available project virtualenv.

    Scanner images often lack the app's third-party deps on ``sys.path``. The
    app's ``.venv`` (excluded from dead-code file walk) still holds Celery /
    Django sources that define subclass hooks such as ``ResultConsumer``.
    Prefer the first scan root, then ``.venv``, ``venv``, ``env``, ``.env``.
    Keep one environment authoritative so stale environments cannot contribute
    incompatible package files. Arbitrary vendored trees are not included.
    """
    for root in scan_roots:
        try:
            root_path = Path(root).resolve()
        except (OSError, RuntimeError):
            continue
        if not root_path.is_dir():
            continue
        for venv_name in _VENV_DIR_NAMES:
            venv = root_path / venv_name
            if not venv.is_dir():
                continue
            found: list[Path] = []
            for pattern in (
                "lib/python*/site-packages",
                "lib/site-packages",
                "Lib/site-packages",
            ):
                found.extend(
                    path for path in sorted(venv.glob(pattern)) if path.is_dir()
                )
            if found:
                return found
    return []


def default_search_dirs(exclude_roots=()) -> list[Path]:
    """Stdlib plus one project venv, or the scanner's external site-packages.

    The selected project environment is authoritative for dependency source.
    Mixing scanner or stale virtualenv packages could invent an incompatible
    MRO. Without a project environment, keep the scanner's search-path order.
    Vendored trees inside the scan remain excluded.
    """
    excluded = []
    for root in exclude_roots:
        try:
            excluded.append(Path(root).resolve())
        except (OSError, RuntimeError):
            continue

    def inside_scan(path: Path) -> bool:
        return any(path == root or root in path.parents for root in excluded)

    candidates = []
    stdlib = sysconfig.get_paths().get("stdlib")
    if stdlib:
        candidates.append(Path(stdlib))
    project_sites = _venv_site_packages(excluded)
    if project_sites:
        candidates.extend(project_sites)
    else:
        for entry in sys.path:
            if entry and Path(entry).name in ("site-packages", "dist-packages"):
                candidates.append(Path(entry))

    dirs: list[Path] = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError):
            continue
        if resolved in dirs or not resolved.is_dir():
            continue
        # Only explicitly selected virtualenv sources may be inside the scan.
        if inside_scan(resolved) and candidate not in project_sites:
            continue
        dirs.append(resolved)
    return dirs


_INDEXES: dict[tuple, ExternalClassIndex] = {}


def external_class_index(exclude_roots=()) -> ExternalClassIndex:
    dirs = tuple(default_search_dirs(exclude_roots))
    index = _INDEXES.get(dirs)
    if index is None:
        if len(_INDEXES) > 8:
            _INDEXES.clear()
        index = _INDEXES[dirs] = ExternalClassIndex(dirs)
    return index


# -- project side ----------------------------------------------------------


def _bases_of(definition) -> tuple:
    bases = getattr(definition, "base_classes", None)
    return tuple(bases) if isinstance(bases, (list, tuple)) else ()


class ProjectClassGraph:
    """Project classes by qualified and simple name, with the walk from a
    project class to the external bases of its whole project ancestry."""

    def __init__(self, defs: dict) -> None:
        self.defs = defs
        self.classes_by_simple: dict[str, list] = {}
        self.project_roots: set[str] = set()
        self.imports: dict[tuple[str, str], str] = {}
        self.imported_roots: dict[str, set[str]] = {}
        for definition in defs.values():
            kind = getattr(definition, "type", None)
            name = str(getattr(definition, "name", ""))
            if kind == "import":
                filename = str(definition.filename)
                binding = getattr(definition, "binding_name", None)
                if binding:
                    self.imports.setdefault((filename, binding), name)
                self.imported_roots.setdefault(filename, set()).add(
                    name.split(".", 1)[0]
                )
                continue
            if name:
                self.project_roots.add(name.split(".", 1)[0])
            if kind == "class":
                self.classes_by_simple.setdefault(definition.simple_name, []).append(
                    definition
                )
        self._ancestry: dict[str, tuple[list, list]] = {}

    def import_target(self, filename, binding: str) -> Optional[str]:
        return self.imports.get((str(filename), binding))

    def imports_module(self, filename, root: str) -> bool:
        return root in self.imported_roots.get(str(filename), ())

    def resolve_reference(self, filename, dotted: str) -> str:
        """``dotted`` as written in ``filename`` (``default``,
        ``traitlets.default``) with its head expanded through the file's
        imports (``traitlets.default``)."""
        head, sep, rest = dotted.partition(".")
        target = self.import_target(filename, head)
        if not target:
            return dotted
        return f"{target}.{rest}" if sep else target

    def class_defines(self, class_def, name: str) -> bool:
        """Whether ``class_def`` or a project ancestor declares ``name``."""
        if f"{class_def.name}.{name}" in self.defs:
            return True
        project, _ = self.ancestry(class_def)
        return any(f"{ancestor.name}.{name}" in self.defs for ancestor in project)

    def owner_class(self, def_obj):
        """The project class that directly owns a method or attribute."""
        if "." not in def_obj.name:
            return None
        owner = self.defs.get(def_obj.name.rsplit(".", 1)[0])
        if owner is not None and owner.type == "class":
            return owner
        return None

    def _project_class(self, qname: str):
        """("project", def) / ("external", qname) / None (unknown)."""
        definition = self.defs.get(qname)
        if definition is not None and definition.type == "class":
            return ("project", definition)
        simple = qname.rsplit(".", 1)[-1]
        head = qname.split(".", 1)[0]
        if head not in self.project_roots:
            return ("external", qname)
        candidates = self.classes_by_simple.get(simple, [])
        if not candidates:
            builtin = getattr(builtins, simple, None)
            if isinstance(builtin, type):
                return ("external", f"builtins.{simple}")
            return None
        # A package re-export: ``from pkg.sub import Cls`` imported as
        # ``pkg.Cls``. The class must live under the importing package.
        package = qname.rsplit(".", 1)[0] + "."
        under_package = [c for c in candidates if c.name.startswith(package)]
        if len(under_package) == 1:
            return ("project", under_package[0])
        return None

    def ancestry(self, class_def) -> tuple[list, list]:
        """(project ancestors, external base qualified names) of a project
        class, nearest first, excluding the class itself."""
        key = class_def.name
        cached = self._ancestry.get(key)
        if cached is not None:
            return cached
        project: list = []
        external: list[str] = []
        seen = {key}
        queue = [(class_def, 0)]
        while queue:
            current, depth = queue.pop(0)
            if depth > _MAX_PROJECT_DEPTH:
                continue
            for base in _bases_of(current):
                resolved = self._project_class(str(base))
                if resolved is None:
                    continue
                kind, value = resolved
                if kind == "external":
                    if value not in external:
                        external.append(value)
                    continue
                if value.name in seen:
                    continue
                seen.add(value.name)
                project.append(value)
                queue.append((value, depth + 1))
        result = (project, external)
        self._ancestry[key] = result
        return result

    def ancestor_base_names(self, class_def) -> set[str]:
        """Simple names of every base along the project ancestry."""
        names = {str(base).rsplit(".", 1)[-1] for base in _bases_of(class_def)}
        project, external = self.ancestry(class_def)
        for ancestor in project:
            names.update(str(base).rsplit(".", 1)[-1] for base in _bases_of(ancestor))
        names.update(qname.rsplit(".", 1)[-1] for qname in external)
        return names


def project_class_graph(analyzer) -> ProjectClassGraph:
    defs = getattr(analyzer, "defs", {}) or {}
    cached = getattr(analyzer, "_project_class_graph", None)
    if cached is not None and cached.defs is defs:
        return cached
    graph = ProjectClassGraph(defs)
    try:
        analyzer._project_class_graph = graph
    except AttributeError:
        pass
    return graph


def _scan_roots(analyzer) -> list:
    roots = []
    for attr in ("_project_root", "_module_root_path"):
        value = getattr(analyzer, attr, None)
        if value:
            roots.append(value)
    return roots


def external_class_index_for(analyzer) -> ExternalClassIndex:
    index = getattr(analyzer, "_external_class_index", None)
    if index is None:
        index = external_class_index(_scan_roots(analyzer))
        try:
            analyzer._external_class_index = index
        except AttributeError:
            pass
    return index


def external_member_owner(class_def, name: str, analyzer) -> Optional[str]:
    """The external class in ``class_def``'s ancestry that defines ``name``."""
    graph = project_class_graph(analyzer)
    _, external = graph.ancestry(class_def)
    if not external:
        return None
    index = external_class_index_for(analyzer)
    for qname in external:
        if qname.split(".", 1)[0] in graph.project_roots:
            continue
        defining = index.defining_class(qname, name)
        if defining:
            return defining
    return None


def external_override_owner(def_obj, analyzer) -> Optional[str]:
    """The external class (``module.Class``) whose member ``def_obj``
    overrides, or None when no resolvable external ancestor defines it."""
    if getattr(def_obj, "type", None) not in ("method", "variable"):
        return None
    owner = project_class_graph(analyzer).owner_class(def_obj)
    if owner is None:
        return None
    return external_member_owner(owner, def_obj.simple_name, analyzer)
