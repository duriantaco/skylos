"""Can a module rebind its own global names at run time?

Checks that trust a module-level name (an SSRF host fixed by a module setting,
a path sanitizer imported by name) must not trust it when the module can swap
the name out behind its definition: through its namespace dict, its module
object, ``exec``/``eval``, a star import, or a reload. ``module_rebinding``
over-approximates those writes in one pass over the tree."""

from __future__ import annotations

import ast
from pathlib import Path

# Reads of a namespace mapping that cannot rebind a global.
_NAMESPACE_READ_METHODS = frozenset(
    {"get", "keys", "values", "items", "copy", "__contains__", "__getitem__"}
)
_NAMESPACE_NAMES = frozenset({"globals", "vars", "locals"})
# Attributes that reach a module's globals dict or a frame holding it.
_GLOBALS_ATTRIBUTES = frozenset(
    {"__globals__", "func_globals", "f_globals", "f_locals", "_getframe"}
)
_CODE_RUNNERS = frozenset(
    {"exec", "eval", "builtins.exec", "builtins.eval", "__builtins__.exec"}
)
# Functions that return a module object (this one, given the right name).
_MODULE_LOADERS = frozenset({"__import__", "import_module", "getmodule"})
# ``getattr(x, "<name>")`` with one of these reaches a namespace or a writer.
_DANGEROUS_ATTRIBUTE_NAMES = frozenset(
    {
        "__dict__",
        "__globals__",
        "func_globals",
        "f_globals",
        "f_locals",
        "_getframe",
        "globals",
        "vars",
        "locals",
        "exec",
        "eval",
        "__import__",
        "import_module",
        "getmodule",
        "reload",
        "setattr",
        "delattr",
        "__setattr__",
        "__delattr__",
        "__setitem__",
        "__delitem__",
        "__getitem__",
        "__getattribute__",
        "__builtins__",
    }
)
# Module dunders that are plain metadata reads.
_MODULE_METADATA = frozenset(
    {
        "__name__",
        "__file__",
        "__doc__",
        "__spec__",
        "__package__",
        "__path__",
        "__loader__",
        "__all__",
        "__version__",
        "__cached__",
    }
)
# Calls that only read the module object they are given.
_READ_ONLY_CALLS = frozenset(
    {
        "getattr",
        "hasattr",
        "dir",
        "isinstance",
        "issubclass",
        "id",
        "repr",
        "str",
        "type",
        "print",
        "callable",
        "hash",
        "bool",
    }
)
# Expressions that pass a module object through to their own parent.
_PASS_THROUGH = (ast.BoolOp, ast.IfExp, ast.NamedExpr)


def module_name_for(file_path) -> str | None:
    """The importable name of the module in ``file_path`` (its last part)."""
    if not file_path:
        return None
    path = Path(str(file_path))
    return path.parent.name if path.stem == "__init__" else path.stem


def _dotted(node: ast.AST) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _callee(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


class _Analysis:
    def __init__(self, tree: ast.AST, module_name: str | None, parents=None):
        self.tree = tree
        self.module_name = module_name
        self.parents = (
            parents
            if parents is not None
            else {
                id(child): parent
                for parent in ast.walk(tree)
                for child in ast.iter_child_nodes(parent)
            }
        )
        self.aliases = self._module_aliases()

    def is_modules_mapping(self, node: ast.AST) -> bool:
        """``sys.modules`` (however ``sys`` or ``modules`` was imported)."""
        if isinstance(node, ast.Name):
            return node.id in self.modules_aliases
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "modules"
            and isinstance(node.value, ast.Name)
            and node.value.id in self.sys_aliases
        )

    def is_module_object(self, node: ast.AST) -> bool:
        """``node`` may evaluate to this module, or is ``sys.modules``."""
        if self.is_modules_mapping(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.aliases
        if isinstance(node, ast.Subscript):
            return self.is_module_object(node.value)
        if isinstance(node, ast.Call):
            if _callee(node.func) in self.loaders:
                return True
            func = node.func
            return (
                isinstance(func, ast.Attribute)
                and func.attr in {"get", "setdefault"}
                and self.is_modules_mapping(func.value)
            )
        return False

    def refers_to_module(self, node: ast.AST) -> bool:
        """``node`` is this module or a submodule reached through it."""
        while isinstance(node, ast.Attribute) and not self.is_module_object(node):
            node = node.value
        return self.is_module_object(node)

    def _module_aliases(self) -> set[str]:
        """Names that may hold this module: imports of it (``import app as
        me``, ``from pkg import app``) and anything assigned from
        ``sys.modules[...]``, ``importlib.import_module(...)`` or another
        alias. Assignment targets are over-approximated to their root name."""
        name = self.module_name
        aliases: set[str] = set()
        self.sys_aliases = {"sys"}
        self.modules_aliases: set[str] = set()
        # ``from importlib import import_module as im``, ``im = __import__``.
        self.loaders = set(_MODULE_LOADERS)
        self.reloaders = {"reload"}
        assignments = []
        for node in ast.walk(self.tree):
            if (
                isinstance(
                    node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)
                )
                and node.value is not None
            ):
                assignments.append(node)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    parts = alias.name.split(".")
                    if alias.name == "sys":
                        self.sys_aliases.add(alias.asname or "sys")
                    if name is None or name in parts or alias.name == "__main__":
                        aliases.add(alias.asname or parts[0])
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    bound = alias.asname or alias.name
                    if node.module == "sys" and alias.name == "modules":
                        self.modules_aliases.add(bound)
                    if alias.name in _MODULE_LOADERS:
                        self.loaders.add(bound)
                    if alias.name == "reload":
                        self.reloaders.add(bound)
                    if name is None or alias.name == name:
                        aliases.add(bound)
            elif isinstance(node, ast.Assign) and isinstance(
                node.value, (ast.Name, ast.Attribute)
            ):
                referenced = _callee(node.value)
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if referenced in self.loaders:
                            self.loaders.add(target.id)
                        if referenced in self.reloaders:
                            self.reloaders.add(target.id)
        self.aliases = aliases
        # Only assignments whose value mentions a possible module reference
        # can make a new alias; collect their names once, then iterate.
        candidates = []
        seeds = self.loaders | self.modules_aliases | self.sys_aliases
        for node in assignments:
            names = set()
            fixed = False
            for sub in ast.walk(node.value):
                if isinstance(sub, ast.Name):
                    names.add(sub.id)
                elif isinstance(sub, ast.Attribute) and (
                    sub.attr == "modules" or sub.attr in self.loaders
                ):
                    fixed = True
            if fixed or names & seeds:
                candidates.append((node, None))
            elif names:
                candidates.append((node, names))
        grown = True
        while grown:
            grown = False
            for node, names in candidates:
                if names is not None and not names & aliases:
                    continue
                if not self._carries_module(node.value):
                    continue
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                for target in targets:
                    for sub in ast.walk(target):
                        if isinstance(sub, ast.Name) and sub.id not in aliases:
                            aliases.add(sub.id)
                            grown = True
        return aliases

    def _carries_module(self, value: ast.AST) -> bool:
        """``value`` may hold a module object: one appears in it other than as
        the receiver of an attribute read (``me.BASE`` is just a value)."""
        for sub in ast.walk(value):
            if not self.is_module_object(sub):
                continue
            parent = self.parents.get(id(sub))
            if (
                isinstance(parent, ast.Attribute)
                and parent.value is sub
                and parent.attr != "__dict__"
                and not self.is_modules_mapping(sub)
            ):
                continue
            return True
        return False

    def _at_module_scope(self, node: ast.AST) -> bool:
        current = self.parents.get(id(node))
        while current is not None:
            if isinstance(
                current,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
            ):
                return False
            current = self.parents.get(id(current))
        return True

    def _is_namespace(self, node: ast.AST) -> bool:
        """``globals()``, ``builtins.globals()``, ``vars(...)``, or
        ``locals()`` at module level: a mapping whose writes rebind globals."""
        if not isinstance(node, ast.Call):
            return False
        callee = _callee(node.func)
        if callee is None:
            return False
        if callee.endswith(("globals", "vars")):
            return True
        return callee.endswith("locals") and self._at_module_scope(node)

    def _is_read(self, node: ast.AST) -> bool:
        """``node``'s value is only read: subscripted, ``.get()``-style calls,
        ``in``/``is`` comparisons, truth tests or a bare expression."""
        parent = self.parents.get(id(node))
        if isinstance(parent, ast.Subscript):
            return parent.value is node and isinstance(parent.ctx, ast.Load)
        if isinstance(parent, ast.Attribute):
            grandparent = self.parents.get(id(parent))
            return (
                parent.attr in _NAMESPACE_READ_METHODS
                and isinstance(grandparent, ast.Call)
                and grandparent.func is parent
            )
        if isinstance(parent, ast.Compare):
            return True
        return False

    def _module_object_escapes(self, node: ast.AST, rebound: set[str]) -> bool:
        """A module object used anywhere but a read, an attribute write (which
        rebinds that one name) or an alias assignment may be rewritten."""
        current = node
        parent = self.parents.get(id(current))
        while isinstance(parent, _PASS_THROUGH) or (
            isinstance(parent, ast.Starred) and parent.value is current
        ):
            current, parent = parent, self.parents.get(id(parent))
        if parent is None or isinstance(
            parent, (ast.Expr, ast.Compare, ast.If, ast.While, ast.Assert, ast.UnaryOp)
        ):
            return False
        if isinstance(parent, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            return parent.value is not current  # the targets become aliases
        if isinstance(parent, ast.Subscript):
            # ``sys.modules[name]`` is another module object; storing into
            # ``sys.modules`` swaps a module out.
            return parent.value is current and not isinstance(parent.ctx, ast.Load)
        if isinstance(parent, ast.Attribute) and parent.value is current:
            if (
                parent.attr.startswith("__")
                and parent.attr.endswith("__")
                and parent.attr not in _MODULE_METADATA
            ):
                # ``__dict__``, ``__setattr__``, ``sys.modules.__getitem__``:
                # a writer or a way around the attribute checks.
                return True
            if isinstance(parent.ctx, (ast.Store, ast.Del)):
                rebound.add(parent.attr)
                return False
            grandparent = self.parents.get(id(parent))
            if (
                self.is_modules_mapping(current)
                and isinstance(grandparent, ast.Call)
                and grandparent.func is parent
            ):
                # ``sys.modules.get(...)`` is checked as its own module
                # object; a mutating method of ``sys.modules`` is a write.
                return parent.attr not in _NAMESPACE_READ_METHODS | {"setdefault"}
            return False
        if isinstance(parent, ast.keyword):
            parent = self.parents.get(id(parent))
        if isinstance(parent, ast.Call) and parent.func is not current:
            callee = _callee(parent.func)
            if (
                callee in {"setattr", "delattr"}
                and parent.args
                and parent.args[0] is current
            ):
                attr = parent.args[1] if len(parent.args) > 1 else None
                if isinstance(attr, ast.Constant) and isinstance(attr.value, str):
                    rebound.add(attr.value)
                    return False
                return True
            return callee not in _READ_ONLY_CALLS
        return True

    def run(self) -> tuple[bool, frozenset[str]]:
        rebound: set[str] = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ImportFrom) and any(
                alias.name == "*" for alias in node.names
            ):
                return True, frozenset()
            if isinstance(node, ast.Call):
                callee = _callee(node.func)
                if callee in self.reloaders or _dotted(node.func) in _CODE_RUNNERS:
                    return True, frozenset()
                if callee == "getattr" and len(node.args) >= 2:
                    attr = node.args[1]
                    if isinstance(attr, ast.Constant):
                        if attr.value in _DANGEROUS_ATTRIBUTE_NAMES:
                            return True, frozenset()
                    elif self.is_module_object(node.args[0]) or _dotted(
                        node.args[0]
                    ) in {"builtins", "__builtins__"}:
                        return True, frozenset()
                if callee in {"setattr", "delattr"} and any(
                    isinstance(arg, ast.Starred) for arg in node.args[:2]
                ):
                    return True, frozenset()
                if self._is_namespace(node) and not self._is_read(node):
                    return True, frozenset()
            elif isinstance(node, ast.Name):
                if node.id in {"exec", "eval"}:
                    parent = self.parents.get(id(node))
                    if not (isinstance(parent, ast.Call) and parent.func is node):
                        return True, frozenset()
                if node.id in _NAMESPACE_NAMES or node.id in _GLOBALS_ATTRIBUTES:
                    parent = self.parents.get(id(node))
                    if not (isinstance(parent, ast.Call) and parent.func is node):
                        return True, frozenset()
                    if node.id in _GLOBALS_ATTRIBUTES:
                        return True, frozenset()
            elif isinstance(node, ast.Attribute):
                if node.attr in _GLOBALS_ATTRIBUTES:
                    return True, frozenset()
                if node.attr == "__dict__" and not (
                    isinstance(node.value, ast.Name)
                    and node.value.id in {"self", "cls"}
                ):
                    return True, frozenset()
                if node.attr in _NAMESPACE_NAMES and _dotted(node.value) in {
                    "builtins",
                    "__builtins__",
                }:
                    parent = self.parents.get(id(node))
                    if not (isinstance(parent, ast.Call) and parent.func is node):
                        return True, frozenset()
                if isinstance(node.ctx, (ast.Store, ast.Del)) and self.refers_to_module(
                    node.value
                ):
                    rebound.add(node.attr)
            if (
                isinstance(node, (ast.Name, ast.Attribute, ast.Subscript, ast.Call))
                and isinstance(getattr(node, "ctx", ast.Load()), ast.Load)
                and self.is_module_object(node)
                and self._module_object_escapes(node, rebound)
            ):
                return True, frozenset()
        return False, frozenset(rebound)


def module_rebinding(
    tree: ast.AST | None, module_name: str | None = None, parents=None
) -> tuple[bool, frozenset[str]]:
    """``(dynamic, rebound)`` for the module ``tree``.

    ``dynamic``: any global may be replaced at run time (a write through
    ``globals()``/``vars()``/``locals()``, ``builtins.globals()``, a function's
    ``__globals__``, a frame's ``f_globals``, a module ``__dict__``,
    ``exec``/``eval``, ``reload``, a star import, ``setattr`` on the module with
    a computed name, or the module object passed to other code).
    ``rebound``: names written through the module object
    (``setattr(sys.modules[__name__], "NAME", ...)``, ``me.NAME = ...``).
    ``module_name`` (see ``module_name_for``) recognises self-imports; without
    it every import counts as one. ``parents`` (child id -> parent node) may
    be passed to reuse a map the caller already built."""
    if tree is None:
        return False, frozenset()
    return _Analysis(tree, module_name, parents).run()


def attribute_write_names(tree: ast.AST | None) -> tuple[frozenset[str], bool]:
    """Attribute names the module writes on any object (``x.basename = ...``,
    ``del x.basename``, ``setattr(x, "basename", ...)``), and whether it
    writes one with a computed name (``setattr(x, name, ...)`` on anything
    but ``self``/``cls``). A function imported by name is not the library's
    own if the module may have replaced it on the library module first."""
    names: set[str] = set()
    computed = False
    for node in ast.walk(tree) if tree is not None else ():
        if isinstance(node, ast.Attribute) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            names.add(node.attr)
        elif isinstance(node, ast.Call) and _callee(node.func) in {
            "setattr",
            "delattr",
        }:
            attr = node.args[1] if len(node.args) > 1 else None
            if isinstance(attr, ast.Constant) and isinstance(attr.value, str):
                names.add(attr.value)
            elif not (
                node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in {"self", "cls"}
            ):
                computed = True
    return frozenset(names), computed


def has_mock_api_patching(tree: ast.AST | None) -> bool:
    """A mock patcher may replace an imported API without an attribute store.

    This is an uncertainty check for optional safety proofs, not a claim that
    the patch targets a particular API. Aliases are overapproximated across
    scopes so rebinding a patch name cannot accidentally establish safety.
    """
    if tree is None:
        return False
    nodes = list(ast.walk(tree))
    bindings: dict[str, set[str]] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                qualified = alias.name if alias.asname else name
                bindings.setdefault(name, set()).add(qualified)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                bindings.setdefault(alias.asname or alias.name, set()).add(
                    f"{node.module}.{alias.name}"
                )

    patch_paths = {
        "unittest", "unittest.mock", "mock",
        "unittest.mock.patch", "mock.patch",
        "unittest.mock.patch.object", "mock.patch.object",
        "unittest.mock.patch.dict", "mock.patch.dict",
        "unittest.mock.patch.multiple", "mock.patch.multiple",
    }
    bindings = {
        name: values & patch_paths for name, values in bindings.items()
        if values & patch_paths
    }
    if not bindings:
        return False

    def qualified(expr):
        dotted = _dotted(expr)
        if not dotted:
            return set()
        root, separator, tail = dotted.partition(".")
        return {
            f"{value}.{tail}" if separator else value
            for value in bindings.get(root, ())
        }

    assignments = [node for node in nodes if isinstance(node, (ast.Assign, ast.AnnAssign))]
    for _ in range(len(assignments) + 1):
        changed = False
        for node in assignments:
            values = qualified(node.value) & patch_paths
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and values:
                    existing = bindings.setdefault(target.id, set())
                    before = len(existing)
                    existing.update(values)
                    changed |= len(existing) != before
        if not changed:
            break
    for node in nodes:
        if isinstance(node, ast.Call):
            if any(
                name == prefix or name.startswith(prefix + ".")
                for name in qualified(node.func)
                for prefix in ("unittest.mock.patch", "mock.patch")
            ):
                return True
    return False
