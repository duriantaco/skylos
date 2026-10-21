"""A bounded index of source-owned Python symbols and path effects.

The index parses project files. It never imports a target module or invokes a
target callable; known filesystem operations only inspect the scanned tree.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.deadcode.python_source_proofs import _scope_nodes


@dataclass
class Symbol:
    name: str
    bound: bool = False
    invalid: bool = False
    kind: str | None = None


@dataclass
class Function:
    path: Path
    node: ast.FunctionDef
    closure: dict = field(default_factory=dict)
    registered: bool = False
    owner: Class | None = None


@dataclass
class Class:
    path: Path
    node: ast.ClassDef | None
    fields: tuple[str, ...] = ()
    defaults: dict = field(default_factory=dict)
    generated_init: bool = False


@dataclass
class Record:
    owner: Class | None
    fields: dict
    provider: str | None = None


@dataclass
class SourceSuper:
    receiver: Record
    owner: Class


@dataclass
class BrowserMethod:
    receiver: Record
    name: str


@dataclass
class Choice:
    values: list


@dataclass(frozen=True)
class NullValue:
    pass


NULL = NullValue()


class Environment(dict):
    """Frame metadata is separate from target-controlled variable names."""

    def __init__(self, values=(), *, module_scope=False):
        super().__init__(values)
        self.module_scope = module_scope
        self.global_names = set(getattr(values, "global_names", ()))
        self.yielded = []
        self.class_owner = getattr(values, "class_owner", None)


def alternatives(value):
    if isinstance(value, Choice):
        return value.values
    return [value]


def merge(values):
    found = []
    signatures = set()
    for value in values:
        for item in alternatives(value):
            if item is None:
                continue
            if isinstance(item, (str, bool, int, float, Path)):
                key = (type(item), str(item))
            else:
                key = (type(item), id(item))
            if key not in signatures:
                signatures.add(key)
                found.append(item)
            if len(found) >= 256:
                return Choice(found)
    if not found:
        return None
    if len(found) == 1:
        return found[0]
    return Choice(found)


class ProjectSourceIndex:
    """Resolve finite source paths, returned records and directory listings."""

    def __init__(self, root: Path, source_files):
        self.root = root.resolve()
        self.trees = {}
        self.modules = {}
        self.definitions = {}
        self.imports = {}
        self.mutations = set()
        self.registry_unknown = False
        self.registry_changes = set()
        self.assignments = {}
        self.globals = {}
        self.reading = set()
        self.reachable = set()
        self.completed = set()
        self.completed_call_sites = set()
        self.context_cache = None
        self.writers_done = set()
        self.initialized = set()
        self.budget = 0
        self.total_steps = 0
        self.owner_steps = 0
        self.observer = None
        self.executed_contexts = []
        self.context_keys = set()
        self.browser_calls = []
        self.rendered_html = []
        for raw in sorted(source_files, key=str):
            path = Path(raw)
            if not path.is_absolute():
                path = self.root / path
            if any(
                candidate.is_symlink()
                for candidate in [path, *path.parents]
                if candidate != self.root
            ):
                continue
            path = path.resolve()
            if path.suffix not in {".py", ".pyw"}:
                continue
            try:
                relative = path.relative_to(self.root)
            except ValueError:
                continue
            source = read_text_no_symlink(path, max_bytes=512_000, encoding="utf-8")
            if source is None:
                continue
            try:
                tree = ast.parse(source)
            except (ValueError, SyntaxError, RecursionError):
                continue
            parts = list(relative.with_suffix("").parts)
            if parts[-1] == "__init__":
                parts.pop()
            name = ".".join(parts)
            self.trees[path] = tree
            self.modules[name] = path
            self.definitions[path] = {}
            self.imports[path] = {}
            self.assignments[path] = {}
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    self.definitions[path][node.name] = node
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.assignments[path].setdefault(target.id, []).append(
                                node.value
                            )
                elif isinstance(node, ast.AnnAssign) and isinstance(
                    node.target, ast.Name
                ):
                    self.assignments[path].setdefault(node.target.id, []).append(
                        node.value
                    )
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    self.imports[path].update(self.import_bindings(node, path))
        for path, tree in self.trees.items():
            blocked = set()
            unknown = False
            for node in tree.body:
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if (
                            isinstance(target, ast.Subscript)
                            and self.provider_name(path, target.value) == "sys.modules"
                        ):
                            if isinstance(target.slice, ast.Constant) and isinstance(
                                target.slice.value, str
                            ):
                                blocked.add(target.slice.value)
                            else:
                                unknown = True
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    for name, symbol in self.import_bindings(node, path).items():
                        if unknown or symbol.name.split(".")[0] in blocked:
                            self.imports[path][name] = Symbol(symbol.name, invalid=True)

    def provider_name(self, path, node, seen=frozenset()):
        if isinstance(node, ast.Attribute):
            parent = self.provider_name(path, node.value, seen)
            if parent:
                return parent + "." + node.attr
        if isinstance(node, ast.Name) and node.id not in seen:
            imported = self.imports.get(path, {}).get(node.id)
            if imported is not None:
                return imported.name
            values = self.assignments.get(path, {}).get(node.id, ())
            if len(values) == 1:
                return self.provider_name(path, values[0], seen | {node.id})
        return ""

    def import_bindings(self, node, path):
        result = {}
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                provider = alias.name if alias.asname else name
                blocked = (
                    self.registry_unknown
                    or provider.split(".")[0] in self.registry_changes
                )
                result[name] = Symbol(
                    provider, bound=True, invalid=blocked, kind="module"
                )
        elif isinstance(node, ast.ImportFrom) and (node.module or node.level):
            provider = node.module or ""
            if node.level:
                current = self.module_name(path).split(".")
                if path.stem != "__init__":
                    current = current[:-1]
                if node.level > 1:
                    current = current[: -(node.level - 1)]
                if provider:
                    current.append(provider)
                provider = ".".join(current)
            for alias in node.names:
                if alias.name != "*":
                    result[alias.asname or alias.name] = Symbol(
                        provider + "." + alias.name,
                        bound=True,
                        invalid=self.registry_unknown
                        or provider.split(".")[0] in self.registry_changes,
                    )
        return result

    def module_name(self, path):
        for name, candidate in self.modules.items():
            if candidate == path:
                return name
        return ""

    def symbol(self, value):
        if not isinstance(value, Symbol):
            return value
        if value.invalid:
            return None
        if (
            not value.bound
            and (
                self.registry_unknown
                or value.name.split(".")[0] in self.registry_changes
            )
            and not value.name.startswith("builtins.")
        ):
            return None
        if any(
            value.name == name or value.name.startswith(name + ".")
            for name in self.mutations
        ):
            return None
        if value.name in self.modules:
            return value
        provider, _, name = value.name.rpartition(".")
        path = self.modules.get(provider)
        if path is not None:
            return self.global_value(path, name)
        return value

    def global_value(self, path, name):
        key = (path, name)
        if key in self.globals:
            return self.globals[key]
        if key in self.reading:
            return None
        self.reading.add(key)
        try:
            node = self.definitions.get(path, {}).get(name)
            if isinstance(node, ast.FunctionDef):
                value = Function(path, node)
            elif isinstance(node, ast.ClassDef):
                fields = []
                defaults = {}
                decorated_dataclass = False
                generated_init = False
                if (
                    len(node.decorator_list) == 1
                    and not node.keywords
                    and not node.bases
                ):
                    decorator = node.decorator_list[0]
                    provider_node = decorator
                    safe_options = True
                    if isinstance(decorator, ast.Call):
                        provider_node = decorator.func
                        safe_options = not decorator.args
                        for keyword in decorator.keywords:
                            if (
                                keyword.arg
                                not in {
                                    "frozen",
                                    "slots",
                                    "eq",
                                    "order",
                                    "repr",
                                    "unsafe_hash",
                                    "match_args",
                                }
                                or not isinstance(keyword.value, ast.Constant)
                                or not isinstance(keyword.value.value, bool)
                            ):
                                safe_options = False
                    provider = self.evaluate(provider_node, path, {})
                    decorated_dataclass = (
                        safe_options
                        and isinstance(provider, Symbol)
                        and provider.name == "dataclasses.dataclass"
                    )
                methods = {
                    child.name
                    for child in node.body
                    if isinstance(child, ast.FunctionDef)
                }
                if decorated_dataclass and not (
                    methods
                    & {
                        "__init__",
                        "__post_init__",
                        "__new__",
                        "__getattribute__",
                        "__getattr__",
                    }
                ):
                    generated_init = True
                    for child in node.body:
                        if isinstance(child, ast.AnnAssign) and isinstance(
                            child.target, ast.Name
                        ):
                            annotation = child.annotation
                            if isinstance(annotation, ast.Subscript):
                                annotation = annotation.value
                            annotation_provider = self.evaluate(annotation, path, {})
                            if isinstance(child.value, ast.Call) or (
                                isinstance(annotation_provider, Symbol)
                                and annotation_provider.name == "typing.ClassVar"
                            ):
                                fields = []
                                defaults = {}
                                generated_init = False
                                break
                            fields.append(child.target.id)
                            if child.value is not None:
                                defaults[child.target.id] = self.evaluate(
                                    child.value, path, {}
                                )
                value = Class(path, node, tuple(fields), defaults, generated_init)
            else:
                assignments = self.assignments.get(path, {}).get(name, ())
                value = None
                if len(assignments) == 1:
                    value = self.evaluate(assignments[0], path, {})
                elif not assignments and name in self.imports.get(path, {}):
                    value = self.symbol(self.imports[path][name])
            self.globals[key] = value
            return value
        finally:
            self.reading.remove(key)

    def name(self, path, name, bindings):
        if name in bindings:
            return bindings[name]
        if name == "__file__":
            return path
        value = self.global_value(path, name)
        if value is not None:
            return value
        if (
            name in self.assignments.get(path, {})
            or name in self.imports.get(path, {})
            or name in self.definitions.get(path, {})
        ):
            return None
        if name in {
            "str",
            "list",
            "tuple",
            "dict",
            "sorted",
            "reversed",
            "len",
            "enumerate",
            "zip",
            "super",
            "getattr",
            "hasattr",
            "isinstance",
            "issubclass",
            "type",
            "open",
            "setattr",
            "delattr",
        }:
            return Symbol("builtins." + name)
        return None

    def evaluate(self, node, path, bindings):
        from skylos.deadcode.python_source_effects import evaluate

        self.budget += 1
        self.total_steps += 1
        self.owner_steps += 1
        if self.budget > 150_000 or self.owner_steps > 1_000_000:
            return None
        value = evaluate(self, node, path, bindings)
        if (
            isinstance(node, ast.Call)
            and value is not None
            and self.budget <= 150_000
            and self.owner_steps <= 1_000_000
        ):
            self.completed_call_sites.add((path, id(node)))
        return value

    def resolve_text(self, node, module_path, bindings=None):
        self.budget = 0
        value = self.evaluate(node, Path(module_path), bindings or {})
        result = {item for item in alternatives(value) if isinstance(item, str)}
        return result or None

    def call(self, function, arguments, keywords):
        from skylos.deadcode.python_source_effects import call_function

        return call_function(self, function, arguments, keywords)

    def initialize_module(self, path):
        from skylos.deadcode.python_source_effects import block

        if path in self.initialized or path not in self.trees:
            return
        self.initialized.add(path)
        env = Environment(module_scope=True)
        block(self, self.trees[path].body, path, env)
        self.executed_contexts.append((self.trees[path], path, dict(env)))

    def contexts(self):
        """Potentially executed source owners reached from module statements."""

        if self.context_cache is None:
            self.executed_contexts = []
            for path, tree in self.trees.items():
                self.budget = 0
                self.owner_steps = 0
                self.initialize_module(path)
            # Module discovery order is not execution order. Revisit only
            # executable calls after initializers are known, never resetting
            # a source-owned registry that a reachable writer populated.
            for path, tree in self.trees.items():
                self.owner_steps = 0
                env = {}
                for node in _scope_nodes(tree):
                    if isinstance(node, ast.Call):
                        if (path, id(node)) in self.completed_call_sites:
                            continue
                        self.budget = 0
                        self.evaluate(node, path, env)
            pending = list(self.executed_contexts)
            expanded = set()
            while pending and len(expanded) < 4096:
                scope, path, bindings = pending.pop()
                key = (path, id(scope))
                if key in expanded:
                    continue
                expanded.add(key)
                self.owner_steps = 0
                previous = len(self.executed_contexts)
                for node in _scope_nodes(scope):
                    if isinstance(node, ast.Call):
                        self.budget = 0
                        callee = self.evaluate(node.func, path, bindings)
                        if (
                            isinstance(callee, Function)
                            and (callee.path, id(callee.node)) not in self.completed
                        ):
                            self.evaluate(node, path, bindings)
                pending.extend(self.executed_contexts[previous:])
            self.context_cache = list(self.executed_contexts)
        return iter(self.context_cache)

    def resolve_function(self, node, module_path, bindings=None):
        value = self.symbol(self.evaluate(node, Path(module_path), bindings or {}))
        if isinstance(value, Function):
            return value.node, value.path
        return None

    def registered_route(self, node, path, env):
        if not node.decorator_list:
            return False
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                return False
            function = decorator.func
            if not isinstance(function, ast.Attribute):
                return False
            receiver = self.evaluate(function.value, path, env)
            if isinstance(receiver, Record):
                if receiver.provider not in {
                    "flask.Flask",
                    "flask.Blueprint",
                    "fastapi.FastAPI",
                    "fastapi.APIRouter",
                }:
                    return False
                if (
                    function.attr
                    not in {
                        "route",
                        "get",
                        "post",
                        "put",
                        "patch",
                        "delete",
                        "options",
                        "head",
                        "api_route",
                    }
                    or function.attr in receiver.fields
                ):
                    return False
                if (
                    self.symbol(
                        Symbol(receiver.provider + "." + function.attr, bound=True)
                    )
                    is None
                ):
                    return False
            elif isinstance(receiver, Symbol):
                if receiver.name != "nicegui.ui" or function.attr != "page":
                    return False
                if self.symbol(Symbol("nicegui.ui.page", bound=True)) is None:
                    return False
            else:
                return False
        return True

    def source_lineage(self, owner):
        """Resolve a linear source hierarchy without guessing external MROs."""

        lineage = []
        seen = set()
        while isinstance(owner, Class):
            node = owner.node
            if node is None or id(node) in seen or node.keywords or node.decorator_list:
                return None
            for child in node.body:
                if isinstance(child, ast.FunctionDef) and child.name in {
                    "__new__",
                    "__getattribute__",
                    "__getattr__",
                }:
                    return None
            seen.add(id(node))
            lineage.append(owner)
            if not node.bases:
                return lineage
            if len(node.bases) != 1:
                return None
            owner = self.evaluate(node.bases[0], owner.path, {})
        return None

    def source_initializer(self, record):
        owner = record.owner
        if owner is None or owner.node is None:
            return None
        for child in owner.node.body:
            if isinstance(child, ast.FunctionDef) and child.name == "__init__":
                return self.instance_method(record, "__init__", owner)
        lineage = self.source_lineage(owner)
        if lineage is None:
            return None
        for parent in lineage[1:]:
            for child in parent.node.body:
                if isinstance(child, ast.FunctionDef) and child.name == "__init__":
                    return self.instance_method(record, "__init__", parent)
        return None

    def instance_method(self, record, name, owner=None, seen=frozenset()):
        if owner is None:
            owner = record.owner
        if owner is None or owner.node is None or id(owner.node) in seen:
            return None
        for child in owner.node.body:
            if isinstance(child, ast.FunctionDef) and child.name == name:
                if child.decorator_list:
                    return None
                return Function(owner.path, child, {"self": record}, owner=owner)
        found = {}
        for base in owner.node.bases:
            parent = self.evaluate(base, owner.path, {})
            if isinstance(parent, Class):
                method = self.instance_method(
                    record, name, parent, seen | {id(owner.node)}
                )
                if method is not None:
                    found[id(method.node)] = method
        if len(found) == 1:
            return next(iter(found.values()))
        return None

    def resolve_path(self, node, module_path, bindings=None):
        self.budget = 0
        value = self.evaluate(node, Path(module_path), bindings or {})
        result = set()
        for item in alternatives(value):
            if not isinstance(item, (str, Path)):
                continue
            candidate = Path(item)
            if not candidate.is_absolute():
                candidate = self.root / candidate
            try:
                if "\x00" in str(candidate) or any(
                    part.is_symlink()
                    for part in [candidate, *candidate.parents]
                    if part != self.root
                ):
                    continue
                candidate = candidate.resolve()
                candidate.relative_to(self.root)
            except (OSError, ValueError):
                continue
            result.add(candidate)
        return result or None

    def listing_files(self, call, module_path, bindings=None):
        self.budget = 0
        value = self.evaluate(call, Path(module_path), bindings or {})
        found = set()
        pending = list(alternatives(value))
        seen = set()
        while pending and len(seen) < 4096:
            item = pending.pop()
            if id(item) in seen:
                continue
            seen.add(id(item))
            if isinstance(item, Choice):
                pending.extend(item.values)
            elif isinstance(item, Record):
                if "path" in item.fields:
                    pending.extend(alternatives(item.fields["path"]))
                elif "file" in item.fields:
                    pending.extend(alternatives(item.fields["file"]))
            elif isinstance(item, (list, tuple)):
                pending.extend(item)
            elif isinstance(item, (str, Path)):
                candidate = Path(item)
                if not candidate.is_absolute():
                    candidate = self.root / candidate
                try:
                    if "\x00" in str(candidate) or any(
                        part.is_symlink()
                        for part in [candidate, *candidate.parents]
                        if part != self.root
                    ):
                        continue
                    candidate = candidate.resolve()
                    candidate.relative_to(self.root)
                except (OSError, ValueError):
                    continue
                if candidate.is_file() and not candidate.is_symlink():
                    found.add(candidate)
        if value is None:
            return None
        return found
