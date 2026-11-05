"""Static Robot Framework Library/Variables imports, without importing Robot.

Only settings in Robot data files supply providers. Resolution is restricted to
the importing file's directory and project source roots; a matching basename
somewhere else in the project is not evidence of a Python import.
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from skylos.core.file_discovery import discover_source_files
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.deadcode._reachability_bindings import bound_names
from skylos.deadcode.python_ast import ParsedPythonFile

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_DECO = "robot.api.deco."
_STANDARD_LIBRARIES = {
    "BuiltIn",
    "Collections",
    "DateTime",
    "Dialogs",
    "OperatingSystem",
    "Process",
    "Remote",
    "Screenshot",
    "String",
    "Telnet",
    "XML",
}
_DYNAMIC_METHODS = {
    "get_keyword_names",
    "getKeywordNames",
    "run_keyword",
    "runKeyword",
    "get_keyword_arguments",
    "getKeywordArguments",
    "get_keyword_documentation",
    "getKeywordDocumentation",
    "get_keyword_tags",
    "getKeywordTags",
    "get_keyword_types",
    "getKeywordTypes",
}
_LISTENER_METHODS = {
    "close",
    "log_message",
    "message",
    "library_import",
    "resource_import",
    "variables_import",
    "output_file",
    "log_file",
    "report_file",
    "xunit_file",
    "debug_file",
} | {
    f"{phase}_{event}"
    for phase in ("start", "end")
    for event in (
        "suite",
        "test",
        "keyword",
        "user_keyword",
        "library_keyword",
        "invalid_keyword",
        "for",
        "for_iteration",
        "while",
        "while_iteration",
        "group",
        "if",
        "if_branch",
        "try",
        "try_branch",
        "var",
        "break",
        "continue",
        "return",
        "error",
        "body_item",
    )
}
_VARIABLE = re.compile(r"\$\{([^}]+)\}")
_UNKNOWN = object()
_UNSET = object()


def _normalize(name: str) -> str:
    return re.sub(r"[\s_]", "", name).casefold()


def _setting_name(name: str) -> str:
    # Settings and section names retain internal spaces and underscores. Only
    # variable/keyword names use Robot's underscore-insensitive normalization.
    return " ".join(name.split()).casefold()


@dataclass
class _Document:
    path: Path
    imports: list[tuple[str, str]] = field(default_factory=list)
    variables: dict[str, str | None] = field(default_factory=dict)
    has_sections: bool = False


def _document(root: Path, path: Path) -> _Document | None:
    text = read_project_text_no_symlink(root, path, max_bytes=512_000)
    if text is None:
        return None
    document = _Document(path)
    section = ""
    pending: list[str] = []

    def flush():
        if section in {"settings", "setting"} and len(pending) > 1:
            kind = _setting_name(pending[0])
            if kind in {"library", "variables", "resource"}:
                document.imports.append((kind, pending[1]))
        elif section in {"variables", "variable"} and pending:
            if match := _VARIABLE.fullmatch(pending[0]):
                # Robot's variable table keeps the first definition. Reserve
                # unsupported/empty values too, so a later duplicate cannot
                # turn an unknown provider into a different proven import.
                document.variables.setdefault(
                    _normalize(match[1]), pending[1] if len(pending) == 2 else None
                )

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cells = (
            [part.strip() for part in re.split(r"(?<!\\)\|", line)[1:-1]]
            if line.startswith("|") and line.endswith("|")
            else re.split(r"\t+| {2,}", line)
        )
        for offset, cell in enumerate(cells):
            if cell.startswith("#"):
                cells = cells[:offset]
                break
        if not cells:
            continue
        if re.fullmatch(r"\*{3,}\s*[^*]+\s*\*{3,}", cells[0]):
            flush()
            pending = []
            section = _setting_name(cells[0].strip("* "))
            document.has_sections |= section in {
                "settings",
                "setting",
                "variables",
                "variable",
                "test cases",
                "test case",
                "tasks",
                "task",
                "keywords",
                "keyword",
            }
        elif cells[0] == "...":
            pending.extend(cells[1:])
        else:
            flush()
            pending = cells
    flush()
    return document if document.has_sections else None


def _expand(value: str, variables: dict[str, str | None]) -> str | None:
    for _ in range(16):
        if not _VARIABLE.search(value):
            return None if re.search(r"[$@&%]\{", value) else value
        missing = False

        def replace(match):
            nonlocal missing
            replacement = variables.get(_normalize(match[1]))
            if replacement is None:
                missing = True
                return match[0]
            return replacement

        updated = _VARIABLE.sub(replace, value)
        if missing or updated == value:
            return None
        value = updated
    return None


def _literal(node):
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, RecursionError):
        return _UNKNOWN


def _qualified(node, bindings):
    if isinstance(node, ast.Name):
        return bindings.get(node.id)
    if isinstance(node, ast.Attribute):
        parent = _qualified(node.value, bindings)
        return f"{parent}.{node.attr}" if parent else None
    return None


@dataclass
class _Scope:
    path: Path
    node: Any
    members: dict[str, ast.AST] = field(default_factory=dict)
    values: dict[str, Any] = field(default_factory=dict)
    bindings: dict[str, str | None] = field(default_factory=dict)
    decorators: dict[int, list[tuple[str | None, ast.AST]]] = field(
        default_factory=dict
    )
    not_keywords: set[int] = field(default_factory=set)
    explicit_keywords: set[int] = field(default_factory=set)
    bases: dict[int, list[ast.ClassDef | str | None]] = field(default_factory=dict)
    class_bindings: dict[int, dict[str, str | None]] = field(default_factory=dict)


def _assignment_values(target, value):
    if isinstance(target, ast.Name):
        return {target.id: value}
    if (
        isinstance(target, (ast.Tuple, ast.List))
        and isinstance(value, (tuple, list))
        and len(target.elts) == len(value)
        and not any(isinstance(item, ast.Starred) for item in target.elts)
    ):
        values = {}
        for child, item in zip(target.elts, value):
            values.update(_assignment_values(child, item))
        return values
    return {}


def _scope(path, node, bindings=None):
    scope = _Scope(path, node, bindings=dict(bindings or {}))
    for statement in node.body:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            for alias in statement.names:
                name = alias.asname or (
                    alias.name.split(".")[0]
                    if isinstance(statement, ast.Import)
                    else alias.name
                )
                provider = (
                    (alias.name if alias.asname else alias.name.split(".")[0])
                    if isinstance(statement, ast.Import)
                    else (
                        "." * statement.level
                        + ".".join(
                            part for part in (statement.module, alias.name) if part
                        )
                    )
                )
                scope.members[name] = statement
                scope.bindings[name] = provider
        elif isinstance(statement, (*_FUNCTIONS, ast.ClassDef)):
            if isinstance(statement, ast.ClassDef):
                scope.class_bindings[statement.lineno] = scope.bindings.copy()
                bases = []
                for base in statement.bases:
                    local = (
                        scope.members.get(base.id)
                        if isinstance(base, ast.Name)
                        else None
                    )
                    if isinstance(local, ast.ClassDef):
                        bases.append(local)
                    elif (
                        isinstance(base, ast.Name)
                        and base.id == "object"
                        and base.id not in scope.bindings
                    ):
                        bases.append("builtins.object")
                    else:
                        bases.append(_qualified(base, scope.bindings))
                scope.bases[statement.lineno] = bases
            scope.decorators[statement.lineno] = [
                (
                    _qualified(
                        deco.func if isinstance(deco, ast.Call) else deco,
                        scope.bindings,
                    ),
                    deco,
                )
                for deco in statement.decorator_list
            ]
            scope.members[statement.name] = statement
            scope.bindings[statement.name] = None
        elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
            if isinstance(statement, ast.AnnAssign) and statement.value is None:
                continue
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            assigned_values = {}
            literal = _literal(statement.value)
            for target in targets:
                assigned_values.update(_assignment_values(target, literal))
            for target in targets:
                if isinstance(target, ast.Attribute) and isinstance(
                    target.value, ast.Name
                ):
                    member = scope.members.get(target.value.id)
                    if isinstance(member, _FUNCTIONS):
                        if (
                            target.attr == "robot_not_keyword"
                            and _literal(statement.value) is not False
                        ):
                            scope.not_keywords.add(member.lineno)
                        elif target.attr == "robot_name":
                            scope.explicit_keywords.add(member.lineno)
            for name in bound_names([statement]).counts:
                scope.members[name] = statement
                scope.values[name] = assigned_values.get(name, _UNKNOWN)
                scope.bindings[name] = (
                    _qualified(statement.value, scope.bindings)
                    if any(
                        isinstance(target, ast.Name) and target.id == name
                        for target in targets
                    )
                    else None
                )
        else:
            if isinstance(statement, ast.Expr) and isinstance(
                statement.value, ast.Call
            ):
                call = statement.value
                if (
                    _qualified(call.func, scope.bindings) == _DECO + "not_keyword"
                    and call.args
                ):
                    argument = call.args[0]
                    member = (
                        scope.members.get(argument.id)
                        if isinstance(argument, ast.Name)
                        else None
                    )
                    if isinstance(member, _FUNCTIONS):
                        scope.not_keywords.add(member.lineno)
                if (
                    isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name)
                    and call.func.value.id == "__all__"
                ):
                    scope.values["__all__"] = _UNKNOWN
            for name in bound_names([statement]).counts:
                scope.members.pop(name, None)
                scope.values[name] = _UNKNOWN
                scope.bindings[name] = None
    return scope


class _Providers:
    def __init__(self, definitions, parsed, root):
        self.root = root
        self.modules = {}
        self.definitions = defaultdict(list)
        self.class_scopes = {}
        self.lineages = {}
        for module in parsed:
            path = module.path.resolve()
            if path.is_relative_to(root):
                self.modules[path] = _scope(path, module.tree)
        for definition in definitions.values():
            path = Path(definition.filename).resolve()
            if path in self.modules:
                self.definitions[path, definition.line].append(definition)
        self.source_roots = [root, root / "src", root / "lib", root / "python"]

    def module(self, name, parent):
        candidates = set()
        for base in [parent, *self.source_roots]:
            for relative in (name + ".py", name + "/__init__.py"):
                path = (base / relative).resolve()
                if path in self.modules:
                    candidates.add(path)
        return self.modules[next(iter(candidates))] if len(candidates) == 1 else None

    def resolve(self, name, parent):
        if name.endswith(".py") or "/" in name or "\\" in name:
            path = (parent / name.replace("\\", "/")).resolve()
            scope = self.modules.get(path) or self.modules.get(path / "__init__.py")
            return (scope, None) if scope else (None, None)
        if name.startswith("."):
            level = len(name) - len(name.lstrip("."))
            name = name[level:]
            for _ in range(level - 1):
                parent = parent.parent
        if not all(part.isidentifier() for part in name.split(".")):
            return None, None
        module = self.module(name.replace(".", "/"), parent)
        if module:
            return module, None
        module_name, _, class_name = name.rpartition(".")
        if module_name:
            module = self.module(module_name.replace(".", "/"), parent)
            node = module.members.get(class_name) if module else None
            if isinstance(node, ast.ClassDef):
                return module, node
        return None, None

    def selected_class(self, module, *, library):
        stem = module.path.stem
        if stem == "__init__":
            stem = module.path.parent.name
        node = module.members.get(stem)
        if isinstance(node, ast.ClassDef):
            return node
        if library:
            decorated = [
                node
                for node in module.members.values()
                if isinstance(node, ast.ClassDef)
                and any(
                    provider == _DECO + "library"
                    for provider, _ in module.decorators.get(node.lineno, ())
                )
            ]
            if len(decorated) == 1:
                return decorated[0]
        return None

    def class_scope(self, module, node):
        key = module.path, node.lineno
        if key not in self.class_scopes:
            self.class_scopes[key] = _scope(
                module.path, node, module.class_bindings.get(node.lineno, {})
            )
        return self.class_scopes[key]

    def members(self, module, node):
        if node is None:
            return {name: (module, item) for name, item in module.members.items()}
        members = {}
        for owner, cls in reversed(self.lineage(module, node) or [(module, node)]):
            scope = self.class_scope(owner, cls)
            members.update(
                {name: (scope, item) for name, item in scope.members.items()}
            )
        return members

    def bases(self, module, node):
        bases = []
        for provider in module.bases.get(node.lineno, ()):
            if isinstance(provider, ast.ClassDef):
                bases.append((module, provider))
            elif provider == "builtins.object":
                continue
            elif provider:
                # Relative imports are resolved against the defining package.
                parent, base_node = self.resolve(provider, module.path.parent)
                if parent and base_node:
                    bases.append((parent, base_node))
                else:
                    return None
            else:
                return None
        return bases

    def lineage(self, module, node, seen=()):
        """C3 order for source-owned bases; unknown parents prove no inheritance."""
        key = module.path, node.lineno
        if key in self.lineages:
            return self.lineages[key]
        if key in seen or len(seen) >= 16:
            return None
        bases = self.bases(module, node)
        if bases is None:
            return None
        sequences = [self.lineage(parent, cls, (*seen, key)) for parent, cls in bases]
        if any(sequence is None for sequence in sequences):
            return None
        sequences = [list(sequence) for sequence in sequences] + [list(bases)]
        result = [(module, node)]
        while sequences := [sequence for sequence in sequences if sequence]:
            candidate = None
            for sequence in sequences:
                head = sequence[0]
                head_key = head[0].path, head[1].lineno
                if not any(
                    (owner.path, cls.lineno) == head_key
                    for other in sequences
                    for owner, cls in other[1:]
                ):
                    candidate = head
                    break
            if candidate is None:
                return None
            result.append(candidate)
            key_to_remove = candidate[0].path, candidate[1].lineno
            for sequence in sequences:
                if (sequence[0][0].path, sequence[0][1].lineno) == key_to_remove:
                    sequence.pop(0)
        self.lineages[key] = result
        return result

    def auto_keywords(self, module, node):
        if node is None:
            return module.values.get("ROBOT_AUTO_KEYWORDS", _UNSET)
        lineage = self.lineage(module, node)
        for owner, cls in lineage or [(module, node)]:
            value = self.own_auto_keywords(owner, cls)
            if value is not _UNSET:
                return value
        return _UNSET if lineage is not None else _UNKNOWN

    def own_auto_keywords(self, module, node):
        for provider, decorator in module.decorators.get(node.lineno, ()):
            if provider == _DECO + "library":
                if isinstance(decorator, ast.Call):
                    for argument in decorator.keywords:
                        if argument.arg == "auto_keywords":
                            return _literal(argument.value)
                return False
        scope = self.class_scope(module, node)
        if "ROBOT_AUTO_KEYWORDS" in scope.values:
            return scope.values["ROBOT_AUTO_KEYWORDS"]
        return _UNSET

    def self_listener(self, module, node):
        if node is None:
            return False
        for owner, cls in self.lineage(module, node) or [(module, node)]:
            for provider, decorator in owner.decorators.get(cls.lineno, ()):
                if provider == _DECO + "library" and isinstance(decorator, ast.Call):
                    for argument in decorator.keywords:
                        if argument.arg == "listener":
                            value = _literal(argument.value)
                            if value is not None:
                                return (
                                    isinstance(value, str)
                                    and value.casefold() == "self"
                                )
        return False

    def targets(self, scope, node, kind, name=None):
        for definition in self.definitions.get((scope.path, node.lineno), ()):
            if definition.type in kind and (
                name is None or definition.simple_name == name
            ):
                yield definition


def _dynamic_names(owner, method, members, global_bindings):
    returns = [item for item in method.body if isinstance(item, ast.Return)]
    if len(returns) != 1:
        return None
    expression = returns[0].value
    value = _literal(expression)
    if isinstance(value, (list, tuple)) and all(
        isinstance(item, str) for item in value
    ):
        return set(value)
    if not isinstance(expression, ast.ListComp) or len(expression.generators) != 1:
        return None
    generator = expression.generators[0]
    receiver = [*method.args.posonlyargs, *method.args.args]
    local_names = bound_names(method.body).counts
    if (
        not receiver
        or "dir" in global_bindings
        or "dir" in local_names
        or receiver[0].arg in local_names
        or any(arg.arg == "dir" for arg in [*receiver, *method.args.kwonlyargs])
        or generator.is_async
        or not isinstance(generator.target, ast.Name)
        or not isinstance(expression.elt, ast.Name)
        or expression.elt.id != generator.target.id
        or not isinstance(generator.iter, ast.Call)
        or not isinstance(generator.iter.func, ast.Name)
        or generator.iter.func.id != "dir"
        or len(generator.iter.args) != 1
        or generator.iter.keywords
        or not isinstance(generator.iter.args[0], ast.Name)
        or generator.iter.args[0].id != receiver[0].arg
        or len(generator.ifs) != 1
    ):
        return None
    condition = generator.ifs[0]
    if (
        isinstance(condition, ast.Call)
        and isinstance(condition.func, ast.Attribute)
        and isinstance(condition.func.value, ast.Name)
        and condition.func.value.id == generator.target.id
        and condition.func.attr == "startswith"
        and len(condition.args) == 1
        and not condition.keywords
        and isinstance(prefix := _literal(condition.args[0]), str)
    ):
        return {name for name in members if name.startswith(prefix)}
    return None


def _library_targets(providers, module, node):
    if node:
        yield from providers.targets(module, node, {"class"})
    policy = providers.auto_keywords(module, node)
    auto = policy is _UNSET or (policy is not _UNKNOWN and bool(policy))
    includes = module.values.get("__all__") if node is None else None
    if includes is _UNKNOWN or (
        includes is not None and not isinstance(includes, (list, tuple, set))
    ):
        return
    members = providers.members(module, node)
    listener = providers.self_listener(module, node)
    dynamic = next(
        (
            members.get(name)
            for name in ("get_keyword_names", "getKeywordNames")
            if name in members
        ),
        None,
    )
    dynamic_names = None
    if dynamic and isinstance(dynamic[1], _FUNCTIONS):
        dynamic_names = _dynamic_names(
            dynamic[0],
            dynamic[1],
            members,
            providers.modules[dynamic[0].path].bindings,
        )
    for name, (owner, member) in members.items():
        if not isinstance(member, _FUNCTIONS):
            continue
        decorators = {
            provider for provider, _ in owner.decorators.get(member.lineno, ())
        }
        if "property" in {getattr(deco, "id", None) for deco in member.decorator_list}:
            continue
        protocol = (
            name == "__init__"
            or (dynamic and name in _DYNAMIC_METHODS)
            or (listener and name in _LISTENER_METHODS)
        )
        keyword = (
            member.lineno in owner.explicit_keywords
            or _DECO + "keyword" in decorators
            or (auto is True and not name.startswith("_"))
        )
        if dynamic and (dynamic_names is None or name not in dynamic_names):
            keyword = False
        elif dynamic_names is not None and name in dynamic_names:
            keyword = True
        if member.lineno in owner.not_keywords or _DECO + "not_keyword" in decorators:
            keyword = False
        if includes is not None and name not in includes:
            keyword = False
        if protocol or keyword:
            yield from providers.targets(owner, member, {"method", "function"}, name)


def _variable_targets(providers, module, node):
    if node:
        yield from providers.targets(module, node, {"class"})
    members = providers.members(module, node)
    for name in ("get_variables", "getVariables"):
        if name in members:
            owner, getter = members[name]
            if isinstance(getter, _FUNCTIONS):
                yield from providers.targets(
                    owner, getter, {"function", "method"}, name
                )
            return
    scope = providers.class_scope(module, node) if node else module
    includes = scope.values.get("__all__")
    if includes is _UNKNOWN or (
        includes is not None and not isinstance(includes, (list, tuple, set))
    ):
        return
    for name, (owner, member) in members.items():
        if name.startswith("_") or (includes is not None and name not in includes):
            continue
        kinds = (
            {"variable", "import"}
            if node
            else {"variable", "import", "function", "class"}
        )
        yield from providers.targets(owner, member, kinds, name)


def find_robot_framework_targets(
    definitions: dict[str, Any],
    parsed_files: Iterable[ParsedPythonFile],
    root: Path,
    *,
    exclude_folders=None,
) -> list[tuple[Any, str]]:
    documents = {}
    for path in discover_source_files(
        root, {".robot", ".resource"}, exclude_folders=exclude_folders
    ):
        if document := _document(root, path):
            documents[path.resolve()] = document
    active = {path for path in documents if path.suffix.lower() == ".robot"}
    if not active:
        return []
    providers = _Providers(definitions, parsed_files, root)
    found = {}

    def add(module, node, kind):
        if module is None:
            return
        node = node or providers.selected_class(module, library=kind == "library")
        targets = _library_targets if kind == "library" else _variable_targets
        for target in targets(providers, module, node):
            found[id(target)] = target, f"robot_{kind}"

    def variables(document, seen=()):
        if document.path in seen or len(seen) >= 16:
            return {}
        values = {**document.variables, "curdir": str(document.path.parent), "/": "/"}
        for kind, name in document.imports:
            if kind != "resource" or (name := _expand(name, values)) is None:
                continue
            resource = documents.get((document.path.parent / name).resolve())
            if resource:
                inherited = variables(resource, (*seen, document.path))
                for key, value in inherited.items():
                    if key not in {"curdir", "/"} and key not in values:
                        values[key] = (
                            _expand(value, inherited) if value is not None else None
                        )
        return values

    builtin, _ = providers.resolve("robot.libraries.BuiltIn", root)
    add(builtin, None, "library")
    pending = list(active)
    while pending:
        document = documents[pending.pop()]
        values = variables(document)
        for kind, name in document.imports:
            name = _expand(name, values)
            if name is None:
                continue
            if kind == "variables" and name.lower().endswith(
                (".yaml", ".yml", ".json")
            ):
                continue
            if kind == "resource":
                path = (document.path.parent / name).resolve()
                if path in documents and path not in active:
                    active.add(path)
                    pending.append(path)
                continue
            if kind == "library" and name in _STANDARD_LIBRARIES:
                module, node = providers.resolve(f"robot.libraries.{name}", root)
            else:
                module, node = providers.resolve(name, document.path.parent)
            add(module, node, kind)
    return list(found.values())
